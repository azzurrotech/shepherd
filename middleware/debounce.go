// Debounce middleware for the middleware package.
//
// Duplicate/replay suppression is the fourth stage of shepherd's request
// pipeline: a request that is an identical repeat of one already in flight
// (same method, path, query, client and body digest) — or one that follows a
// completed request within the debounce window — is coalesced/dropped instead
// of being forwarded. A misbehaving client therefore cannot use shepherd as an
// amplifier.
//
// The Debounce wrapper is composable like Firewall/RateLimit, and the
// Gateway applies the same policy automatically when Config.Debounce is set.
package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"azzurrotech/shepherd/debounce"
)

// debounceBodyCap bounds how much of a body the debounce key digest reads, so
// the cheap duplicate check cannot itself be turned into a large-body read.
const debounceBodyCap = 1 << 20 // 1 MiB

// Debounce returns a wrapper that coalesces/drops duplicate or immediately
// replayed identical requests within window, and drops extras beyond
// maxInflight concurrent identical requests. A window <= 0 disables it and
// returns a pass-through wrapper.
//
// It satisfies the middleware addition `Debounce(window, maxInflight)`:
//
//	handler = s.Debounce(250*time.Millisecond, 4)(handler)
func (s *Shepherd) Debounce(window time.Duration, maxInflight int) func(http.Handler) http.Handler {
	if window <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	// Reuse the configured debouncer when it matches, so Config.Debounce and an
	// explicit wrapper share state; otherwise build a dedicated one.
	d := s.dbnc
	if d == nil || d.Window() != window || d.MaxInflight() != normalizedMaxInflight(maxInflight) {
		d = debounce.New(window, maxInflight)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			release := s.applyDebounce(d, w, r)
			if release == nil {
				return // dropped: applyDebounce already wrote the response
			}
			defer release()
			next.ServeHTTP(w, r)
		})
	}
}

// applyDebounce checks the request against d and writes a 429 when it is a
// duplicate/replay or over the in-flight cap. It returns a non-nil release
// function when the request may proceed, and nil when it has been dropped.
func (s *Shepherd) applyDebounce(d *debounce.Debouncer, w http.ResponseWriter, r *http.Request) func() {
	if d == nil || !d.Enabled() {
		return func() {}
	}
	decision, release := d.Allow(debounceKey(r, s.ClientIP(r)))
	if !decision.Allowed {
		w.Header().Set("X-Shepherd-Debounced", decision.Reason)
		// A dropped duplicate is not an authorization failure; 429 with a
		// Retry-After lets a well-behaved client back off, in the same spirit
		// as the rate limiter.
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":  "duplicate or replayed request dropped",
			"reason": decision.Reason,
		})
		return nil
	}
	return release
}

// debounceKey derives the identity of a request for debouncing: method, path,
// raw query, client and a digest of the body. Two requests that are identical
// in all of those share a key. The body is buffered and restored so the
// downstream handler (the reverse proxy) still sees it.
func debounceKey(r *http.Request, ip string) string {
	h := sha256.New()
	h.Write([]byte(r.Method))
	h.Write([]byte{0})
	h.Write([]byte(r.URL.EscapedPath()))
	h.Write([]byte{0})
	h.Write([]byte(r.URL.RawQuery))
	h.Write([]byte{0})
	h.Write([]byte(ip))
	h.Write([]byte{0})
	if body, ok := captureBody(r); ok {
		sum := sha256.Sum256(body)
		h.Write(sum[:])
	} else {
		// Oversized/unreadable body: use a constant marker rather than reading
		// it all here. The gateway enforces its own body cap downstream.
		h.Write([]byte("oversized"))
	}
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// captureBody reads up to debounceBodyCap bytes of r.Body and restores the body
// so later handlers can read it in full. ok is false when the body exceeded the
// cap; in that case the already-read prefix is put back in front of the
// remainder, so nothing is lost.
func captureBody(r *http.Request) (body []byte, ok bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, debounceBodyCap+1))
	if err != nil {
		return nil, false
	}
	if len(buf) > debounceBodyCap {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return buf, true
}

// normalizedMaxInflight mirrors debounce.New's normalization so Debounce can
// decide whether it can reuse the configured debouncer.
func normalizedMaxInflight(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
