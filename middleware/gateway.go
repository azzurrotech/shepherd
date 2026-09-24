// Gateway support for the middleware package.
//
// A gateway is how shepherd "enhances a query and passes it correctly to a
// given point": incoming traffic is checked against the firewall and rate
// limit, authenticated with a capability token (unless the upstream is
// public), then enriched — query parameters injected from the token's claims,
// X-Shepherd-* headers added, and an HMAC-SHA256 request signature computed —
// before being reverse-proxied to the registered backend.
//
// The backend verifies the signature the same way it would verify a webhook:
// recompute the canonical line with a shared secret and a bounded clock skew.
// It can also read the identity-less subject/scopes straight from the
// X-Shepherd-* headers.
package middleware

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"azzurrotech/shepherd/token"
)

// DefaultMaxBody caps how much of a request body is buffered for the body
// digest in the gateway signature. Larger requests are rejected.
const DefaultMaxBody = 16 << 20 // 16 MiB

// errBodyTooLarge is returned by readBody when the body exceeds the cap.
var errBodyTooLarge = errors.New("body too large for gateway hashing")

// Upstream describes one protected backend behind the gateway.
type Upstream struct {
	// Name is a human label, used in status output.
	Name string `json:"name"`
	// Prefix is the first path segment under the gateway mount that routes
	// to this backend, e.g. "orders". Requests to <mount>/orders/... are
	// proxied to Target with the "/orders" part stripped.
	Prefix string `json:"prefix"`
	// Target is the backend base URL, e.g. "http://localhost:9000".
	Target string `json:"target"`
	// Public skips authentication (the backend is still firewall-checked and
	// rate-limited).
	Public bool `json:"public"`
	// Scopes are the capability scopes required to reach a non-public
	// backend.
	Scopes []string `json:"scopes,omitempty"`
	// QueryEnrich maps a query parameter name to a claims field
	// ("sub", "scopes", "roles", "jti", "block", "aud", "exp") or to a key of
	// the token's Meta map. The parameter is only added when the caller did
	// not already supply it.
	QueryEnrich map[string]string `json:"query_enrich,omitempty"`
	// MaxBody is the maximum body size buffered for gateway signature
	// hashing. 0 means DefaultMaxBody; -1 disables body hashing.
	MaxBody int64 `json:"max_body,omitempty"`
}

// GatewayOptions configures a gateway HTTP handler.
type GatewayOptions struct {
	// Mount is the path prefix the gateway handler lives under, e.g. "/gw/".
	// Defaults to "/gw/".
	Mount string `json:"mount"`
	// Upstreams is the routing table.
	Upstreams []Upstream `json:"upstreams"`
}

type upstreamRoute struct {
	up   Upstream
	base *url.URL
}

// Gateway returns an http.Handler implementing the protected reverse proxy.
func (s *Shepherd) Gateway(opt GatewayOptions) http.Handler {
	base := "/" + strings.Trim(opt.Mount, "/")
	if base == "/" {
		base = "/gw"
	}
	routes := make(map[string]upstreamRoute, len(opt.Upstreams))
	for _, u := range opt.Upstreams {
		u.Prefix = strings.Trim(u.Prefix, "/")
		if u.Prefix == "" {
			continue
		}
		parsed, err := url.Parse(u.Target)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue // invalid targets are skipped at build time
		}
		routes[u.Prefix] = upstreamRoute{up: u, base: parsed}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Locate the route.
		after := strings.TrimPrefix(r.URL.Path, base) // "/orders/123"
		segments := strings.SplitN(strings.TrimPrefix(after, "/"), "/", 2)
		route, ok := routes[segments[0]]
		if !ok || segments[0] == "" {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "no upstream for " + r.URL.Path})
			return
		}
		restPath := "/"
		if len(segments) == 2 && segments[1] != "" {
			restPath = "/" + segments[1]
		}

		// 2. Firewall.
		if s.f != nil {
			d := s.f.Evaluate(r, s.ClientIP(r))
			if !d.Allowed {
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error": "request denied by firewall", "rule_id": d.RuleID})
				return
			}
		}

		// 3. Authentication + authorization. Public upstreams are still
		//    enriched when the caller happens to present a valid token.
		var claims *token.Claims
		if route.up.Public {
			if c, _, _ := s.authenticate(r); c != nil {
				claims = c
			}
		} else {
			c, code, msg := s.authenticate(r)
			if c == nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="shepherd"`)
				writeJSON(w, code, map[string]any{"error": msg})
				return
			}
			if !grantsAll(*c, route.up.Scopes) {
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error": "missing required scope(s)", "required": route.up.Scopes})
				return
			}
			claims = c
		}

		// 4. Rate limit (IP always; subject too when authenticated).
		if s.lim != nil {
			if !s.limiterAllow(w, "ip:"+s.ClientIP(r)) {
				return
			}
			if claims != nil && !s.limiterAllow(w, "sub:"+claims.Subject) {
				return
			}
		}

		// 5. Query enhancement: shepherd injects claims-derived parameters
		//    the backend needs, without overwriting caller-supplied ones.
		if claims != nil {
			q := r.URL.Query()
			for param, field := range route.up.QueryEnrich {
				if q.Get(param) != "" {
					continue
				}
				if v, ok := claimsValue(*claims, field); ok {
					q.Set(param, v)
				}
			}
			r.URL.RawQuery = q.Encode()
		}

		// 6. Body digest for the gateway signature. The signature covers the
		//    final proxied request — method, rewritten path (r.URL.Path, the
		//    decoded form the backend receives), enriched query, client IP,
		//    timestamp and body digest — so the backend can recompute and
		//    verify it exactly against what it sees.
		ts := time.Now().Unix()
		var digest []byte
		if route.up.MaxBody != -1 {
			maxBody := route.up.MaxBody
			if maxBody == 0 {
				maxBody = DefaultMaxBody
			}
			body, err := readBody(r, maxBody)
			if err != nil {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": err.Error()})
				return
			}
			sum := sha256.Sum256(body)
			digest = sum[:]
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}

		// 7. Enrichment headers + request signature.
		targetPath := route.base.Path + restPath
		if targetPath == "" {
			targetPath = "/"
		}
		ip := s.ClientIP(r)
		r.Header.Set("X-Shepherd-Client", ip)
		r.Header.Set("X-Shepherd-Time", strconv.FormatInt(ts, 10))
		r.Header.Set("X-Shepherd-Path", r.URL.Path)
		if claims != nil {
			setClaimsHeaders(r, claims)
		}
		canonical := canonicalLine(r.Method, targetPath, r.URL.RawQuery, ip, ts, digest)
		r.Header.Set("X-Shepherd-Signature", s.tokens.Signer().Sign(canonical))
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			r.Header.Set("X-Forwarded-For", v+", "+ip)
		} else {
			r.Header.Set("X-Forwarded-For", ip)
		}

		// 8. Reverse-proxy to the backend.
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = route.base.Scheme
				req.URL.Host = route.base.Host
				req.URL.Path = targetPath
				req.Host = route.base.Host
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error": "upstream unreachable", "upstream": route.up.Name,
					"detail": err.Error()})
			},
		}
		proxy.ServeHTTP(w, r)
	})
}

// limiterAllow consumes a rate-limit token, writing 429 on denial. It reports
// whether the request may continue.
func (s *Shepherd) limiterAllow(w http.ResponseWriter, key string) bool {
	ok, _, _ := s.lim.Allow(key)
	if ok {
		return true
	}
	w.Header().Set("X-RateLimit-Key", key)
	writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded"})
	return false
}

// readBody reads at most max bytes from r.Body. Exceeding the cap returns an
// error so the handler can answer 413.
func readBody(r *http.Request, max int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > max {
		return nil, errBodyTooLarge
	}
	return buf, nil
}

// claimsValue resolves a claims field name to a string value.
func claimsValue(c token.Claims, field string) (string, bool) {
	switch field {
	case "sub":
		return c.Subject, true
	case "scopes":
		if len(c.Scopes) > 0 {
			return strings.Join(c.Scopes, ","), true
		}
	case "roles":
		if len(c.Roles) > 0 {
			return strings.Join(c.Roles, ","), true
		}
	case "jti":
		return c.ID, true
	case "block":
		if c.Block != "" {
			return c.Block, true
		}
	case "aud":
		return c.Audience, true
	case "exp":
		return strconv.FormatInt(c.ExpiresAt, 10), true
	}
	if v, ok := c.Meta[field]; ok {
		return v, true
	}
	return "", false
}
