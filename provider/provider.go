// Package provider implements shepherd's identity-free auth provider: the same
// small contract that pod's AuthOptions.Authenticate expects, so shepherd is an
// interchangeable, database-less identity provider for a pod-backed site (and a
// pod-style provider can supply subjects to shepherd).
//
// The contract is deliberately minimal and transport-agnostic — resolve a
// request to an identity-free principal, or refuse it:
//
//	type Principal struct{ Subject string; Scopes, Roles []string }
//	type Provider interface {
//	    Authenticate(r *http.Request) (Principal, error)
//	    Wrap(h http.Handler) http.Handler
//	}
//
// shepherd never stores who a subject is: Subject is the opaque identifier that
// travels inside the capability token. Because both sides speak Subject +
// Scopes + Roles, a pod policy written for pod (Policy(p, table, action))
// evaluates directly against a shepherd principal, and pod's HTML UI, JSON/XML
// API, uploads and share links are governed by shepherd — including its RBAC
// and rate limiting — with no identity stored anywhere.
//
// Refusals are compatible too: a missing, invalid or revoked token returns an
// error and Wrap answers 401; an over-rate-limit request returns ErrRateLimited
// and Wrap answers 429. A pod host renders both as an auth failure rather than
// an open page.
//
// Everything here is standard library only.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"azzurrotech/shepherd/token"
)

// Principal is an identity-free caller: an opaque subject plus its RBAC
// capabilities. It mirrors pod's Principal (Subject/Scopes/Roles) field for
// field so the two are interchangeable.
type Principal struct {
	// Subject is opaque: shepherd never stores who this is.
	Subject string `json:"subject"`
	// Scopes are the RBAC capabilities carried by the token.
	Scopes []string `json:"scopes,omitempty"`
	// Roles are named capability bundles carried by the token.
	Roles []string `json:"roles,omitempty"`
}

// Provider resolves a request to a principal or refuses it. It is the exact
// shape pod's AuthOptions.Authenticate expects.
type Provider interface {
	// Authenticate resolves a request to a principal, or returns an error.
	Authenticate(r *http.Request) (Principal, error)
	// Wrap gates a handler with the provider (401, or 429 when rate limited, on
	// refusal).
	Wrap(h http.Handler) http.Handler
}

// Refusal errors. Wrap maps ErrRateLimited to 429 and everything else to 401.
var (
	// ErrNoToken means no capability token was presented.
	ErrNoToken = errors.New("provider: no capability token presented")
	// ErrInvalidToken means the presented token did not verify.
	ErrInvalidToken = errors.New("provider: invalid capability token")
	// ErrRevoked means the token verified but is revoked or already consumed.
	ErrRevoked = errors.New("provider: capability revoked")
	// ErrRateLimited means the caller exceeded the configured rate limit.
	ErrRateLimited = errors.New("provider: rate limit exceeded")
)

// DenyChecker is the minimal revocation view a provider needs. *revoke.Store
// satisfies it, which keeps this package free of a dependency cycle.
type DenyChecker interface {
	Denied(id string) bool
}

// Limiter is the minimal rate-limit view a provider needs. *ratelimit.Limiter
// satisfies it.
type Limiter interface {
	Allow(key string) (ok bool, remaining float64, resetAt time.Time)
}

// capability adapts shepherd capability tokens to the Provider contract.
type capability struct {
	m    *token.Manager
	deny DenyChecker
	lim  Limiter
}

// Option configures a provider built with New.
type Option func(*capability)

// WithDeny attaches a revocation store so revoked jti/blk values are refused.
func WithDeny(d DenyChecker) Option {
	return func(c *capability) { c.deny = d }
}

// WithLimiter attaches a rate limiter so over-limit requests are refused with
// ErrRateLimited (→ 429 from Wrap).
func WithLimiter(l Limiter) Option {
	return func(c *capability) { c.lim = l }
}

// FromCapability adapts shepherd's capability tokens to the provider contract.
// It is the constructor required by the shepherd/provider contract and is
// equivalent to New(m) with no extra options.
func FromCapability(m *token.Manager) Provider { return New(m) }

// New returns a Provider backed by token manager m. Attach a revocation store
// with WithDeny and a rate limiter with WithLimiter for the full behaviour.
func New(m *token.Manager, opts ...Option) Provider {
	c := &capability{m: m}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Authenticate resolves the caller's capability token to a Principal. It
// returns a refusal error (never a partially trusted principal) when the token
// is missing, invalid, revoked/consumed, or the caller is over a rate limit.
func (c *capability) Authenticate(r *http.Request) (Principal, error) {
	raw := TokenFromRequest(r)
	if raw == "" {
		return Principal{}, ErrNoToken
	}
	claims, err := c.m.Verify(raw)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if c.deny != nil && (c.deny.Denied(claims.ID) || (claims.Block != "" && c.deny.Denied(claims.Block))) {
		return Principal{}, ErrRevoked
	}
	if c.lim != nil {
		// Key by subject when we have one, otherwise by client IP. This mirrors
		// shepherd's per-subject / per-IP limiter.
		key := "sub:" + claims.Subject
		if claims.Subject == "" {
			key = "ip:" + ClientIP(r)
		}
		if ok, _, _ := c.lim.Allow(key); !ok {
			return Principal{}, ErrRateLimited
		}
	}
	return Principal{
		Subject: claims.Subject,
		Scopes:  append([]string(nil), claims.Scopes...),
		Roles:   append([]string(nil), claims.Roles...),
	}, nil
}

// Wrap gates h with the provider. A refusal is written as 401 (or 429 with a
// Retry-After when rate limited) and h is never called.
func (c *capability) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := c.Authenticate(r)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrRateLimited) {
				status = http.StatusTooManyRequests
				w.Header().Set("Retry-After", "1")
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="shepherd"`)
			writeJSON(w, status, map[string]any{"error": err.Error()})
			return
		}
		h.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// principalKey is private so nobody outside the package can forge a principal.
type principalKey struct{}

// WithPrincipal attaches a principal to a context. Wrap does this for hosts;
// it is exported so hosts that authenticate manually can do the same.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext extracts a principal stored by Wrap/WithPrincipal.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// TokenFromRequest finds a presented capability token in the Authorization
// Bearer header, the X-Shepherd-Token header, or the shepherd_cap cookie, in
// that order. It mirrors middleware.TokenFromRequest without importing
// middleware (which would create an import cycle).
func TokenFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if c, ok := strings.CutPrefix(h, "Bearer "); ok {
			if t := strings.TrimSpace(c); t != "" {
				return t
			}
		}
	}
	if t := r.Header.Get("X-Shepherd-Token"); t != "" {
		return t
	}
	if c, err := r.Cookie("shepherd_cap"); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// ClientIP resolves the caller's IP from the socket address, ignoring any
// proxy header (the provider is used in library form; middleware already
// handles trusted-proxy resolution for its own limiter).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
