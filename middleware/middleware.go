// Package middleware lets any standard-library Go HTTP server be protected by
// shepherd in "middleware mode": a host server owns its mux and wraps its own
// http.Handlers with shepherd's Firewall, RateLimit, Authenticate, Authorize
// and Enhance wrappers (all plain http.Handler middleware).
//
// The same package backs shepherd's standalone server mode, so the two modes
// share one code path and one behavioural contract:
//
//	import "azzurrotech/shepherd/middleware"
//
//	s, _ := middleware.New(middleware.Config{Secret: []byte("...32 random bytes...")})
//	mux.Handle("/api/", s.Gate([]string{"read:orders"}, ordersHandler))
//	mux.Handle("/gw/", s.Gateway(middleware.GatewayOptions{...}))
//
// Everything is identity-less and stateless: the only thing a host holds is
// the signing secret, and a capability token carries both authentication and
// authorization inside itself. No database is touched.
package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"azzurrotech/shepherd/firewall"
	"azzurrotech/shepherd/keys"
	"azzurrotech/shepherd/ratelimit"
	"azzurrotech/shepherd/revoke"
	"azzurrotech/shepherd/token"
)

// Defaults and shared constants.
const (
	DefaultIssuer = "azzurrotech/shepherd"
	DefaultTTL    = 24 * time.Hour
	defaultBurst  = 5
	// CookieName is the cookie the standalone server and the gateway accept
	// as a capability transport (set after magic-link redemption).
	CookieName = "shepherd_cap"
)

// KDF purposes (namespaced so scopes cannot collide across uses).
const (
	adminPurpose = "shepherd:admin:v1"
)

// Config wires the middleware instance.
type Config struct {
	// Secret is the master signing secret (HMAC-SHA256). Must be at least
	// token.MinSecretLen bytes. It signs tokens and gateway request
	// signatures, and derives the admin + JavaScript keys.
	Secret []byte
	// Issuer names the token issuer (default DefaultIssuer).
	Issuer string
	// Audience is the default audience embedded in issued tokens. Empty
	// means "any" (verification does not check audience).
	Audience string
	// DefaultTTL is the default lifetime of issued tokens.
	DefaultTTL time.Duration

	// Firewall, when non-nil, is applied by Gate and Gateway.
	Firewall *firewall.Firewall
	// LimitsPerMinute enables an in-process token-bucket limiter keyed by
	// client IP. Zero disables rate limiting.
	LimitsPerMinute float64
	// Burst is the limiter's burst size (default 5).
	Burst float64

	// Deny is an optional shared in-memory revocation/once-use store. When
	// nil a private store is created.
	Deny *revoke.Store

	// ClientIPHeader, when set (e.g. "X-Forwarded-For"), is trusted as the
	// source of the real client IP. Only set this when shepherd sits behind
	// a proxy you control that overwrites the header.
	ClientIPHeader string
}

// Shepherd is a configured instance of the middleware.
type Shepherd struct {
	tokens *token.Manager
	f      *firewall.Firewall
	lim    *ratelimit.Limiter
	deny   *revoke.Store
	ipHdr  string
	issuer string
	secret []byte
}

// New builds a Shepherd from cfg.
func New(cfg Config) (*Shepherd, error) {
	secret := append([]byte(nil), cfg.Secret...)
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = DefaultIssuer
	}
	mgr, err := token.NewManager(secret, issuer)
	if err != nil {
		return nil, err
	}
	if cfg.Audience != "" {
		mgr.WithAudience(cfg.Audience)
	}
	if cfg.DefaultTTL > 0 {
		mgr.WithTTL(cfg.DefaultTTL)
	}
	s := &Shepherd{
		tokens: mgr,
		f:      cfg.Firewall,
		deny:   cfg.Deny,
		ipHdr:  cfg.ClientIPHeader,
		issuer: issuer,
		secret: secret,
	}
	if s.deny == nil {
		s.deny = revoke.NewStore()
	}
	if cfg.LimitsPerMinute > 0 {
		burst := cfg.Burst
		if burst < 1 {
			burst = defaultBurst
		}
		s.lim = ratelimit.New(cfg.LimitsPerMinute, burst)
	}
	return s, nil
}

// Manager exposes the underlying token manager (issue/verify/batch).
func (s *Shepherd) Manager() *token.Manager { return s.tokens }

// Issue creates a capability token through the manager.
func (s *Shepherd) Issue(opts token.IssueOptions) (string, token.Claims, error) {
	return s.tokens.Issue(opts)
}

// Issuer returns the configured issuer string.
func (s *Shepherd) Issuer() string { return s.issuer }

// RateLimitStatus returns a snapshot for a limiter key. ok is false when rate
// limiting is disabled.
func (s *Shepherd) RateLimitStatus(key string) (ratelimit.Status, bool) {
	if s.lim == nil {
		return ratelimit.Status{}, false
	}
	return s.lim.Status(key), true
}

// RateLimitReset drops all rate-limit buckets.
func (s *Shepherd) RateLimitReset() {
	if s.lim != nil {
		s.lim.Reset()
	}
}

// RateLimitCleanup prunes limiter buckets idle for longer than idleFor.
func (s *Shepherd) RateLimitCleanup(idleFor time.Duration) {
	if s.lim != nil {
		s.lim.Cleanup(idleFor)
	}
}

// CleanupRevocations prunes expired revocation/consumption entries.
func (s *Shepherd) CleanupRevocations() {
	s.deny.Cleanup()
}

// IsDenied reports whether a token id or block id is currently revoked or
// already consumed.
func (s *Shepherd) IsDenied(id string) bool {
	return s.deny.Denied(id)
}

// RevokeToken marks a token id revoked until its natural expiry.
func (s *Shepherd) RevokeToken(jti string, expiresAt int64) {
	s.deny.RevokeToken(jti, expiresAt)
}

// RevokeBlock marks every token carrying a block id revoked until its natural
// expiry.
func (s *Shepherd) RevokeBlock(blockID string, expiresAt int64) {
	s.deny.RevokeBlock(blockID, expiresAt)
}

// JSCryptoKey returns a deterministic key for browser JavaScript software
// served by shepherd (AES-GCM raw key for usage "encrypt", HMAC-SHA256 raw
// key for usage "sign"). The key is derived from the master secret and the
// scope: same scope ⇒ same key, no storage needed.
func (s *Shepherd) JSCryptoKey(scope, usage string) (keys.JSCryptoKey, error) {
	switch usage {
	case "", keys.PurposeEncrypt:
		return keys.JSDerivedAES(s.secret, scope)
	case keys.PurposeSign:
		return keys.JSHMAC(s.secret, scope)
	default:
		return keys.JSCryptoKey{}, fmt.Errorf("unknown usage %q", usage)
	}
}

// RandomJSCryptoKey returns a fresh, random AES-GCM key for JavaScript use.
func (s *Shepherd) RandomJSCryptoKey(scope string) (keys.JSCryptoKey, error) {
	return keys.JSRandomAES(scope)
}

// AdminToken derives the deterministic admin capability used by the standalone
// server's management endpoints (identity-less bootstrapping: possession of
// the token is the entire identity).
func (s *Shepherd) AdminToken() string {
	return hex.EncodeToString(derive(s.secret, adminPurpose, "admin"))
}

// ClientIP resolves the caller's IP, honoring the trusted proxy header when
// configured.
func (s *Shepherd) ClientIP(r *http.Request) string {
	if s.ipHdr != "" {
		if v := r.Header.Get(s.ipHdr); v != "" {
			first := strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
			if first != "" {
				return first
			}
		}
	}
	return firewall.ClientIP(r.RemoteAddr)
}

// TokenFromRequest finds a presented capability token: Authorization Bearer
// header, X-Shepherd-Token header, or the shepherd_cap cookie, in that order.
func (s *Shepherd) TokenFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if c, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(c)
		}
	}
	if t := r.Header.Get("X-Shepherd-Token"); t != "" {
		return t
	}
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// ctxKey is private so nobody outside the package can forge claims.
type ctxKey struct{}

// ClaimsFromContext extracts claims injected by Authenticate/Authorize/Gate.
func ClaimsFromContext(ctx context.Context) (token.Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(token.Claims)
	return c, ok
}

func withClaims(ctx context.Context, c token.Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// authenticate validates the presented token and checks the revocation store.
func (s *Shepherd) authenticate(r *http.Request) (*token.Claims, int, string) {
	raw := s.TokenFromRequest(r)
	if raw == "" {
		return nil, http.StatusUnauthorized, "missing capability token"
	}
	claims, err := s.tokens.Verify(raw)
	if err != nil {
		return nil, http.StatusUnauthorized, "invalid capability token: " + err.Error()
	}
	if s.deny.Denied(claims.ID) || (claims.Block != "" && s.deny.Denied(claims.Block)) {
		return nil, http.StatusUnauthorized, "capability revoked"
	}
	return &claims, 0, ""
}

// Firewall evaluates the configured rule set, denying on a deny match.
func (s *Shepherd) Firewall(next http.Handler) http.Handler {
	if s.f == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := s.f.Evaluate(r, s.ClientIP(r))
		if !d.Allowed {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "request denied by firewall", "rule_id": d.RuleID})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimit applies the in-process token bucket keyed by client IP.
func (s *Shepherd) RateLimit(next http.Handler) http.Handler {
	if s.lim == nil {
		return next
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := "ip:" + s.ClientIP(r)
		ok, remaining, resetAt := s.lim.Allow(key)
		if !ok {
			retry := int(resetAt.Sub(time.Now()).Seconds())
			if retry < 1 {
				retry = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "rate limit exceeded", "retry_after": resetAt.Unix()})
			return
		}
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(int(remaining)))
		next.ServeHTTP(w, r)
	})
	return h
}

// Authenticate requires a valid, non-revoked capability token and stores its
// claims in the request context.
func (s *Shepherd) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, code, msg := s.authenticate(r)
		if claims == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="shepherd"`)
			writeJSON(w, code, map[string]any{"error": msg})
			return
		}
		next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), *claims)))
	})
}

// Optional injects claims when a valid token is presented and otherwise lets
// the request through untouched (for endpoints that serve both).
func (s *Shepherd) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw := s.TokenFromRequest(r); raw != "" {
			if claims, err := s.tokens.Verify(raw); err == nil &&
				!s.deny.Denied(claims.ID) &&
				!(claims.Block != "" && s.deny.Denied(claims.Block)) {
				r = r.WithContext(withClaims(r.Context(), claims))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Authorize returns middleware that requires the presented claims to grant
// every scope. A scope of the form "role:<name>" is satisfied by the matching
// role claim instead.
func (s *Shepherd) Authorize(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, code, msg := s.authenticate(r)
			if claims == nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="shepherd"`)
				writeJSON(w, code, map[string]any{"error": msg})
				return
			}
			if !grantsAll(*claims, scopes) {
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error": "missing required scope(s)", "required": scopes})
				return
			}
			next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), *claims)))
		})
	}
}

// Gate composes the full protection chain for a protected handler:
// firewall → rate limit → authenticate → authorize.
func (s *Shepherd) Gate(required []string, next http.Handler) http.Handler {
	h := s.Firewall(next)
	h = s.RateLimit(h)
	h = s.Authorize(required...)(h)
	return h
}

// Enhance decorates a request with X-Shepherd-* headers an upstream can trust
// after shepherd has authenticated it. Claims must be in the context.
func (s *Shepherd) Enhance(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims, ok := ClaimsFromContext(r.Context()); ok {
			s.enrichHeaders(r, &claims, s.ClientIP(r), time.Now().Unix(), nil)
		}
		next.ServeHTTP(w, r)
	})
}

// VerifyMagicToken validates a magic-link token, enforces once-use when a
// store is available, and returns its claims. It is the primitive used by
// both server-mode /verify and middleware-mode host flows.
func (s *Shepherd) VerifyMagicToken(raw string) (token.Claims, error) {
	claims, err := s.tokens.VerifyMagic(raw)
	if err != nil {
		return token.Claims{}, err
	}
	if s.deny.Denied(claims.ID) {
		return token.Claims{}, token.ErrInvalidToken
	}
	// Redeem (once-use): the token id is consumed. Replays are discarded
	// while this process runs.
	s.deny.Consume(claims.ID, claims.ExpiresAt)
	return claims, nil
}

// MagicLinkHandler consumes a magic link (?t=<token>) and hands a request with
// the redeemed claims in its context to next. The host decides what to do next
// (render a page, set its own cookie, redirect).
func (s *Shepherd) MagicLinkHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("t")
		if tok == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing magic link token"})
			return
		}
		claims, err := s.VerifyMagicToken(tok)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid magic link: " + err.Error()})
			return
		}
		next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
	})
}

// setClaimsHeaders writes the identity-less claim headers an upstream trusts
// after shepherd authentication.
func setClaimsHeaders(r *http.Request, claims *token.Claims) {
	r.Header.Set("X-Shepherd-Subject", claims.Subject)
	if len(claims.Scopes) > 0 {
		r.Header.Set("X-Shepherd-Scopes", strings.Join(claims.Scopes, ","))
	}
	if len(claims.Roles) > 0 {
		r.Header.Set("X-Shepherd-Roles", strings.Join(claims.Roles, ","))
	}
	r.Header.Set("X-Shepherd-Token-Id", claims.ID)
	if claims.Block != "" {
		r.Header.Set("X-Shepherd-Block", claims.Block)
	}
	if claims.Audience != "" {
		r.Header.Set("X-Shepherd-Audience", claims.Audience)
	}
}

// enrichHeaders decorates a request with claim headers, the client/time
// headers and a request signature over the incoming path (the path the
// downstream handler will itself observe). Used by the Enhance middleware.
func (s *Shepherd) enrichHeaders(r *http.Request, claims *token.Claims, ip string, ts int64, bodyHash []byte) string {
	setClaimsHeaders(r, claims)
	r.Header.Set("X-Shepherd-Client", ip)
	r.Header.Set("X-Shepherd-Time", strconv.FormatInt(ts, 10))
	canonical := canonicalLine(r.Method, r.URL.Path, r.URL.RawQuery, ip, ts, bodyHash)
	sig := s.tokens.Signer().Sign(canonical)
	r.Header.Set("X-Shepherd-Signature", sig)
	return sig
}

// RequestSignature lets an upstream recompute a gateway request signature for
// its own verification:
//
//	HMAC-SHA256(secret, method|decodedPath|rawQuery|clientIP|unixTime|sha256hex(body))
//
// decodedPath is the path exactly as the upstream received it (r.URL.Path in
// Go servers); rawQuery is the query string as received.
func (s *Shepherd) RequestSignature(method, decodedPath, rawQuery, ip string, ts int64, body []byte) string {
	hash := sha256.Sum256(body)
	return s.tokens.Signer().Sign(canonicalLine(method, decodedPath, rawQuery, ip, ts, hash[:]))
}

func canonicalLine(method, escPath, rawQuery, ip string, ts int64, bodyHash []byte) string {
	digest := hex.EncodeToString(bodyHash)
	if digest == "" {
		d := sha256.Sum256(nil)
		digest = hex.EncodeToString(d[:])
	}
	return method + "|" + escPath + "|" + rawQuery + "|" + ip + "|" + strconv.FormatInt(ts, 10) + "|" + digest
}

// derive is the local HMAC-SHA256 KDF over the master secret.
func derive(master []byte, purpose, scope string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(scope))
	return mac.Sum(nil)
}

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// grantsAll reports whether claims satisfies every required scope.
func grantsAll(c token.Claims, scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if strings.HasPrefix(s, "role:") {
			if !c.HasRole(strings.TrimPrefix(s, "role:")) {
				return false
			}
			continue
		}
		if !c.HasScope(s) {
			return false
		}
	}
	return true
}
