# middleware — identity-less IAM, firewall, rate limit and enhancing gateway

`azzurrotech/shepherd/middleware` lets any standard-library Go HTTP server be
protected by shepherd in "middleware mode": a host server owns its mux and
wraps its own `http.Handler`s with shepherd's `Firewall`, `RateLimit`,
`Authenticate`, `Authorize` and `Enhance` wrappers (all plain `http.Handler`
middleware). It also hosts the `Gateway` reverse proxy.

## Overview

The package lives in the `azzurrotech/shepherd` module and is the same code
path that backs shepherd's standalone server mode (`server.go` constructs a
`middleware.Shepherd` in `NewServer`). Everything is identity-less and
stateless: the only thing a host holds is the signing secret, and a capability
token carries both authentication and authorization inside itself. No database
is touched.

```go
import "azzurrotech/shepherd/middleware"

s, _ := middleware.New(middleware.Config{Secret: []byte("...32 random bytes...")})
mux.Handle("/api/", s.Gate([]string{"read:orders"}, ordersHandler))
mux.Handle("/gw/", s.Gateway(middleware.GatewayOptions{...}))
```

`New` builds a `token.Manager`, an optional `ratelimit.Limiter` and a
`revoke.Store`, and wires an optional `firewall.Firewall`; the wrappers and the
gateway all share those instances.

## Public API

### Constants

- `const DefaultIssuer = "azzurrotech/shepherd"` — issuer used when
  `Config.Issuer` is empty.
- `const DefaultTTL = 24 * time.Hour` — default issued-token lifetime.
- `const CookieName = "shepherd_cap"` — capability cookie accepted by
  `TokenFromRequest` and set by server-mode `/verify`.
- `const DefaultMaxBody = 16 << 20` — 16 MiB cap on the body buffered for the
  gateway signature when `Upstream.MaxBody == 0`.

`defaultBurst` (5), `adminPurpose` (`"shepherd:admin:v1"`) and
`errBodyTooLarge` are unexported.

### Types

- `type Config struct` — `Secret []byte` (>= `token.MinSecretLen`),
  `Issuer string`, `Audience string`, `DefaultTTL time.Duration`,
  `Firewall *firewall.Firewall`, `LimitsPerMinute float64`, `Burst float64`,
  `Deny *revoke.Store`, `ClientIPHeader string`.
- `type Shepherd struct` — a configured middleware instance.
- `type Upstream struct` — one protected backend:
  `Name string` (`name`), `Prefix string` (`prefix`), `Target string`
  (`target`), `Public bool` (`public`), `Scopes []string` (`scopes,omitempty`),
  `QueryEnrich map[string]string` (`query_enrich,omitempty`),
  `MaxBody int64` (`max_body,omitempty`).
- `type GatewayOptions struct` — `Mount string` (`mount`, default `/gw/`) and
  `Upstreams []Upstream` (`upstreams`).

### Construction and wiring

- `func New(cfg Config) (*Shepherd, error)` — builds the instance; fails when
  the secret is too short.
- `func (s *Shepherd) Manager() *token.Manager` — the underlying token manager.
- `func (s *Shepherd) Issue(opts token.IssueOptions) (string, token.Claims, error)`
  — issue through the manager.
- `func (s *Shepherd) Issuer() string` — configured issuer.
- `func (s *Shepherd) AdminToken() string` — deterministic, secret-derived
  admin token (hex of `HMAC-SHA256(secret, "shepherd:admin:v1" \x00 "admin")`).
- `func (s *Shepherd) JSCryptoKey(scope, usage string) (keys.JSCryptoKey, error)`
  — `""`/`"encrypt"` → `keys.JSDerivedAES`, `"sign"` → `keys.JSHMAC`.
- `func (s *Shepherd) RandomJSCryptoKey(scope string) (keys.JSCryptoKey, error)`
  — fresh random AES key.

### Identity, tokens and context

- `func (s *Shepherd) ClientIP(r *http.Request) string` — trusted proxy header
  (first value) when configured, else `firewall.ClientIP(r.RemoteAddr)`.
- `func (s *Shepherd) TokenFromRequest(r *http.Request) string` — finds a
  token in `Authorization: Bearer`, then `X-Shepherd-Token`, then the
  `shepherd_cap` cookie.
- `func ClaimsFromContext(ctx context.Context) (token.Claims, bool)` — extracts
  claims injected by `Authenticate`/`Authorize`/`Gate` (private context key).

### Handler middleware

- `func (s *Shepherd) Firewall(next http.Handler) http.Handler` — evaluate the
  firewall; 403 on deny.
- `func (s *Shepherd) RateLimit(next http.Handler) http.Handler` — per-IP token
  bucket; 429 with `Retry-After` and `X-RateLimit-Remaining`.
- `func (s *Shepherd) Authenticate(next http.Handler) http.Handler` — require a
  valid, non-revoked token; injects claims.
- `func (s *Shepherd) Optional(next http.Handler) http.Handler` — inject claims
  when a valid token is present, otherwise pass through.
- `func (s *Shepherd) Authorize(scopes ...string) func(http.Handler) http.Handler`
  — require every scope; a `"role:<name>"` scope is satisfied by the role.
- `func (s *Shepherd) Gate(required []string, next http.Handler) http.Handler` —
  compose `Authorize(required...)` → `RateLimit` → `Firewall` (outermost first).
- `func (s *Shepherd) Enhance(next http.Handler) http.Handler` — add
  `X-Shepherd-*` headers when claims are in the context.
- `func (s *Shepherd) MagicLinkHandler(next http.Handler) http.Handler` —
  consume `?t=<token>` and hand redeemed claims to `next`.

### Magic links and revocation

- `func (s *Shepherd) VerifyMagicToken(raw string) (token.Claims, error)` —
  `token.VerifyMagic`, deny-list check, then once-use `Consume`.
- `func (s *Shepherd) RevokeToken(jti string, expiresAt int64)` /
  `func (s *Shepherd) RevokeBlock(blockID string, expiresAt int64)` — revoke a
  token / block until the given expiry.
- `func (s *Shepherd) IsDenied(id string) bool` — query the deny store;
  `func (s *Shepherd) CleanupRevocations()` prunes expired deny entries.
- `func (s *Shepherd) RateLimitStatus(key string) (ratelimit.Status, bool)` —
  snapshot for a key (`ok == false` when limiting is disabled).
- `func (s *Shepherd) RateLimitReset()` /
  `func (s *Shepherd) RateLimitCleanup(idleFor time.Duration)` — drop all
  buckets / prune buckets idle for `idleFor`.

### Gateway and signatures

- `func (s *Shepherd) Gateway(opt GatewayOptions) http.Handler` — the
  protecting, enriching reverse proxy.
- `func (s *Shepherd) RequestSignature(method, decodedPath, rawQuery, ip string, ts int64, body []byte) string`
  — recomputable backend signature (lowercase hex).

## Gateway behavior

For each request the gateway: locates the upstream by the first path segment
after the mount (unknown → 404); evaluates the firewall (403); authenticates
and authorizes non-public upstreams (401/403) while public ones still enrich
when a valid token is present; rate-limits by `ip:<client>` and, when
authenticated, `sub:<subject>` (429 with `X-RateLimit-Key`); injects
`QueryEnrich` parameters without overwriting caller-supplied ones; computes a
body digest (unless `MaxBody == -1`) within the cap; sets `X-Shepherd-Client`,
`-Time`, `-Path`, the claim headers (`-Subject`, `-Scopes`, `-Roles`,
`-Token-Id`, `-Block`, `-Audience`) and `X-Shepherd-Signature`; then
reverse-proxies.

`QueryEnrich` values resolve against `Claims` fields `sub`, `scopes`, `roles`,
`jti`, `block`, `aud`, `exp`, or a key of `Meta`. The signature is
`Signer.Sign(canonicalLine(...))` over
`method|targetPath|rawQuery|clientIP|unixTime|sha256hex(body)`, where
`targetPath` is the path the backend receives (`route.base.Path + restPath`),
`rawQuery` is the enriched query, and the digest is `sha256(nil)` when no body
is hashed. `RequestSignature` recomputes the same value.

## Configuration, inputs, defaults and limits

- **Secret**: required, >= `token.MinSecretLen` (16) bytes. `New` copies it.
- **Issuer**: `Config.Issuer`, default `DefaultIssuer`.
- **Audience**: applied via `WithAudience` only when non-empty; empty means
  "any".
- **Default TTL**: applied via `WithTTL` only when `Config.DefaultTTL > 0`;
  otherwise the token manager's 24h applies (equal to `DefaultTTL`).
- **Rate limiting**: enabled only when `Config.LimitsPerMinute > 0`; bursts
  below 1 fall back to `defaultBurst` (5).
- **Deny store**: `Config.Deny` may be shared; when nil a private
  `revoke.NewStore()` is created.
- **Client IP**: `ClientIPHeader` is trusted verbatim (first comma-separated
  value) when set — only behind a proxy you control.
- **Gateway mount**: leading/trailing slashes are trimmed; a mount of `""` or
  `"/"` becomes `/gw`.
- **Upstreams**: invalid prefixes or unparsable targets are skipped at build
  time (server-mode registration validates them and rejects them).
- **Body cap**: `MaxBody == 0` → `DefaultMaxBody` (16 MiB); `-1` disables body
  hashing; a larger body yields 413.
- **`Gate` order**: `Authorize(...)(RateLimit(Firewall(next)))` — at request
  time, authorization runs first, then rate limiting, then the firewall.

## Testing

From the module root `/home/matthew/Projects/Platform/stenella/atp/shepherd`:

```sh
go test ./middleware/
go test -race ./middleware/
```

`middleware_test.go` covers the authenticate flow (missing/garbage/valid/
revoked tokens), scope and `role:` authorization, firewall + `Gate`, rate
limiting inside `Gate`, `Optional` + `Enhance` header injection, magic-link
issue/verify/replay rejection and `MagicLinkHandler`, deterministic
`AdminToken`, token-source priority, context claim round-trip, and the gateway
(routing, path rewrite, query enrichment, header injection including a
backend-side signature recomputation, unauthenticated rejection, 404 for
unknown upstreams, public upstreams, and the 413 body cap).

## Design notes and invariants

- The context key (`ctxKey`) is private to the package, so claims cannot be
  forged by outside code; only the wrappers inject them.
- `authenticate` verifies the signature with the token manager and then checks
  `deny.Denied(claims.ID)` and the block id.
- `VerifyMagicToken` consumes the link after a successful check, so a second
  redemption is rejected while the process runs.
- `Shepherd` holds the same secret that signs tokens and gateway request
  signatures, keeping both consistent.
- `AdminToken` is deterministic for a given secret and identity-less:
  possession of the token is the whole admin identity.
- The gateway reuses `httputil.ReverseProxy`; upstream errors are mapped to 502
  with a JSON body.
