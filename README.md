# shepherd

**Security without identification** — an identity-less (zero-knowledge) IAM,
software firewall, API rate limiter, block-key generator, magic-link issuer,
and an *enhancing reverse-proxy gateway*.

Everything is **standard library Go only** (`go.mod` has zero `require` lines),
uses **no database**, and stores **no identifying data**. Instead of who you are,
a capability token says *what you may do*. The system has complete privacy for its
subjects: an opaque, random subject per key, and nothing else.

© Azzurro Technology Inc. — MIT.

---

## What shepherd does

| Concern | How it works |
|---|---|
| **Identity-less IAM** | Self-contained capability tokens (HMAC-SHA256, JWT-like shape, no external libs) carrying scopes/roles. No user store, no accounts, no PRII. |
| **Block key generation** | Mint a batch of keys that share one `blk` block id — revoke the whole batch with one call. |
| **Magic links** | Issue a one-shot link; redemption consumes it (in-memory) and yields a fresh session capability. |
| **Revocation** | Stateless tokens are validated against an in-memory deny list (by `jti`, or by block id). No database. |
| **Firewall** | Ordered allow/deny rules on method, path glob, client IP/CIDR, and required headers. Optional default-deny. |
| **Rate limiting** | Token bucket per client IP (and per subject when authenticated). All in-memory. |
| **JS encryption keys** | Derive 32-byte raw key material (WebCrypto AES-GCM `raw` format) from the master secret — nothing stored, key reproducible, intended for browser-side encryption/decryption. |
| **Enhancing gateway** | Protect + front a backend API via reverse proxy: query params injected from claims, `X-Shepherd-*` headers added, and an HMAC-SHA256 request signature the backend can verify. |

**Two deployment modes:**

1. **Server mode** — run the `shepherd` binary as a standalone Go HTTP server
   (default port `8084`).
2. **Middleware mode** — import `azzurrotech/shepherd/middleware` inside any
   other Go server and wrap your own `http.Handler`s. See
   [`examples/middleware-demo`](examples/middleware-demo/main.go) for a complete
   host server with a gated inline API, a gateway to a separate "orders" backend,
   and magic-link redemption.

---

## Quick start (server mode)

```sh
go build .
# Deterministic admin token + keys: provide a secret (>=16 bytes) or set
# SHEPHERD_SECRET. Without one, an ephemeral secret is generated and everything
# dies with the process.
./shepherd -port 8084 -secret 0123456789abcdef0123456789abcdef
```

The banner prints the **admin token** — send it as `X-Shepherd-Admin` on every
management call:

```
shepherd 0.1.0 - identity-less IAM, firewall, rate limiter, gateway
listening on :8084
issuer:         azzurrotech/shepherd
firewall:       0 rules, default allow
rate limit:     per client (IP) with in-memory token bucket
admin token (send as X-Shepherd-Admin): 5dc8e532…9a3f
```

Worked example:

```sh
ADMIN=<token from the banner>
H='Content-Type: application/json'

# 1. Issue a capability key
TOK=$(curl -s -X POST localhost:8084/api/keys -H "$H" -H "X-Shepherd-Admin: $ADMIN" \
  -d '{"scopes":["read:orders"],"roles":["member"],"ttl":"1h"}' | jq -r .token)

# 2. Register a backend behind the gateway
curl -s -X POST localhost:8084/api/upstreams -H "$H" -H "X-Shepherd-Admin: $ADMIN" \
  -d '{"name":"orders","prefix":"orders","target":"http://localhost:9100",
       "scopes":["read:orders"],
       "query_enrich":{"uid":"sub","scopes":"scopes"}}' >/dev/null

# 3. Call the protected API through the gateway (enriched + signed)
curl -s localhost:8084/gw/orders/summary -H "Authorization: Bearer $TOK"

# 4. Revoke it
curl -s -X POST localhost:8084/api/revoke -H "$H" -H "X-Shepherd-Admin: $ADMIN" \
  -d "{\"token\":\"$TOK\"}"
```

---

## Server mode: CLI

```
-port string      listen port (default "8084")
-secret string    master signing secret, hex or raw bytes
                  (fallback: SHEPHERD_SECRET env var; empty = ephemeral secret)
-issuer string    token issuer name
-audience string  default capability audience
-config string    JSON config file (firewall / rate / upstreams)
-rate float       rate limit per minute per client (default 120, 0 = off)
-burst float      rate limiter burst (default 30)
-default-deny     firewall denies by default
-trust-proxy-header string
                  trust this header for the real client IP (e.g. X-Forwarded-For)
                  — only set behind a proxy you control
-version          show version
-help             show help
```

## Server mode: HTTP API

All management endpoints require `X-Shepherd-Admin: <admin token>`.

| Method & path | Purpose |
|---|---|
| `GET /` | Small HTML index (API map). |
| `GET /health` | Liveness. |
| `POST /api/keys` | Issue a capability key. Body: `scopes`, `roles`, `ttl`, `audience`, `meta`. |
| `POST /api/keys/block` | Issue a block of N keys (one opaque subject each, shared `blk`). |
| `POST /api/keys/magic` | Issue a magic link. Body: `next` (relative redirect target). Reply contains the `verify` URL. |
| `GET /api/keys/javascript?scope=…&usage=encrypt\|sign` | Derive a JS key: WebCrypto AES-GCM `raw` (base64) or HMAC key for signature. |
| `GET /verify?t=<magic-token>` | Redeem a magic link: consumes it, issues a fresh `shepherd_cap` session cookie, redirects to `next` (must be relative / same-host). |
| `POST /api/token/verify` | Verify a token. Body: `token` (or `Authorization: Bearer`). |
| `POST /api/revoke` | Revoke a token. Body: `token`. |
| `POST /api/revoke/block` | Revoke a whole block. Body: `block`. |
| `GET\|POST /api/firewall/rules` | List / create rules. Body: `name`, `action` (`allow`/`deny`), `methods`, `path_glob`, `sources`, `headers`. |
| `GET\|PUT\|DELETE /api/firewall/rules/{id}` | Read / toggle / delete a rule. |
| `GET /api/ratelimit/status` | Per-key limiter status. |
| `POST /api/ratelimit/reset` | Reset the limiter. |
| `GET\|POST /api/upstreams` | List / register gateway backends. |
| `GET\|PUT\|DELETE /api/upstreams/{prefix}` | Read / replace / remove a backend. |
| `<mount>/<prefix>/*` | The gateway proxy (default mount `/gw`). |

### Config file (`-config shepherd.json`)

Firewall rules, rate limits and upstreams can be pre-loaded from JSON so they
are live from the first request:

```json
{
  "firewall": {
    "default_allow": true,
    "rules": [{ "name": "block debug", "action": "deny", "path_glob": "/debug/**" }]
  },
  "rate": { "per_minute": 120, "burst": 30 },
  "upstreams": [
    { "name": "orders", "prefix": "orders", "target": "http://localhost:9100",
      "scopes": ["read:orders"], "query_enrich": { "uid": "sub" } }
  ]
}
```

See [`shepherd.json`](shepherd.json) for a fuller example.

---

## Concepts

### Capability tokens

Format: `<base64url(payload)>.<base64url(HMAC-SHA256(secret, payload))>` — the
signature is computed over the base64url payload bytes, a JWT-style envelope with
no external library.

Claims:

```
v     version (1)        sub   opaque random subject (one per key)
iss   issuer             aud   audience      scp   scopes
rol   roles              iat   issued at     exp   expiry
jti   unique id          blk   block id      mag   magic-link flag
nxt   magic-link redirect target   meta      arbitrary k/v for enrichment
```

Scopes are the whole authorization story, checked **statelessly** by the
verifier. To check *role*-based rules, prefix the role with `role:` when calling
`Authorize` / `required` scopes — e.g. `required: ["role:admin"]`.

### Block keys

`POST /api/keys/block` returns many keys that each carry their own `sub` but a
shared `blk`. One `POST /api/revoke/block {"block":"…"}` invalidates them all.

### Magic links

`POST /api/keys/magic {"next":"/dashboard"}` returns a `verify` URL. Opening it
consumes the link (in-process once-use), issues a fresh capability as the
`shepherd_cap` cookie, and redirects to `next`. Only relative / same-host
targets are allowed. `next` is also honoured in **middleware mode** via
`MagicLinkHandler` + `ClaimsFromContext`.

### JavaScript encryption keys

`GET /api/keys/javascript?scope=chat` derives a deterministic 32-byte key
(`HMAC-SHA256(secret, "…")`, purpose-namespaced) and returns it as WebCrypto
AES-GCM `raw` (base64) plus `iv_length` — directly usable with
`crypto.subtle.importKey("raw", …)` in the browser. `usage=sign` returns a
matching HMAC key for signatures. Nothing is stored; the key is re-derivable
from the master secret.

### The gateway ("enhance a query and pass it correctly to a given point")

For each proxied request shepherd:

1. applies the **firewall**,
2. **authenticates** the capability token (unless the upstream is `public`),
3. authorizes the upstream's `scopes`,
4. **rate-limits** by client IP (and subject),
5. **enriches the query** — injects claims fields as query parameters the
   backend needs (`query_enrich`, e.g. `{"uid":"sub","tenant":"meta.tenant"}`),
   never overwriting caller-supplied ones,
6. adds **`X-Shepherd-*` headers**: `Subject`, `Scopes`, `Roles`, `Token-Id`,
   `Block`, `Audience`, `Client`, `Time`, `Path`, and **`Signature`**,
7. signs the **final proxied request** with HMAC-SHA256 over:

```
method|decodedPath|rawQuery|clientIP|unixTime|sha256hex(body)
```

`decodedPath` and `rawQuery` are exactly what the backend receives
(`r.URL.Path` / `r.URL.RawQuery` in Go), and the body digest covers the buffered
body, so a backend can recompute and compare the signature with a shared secret
and a bounded clock skew — the same pattern as verified webhooks.

That is the whole promise: **the request that arrives downstream carries its own
proof, and the enriched query is correctly passed to the given point.**

Example backend verification (Go, stdlib):

```go
func verifyShepherd(r *http.Request, secret []byte, skew time.Duration) bool {
    mac := hmac.New(sha256.New, secret)
    body, _ := io.ReadAll(r.Body)
    sum := sha256.Sum256(body)
    line := fmt.Sprintf("%s|%s|%s|%s|%s|%x",
        r.Method, r.URL.Path, r.URL.RawQuery,
        r.Header.Get("X-Shepherd-Client"),
        r.Header.Get("X-Shepherd-Time"), sum[:])
    mac.Write([]byte(line))
    got := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
    if !hmac.Equal([]byte(got), []byte(r.Header.Get("X-Shepherd-Signature"))) {
        return false
    }
    ts, _ := strconv.ParseInt(r.Header.Get("X-Shepherd-Time"), 10, 64)
    return abs(time.Now().Unix()-ts) <= int64(skew.Seconds())
}
```

---

## Middleware mode

`azzurrotech/shepherd/middleware` provides `New(cfg)` → `*Shepherd` with:

- `Firewall(...)`, `RateLimit(...)`, `Authenticate(...)`, `Optional(...)`,
  `Authorize(scopes...)`, `Gate(required, h)`, `Enhance(h)` — composable
  `http.Handler` wrappers.
- `Gateway(GatewayOptions{Mount, Upstreams})` — the protecting proxy in one
  handler.
- `Issue`, `Manager()`, `VerifyMagicToken`, `MagicLinkHandler(next)`,
  `ClaimsFromContext(ctx)` for linking a host's own session flow.
- `JSCryptoKey(scope, usage)`, `AdminToken()`, `RevokeToken`, `RevokeBlock`,
  `RateLimitStatus/Reset/Cleanup`, `CleanupRevocations`, `RequestSignature`.

```go
s, err := middleware.New(middleware.Config{
    Secret:          []byte("0123456789abcdef0123456789abcdef"),
    Issuer:          "my-host",
    LimitsPerMinute: 60,
})
mux.Handle("/api/orders", s.Gate([]string{"read:orders"}, ordersHandler))
mux.Handle("/gw/", s.Gateway(middleware.GatewayOptions{
    Mount: "/gw",
    Upstreams: []middleware.Upstream{{
        Name: "orders", Prefix: "orders", Target: "http://localhost:9100",
        Scopes: []string{"read:orders"},
        QueryEnrich: map[string]string{"uid": "sub"},
    }},
}))
```

Run `examples/middleware-demo` to see the full flow: gated inline handler,
gateway to a separate backend (which reads the enriched headers), and
magic-link redemption into a session cookie.

---

## Build, test, image

```sh
go build ./...
go vet ./...
go test -race ./...
```

`Dockerfile` builds a static, cgo-free image from `golang:1.20-alpine` and
`EXPOSE 8084`. Run it with the CLI flags above.

```sh
docker build -t azzurrotech/shepherd .
docker run --rm -e SHEPHERD_SECRET=... -p 8084:8084 azzurrotech/shepherd -port 8084
```

---

## Operational notes

- **In-memory only.** Revocations, consumed magic links, and rate-limit state
  live in process memory. A restart forgets them (tokens themselves remain
  valid until their `exp`). This is a property, not a bug: shepherd is
  deliberately stateless and has no database.
- **Client IP.** Take the client IP from the socket by default. If you run
  behind a proxy you control and it overwrites `X-Forwarded-For`, pass
  `-trust-proxy-header X-Forwarded-For`. Never trust that header from the
  open internet.
- **Reloads.** Editing the config file does not hot-reload; restart the process
  or use `/api/firewall/rules` and `/api/upstreams` for live changes.
- **Ports.** This module defaults to `8084` (both the binary and the
  Dockerfile). If you wire it into the atp/stenella compose stack, map it
  consistently.

---

## Layout

```
main.go, server.go     server mode (flags, HTTP API, config file)
middleware/            importable middleware mode (auth, firewall, rate limit,
                       enrich, gateway)
token/                 capability token engine (issue/verify/blocks/magic links)
firewall/              ordered allow/deny rules
ratelimit/             token-bucket limiter
revoke/                in-memory deny store (revocations + once-use)
keys/                  CSPRNG, HMAC KDF, JS WebCrypto key derivation
examples/middleware-demo/  self-contained middleware-mode host server
shepherd.json          sample config file
```

See [`SECURITY.md`](SECURITY.md) for the threat model, crypto inventory, and
deployment guidance.