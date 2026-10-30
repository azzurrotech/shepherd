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
| **Identity-less IAM** | Self-contained capability tokens (HMAC-SHA256, JWT-like shape, no external libs) carrying scopes/roles with RBAC semantics. No user store, no accounts, no PRII. |
| **Block key generation** | Mint a batch of keys that share one `blk` block id — revoke the whole batch with one call. |
| **Magic links** | Issue a one-shot link; redemption consumes it (in-memory) and yields a fresh session capability. |
| **Revocation** | Stateless tokens are validated against an in-memory deny list (by `jti`, or by block id). No database. |
| **Firewall** | Ordered allow/deny rules on method, path glob, client IP/CIDR, and required headers. Optional default-deny. |
| **Rate limiting** | Token bucket per client IP (and per subject when authenticated). All in-memory. |
| **JS encryption keys** | Derive 32-byte raw key material (WebCrypto AES-GCM `raw` format) from the master secret — nothing stored, key reproducible, intended for browser-side encryption/decryption. |
| **Enhancing gateway** | Protect + front a backend API via reverse proxy: query params injected from claims, `X-Shepherd-*` headers added, and an HMAC-SHA256 request signature the backend can verify. |
| **Security enforcement** | Blocks and drops requests that are invalid, above rate limits, fail validation/debouncing, or otherwise pose potential security issues (default-deny capable, in-memory deny lists, input validation). |

**Two deployment modes:**

1. **Server mode** — run the `shepherd` binary as a standalone Go HTTP server
   (default port `8084`).
2. **Middleware mode** — import `azzurrotech/shepherd/middleware` inside any
   other Go server and wrap your own `http.Handler`s. See
   [`examples/middleware-demo`](examples/middleware-demo/main.go) for a complete
   host server with a gated inline API, a gateway to a separate "orders" backend,
   and magic-link redemption.

---

## Security model

shepherd is a **security-first** component built to the same standards the
[MDN Web Security guide](https://developer.mozilla.org/en-US/docs/Web/Security)
and the [Go security documentation](https://go.dev/doc/security/) call for:
least privilege, deny by default where it matters, defense in depth, no trusted
input, and a minimal dependency surface.

### Identity-free by construction

- **No identity is stored, ever.** There is no user table, no username, no
  email, no session ledger. A token carries an opaque `sub` (a random
  `crypto/rand` identifier) plus the *capabilities* it grants; nothing maps
  that `sub` back to a person inside shepherd.
- **Capabilities, not accounts.** Authorization is **RBAC over scopes and
  roles** carried in the signed token and checked statelessly by the verifier.
  A subject is only ever "what it may do".
- **Least privilege is the default shape.** A token is scoped to the exact
  actions it needs; unauthenticated upstreams are opt-in (`public`), and the
  firewall can be flipped to **default-deny**.

### What is enforced on every request

shepherd's request pipeline (used by both the server and the middleware)
inspects and, where appropriate, **blocks and drops** traffic:

1. **Input validation / malformed requests** — missing or malformed tokens,
   wrong version, bad signature, expired or not-yet-valid tokens, wrong
   audience, or tokens failing revocation checks are rejected (never partially
   trusted).
2. **Firewall** — ordered allow/deny rules on method, path glob, source
   IP/CIDR and required headers; with `-default-deny` anything not explicitly
   allowed is dropped.
3. **Rate limiting** — an in-memory token bucket per client IP (and per
   subject once authenticated). Over-limit requests are dropped with
   `429 Too Many Requests` and a `Retry-After`.
4. **Debouncing / duplicate suppression** — repeated or immediately replayed
   identical traffic is coalesced and dropped rather than forwarded, so a
   client cannot amplify load by hammering the same request.
5. **Potential security issues** — anything that would otherwise be risky
   (unknown principal, revoked `jti`/`blk`, failed authorization, signature
   mismatch on the response path) is denied before it reaches a backend.

Rejections are explicit and uniform: `401` for a missing/invalid/revoked
token, `403` for a firewall or authorization denial, `429` for rate limiting.
Nothing silently degrades to "allow".

### Crypto and dependency hygiene

- **Standard library only.** `crypto/hmac`, `crypto/sha256`, `crypto/rand`,
  `crypto/subtle` and friends — no third-party crypto, no supply-chain surface
  to audit, and `go.mod` has zero `require` lines (a core recommendation of the
  Go security guidance and of MDN's supply-chain section).
- **Constant-time comparison** for signatures (`hmac.Equal`), a **minimum
  secret length**, and **opaque random identifiers** for `sub`/`jti`/block ids.
- **No secrets in tokens**: a capability token grants access, so treat it as a
  bearer credential; transport security (TLS) is expected to be terminated in
  front. Claims are integrity-protected, not encrypted.
- **No database** means no SQL injection, no ORM, and no persistent credential
  store to leak; all deny/rate state is in memory and lost on restart by design
  (see [Operational notes](#operational-notes)).

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
-debounce duration
                  duplicate/replay suppression window for identical requests
                  (default 250ms, 0 = off)
-debounce-max int
                  max in-flight identical requests before extra ones are dropped
                  (default 4)
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
| `POST /api/provider/authenticate` | Identity-free provider call: present a token, receive the principal (`subject`, `scopes`, `roles`) or a refusal. pod-compatible. |
| `POST /api/keys/regenerate` | Regenerate the tokens owned by a credential. Body: `username`, `password`. Fixed credentials → deterministic token derivation; **no username is stored**. |
| `GET /api/track/<token>` | Resolve a token to the **item/ownership** it tracks (subject, scopes, block, issuance) without revealing identity. |
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
  "debounce": { "window_ms": 250, "max_inflight": 4 },
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

### RBAC — scopes and roles

Access control is **role-based access control (RBAC)** expressed as
capabilities, with no user directory behind it:

- A **scope** names an action or resource (`read:orders`, `write:orders`,
  `item:admin`, or the wildcard `*`). Scopes are the primary unit of
  authorization.
- A **role** is a named bundle of scopes (`member`, `admin`), checked by
  prefixing `role:` in a required list or via `Claims.HasRole`.
- **Checked statelessly** by the verifier from the signed claims — no lookup,
  no session table. `Authorize`/`required` refuses when the claims lack the
  scope (or role), returning `403`.
- **Least privilege** is achieved by minting tokens with only the scopes they
  need; a block of keys can be revoked as a unit when a role is retired.

### Block keys

`POST /api/keys/block` returns many keys that each carry their own `sub` but a
shared `blk`. One `POST /api/revoke/block {"block":"…"}` invalidates them all.

### Shares (the `capability` package)

Applications rarely need "a token with scopes"; they need "hand a colleague a
revocable pointer to one named thing". `shepherd/capability` is that operation
over the normal token manager:

```go
share, err := capability.Issue(mgr, capability.IssueOptions{
    Target: capability.Target{Kind: "item", ID: "item-1"}, // the app's own nouns
    TTL:    time.Hour,
})
target, claims, err := capability.Resolve(mgr, share.Token) // read side
err = capability.RevokeRaw(mgr, shepherd, share.Token)      // cancel by value
```

- The share is a capability **record**, not an access-control decision: the kind
  and id live in the token's `meta`, and the application decides what they mean.
- `Issue` returns the token's `jti` (`Share.JTI`), so a caller that kept the
  issue-time response can revoke with `Revoke(revoker, share)`.
- `RevokeRaw` resolves a token string to its `jti` and expiry and adds it to
  shepherd's deny list, so cancellation works from a value alone. Revocation is
  the platform's normal in-memory deny entry: durable only for the life of the
  process.
- `Revoker` is the one method a share needs (`RevokeToken(jti, expiresAt)`);
  `middleware.Shepherd` implements it, and so does any store that keeps a deny
  list.

### Token tracking — ownership without identity

A token is how shepherd tracks **ownership of an item** without ever learning
*who* the owner is. Because the `sub` is an opaque random identifier, the
mapping "this item belongs to this subject" is a statement about a capability,
not a person:

- **Track an item by presenting its token.** `GET /api/track/<token>` (and
  `ClaimsFromContext` in middleware mode) resolves the token to the subject,
  scopes, roles, block and issuance window that own the item. The store keeps
  `item → subject`, never `item → username`.
- **Ownership is checked, not looked up in a directory.** A write to an item is
  allowed only when the presented token's `sub` matches the recorded owner (or
  a scope such as `item:admin` grants override). No account list is consulted.
- **Blocks group ownership.** Every token in a batch shares a `blk`, so
  ownership of a set of items can be tracked and revoked together.

### Token regeneration with fixed credentials

Tokens can be **regenerated on demand** so a client that loses or rotates its
capability can obtain a fresh, equivalent one:

- `POST /api/keys/regenerate {"username":"…","password":"…"}` re-derives the
  token whose capability set is bound to that credential.
- The derivation is **deterministic and secret-keyed**
  (`HMAC-SHA256(master_secret, domain || username || password)`), so the same
  fixed username and password always reproduce the same capability — no
  server-side record is required.
- **No username details are ever saved.** shepherd does not persist the
  username, the password, a hash of either, or any credential record. The
  credential is used only as KDF input for the duration of the call; the
  resulting token remains identity-free (its `sub` is still random/derived and
  carries no username). Rotating the master secret invalidates all derived
  tokens at once.
- Regeneration never widens privilege: it reproduces exactly the scopes/roles
  the credential was provisioned for, and can be disabled per-deployment.

### Request vetting, debouncing and dropping

shepherd **blocks and drops** any request that should not proceed, rather than
forwarding and hoping a backend re-checks it:

- **Invalid** — malformed/missing token, signature or version mismatch, wrong
  audience, outside the `nbf`/`exp` window, or a revoked `jti`/`blk`:
  `401 Unauthorized`.
- **Unauthorized** — the token verifies but does not grant the required
  scopes/roles (or the firewall denies it): `403 Forbidden`.
- **Above rate limit** — the token bucket is empty for that client IP /
  subject: `429 Too Many Requests`, with `Retry-After` and
  `X-RateLimit-Remaining`.
- **Failing debouncing** — a request that is a duplicate/replay of one already
  in flight (same key + body digest within the debounce window), or that trips
  a volume/velocity threshold, is coalesced or dropped instead of being
  processed.
- **Otherwise risky** — empty or oversized bodies, unexpected methods, or
  requests that fail content validation are rejected before any backend work.
- **Default-deny** — with `-default-deny`, anything the firewall does not
  explicitly allow is dropped by default.

Dropped requests are never queued for later delivery and never reach the
upstream, so a misbehaving client cannot use shepherd as an amplifier.

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

## Auth provider (pod-compatible)

pod's README exposes an **auth helper** so a host can plug in *any* identity
provider (`pod.NewAuth(pod.AuthOptions{Authenticate: …})` / `auth.Wrap(h)`).
shepherd implements the same provider shape on its side, so the two are
**interchangeable**: shepherd is the identity-free provider for a pod-backed
site, and a pod-style provider can supply subjects to shepherd.

The provider contract is deliberately small and transport-agnostic — resolve a
request to an **identity-free principal**, or refuse it:

```go
// shepherd/provider — the same shape pod's AuthOptions.Authenticate expects.
type Principal struct {
    Subject string   // opaque; shepherd never stores who this is
    Scopes  []string // RBAC capabilities
    Roles   []string
}

type Provider interface {
    // Authenticate resolves a request to a principal, or returns an error.
    Authenticate(r *http.Request) (Principal, error)
    // Wrap gates a handler with the provider (401 on refusal).
    Wrap(h http.Handler) http.Handler
}

// FromCapability adapts shepherd's capability tokens to the provider contract.
func FromCapability(m *token.Manager) Provider
```

Compatibility rules:

- **Same `Authenticate(r) (Principal, error)` signature.** Drop a
  `shepherd.Provider` into pod's `AuthOptions.Authenticate` (returning
  `pod.Principal` with `Subject`/`Scopes`/`Roles`) and pod's HTML UI, JSON/XML
  API, uploads and share links are governed by shepherd — including its RBAC
  and rate limiting — with **no identity stored anywhere**.
- **Same principal fields.** Both sides speak `Subject` + `Scopes` + `Roles`,
  so a policy written for pod (`Policy(p, table, action)`) evaluates directly
  against a shepherd principal.
- **One token, two consumers.** The token pod receives is exactly the
  capability token shepherd issued and verifies; no second session format is
  introduced.
- **Deny is compatible too.** When shepherd's provider refuses (missing /
  invalid / revoked token, or over rate limit), it returns an error and `Wrap`
  responds `401`/`429`; pod renders that as an auth failure rather than an open
  page.

In **server mode** the same provider is exposed over HTTP at
`POST /api/provider/authenticate` (send the candidate token, receive the
principal or a refusal), so non-Go hosts get the identical contract.

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
- `Provider() Provider` — the identity-free auth provider compatible with pod's
  `AuthOptions.Authenticate`, plus `TrackToken(raw)` for item/ownership lookup
  and `Regenerate(username, password)` for credential-keyed token regeneration.
- `Debounce(window, maxInflight)` — duplicate/replay suppression wrapper.

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
- **Security posture.** Following [Go security best practices](/go.dev/doc/security/) and [web security guidance](https://developer.mozilla.org/en-US/docs/Web/Security), shepherd rejects malformed/expired/revoked tokens, enforces scoped RBAC, applies firewall allow/deny with default-deny capability, drops requests exceeding limits or failing validation/debouncing, and uses constant-time HMAC signature verification with proper secret length enforcement. Transport security (TLS) is expected to be terminated in front; claims are integrity-protected but not encrypted.

---

## Implementation status

The [Security model](#security-model),
[Auth provider](#auth-provider-pod-compatible),
[Token tracking](#token-tracking--ownership-without-identity),
[Token regeneration](#token-regeneration-with-fixed-credentials) and
[Request vetting](#request-vetting-debouncing-and-dropping) sections above are
the **implemented contract**, not an aspiration. The whole surface is present
and covered by tests:

- The `provider/` package (`Principal`, `Provider`, `FromCapability`, `Wrap`),
  the `debounce/` package, `POST /api/provider/authenticate`, `POST
  /api/keys/regenerate` and `GET /api/track/<token>` are all implemented.
- The `capability/` package (`Issue`, `Resolve`, `Revoke`, `RevokeRaw`,
  `Share.JTI`) turns the token manager into the revocable named-share operation
  applications actually use.
- Capability tokens (HMAC-SHA256, versioned claims, opaque `sub`/`jti`),
  scopes/roles authorization, block keys, magic links, revocation, the
  firewall, the per-IP/subject token-bucket rate limiter, the debouncer, the JS
  WebCrypto key derivation, the enriching + signing gateway, and the
  `X-Shepherd-*` headers are all implemented.

Verify with:

```sh
go build ./... && go vet ./... && go test -race ./...
```

## Threat model and crypto inventory

- **Protected:** master signing secret; integrity/authenticity of capability
  claims (subject, scopes, roles, audience, block, validity window); subject
  privacy (`sub`/`jti` are opaque random identifiers; no stored mapping).
- **In scope:** tamper-proofing a token in transit, enforcing the validity
  window and audience, rejecting weak secrets, constant-time signature
  comparison, and dropping invalid / over-limit / debounce-failing requests.
- **Out of scope:** revocation and replay of *valid, unexpired* regular tokens
  without the in-memory deny store; confidentiality of claims (base64url only —
  integrity is protected, not secrecy); transport security (run behind TLS); and
  any reliance on identity, since none is stored.

Crypto inventory (standard library only): `crypto/hmac` + `crypto/sha256`
(token signatures, request signatures, KDF), `hmac.Equal` (constant-time
compare), `crypto/rand` (subjects, token ids, nonces), `crypto/subtle` where
guarded comparisons are needed. No third-party cryptography and no database.

---

## Layout

```
main.go, server.go     server mode (flags, HTTP API, config file)
middleware/            importable middleware mode (auth, firewall, rate limit,
                       enrich, gateway)
provider/              identity-free auth provider (pod-compatible Authenticate/Wrap)
token/                 capability token engine (issue/verify/blocks/magic links,
                       token tracking + credential-keyed regeneration)
firewall/              ordered allow/deny rules
ratelimit/             token-bucket limiter
debounce/              duplicate/replay suppression and drop policy
revoke/                in-memory deny store (revocations + once-use)
keys/                  CSPRNG, HMAC KDF, JS WebCrypto key derivation
examples/middleware-demo/  self-contained middleware-mode host server
shepherd.json          sample config file
```

