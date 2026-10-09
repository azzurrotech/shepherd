# middleware — Security

This document describes the security properties of
`azzurrotech/shepherd/middleware` as implemented. It makes no claims beyond the
code.

## Assets protected

- The **master signing secret** (`Config.Secret`) — signs tokens, request
  signatures, the admin token and derived JS keys.
- **Protected host handlers and gateway upstreams** — access is gated by
  capability scope/role.
- The **integrity of the request a backend receives** — claims, query and body
  are covered by an HMAC signature.
- **Revocation and once-use state** (`revoke.Store`) and **rate-limit state**
  (`ratelimit.Limiter`).

## Threat model

In scope:

- **Forged or tampered tokens** presented via `Authorization: Bearer`,
  `X-Shepherd-Token`, or the `shepherd_cap` cookie.
- **Replay** of a revoked token id/block id or a consumed magic link.
- **Unauthorized access** to a scoped handler or non-public upstream.
- **Floods** against protected routes.
- **Tampering with the proxied request** between the gateway and the backend.
- **Scope escalation** through query-parameter injection.

Out of scope:

- TLS/transport security — run behind a TLS terminator.
- Durable revocation or rate limiting across restarts and replicas.
- Protecting a host that trusts enriched `X-Shepherd-*` headers from a source
  other than shepherd.

## Mitigations actually implemented

- **Token verification**: `Shepherd.authenticate` calls `tokens.Verify`, which
  checks the HMAC-SHA256 signature with `hmac.Equal` (constant-time compare),
  the version, the validity window and the audience.
- **Revocation check**: after verification, `authenticate` rejects the request
  when `deny.Denied(claims.ID)` or the block id is present.
- **Single-use magic links**: `VerifyMagicToken` runs `tokens.VerifyMagic`,
  checks the deny store, then calls `deny.Consume(claims.ID, claims.ExpiresAt)`
  so a replay within the process is rejected with `token.ErrInvalidToken`.
- **Authorization**: `Authorize`/`grantsAll` require every listed scope, with
  `role:<name>` satisfied by `Claims.HasRole`; scope wildcard `"*"` is honored
  by `Claims.HasScope`.
- **Gateway ordering**: the gateway applies the firewall, then authentication
  and scope checks (unless the upstream is `Public`), then the rate limit,
  before proxying.
- **Request signature**: `Gateway` and `Enrich` set `X-Shepherd-Signature`
  using `token.Signer.Sign` over `canonicalLine`, covering
  `method|targetPath|rawQuery|clientIP|unixTime|sha256hex(body)`;
  `RequestSignature` lets the backend recompute it.
- **Query injection safety**: `QueryEnrich` only sets a parameter when the
  caller did not already supply it (`q.Get(param) != ""`), preventing caller
  override of injected values.
- **Body bound**: `readBody` reads at most `max+1` bytes and returns
  `errBodyTooLarge` above the cap (413), so signature hashing cannot buffer
  unbounded data.
- **Rate limiting**: `LimitsPerMinute`/`Burst` drive an in-memory token bucket
  keyed by `ip:<client>` and (when authenticated) `sub:<subject>`.
- **Randomness**: issued subjects, token ids and block ids come from
  `crypto/rand` (`token.RandomID`).
- **Private context key**: `ctxKey` is unexported, so claims in the request
  context cannot be forged by external code.
- **Cookie hygiene** (server mode): the `shepherd_cap` session cookie is set
  `HttpOnly`, `SameSite=Lax`, and `Secure` when TLS is detected.

## Honest limits / non-claims

- **In-memory state.** Revocations, once-used magic links and rate-limit
  buckets live only in the process. A restart forgets them: a token revoked
  before restart validates again until its `exp`, a consumed link can be
  replayed, and the rate budget resets. `Config.Deny` accepts a shared
  `revoke.Store`, but that store is itself in-memory.
- **Not shared across replicas.** Each instance has its own deny and limiter
  state; horizontal scaling multiplies the effective rate budget.
- **Trusted proxy header is dangerous if misconfigured.** When
  `Config.ClientIPHeader` is set, `ClientIP` trusts the first value of that
  header. If the edge proxy does not overwrite it, clients can spoof their IP
  and evade IP-based firewall rules and rate limits.
- **The master secret is the crown jewel.** Anyone holding it can mint tokens,
  compute gateway signatures and derive the admin token. `AdminToken` is a
  deterministic KDF of the secret — rotating the secret rotates everything.
- **`Enhance` headers are only meaningful in-process.** They are trustworthy
  because shepherd authenticated the request in the same server; they are not
  independently signed. Use the gateway `X-Shepherd-Signature` (hex!) when a
  separate backend must trust the request. Note that `Signer.Sign` returns
  **lowercase hex**, not base64.
- **The signature does not cover all headers.** Only method, target path, raw
  query, client IP, timestamp and body digest are signed; `X-Shepherd-*` claim
  headers are covered indirectly through the token, not by the request MAC.
- **Firewall default-allow.** Unless the configured firewall is default-deny,
  requests matching no rule pass.
- **`Optional` is not authentication.** It injects claims only when a valid
  token is present, but never rejects a request.
- **Body size cap.** The gateway rejects bodies over `MaxBody`/`DefaultMaxBody`
  (16 MiB); `MaxBody == -1` disables body hashing, so the body is not covered
  by the signature.
- **No compliance claims.** This document claims nothing about SOC 2, HIPAA,
  GDPR, PCI or any other regime.

## Dependencies

Standard library only plus sibling packages in the same module:
`context`, `crypto/hmac`, `crypto/sha256`, `encoding/hex`, `encoding/json`,
`fmt`, `net/http`, `net/http/httputil`, `net/url`, `strconv`, `strings`,
`time`, and `azzurrotech/shepherd/{firewall,keys,ratelimit,revoke,token}`. No
third-party packages.

## Reporting

Report security issues privately to **security@azzurro.tech**. Do not open a
public issue. Include the shepherd version, the mode (server/middleware), and a
minimal reproduction.
