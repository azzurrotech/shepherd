# Shepherd Security

Shepherd is an **identity-less (zero-knowledge) IAM**: security without
identification. This document describes what the code actually does — the crypto,
the threat model, the guarantees, and the honest limits. It deliberately makes
**no** claims the code does not keep.

- Standard library Go only. No external dependencies, no database.
- **No identifying data is ever stored.** Subjects are opaque random tokens
  (`crypto/rand`); nothing maps them back to a person.
- All long-lived state is the *lack* of state: authorization lives in
  self-contained signed tokens.

---

## Threat model

Shepherd protects **your APIs and downstream backends** from requests that lack
a capability, exceed a rate, violate a firewall rule, or have been tampered
with in transit *through* the gateway.

What it is **not**:

- Not an encryption-at-rest store (it has no database by design).
- Not a password/identity directory, MFA, or SSO provider. Magic links are an
  auth *method*, and the session it establishes is a capability, not a person.
- Not a substitute for TLS on the wire. Run shepherd behind a TLS-terminating
  reverse proxy (e.g. Caddy) in production.

In-scope threats:

| Threat | Mitigation |
|---|---|
| Forged capability tokens | HMAC-SHA256 signature bound to the master secret. Verified with `hmac.Equal` (constant-time compare). |
| Replay of a revoked token / consumed magic link | In-memory deny list keyed by `jti` / `blk`; magic links are single-use until process restart. |
| Unauthorized access to a protected backend | Stateless scope/role authorization on every gateway request; firewall + rate limit applied before proxying. |
| Tampered queries | The gateway signs the **final** proxied request (path, enriched query, client IP, time, body digest), so the backend detects any modification. |
| Scrapers / floods | Per-IP token-bucket rate limiter (and per-subject when authenticated). |
| Weak randomness | All subjects, ids, block ids, salts, ephemeral secrets via `crypto/rand`. |
| Mismanaged master secret | The admin token (and JS keys) are HMAC-KDF-derived from the secret; the banner prints the admin token at startup. Rotate the secret to invalidate everything. |

---

## Crypto inventory

| Use | Mechanism | Where |
|---|---|---|
| Token signature | `HMAC-SHA256` over the base64url payload, JWT-like envelope `<payload>.<sig>` | `token/` |
| Gateway request signature | `HMAC-SHA256` over `method\|decodedPath\|rawQuery\|clientIP\|unixTime\|sha256hex(body)` | `middleware/` |
| Admin + JS key derivation | `HMAC-SHA256(secret, purpose \x00 scope)` KDF, purpose-namespaced | `middleware/`, `keys/` |
| Randomness | `crypto/rand` (`RandomBytes`, `RandomID`) | `keys/` |
| JS encryption keys | 32-byte raw key material for WebCrypto `AES-GCM` (`raw` format) or HMAC sign keys | `server.go` `/api/keys/javascript` |

Shepherd itself does not encrypt data at rest or in transit; it **supplies the
keys** for JavaScript software to encrypt/decrypt with WebCrypto AES-GCM, and it
**signs** requests/claims with HMAC-SHA256. AES encryption happens where the
data lives (client side), not inside shepherd.

---

## Guarantees (what you can rely on)

1. **Identity-less.** There is no user table, no username, no email, no PRII, no
   analytics of who you are. Only an opaque `sub` per key, generated at issue
   time and never correlated to a person. Restarting with a fresh ephemeral
   secret leaves *no* recoverable trace of issued keys.
2. **Stateless authorization.** Every token is self-contained and verifiable
   with the secret alone; no lookup required.
3. **Secret hygiene.** Provide a secret `>= 16 bytes` (32 recommended) via
   `-secret` or `SHEPHERD_SECRET`. Without one, an ephemeral `crypto/rand`
   secret is generated and everything signed dies with the process — safe by
   default, but useless across restarts.
4. **Magic links are one-shot.** Redemption consumes the link in memory and
   issues a fresh capability cookie (`shepherd_cap`, `HttpOnly`). The link
   itself cannot be reused within the process lifetime. Redirect targets must be
   relative / same-host — an open-redirect via `next` is not possible.
5. **The gateway proves itself downstream.** Backends receive
   `X-Shepherd-*` claim headers plus a signature over the request exactly as the
   backend observes it, so trust does not require trusting the network or the
   proxy hop.

---

## Deployment guidance

- **Always TLS.** Run shepherd behind a reverse proxy you control (Caddy/nginx)
  that terminates TLS. Only then consider
  `-trust-proxy-header X-Forwarded-For` — and ensure the proxy **overwrites**
  that header so clients cannot spoof it. From the open internet, keep the
  default (socket IP).
- **Secret management.** Pass the master secret via environment/file without
  embedding it in configs or images that others can read. Rotating the secret
  revokes every token and signature instantly.
- **Default-allow vs default-deny.** The firewall defaults to **allow**
  (`-default-deny` flips it). Deny-by-default is the safer posture for
  gateways exposed publicly; allow-by-default is convenient behind a trusted
  edge.
- **Time skew.** Backends verifying gateway signatures should allow a small
  clock skew (seconds) around `X-Shepherd-Time`.
- **Rate limiting** is per-process. Horizontal scaling resets the per-IP budget
  per instance; size your deployment accordingly.

---

## Honest limits (read before relying on it)

- **No persistence.** Revocations, link consumption, and rate-limit state are
  in memory. Restart → they are forgotten; a token that was revoked before the
  restart becomes valid again until its `exp`. A restarted magically-linked
  session invalidates only if its cookie expires. If you need durable
  revocation, add it behind shepherd (the deny list is a plain in-memory store —
  `middleware.Config.Deny` accepts a shared `revoke.Store` if you want to back
  it).
- **The master secret is the crown jewels.** Anyone who holds it can mint any
  token. Guard it accordingly.
- **JS keys are derivable by anyone who holds the secret** (they are pure KDF
  output). They are for *encrypting data belonging to the deployment*, not for
  secret-key distribution to browsers — a browser must still receive the key it
  will use, so treat delivery channel as part of your design.
- **Middleware trust boundaries.** When a host uses `Authenticate`/`Enhance`,
  downstream code must trust the host server — the enriched headers are
  meaningful only because shepherd authenticated the request in-process.
- **No compliance claims.** This document claims nothing about SOC 2, HIPAA,
  GDPR, PCI, or any other regime. Shepherd stores no personal data, which is the
  strong privacy posture — but compliance is your organization's job to assess.

---

## Reporting

Security issues: open a private report on the repository, or contact the
maintainers via the Azzurro Technology channel. Please include the shepherd
version, the mode (server / middleware), and a minimal reproduction.

© Azzurro Technology Inc. — MIT.