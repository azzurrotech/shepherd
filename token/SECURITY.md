# token — Security

This document describes the security properties of
`azzurrotech/shepherd/token` as implemented. It makes no claims beyond what the
code actually does.

## Assets protected

- The **master signing secret** — the only key needed to mint or verify tokens.
- The **integrity and authenticity of capability claims** (subject, scopes,
  roles, audience, block id, validity window).
- **Subject privacy** — `sub` and `jti` are opaque random identifiers; the
  package stores no mapping to a person.

## Threat model

In scope:

- An attacker who can read or modify a token in transit must not be able to
  alter its claims or fabricate a new token without the secret.
- An attacker must not be able to use a token outside its validity window or
  against the wrong audience.
- Weak or short master secrets must be rejected at construction.

Out of scope:

- Revocation and replay of *valid, unexpired* regular tokens; this package is
  stateless and every signed token verifies until `exp`. Callers add
  revocation via `azzurrotech/shepherd/revoke`.
- Confidentiality of claims. The payload is only base64url-encoded and is
  readable by anyone holding the token; only integrity is protected.
- Transport security. Run behind TLS.

## Mitigations actually implemented

- **Signature**: `(*Manager).sign` serializes claims with `json.Marshal` and
  emits `base64url(payload).base64url(HMAC-SHA256(secret, base64url(payload)))`
  using `(*Manager).mac`. `Verify` recomputes the MAC over the presented
  payload string.
- **Constant-time comparison**: `Verify` rejects mismatches with
  `hmac.Equal(expected, sig)`, avoiding timing leaks on the signature.
- **Version gating**: `Verify` rejects any `Claims.Version != Version`.
- **Validity window**: `Claims.Valid` enforces `nbf <= now < exp`; `Verify`
  distinguishes `ErrExpired` from `ErrNotYetValid`.
- **Audience binding**: when both sides set an audience, a mismatch yields
  `ErrWrongAudience`.
- **Secret length floor**: `NewManager` returns `ErrWeakSecret` for secrets
  shorter than `MinSecretLen` (16 bytes) and copies the secret with
  `append([]byte(nil), secret...)`.
- **Randomness**: subjects, token ids and block ids come from
  `RandomBytes`/`RandomID`, which use `crypto/rand`.
- **Magic-link flagging**: `VerifyMagic` refuses tokens that do not carry the
  `mag` claim (`ErrNotMagic`).

## Honest limits / non-claims

- **No replay protection here.** Any valid, unexpired token can be presented
  repeatedly. Single-use is implemented only by the magic-link path in the
  `middleware`/`revoke` packages, and only in memory.
- **No revocation here.** Revoking a `jti` or `blk` requires an external deny
  list checked by the caller.
- **Claims are not confidential.** Do not place secrets in `Meta` or other
  claims.
- **Scope wildcard is literal.** `HasScope` treats a claim of `"*"` as matching
  any scope; callers should avoid issuing `"*"` unintentionally.
- **`Signer.Sign` output is hex**, not base64. Backends that verify gateway
  signatures must reproduce the hex encoding exactly.
- **Clock dependence.** Validity is computed from `time.Now()` (or the
  manager's `now` hook); hosts with skewed clocks can reject valid tokens.
- **The master secret is the crown jewel.** Anyone holding it can mint
  arbitrary tokens; it is not derivable or rotatable within this package.

## Dependencies

Standard library only:
`crypto/hmac`, `crypto/rand`, `crypto/sha256`, `encoding/base64`,
`encoding/hex`, `encoding/json`, `errors`, `fmt`, `strings`, `time`. No third
party packages.

## Reporting

Report security issues privately to **security@azzurro.tech**. Do not open a
public issue. Include the shepherd version, the mode (server/middleware), and a
minimal reproduction.
