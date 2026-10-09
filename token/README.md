# token — identity-less capability tokens

`azzurrotech/shepherd/token` is the capability-token engine at the core of
shepherd. A token is self-contained: it carries an opaque subject, scopes,
roles, audience, block id and expiry inside an HMAC-SHA256-signed payload. A
verifier needs only the shared signing secret, so validation is fully stateless
and no account store, session table or database is involved.

## Overview

The package lives in the `azzurrotech/shepherd` module and is used directly by
`azzurrotech/shepherd/middleware` (which owns a `*token.Manager`) and by
`server.go` in server mode. The gateway in the middleware package also reuses
`Manager.Signer()` so request signatures and tokens always share one secret.

Every token is a compact, JWT-like envelope with no external library:

```
<base64url(payloadJSON)>.<base64url(HMAC-SHA256(secret, base64url(payloadJSON)))>
```

The HMAC is computed over the exact base64url payload string, so tampering with
any claim invalidates the signature. The payload carries a `Version` field so
the encoding can evolve. Subjects (`sub`) and token ids (`jti`) are opaque
`crypto/rand` identifiers; no personally identifying data is ever stored.

## Public API

### Constants

- `const Version = 1` — current token encoding version.
- `const MagicLinkTTL = 10 * time.Minute` — default magic-link lifetime.
- `const MinSecretLen = 16` — minimum accepted master-secret length.

### Errors

- `ErrInvalidToken` — malformed token or signature mismatch.
- `ErrExpired` — token past its `exp`.
- `ErrNotYetValid` — token used before its `nbf`.
- `ErrWrongAudience` — token targets a different audience.
- `ErrNotMagic` — non-magic token used where a magic link is required.
- `ErrWeakSecret` — master secret shorter than `MinSecretLen`.
- `ErrBadBlock` — invalid block-issue parameters.

### Types

- `type Claims struct` — signed payload:
  `Version int` (`v`), `Issuer string` (`iss,omitempty`),
  `Audience string` (`aud,omitempty`), `Subject string` (`sub`),
  `Scopes []string` (`scp,omitempty`), `Roles []string` (`rol,omitempty`),
  `Block string` (`blk,omitempty`), `NotBefore int64` (`nbf,omitempty`),
  `IssuedAt int64` (`iat`), `ExpiresAt int64` (`exp`), `ID string` (`jti`),
  `Magic bool` (`mag,omitempty`), `Next string` (`nxt,omitempty`),
  `Meta map[string]string` (`meta,omitempty`).
  - `func (c Claims) HasScope(scope string) bool` — true when the claims list
    the scope or the wildcard `"*"`.
  - `func (c Claims) HasRole(role string) bool` — true when the claims carry
    the role.
  - `func (c Claims) Expired(now time.Time) bool` — true when
    `now.Unix() >= ExpiresAt`.
  - `func (c Claims) Valid(now time.Time) bool` — true when
    `NotBefore <= now.Unix() < ExpiresAt`.
- `type IssuedKey struct` — one block-issued key:
  `Index int`, `Token string`, `Claims Claims`.
- `type IssueOptions struct` — per-token inputs:
  `Subject string`, `Scopes []string`, `Roles []string`, `Audience string`,
  `TTL time.Duration`, `NotBefore time.Time`, `Block string`, `Magic bool`,
  `Next string`, `Meta map[string]string`.
- `type Manager struct` — issues and verifies tokens; safe for concurrent use.
- `type Signer struct` — raw HMAC-SHA256 signing primitive for gateway
  request signatures.

### Functions and methods

- `func NewManager(secret []byte, issuer string) (*Manager, error)` — builds a
  manager; returns `ErrWeakSecret` when `len(secret) < MinSecretLen`.
- `func (m *Manager) WithAudience(aud string) *Manager` — sets the default
  audience for issued tokens.
- `func (m *Manager) WithTTL(ttl time.Duration) *Manager` — sets the default
  token lifetime.
- `func (m *Manager) Issue(o IssueOptions) (string, Claims, error)` — signs a
  new capability token.
- `func (m *Manager) IssueBlock(o IssueOptions, blockID string, count int) ([]IssuedKey, error)`
  — issues `count` keys sharing one block id.
- `func (m *Manager) Verify(raw string) (Claims, error)` — checks signature,
  version, validity window and audience.
- `func (m *Manager) VerifyMagic(raw string) (Claims, error)` — `Verify` plus a
  required `Magic` flag.
- `func (m *Manager) IssueMagicLink(o IssueOptions) (string, Claims, error)` —
  issues a short-TTL magic token carrying `Next`.
- `func (m *Manager) Signer() Signer` — exposes the shared secret as a signer.
- `func (s Signer) Sign(canonical string) string` — lowercase-hex
  HMAC-SHA256 of `canonical`.
- `func RandomBytes(n int) ([]byte, error)` — `n` bytes from `crypto/rand`.
- `func RandomID() (string, error)` — 128-bit random identifier as hex.

## Usage

```go
m, err := token.NewManager([]byte("0123456789abcdef0123456789abcdef"), "my-host")
if err != nil {
    log.Fatal(err)
}
raw, claims, err := m.Issue(token.IssueOptions{
    Scopes: []string{"read:orders"},
    Roles:  []string{"member"},
    TTL:    time.Hour,
})
if err != nil {
    log.Fatal(err)
}
got, err := m.Verify(raw)
if err != nil || got.Subject != claims.Subject {
    log.Fatal("verification failed")
}
```

Revocation of a regular token is not done here; callers mark
`claims.ID` (or `claims.Block`) in `azzurrotech/shepherd/revoke` and check it
after `Verify`.

## Configuration, defaults and limits

- **Master secret**: at least `MinSecretLen` (16) bytes; `NewManager` copies it
  into the manager, so later mutation of the caller's slice is harmless.
- **Default TTL**: 24 hours, set inside `NewManager`; override with `WithTTL`
  or per-issue `IssueOptions.TTL` (per-issue wins when non-zero).
- **Magic-link TTL**: `MagicLinkTTL` (10 minutes), used when
  `IssueOptions.Magic` is set and no explicit `TTL` is given.
- **Audience**: empty manager audience means "any"; `Verify` only enforces the
  audience check when both the manager and the token carry one.
- **Not-before**: only set when `IssueOptions.NotBefore` is non-zero.
- **Block size**: `IssueBlock` accepts `count` in `1..10000`; each key gets the
  same `Block` and a distinct `jti` and `sub`.
- **Scope wildcard**: `HasScope` treats `"*"` as matching any scope.

## Testing

From the module root `/home/matthew/Projects/Platform/stenella/atp/shepherd`:

```sh
go test ./token/
go test -race ./token/
```

`token_test.go` covers round-trip issue/verify, tamper rejection, wrong-secret
rejection, expiry and not-before windows, audience mismatch, weak-secret
rejection, block issuance (shared block id, unique ids, count validation),
magic-link issue/verify and `ErrNotMagic`, and deterministic
`Signer.Sign` behavior across timestamp and secret changes.

## Design notes and invariants

- The signature covers the base64url payload string, not the decoded JSON, so
  re-encoding cannot be used to forge an equivalent token.
- Signature comparison uses `hmac.Equal` (constant-time).
- All identifiers come from `crypto/rand` via `RandomBytes`/`RandomID`.
- `Manager` is immutable after construction except through the `With*` setters
  called before concurrent use; it is documented as safe for concurrent use.
- `Verify` checks signature before parsing, then version, validity window, and
  audience, in that order.
- Regular tokens are replayable until `exp`; single-use semantics live in the
  `revoke`/`middleware` layers, not in this package.
