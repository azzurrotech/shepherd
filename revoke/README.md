# revoke — in-memory revocation and once-use store

`azzurrotech/shepherd/revoke` provides the in-memory trust store that gives
shepherd its "revocation without a database" story. Two kinds of entries share
one deny map:

- **revocations** — a token id (`jti`) or a block id (`blk`) that must no
  longer be honored even though its signature and expiry are otherwise valid;
- **consumptions** — a magic-link token id that has already been redeemed, so
  the same link cannot be replayed while the process is alive.

Everything lives in RAM and is lost on restart. That is the intended trade-off
of a database-less IAM: token validity hinges on signature plus TTL, and
revocation is a best-effort bolt-on.

## Overview

The package lives in the `azzurrotech/shepherd` module. It is used by
`azzurrotech/shepherd/middleware`: `Config.Deny` optionally supplies a shared
`*revoke.Store`, and when it is nil the middleware creates a private one.
`Shepherd.authenticate` checks the store after `token.Verify`;
`Shepherd.VerifyMagicToken` consumes a redeemed link; and `server.go` drives
revocation through the management endpoints and periodically calls
`CleanupRevocations()`.

A single `map[string]int64` maps an id to its expiry (unix seconds). Block
entries are stored under a `blk:` prefix so they never collide with token ids.
`Denied(id)` checks both the raw id and the `blk:`-prefixed form, so a block id
can be queried directly as well as through `claims.Block`.

## Public API

### Types

- `type Store struct` — concurrency-safe, in-memory deny/consume map
  (unexported `mu sync.Mutex`, `deny map[string]int64`, `now func() time.Time`).

### Functions and methods

- `func NewStore() *Store` — returns an empty store.
- `func (s *Store) RevokeToken(jti string, expiresAt int64)` — marks a token id
  revoked until `expiresAt`. An empty `jti` is ignored.
- `func (s *Store) RevokeBlock(blockID string, expiresAt int64)` — marks a
  block id revoked (stored as `blk:<blockID>`). An empty id is ignored.
- `func (s *Store) Consume(jti string, expiresAt int64)` — records a one-time
  token as spent; `Denied` reports true for the same id until it expires.
- `func (s *Store) Denied(id string) bool` — true when `id` (or its `blk:`
  form) has an entry whose expiry is in the future.
- `func (s *Store) DeniedFor(id string, at int64) bool` — `Denied` evaluated
  at an explicit unix time.
- `func (s *Store) Cleanup()` — drops entries whose expiry has passed
  (`exp <= now`).
- `func (s *Store) Len() int` — number of tracked entries (tests/debug only).

## Usage

```go
deny := revoke.NewStore()

// Revoke one token until it naturally expires.
deny.RevokeToken(claims.ID, claims.ExpiresAt)

// Revoke a whole block.
deny.RevokeBlock("blk-123", time.Now().Add(24*time.Hour).Unix())

// Check after a successful token.Verify.
if deny.Denied(claims.ID) || (claims.Block != "" && deny.Denied(claims.Block)) {
    // treat as unauthorized
}

// Redeem a magic link exactly once.
if deny.Denied(claims.ID) {
    // already consumed / revoked
}
deny.Consume(claims.ID, claims.ExpiresAt)
```

## Configuration, inputs, defaults and limits

- **Key form**: token ids are stored verbatim; block ids are stored with the
  `blk:` prefix. `Denied(id)` checks `deny[id]` and `deny["blk:"+id]`, so
  passing a block id directly works.
- **Expiry semantics**: an entry is live while `expiry > now`; `Cleanup`
  removes entries with `expiry <= now`.
- **Empty ids**: `RevokeToken`, `RevokeBlock` and `Consume` silently ignore an
  empty id.
- **No TTL default**: callers supply `expiresAt`. In server mode
  `POST /api/revoke/block` records the block with `time.Now().Add(365*24h)`,
  but the effective lifetime is capped by each token's own `exp` claim, and the
  entry is still subject to `Cleanup`.
- **In-memory only**: no persistence, no replication, no cross-process
  coordination.

## Testing

From the module root `/home/matthew/Projects/Platform/stenella/atp/shepherd`:

```sh
go test ./revoke/
go test -race ./revoke/
```

`revoke_test.go` covers token revocation expiring on its own, block revocation
(queryable both as the raw block id and via the `blk:` key), once-use
consumption (a consumed id is denied while unrelated ids remain allowed), and
`Cleanup` keeping live entries while removing expired ones.

## Design notes and invariants

- All reads and writes take the same `sync.Mutex`; `add` creates the map
  lazily, so a zero-value `Store` can be used without `NewStore`.
- `Denied` is read-only; the map is only mutated by `Revoke*`, `Consume` and
  `Cleanup`.
- Entries are pruned lazily by explicit `Cleanup` or naturally by the expiry
  comparison; the store never treats an expired entry as denied.
- Revocation by block depends on tokens actually carrying the `blk` claim; see
  `token.Claims.Block`.
- Restart discards the store: a token revoked before a restart validates again
  until its `exp`.
