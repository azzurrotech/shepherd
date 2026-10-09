# revoke — Security

This document describes the security properties of
`azzurrotech/shepherd/revoke` as implemented. It makes no claims beyond the
code.

## Assets protected

- **Revocation state** for token ids (`jti`) and block ids (`blk`).
- **Once-use state** that makes redeemed magic links non-replayable within the
  process lifetime.

## Threat model

In scope:

- A revoked token that still has a valid signature and unexpired `exp` must be
  rejected by callers that consult the store.
- A magic link that has been redeemed must not be accepted a second time while
  the process runs.
- Revoking a block id must deny every token carrying that block.

Out of scope:

- Durability. State exists only in memory; it is not persisted or replicated.
- The decision to revoke. This package stores entries; callers (admin
  endpoints, application code) decide what to revoke.
- Authenticating the revocation API. In server mode `/api/revoke*` requires the
  admin token, but the store itself performs no authorization.

## Mitigations actually implemented

- **Expiry-bounded entries**: every entry stores an expiry; `denied` returns
  true only when `exp > at`, so entries cannot outlive the token they mirror
  (when callers pass the token's real `exp`).
- **Block namespacing**: `RevokeBlock` writes `blk:<id>` and `denied` checks
  both the raw id and the prefixed form, preventing collisions between token
  ids and block ids while letting callers query block ids directly.
- **Once-use consumption**: `Consume` reuses the deny map, so a redeemed magic
  link's `jti` is denied until its natural expiry — the replay defense used by
  `middleware.VerifyMagicToken`.
- **Concurrency safety**: a single `sync.Mutex` guards the map; `Cleanup` and
  `add` take the lock before mutating.
- **Idle pruning**: `Cleanup` removes expired entries so the map does not grow
  without bound under revocation/link churn.

## Honest limits / non-claims

- **In-memory and process-local.** All entries vanish on restart. A token
  revoked before a restart becomes valid again until its `exp`; a magic link
  consumed before a restart can be replayed afterward.
- **Not shared across replicas.** Running multiple shepherd instances means
  each has an independent deny map; revoking on one does not revoke on another.
- **Best-effort revoke.** Tokens remain valid until `exp` unless a caller both
  writes an entry and checks `Denied` on every request path. Any code path that
  verifies a token without consulting the store bypasses revocation.
- **Block revocation depends on the `blk` claim.** If a token does not carry
  `Block`, `RevokeBlock` cannot affect it.
- **Server-mode block expiry is a placeholder.** `POST /api/revoke/block` uses
  `now + 365 days`; the real bound is each token's `exp`. Until `Cleanup` runs,
  the entry lingers.
- **No audit trail.** The store keeps no history, timestamps of who revoked
  what, or logs.
- **`Len` is diagnostic only** and must not be used for security decisions.

## Dependencies

Standard library only: `sync`, `time`. No third-party packages.

## Reporting

Report security issues privately to **security@azzurro.tech**. Do not open a
public issue. Include the shepherd version, the mode (server/middleware), and a
minimal reproduction.
