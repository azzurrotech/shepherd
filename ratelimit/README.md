# ratelimit — in-memory token-bucket limiter

`azzurrotech/shepherd/ratelimit` implements a software token-bucket rate
limiter backed by in-memory state only — no database required. The limiter is
keyed by an arbitrary string (client IP, token subject, or both), so it works
the same in server mode and middleware mode.

## Overview

The package lives in the `azzurrotech/shepherd` module. It is used by
`azzurrotech/shepherd/middleware`: `Config.LimitsPerMinute` and `Config.Burst`
construct a `*Limiter`, which `Shepherd.RateLimit`, `Shepherd.Gate` and the
gateway apply per request. `server.go` exposes status/reset through
`/api/ratelimit/status` and `/api/ratelimit/reset`.

Each key gets its own bucket. A bucket starts full (`burst` tokens), refills at
`perMinute/60` tokens per second, and is capped at `burst`. All access is
guarded by a `sync.Mutex`.

## Public API

### Types

- `type Status struct` — point-in-time snapshot of one key's bucket:
  - `Key string` (`key`), `Remaining float64` (`remaining`),
    `Limit float64` (`limit`), `ResetAt time.Time` (`reset_at`).
- `type Limiter struct` — concurrency-safe token-bucket limiter.

### Functions and methods

- `func New(perMinute float64, burst float64) *Limiter` — allows a sustained
  average of `perMinute` requests per minute with bursts up to `burst`.
  Fractional values are allowed; negative `perMinute` is clamped to 0 and
  `burst < 1` is clamped to 1.
- `func (l *Limiter) Allow(key string) (ok bool, remaining float64, resetAt time.Time)`
  — consumes one token for `key`. On success `remaining` is the tokens left and
  `resetAt` is when the bucket refills to full; when denied `resetAt` is when
  the next token is expected.
- `func (l *Limiter) Status(key string) Status` — snapshot without consuming a
  token; an unknown key reports a full bucket
  (`Remaining == Limit == burst`, `ResetAt == now`).
- `func (l *Limiter) Reset()` — drops all bucket state.
- `func (l *Limiter) Cleanup(idleFor time.Duration)` — removes buckets whose
  last touch predates `now - idleFor`.
- `func (l *Limiter) Len() int` — number of tracked buckets (tests/debug only).

## Usage

```go
l := ratelimit.New(60, 5) // 1 token/sec, burst 5
ok, remaining, resetAt := l.Allow("ip:203.0.113.7")
if !ok {
    // 429; resetAt is when the next token arrives
    _ = remaining
    _ = resetAt
}
```

Middleware builds keys as `"ip:" + ClientIP` and, when a token is presented,
`"sub:" + claims.Subject`; the gateway checks both. `server.go` periodically
calls `Cleanup(time.Hour)` from a background ticker.

## Configuration, inputs, defaults and limits

- **Rate**: `perMinute` tokens per minute, converted to `perMinute/60` tokens
  per second. `0` (or negative) disables refill — a burst-only limiter.
- **Burst**: maximum bucket size; `burst < 1` becomes `1`. In middleware mode,
  when `LimitsPerMinute > 0` and `Config.Burst < 1`, the middleware substitutes
  its own default of `5` (`defaultBurst`).
- **Initial balance**: a bucket starts at `burst`, so the first `burst`
  requests from a key pass immediately.
- **Refill cap**: `refill` never exceeds `burst`.
- **Reset semantics**: on a compliant request `Allow` returns `now + burst/rate`
  (time to full); when rate is 0 it returns `now`.
- **Denial**: `Allow` returns `ok == false` when fewer than one token is
  available and reports how long until one accrues.
- **Memory bound**: use `Cleanup` to prune idle buckets; `Reset` clears all.

## Testing

From the module root `/home/matthew/Projects/Platform/stenella/atp/shepherd`:

```sh
go test ./ratelimit/
go test -race ./ratelimit/
```

`ratelimit_test.go` covers burst-then-refill behavior (5 tokens, deny on the
sixth, refill of exactly 3 after 3 seconds), independent per-key buckets,
`Status` and `Cleanup` (an idle bucket is pruned), and the zero-rate
burst-only case (`New(0, 0)` clamps burst to 1, so the first request passes
and the second is denied with no refill).

## Design notes and invariants

- Buckets are created lazily on first use; `Status` for an unseen key does not
  create one.
- Time is read through the unexported `now` hook (set to `time.Now`), which the
  tests override; production callers do not set it.
- The limiter is per-process and in-memory: state is lost on restart and is not
  shared across instances.
- `Len` exists for tests and diagnostics, not for control flow.
