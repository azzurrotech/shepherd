# ratelimit — Security

This document describes the security properties of
`azzurrotech/shepherd/ratelimit` as implemented. It makes no claims beyond the
code.

## Assets protected

- **Availability of protected backends** under request floods from a single
  client identity.
- **Bounded process memory** for limiter state, so key churn cannot grow the
  bucket map without limit.

## Threat model

In scope:

- A client (keyed by IP, subject, or a caller-chosen key) sending more than its
  configured sustained rate plus burst is denied while the burst is exhausted.
- Long-idle keys eventually release their memory via `Cleanup`.

Out of scope:

- Distributed or volumetric denial of service. The limiter is one in-process
  map; it does not coordinate across replicas and does not stop traffic before
  it reaches the process.
- Attribution. The limiter trusts the key string given to `Allow`; if that key
  is derived from a spoofable client IP, an attacker can vary it to evade the
  limit.

## Mitigations actually implemented

- **Token-bucket enforcement**: `(*Limiter).Allow` consumes one token and
  returns `ok == false` when the balance is below one, so bursts are bounded by
  `burst` and sustained throughput by `perMinute/60`.
- **Refill cap**: `refill` clamps the balance to `burst`, so a long idle period
  cannot accumulate credit beyond the configured burst.
- **Concurrency safety**: every operation holds a `sync.Mutex`, so concurrent
  requests cannot race the balance.
- **Parameter clamping**: negative rates become 0 and `burst < 1` becomes 1,
  preventing accidental "infinite" buckets.
- **Idle eviction**: `Cleanup` deletes buckets untouched for longer than a
  caller-supplied duration, bounding memory growth.

## Honest limits / non-claims

- **In-memory and per-process.** State is lost on restart and is not shared
  between instances. Horizontal scaling multiplies the effective budget per
  identity by the number of replicas.
- **Keying is only as good as the key.** In the gateway the key is the client
  IP and, when authenticated, the token subject. Behind a misconfigured trusted
  proxy header, the IP component can be spoofed to evade limiting.
- **No global ceiling.** There is no aggregate limit, priority, or per-route
  weighting; a flood spread across many keys is not throttled by this package.
- **No automatic cleanup.** Callers must invoke `Cleanup` (server mode does so
  on a 10-minute ticker for buckets idle over an hour); otherwise the map can
  grow with key churn.
- **No audit trail.** Denials are surfaced only through the return values and
  the caller's HTTP response; the package keeps no log.
- **Clock dependence.** Refill is computed from the `now` source; a
  backwards clock jump can delay refill.

## Dependencies

Standard library only: `sync`, `time`. No third-party packages.

## Reporting

Report security issues privately to **security@azzurro.tech**. Do not open a
public issue. Include the shepherd version, the mode (server/middleware), and a
minimal reproduction.
