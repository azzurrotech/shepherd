# firewall — Security

This document describes the security properties of
`azzurrotech/shepherd/firewall` as implemented. It makes no claims beyond the
code.

## Assets protected

- The set of **HTTP routes, methods and header-gated operations** an
  application intends to expose.
- **Network-origin policy** for those routes via client IP/CIDR rules.

## Threat model

In scope:

- Requests that should be blocked by a deny rule (path, method, source, header)
  are rejected before the protected handler runs.
- A default-deny posture can be selected so unmatched requests are blocked.
- Ordering is deterministic: a deny rule placed before a broader allow rule
  still takes effect.

Out of scope:

- Network-layer attacks. This is an HTTP middleware/firewall, not a packet
  filter or DDoS scrubber.
- Trustworthy client IPs. `Evaluate` trusts the `clientIP` argument it is
  given; correctness depends on how the caller derives it (see the
  `middleware` package's `ClientIPHeader` handling).
- Authenticating the managed API that edits rules. In server mode those
  endpoints require the admin token, but the rule engine itself performs no
  authentication.

## Mitigations actually implemented

- **Deterministic first-match evaluation**: `Evaluate` walks rules in order and
  returns on the first enabled match, so rule precedence cannot be
  non-deterministic.
- **Explicit default disposition**: `New(defaultAllow)` and
  `SetDefaultAllow` make the fall-through behavior explicit; `Decision.Denied`
  always mirrors `!Allowed`.
- **CIDR-aware source matching**: `matchIP` uses `net/netip` (`ParsePrefix`,
  `ParseAddr`) instead of string prefixes, avoiding `10.0.0.0/8` style
  false positives.
- **Case handling**: methods and header names are compared case-insensitively
  (`strings.EqualFold`, `http.Header.Get`), reducing bypasses from casing.
- **Concurrency safety**: the rule set is guarded by a `sync.RWMutex`, so
  concurrent updates and evaluations do not race.
- **Non-secret ids**: generated rule ids are derived from the rule count and
  are explicitly documented as not secrets.

## Honest limits / non-claims

- **Default-allow in server mode.** Unless `-default-deny` is set, requests
  matching no rule pass. This is convenient behind a trusted edge and weaker
  in front of the open internet.
- **Header rules are spoofable at the edge.** Required headers are exact string
  matches on whatever reaches this process; if an untrusted client can set
  them, a header rule is not an authentication control.
- **Source rules depend on a trustworthy client IP.** If a proxy header is
  trusted (`middleware.Config.ClientIPHeader`, `-trust-proxy-header`) and the
  edge does not overwrite it, clients can spoof their IP and evade source
  rules.
- **Path matching is on the decoded request path** (`r.URL.Path`). Encoded
  variants should be normalized by the HTTP server; this engine does not
  decode or canonicalize further.
- **In-memory rule set.** Rules are lost on restart and are not replicated;
  there is no persistence or clustered consistency.
- **No accounting.** The engine does not rate-limit or log; pair it with the
  `ratelimit` package and normal request logging.
- **`Add` does not validate globs.** A malformed glob simply fails to match
  (via `path.Match`); it is not rejected.

## Dependencies

Standard library only: `errors`, `net`, `net/http`, `net/netip`, `path`,
`strings`, `sync`. No third-party packages.

## Reporting

Report security issues privately to **security@azzurro.tech**. Do not open a
public issue. Include the shepherd version, the mode (server/middleware), and a
minimal reproduction.
