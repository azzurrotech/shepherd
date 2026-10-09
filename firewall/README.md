# firewall — ordered HTTP allow/deny rules

`azzurrotech/shepherd/firewall` implements shepherd's software firewall:
request-level allow/deny rules evaluated in order. Rules match on the HTTP
surface — method, path, client IP/CIDR, and required headers — rather than on
TCP packets, which is what a firewall guarding a custom API needs.

## Overview

The package lives in the `azzurrotech/shepherd` module. It is used by
`azzurrotech/shepherd/middleware`, where `Config.Firewall` is applied by
`Shepherd.Firewall`, `Shepherd.Gate` and the gateway, and by `server.go` in
server mode (`/api/firewall/rules`, `/api/firewall/rules/{id}`). The same
`*Firewall` instance can be shared between modes.

Rules are held in memory, evaluated under a `sync.RWMutex`, and the **first
matching enabled rule wins**. When no rule matches, the configured default
disposition applies.

## Public API

### Constants and errors

- `const ActionAllow = "allow"` — allow action.
- `const ActionDeny = "deny"` — deny action.
- `var ErrBadAction` — returned by `Add` for an unknown action.

### Types

- `type Rule struct` — one rule (all fields JSON-tagged):
  - `ID string` (`id`), `Name string` (`name`)
  - `Action string` (`action`): `"allow"` or `"deny"`
  - `Enabled bool` (`enabled`)
  - `Methods []string` (`methods,omitempty`) — e.g. `["GET","POST"]`
  - `PathGlob string` (`path_glob,omitempty`) — glob or `/**` prefix
  - `Sources []string` (`sources,omitempty`) — IPs or CIDRs
  - `Headers map[string]string` (`headers,omitempty`) — required header/value
    pairs
  An empty field matches anything.
- `type Decision struct` — evaluation outcome:
  - `Allowed bool` (`allowed`), `RuleID string` (`rule_id,omitempty`),
    `RuleName string` (`rule_name,omitempty`), `Denied bool` (`denied`).
- `type Firewall struct` — ordered, concurrency-safe rule evaluator.

### Functions and methods

- `func New(defaultAllow bool) *Firewall` — builds a firewall; `false` means
  default-deny.
- `func (f *Firewall) DefaultAllow() bool` — current default disposition.
- `func (f *Firewall) SetDefaultAllow(allow bool)` — change the default.
- `func (f *Firewall) Add(r Rule) (string, error)` — appends a rule, assigning
  a generated id when `r.ID` is empty; `ErrBadAction` for a bad action.
- `func (f *Firewall) Remove(id string) bool` — deletes by id, reports whether
  it existed.
- `func (f *Firewall) Rules() []Rule` — a copy of the current rule slice.
- `func (f *Firewall) Evaluate(r *http.Request, clientIP string) Decision` —
  runs the ordered match and returns the decision.
- `func ClientIP(remoteAddr string) string` — strips the port from a
  `host:port` remote address.

## Usage

```go
fw := firewall.New(false) // default-deny
fw.Add(firewall.Rule{
    Name: "block debug", Action: firewall.ActionDeny,
    PathGlob: "/debug/**", Enabled: true,
})
d := fw.Evaluate(r, firewall.ClientIP(r.RemoteAddr))
if !d.Allowed {
    // deny: d.RuleID identifies the matching rule (empty for the default)
}
```

In middleware/server mode the `Rule` struct is the JSON body accepted by
`POST /api/firewall/rules`.

## Configuration, inputs, defaults and limits

- **Default disposition**: set explicitly with `New(defaultAllow)`. Server mode
  passes `DefaultAllow: !*deny`, and the CLI flag `-default-deny` (default
  false) therefore leaves the firewall **default-allow** unless set.
- **Evaluation order**: rules are appended in `Add` order; the first enabled
  rule whose non-empty criteria all match determines the decision.
- **Method matching**: `matchMethods` uses `strings.EqualFold` (case
  insensitive); an empty method list matches any method.
- **Path matching** (`matchPath`):
  - a glob ending in `/**` is a prefix match on the part before `**`;
  - a glob containing any of `*?[` uses `path.Match`;
  - otherwise the path must equal the glob exactly.
  Because `path.Match`'s `*` does not cross `/`, `/z*` does not match
  `/zebra/x`.
- **Source matching** (`matchIP`): entries containing `/` are parsed as CIDRs
  with `netip.ParsePrefix`; bare entries are parsed as `netip.Addr`. If the
  client id is not a parsable address (e.g. a unix-socket label), sources are
  compared as exact strings.
- **Header matching** (`matchHeaders`): case-insensitive header name, exact
  value comparison via `h.Get(k)`.
- **Generated ids**: `Add` creates an id of the form `rule_…` when none is
  supplied. Ids are not secrets.
- **In-memory only**: rules live in the process; there is no persistence or hot
  reload from this package.

## Testing

From the module root `/home/matthew/Projects/Platform/stenella/atp/shepherd`:

```sh
go test ./firewall/
go test -race ./firewall/
```

`firewall_test.go` covers first-match-wins ordering (a deny rule before an
allow rule still wins), default-deny, method + header matching (including
value and method mismatches not matching), `/**` and `path.Match` globs, the
`/z*` non-nested behavior, removing and disabling rules, `ErrBadAction`, and
`ClientIP` port stripping for IPv4 and bracketed IPv6.

## Design notes and invariants

- All reads and writes take the `sync.RWMutex`; `Rules` and `Evaluate` copy or
  read under lock.
- `Evaluate` never mutates state.
- Empty rule fields are wildcards; a rule with every field empty and
  `Enabled: true` matches every request.
- `Denied` is always `!Allowed`; `RuleID` is empty when the default disposition
  decides.
- Rule ids are for management and reporting, not security decisions.
