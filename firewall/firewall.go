// Package firewall implements shepherd's software firewall: request-level
// allow/deny rules evaluated in order. Rules match on the HTTP surface
// (method, path, client IP/CIDR, required headers) rather than on TCP packets,
// which is what a software firewall that protects custom APIs needs.
package firewall

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync"
)

// Actions.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// ErrBadAction is returned when a rule uses an unknown action.
var ErrBadAction = errors.New("rule action must be allow or deny")

// Rule is a single firewall rule. An empty field matches anything.
type Rule struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Action   string            `json:"action"` // "allow" | "deny"
	Enabled  bool              `json:"enabled"`
	Methods  []string          `json:"methods,omitempty"`   // e.g. ["GET","POST"]
	PathGlob string            `json:"path_glob,omitempty"` // glob; "/**" suffix = prefix match
	Sources  []string          `json:"sources,omitempty"`   // IPs or CIDRs
	Headers  map[string]string `json:"headers,omitempty"`   // required header value pairs
}

// Decision is the outcome of evaluating a request against the rule set.
type Decision struct {
	Allowed  bool   `json:"allowed"`
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
	Denied   bool   `json:"denied"`
}

// Firewall is an ordered, concurrency-safe rule evaluator.
type Firewall struct {
	mu           sync.RWMutex
	rules        []Rule
	defaultAllow bool
}

// New returns a Firewall. When defaultAllow is false any request that matches
// no rule is denied (default-deny posture).
func New(defaultAllow bool) *Firewall {
	return &Firewall{defaultAllow: defaultAllow}
}

// DefaultAllow reports the current default disposition.
func (f *Firewall) DefaultAllow() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.defaultAllow
}

// SetDefaultAllow changes the default disposition.
func (f *Firewall) SetDefaultAllow(allow bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.defaultAllow = allow
}

// Add appends a rule. Empty IDs get a generated one.
func (f *Firewall) Add(r Rule) (string, error) {
	if r.Action != ActionAllow && r.Action != ActionDeny {
		return "", ErrBadAction
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.ID == "" {
		// Deterministic in-sequence ids are fine here: ids are not secrets.
		r.ID = "rule_" + strings.Repeat("0", 4-len(f.rules)+1) + itoa(len(f.rules)+1)
	}
	f.rules = append(f.rules, r)
	return r.ID, nil
}

// Remove deletes a rule by id and reports whether anything was removed.
func (f *Firewall) Remove(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.rules {
		if r.ID == id {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return true
		}
	}
	return false
}

// Rules returns a copy of the current rules.
func (f *Firewall) Rules() []Rule {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Rule, len(f.rules))
	copy(out, f.rules)
	return out
}

// Evaluate runs the request through the ordered rules. The first matching rule
// wins. When nothing matches the default disposition applies.
func (f *Firewall) Evaluate(r *http.Request, clientIP string) Decision {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, rule := range f.rules {
		if !rule.Enabled {
			continue
		}
		if !matchMethods(rule.Methods, r.Method) {
			continue
		}
		if rule.PathGlob != "" && !matchPath(rule.PathGlob, r.URL.Path) {
			continue
		}
		if len(rule.Sources) > 0 && !matchIP(rule.Sources, clientIP) {
			continue
		}
		if !matchHeaders(rule.Headers, r.Header) {
			continue
		}
		allowed := rule.Action == ActionAllow
		return Decision{Allowed: allowed, Denied: !allowed, RuleID: rule.ID, RuleName: rule.Name}
	}
	allowed := f.defaultAllow
	return Decision{Allowed: allowed, Denied: !allowed}
}

// ClientIP strips the port from a remote address and also honors a trusted
// hop (e.g. the last entry a configured proxy header gives us). The caller
// decides whether a proxy header is trustworthy; by default only RemoteAddr
// is used.
func ClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func matchMethods(methods []string, m string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, e := range methods {
		if strings.EqualFold(e, m) {
			return true
		}
	}
	return false
}

// matchPath supports plain equality, shell-style globs (via path.Match), and
// the suffix "/**" as a "this directory and everything below it" prefix.
func matchPath(glob, p string) bool {
	if strings.HasSuffix(glob, "/**") {
		prefix := strings.TrimSuffix(glob, "**")
		return strings.HasPrefix(p, prefix)
	}
	if strings.ContainsAny(glob, "*?[") {
		ok, _ := path.Match(glob, p)
		return ok
	}
	return glob == p
}

func matchIP(sources []string, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		// Non-parsable client id (e.g. a unix socket label): exact-string match.
		for _, s := range sources {
			if s == ip {
				return true
			}
		}
		return false
	}
	for _, s := range sources {
		if strings.Contains(s, "/") {
			if prefix, err := netip.ParsePrefix(s); err == nil && prefix.Contains(addr) {
				return true
			}
			continue
		}
		if o, err := netip.ParseAddr(s); err == nil && o == addr {
			return true
		}
	}
	return false
}

func matchHeaders(required map[string]string, h http.Header) bool {
	for k, v := range required {
		if !strings.EqualFold(h.Get(k), v) {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
