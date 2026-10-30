// Package capability turns shepherd's token manager into the one operation
// applications actually ask for: hand a colleague a revocable pointer to one
// named thing.
//
// The token is a capability record, not an access-control decision. It names a
// kind and an id, carries an expiry, and can be verified or revoked through
// shepherd's normal surfaces. Applications differ in what they call the thing
// (item, record, document, group); the shape of the share does not.
package capability

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"azzurrotech/shepherd/token"
)

// DefaultTTL is the lifetime used when a caller does not supply one.
const DefaultTTL = 7 * 24 * time.Hour

// Target is the thing a share points at. Kind is the application's own noun
// (item, document, group, …) and ID is the record id the application resolves.
type Target struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Normalize trims and defaults the target, rejecting an empty id.
func (t Target) Normalize() (Target, error) {
	t.Kind = strings.ToLower(strings.TrimSpace(t.Kind))
	t.ID = strings.TrimSpace(t.ID)
	if t.Kind == "" {
		t.Kind = "record"
	}
	if t.ID == "" {
		return Target{}, errors.New("capability: target id is required")
	}
	return t, nil
}

// Share is the JSON-facing result of issuing a capability token.
type Share struct {
	Token    string    `json:"token"`
	Kind     string    `json:"kind"`
	ID       string    `json:"id"`
	JTI      string    `json:"jti,omitempty"`
	Issuer   string    `json:"issuer,omitempty"`
	Subject  string    `json:"subject,omitempty"`
	IssuedAt time.Time `json:"issuedAt"`
	Expires  time.Time `json:"expires"`
}

// IssueOptions controls Issue.
type IssueOptions struct {
	Target  Target
	TTL     time.Duration
	Issuer  string   // informational; the manager's issuer is authoritative
	Subject string   // opaque principal; defaults to "share"
	Scopes  []string // defaults to ["share"]
	Meta    map[string]string
}

// Issue creates a capability token for a target. The target's kind and id are
// copied into the token metadata, so verification can answer "what does this
// token point at?" without application-specific code.
func Issue(m *token.Manager, o IssueOptions) (*Share, error) {
	if m == nil {
		return nil, errors.New("capability: nil token manager")
	}
	t, err := o.Target.Normalize()
	if err != nil {
		return nil, err
	}
	ttl := o.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	subject := strings.TrimSpace(o.Subject)
	if subject == "" {
		subject = "share"
	}
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = []string{"share"}
	}
	meta := map[string]string{"kind": t.Kind, "target": t.ID}
	for k, v := range o.Meta {
		if k == "" {
			continue
		}
		meta[k] = v
	}

	raw, claims, err := m.Issue(token.IssueOptions{
		Subject: subject,
		Scopes:  scopes,
		TTL:     ttl,
		Meta:    meta,
	})
	if err != nil {
		return nil, fmt.Errorf("capability: issue share: %w", err)
	}
	return &Share{
		Token:    raw,
		Kind:     t.Kind,
		ID:       t.ID,
		JTI:      claims.ID,
		Issuer:   firstNonEmpty(o.Issuer, claims.Issuer),
		Subject:  claims.Subject,
		IssuedAt: time.Unix(claims.IssuedAt, 0).UTC(),
		Expires:  time.Unix(claims.ExpiresAt, 0).UTC(),
	}, nil
}

// Resolve verifies a share token and returns what it points at. It is the
// read-side twin of Issue.
func Resolve(m *token.Manager, raw string) (Target, token.Claims, error) {
	if m == nil {
		return Target{}, token.Claims{}, errors.New("capability: nil token manager")
	}
	claims, err := m.Verify(raw)
	if err != nil {
		return Target{}, token.Claims{}, err
	}
	t := Target{Kind: claims.Meta["kind"], ID: claims.Meta["target"]}
	if _, err := t.Normalize(); err != nil {
		return Target{}, claims, fmt.Errorf("capability: token is not a share")
	}
	return t, claims, nil
}

// Revoker is the small part of shepherd a share needs in order to be revoked:
// middleware.Shepherd implements it, and so does any store that keeps a deny
// list. Keeping the interface here means callers do not import shepherd's
// middleware just to cancel a link.
type Revoker interface {
	RevokeToken(jti string, expiresAt int64)
}

// Revoke cancels a share that was issued in this process. Revocation is
// best-effort and in memory, like every shepherd deny entry: a restart forgets
// it, so a token is only as durable as the process that issued it.
func Revoke(r Revoker, s *Share) error {
	if r == nil {
		return errors.New("capability: nil revoker")
	}
	if s == nil {
		return errors.New("capability: nil share")
	}
	if s.JTI == "" {
		return errors.New("capability: share has no token id")
	}
	r.RevokeToken(s.JTI, s.Expires.Unix())
	return nil
}

// RevokeRaw verifies a token, resolves the share it names and revokes it. It
// is the endpoint-friendly form: a caller holding only the token string can
// cancel it without keeping the Share returned at issue time.
func RevokeRaw(m *token.Manager, r Revoker, raw string) (Target, error) {
	t, claims, err := Resolve(m, raw)
	if err != nil {
		return Target{}, err
	}
	if r == nil {
		return Target{}, errors.New("capability: nil revoker")
	}
	if claims.ID == "" {
		return Target{}, errors.New("capability: token has no id")
	}
	r.RevokeToken(claims.ID, claims.ExpiresAt)
	return t, nil
}

// ParseTTL reads a duration string, returning def when it is empty or invalid.
func ParseTTL(raw string, def time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if def > 0 {
			return def
		}
		return DefaultTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		if def > 0 {
			return def
		}
		return DefaultTTL
	}
	return d
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
