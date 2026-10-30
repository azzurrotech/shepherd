package capability

import (
	"testing"
	"time"

	"azzurrotech/shepherd/token"
)

func newManager(t *testing.T) *token.Manager {
	t.Helper()
	m, err := token.NewManager([]byte("a-very-long-test-secret-value-1234"), "test")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIssueAndResolve(t *testing.T) {
	m := newManager(t)
	s, err := Issue(m, IssueOptions{
		Target: Target{Kind: "Item", ID: "item-1"},
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != "item" || s.ID != "item-1" {
		t.Errorf("share target = %#v", s)
	}
	if s.Token == "" || !s.Expires.After(s.IssuedAt) {
		t.Errorf("bad share = %#v", s)
	}
	tt, claims, err := Resolve(m, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	if tt.Kind != "item" || tt.ID != "item-1" || claims.Subject != "share" {
		t.Errorf("resolved = %#v claims=%#v", tt, claims)
	}
}

func TestIssueDefaultsKindAndTTL(t *testing.T) {
	m := newManager(t)
	s, err := Issue(m, IssueOptions{Target: Target{ID: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != "record" {
		t.Errorf("kind = %q", s.Kind)
	}
	if got := s.Expires.Sub(s.IssuedAt); got < DefaultTTL-time.Minute || got > DefaultTTL+time.Minute {
		t.Errorf("ttl = %v", got)
	}
}

func TestIssueRejectsEmptyTarget(t *testing.T) {
	if _, err := Issue(newManager(t), IssueOptions{}); err == nil {
		t.Fatal("expected an error for an empty target")
	}
}

func TestResolveRejectsForeignToken(t *testing.T) {
	m := newManager(t)
	raw, _, err := m.Issue(token.IssueOptions{Subject: "other", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(m, raw); err == nil {
		t.Fatal("a token without target metadata must not resolve as a share")
	}
}

func TestParseTTL(t *testing.T) {
	for _, c := range []struct {
		raw  string
		def  time.Duration
		want time.Duration
	}{
		{"", 0, DefaultTTL},
		{"", time.Minute, time.Minute},
		{"2h", time.Minute, 2 * time.Hour},
		{"nonsense", time.Minute, time.Minute},
		{"-1h", time.Minute, time.Minute},
	} {
		if got := ParseTTL(c.raw, c.def); got != c.want {
			t.Errorf("ParseTTL(%q, %v) = %v, want %v", c.raw, c.def, got, c.want)
		}
	}
}

// recordingRevoker is the smallest Revoker: it remembers what it was asked to
// deny so the test can assert on the token id and expiry.
type recordingRevoker struct {
	jti string
	exp int64
}

func (r *recordingRevoker) RevokeToken(jti string, exp int64) {
	r.jti = jti
	r.exp = exp
}

func TestIssueCarriesTokenID(t *testing.T) {
	s, err := Issue(newManager(t), IssueOptions{Target: Target{Kind: "item", ID: "x"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if s.JTI == "" {
		t.Fatal("share has no token id, so it cannot be revoked by value")
	}
}

func TestRevokeUsesShareTokenID(t *testing.T) {
	s, err := Issue(newManager(t), IssueOptions{Target: Target{Kind: "item", ID: "x"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r := &recordingRevoker{}
	if err := Revoke(r, s); err != nil {
		t.Fatal(err)
	}
	if r.jti != s.JTI {
		t.Errorf("revoked jti = %q, want %q", r.jti, s.JTI)
	}
	if r.exp != s.Expires.Unix() {
		t.Errorf("revoked exp = %d, want %d", r.exp, s.Expires.Unix())
	}
}

func TestRevokeRaw(t *testing.T) {
	m := newManager(t)
	s, err := Issue(m, IssueOptions{Target: Target{Kind: "group", ID: "g-1"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r := &recordingRevoker{}
	target, err := RevokeRaw(m, r, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	if target.Kind != "group" || target.ID != "g-1" {
		t.Errorf("target = %#v", target)
	}
	if r.jti != s.JTI {
		t.Errorf("revoked jti = %q, want %q", r.jti, s.JTI)
	}
}

func TestRevokeRejectsBadInput(t *testing.T) {
	if err := Revoke(nil, &Share{JTI: "x"}); err == nil {
		t.Error("nil revoker accepted")
	}
	if err := Revoke(&recordingRevoker{}, nil); err == nil {
		t.Error("nil share accepted")
	}
	if err := Revoke(&recordingRevoker{}, &Share{}); err == nil {
		t.Error("share without a token id accepted")
	}
	if _, err := RevokeRaw(newManager(t), &recordingRevoker{}, "not-a-token"); err == nil {
		t.Error("invalid token accepted")
	}
}
