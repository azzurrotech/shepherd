package token

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testSecret() []byte { return []byte("0123456789abcdef0123456789abcdef") }

func TestIssueVerifyRoundTrip(t *testing.T) {
	m, err := NewManager(testSecret(), "shepherd")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	raw, claims, err := m.Issue(IssueOptions{
		Scopes: []string{"read:orders", "write:orders"},
		Roles:  []string{"member"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if claims.Subject == "" || claims.ID == "" {
		t.Fatalf("expected opaque subject and token id, got sub=%q jti=%q", claims.Subject, claims.ID)
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		t.Fatalf("expiry must be after iat")
	}
	got, err := m.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != claims.Subject {
		t.Fatalf("subject mismatch: %q != %q", got.Subject, claims.Subject)
	}
	if !got.HasScope("read:orders") || !got.HasScope("write:orders") {
		t.Fatalf("scopes not preserved: %v", got.Scopes)
	}
	if !got.HasRole("member") {
		t.Fatalf("roles not preserved: %v", got.Roles)
	}
	if got.Magic {
		t.Fatalf("regular token flagged as magic")
	}
}

func TestTamperFails(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	raw, _, _ := m.Issue(IssueOptions{Scopes: []string{"one"}})
	// Flip a character in the payload.
	parts := strings.Split(raw, ".")
	payload := []byte(parts[0])
	if payload[len(payload)-1] == 'A' {
		payload[len(payload)-1] = 'B'
	} else {
		payload[len(payload)-1] = 'A'
	}
	if _, err := m.Verify(parts[1] + "." + string(payload)); err == nil {
		t.Fatalf("expected verification failure for garbage")
	}
	tampered := string(payload) + "." + parts[1]
	if _, err := m.Verify(tampered); err == nil {
		t.Fatalf("tampered token verified successfully")
	}
}

func TestWrongSecretFails(t *testing.T) {
	m1, _ := NewManager(testSecret(), "shepherd")
	m2, _ := NewManager([]byte("0123456789abcdef0123456789abcdee"), "shepherd")
	raw, _, _ := m1.Issue(IssueOptions{})
	if _, err := m2.Verify(raw); err == nil {
		t.Fatalf("token verified with wrong secret")
	}
}

func TestExpiry(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	now := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return now }
	raw, _, err := m.Issue(IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := m.Verify(raw); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	m.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := m.Verify(raw); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestNotBefore(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	now := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return now }
	raw, _, err := m.Issue(IssueOptions{NotBefore: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := m.Verify(raw); err != ErrNotYetValid {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
	m.now = func() time.Time { return now.Add(3 * time.Hour) }
	if _, err := m.Verify(raw); err != nil {
		t.Fatalf("token should be valid after nbf: %v", err)
	}
}

func TestAudience(t *testing.T) {
	m, err := NewManager(testSecret(), "shepherd")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.WithAudience("api")
	m2, err := NewManager(testSecret(), "shepherd")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m2.WithAudience("other")
	raw, _, _ := m.Issue(IssueOptions{})
	if _, err := m.Verify(raw); err != nil {
		t.Fatalf("own audience rejected: %v", err)
	}
	if _, err := m2.Verify(raw); err != ErrWrongAudience {
		t.Fatalf("expected ErrWrongAudience, got %v", err)
	}
}

func TestWeakSecret(t *testing.T) {
	if _, err := NewManager([]byte("short"), "shepherd"); err != ErrWeakSecret {
		t.Fatalf("expected ErrWeakSecret, got %v", err)
	}
}

func TestIssueBlock(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	keys, err := m.IssueBlock(IssueOptions{Scopes: []string{"read:reports"}}, "", 5)
	if err != nil {
		t.Fatalf("IssueBlock: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(keys))
	}
	blk := keys[0].Claims.Block
	if blk == "" {
		t.Fatalf("block id not assigned")
	}
	for i, k := range keys {
		if k.Claims.Block != blk {
			t.Fatalf("key %d in different block", i)
		}
		if k.Claims.ID == keys[0].Claims.ID && i > 0 {
			t.Fatalf("duplicate jti across block")
		}
		if _, err := m.Verify(k.Token); err != nil {
			t.Fatalf("key %d does not verify: %v", i, err)
		}
	}
	if _, err := m.IssueBlock(IssueOptions{}, "", 0); err == nil {
		t.Fatalf("expected error for zero count")
	}
}

func TestMagicLink(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	now := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return now }
	raw, claims, err := m.IssueMagicLink(IssueOptions{Next: "https://app.example.com/dash"})
	if err != nil {
		t.Fatalf("IssueMagicLink: %v", err)
	}
	if !claims.Magic || claims.Next != "https://app.example.com/dash" {
		t.Fatalf("magic claims wrong: mag=%v nxt=%q", claims.Magic, claims.Next)
	}
	if claims.ExpiresAt-now.Unix() > int64(MagicLinkTTL/time.Second) {
		t.Fatalf("magic link TTL too long: %d", claims.ExpiresAt-now.Unix())
	}
	got, err := m.VerifyMagic(raw)
	if err != nil {
		t.Fatalf("VerifyMagic: %v", err)
	}
	if got.Subject != claims.Subject {
		t.Fatalf("magic link subject mismatch")
	}
}

func TestMagicRequired(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	raw, _, _ := m.Issue(IssueOptions{})
	if _, err := m.VerifyMagic(raw); err != ErrNotMagic {
		t.Fatalf("expected ErrNotMagic, got %v", err)
	}
}

func TestSigner(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	a := m.Signer().Sign("GET|/orders|a=1|1.2.3.4|1700000000|<empty>")
	b := m.Signer().Sign("GET|/orders|a=1|1.2.3.4|1700000000|<empty>")
	if a != b {
		t.Fatalf("canonical signature must be deterministic")
	}
	c := m.Signer().Sign("GET|/orders|a=1|1.2.3.4|1700000001|<empty>")
	if a == c {
		t.Fatalf("signature must change with timestamp")
	}
	m2, _ := NewManager([]byte("0123456789abcdef0123456789abcdee"), "shepherd")
	if a == m2.Signer().Sign("GET|/orders|a=1|1.2.3.4|1700000000|<empty>") {
		t.Fatalf("signature must change with secret")
	}
}

func TestTrackOwnership(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	raw, claims, err := m.Issue(IssueOptions{
		Subject: "opaque-owner",
		Scopes:  []string{"write:docs"},
		Roles:   []string{"editor"},
		Block:   "blk-1",
		Meta:    map[string]string{"item": "doc-42"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	o, err := m.Track(raw)
	if err != nil {
		t.Fatalf("Track: %v", err)
	}
	if o.Subject != "opaque-owner" || o.Block != "blk-1" || o.Item != "doc-42" {
		t.Fatalf("ownership wrong: %+v", o)
	}
	if o.TokenID != claims.ID || o.IssuedAt != claims.IssuedAt || o.ExpiresAt != claims.ExpiresAt {
		t.Fatalf("issuance window wrong: %+v", o)
	}
	if _, err := m.Track("garbage.token"); err == nil {
		t.Fatalf("invalid token should not track")
	}
}

func TestOwnershipStore(t *testing.T) {
	s := NewOwnershipStore()
	if err := s.Claim("item-1", "sub-a"); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if owner, ok := s.Owner("item-1"); !ok || owner != "sub-a" {
		t.Fatalf("owner lookup failed: %q %v", owner, ok)
	}
	// Same subject re-claim is fine.
	if err := s.Claim("item-1", "sub-a"); err != nil {
		t.Fatalf("re-claim by owner should succeed: %v", err)
	}
	// Another subject cannot steal it.
	if err := s.Claim("item-1", "sub-b"); !errors.Is(err, ErrItemOwned) {
		t.Fatalf("steal should fail with ErrItemOwned, got %v", err)
	}
}

func TestRegenerateDeterministic(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	m.WithRegenerate(&RegenProfile{Enabled: true, Scopes: []string{"read:orders"}, Roles: []string{"member"}, TTL: time.Hour})

	raw1, c1, err := m.Regenerate(RegenOptions{Username: "alice", Password: "hunter2"})
	if err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	raw2, c2, err := m.Regenerate(RegenOptions{Username: "alice", Password: "hunter2"})
	if err != nil {
		t.Fatalf("Regenerate 2: %v", err)
	}
	// Same capability (subject/scopes/roles) every time.
	if c1.Subject != c2.Subject || raw1 == "" || raw2 == "" {
		t.Fatalf("subject not deterministic: %q vs %q", c1.Subject, c2.Subject)
	}
	if strings.Join(c1.Scopes, ",") != strings.Join(c2.Scopes, ",") ||
		strings.Join(c1.Roles, ",") != strings.Join(c2.Roles, ",") {
		t.Fatalf("capability not deterministic")
	}
	// A different password yields a different subject.
	c3 := mustRegen(t, m, "alice", "different")
	if c3.Subject == c1.Subject {
		t.Fatalf("different password produced the same subject")
	}
	// The subject is opaque and carries no username.
	if strings.Contains(c1.Subject, "alice") {
		t.Fatalf("subject leaked the username: %q", c1.Subject)
	}
	// Both tokens verify.
	if _, err := m.Verify(raw1); err != nil {
		t.Fatalf("regenerated token does not verify: %v", err)
	}
}

func TestRegenerateNeverWidens(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	m.WithRegenerate(&RegenProfile{Enabled: true, Scopes: []string{"read:orders", "write:orders"}, Roles: []string{"member"}})

	// Requesting a scope outside the profile is refused.
	if _, _, err := m.Regenerate(RegenOptions{Username: "bob", Password: "pw", Scopes: []string{"*"}}); !errors.Is(err, ErrWidenPrivilege) {
		t.Fatalf("expected ErrWidenPrivilege, got %v", err)
	}
	// A subset is allowed and narrows.
	_, c, err := m.Regenerate(RegenOptions{Username: "bob", Password: "pw", Scopes: []string{"read:orders"}})
	if err != nil {
		t.Fatalf("subset should be allowed: %v", err)
	}
	if len(c.Scopes) != 1 || c.Scopes[0] != "read:orders" {
		t.Fatalf("subset not honored: %v", c.Scopes)
	}
}

func TestRegenerateDisabled(t *testing.T) {
	m, _ := NewManager(testSecret(), "shepherd")
	if _, _, err := m.Regenerate(RegenOptions{Username: "u", Password: "p"}); !errors.Is(err, ErrRegenDisabled) {
		t.Fatalf("expected ErrRegenDisabled, got %v", err)
	}
	m.WithRegenerate(&RegenProfile{Enabled: false})
	if _, _, err := m.Regenerate(RegenOptions{Username: "u", Password: "p"}); !errors.Is(err, ErrRegenDisabled) {
		t.Fatalf("expected ErrRegenDisabled, got %v", err)
	}
	if _, _, err := m.Regenerate(RegenOptions{}); !errors.Is(err, ErrRegenDisabled) {
		t.Fatalf("expected ErrRegenDisabled, got %v", err)
	}
	m.WithRegenerate(&RegenProfile{Enabled: true})
	if _, _, err := m.Regenerate(RegenOptions{Username: "u"}); !errors.Is(err, ErrCredentials) {
		t.Fatalf("expected ErrCredentials, got %v", err)
	}
}

func mustRegen(t *testing.T, m *Manager, user, pass string) Claims {
	t.Helper()
	_, c, err := m.Regenerate(RegenOptions{Username: user, Password: pass})
	if err != nil {
		t.Fatalf("Regenerate(%s): %v", user, err)
	}
	return c
}
