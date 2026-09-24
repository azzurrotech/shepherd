package token

import (
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
