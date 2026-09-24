package revoke

import (
	"testing"
	"time"
)

func TestRevokeToken(t *testing.T) {
	s := NewStore()
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	s.RevokeToken("abc", now.Add(time.Hour).Unix())
	if !s.Denied("abc") {
		t.Fatalf("token not denied after revoke")
	}
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	if s.Denied("abc") {
		t.Fatalf("entry should expire on its own")
	}
}

func TestRevokeBlock(t *testing.T) {
	s := NewStore()
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	s.RevokeBlock("blk1", now.Add(time.Hour).Unix())
	// A claim with Block "blk1" is denied by id and by block.
	if !s.Denied("blk1") {
		t.Fatalf("block id itself should be denied")
	}
	// A token visible through the block prefix must also be denied.
	if !s.DeniedFor("blk:"+"blk1", now.Unix()) {
		t.Fatalf("prefixed block key not denied")
	}
}

func TestConsumeOnce(t *testing.T) {
	s := NewStore()
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	s.Consume("magic1", now.Add(time.Hour).Unix())
	if !s.Denied("magic1") {
		t.Fatalf("consumed magic link not denied")
	}
	// Different ids remain allowed.
	if s.Denied("magic2") {
		t.Fatalf("unrelated id denied")
	}
}

func TestCleanup(t *testing.T) {
	s := NewStore()
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	s.RevokeToken("a", now.Add(time.Minute).Unix())
	s.RevokeToken("b", now.Add(-time.Second).Unix())
	s.Cleanup()
	if !s.Denied("a") {
		t.Fatalf("live entry removed by cleanup")
	}
	if s.Denied("b") {
		t.Fatalf("expired entry survived cleanup")
	}
}
