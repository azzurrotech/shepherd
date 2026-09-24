package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := New(60, 5) // 1/sec, burst 5
	l.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		ok, remaining, _ := l.Allow("ip")
		if !ok {
			t.Fatalf("request %d should pass within burst", i)
		}
		if remaining != float64(4-i) {
			t.Fatalf("request %d: remaining=%v want %d", i, remaining, 4-i)
		}
	}
	ok, _, resetAt := l.Allow("ip")
	if ok {
		t.Fatalf("burst exceeded, should be denied")
	}
	if resetAt.Before(now) {
		t.Fatalf("resetAt in the past: %v", resetAt)
	}

	// Advance 3 seconds: 3 tokens refilled.
	now = now.Add(3 * time.Second)
	for i := 0; i < 3; i++ {
		ok, _, _ := l.Allow("ip")
		if !ok {
			t.Fatalf("expected refill to allow request %d", i)
		}
	}
	ok, _, _ = l.Allow("ip")
	if ok {
		t.Fatalf("only 3 tokens should have refilled")
	}
}

func TestIndependentKeys(t *testing.T) {
	l := New(60, 1)
	if ok, _, _ := l.Allow("a"); !ok {
		t.Fatalf("key a denied")
	}
	if ok, _, _ := l.Allow("b"); !ok {
		t.Fatalf("key b denied (should have its own full bucket)")
	}
	if ok, _, _ := l.Allow("a"); ok {
		t.Fatalf("key a should now be limited")
	}
	if l.Len() != 2 {
		t.Fatalf("expected 2 buckets, got %d", l.Len())
	}
}

func TestStatusAndCleanup(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := New(60, 2)
	l.now = func() time.Time { return now }
	l.Allow("k")
	l.Allow("k")
	st := l.Status("k")
	if st.Remaining != 0 || st.Limit != 2 {
		t.Fatalf("status wrong: %+v", st)
	}
	now = now.Add(10 * time.Minute)
	l.Cleanup(5 * time.Minute)
	if l.Len() != 0 {
		t.Fatalf("cleanup did not remove idle bucket")
	}
}

func TestZeroRateBurstOnly(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := New(0, 0) // burst-only limiter: rate 0, burst clamped to 1
	l.now = func() time.Time { return now }
	if ok, _, _ := l.Allow("x"); !ok {
		t.Fatalf("first request of burst should pass")
	}
	if ok, _, _ := l.Allow("x"); ok {
		t.Fatalf("zero rate must not refill")
	}
}
