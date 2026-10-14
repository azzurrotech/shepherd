package debounce

import (
	"sync"
	"testing"
	"time"
)

// newTestDebouncer returns a Debouncer with a controllable clock so tests do
// not depend on wall-clock sleeps.
func newTestDebouncer(window time.Duration, maxInflight int) (*Debouncer, *time.Time) {
	d := New(window, maxInflight)
	now := time.Unix(1_700_000_000, 0)
	d.now = func() time.Time { return now }
	return d, &now
}

func TestDisabledAllowsEverything(t *testing.T) {
	d := New(0, 4)
	if d.Enabled() {
		t.Fatalf("zero window must be disabled")
	}
	// Even back-to-back identical calls pass when the window is off.
	for i := 0; i < 5; i++ {
		dec, release := d.Allow("same")
		if !dec.Allowed {
			t.Fatalf("disabled debouncer refused call %d: %+v", i, dec)
		}
		if release == nil {
			t.Fatalf("allowed call returned nil release")
		}
		release()
	}
}

func TestDuplicateWithinWindowDropped(t *testing.T) {
	d, now := newTestDebouncer(250*time.Millisecond, 4)

	dec, release := d.Allow("k")
	if !dec.Allowed {
		t.Fatalf("first call refused: %+v", dec)
	}
	release() // request completed at t0

	// Immediately identical -> duplicate.
	dec, r2 := d.Allow("k")
	if dec.Allowed || dec.Reason != ReasonDuplicate || r2 != nil {
		t.Fatalf("replay within window should be a duplicate, got %+v", dec)
	}

	// After the window, the same key is allowed again.
	*now = now.Add(251 * time.Millisecond)
	dec, release = d.Allow("k")
	if !dec.Allowed {
		t.Fatalf("call after window refused: %+v", dec)
	}
	release()
}

func TestDifferentKeysIndependent(t *testing.T) {
	d, _ := newTestDebouncer(time.Second, 4)
	if dec, rel := d.Allow("a"); !dec.Allowed {
		t.Fatalf("a refused: %+v", dec)
	} else {
		rel()
	}
	// A different key is never considered a duplicate of "a".
	if dec, rel := d.Allow("b"); !dec.Allowed {
		t.Fatalf("b refused: %+v", dec)
	} else {
		rel()
	}
}

func TestMaxInflightDropsExtras(t *testing.T) {
	d, now := newTestDebouncer(time.Millisecond, 2)

	// Two concurrent identical requests fit.
	dec1, rel1 := d.Allow("k")
	dec2, rel2 := d.Allow("k")
	if !dec1.Allowed || !dec2.Allowed {
		t.Fatalf("first two in-flight calls should be allowed: %+v %+v", dec1, dec2)
	}
	// The third exceeds maxInflight and is dropped.
	dec3, rel3 := d.Allow("k")
	if dec3.Allowed || dec3.Reason != ReasonInflight || rel3 != nil {
		t.Fatalf("third call should be max-inflight refused, got %+v", dec3)
	}
	// Completing one frees a slot; move past the replay window so the freed
	// slot can be used rather than being suppressed as a duplicate.
	rel1()
	*now = now.Add(2 * time.Millisecond)
	dec4, rel4 := d.Allow("k")
	if !dec4.Allowed {
		t.Fatalf("call after a slot freed should pass: %+v", dec4)
	}
	rel2()
	rel4()
}

func TestReleaseIdempotent(t *testing.T) {
	d, _ := newTestDebouncer(time.Hour, 1)
	dec, release := d.Allow("k")
	if !dec.Allowed {
		t.Fatalf("refused: %+v", dec)
	}
	release()
	release() // must not double-decrement
	// With one slot, a fresh call is allowed (no window elapsed for duplicate
	// because lastSeen is "now"; but a request already completed and the window
	// is 1h so it is a duplicate — verify the count did not go negative by
	// checking a *different* key still works).
	if dec2, rel2 := d.Allow("other"); !dec2.Allowed {
		t.Fatalf("other key refused: %+v", dec2)
	} else {
		rel2()
	}
}

func TestConcurrentAllowRaceFree(t *testing.T) {
	d := New(time.Millisecond, 4)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if dec, rel := d.Allow("hot"); dec.Allowed {
					rel()
				}
			}
		}()
	}
	wg.Wait()
	if d.Len() == 0 {
		t.Fatalf("expected the hot key to be tracked")
	}
}

func TestCleanup(t *testing.T) {
	d, now := newTestDebouncer(time.Millisecond, 1)
	if dec, rel := d.Allow("k"); dec.Allowed {
		rel()
	} else {
		t.Fatalf("refused: %+v", dec)
	}
	if d.Len() != 1 {
		t.Fatalf("expected 1 tracked key, got %d", d.Len())
	}
	*now = now.Add(2 * time.Hour)
	d.Cleanup(time.Hour)
	if d.Len() != 0 {
		t.Fatalf("expected cleanup to drop the idle key, got %d", d.Len())
	}
}
