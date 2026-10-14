// Package debounce implements shepherd's duplicate/replay suppression — the
// policy that stops a misbehaving client from amplifying load by hammering the
// same request.
//
// A Debouncer is keyed by an opaque string. The middleware builds that key from
// the HTTP method, path, query, client identity and a digest of the request
// body, so two requests that are "identical" share a key. For each key it
// enforces two independent limits:
//
//   - Window: once a request for the key has completed, further identical
//     requests are suppressed for Window. This is the replay/duplicate guard.
//   - MaxInflight: at most this many identical requests may run concurrently;
//     every extra one is dropped rather than queued (so a client cannot use
//     shepherd as an amplifier).
//
// Extra identical requests are therefore coalesced/dropped — never forwarded.
// Everything is in memory and lost on restart: the same deliberate "no
// database" trade-off as the rest of shepherd. A window of zero (or negative)
// disables suppression entirely, which gives the CLI its "-debounce 0 = off"
// semantics.
//
// The Debouncer is safe for concurrent use. Callers must call the release
// function returned by Allow exactly once (it is idempotent) when the guarded
// request finishes.
package debounce

import (
	"sync"
	"time"
)

// Reasons reported by Allow when a request is not allowed through.
const (
	// ReasonDuplicate marks a replay of a request seen within the window.
	ReasonDuplicate = "duplicate"
	// ReasonInflight marks a request that exceeded the max-in-flight cap.
	ReasonInflight = "max-inflight"
)

// Decision is the outcome of a debounce check.
type Decision struct {
	// Allowed is true when the caller may proceed (and must call release).
	Allowed bool `json:"allowed"`
	// Reason is empty when allowed, otherwise one of the Reason* constants.
	Reason string `json:"reason,omitempty"`
}

// entry is the per-key bookkeeping.
type entry struct {
	// inflight counts requests currently running for this key.
	inflight int
	// lastSeen is when the most recent request for this key completed. A zero
	// value means no request has completed yet.
	lastSeen time.Time
}

// Debouncer suppresses duplicate/replayed identical requests. It is safe for
// concurrent use and must be created with New.
type Debouncer struct {
	mu          sync.Mutex
	window      time.Duration
	maxInflight int
	now         func() time.Time
	entries     map[string]*entry
}

// New returns a Debouncer. A window <= 0 disables suppression (every call is
// allowed). maxInflight < 1 is normalized to 1, which means "one identical
// request at a time".
func New(window time.Duration, maxInflight int) *Debouncer {
	if maxInflight < 1 {
		maxInflight = 1
	}
	return &Debouncer{
		window:      window,
		maxInflight: maxInflight,
		now:         time.Now,
		entries:     make(map[string]*entry),
	}
}

// Window returns the configured suppression window.
func (d *Debouncer) Window() time.Duration { return d.window }

// MaxInflight returns the configured concurrent-identical cap.
func (d *Debouncer) MaxInflight() int { return d.maxInflight }

// Enabled reports whether the Debouncer suppresses anything. A window of zero
// means the feature is off.
func (d *Debouncer) Enabled() bool { return d != nil && d.window > 0 }

// Allow checks whether a request identified by key may proceed. When it
// returns an allowed decision, release is non-nil and must be called when the
// request finishes; release is safe to call more than once. When it returns a
// refusal, release is nil, Reason explains why, and the caller drops the
// request without doing any work.
func (d *Debouncer) Allow(key string) (Decision, func()) {
	// An empty key cannot be meaningfully deduplicated, and a disabled
	// debouncer is a pass-through. Both yield a no-op release.
	noop := func() {}
	if d == nil || d.window <= 0 || key == "" {
		return Decision{Allowed: true}, noop
	}

	d.mu.Lock()
	now := d.now()
	e := d.entries[key]
	if e == nil {
		e = &entry{}
		d.entries[key] = e
	}

	// 1. Volume cap: refuse once too many identical requests are in flight.
	if e.inflight >= d.maxInflight {
		d.mu.Unlock()
		return Decision{Reason: ReasonInflight}, nil
	}
	// 2. Replay guard: refuse an identical request that follows a completed
	//    one too closely.
	if !e.lastSeen.IsZero() && now.Sub(e.lastSeen) < d.window {
		d.mu.Unlock()
		return Decision{Reason: ReasonDuplicate}, nil
	}

	e.inflight++
	d.mu.Unlock()

	// Release marks the request complete and starts the replay window.
	var once sync.Once
	release := func() {
		once.Do(func() {
			d.mu.Lock()
			e.inflight--
			e.lastSeen = d.now()
			d.mu.Unlock()
		})
	}
	return Decision{Allowed: true}, release
}

// Cleanup drops bookkeeping for keys that have been idle (no in-flight request
// and no recent completion) for longer than idleFor, so the map does not grow
// without bound as keys churn.
func (d *Debouncer) Cleanup(idleFor time.Duration) {
	if d == nil || idleFor <= 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := d.now().Add(-idleFor)
	for k, e := range d.entries {
		if e.inflight == 0 && !e.lastSeen.After(cutoff) {
			delete(d.entries, k)
		}
	}
}

// Len reports the number of tracked keys (tests/debug only).
func (d *Debouncer) Len() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}
