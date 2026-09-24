// Package ratelimit implements a software token-bucket rate limiter backed by
// in-memory state only — no database required. The limiter is keyed by an
// arbitrary string (client IP, token subject, or both), so it works the same
// in server mode and middleware mode.
package ratelimit

import (
	"sync"
	"time"
)

// bucket is one token bucket for a single key.
type bucket struct {
	tokens float64
	last   time.Time
}

// Status is a point-in-time snapshot of one key's bucket.
type Status struct {
	Key       string    `json:"key"`
	Remaining float64   `json:"remaining"`
	Limit     float64   `json:"limit"`
	ResetAt   time.Time `json:"reset_at"`
}

// Limiter is a concurrency-safe token-bucket limiter.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens refilled per second
	burst   float64 // maximum bucket size
	now     func() time.Time
	buckets map[string]*bucket
}

// New returns a Limiter allowing bursts up to burst tokens at a sustained
// average of perMinute tokens per minute (fractional values allowed).
func New(perMinute float64, burst float64) *Limiter {
	if perMinute < 0 {
		perMinute = 0
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    perMinute / 60,
		burst:   burst,
		now:     time.Now,
		buckets: make(map[string]*bucket),
	}
}

// Allow consumes one token for key. It reports whether the request may pass
// and how many tokens remain; when denied, resetAt is when the next token is
// expected to be available, useful for a Retry-After header.
func (l *Limiter) Allow(key string) (ok bool, remaining float64, resetAt time.Time) {
	return l.allowAt(key, l.now())
}

func (l *Limiter) allowAt(key string, now time.Time) (bool, float64, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens < 1 {
		return false, b.tokens, now.Add(l.timeToToken(b.tokens))
	}
	b.tokens--
	if l.rate == 0 {
		return true, b.tokens, now // unbounded bucket; never "resets" differently
	}
	return true, b.tokens, now.Add(time.Duration(float64(l.burst/l.rate) * float64(time.Second)))
}

// Status returns a snapshot for key without consuming a token.
func (l *Limiter) Status(key string) Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if ok {
		l.refill(b, now)
		return Status{Key: key, Remaining: b.tokens, Limit: l.burst, ResetAt: l.fullAt(b.tokens, now)}
	}
	return Status{Key: key, Remaining: l.burst, Limit: l.burst, ResetAt: now}
}

// Reset drops all bucket state (e.g. after a config reload).
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[string]*bucket)
}

// Cleanup removes buckets idle for longer than idleFor, so the map does not
// grow without bound as keys churn.
func (l *Limiter) Cleanup(idleFor time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-idleFor)
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// Len reports the number of tracked buckets (tests/debug only).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// refill adds the tokens earned since the bucket was last touched.
func (l *Limiter) refill(b *bucket, now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.last = now
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
}

// timeToToken is how long until one token accrues given current balance.
func (l *Limiter) timeToToken(tokens float64) time.Duration {
	if l.rate <= 0 {
		return time.Duration(0)
	}
	need := 1 - tokens
	if need <= 0 {
		return time.Duration(0)
	}
	return time.Duration((need / l.rate) * float64(time.Second))
}

// fullAt is when the bucket reaches full from its current balance.
func (l *Limiter) fullAt(tokens float64, now time.Time) time.Time {
	if l.rate <= 0 {
		return now
	}
	need := l.burst - tokens
	if need <= 0 {
		return now
	}
	return now.Add(time.Duration((need / l.rate) * float64(time.Second)))
}
