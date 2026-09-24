// Package revoke provides the in-memory trust store that gives shepherd its
// "revocation without a database" story. Two kinds of entries are tracked in
// a single deny map:
//
//   - revocations: a token id (jti) or a block id (blk) that must no longer be
//     honored even if its signature and expiry are otherwise valid;
//   - consumptions: a magic-link token id that has already been redeemed, so
//     the same link cannot be replayed while the process is alive.
//
// Both are surfaced through Denied (RevokeToken/RevokeBlock for the former,
// Consume for the latter); callers choose which ids to check. Everything lives
// in RAM and is lost on restart — that is the intended trade-off of a
// database-less IAM. Token validity therefore hinges on the signature + TTL
// alone, and revocation is a best-effort bolt-on.
package revoke

import (
	"sync"
	"time"
)

// blockPrefix keys block revocations so they never collide with token ids.
const blockPrefix = "blk:"

// Store is a concurrency-safe, in-memory deny/consume map.
type Store struct {
	mu   sync.Mutex
	deny map[string]int64 // key -> expiry unix seconds
	now  func() time.Time
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{deny: make(map[string]int64), now: time.Now}
}

// RevokeToken marks a token id as revoked until its natural expiry.
func (s *Store) RevokeToken(jti string, expiresAt int64) {
	if jti == "" {
		return
	}
	s.add(jti, expiresAt)
}

// RevokeBlock marks every token carrying a block id as revoked. Claims must
// include the block field for this to take effect; see token.Claims.Block.
func (s *Store) RevokeBlock(blockID string, expiresAt int64) {
	if blockID == "" {
		return
	}
	s.add(blockPrefix+blockID, expiresAt)
}

// Consume records a one-time token (magic link) as already spent. Until the
// entry expires, Denied reports true for the same id, which is what stops
// link replays.
func (s *Store) Consume(jti string, expiresAt int64) {
	if jti == "" {
		return
	}
	s.add(jti, expiresAt)
}

// Denied reports whether a token id or block id is currently under a deny or
// consume entry that has not yet expired.
func (s *Store) Denied(id string) bool {
	return s.denied(id, s.now().Unix())
}

// DeniedFor reports whether id is denied at the given unix time.
func (s *Store) DeniedFor(id string, at int64) bool {
	return s.denied(id, at)
}

// Cleanup drops entries whose expiry has passed.
func (s *Store) Cleanup() {
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.deny {
		if exp <= now {
			delete(s.deny, k)
		}
	}
}

// Len reports the number of tracked entries (tests/debug only).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.deny)
}

func (s *Store) add(key string, expiresAt int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deny == nil {
		s.deny = make(map[string]int64)
	}
	s.deny[key] = expiresAt
}

func (s *Store) denied(id string, at int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.deny[id]; ok && exp > at {
		return true
	}
	if exp, ok := s.deny[blockPrefix+id]; ok && exp > at {
		return true
	}
	// The block check above also serves block ids passed directly.
	return false
}
