// Package token implements shepherd's zero-knowledge, identity-less
// capability tokens.
//
// A token is a self-contained, signed capability: everything needed to
// authorize a request (who the opaque subject is, which scopes and roles it
// holds, when it expires, which audience it targets) travels inside the token
// itself. No identifying information about a person is ever stored — the
// subject is an opaque random identifier generated at issue time. The only
// thing a validation host needs is the shared signing secret, which makes
// validation fully stateless.
//
// Format (compact, stdlib-only):
//
//	<base64url(payloadJSON)>.<base64url(HMAC-SHA256(secret, payload))>
//
// The payload carries a version field so the encoding can evolve. The HMAC is
// computed over the exact base64url payload string, so tampering with any
// claim invalidates the signature.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version is the current token encoding version.
const Version = 1

// MagicLinkTTL is the default lifetime of a magic-link token. Magic links are
// short-lived on purpose: a stateless server cannot enforce single use and
// instead relies on a tight expiry window plus an optional in-memory once-use
// store.
const MagicLinkTTL = 10 * time.Minute

// MinSecretLen is the minimum acceptable master-secret length.
const MinSecretLen = 16

var (
	// ErrInvalidToken is returned when a token is malformed or fails
	// signature verification.
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpired is returned when a token is past its expiry.
	ErrExpired = errors.New("token expired")
	// ErrNotYetValid is returned when a token is used before its nbf
	// (not before) claim.
	ErrNotYetValid = errors.New("token not yet valid")
	// ErrWrongAudience is returned when a token targets a different audience
	// than the verifier expects.
	ErrWrongAudience = errors.New("token audience mismatch")
	// ErrNotMagic is returned when a non-magic token is used where a magic
	// link is required.
	ErrNotMagic = errors.New("token is not a magic link")
	// ErrWeakSecret is returned when the master secret is too short.
	ErrWeakSecret = errors.New("master secret too short")
	// ErrBadBlock is returned for invalid block-issue options.
	ErrBadBlock = errors.New("invalid block parameters")
)

// Claims is the signed payload of a capability token. It deliberately
// contains no personally identifying data: Subject and ID are opaque random
// identifiers.
type Claims struct {
	Version   int               `json:"v"`
	Issuer    string            `json:"iss,omitempty"`
	Audience  string            `json:"aud,omitempty"`
	Subject   string            `json:"sub"`           // opaque principal (one per key)
	Scopes    []string          `json:"scp,omitempty"` // RBAC scopes, e.g. ["read:orders","write:orders"]
	Roles     []string          `json:"rol,omitempty"` // RBAC roles, e.g. ["member","admin"]
	Block     string            `json:"blk,omitempty"` // block id shared by a batch of keys
	NotBefore int64             `json:"nbf,omitempty"` // unix seconds
	IssuedAt  int64             `json:"iat"`
	ExpiresAt int64             `json:"exp"`
	ID        string            `json:"jti"`            // unique token id
	Magic     bool              `json:"mag,omitempty"`  // true for magic-link tokens
	Next      string            `json:"nxt,omitempty"`  // magic-link redirect target
	Meta      map[string]string `json:"meta,omitempty"` // arbitrary key/values for query enrichment
}

// HasScope reports whether the claims grant the given scope.
func (c Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// HasRole reports whether the claims carry the given role.
func (c Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Expired reports whether the token is past expiry at time now.
func (c Claims) Expired(now time.Time) bool {
	return now.Unix() >= c.ExpiresAt
}

// Valid reports whether the token is within its validity window at now.
func (c Claims) Valid(now time.Time) bool {
	return now.Unix() >= c.NotBefore && now.Unix() < c.ExpiresAt
}

// IssuedKey is one key from a block issuance.
type IssuedKey struct {
	Index  int    `json:"index"`
	Token  string `json:"token"`
	Claims Claims `json:"claims"`
}

// Manager issues and verifies tokens. It is safe for concurrent use.
type Manager struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
	magicTTL time.Duration
	now      func() time.Time
}

// NewManager returns a Manager that signs with secret and issuer. An empty
// audience means "any" (verification skips the audience check). The default
// token TTL is 24 hours; magic links default to MagicLinkTTL.
func NewManager(secret []byte, issuer string) (*Manager, error) {
	if len(secret) < MinSecretLen {
		return nil, ErrWeakSecret
	}
	return &Manager{
		secret:   append([]byte(nil), secret...),
		issuer:   issuer,
		ttl:      24 * time.Hour,
		magicTTL: MagicLinkTTL,
		now:      time.Now,
	}, nil
}

// WithAudience sets the default audience for issued tokens.
func (m *Manager) WithAudience(aud string) *Manager { m.audience = aud; return m }

// WithTTL sets the default lifetime for issued tokens.
func (m *Manager) WithTTL(ttl time.Duration) *Manager { m.ttl = ttl; return m }

// IssueOptions configures a single token or magic link.
type IssueOptions struct {
	Subject   string            // opaque principal; a random one is generated when empty
	Scopes    []string          // RBAC scopes
	Roles     []string          // RBAC roles
	Audience  string            // falls back to the manager default
	TTL       time.Duration     // falls back to the manager default
	NotBefore time.Time         // optional
	Block     string            // optional block id for batch revocation
	Magic     bool              // issue as a magic-link token (short TTL)
	Next      string            // magic-link redirect target
	Meta      map[string]string // arbitrary claims for enrichment
}

// Issue creates a new capability token. It returns the compact signed token
// and the claims embedded in it.
func (m *Manager) Issue(o IssueOptions) (string, Claims, error) {
	aud := o.Audience
	if aud == "" {
		aud = m.audience
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = m.ttl
		if o.Magic {
			ttl = m.magicTTL
		}
	}
	subj := o.Subject
	if subj == "" {
		id, err := RandomID()
		if err != nil {
			return "", Claims{}, err
		}
		subj = id
	}
	jti, err := RandomID()
	if err != nil {
		return "", Claims{}, err
	}
	now := m.now()
	claims := Claims{
		Version:   Version,
		Issuer:    m.issuer,
		Audience:  aud,
		Subject:   subj,
		Scopes:    append([]string(nil), o.Scopes...),
		Roles:     append([]string(nil), o.Roles...),
		Block:     o.Block,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		ID:        jti,
		Magic:     o.Magic,
		Next:      o.Next,
		Meta:      o.Meta,
	}
	if !o.NotBefore.IsZero() {
		claims.NotBefore = o.NotBefore.Unix()
	}
	raw, err := m.sign(claims)
	if err != nil {
		return "", Claims{}, err
	}
	return raw, claims, nil
}

// IssueBlock issues count keys as one block. All keys share the block id
// (which can later be revoked as a unit) but each carries its own subject and
// token id. When blockID is empty a random block id is generated.
func (m *Manager) IssueBlock(o IssueOptions, blockID string, count int) ([]IssuedKey, error) {
	if count <= 0 || count > 10000 {
		return nil, fmt.Errorf("%w: count must be 1..10000, got %d", ErrBadBlock, count)
	}
	if blockID == "" {
		id, err := RandomID()
		if err != nil {
			return nil, err
		}
		blockID = id
	}
	// A block of keys that are identical in every way except index would be
	// pointless (they would all be interchangeable), so give each key a
	// distinct meta entry identifying its slot inside the block.
	keys := make([]IssuedKey, 0, count)
	for i := 0; i < count; i++ {
		meta := map[string]string{"block": blockID, "index": fmt.Sprintf("%d", i)}
		o.Block = blockID
		o.Meta = meta
		raw, claims, err := m.Issue(o)
		if err != nil {
			return nil, err
		}
		keys = append(keys, IssuedKey{Index: i, Token: raw, Claims: claims})
	}
	return keys, nil
}

// Verify checks signature, version, validity window and (when set) audience,
// and returns the claims on success.
func (m *Manager) Verify(raw string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return Claims{}, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	expected := m.mac(parts[0])
	if !hmac.Equal(expected, sig) {
		return Claims{}, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if c.Version != Version {
		return Claims{}, fmt.Errorf("%w: version %d", ErrInvalidToken, c.Version)
	}
	now := m.now()
	if !c.Valid(now) {
		if now.Unix() >= c.ExpiresAt {
			return Claims{}, ErrExpired
		}
		return Claims{}, ErrNotYetValid
	}
	if m.audience != "" && c.Audience != "" && c.Audience != m.audience {
		return Claims{}, ErrWrongAudience
	}
	return c, nil
}

// VerifyMagic is Verify that additionally requires the token to be a magic
// link. It is used by gateway/magic-link flows that only accept tokens issued
// through the magic-link endpoint.
func (m *Manager) VerifyMagic(raw string) (Claims, error) {
	c, err := m.Verify(raw)
	if err != nil {
		return Claims{}, err
	}
	if !c.Magic {
		return Claims{}, ErrNotMagic
	}
	return c, nil
}

// IssueMagicLink returns a token that is valid for the manager's magic-link
// TTL and carries the redirect target in its Next claim.
func (m *Manager) IssueMagicLink(o IssueOptions) (string, Claims, error) {
	o.Magic = true
	return m.Issue(o)
}

// Signer exposes the raw HMAC primitive used to sign canonicalized request
// lines for the gateway (X-Shepherd-Signature). Keeping it on the Manager
// guarantees the gateway always uses the same secret as the token store.
func (m *Manager) Signer() Signer { return Signer{secret: m.secret} }

// sign serializes claims and returns the compact token.
func (m *Manager) sign(c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	return b64 + "." + base64.RawURLEncoding.EncodeToString(m.mac(b64)), nil
}

// mac is HMAC-SHA256 over the base64url payload.
func (m *Manager) mac(b64 string) []byte {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(b64))
	return mac.Sum(nil)
}

// Signer computes HMAC-SHA256 request signatures for gateway heads-up to
// upstreams.
type Signer struct {
	secret []byte
}

// Sign signs canonical:method|path|query|ip|time|bodyhash.
func (s Signer) Sign(canonical string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomID returns a 128-bit random identifier as hex.
func RandomID() (string, error) {
	b, err := RandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
