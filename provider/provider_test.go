package provider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"azzurrotech/shepherd/token"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func newManager(t *testing.T) *token.Manager {
	t.Helper()
	m, err := token.NewManager([]byte(testSecret), "provider-test")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// fakeDeny is a minimal DenyChecker.
type fakeDeny struct{ ids map[string]bool }

func (f fakeDeny) Denied(id string) bool { return f.ids[id] }

// fakeLimiter denies after allowN calls for a given key.
type fakeLimiter struct {
	remaining float64
	calls     int
}

func (f *fakeLimiter) Allow(key string) (bool, float64, time.Time) {
	f.calls++
	if f.remaining <= 0 {
		return false, 0, time.Now().Add(time.Second)
	}
	f.remaining--
	return true, f.remaining, time.Now().Add(time.Second)
}

func bearer(r *http.Request, tok string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func TestAuthenticateSuccess(t *testing.T) {
	m := newManager(t)
	tok, claims, err := m.Issue(token.IssueOptions{
		Subject: "opaque-1",
		Scopes:  []string{"read:orders"},
		Roles:   []string{"member"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	p := FromCapability(m)
	got, err := p.Authenticate(bearer(httptest.NewRequest("GET", "/", nil), tok))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.Subject != "opaque-1" || got.Subject != claims.Subject {
		t.Fatalf("subject mismatch: %+v", got)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "read:orders" || !contains(got.Roles, "member") {
		t.Fatalf("capability mismatch: %+v", got)
	}
}

func TestAuthenticateRefusals(t *testing.T) {
	m := newManager(t)
	p := FromCapability(m)

	// No token.
	if _, err := p.Authenticate(httptest.NewRequest("GET", "/", nil)); !errors.Is(err, ErrNoToken) {
		t.Fatalf("expected ErrNoToken, got %v", err)
	}
	// Garbage token.
	if _, err := p.Authenticate(bearer(httptest.NewRequest("GET", "/", nil), "nope.nope")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	// Revoked token.
	tok, claims, _ := m.Issue(token.IssueOptions{})
	withDeny := New(m, WithDeny(fakeDeny{ids: map[string]bool{claims.ID: true}}))
	if _, err := withDeny.Authenticate(bearer(httptest.NewRequest("GET", "/", nil), tok)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

func TestTokenFromCookie(t *testing.T) {
	m := newManager(t)
	tok, _, _ := m.Issue(token.IssueOptions{Subject: "cookie-sub"})
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "shepherd_cap", Value: tok})
	p, err := FromCapability(m).Authenticate(r)
	if err != nil || p.Subject != "cookie-sub" {
		t.Fatalf("cookie auth failed: %+v %v", p, err)
	}
}

func TestRateLimited(t *testing.T) {
	m := newManager(t)
	tok, _, _ := m.Issue(token.IssueOptions{Subject: "rl"})
	lim := &fakeLimiter{remaining: 1}
	p := New(m, WithLimiter(lim))
	if _, err := p.Authenticate(bearer(httptest.NewRequest("GET", "/", nil), tok)); err != nil {
		t.Fatalf("first call should pass: %v", err)
	}
	if _, err := p.Authenticate(bearer(httptest.NewRequest("GET", "/", nil), tok)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

func TestWrapStatusCodes(t *testing.T) {
	m := newManager(t)
	lim := &fakeLimiter{remaining: 1}
	p := New(m, WithLimiter(lim))
	h := p.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pr, ok := PrincipalFromContext(r.Context())
		if !ok || pr.Subject == "" {
			t.Errorf("principal not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Missing token -> 401.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: got %d, want 401", rec.Code)
	}

	// Valid token -> 200.
	tok, _, _ := m.Issue(token.IssueOptions{Subject: "w"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bearer(httptest.NewRequest("GET", "/", nil), tok))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: got %d, want 200", rec.Code)
	}
	// The limiter is now exhausted for "sub:w"; next valid token -> 429.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bearer(httptest.NewRequest("GET", "/", nil), tok))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited: got %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatalf("429 must carry Retry-After")
	}
}

func TestFromCapabilityImplementsProvider(t *testing.T) {
	var _ Provider = FromCapability(newManager(t))
	// The refusal body is JSON with an error field, as pod expects.
	m := newManager(t)
	rec := httptest.NewRecorder()
	FromCapability(m).Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal body not JSON: %v", err)
	}
	if body["error"] == nil {
		t.Fatalf("refusal body missing error: %v", body)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
