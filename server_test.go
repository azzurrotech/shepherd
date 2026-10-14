package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"azzurrotech/shepherd/middleware"
	"azzurrotech/shepherd/token"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T, opts Options) *Server {
	t.Helper()
	if opts.Secret == nil {
		opts.Secret = []byte(testSecret)
	}
	if opts.Issuer == "" {
		opts.Issuer = "shepherd-test"
	}
	s, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "shepherd.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func doJSON(t *testing.T, h http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return m
}

// --- H04: POST /api/provider/authenticate ---

func TestProviderAuthenticateEndpoint(t *testing.T) {
	s := newTestServer(t, Options{})
	tok, claims, err := s.mw.Issue(token.IssueOptions{
		Subject: "opaque-principal",
		Scopes:  []string{"read:orders"},
		Roles:   []string{"member"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Present the token in the body: receive the principal.
	rec := doJSON(t, s.Router(), "POST", "/api/provider/authenticate",
		`{"token":"`+tok+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticate valid token: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if body["authenticated"] != true || body["subject"] != "opaque-principal" {
		t.Fatalf("principal not returned: %v", body)
	}
	if body["subject"] != claims.Subject {
		t.Fatalf("subject mismatch: %v != %v", body["subject"], claims.Subject)
	}
	if scopes, _ := body["scopes"].([]any); len(scopes) != 1 || scopes[0] != "read:orders" {
		t.Fatalf("scopes not returned: %v", body["scopes"])
	}

	// Present the same token as a bearer header.
	rec = doJSON(t, s.Router(), "POST", "/api/provider/authenticate", "",
		map[string]string{"Authorization": "Bearer " + tok})
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticate via bearer: got %d, want 200", rec.Code)
	}

	// A missing token is a refusal (401).
	rec = doJSON(t, s.Router(), "POST", "/api/provider/authenticate", "{}", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: got %d, want 401", rec.Code)
	}
	if b := decode(t, rec); b["authenticated"] != false {
		t.Fatalf("refusal must be explicit: %v", b)
	}

	// A garbage token is a refusal (401).
	rec = doJSON(t, s.Router(), "POST", "/api/provider/authenticate", `{"token":"nope.nope"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d, want 401", rec.Code)
	}

	// Over the rate limit is a 429 refusal.
	limited := newTestServer(t, Options{RatePerMinute: 60, Burst: 1})
	ltok, _, _ := limited.mw.Issue(token.IssueOptions{Subject: "rl"})
	if rec := doJSON(t, limited.Router(), "POST", "/api/provider/authenticate", `{"token":"`+ltok+`"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("first limited call: got %d, want 200", rec.Code)
	}
	rec = doJSON(t, limited.Router(), "POST", "/api/provider/authenticate", `{"token":"`+ltok+`"}`, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over limit: got %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatalf("429 must carry Retry-After")
	}
}

// --- H05: POST /api/keys/regenerate ---

func TestRegenerateEndpoint(t *testing.T) {
	cfg := writeConfig(t, `{
		"regenerate": {"enabled": true, "scopes": ["read:orders"], "roles": ["member"], "ttl": "1h"}
	}`)
	s := newTestServer(t, Options{ConfigPath: cfg})

	// Same credential -> same deterministic subject/capability.
	rec1 := doJSON(t, s.Router(), "POST", "/api/keys/regenerate", `{"username":"alice","password":"hunter2"}`, nil)
	if rec1.Code != http.StatusCreated {
		t.Fatalf("regenerate: got %d, want 201 (%s)", rec1.Code, rec1.Body.String())
	}
	b1 := decode(t, rec1)
	tok1, _ := b1["token"].(string)
	if tok1 == "" {
		t.Fatalf("no token returned: %v", b1)
	}
	c1, _ := b1["claims"].(map[string]any)
	sub1, _ := c1["sub"].(string)
	if sub1 == "" {
		t.Fatalf("no derived subject: %v", c1)
	}
	// The profile's capability is reproduced.
	if scp, _ := c1["scp"].([]any); len(scp) != 1 || scp[0] != "read:orders" {
		t.Fatalf("provisioned scopes not reproduced: %v", c1)
	}
	if rol, _ := c1["rol"].([]any); len(rol) != 1 || rol[0] != "member" {
		t.Fatalf("provisioned roles not reproduced: %v", c1)
	}
	// No username/password is echoed or persisted.
	if strings.Contains(rec1.Body.String(), "username") || strings.Contains(rec1.Body.String(), "password") {
		t.Fatalf("credential leaked in response: %s", rec1.Body.String())
	}

	rec2 := doJSON(t, s.Router(), "POST", "/api/keys/regenerate", `{"username":"alice","password":"hunter2"}`, nil)
	b2 := decode(t, rec2)
	c2, _ := b2["claims"].(map[string]any)
	if sub2, _ := c2["sub"].(string); sub2 != sub1 {
		t.Fatalf("subject not deterministic: %q != %q", sub2, sub1)
	}

	// A different password yields a different subject.
	rec3 := doJSON(t, s.Router(), "POST", "/api/keys/regenerate", `{"username":"alice","password":"other"}`, nil)
	c3, _ := decode(t, rec3)["claims"].(map[string]any)
	if sub3, _ := c3["sub"].(string); sub3 == sub1 {
		t.Fatalf("different password produced the same subject")
	}

	// Never widens privilege: a scope outside the profile is refused.
	rec4 := doJSON(t, s.Router(), "POST", "/api/keys/regenerate",
		`{"username":"alice","password":"hunter2","scopes":["*"]}`, nil)
	if rec4.Code != http.StatusBadRequest {
		t.Fatalf("widening should be refused with 400, got %d (%s)", rec4.Code, rec4.Body.String())
	}

	// Missing credentials -> 400.
	rec5 := doJSON(t, s.Router(), "POST", "/api/keys/regenerate", `{"username":"alice"}`, nil)
	if rec5.Code != http.StatusBadRequest {
		t.Fatalf("missing password should be 400, got %d", rec5.Code)
	}
}

func TestRegenerateDisabledByConfig(t *testing.T) {
	cfg := writeConfig(t, `{"regenerate": {"enabled": false}}`)
	s := newTestServer(t, Options{ConfigPath: cfg})
	rec := doJSON(t, s.Router(), "POST", "/api/keys/regenerate", `{"username":"a","password":"b"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disabled regenerate should be 403, got %d", rec.Code)
	}
}

// --- H06: GET /api/track/<token> ---

func TestTrackEndpoint(t *testing.T) {
	s := newTestServer(t, Options{})
	tok, claims, err := s.mw.Issue(token.IssueOptions{
		Subject: "owner-1",
		Scopes:  []string{"write:doc"},
		Roles:   []string{"editor"},
		Block:   "blk-9",
		Meta:    map[string]string{"item": "doc-42"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := doJSON(t, s.Router(), "GET", "/api/track/"+tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("track: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	b := decode(t, rec)
	if b["tracked"] != true || b["subject"] != "owner-1" {
		t.Fatalf("ownership not resolved: %v", b)
	}
	if b["block"] != "blk-9" || b["item"] != "doc-42" || b["jti"] != claims.ID {
		t.Fatalf("ownership fields wrong: %v", b)
	}
	// The store now keeps item -> subject (never item -> username).
	if b["owner"] != "owner-1" {
		t.Fatalf("recorded owner wrong: %v", b["owner"])
	}
	if owner, ok := s.mw.ItemOwner("doc-42"); !ok || owner != "owner-1" {
		t.Fatalf("ownership store not populated: %q %v", owner, ok)
	}
	// Identity is never revealed: no username appears.
	if strings.Contains(rec.Body.String(), "username") {
		t.Fatalf("track leaked identity: %s", rec.Body.String())
	}

	// An invalid token -> 404 (unknown/invalid).
	rec = doJSON(t, s.Router(), "GET", "/api/track/not.a.token", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invalid track token: got %d, want 404", rec.Code)
	}
}

// --- H07: debounce flag/config plumbing ---

func TestDebounceConfigParsing(t *testing.T) {
	cfg := writeConfig(t, `{"debounce": {"window_ms": 123, "max_inflight": 7}}`)
	fc, err := loadFileConfig(cfg)
	if err != nil {
		t.Fatalf("loadFileConfig: %v", err)
	}
	if fc.Debounce == nil || fc.Debounce.WindowMS != 123 || fc.Debounce.MaxInflight != 7 {
		t.Fatalf("debounce block not parsed: %+v", fc.Debounce)
	}
}

func TestDebounceDropsDuplicateGatewayRequests(t *testing.T) {
	var calls int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newTestServer(t, Options{Debounce: 500 * time.Millisecond, DebounceMax: 4, DefaultAllow: true})
	if err := s.registerUpstream(middleware.Upstream{
		Name: "b", Prefix: "b", Target: backend.URL, Public: true, MaxBody: 1 << 20,
	}); err != nil {
		t.Fatalf("registerUpstream: %v", err)
	}
	router := s.Router()

	rec1 := doJSON(t, router, "GET", "/gw/b/thing", "", nil)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first gateway request: got %d, want 200 (%s)", rec1.Code, rec1.Body.String())
	}
	// The identical repeat within the window is dropped, not forwarded.
	rec2 := doJSON(t, router, "GET", "/gw/b/thing", "", nil)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("duplicate gateway request: got %d, want 429 (%s)", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("X-Shepherd-Debounced") == "" {
		t.Fatalf("debounce reason header missing")
	}
	if calls != 1 {
		t.Fatalf("backend should have seen exactly one request, saw %d", calls)
	}
}

// TestDebounceDisabledByDefaultZero confirms 0 = off: with no window a repeated
// identical gateway request is forwarded normally.
func TestDebounceDisabled(t *testing.T) {
	var calls int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := newTestServer(t, Options{Debounce: 0, DefaultAllow: true})
	if err := s.registerUpstream(middleware.Upstream{
		Name: "b", Prefix: "b", Target: backend.URL, Public: true, MaxBody: 1 << 20,
	}); err != nil {
		t.Fatalf("registerUpstream: %v", err)
	}
	router := s.Router()
	for i := 0; i < 3; i++ {
		if rec := doJSON(t, router, "GET", "/gw/b/thing", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i, rec.Code)
		}
	}
	if calls != 3 {
		t.Fatalf("debounce off should forward all 3, saw %d", calls)
	}
}
