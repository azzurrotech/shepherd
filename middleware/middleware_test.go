package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"azzurrotech/shepherd/firewall"
	"azzurrotech/shepherd/token"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func newTest(t *testing.T, cfg Config) *Shepherd {
	t.Helper()
	if cfg.Secret == nil {
		cfg.Secret = []byte(testSecret)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func respond(s *Shepherd) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusOK, map[string]any{"authed": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"authed": true, "sub": claims.Subject})
	})
}

func doReq(t *testing.T, h http.Handler, method, target string, tok string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestAuthenticateFlow(t *testing.T) {
	s := newTest(t, Config{})
	h := s.Authenticate(respond(s))

	// Missing token -> 401.
	if rec := doReq(t, h, "GET", "/x", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: got %d, want 401", rec.Code)
	}

	// Garbage token -> 401.
	if rec := doReq(t, h, "GET", "/x", "not.a.token"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d, want 401", rec.Code)
	}

	// Valid token -> 200 with claims.
	tok, _, err := s.Issue(token.IssueOptions{Subject: "opaque-1", Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rec := doReq(t, h, "GET", "/x", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["authed"] != true || body["sub"] != "opaque-1" {
		t.Fatalf("claims not propagated: %v", body)
	}

	// Revoked token -> 401.
	tok2, claims2, _ := s.Issue(token.IssueOptions{})
	s.deny.RevokeToken(claims2.ID, claims2.ExpiresAt)
	if rec := doReq(t, h, "GET", "/x", tok2); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: got %d, want 401", rec.Code)
	}
}

func TestAuthorizeScopes(t *testing.T) {
	s := newTest(t, Config{})
	ok := s.Authorize("read:orders", "write:orders")(respond(s))

	tok, _, _ := s.Issue(token.IssueOptions{Scopes: []string{"read:orders"}})
	if rec := doReq(t, ok, "GET", "/x", tok); rec.Code != http.StatusForbidden {
		t.Fatalf("missing scope should be 403, got %d", rec.Code)
	}

	tok2, _, _ := s.Issue(token.IssueOptions{Scopes: []string{"read:orders", "write:orders"}})
	if rec := doReq(t, ok, "GET", "/x", tok2); rec.Code != http.StatusOK {
		t.Fatalf("all scopes present should pass, got %d", rec.Code)
	}

	// role: prefix matching
	roleOk := s.Authorize("role:admin")(respond(s))
	tok3, _, _ := s.Issue(token.IssueOptions{Roles: []string{"member"}})
	if rec := doReq(t, roleOk, "GET", "/x", tok3); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong role should be 403, got %d", rec.Code)
	}
	tok4, _, _ := s.Issue(token.IssueOptions{Roles: []string{"admin"}})
	if rec := doReq(t, roleOk, "GET", "/x", tok4); rec.Code != http.StatusOK {
		t.Fatalf("right role should pass, got %d", rec.Code)
	}
}

func TestFirewallAndGate(t *testing.T) {
	fw := firewall.New(true)
	fw.Add(firewall.Rule{Name: "deny admin area", Action: firewall.ActionDeny, PathGlob: "/admin/**", Enabled: true})
	s := newTest(t, Config{Firewall: fw})
	g := s.Gate(nil, respond(s))

	tok, _, _ := s.Issue(token.IssueOptions{})
	if rec := doReq(t, g, "GET", "/admin/panel", tok); rec.Code != http.StatusForbidden {
		t.Fatalf("firewall deny should be 403, got %d", rec.Code)
	}
	if rec := doReq(t, g, "GET", "/api/health", tok); rec.Code != http.StatusOK {
		t.Fatalf("allowed path should pass, got %d", rec.Code)
	}
	if rec := doReq(t, g, "GET", "/api/health", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("gate without token should be 401, got %d", rec.Code)
	}
}

func TestRateLimitInGate(t *testing.T) {
	s := newTest(t, Config{LimitsPerMinute: 60, Burst: 1}) // 1 token total
	g := s.Gate(nil, respond(s))
	tok, _, _ := s.Issue(token.IssueOptions{})

	if rec := doReq(t, g, "GET", "/api/x", tok); rec.Code != http.StatusOK {
		t.Fatalf("first request should pass, got %d", rec.Code)
	}
	// Second request from the same IP hits the burst limit.
	rec := doReq(t, g, "GET", "/api/x", tok)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be 429, got %d", rec.Code)
	}
}

func TestOptionalAndEnhance(t *testing.T) {
	s := newTest(t, Config{})
	var got token.Claims
	gotSet := false
	h := s.Optional(s.Enhance(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := ClaimsFromContext(r.Context()); ok {
			got = c
			gotSet = true
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	tok, _, _ := s.Issue(token.IssueOptions{Subject: "s-1", Scopes: []string{"read"}, Roles: []string{"dev"}})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/submit?a=1", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, r)

	if !gotSet || got.Subject != "s-1" {
		t.Fatalf("optional auth did not capture claims: %+v set=%v", got, gotSet)
	}
	if r.Header.Get("X-Shepherd-Subject") != "s-1" {
		t.Fatalf("subject header missing")
	}
	if r.Header.Get("X-Shepherd-Scopes") != "read" || r.Header.Get("X-Shepherd-Roles") != "dev" {
		t.Fatalf("scope/role headers wrong: %q %q", r.Header.Get("X-Shepherd-Scopes"), r.Header.Get("X-Shepherd-Roles"))
	}
	if r.Header.Get("X-Shepherd-Signature") == "" || r.Header.Get("X-Shepherd-Time") == "" {
		t.Fatalf("signature/time headers missing")
	}
}

func TestMagicLink(t *testing.T) {
	s := newTest(t, Config{})
	raw, claims, err := s.Manager().IssueMagicLink(token.IssueOptions{Next: "https://app/dash"})
	if err != nil {
		t.Fatalf("IssueMagicLink: %v", err)
	}
	// First redemption succeeds.
	c1, err := s.VerifyMagicToken(raw)
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if c1.ID != claims.ID {
		t.Fatalf("claims mismatch")
	}
	// Replay is denied by the once-use store.
	if _, err := s.VerifyMagicToken(raw); err == nil {
		t.Fatalf("replayed magic link was accepted")
	}
	// Regular tokens are rejected by VerifyMagicToken.
	regular, _, _ := s.Issue(token.IssueOptions{})
	if _, err := s.VerifyMagicToken(regular); err == nil {
		t.Fatalf("regular token accepted as magic link")
	}
}

func TestMagicLinkHandler(t *testing.T) {
	s := newTest(t, Config{})
	var got string
	h := s.MagicLinkHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := ClaimsFromContext(r.Context()); ok {
			got = c.Next
		}
		w.WriteHeader(http.StatusOK)
	}))
	raw, _, err := s.Manager().IssueMagicLink(token.IssueOptions{Next: "/dashboard"})
	if err != nil {
		t.Fatalf("IssueMagicLink: %v", err)
	}
	r := httptest.NewRequest("GET", "/verify?t="+raw, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || got != "/dashboard" {
		t.Fatalf("magic ok but claims not routed: code=%d next=%q", rec.Code, got)
	}
	// Without token -> 400.
	r2 := httptest.NewRequest("GET", "/verify", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without token, got %d", rec2.Code)
	}
}

func TestAdminTokenDeterministic(t *testing.T) {
	s1 := newTest(t, Config{})
	s2 := newTest(t, Config{})
	if s1.AdminToken() == "" || s1.AdminToken() != s2.AdminToken() {
		t.Fatalf("admin token must be deterministic for a given secret")
	}
}

func TestTokenFromRequestPriority(t *testing.T) {
	s := newTest(t, Config{})
	tok, _, _ := s.Issue(token.IssueOptions{})
	r := httptest.NewRequest("GET", "/x", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if got := s.TokenFromRequest(r); got != tok {
		t.Fatalf("bearer not found")
	}
	r2 := httptest.NewRequest("GET", "/x", nil)
	r2.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	if got := s.TokenFromRequest(r2); got != tok {
		t.Fatalf("cookie not found")
	}
}

func TestClaimsFromContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := ClaimsFromContext(ctx); ok {
		t.Fatalf("empty context must not yield claims")
	}
	c := token.Claims{Subject: "x"}
	got, ok := ClaimsFromContext(withClaims(ctx, c))
	if !ok || got.Subject != "x" {
		t.Fatalf("claim round-trip failed")
	}
}

// --- gateway tests ---

func TestGatewayEnrichesAndProxies(t *testing.T) {
	// Backend echoes what it received.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{
			"path":       r.URL.Path,
			"uid":        r.URL.Query().Get("uid"),
			"referrer":   r.URL.Query().Get("referrer"),
			"subject":    r.Header.Get("X-Shepherd-Subject"),
			"scopes":     r.Header.Get("X-Shepherd-Scopes"),
			"signature":  r.Header.Get("X-Shepherd-Signature"),
			"shep_time":  r.Header.Get("X-Shepherd-Time"),
			"client":     r.Header.Get("X-Shepherd-Client"),
			"xff":        r.Header.Get("X-Forwarded-For"),
			"orig_query": r.URL.Query().Get("orig"),
			"raw_query":  r.URL.RawQuery,
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer backend.Close()

	s := newTest(t, Config{})
	gw := s.Gateway(GatewayOptions{
		Mount: "/gw",
		Upstreams: []Upstream{{
			Name:   "orders",
			Prefix: "orders",
			Target: backend.URL,
			Scopes: []string{"read:orders"},
			QueryEnrich: map[string]string{
				"uid":      "sub",
				"referrer": "ref", // from Meta
			},
		}},
	})

	tok, _, err := s.Issue(token.IssueOptions{
		Subject: "opaque-9",
		Scopes:  []string{"read:orders"},
		Meta:    map[string]string{"ref": "share-X"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	r := httptest.NewRequest("POST", "/gw/orders/123?orig=kept", strings.NewReader(`{"q":1}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.RemoteAddr = "203.0.113.7:9999"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("gateway status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode backend response: %v", err)
	}
	if out["path"] != "/123" {
		t.Fatalf("path rewrite wrong: %v", out["path"])
	}
	if out["uid"] != "opaque-9" {
		t.Fatalf("query enrichment failed: uid=%v", out["uid"])
	}
	if out["referrer"] != "share-X" {
		t.Fatalf("meta query enrichment failed: referrer=%v", out["referrer"])
	}
	if out["orig_query"] != "kept" {
		t.Fatalf("caller-supplied query param overwritten: %v", out["orig_query"])
	}
	if out["subject"] != "opaque-9" || out["scopes"] != "read:orders" {
		t.Fatalf("headers wrong: %v %v", out["subject"], out["scopes"])
	}
	if out["signature"] == "" || out["shep_time"] == "" {
		t.Fatalf("signature headers missing")
	}

	// Backend verifies the signature itself: it recomputes the canonical line
	// over exactly what it received.
	ts, _ := strconv.ParseInt(out["shep_time"].(string), 10, 64)
	want := s.RequestSignature("POST", "/123", out["raw_query"].(string), "203.0.113.7", ts, []byte(`{"q":1}`))
	if out["signature"] != want {
		t.Fatalf("signature mismatch: got %v want %v", out["signature"], want)
	}
	if out["client"] != "203.0.113.7" {
		t.Fatalf("client header wrong: %v", out["client"])
	}
}

func TestGatewayRejectsUnauthenticated(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	s := newTest(t, Config{})
	gw := s.Gateway(GatewayOptions{
		Mount:     "/gw",
		Upstreams: []Upstream{{Name: "orders", Prefix: "orders", Target: backend.URL, Scopes: []string{"read:orders"}}},
	})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/gw/orders/list", nil)
	gw.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestGatewayNotFound(t *testing.T) {
	s := newTest(t, Config{})
	gw := s.Gateway(GatewayOptions{Mount: "/gw", Upstreams: []Upstream{{Name: "a", Prefix: "a", Target: "http://127.0.0.1:1"}}})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/gw/nope/x", nil)
	gw.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGatewayPublic(t *testing.T) {
	var sawAuth bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("X-Shepherd-Subject") != ""
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer backend.Close()
	s := newTest(t, Config{})
	gw := s.Gateway(GatewayOptions{Mount: "/gw", Upstreams: []Upstream{
		{Name: "pub", Prefix: "pub", Target: backend.URL, Public: true},
	}})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/gw/pub/status", nil)
	gw.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("public upstream rejected, got %d", rec.Code)
	}
	if sawAuth {
		t.Fatalf("public upstream should not see subject headers without a token")
	}
	// With a token the same public upstream still gets enrichment.
	tok, _, _ := s.Issue(token.IssueOptions{Subject: "opaque-1"})
	rec2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/gw/pub/status", nil)
	r2.Header.Set("Authorization", "Bearer "+tok)
	gw.ServeHTTP(rec2, r2)
	if !sawAuth || rec2.Code != http.StatusOK {
		t.Fatalf("public upstream with token should enrich: auth=%v code=%d", sawAuth, rec2.Code)
	}
}

func TestGatewayBodyTooLarge(t *testing.T) {
	s := newTest(t, Config{})
	gw := s.Gateway(GatewayOptions{Mount: "/gw", Upstreams: []Upstream{
		{Name: "a", Prefix: "a", Target: "http://127.0.0.1:1", MaxBody: 4, Public: true},
	}})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/gw/a/x", strings.NewReader("0123456789"))
	gw.ServeHTTP(rec, r)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
