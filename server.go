// Server mode for shepherd: a self-contained, standard-library HTTP server
// exposing the full IAM surface (capability key issuance, block keys, magic
// links, revocation), the software firewall rules and rate limiter, a
// JavaScript encryption-key endpoint, and the gateway reverse proxy that
// "enhances a query and passes it correctly to a given point".
//
// The same components are available as importable middleware (package
// azzurrotech/shepherd/middleware) for embedding in other Go servers; this
// file is just one hosting of them.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"azzurrotech/shepherd/firewall"
	"azzurrotech/shepherd/middleware"
	"azzurrotech/shepherd/token"
)

// Version of the shepherd binary.
const Version = "0.1.0"

// GatewayMount is the path prefix of the reverse-proxy gateway.
const GatewayMount = "/gw"

// Options configures the standalone server.
type Options struct {
	Secret          []byte
	Issuer          string
	Audience        string
	ConfigPath      string
	RatePerMinute   float64
	Burst           float64
	DefaultAllow    bool
	ClientIPHeader  string
	EphemeralSecret bool
}

// fileConfig mirrors the on-disk JSON options file.
type fileConfig struct {
	Firewall *struct {
		DefaultAllow bool            `json:"default_allow"`
		Rules        []firewall.Rule `json:"rules"`
	} `json:"firewall,omitempty"`
	Rate *struct {
		PerMinute float64 `json:"per_minute"`
		Burst     float64 `json:"burst"`
	} `json:"rate,omitempty"`
	Upstreams []middleware.Upstream `json:"upstreams,omitempty"`
}

// Server is the standalone shepherd HTTP server.
type Server struct {
	mw       *middleware.Shepherd
	fw       *firewall.Firewall
	adminTok string
	opts     Options

	regMu sync.RWMutex
	regs  map[string]middleware.Upstream
	gw    http.Handler
}

// NewServer builds the server and wires the shared firewall/limiter/deny
// store into the middleware instance. An optional JSON config file is applied
// during construction so its rate/firewall/upstream settings are live from
// the first request.
func NewServer(opts Options) (*Server, error) {
	var fcfg *fileConfig
	if opts.ConfigPath != "" {
		cfg, err := loadFileConfig(opts.ConfigPath)
		if err != nil {
			return nil, err
		}
		fcfg = cfg
	}

	defaultAllow := opts.DefaultAllow
	ratePerMinute := opts.RatePerMinute
	burst := opts.Burst
	if fcfg != nil {
		if fcfg.Firewall != nil {
			defaultAllow = fcfg.Firewall.DefaultAllow
		}
		if fcfg.Rate != nil {
			ratePerMinute = fcfg.Rate.PerMinute
			burst = fcfg.Rate.Burst
		}
	}

	fw := firewall.New(defaultAllow)
	mw, err := middleware.New(middleware.Config{
		Secret:          opts.Secret,
		Issuer:          opts.Issuer,
		Audience:        opts.Audience,
		Firewall:        fw,
		LimitsPerMinute: ratePerMinute,
		Burst:           burst,
		ClientIPHeader:  opts.ClientIPHeader,
	})
	if err != nil {
		return nil, err
	}

	s := &Server{
		mw:       mw,
		fw:       fw,
		adminTok: mw.AdminToken(),
		opts:     opts,
		regs:     make(map[string]middleware.Upstream),
	}
	if fcfg != nil {
		if fcfg.Firewall != nil {
			for _, rule := range fcfg.Firewall.Rules {
				if _, err := fw.Add(rule); err != nil {
					return nil, fmt.Errorf("config rule: %w", err)
				}
			}
		}
		for _, u := range fcfg.Upstreams {
			if err := s.registerUpstream(u); err != nil {
				return nil, fmt.Errorf("config upstream %q: %w", u.Prefix, err)
			}
		}
	}
	s.rebuildGateway()
	return s, nil
}

// Router assembles all http routes.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/health", s.handleHealth)

	mux.HandleFunc("/api/keys", s.handleIssue)
	mux.HandleFunc("/api/keys/block", s.handleIssueBlock)
	mux.HandleFunc("/api/keys/magic", s.handleMagicLink)
	mux.HandleFunc("/api/keys/javascript", s.handleJavascriptKey)
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/api/token/verify", s.handleVerifyToken)

	mux.HandleFunc("/api/revoke", s.handleRevoke)
	mux.HandleFunc("/api/revoke/block", s.handleRevokeBlock)

	mux.HandleFunc("/api/firewall/rules", s.handleFirewallRules)
	mux.HandleFunc("/api/firewall/rules/", s.handleFirewallRuleByID)

	mux.HandleFunc("/api/ratelimit/status", s.handleRateStatus)
	mux.HandleFunc("/api/ratelimit/reset", s.handleRateReset)

	mux.HandleFunc("/api/upstreams", s.handleUpstreams)
	mux.HandleFunc("/api/upstreams/", s.handleUpstreamByPrefix)

	mux.HandleFunc(GatewayMount+"/", s.handleGateway)
	return mux
}

// Run starts the HTTP listener with sane timeouts.
func (s *Server) Run(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// Background hygiene: prune idle rate-limit buckets and expired
	// revocation entries.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			s.mw.RateLimitCleanup(time.Hour)
			s.mw.CleanupRevocations()
		}
	}()
	return srv.ListenAndServe()
}

// --- helpers ---

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Shepherd-Admin") != s.adminTok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "admin token required"})
		return false
	}
	return true
}

func (s *Server) baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) rebuildGateway() {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	ups := make([]middleware.Upstream, 0, len(s.regs))
	for _, u := range s.regs {
		ups = append(ups, u)
	}
	s.gw = s.mw.Gateway(middleware.GatewayOptions{Mount: GatewayMount, Upstreams: ups})
}

func (s *Server) registerUpstream(u middleware.Upstream) error {
	u.Prefix = strings.Trim(strings.TrimSpace(u.Prefix), "/")
	if u.Prefix == "" {
		return fmt.Errorf("upstream prefix required")
	}
	parsed, err := url.Parse(u.Target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid upstream target %q", u.Target)
	}
	s.regMu.Lock()
	s.regs[u.Prefix] = u
	s.regMu.Unlock()
	s.rebuildGateway()
	return nil
}

func (s *Server) unregisterUpstream(prefix string) bool {
	s.regMu.Lock()
	_, ok := s.regs[prefix]
	delete(s.regs, prefix)
	s.regMu.Unlock()
	if ok {
		s.rebuildGateway()
	}
	return ok
}

// --- homepage & health ---

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>shepherd — identity-less IAM &amp; firewall</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}
h1{font-size:1.6rem}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem}
code{background:#f3f3f3;padding:.1rem .3rem;border-radius:3px}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:999px;background:#e6f4ea;color:#137333;font-size:.75rem}
</style></head><body>
<h1>shepherd <span class="badge">server mode</span></h1>
<p>Zero-knowledge, identity-less capability IAM, software firewall, rate limiter,
magic links, JavaScript encryption keys, and an enhancing reverse-proxy gateway.
Standard library only — no database.</p>
<h2>Endpoints</h2>
<table><tr><th>Method</th><th>Path</th><th>Purpose</th></tr>
<tr><td>GET</td><td><code>/health</code></td><td>liveness</td></tr>
<tr><td>POST</td><td><code>/api/keys</code></td><td>issue one capability token (admin)</td></tr>
<tr><td>POST</td><td><code>/api/keys/block</code></td><td>issue a block of keys (admin)</td></tr>
<tr><td>POST</td><td><code>/api/keys/magic</code></td><td>create a magic link (admin)</td></tr>
<tr><td>GET</td><td><code>/verify?t=...</code></td><td>redeem a magic link</td></tr>
<tr><td>GET</td><td><code>/api/keys/javascript?scope=&amp;usage=</code></td><td>encryption key for JS software (admin)</td></tr>
<tr><td>GET</td><td><code>/api/token/verify</code></td><td>validate a presented capability token</td></tr>
<tr><td>POST</td><td><code>/api/revoke</code></td><td>revoke a token (admin)</td></tr>
<tr><td>POST</td><td><code>/api/revoke/block</code></td><td>revoke a key block (admin)</td></tr>
<tr><td>GET/POST</td><td><code>/api/firewall/rules</code></td><td>list/add firewall rules</td></tr>
<tr><td>DELETE</td><td><code>/api/firewall/rules/{id}</code></td><td>remove a rule (admin)</td></tr>
<tr><td>GET</td><td><code>/api/ratelimit/status?key=</code></td><td>limiter snapshot (admin)</td></tr>
<tr><td>GET/POST</td><td><code>/api/upstreams</code></td><td>gateway routing table</td></tr>
<tr><td>ANY</td><td><code>/gw/{prefix}/...</code></td><td>protected, enriched reverse proxy</td></tr>
</table>
<p>Management endpoints expect the admin token in <code>X-Shepherd-Admin</code>.
The admin token is printed to stdout at startup. <a href="/health">health</a></p>
</body></html>`)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "healthy",
		"service":  "shepherd",
		"version":  Version,
		"issuer":   s.mw.Issuer(),
		"time":     time.Now().UTC().Format(time.RFC3339),
		"firewall": len(s.fw.Rules()),
	})
}

// --- key issuance ---

type issueRequest struct {
	Subject  string            `json:"subject,omitempty"`
	Scopes   []string          `json:"scopes,omitempty"`
	Roles    []string          `json:"roles,omitempty"`
	Audience string            `json:"audience,omitempty"`
	TTL      string            `json:"ttl,omitempty"`
	Block    string            `json:"block,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
	Count    int               `json:"count,omitempty"`
}

func (s *Server) issueOpts(req issueRequest) (token.IssueOptions, error) {
	var ttl time.Duration
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil {
			return token.IssueOptions{}, fmt.Errorf("invalid ttl %q: %v", req.TTL, err)
		}
		ttl = d
	}
	return token.IssueOptions{
		Subject:  req.Subject,
		Scopes:   req.Scopes,
		Roles:    req.Roles,
		Audience: req.Audience,
		TTL:      ttl,
		Block:    req.Block,
		Meta:     req.Meta,
	}, nil
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req issueRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	opts, err := s.issueOpts(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	raw, claims, err := s.mw.Issue(opts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      raw,
		"claims":     claims,
		"expires_in": claims.ExpiresAt - claims.IssuedAt,
	})
}

func (s *Server) handleIssueBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req issueRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if req.Count == 0 {
		req.Count = 1
	}
	if req.Count > 10000 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "count must be <= 10000"})
		return
	}
	opts, err := s.issueOpts(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	keys, err := s.mw.Manager().IssueBlock(opts, req.Block, req.Count)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"block": keys[0].Claims.Block,
		"count": len(keys),
		"keys":  keys,
	})
}

func (s *Server) handleMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		issueRequest
		Next string `json:"next,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if req.Next == "" {
		req.Next = "/"
	}
	opts, err := s.issueOpts(req.issueRequest)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	opts.Next = req.Next
	raw, claims, err := s.mw.Manager().IssueMagicLink(opts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	u := s.baseURL(r) + "/verify?t=" + url.QueryEscape(raw)
	if req.Next != "" && req.Next != "/" {
		u += "&next=" + url.QueryEscape(req.Next)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"url":        u,
		"token":      raw,
		"claims":     claims,
		"expires_in": claims.ExpiresAt - claims.IssuedAt,
	})
}

func (s *Server) handleJavascriptKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	scope := q.Get("scope")
	if scope == "" {
		scope = "frontend"
	}
	usage := q.Get("usage")
	if usage == "" {
		usage = "encrypt"
	}
	k, err := s.mw.JSCryptoKey(scope, usage)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, k)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	tok := r.URL.Query().Get("t")
	if tok == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing magic link token"})
		return
	}
	claims, err := s.mw.VerifyMagicToken(tok)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid magic link"})
		return
	}
	// Convert the one-shot link into a session capability cookie with the
	// token's normal TTL. The magic token itself stays consumed.
	sess, sessClaims, err := s.mw.Issue(token.IssueOptions{
		Subject:  claims.Subject,
		Scopes:   claims.Scopes,
		Roles:    claims.Roles,
		Audience: claims.Audience,
		Block:    claims.Block,
		Meta:     claims.Meta,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     middleware.CookieName,
		Value:    sess,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessClaims.ExpiresAt - sessClaims.IssuedAt),
	})
	target := "/"
	if safeRedirect(claims.Next, r.Host) {
		target = claims.Next
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	raw := s.mw.TokenFromRequest(r)
	if raw == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"valid": false, "error": "missing token"})
		return
	}
	claims, err := s.mw.Manager().Verify(raw)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	if s.mw.IsDenied(claims.ID) || (claims.Block != "" && s.mw.IsDenied(claims.Block)) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"valid": false, "error": "token revoked"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "claims": claims})
}

// --- revocation ---

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil || req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "token required"})
		return
	}
	claims, err := s.mw.Manager().Verify(req.Token)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cannot revoke: " + err.Error()})
		return
	}
	s.mw.RevokeToken(claims.ID, claims.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": claims.ID})
}

func (s *Server) handleRevokeBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		Block string `json:"block"`
	}
	if err := readJSON(r, &req); err != nil || req.Block == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "block required"})
		return
	}
	// Expire the block kick-off far in the future; the effective expiry is
	// naturally capped by each token's own exp claim.
	s.mw.RevokeBlock(req.Block, time.Now().Add(365*24*time.Hour).Unix())
	writeJSON(w, http.StatusOK, map[string]any{"revoked_block": req.Block})
}

// --- firewall ---

func (s *Server) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"default_allow": s.fw.DefaultAllow(),
			"rules":         s.fw.Rules(),
		})
	case http.MethodPost:
		if !s.requireAdmin(w, r) {
			return
		}
		var payload struct {
			firewall.Rule
			DefaultAllow *bool `json:"default_allow,omitempty"`
		}
		if err := readJSON(r, &payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if payload.DefaultAllow != nil {
			s.fw.SetDefaultAllow(*payload.DefaultAllow)
			writeJSON(w, http.StatusOK, map[string]any{"default_allow": s.fw.DefaultAllow()})
			return
		}
		id, err := s.fw.Add(payload.Rule)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) handleFirewallRuleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/firewall/rules/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "rule id required"})
		return
	}
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if !s.fw.Remove(id) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "rule not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": id})
}

// --- rate limiter ---

func (s *Server) handleRateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key query param required (e.g. ip:1.2.3.4)"})
		return
	}
	st, ok := s.mw.RateLimitStatus(key)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "status": st})
}

func (s *Server) handleRateReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	s.mw.RateLimitReset()
	writeJSON(w, http.StatusOK, map[string]any{"reset": true})
}

// --- upstream gateway registry ---

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.regMu.RLock()
		ups := make([]middleware.Upstream, 0, len(s.regs))
		for _, u := range s.regs {
			ups = append(ups, u)
		}
		s.regMu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{"mount": GatewayMount, "upstreams": ups})
	case http.MethodPost:
		if !s.requireAdmin(w, r) {
			return
		}
		var u middleware.Upstream
		if err := readJSON(r, &u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := s.registerUpstream(u); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"upstream": u, "mount": GatewayMount})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) handleUpstreamByPrefix(w http.ResponseWriter, r *http.Request) {
	prefix := strings.TrimPrefix(r.URL.Path, "/api/upstreams/")
	if prefix == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "prefix required"})
		return
	}
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if !s.unregisterUpstream(prefix) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "upstream not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": prefix})
}

// --- gateway ---

func (s *Server) handleGateway(w http.ResponseWriter, r *http.Request) {
	s.regMu.RLock()
	gw := s.gw
	s.regMu.RUnlock()
	gw.ServeHTTP(w, r)
}

// --- config file ---

func loadFileConfig(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg fileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

// --- misc ---

func safeRedirect(to, reqHost string) bool {
	if to == "" {
		return false
	}
	if strings.HasPrefix(to, "/") && !strings.HasPrefix(to, "//") {
		return true
	}
	u, err := url.Parse(to)
	if err != nil {
		return false
	}
	return u.Scheme != "" && strings.EqualFold(u.Host, reqHost)
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}
