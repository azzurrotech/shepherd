// Demo: consuming shepherd in middleware mode from a completely different Go
// server.
//
// This program is a self-contained microcosm of the intended deployment:
//
//   - an "orders" backend API runs on its own listener (:19081) and knows
//     nothing about auth — it only reads the X-Shepherd-* headers shepherd
//     injects;
//   - the main server (:19080) wraps its OWN handlers with
//     middleware.Gate(...) (firewall → rate limit → authenticate → authorize),
//     uses middleware.MagicLinkHandler to redeem magic links into session
//     cookies, and uses middleware.Gateway(...) to front the backend with an
//     enriching reverse proxy at /gw/orders/*.
//
// Run it, then:
//
//	TOK=$(curl -s -HPOST localhost:19080/issue -d '{"scopes":["read:orders"]}' \
//	     -H 'Content-Type: application/json' | jq -r .token)
//	curl -H "Authorization: Bearer $TOK" localhost:19080/api/orders        # gated
//	curl -H "Authorization: Bearer $TOK" localhost:19080/gw/orders/summary # gateway
//
// Only the Go standard library is used.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"azzurrotech/shepherd/middleware"
	"azzurrotech/shepherd/token"
)

const demoScheme = "http"

func main() {
	var (
		addr    = flag.String("addr", ":19080", "main (public) listener")
		backend = flag.String("backend", ":19081", "orders backend listener")
		secret  = flag.String("secret", "0123456789abcdef0123456789abcdef", "shared signing secret (32 bytes)")
	)
	flag.Parse()

	s, err := middleware.New(middleware.Config{
		Secret:          []byte(*secret),
		Issuer:          "demo-host",
		LimitsPerMinute: 60, // rate limit for the gated API and the gateway
		Burst:           10,
	})
	if err != nil {
		log.Fatalf("middleware: %v", err)
	}

	// The backend API: a "different Go server" that trusts the enriched
	// headers after shepherd authenticated the request.
	http.HandleFunc("/", backendHandler)
	go func() {
		blog := &http.Server{Addr: *backend, Handler: nil, ReadHeaderTimeout: 5 * time.Second}
		log.Printf("orders backend listening on %s", *backend)
		if err := blog.ListenAndServe(); err != nil {
			log.Fatalf("backend: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "issuer": s.Issuer()})
	})

	// Issue demo tokens (this would normally be sheepherd's admin key API;
	// here it is open so the demo is easy to drive).
	mux.HandleFunc("/issue", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Scopes []string `json:"scopes,omitempty"`
			Roles  []string `json:"roles,omitempty"`
			TTL    string   `json:"ttl,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		var ttl time.Duration
		if req.TTL != "" {
			if ttl, err = time.ParseDuration(req.TTL); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
		}
		raw, claims, err := s.Issue(token.IssueOptions{Scopes: req.Scopes, Roles: req.Roles, TTL: ttl})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"token": raw, "claims": claims})
	})

	// Magic-link redemption: middleware.MagicLinkHandler validates the
	// one-shot token, marks it consumed, and hands us the claims in context.
	// The host then converts it into its own session cookie (a fresh token —
	// the magic token itself is spent).
	mux.Handle("/verify", s.MagicLinkHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := middleware.ClaimsFromContext(r.Context())
		session, _, err := s.Issue(token.IssueOptions{
			Subject: claims.Subject, Scopes: claims.Scopes, Roles: claims.Roles,
			Block: claims.Block, Meta: claims.Meta,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: middleware.CookieName, Value: session,
			Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600,
		})
		http.Redirect(w, r, safeNext(claims.Next), http.StatusFound)
	})))

	// Issue a magic link (hostApplication uses the same manager so the URL
	// just embeds the token).
	mux.HandleFunc("/magic", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Next string `json:"next,omitempty"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Next == "" {
			req.Next = "/"
		}
		raw, claims, err := s.Manager().IssueMagicLink(token.IssueOptions{Next: req.Next, Scopes: []string{"read:orders"}})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		u := demoScheme + "://localhost" + *addr + "/verify?t=" + escapeToken(raw) + "&next=" + escapeToken(req.Next)
		writeJSON(w, http.StatusCreated, map[string]any{"url": u, "claims": claims})
	})

	// A handler of THIS server protected by the full shepherd chain:
	// firewall → rate limit → authenticate → authorize("read:orders").
	orders := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := middleware.ClaimsFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{
			"handler": "gated-inline",
			"subject": claims.Subject,
			"scopes":  claims.Scopes,
		})
	})
	mux.Handle("/api/orders", s.Gate([]string{"read:orders"}, orders))

	// The gateway: protect + enrich the orders backend reverse-proxied under
	// /gw/orders/*. Backend replies include the enhanced headers.
	mux.Handle("/gw/", s.Gateway(middleware.GatewayOptions{
		Mount: "/gw",
		Upstreams: []middleware.Upstream{
			{
				Name:        "orders",
				Prefix:      "orders",
				Target:      demoScheme + "://localhost" + *backend,
				Scopes:      []string{"read:orders"},
				MaxBody:     1 << 20,
				QueryEnrich: map[string]string{"uid": "sub", "scopes": "scopes"},
			},
		},
	}))

	log.Printf("middleware-mode demo listening on %s", *addr)
	log.Printf("  gated CLI:     curl -H \"Authorization: Bearer $TOK\" %s/api/orders", host(*addr))
	log.Printf("  gateway:       curl -H \"Authorization: Bearer $TOK\" %s/gw/orders/summary", host(*addr))
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("mux: %v", err)
	}
}

// backendHandler is the orders API on its own listener. It does not do auth:
// it trusts the X-Shepherd-* enrichment headers and the gateway signature.
func backendHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"backend":  "orders",
		"path":     r.URL.Path,
		"uid":      r.URL.Query().Get("uid"),
		"scopes":   r.URL.Query().Get("scopes"),
		"subject":  r.Header.Get("X-Shepherd-Subject"),
		"sig":      r.Header.Get("X-Shepherd-Signature") != "",
		"verified": "trusted via gateway",
	})
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<html><body style="font-family:system-ui"><h1>shepherd in middleware mode</h1>
<ul>
<li><code>POST /issue</code> — mint a capability token</li>
<li><code>GET /api/orders</code> — this server's handler behind <code>Gate(["read:orders"])</code></li>
<li><code>GET /gw/orders/*</code> — protected, enriched reverse proxy to the orders backend</li>
<li><code>POST /magic</code> — create a magic link; open the returned <code>/verify</code> URL</li>
</ul></body></html>`)
}

func safeNext(next string) string {
	if next == "" || next[0] != '/' || (len(next) > 1 && next[1] == '/') {
		return "/"
	}
	return next
}

func escapeToken(t string) string {
	// url.QueryEscape would be the real choice; the demo tokens are
	// base64url so they are already URL-safe.
	return t
}

func host(addr string) string {
	return demoScheme + "://localhost" + addr
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
