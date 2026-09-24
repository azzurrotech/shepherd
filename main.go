// shepherd — identity-less IAM, software firewall, API rate limiter, and an
// enhancing reverse-proxy gateway.
//
// Two modes:
//
//   - Server mode (this binary): run `shepherd` as a standalone Go HTTP
//     server exposing key issuance (single, block, magic link), revocation,
//     firewall rules, rate limiting, JavaScript encryption keys, and the
//     /gw gateway.
//   - Middleware mode: import azzurrotech/shepherd/middleware from another Go
//     server and wrap your own http.Handlers with Firewall/RateLimit/
//     Authenticate/Authorize/Enhance/Gateway. See examples/middleware-demo.
//
// Everything is standard library only, identity-less (no identifying data is
// ever stored) and stateless (capability tokens are self-contained HMAC-SHA256
// signatures; the in-memory revocation/rate-limit state is an optional
// enhancement, never a database).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"azzurrotech/shepherd/keys"
	"azzurrotech/shepherd/middleware"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("shepherd: %v", err)
	}
}

func run() error {
	var (
		port    = flag.String("port", "8084", "listen port (default 8084)")
		secret  = flag.String("secret", os.Getenv("SHEPHERD_SECRET"), "master signing secret, hex or raw (env SHEPHERD_SECRET)")
		issuer  = flag.String("issuer", middleware.DefaultIssuer, "token issuer name")
		aud     = flag.String("audience", "", "default token audience")
		config  = flag.String("config", "", "optional JSON config file (firewall/rate/upstreams)")
		rate    = flag.Float64("rate", 120, "rate limit per minute per client (0 disables)")
		burst   = flag.Float64("burst", 30, "rate limiter burst size")
		deny    = flag.Bool("default-deny", false, "firewall default to deny instead of allow")
		trustIP = flag.String("trust-proxy-header", "", "trust this header for the real client IP (e.g. X-Forwarded-For) — only behind a proxy you control")
		help    = flag.Bool("help", false, "show help")
		version = flag.Bool("version", false, "show version")
	)
	flag.Parse()

	if *help {
		usage()
		return nil
	}
	if *version {
		fmt.Printf("shepherd %s\n", Version)
		fmt.Println("identity-less IAM, software firewall, API rate limiter, enhancing gateway.")
		fmt.Println("© Azzurro Technology Inc. (MIT) — standard library only, no database.")
		return nil
	}

	secretBytes, err := resolveSecret(*secret)
	if err != nil {
		return err
	}
	ephemeral := *secret == "" && os.Getenv("SHEPHERD_SECRET") == ""

	srv, err := NewServer(Options{
		Secret:          secretBytes,
		Issuer:          *issuer,
		Audience:        *aud,
		ConfigPath:      *config,
		RatePerMinute:   *rate,
		Burst:           *burst,
		DefaultAllow:    !*deny,
		ClientIPHeader:  *trustIP,
		EphemeralSecret: ephemeral,
	})
	if err != nil {
		return err
	}

	addr := ":" + *port
	printBanner(srv, addr, ephemeral)
	return srv.Run(addr)
}

func usage() {
	fmt.Println(`usage: shepherd [options]

Server mode — a standalone Go HTTP server exposing shepherd's IAM surface:

  -port string                 listen port (default "8084")
  -secret string               master signing secret, hex or raw bytes
                               (fallback: SHEPHERD_SECRET env var; when both
                               are empty an ephemeral secret is generated)
  -issuer string               token issuer name
  -audience string             default capability audience
  -config string               JSON config file (firewall rules/rate/upstreams)
  -rate float                  rate limit per minute per client (default 120, 0 = off)
  -burst float                 rate limiter burst (default 30)
  -default-deny                firewall denies by default
  -trust-proxy-header string   trust this header for the client IP
  -version                     show version
  -help                        show help

Middleware mode is available by importing the Go package:
  azzurrotech/shepherd/middleware
See examples/middleware-demo for a complete host server.`)
}

func printBanner(srv *Server, addr string, ephemeral bool) {
	fmt.Println("shepherd", Version, "- identity-less IAM, firewall, rate limiter, gateway")
	fmt.Println("listening on", addr)
	fmt.Printf("issuer:         %s\n", srv.mw.Issuer())
	fmt.Printf("firewall:       %d rules, default %s\n", len(srv.fw.Rules()), allowDeny(srv.fw.DefaultAllow()))
	fmt.Printf("rate limit:     per client (IP) with in-memory token bucket\n")
	if ephemeral {
		fmt.Println("WARNING: no -secret / SHEPHERD_SECRET set; using an ephemeral secret.")
		fmt.Println("         every issued token and signature will die with this process.")
	}
	fmt.Println("admin token (send as X-Shepherd-Admin):", srv.adminTok)
	fmt.Println()
}

func allowDeny(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// resolveSecret normalizes the -secret flag (hex or raw UTF-8 bytes) into the
// master secret used for token signing and key derivation.
func resolveSecret(raw string) ([]byte, error) {
	if raw == "" {
		b, err := keys.RandomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("generating ephemeral secret: %w", err)
		}
		return b, nil
	}
	// Prefer hex decoding when the value looks like hex of >= 16 bytes.
	if decoded, err := hex.DecodeString(raw); err == nil {
		if len(decoded) >= 16 {
			return decoded, nil
		}
		return nil, fmt.Errorf("secret decodes to %d bytes; need at least 16", len(decoded))
	}
	if len([]byte(raw)) < 16 {
		return nil, fmt.Errorf("secret too short (need at least 16 bytes)")
	}
	// Raw bytes as given.
	return []byte(raw), nil
}
