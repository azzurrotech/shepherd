package firewall

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReq(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

func TestOrderFirstMatchWins(t *testing.T) {
	fw := New(true)
	fw.Add(Rule{ID: "d1", Name: "deny admin", Action: ActionDeny, PathGlob: "/admin/**", Enabled: true})
	fw.Add(Rule{ID: "a1", Name: "allow local", Action: ActionAllow, Sources: []string{"192.168.1.0/24"}, Enabled: true})

	cases := []struct {
		ip      string
		path    string
		allowed bool
		rule    string
	}{
		{"10.0.0.5", "/admin/panel", false, "d1"},
		{"192.168.1.10", "/admin/panel", false, "d1"}, // first rule still wins
		{"192.168.1.10", "/api/x", true, "a1"},
		{"10.0.0.5", "/api/x", true, ""}, // default allow
	}
	for _, c := range cases {
		r := newReq("GET", c.path)
		r.RemoteAddr = c.ip + ":1234"
		d := fw.Evaluate(r, ClientIP(r.RemoteAddr))
		if d.Allowed != c.allowed || d.RuleID != c.rule {
			t.Fatalf("ip=%s path=%s: got allowed=%v rule=%q, want allowed=%v rule=%q",
				c.ip, c.path, d.Allowed, d.RuleID, c.allowed, c.rule)
		}
	}
}

func TestDefaultDeny(t *testing.T) {
	fw := New(false)
	d := fw.Evaluate(newReq("GET", "/anything"), "1.2.3.4")
	if d.Allowed {
		t.Fatalf("default-deny violated")
	}
	if d.Denied != true {
		t.Fatalf("decision not flagged denied")
	}
}

func TestMethodAndHeaderMatching(t *testing.T) {
	fw := New(true)
	fw.Add(Rule{
		ID: "r1", Action: ActionDeny, Enabled: true,
		Methods: []string{"POST"},
		Headers: map[string]string{"X-Secret": "open-sesame"},
	})
	r := newReq("POST", "/submit")
	r.Header.Set("X-Secret", "open-sesame")
	if d := fw.Evaluate(r, "1.2.3.4"); d.Allowed {
		t.Fatalf("expected deny for POST with matching header")
	}
	r = newReq("POST", "/submit")
	r.Header.Set("X-Secret", "wrong")
	if d := fw.Evaluate(r, "1.2.3.4"); !d.Allowed {
		t.Fatalf("header value mismatch should not match rule")
	}
	r = newReq("GET", "/submit")
	r.Header.Set("X-Secret", "open-sesame")
	if d := fw.Evaluate(r, "1.2.3.4"); !d.Allowed {
		t.Fatalf("method mismatch should not match rule")
	}
}

func TestPathGlobs(t *testing.T) {
	fw := New(true)
	fw.Add(Rule{ID: "sub", Action: ActionDeny, PathGlob: "/private/**", Enabled: true})
	fw.Add(Rule{ID: "zone", Action: ActionDeny, PathGlob: "/z*", Enabled: true})

	if d := fw.Evaluate(newReq("GET", "/private/a/b/c"), "1.2.3.4"); d.Allowed {
		t.Fatalf("prefix glob failed")
	}
	if d := fw.Evaluate(newReq("GET", "/zebra"), "1.2.3.4"); d.Allowed {
		t.Fatalf("singe-char glob failed")
	}
	if d := fw.Evaluate(newReq("GET", "/zebra/x"), "1.2.3.4"); !d.Allowed {
		t.Fatalf("/z* must not match nested path")
	}
}

func TestRemoveAndDisabled(t *testing.T) {
	fw := New(true)
	id, _ := fw.Add(Rule{ID: "x", Name: "deny", Action: ActionDeny, PathGlob: "/no", Enabled: false})
	if d := fw.Evaluate(newReq("GET", "/no"), "1.2.3.4"); !d.Allowed {
		t.Fatalf("disabled rule must not match")
	}
	if !fw.Remove(id) {
		t.Fatalf("remove failed for existing rule")
	}
	if d := fw.Evaluate(newReq("GET", "/no"), "1.2.3.4"); !d.Allowed {
		t.Fatalf("removed rule must not match")
	}
}

func TestBadAction(t *testing.T) {
	fw := New(true)
	if _, err := fw.Add(Rule{Name: "boom", Action: "maybe"}); err != ErrBadAction {
		t.Fatalf("expected ErrBadAction, got %v", err)
	}
}

func TestClientIPStripsPort(t *testing.T) {
	if got := ClientIP("203.0.113.9:8080"); got != "203.0.113.9" {
		t.Fatalf("got %q", got)
	}
	if got := ClientIP("[::1]:443"); got != "::1" {
		t.Fatalf("got %q", got)
	}
}
