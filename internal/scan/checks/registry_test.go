package checks

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

func TestRegistryCountAndUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	total := 0
	add := func(id string) {
		if seen[id] {
			t.Errorf("duplicate check ID: %q", id)
		}
		seen[id] = true
		total++
	}
	for _, c := range Passive() {
		add(c.ID())
	}
	for _, c := range Active() {
		add(c.ID())
	}
	for _, c := range Request() {
		add(c.ID())
	}
	t.Logf("registered checks: %d", total)
	if total < 100 {
		t.Errorf("expected 100+ registered checks, got %d", total)
	}
}

func TestSecretDBDetects(t *testing.T) {
	// Fake keys assembled at runtime so no literal secret token lives in source.
	body := `config = { stripe: "sk_live_` + `abcdefghijklmnop0123456789", gitlab: "glpat-` + `ABCDEFGHIJ1234567890" }`
	tx := txFull("http://x/", "application/json", body, nil)
	var hits int
	for _, c := range Secrets() {
		hits += len(c.Passive(tx))
	}
	if hits < 2 {
		t.Errorf("expected Stripe + GitLab secrets detected, got %d", hits)
	}
}

func TestFingerprintDBDetects(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.25.3")
	h.Set("X-Powered-By", "Express")
	tx := txFull("http://x/", "text/html", "<html></html>", h)
	var names []string
	for _, c := range Fingerprints() {
		for _, is := range c.Passive(tx) {
			names = append(names, is.Check)
		}
	}
	if !containsStr(names, "fingerprint-nginx") || !containsStr(names, "fingerprint-express") {
		t.Errorf("expected nginx + express fingerprints, got %v", names)
	}
}

func TestInjectionDBDetectsMySQL(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		body := "ok"
		if containsAnyQuote(r.URL.RawQuery) {
			body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
		}
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte(body)}
	}}
	u, _ := url.Parse("http://x/p?id=1")
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x", Header: http.Header{}}
	var p scan.InsertionPoint
	for _, ip := range scan.InsertionPoints(base) {
		if ip.Name == "id" {
			p = ip
		}
	}
	var found bool
	for _, c := range InjectionDB() {
		if c.ID() == "sqli-mysql" {
			if len(c.Active(context.Background(), sender, base, p)) > 0 {
				found = true
			}
		}
	}
	if !found {
		t.Error("sqli-mysql should fire on a MySQL error signature")
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsAnyQuote(s string) bool {
	for _, c := range s {
		if c == '\'' || c == '"' || c == '%' { // %27 etc
			return true
		}
	}
	return false
}
