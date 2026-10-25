package checks

import (
	"net/http"
	"testing"
)

func runCookie(t *testing.T, scheme string, cookies []string) map[string]bool {
	t.Helper()
	h := http.Header{}
	for _, c := range cookies {
		h.Add("Set-Cookie", c)
	}
	tx := txFull(scheme+"://x/", "text/html", "", h)
	names := map[string]bool{}
	for _, is := range (CookieHardening{}).Passive(tx) {
		names[is.Param] = true
	}
	return names
}

func TestCookieHardeningSecureAndPrefix(t *testing.T) {
	got := runCookie(t, "https", []string{
		"SESSIONID=abc; Path=/; HttpOnly",          // missing Secure over HTTPS
		"__Host-sid=xyz; Path=/; HttpOnly",         // __Host- without Secure => violation
		"__Secure-tok=1; Path=/; HttpOnly; Secure", // valid => no finding
	})
	if !got["SESSIONID"] {
		t.Errorf("expected Secure finding for SESSIONID, got %v", got)
	}
	if !got["__Host-sid"] {
		t.Errorf("expected __Host- prefix violation, got %v", got)
	}
	if got["__Secure-tok"] {
		t.Errorf("valid __Secure- cookie should not be flagged, got %v", got)
	}
}

func TestCookieHardeningCleanOnHTTP(t *testing.T) {
	got := runCookie(t, "http", []string{"pref=dark; Path=/"})
	if len(got) != 0 {
		t.Errorf("non-session HTTP cookie should be clean, got %v", got)
	}
}

func TestWeakHSTS(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=3600")
	if iss := (WeakHSTS{}).Passive(txFull("https://x/", "text/html", "", h)); len(iss) == 0 {
		t.Fatal("expected a weak-HSTS finding for short max-age without includeSubDomains")
	}
	h2 := http.Header{}
	h2.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	if iss := (WeakHSTS{}).Passive(txFull("https://x/", "text/html", "", h2)); len(iss) != 0 {
		t.Errorf("strong HSTS should be clean, got %v", iss)
	}
	// No HSTS at all is not this check's job (security-headers covers it).
	if iss := (WeakHSTS{}).Passive(txFull("https://x/", "text/html", "", http.Header{})); len(iss) != 0 {
		t.Errorf("missing HSTS should not be flagged here, got %v", iss)
	}
}

func TestParseSetCookie(t *testing.T) {
	name, attrs, path := parseSetCookie("__Host-x=1; Path=/; Secure; HttpOnly; SameSite=Lax")
	if name != "__Host-x" {
		t.Errorf("name = %q, want __Host-x", name)
	}
	if path != "/" {
		t.Errorf("path = %q, want /", path)
	}
	if !attrs["secure"] || !attrs["httponly"] || !attrs["samesite"] {
		t.Errorf("attrs missing expected flags: %v", attrs)
	}
}
