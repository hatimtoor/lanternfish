package checks

import (
	"net/http"
	"testing"
)

func cspIssues(t *testing.T, policy string) map[string]bool {
	t.Helper()
	h := http.Header{}
	if policy != "" {
		h.Set("Content-Security-Policy", policy)
	}
	tx := txFull("http://x/", "text/html", "<html></html>", h)
	names := map[string]bool{}
	for _, is := range (CSPWeakness{}).Passive(tx) {
		names[is.Name] = true
	}
	return names
}

func TestCSPWeaknessFlagsUnsafeInline(t *testing.T) {
	got := cspIssues(t, "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'")
	if !got["CSP allows 'unsafe-inline' scripts"] {
		t.Errorf("expected unsafe-inline finding, got %v", got)
	}
}

func TestCSPWeaknessFlagsWildcardAndMissingDirectives(t *testing.T) {
	got := cspIssues(t, "default-src *")
	if !got["CSP script-src is effectively wildcard"] {
		t.Errorf("expected wildcard finding, got %v", got)
	}
	if !got["CSP missing base-uri"] {
		t.Errorf("expected missing base-uri, got %v", got)
	}
	// default-src present => object-src fallback exists, so no object-src finding.
	if got["CSP missing object-src"] {
		t.Errorf("object-src should fall back to default-src")
	}
}

func TestCSPWeaknessStrictPolicyClean(t *testing.T) {
	got := cspIssues(t, "default-src 'none'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'none'")
	if len(got) != 0 {
		t.Errorf("a strict policy should produce no findings, got %v", got)
	}
}

func TestCSPWeaknessNoHeaderNoFindings(t *testing.T) {
	if got := cspIssues(t, ""); len(got) != 0 {
		t.Errorf("no CSP header => csp-weakness silent, got %v", got)
	}
}
