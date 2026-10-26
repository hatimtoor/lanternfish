package browser

import (
	"strings"
	"testing"
)

func TestDomProbeURLPreservesHashRoute(t *testing.T) {
	const canary = "CANARY123"

	// A SPA hash-route with a query must keep its route and carry the canary in
	// the route's own query — not be overwritten by a bare "#CANARY".
	out, err := domProbeURL("http://127.0.0.1:3000/#/search?q=apples", canary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "#/search?q=") {
		t.Fatalf("hash-route /search?q= must be preserved, got %q", out)
	}
	if !strings.Contains(out, "search?q="+canary) {
		t.Fatalf("canary must land in the route query, got %q", out)
	}
	if strings.Contains(out, "#"+canary) {
		t.Fatalf("fragment must not be clobbered with a bare canary, got %q", out)
	}
}

func TestDomProbeURLHashRouteNoQuery(t *testing.T) {
	out, err := domProbeURL("http://h/#/profile", "C")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "#/profile?q=C") {
		t.Fatalf("a query-less hash-route should gain ?q=canary, got %q", out)
	}
}

func TestDomProbeURLPlainPage(t *testing.T) {
	// A non-SPA page keeps the classic behaviour: canary in the real query and
	// in the fragment (for location.hash sinks).
	out, err := domProbeURL("http://h/p?id=1", "C")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "id=C") {
		t.Fatalf("existing query value should become the canary, got %q", out)
	}
	if !strings.HasSuffix(out, "#C") {
		t.Fatalf("plain page should carry the canary in the fragment, got %q", out)
	}
}
