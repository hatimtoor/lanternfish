package service

import (
	"testing"

	"lanternfish/internal/browser"
)

func TestDOMProbeTargetsSelectsRoutesAndQueries(t *testing.T) {
	s := &Service{}
	br := &browser.Result{
		Routes: []string{"http://h/#/search?q=1", "http://h/#/about"},
		Links:  []string{"http://h/item?id=1", "http://h/plain"},
		XHR:    []string{"http://h/api?u=1", "http://h/api/noparam"},
	}
	got := s.DOMProbeTargets(br, "http://h/", 25)

	want := map[string]bool{
		"http://h/":             true, // seed always included
		"http://h/#/search?q=1": true, // SPA route
		"http://h/#/about":      true, // SPA route (even without a query)
		"http://h/item?id=1":    true, // link with a query
		"http://h/api?u=1":      true, // XHR with a query
	}
	for w := range want {
		if !contains(got, w) {
			t.Errorf("expected %q in probe targets, got %v", w, got)
		}
	}
	if contains(got, "http://h/plain") || contains(got, "http://h/api/noparam") {
		t.Errorf("plain query-less links/XHR should be skipped, got %v", got)
	}
}

func TestDOMProbeTargetsRespectsBudget(t *testing.T) {
	s := &Service{}
	br := &browser.Result{Routes: []string{"http://h/#/a", "http://h/#/b", "http://h/#/c"}}
	if got := s.DOMProbeTargets(br, "http://h/", 2); len(got) != 2 {
		t.Fatalf("budget of 2 must cap the list, got %d: %v", len(got), got)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
