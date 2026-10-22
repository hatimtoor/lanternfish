package scope

import (
	"net/url"
	"testing"
)

func u(s string) *url.URL { p, _ := url.Parse(s); return p }

func TestEmptyScopeAllowsAll(t *testing.T) {
	s := New()
	if !s.InScope(u("http://anything.test/x")) {
		t.Error("empty include set should allow everything")
	}
	if s.InScope(nil) {
		t.Error("nil url should be out of scope")
	}
}

func TestIncludeExactAndWildcard(t *testing.T) {
	s := New()
	s.Include("app.test", "")
	s.Include("*.api.test", "")
	if !s.InScope(u("http://app.test/x")) {
		t.Error("exact host should match")
	}
	if s.InScope(u("http://other.test/x")) {
		t.Error("non-listed host should be out")
	}
	if !s.InScope(u("https://v1.api.test/x")) {
		t.Error("wildcard should match subdomain")
	}
	if s.InScope(u("https://api.test/x")) {
		t.Error("wildcard *.api.test should not match bare api.test")
	}
}

func TestPathPrefix(t *testing.T) {
	s := New()
	s.Include("h.test", "/admin")
	if !s.InScope(u("http://h.test/admin/panel")) {
		t.Error("path under prefix should match")
	}
	if s.InScope(u("http://h.test/public")) {
		t.Error("path outside prefix should not match")
	}
}

func TestExcludeOverridesInclude(t *testing.T) {
	s := New()
	s.Include("h.test", "")
	s.Exclude("h.test", "/logout")
	if s.InScope(u("http://h.test/logout")) {
		t.Error("exclude must override include")
	}
	if !s.InScope(u("http://h.test/home")) {
		t.Error("non-excluded path should remain in scope")
	}
}

func TestRulesAndClear(t *testing.T) {
	s := New()
	s.Include("a", "")
	s.Exclude("b", "/x")
	inc, exc := s.Rules()
	if len(inc) != 1 || len(exc) != 1 {
		t.Fatalf("rules wrong: %d/%d", len(inc), len(exc))
	}
	s.Clear()
	inc, exc = s.Rules()
	if len(inc) != 0 || len(exc) != 0 {
		t.Error("clear failed")
	}
}
