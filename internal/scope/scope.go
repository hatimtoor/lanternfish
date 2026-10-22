// Package scope decides which hosts/URLs are in-scope for recording, scanning,
// and interception, mirroring the include/exclude model of a target scope.
package scope

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Rule matches a URL by host (and optional path prefix). Host may be a literal
// or a wildcard like "*.example.com".
type Rule struct {
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix,omitempty"`
	hostRE     *regexp.Regexp
}

func compile(r *Rule) {
	pat := regexp.QuoteMeta(r.Host)
	pat = strings.ReplaceAll(pat, `\*`, `.*`)
	r.hostRE = regexp.MustCompile("(?i)^" + pat + "$")
}

func (r *Rule) matches(u *url.URL) bool {
	if r.hostRE == nil {
		compile(r)
	}
	if !r.hostRE.MatchString(u.Hostname()) {
		return false
	}
	if r.PathPrefix != "" && !strings.HasPrefix(u.Path, r.PathPrefix) {
		return false
	}
	return true
}

// Scope holds include and exclude rules. Empty include set means "everything"
// so the tool is useful out of the box; add includes to narrow it.
type Scope struct {
	mu       sync.RWMutex
	includes []*Rule
	excludes []*Rule
}

func New() *Scope { return &Scope{} }

// InScope reports whether u is in scope.
func (s *Scope) InScope(u *url.URL) bool {
	if u == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.excludes {
		if e.matches(u) {
			return false
		}
	}
	if len(s.includes) == 0 {
		return true
	}
	for _, in := range s.includes {
		if in.matches(u) {
			return true
		}
	}
	return false
}

// HasIncludes reports whether any include rule has been set, i.e. whether the
// scope has been narrowed from the default "everything". Callers that take
// active or outbound action on in-scope traffic use this to refuse to run
// against an unbounded scope.
func (s *Scope) HasIncludes() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.includes) > 0
}

// Include adds an include rule.
func (s *Scope) Include(host, pathPrefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &Rule{Host: host, PathPrefix: pathPrefix}
	compile(r)
	s.includes = append(s.includes, r)
}

// Exclude adds an exclude rule.
func (s *Scope) Exclude(host, pathPrefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &Rule{Host: host, PathPrefix: pathPrefix}
	compile(r)
	s.excludes = append(s.excludes, r)
}

// Rules returns copies of the current include/exclude rules.
func (s *Scope) Rules() (includes, excludes []Rule) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.includes {
		includes = append(includes, Rule{Host: r.Host, PathPrefix: r.PathPrefix})
	}
	for _, r := range s.excludes {
		excludes = append(excludes, Rule{Host: r.Host, PathPrefix: r.PathPrefix})
	}
	return
}

// Clear removes all rules.
func (s *Scope) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.includes = nil
	s.excludes = nil
}
