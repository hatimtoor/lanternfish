package session

import (
	"net/url"
	"regexp"
	"sync"

	"lanternfish/internal/httpmsg"
)

// RewriteRule is a match-and-replace rule applied to proxied requests.
type RewriteRule struct {
	ID          int64  `json:"id"`
	Enabled     bool   `json:"enabled"`
	Target      string `json:"target"` // "url" | "header" | "body"
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
	re          *regexp.Regexp
}

// Rewriter holds the ordered match-and-replace rules.
type Rewriter struct {
	mu     sync.RWMutex
	nextID int64
	rules  []*RewriteRule
}

func newRewriter() *Rewriter { return &Rewriter{} }

// Add compiles and appends a rule. Returns the rule or an error on bad regex.
func (rw *Rewriter) Add(target, pattern, replacement string, enabled bool) (*RewriteRule, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	rw.nextID++
	r := &RewriteRule{ID: rw.nextID, Enabled: enabled, Target: target, Pattern: pattern, Replacement: replacement, re: re}
	rw.rules = append(rw.rules, r)
	return r, nil
}

// Remove deletes a rule by id.
func (rw *Rewriter) Remove(id int64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	for i, r := range rw.rules {
		if r.ID == id {
			rw.rules = append(rw.rules[:i], rw.rules[i+1:]...)
			return true
		}
	}
	return false
}

// Toggle enables/disables a rule.
func (rw *Rewriter) Toggle(id int64, enabled bool) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	for _, r := range rw.rules {
		if r.ID == id {
			r.Enabled = enabled
			return true
		}
	}
	return false
}

// List returns copies of the rules.
func (rw *Rewriter) List() []RewriteRule {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	out := make([]RewriteRule, 0, len(rw.rules))
	for _, r := range rw.rules {
		out = append(out, *r)
	}
	return out
}

// active reports whether any rule is enabled (fast path).
func (rw *Rewriter) active() bool {
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	for _, r := range rw.rules {
		if r.Enabled {
			return true
		}
	}
	return false
}

// Apply mutates req in place according to enabled rules.
func (rw *Rewriter) Apply(req *httpmsg.Request) {
	if !rw.active() {
		return
	}
	rw.mu.RLock()
	defer rw.mu.RUnlock()
	for _, r := range rw.rules {
		if !r.Enabled || r.re == nil {
			continue
		}
		switch r.Target {
		case "url":
			if req.URL != nil {
				if u := r.re.ReplaceAllString(req.URL.String(), r.Replacement); u != req.URL.String() {
					if parsed, err := url.Parse(u); err == nil {
						req.URL = parsed
					}
				}
			}
		case "header":
			for k, vals := range req.Header {
				for i, v := range vals {
					vals[i] = r.re.ReplaceAllString(v, r.Replacement)
				}
				req.Header[k] = vals
			}
		case "body":
			if len(req.Body) > 0 {
				req.Body = []byte(r.re.ReplaceAllString(string(req.Body), r.Replacement))
			}
		}
	}
}
