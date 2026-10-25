// Package kb is Lanternfish's built-in knowledge base: a plain-language explanation
// for each kind of finding, written for someone learning security. For every
// check it answers what the issue is, why it matters, how to confirm it by
// hand, how to exploit it safely in a lab, and how to fix it, with links to
// free learning resources. This turns a finding from a verdict into a lesson.
package kb

import "strings"

// Entry is the teaching content for one class of finding.
type Entry struct {
	Title   string   `json:"title"`
	What    string   `json:"what"`    // what the vulnerability is
	Why     string   `json:"why"`     // why it matters / impact
	Confirm string   `json:"confirm"` // how to confirm it by hand
	Exploit string   `json:"exploit"` // how to demonstrate it safely (in a lab)
	Fix     string   `json:"fix"`     // how to remediate
	Refs    []string `json:"refs"`    // free resources to learn more
}

// Lookup returns the entry for a check ID. It tries the exact ID, then a
// family prefix (so the many sqli-*, secret-*, fingerprint-*, dom-* checks
// share one lesson), and reports whether anything matched.
func Lookup(check string) (Entry, bool) {
	if e, ok := entries[check]; ok {
		return e, true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(check, p.prefix) {
			if e, ok := entries[p.key]; ok {
				return e, true
			}
		}
	}
	return Entry{}, false
}

// Keys returns every check ID that has a dedicated entry (sorted callers can
// use it to list available lessons).
func Keys() []string {
	out := make([]string, 0, len(entries))
	for k := range entries {
		out = append(out, k)
	}
	return out
}

// prefixes map a family of check IDs to a shared entry. Order matters: the
// most specific prefixes come first.
var prefixes = []struct{ prefix, key string }{
	{"sqli-", "sqli"},
	{"secret-", "exposed-secrets"},
	{"fingerprint-", "banner-disclosure"},
	{"dom-prototype", "dom-prototype-pollution"},
	{"dom-", "dom-xss"},
	{"command-injection", "command-injection"},
	{"path-traversal", "path-traversal"},
	{"csp-", "csp-weakness"},
	{"ssrf", "blind-ssrf"},
	{"graphql", "graphql-introspection"},
	{"ext:", "exposed-secrets"},
}
