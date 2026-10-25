package kb

import "testing"

// TestCheckIDsResolveToLessons guards that every check id a scan can emit maps
// to a knowledge-base lesson (exactly or via a family prefix), so the explain
// command and teachable reports never come up empty for a real finding.
func TestCheckIDsResolveToLessons(t *testing.T) {
	ids := []string{
		"csp-weakness", "path-traversal-oracle", "sqli-oob",
		"command-injection-oob", "command-injection-inband", "sqli-time-blind", "ssrf",
		"sqli-error", "xpath-injection", "ldap-injection", "reflected-xss",
	}
	for _, id := range ids {
		if _, ok := Lookup(id); !ok {
			t.Errorf("no kb lesson resolves for check id %q", id)
		}
	}
}
