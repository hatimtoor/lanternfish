package checks

import (
	"strings"
	"testing"
)

// TestGeneratedSignaturesLoaded verifies the refreshed retire.js signatures are
// embedded and merged, and that one of them (not in the curated set) detects an
// outdated library end to end.
func TestGeneratedSignaturesLoaded(t *testing.T) {
	if len(genSigs) == 0 {
		t.Fatal("no generated signatures loaded from embedded data (run scripts/update-signatures.sh)")
	}
	// AlaSQL comes from the retire.js data, not the curated libSigs.
	body := `<html><head><script>/*! AlaSQL v0.5.0 */</script></head><body>x</body></html>`
	tx := txFull("http://x/app.js", "application/javascript", body, nil)
	issues := (VulnerableJSLibrary{}).Passive(tx)
	found := false
	for _, is := range issues {
		if strings.Contains(is.Name, "AlaSQL") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a generated signature to flag AlaSQL 0.5.0; got %d issue(s)", len(issues))
	}
}
