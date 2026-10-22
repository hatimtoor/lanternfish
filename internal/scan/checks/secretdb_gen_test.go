package checks

import (
	"strings"
	"testing"
)

// TestGitleaksSecretsLoaded verifies the generated gitleaks rules are embedded
// and that one of them fires. The matching value is assembled at runtime so no
// literal secret token lives in source.
func TestGitleaksSecretsLoaded(t *testing.T) {
	// Find a generated rule (one whose id is not in the curated set).
	var genCount int
	for _, r := range secretRules {
		if strings.HasPrefix(r.id, "secret-adafruit") || strings.HasPrefix(r.id, "secret-datadog") {
			genCount++
		}
	}
	if genCount == 0 {
		t.Fatal("no gitleaks-generated secret rules loaded (run scripts/update-signatures.sh)")
	}

	// A fake value matching the adafruit keyword-proximity rule, built at runtime.
	body := "adafruit_api_key = " + strings.Repeat("a", 32) + ";"
	tx := txFull("http://x/", "text/html", body, nil)
	found := false
	for _, c := range Secrets() {
		if len(c.Passive(tx)) > 0 && strings.Contains(c.ID(), "adafruit") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a generated gitleaks rule to flag the fake adafruit key")
	}
}
