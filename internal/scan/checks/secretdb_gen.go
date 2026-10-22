package checks

import (
	"embed"
	"encoding/json"
	"regexp"

	"lanternfish/internal/scan"
)

// secretGenFS holds secret-detection patterns refreshed from gitleaks by
// `scripts/update-signatures.sh` (see tools/sigsync). They supplement the
// curated secretRules so coverage of provider tokens stays current.
//
//go:embed data/gitleaks.json
var secretGenFS embed.FS

// genSecretEntry is the on-disk schema for a generated secret rule.
type genSecretEntry struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

func init() {
	b, err := secretGenFS.ReadFile("data/gitleaks.json")
	if err != nil {
		return
	}
	var items []genSecretEntry
	if json.Unmarshal(b, &items) != nil {
		return
	}
	existing := map[string]bool{}
	for _, r := range secretRules {
		existing[r.id] = true
	}
	for _, it := range items {
		id := "secret-" + it.ID
		if existing[id] || it.Regex == "" {
			continue
		}
		re, err := regexp.Compile(it.Regex)
		if err != nil {
			continue
		}
		secretRules = append(secretRules, regexPassive{
			id: id, name: it.Name, cwe: "CWE-798",
			sev: scan.SeverityHigh, conf: scan.ConfidenceFirm,
			re: re, redactIt: true,
		})
		existing[id] = true
	}
}
