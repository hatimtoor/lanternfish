// Command sigsync refreshes Lanternfish's vulnerable-JS-library signatures from
// the public retire.js database and writes them, in Lanternfish's simple
// schema, to internal/scan/checks/data/retirejs.json. The scanner embeds that
// file and merges the entries with its curated set, so coverage stays current
// without hand-editing. It is a developer tool, not part of the shipped binary.
//
// Usage: go run ./tools/sigsync   (or: scripts/update-signatures.sh)
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const source = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
const outPath = "internal/scan/checks/data/retirejs.json"

const gitleaksSource = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
const gitleaksOut = "internal/scan/checks/data/gitleaks.json"

type vuln struct {
	Below       string `json:"below"`
	Severity    string `json:"severity"`
	Identifiers struct {
		Summary string   `json:"summary"`
		CVE     []string `json:"CVE"`
	} `json:"identifiers"`
}

type comp struct {
	Vulnerabilities []vuln `json:"vulnerabilities"`
	Extractors      struct {
		URI         []string `json:"uri"`
		Filename    []string `json:"filename"`
		Filecontent []string `json:"filecontent"`
	} `json:"extractors"`
}

type libData struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
	Below string `json:"below"`
	Issue string `json:"issue"`
}

func main() {
	raw, err := fetch(source)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch:", err)
		os.Exit(1)
	}
	var db map[string]json.RawMessage
	if err := json.Unmarshal(raw, &db); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}

	var out []libData
	for name, rm := range db {
		if strings.HasPrefix(name, "$") { // $schema etc.
			continue
		}
		var c comp
		if json.Unmarshal(rm, &c) != nil {
			continue
		}
		re := bestRegex(append(append([]string{}, c.Extractors.Filecontent...), append(c.Extractors.URI, c.Extractors.Filename...)...))
		if re == "" {
			continue
		}
		below, v := maxBelow(c.Vulnerabilities)
		if below == "" {
			continue
		}
		out = append(out, libData{
			Name:  title(name),
			Regex: re,
			Below: below,
			Issue: summarize(v),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(outPath, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d signatures to %s (from retire.js)\n", len(out), outPath)

	if err := syncGitleaks(); err != nil {
		fmt.Fprintln(os.Stderr, "gitleaks:", err)
		os.Exit(1)
	}
}

// genSecret is the schema the scanner reads for generated secret rules.
type genSecret struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// syncGitleaks fetches the gitleaks rule set and writes the provider-specific
// (non-generic, regex-sufficient) rules as secret signatures. Rules that lean
// on entropy, or whose id is generic, are skipped to keep false positives low.
func syncGitleaks() error {
	raw, err := fetch(gitleaksSource)
	if err != nil {
		return err
	}
	var cfg struct {
		Rules []struct {
			ID          string  `toml:"id"`
			Description string  `toml:"description"`
			Regex       string  `toml:"regex"`
			Entropy     float64 `toml:"entropy"`
		} `toml:"rules"`
	}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	var out []genSecret
	seen := map[string]bool{}
	for _, r := range cfg.Rules {
		if r.Regex == "" || r.Entropy > 0 || strings.Contains(r.ID, "generic") {
			continue
		}
		if _, err := regexp.Compile(r.Regex); err != nil {
			continue // not a Go-compatible regex
		}
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		name := r.Description
		if name == "" {
			name = r.ID
		}
		if len(name) > 120 {
			name = name[:117] + "..."
		}
		out = append(out, genSecret{ID: r.ID, Name: name, Regex: r.Regex})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(gitleaksOut, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d secret rules to %s (from gitleaks)\n", len(out), gitleaksOut)
	return nil
}

func fetch(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "lanternfish-sigsync")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// verGroup is a named capture so the version can be found regardless of any
// other groups in the retire.js extractor.
var verGroup = `(?P<ver>[0-9]+(?:\.[0-9]+)+)`

// bestRegex converts the first retire.js extractor that yields a valid regex
// with a named "ver" group into our schema.
func bestRegex(extractors []string) string {
	for _, e := range extractors {
		if !strings.Contains(e, "§§version§§") {
			continue
		}
		r := strings.ReplaceAll(e, "§§version§§", verGroup)
		re, err := regexp.Compile(r)
		if err != nil || !hasVer(re) {
			continue
		}
		return r
	}
	return ""
}

func hasVer(re *regexp.Regexp) bool {
	for _, n := range re.SubexpNames() {
		if n == "ver" {
			return true
		}
	}
	return false
}

// maxBelow returns the highest numeric "below" bound and the vuln it came from.
func maxBelow(vs []vuln) (string, vuln) {
	best := ""
	var bestV vuln
	for _, v := range vs {
		p := parseVer(v.Below)
		if p == nil {
			continue
		}
		if best == "" || less(parseVer(best), p) {
			best = v.Below
			bestV = v
		}
	}
	return best, bestV
}

func summarize(v vuln) string {
	sev := v.Severity
	if sev == "" {
		sev = "known"
	}
	s := v.Identifiers.Summary
	if s == "" && len(v.Identifiers.CVE) > 0 {
		s = strings.Join(v.Identifiers.CVE, ", ")
	}
	s = strings.TrimSpace(sev + " severity issue" + ternary(s != "", ": "+s, ""))
	if len(s) > 140 {
		s = s[:137] + "..."
	}
	return s
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func parseVer(v string) []int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func less(a, b []int) bool {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
