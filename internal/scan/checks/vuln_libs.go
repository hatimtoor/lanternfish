package checks

import (
	"embed"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// sigData holds the vulnerable-library signatures refreshed from retire.js by
// `scripts/update-signatures.sh` (see tools/sigsync). They supplement the
// curated libSigs below, so coverage stays current without hand-editing.
//
//go:embed data/retirejs.json
var sigData embed.FS

// libData is the on-disk schema for a generated library signature.
type libData struct {
	Name  string `json:"name"`
	Regex string `json:"regex"` // must have exactly one capture group: the version
	Below string `json:"below"` // vulnerable when the detected version is below this
	Issue string `json:"issue"`
}

func init() {
	b, err := sigData.ReadFile("data/retirejs.json")
	if err != nil {
		return
	}
	var items []libData
	if json.Unmarshal(b, &items) != nil {
		return
	}
	for _, it := range items {
		re, err := regexp.Compile(it.Regex)
		if err != nil {
			continue
		}
		idx := -1
		for i, n := range re.SubexpNames() {
			if n == "ver" {
				idx = i
				break
			}
		}
		parts := parseVerParts(it.Below)
		if idx < 1 || parts == nil {
			continue
		}
		genSigs = append(genSigs, genSig{name: it.Name, re: re, verIdx: idx, fixedI: parts, fixed: it.Below, issue: it.Issue})
	}
}

// parseVerParts turns "1.6.3" into []int{1,6,3}; returns nil on garbage.
func parseVerParts(v string) []int {
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

// VulnerableJSLibrary passively detects common front-end libraries and flags
// versions below a known-safe cutoff, in the spirit of retire.js. The signature
// set is small and conservative; it reports the library, detected version, and
// the issue class fixed at the cutoff.
type VulnerableJSLibrary struct{}

func (VulnerableJSLibrary) ID() string { return "vulnerable-js-library" }

type libSig struct {
	name   string
	re     *regexp.Regexp // first group is the version
	fixedI []int          // fixed-at version as int parts
	fixed  string
	issue  string
}

// genSig is a signature loaded from a refreshed data file (see sigData). Unlike
// the curated libSigs, the version is a named capture group, so the source
// regex may contain other groups.
type genSig struct {
	name   string
	re     *regexp.Regexp
	verIdx int
	fixedI []int
	fixed  string
	issue  string
}

var genSigs []genSig

var libSigs = []libSig{
	{"jQuery", regexp.MustCompile(`(?i)jquery[ \-/]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{3, 5, 0}, "3.5.0", "cross-site scripting (CVE-2020-11022/11023)"},
	{"jQuery", regexp.MustCompile(`(?i)jQuery JavaScript Library v([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{3, 5, 0}, "3.5.0", "cross-site scripting"},
	{"AngularJS", regexp.MustCompile(`(?i)angular(?:js)?[ \-/]?v?([1]\.[0-9]+(?:\.[0-9]+)?)`), []int{1, 8, 0}, "1.8.0", "multiple sandbox-bypass XSS issues (1.x is end-of-life)"},
	{"Bootstrap", regexp.MustCompile(`(?i)bootstrap[ \-/]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{4, 3, 1}, "4.3.1", "XSS in data-* attributes (CVE-2019-8331)"},
	{"Lodash", regexp.MustCompile(`(?i)lodash[ \-/@]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{4, 17, 21}, "4.17.21", "prototype pollution / command injection"},
	{"Moment.js", regexp.MustCompile(`(?i)moment(?:\.js)?[ \-/@]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{2, 29, 4}, "2.29.4", "path traversal / ReDoS (CVE-2022-31129/24785)"},
	{"Handlebars", regexp.MustCompile(`(?i)handlebars[ \-/@]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{4, 7, 7}, "4.7.7", "prototype pollution / RCE in templates"},
	{"jQuery UI", regexp.MustCompile(`(?i)jquery[ \-]?ui[ \-/]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{1, 13, 2}, "1.13.2", "XSS in several widgets"},
	{"DOMPurify", regexp.MustCompile(`(?i)dompurify[ \-/@]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{2, 4, 0}, "2.4.0", "mutation XSS bypasses"},
	{"Axios", regexp.MustCompile(`(?i)axios[ \-/@]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{0, 21, 2}, "0.21.2", "SSRF / credential leak on redirect (CVE-2020-28168)"},
	{"Underscore.js", regexp.MustCompile(`(?i)underscore(?:\.js)?[ \-/@]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{1, 12, 1}, "1.12.1", "arbitrary code execution via template (CVE-2021-23358)"},
	{"CKEditor", regexp.MustCompile(`(?i)ckeditor[ \-/@]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{4, 24, 0}, "4.24.0", "XSS in the HTML parser"},
	{"TinyMCE", regexp.MustCompile(`(?i)tinymce[ \-/@]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`), []int{5, 10, 7}, "5.10.7", "stored XSS (CVE-2022-23494)"},
}

func (VulnerableJSLibrary) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	ct := tx.Response.ContentType()
	if !strings.Contains(ct, "javascript") && !strings.Contains(ct, "html") {
		return nil
	}
	body := tx.Response.BodyString()
	seen := map[string]bool{}
	var issues []*scan.Issue
	for _, sig := range libSigs {
		m := sig.re.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		ver := m[1]
		if !versionLess(ver, sig.fixedI) {
			continue
		}
		if is := libIssue(tx, sig.name, ver, sig.fixed, sig.issue, m[0], seen); is != nil {
			issues = append(issues, is)
		}
	}
	// Generated (refreshed) signatures: version is the named "ver" group.
	for _, sig := range genSigs {
		m := sig.re.FindStringSubmatch(body)
		if m == nil || sig.verIdx >= len(m) {
			continue
		}
		ver := m[sig.verIdx]
		if !versionLess(ver, sig.fixedI) {
			continue
		}
		if is := libIssue(tx, sig.name, ver, sig.fixed, sig.issue, m[0], seen); is != nil {
			issues = append(issues, is)
		}
	}
	return issues
}

// libIssue builds a vulnerable-library issue, de-duplicating on name+version.
func libIssue(tx *httpmsg.Transaction, name, ver, fixed, issue, evidence string, seen map[string]bool) *scan.Issue {
	key := name + ver
	if seen[key] {
		return nil
	}
	seen[key] = true
	return &scan.Issue{
		Check: "vulnerable-js-library", Name: "Outdated JavaScript library: " + name + " " + ver,
		URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityMedium, Confidence: scan.ConfidenceTentative,
		Detail:      name + " " + ver + " is below " + fixed + ", which fixed " + issue + ".",
		Remediation: "Upgrade " + name + " to " + fixed + " or later.",
		Evidence:    strings.TrimSpace(evidence), CWE: "CWE-1104",
	}
}

// versionLess reports whether the dotted version string is below fixed.
func versionLess(ver string, fixed []int) bool {
	parts := strings.Split(ver, ".")
	for i := 0; i < len(fixed); i++ {
		var p int
		if i < len(parts) {
			p, _ = strconv.Atoi(parts[i])
		}
		if p < fixed[i] {
			return true
		}
		if p > fixed[i] {
			return false
		}
	}
	return false
}
