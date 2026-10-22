package checks

import (
	"regexp"
	"strconv"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

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
		key := sig.name + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		issues = append(issues, &scan.Issue{
			Check: "vulnerable-js-library", Name: "Outdated JavaScript library: " + sig.name + " " + ver,
			URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityMedium, Confidence: scan.ConfidenceTentative,
			Detail:      sig.name + " " + ver + " is below " + sig.fixed + ", which fixed " + sig.issue + ".",
			Remediation: "Upgrade " + sig.name + " to " + sig.fixed + " or later.",
			Evidence:    strings.TrimSpace(m[0]), CWE: "CWE-1104",
		})
	}
	return issues
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
