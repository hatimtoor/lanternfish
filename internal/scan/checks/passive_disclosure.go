package checks

import (
	"regexp"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// ExposedSecrets passively flags high-precision secret patterns in responses.
type ExposedSecrets struct{}

func (ExposedSecrets) ID() string { return "exposed-secrets" }

var secretPatterns = []struct {
	name         string
	re           *regexp.Regexp
	skipAuthPath bool // skip on login/token endpoints where returning this is expected
}{
	{"AWS access key id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), false},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), false},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`), false},
	{"private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----`), false},
	{"JSON Web Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), true},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`), false},
}

// authPathRe matches endpoints whose job is to issue a token/session, where a
// JWT in the response is expected rather than a leak.
var authPathRe = regexp.MustCompile(`(?i)/(login|logon|sign-?in|auth|authenticate|oauth|token|session|connect|refresh)`)

func (ExposedSecrets) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	body := tx.Response.BodyString()
	url := tx.Request.AbsoluteURL().String()
	authPath := authPathRe.MatchString(tx.Request.AbsoluteURL().Path)
	var issues []*scan.Issue
	for _, p := range secretPatterns {
		if p.skipAuthPath && authPath {
			continue // a token returned by a login/token endpoint is expected, not a leak
		}
		if m := p.re.FindString(body); m != "" {
			issues = append(issues, &scan.Issue{
				Check: "exposed-secrets", Name: "Exposed secret: " + p.name,
				URL: url, Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
				Detail:      "The response body contains what looks like a " + p.name + ", which should never be returned to clients.",
				Remediation: "Remove the secret from responses, rotate it, and store secrets server-side only.",
				Evidence:    redact(m),
				CWE:         "CWE-200",
			})
		}
	}
	return issues
}

// redact shows only the first few characters of a matched secret.
func redact(s string) string {
	if len(s) <= 8 {
		return s[:len(s)/2] + "…"
	}
	return s[:8] + "…(redacted)"
}

// DirectoryListing flags auto-generated directory index pages.
type DirectoryListing struct{}

func (DirectoryListing) ID() string { return "directory-listing" }

var dirListing = regexp.MustCompile(`(?i)<title>\s*Index of /|<h1>\s*Index of /|Directory Listing For`)

func (DirectoryListing) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil || tx.Response.StatusCode != 200 {
		return nil
	}
	if dirListing.MatchString(tx.Response.BodyString()) {
		return []*scan.Issue{{
			Check: "directory-listing", Name: "Directory listing enabled",
			URL:      tx.Request.AbsoluteURL().String(),
			Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
			Detail:      "The server returned an auto-generated directory index, exposing the names of files that are not meant to be browsable.",
			Remediation: "Disable automatic directory indexing (e.g. Options -Indexes) and serve an explicit index or 403.",
			CWE:         "CWE-548",
		}}
	}
	return nil
}

// VerboseError passively flags stack traces / framework error disclosure.
type VerboseError struct{}

func (VerboseError) ID() string { return "verbose-error" }

var errorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?m)^\s*at [\w.$]+\([\w.]+\.java:\d+\)`),
	regexp.MustCompile(`java\.lang\.[A-Za-z.]+Exception`),
	regexp.MustCompile(`System\.(?:Web|Data|NullReference)[A-Za-z.]*Exception`),
	regexp.MustCompile(`(?i)Fatal error:.*in .*on line \d+`),
	regexp.MustCompile(`(?i)Warning:\s+\w+\(\).*on line \d+`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider`),
	regexp.MustCompile(`(?i)Stack trace:`),
}

func (VerboseError) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	body := tx.Response.BodyString()
	for _, re := range errorSignatures {
		if m := re.FindString(body); m != "" {
			return []*scan.Issue{{
				Check: "verbose-error", Name: "Verbose error message / stack trace",
				URL:      tx.Request.AbsoluteURL().String(),
				Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
				Detail:      "The response exposes a stack trace or framework error, revealing internal implementation details useful to an attacker.",
				Remediation: "Return generic error pages in production and log details server-side only.",
				Evidence:    excerpt(body, m),
				CWE:         "CWE-209",
			}}
		}
	}
	return nil
}
