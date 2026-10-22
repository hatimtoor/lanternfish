package checks

import (
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// PrivateIPDisclosure flags internal IP addresses leaked in responses.
type PrivateIPDisclosure struct{}

func (PrivateIPDisclosure) ID() string { return "private-ip-disclosure" }

var privateIP = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)

func (PrivateIPDisclosure) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	body := tx.Response.BodyString()
	if m := privateIP.FindString(body); m != "" {
		return []*scan.Issue{{
			Check: "private-ip-disclosure", Name: "Private IP address disclosure",
			URL:      tx.Request.AbsoluteURL().String(),
			Severity: scan.SeverityInfo, Confidence: scan.ConfidenceFirm,
			Detail:      "The response exposes a private/internal IP address (" + m + "), revealing internal network structure.",
			Remediation: "Remove internal addresses from responses, error pages, and headers.",
			Evidence:    m, CWE: "CWE-200",
		}}
	}
	return nil
}

// MixedContent flags HTTPS pages that reference http:// sub-resources.
type MixedContent struct{}

func (MixedContent) ID() string { return "mixed-content" }

var httpResource = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']http://[^"']+`)

func (MixedContent) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil || !strings.EqualFold(tx.Request.Scheme, "https") {
		return nil
	}
	if !strings.Contains(tx.Response.ContentType(), "html") {
		return nil
	}
	if m := httpResource.FindString(tx.Response.BodyString()); m != "" {
		return []*scan.Issue{{
			Check: "mixed-content", Name: "Mixed content on HTTPS page",
			URL:      tx.Request.AbsoluteURL().String(),
			Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
			Detail:      "An HTTPS page references a resource over plaintext http://, which can be intercepted or stripped and weakens the page's security guarantees.",
			Remediation: "Load all sub-resources over HTTPS (use protocol-relative or https URLs) and set a CSP upgrade-insecure-requests directive.",
			Evidence:    strings.TrimSpace(m), CWE: "CWE-311",
		}}
	}
	return nil
}

// PasswordAutocomplete flags password inputs that do not disable autocomplete.
type PasswordAutocomplete struct{}

func (PasswordAutocomplete) ID() string { return "password-autocomplete" }

var passwordField = regexp.MustCompile(`(?is)<input\b[^>]*type\s*=\s*["']?password["']?[^>]*>`)
var hasAutocompleteOff = regexp.MustCompile(`(?i)autocomplete\s*=\s*["']?(off|new-password)["']?`)

func (PasswordAutocomplete) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil || !strings.Contains(tx.Response.ContentType(), "html") {
		return nil
	}
	for _, field := range passwordField.FindAllString(tx.Response.BodyString(), -1) {
		if !hasAutocompleteOff.MatchString(field) {
			return []*scan.Issue{{
				Check: "password-autocomplete", Name: "Password field with autocomplete enabled",
				URL:      tx.Request.AbsoluteURL().String(),
				Severity: scan.SeverityInfo, Confidence: scan.ConfidenceTentative,
				Detail:      "A password input does not disable autocomplete, so browsers may cache the credential on shared machines.",
				Remediation: "Set autocomplete=\"off\" (or \"new-password\") on sensitive password fields.",
				Evidence:    strings.TrimSpace(field), CWE: "CWE-200",
			}}
		}
	}
	return nil
}
