package checks

import (
	"encoding/base64"
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// InsecureDeserialization flags serialized-object markers in requests or
// responses (Java, PHP, Python pickle, .NET), which signal deserialization of
// untrusted data.
type InsecureDeserialization struct{}

func (InsecureDeserialization) ID() string { return "insecure-deserialization" }

var (
	javaSerB64 = regexp.MustCompile(`rO0AB`) // base64 of 0xACED0005
	phpSer     = regexp.MustCompile(`(?i)\bO:\d+:"[^"]+":\d+:\{`)
	netViewSt  = regexp.MustCompile(`__VIEWSTATE`)
)

func (InsecureDeserialization) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	hay := string(tx.Request.Body)
	if tx.Response != nil {
		hay += "\n" + tx.Response.BodyString()
	}
	// Also consider the query string.
	hay += "\n" + tx.Request.AbsoluteURL().RawQuery

	var kind string
	switch {
	case javaSerB64.MatchString(hay) || strings.Contains(tx.Request.AbsoluteURL().RawQuery, "%C2%AC%C3%AD"):
		kind = "Java serialized object (0xACED0005)"
	case phpSer.MatchString(hay):
		kind = "PHP serialized object"
	case netViewSt.MatchString(hay):
		kind = ".NET ViewState"
	default:
		return nil
	}
	return []*scan.Issue{{
		Check: "insecure-deserialization", Name: "Serialized object in traffic (" + kind + ")",
		URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityMedium, Confidence: scan.ConfidenceTentative,
		Detail:      "Traffic contains a " + kind + ". If the server deserializes attacker-controllable data, this can lead to remote code execution.",
		Remediation: "Avoid native deserialization of untrusted input; use safe formats (JSON) with strict schemas and integrity protection.",
		CWE:         "CWE-502",
	}}
}

// JWTWeakness flags JSON Web Tokens that use the 'none' algorithm.
type JWTWeakness struct{}

func (JWTWeakness) ID() string { return "jwt-weakness" }

var jwtRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*`)

func (JWTWeakness) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	hay := tx.Request.Header.Get("Authorization") + "\n" + strings.Join(tx.Request.Header.Values("Cookie"), "\n")
	if tx.Response != nil {
		hay += "\n" + strings.Join(tx.Response.Header.Values("Set-Cookie"), "\n") + "\n" + tx.Response.BodyString()
	}
	for _, tok := range jwtRE.FindAllString(hay, 20) {
		parts := strings.Split(tok, ".")
		if len(parts) < 2 {
			continue
		}
		hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			continue
		}
		h := strings.ToLower(string(hdr))
		if strings.Contains(h, `"alg":"none"`) || strings.Contains(h, `"alg": "none"`) {
			return []*scan.Issue{{
				Check: "jwt-weakness", Name: "JWT uses 'none' algorithm",
				URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
				Detail:      "A JSON Web Token declares alg=none, meaning it is unsigned and can be forged by an attacker.",
				Remediation: "Reject alg=none; require a strong signature algorithm and verify it server-side.",
				Evidence:    string(hdr), CWE: "CWE-347",
			}}
		}
	}
	return nil
}

// EmailDisclosure flags email addresses in responses (informational).
type EmailDisclosure struct{}

func (EmailDisclosure) ID() string { return "email-disclosure" }

var emailRE = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func (EmailDisclosure) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	if m := emailRE.FindString(tx.Response.BodyString()); m != "" {
		return []*scan.Issue{{
			Check: "email-disclosure", Name: "Email address disclosure",
			URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityInfo, Confidence: scan.ConfidenceFirm,
			Detail:      "The response discloses an email address, which may aid phishing or enumeration.",
			Remediation: "Avoid exposing internal contact addresses; obfuscate where unavoidable.",
			Evidence:    m, CWE: "CWE-200",
		}}
	}
	return nil
}

// CacheableSensitive flags responses that set a cookie yet permit caching.
type CacheableSensitive struct{}

func (CacheableSensitive) ID() string { return "cacheable-sensitive" }

func (CacheableSensitive) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil || len(tx.Response.Header.Values("Set-Cookie")) == 0 {
		return nil
	}
	cc := strings.ToLower(tx.Response.Header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return nil
	}
	return []*scan.Issue{{
		Check: "cacheable-sensitive", Name: "Cacheable response sets a cookie",
		URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityLow, Confidence: scan.ConfidenceTentative,
		Detail:      "A response that sets a cookie does not forbid caching (no Cache-Control: no-store/private), so shared caches may store session data.",
		Remediation: "Send Cache-Control: no-store (or private, no-cache) on responses that set cookies or contain sensitive data.",
		CWE:         "CWE-525",
	}}
}

// AdditionalHeaders flags missing Referrer-Policy and Permissions-Policy.
type AdditionalHeaders struct{}

func (AdditionalHeaders) ID() string { return "additional-headers" }

func (AdditionalHeaders) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil || !strings.Contains(tx.Response.ContentType(), "html") {
		return nil
	}
	var issues []*scan.Issue
	if tx.Response.Header.Get("Referrer-Policy") == "" {
		issues = append(issues, &scan.Issue{
			Check: "additional-headers", Name: "Missing Referrer-Policy",
			URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityInfo, Confidence: scan.ConfidenceFirm,
			Detail:      "No Referrer-Policy header; full URLs (possibly with tokens) may leak to third parties via the Referer header.",
			Remediation: "Set a Referrer-Policy such as strict-origin-when-cross-origin.", CWE: "CWE-200", HostScoped: true,
		})
	}
	if tx.Response.Header.Get("Permissions-Policy") == "" {
		issues = append(issues, &scan.Issue{
			Check: "additional-headers", Name: "Missing Permissions-Policy",
			URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityInfo, Confidence: scan.ConfidenceFirm,
			Detail:      "No Permissions-Policy header to restrict powerful browser features (camera, geolocation, etc.).",
			Remediation: "Set a Permissions-Policy limiting features the app does not use.", CWE: "CWE-16", HostScoped: true,
		})
	}
	return issues
}
