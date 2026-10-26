package checks

import (
	"net/http"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// SecurityHeaders is a passive check for missing or weak security response
// headers and insecure cookie attributes. All signals here are drawn from
// public guidance (OWASP Secure Headers Project).
type SecurityHeaders struct{}

func (SecurityHeaders) ID() string { return "security-headers" }

func (SecurityHeaders) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	resp := tx.Response
	url := tx.Request.AbsoluteURL().String()
	var issues []*scan.Issue

	isHTML := strings.Contains(resp.ContentType(), "html")

	add := func(name, detail, rem, cwe string, sev scan.Severity) {
		issues = append(issues, &scan.Issue{
			Check: "security-headers", Name: name, URL: url,
			Severity: sev, Confidence: scan.ConfidenceFirm,
			Detail: detail, Remediation: rem, CWE: cwe,
			HostScoped: true, // missing security headers are a site-wide config fact
		})
	}

	if isHTML && resp.Header.Get("Content-Security-Policy") == "" {
		add("Missing Content-Security-Policy",
			"The response does not set a Content-Security-Policy header, which helps mitigate XSS and data-injection.",
			"Define a restrictive Content-Security-Policy appropriate to the application.",
			"CWE-1021", scan.SeverityLow)
	}
	if resp.Header.Get("X-Content-Type-Options") == "" {
		add("Missing X-Content-Type-Options",
			"The response does not set X-Content-Type-Options: nosniff, allowing MIME sniffing.",
			"Set X-Content-Type-Options: nosniff on all responses.",
			"CWE-16", scan.SeverityInfo)
	}
	if isHTML && resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		add("Missing clickjacking protection",
			"No X-Frame-Options or CSP frame-ancestors directive was found; the page may be framed by other origins.",
			"Set X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive.",
			"CWE-1021", scan.SeverityLow)
	}
	if strings.EqualFold(tx.Request.Scheme, "https") && resp.Header.Get("Strict-Transport-Security") == "" {
		add("Missing HSTS",
			"The HTTPS response does not set Strict-Transport-Security.",
			"Set Strict-Transport-Security with an appropriate max-age.",
			"CWE-319", scan.SeverityLow)
	}

	// Cookie attribute analysis.
	for _, c := range readSetCookies(resp.Header) {
		lc := strings.ToLower(c)
		name := cookieName(c)
		if !strings.Contains(lc, "httponly") {
			add("Cookie without HttpOnly flag",
				"Set-Cookie for '"+name+"' lacks the HttpOnly attribute, exposing it to script access.",
				"Add the HttpOnly attribute to session cookies.",
				"CWE-1004", scan.SeverityLow)
		}
		if strings.EqualFold(tx.Request.Scheme, "https") && !strings.Contains(lc, "secure") {
			add("Cookie without Secure flag",
				"Set-Cookie for '"+name+"' lacks the Secure attribute on an HTTPS response.",
				"Add the Secure attribute so the cookie is only sent over HTTPS.",
				"CWE-614", scan.SeverityLow)
		}
	}

	return issues
}

func readSetCookies(h http.Header) []string { return h.Values("Set-Cookie") }

func cookieName(setCookie string) string {
	if i := strings.IndexByte(setCookie, '='); i > 0 {
		return setCookie[:i]
	}
	return setCookie
}
