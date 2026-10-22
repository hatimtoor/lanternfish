package checks

import (
	"regexp"
	"strconv"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// SessionTokenInURL flags session identifiers carried in the query string,
// which leak via logs, Referer headers, and browser history.
type SessionTokenInURL struct{}

func (SessionTokenInURL) ID() string { return "session-token-in-url" }

var sessionParam = regexp.MustCompile(`(?i)(^|[?&])(jsessionid|phpsessid|sessionid|sid|session|auth|token|access_token|api_?key)=`)

func (SessionTokenInURL) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	u := tx.Request.AbsoluteURL()
	if u.RawQuery == "" {
		return nil
	}
	if m := sessionParam.FindString("?" + u.RawQuery); m != "" {
		return []*scan.Issue{{
			Check: "session-token-in-url", Name: "Session token or credential in URL",
			URL: u.String(), Severity: scan.SeverityMedium, Confidence: scan.ConfidenceFirm,
			Detail:      "A session identifier or credential is passed in the query string, where it leaks through logs, the Referer header, and browser history.",
			Remediation: "Carry session tokens in cookies (HttpOnly/Secure) or headers, never in the URL.",
			Evidence:    strings.Trim(m, "?&="), CWE: "CWE-598",
		}}
	}
	return nil
}

// BannerDisclosure flags version banners in response headers.
type BannerDisclosure struct{}

func (BannerDisclosure) ID() string { return "banner-disclosure" }

var versionish = regexp.MustCompile(`\d+\.\d+`)

func (BannerDisclosure) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	var issues []*scan.Issue
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime"} {
		v := tx.Response.Header.Get(h)
		if v != "" && versionish.MatchString(v) {
			issues = append(issues, &scan.Issue{
				Check: "banner-disclosure", Name: "Software version disclosure",
				URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityInfo, Confidence: scan.ConfidenceFirm,
				Detail:      "The response header " + h + " reveals software and version, aiding targeted exploitation.",
				Remediation: "Suppress or genericize version banners in response headers.",
				Evidence:    h + ": " + v, CWE: "CWE-200",
			})
		}
	}
	return issues
}

// CookieSameSite flags cookies without a SameSite attribute.
type CookieSameSite struct{}

func (CookieSameSite) ID() string { return "cookie-samesite" }

func (CookieSameSite) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	for _, c := range tx.Response.Header.Values("Set-Cookie") {
		if !strings.Contains(strings.ToLower(c), "samesite") {
			return []*scan.Issue{{
				Check: "cookie-samesite", Name: "Cookie without SameSite attribute",
				URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
				Detail:      "A Set-Cookie lacks the SameSite attribute, weakening CSRF defenses for cross-site requests.",
				Remediation: "Set SameSite=Lax or Strict on cookies that are not needed cross-site.",
				Evidence:    cookieName(c), CWE: "CWE-1275",
			}}
		}
	}
	return nil
}

// SourceMapDisclosure flags exposed JavaScript source maps.
type SourceMapDisclosure struct{}

func (SourceMapDisclosure) ID() string { return "source-map-disclosure" }

var sourceMap = regexp.MustCompile(`(?i)//# sourceMappingURL=|"version":\s*3,\s*"sources"`)

func (SourceMapDisclosure) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	ct := tx.Response.ContentType()
	if !strings.Contains(ct, "javascript") && !strings.Contains(ct, "json") {
		return nil
	}
	if sourceMap.MatchString(tx.Response.BodyString()) {
		return []*scan.Issue{{
			Check: "source-map-disclosure", Name: "JavaScript source map exposed",
			URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
			Detail:      "A source map reference or source map was served, exposing original (pre-minified) source code and structure.",
			Remediation: "Do not deploy .map files to production, or restrict access to them.",
			Evidence:    "sourceMappingURL / source map present", CWE: "CWE-540",
		}}
	}
	return nil
}

// SensitiveComment flags HTML comments containing risky keywords.
type SensitiveComment struct{}

func (SensitiveComment) ID() string { return "sensitive-comment" }

var htmlComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
var sensitiveWord = regexp.MustCompile(`(?i)\b(password|passwd|secret|api[_-]?key|todo|fixme|hack|backdoor|debug|username|internal only|do not ship)\b`)

func (SensitiveComment) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil || !strings.Contains(tx.Response.ContentType(), "html") {
		return nil
	}
	for _, m := range htmlComment.FindAllStringSubmatch(tx.Response.BodyString(), -1) {
		if w := sensitiveWord.FindString(m[1]); w != "" {
			return []*scan.Issue{{
				Check: "sensitive-comment", Name: "Sensitive information in HTML comment",
				URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityInfo, Confidence: scan.ConfidenceTentative,
				Detail:      "An HTML comment contains a potentially sensitive keyword (" + w + "), which may leak implementation details or credentials.",
				Remediation: "Strip developer comments from production responses.",
				Evidence:    strings.TrimSpace(trimLen(m[1], 120)), CWE: "CWE-615",
			}}
		}
	}
	return nil
}

// CreditCardDisclosure flags Luhn-valid card numbers in responses.
type CreditCardDisclosure struct{}

func (CreditCardDisclosure) ID() string { return "pii-credit-card" }

var cardLike = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)

func (CreditCardDisclosure) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	for _, m := range cardLike.FindAllString(tx.Response.BodyString(), 50) {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, m)
		if len(digits) >= 13 && len(digits) <= 19 && luhn(digits) {
			return []*scan.Issue{{
				Check: "pii-credit-card", Name: "Possible payment card number disclosure",
				URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityMedium, Confidence: scan.ConfidenceTentative,
				Detail:      "The response contains a Luhn-valid number that matches a payment card format, which may be sensitive cardholder data.",
				Remediation: "Mask or remove PANs from responses; comply with PCI DSS storage/display rules.",
				Evidence:    maskCard(digits), CWE: "CWE-359",
			}}
		}
	}
	return nil
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n, _ := strconv.Atoi(string(d[i]))
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func maskCard(d string) string {
	if len(d) < 4 {
		return "****"
	}
	return strings.Repeat("*", len(d)-4) + d[len(d)-4:]
}

// InsecureFormTarget flags login/forms submitting over plaintext HTTP.
type InsecureFormTarget struct{}

func (InsecureFormTarget) ID() string { return "insecure-form" }

var formAction = regexp.MustCompile(`(?is)<form\b[^>]*\baction\s*=\s*["'](http://[^"']+)["'][^>]*>`)

func (InsecureFormTarget) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil || !strings.Contains(tx.Response.ContentType(), "html") {
		return nil
	}
	body := tx.Response.BodyString()
	if m := formAction.FindStringSubmatch(body); m != nil {
		return []*scan.Issue{{
			Check: "insecure-form", Name: "Form submits over plaintext HTTP",
			URL: tx.Request.AbsoluteURL().String(), Severity: scan.SeverityMedium, Confidence: scan.ConfidenceFirm,
			Detail:      "A form posts to an http:// URL, so submitted data (possibly credentials) is sent unencrypted.",
			Remediation: "Submit all forms over HTTPS.",
			Evidence:    m[1], CWE: "CWE-319",
		}}
	}
	return nil
}

func trimLen(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
