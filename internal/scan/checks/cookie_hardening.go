package checks

import (
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// CookieHardening flags insecure cookie attributes and cookie-name-prefix
// violations on Set-Cookie headers. Every signal is read directly from the
// header, so there are no false positives.
type CookieHardening struct{}

func (CookieHardening) ID() string { return "cookie-security" }

func (CookieHardening) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	cookies := tx.Response.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return nil
	}
	url := tx.Request.AbsoluteURL().String()
	https := strings.EqualFold(tx.Request.Scheme, "https")
	var issues []*scan.Issue
	add := func(name, detail, rem string, sev scan.Severity) {
		issues = append(issues, &scan.Issue{
			Check: "cookie-security", Name: "Insecure cookie: " + name, URL: url, Param: name,
			Severity: sev, Confidence: scan.ConfidenceFirm, Detail: detail, Remediation: rem, CWE: "CWE-614",
		})
	}

	for _, sc := range cookies {
		name, attrs, pathVal := parseSetCookie(sc)
		if name == "" {
			continue
		}
		lname := strings.ToLower(name)
		secure := attrs["secure"]
		httpOnly := attrs["httponly"]
		sessionish := strings.Contains(lname, "sess") || strings.Contains(lname, "sid") ||
			strings.Contains(lname, "token") || strings.Contains(lname, "auth") || strings.Contains(lname, "jwt")

		if https && !secure {
			add(name, "Cookie "+name+" is set over HTTPS without the Secure attribute, so it can be sent over plain HTTP and intercepted.",
				"Add the Secure attribute to all cookies.", scan.SeverityLow)
		}
		if sessionish && !httpOnly {
			add(name, "Session-like cookie "+name+" lacks HttpOnly, so client-side script (e.g. via XSS) can read it.",
				"Add HttpOnly to session cookies.", scan.SeverityLow)
		}
		// Cookie name prefixes have browser-enforced rules; a violation means the
		// cookie is silently rejected (broken) and signals a misconfiguration.
		if strings.HasPrefix(name, "__Host-") {
			if !secure || attrs["domain"] || pathVal != "/" {
				add(name, "Cookie "+name+" uses the __Host- prefix but violates its rules (must be Secure, have no Domain, and Path=/). Browsers reject it, so it does not provide the protection intended.",
					"Make __Host- cookies Secure, omit Domain, and set Path=/.", scan.SeverityMedium)
			}
		} else if strings.HasPrefix(name, "__Secure-") && !secure {
			add(name, "Cookie "+name+" uses the __Secure- prefix but is not marked Secure, so browsers reject it.",
				"Mark __Secure- cookies as Secure.", scan.SeverityMedium)
		}
	}
	return issues
}

// parseSetCookie returns the cookie name, the set of attribute names present
// (lowercased), and the Path value.
func parseSetCookie(sc string) (name string, attrs map[string]bool, pathVal string) {
	parts := strings.Split(sc, ";")
	if len(parts) == 0 {
		return "", nil, ""
	}
	name, _, _ = strings.Cut(strings.TrimSpace(parts[0]), "=")
	name = strings.TrimSpace(name)
	attrs = map[string]bool{}
	for _, p := range parts[1:] {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		lk := strings.ToLower(strings.TrimSpace(k))
		attrs[lk] = true
		if lk == "path" {
			pathVal = strings.TrimSpace(v)
		}
	}
	return name, attrs, pathVal
}

// WeakHSTS flags a present-but-weak Strict-Transport-Security policy (a missing
// one is covered by security-headers).
type WeakHSTS struct{}

func (WeakHSTS) ID() string { return "hsts-weak" }

func (WeakHSTS) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil || !strings.EqualFold(tx.Request.Scheme, "https") {
		return nil
	}
	sts := tx.Response.Header.Get("Strict-Transport-Security")
	if sts == "" {
		return nil // "missing HSTS" is already reported elsewhere
	}
	low := strings.ToLower(sts)
	var problems []string
	if maxAge := hstsMaxAge(low); maxAge >= 0 && maxAge < 15552000 {
		problems = append(problems, "max-age is below 180 days")
	}
	if !strings.Contains(low, "includesubdomains") {
		problems = append(problems, "includeSubDomains is missing (subdomains are not protected)")
	}
	if len(problems) == 0 {
		return nil
	}
	return []*scan.Issue{{
		Check: "hsts-weak", Name: "Weak HSTS policy", URL: tx.Request.AbsoluteURL().String(),
		Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
		Detail:      "Strict-Transport-Security is set but weak: " + strings.Join(problems, "; ") + ".",
		Remediation: "Use Strict-Transport-Security: max-age=31536000; includeSubDomains (and preload once verified).",
		Evidence:    sts, CWE: "CWE-523",
	}}
}

// hstsMaxAge extracts the max-age seconds from an HSTS header, or -1 if absent.
func hstsMaxAge(low string) int {
	i := strings.Index(low, "max-age=")
	if i < 0 {
		return -1
	}
	rest := low[i+len("max-age="):]
	n := 0
	found := false
	for _, r := range rest {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
		found = true
	}
	if !found {
		return -1
	}
	return n
}
