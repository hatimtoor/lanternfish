package checks

import (
	"context"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// CORSMisconfig is a request-level check: it sends a crafted Origin and sees
// whether the response reflects that arbitrary origin in
// Access-Control-Allow-Origin, especially with credentials allowed — a common
// CORS misconfiguration. Public technique.
type CORSMisconfig struct{}

func (CORSMisconfig) ID() string { return "cors-misconfig" }

const evilOrigin = "https://lanternfish-evil.example"

// corsOrigin sends one Origin header and reports whether the response reflected
// that exact origin in ACAO and whether credentials are allowed.
func corsOrigin(ctx context.Context, s scan.Sender, base *httpmsg.Request, origin string) (acao string, reflected, creds bool) {
	probe := base.Clone()
	probe.Header.Set("Origin", origin)
	resp, err := s.Send(ctx, probe)
	if err != nil || resp == nil {
		return "", false, false
	}
	acao = resp.Header.Get("Access-Control-Allow-Origin")
	creds = strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	return acao, acao == origin, creds
}

func (CORSMisconfig) Request(ctx context.Context, s scan.Sender, base *httpmsg.Request) []*scan.Issue {
	acaoFor := base.AbsoluteURL().String()
	host := base.AbsoluteURL().Hostname()

	// 1) Bypasses that defeat a naive origin check, derived from the real host.
	//    If the server reflects one of these attacker-controllable origins, its
	//    allow-list logic is broken in a specific, exploitable way.
	if host != "" {
		bypasses := []struct{ origin, how string }{
			{"https://lanternfish-evil." + host, "a subdomain of the target (exploitable via any subdomain XSS or takeover)"},
			{"https://" + host + ".lanternfish-evil.example", "a prefix match (the check accepts any origin that starts with the trusted host)"},
			{"https://lanternfish-evil-" + host, "a suffix match (the check accepts any origin that ends with the trusted host)"},
		}
		for _, b := range bypasses {
			acao, reflected, creds := corsOrigin(ctx, s, base, b.origin)
			if reflected {
				sev := scan.SeverityMedium
				note := ""
				if creds {
					sev = scan.SeverityHigh
					note = " with Access-Control-Allow-Credentials: true, so a malicious site can read authenticated responses"
				}
				return []*scan.Issue{{
					Check: "cors-misconfig", Name: "CORS: origin allow-list bypass",
					URL:      acaoFor,
					Severity: sev, Confidence: scan.ConfidenceFirm,
					Detail:      "The response reflected the origin " + b.origin + " in Access-Control-Allow-Origin" + note + ". This indicates " + b.how + ".",
					Remediation: "Match the Origin against an exact allow-list (full-string equality), not a prefix/suffix/substring, and never trust arbitrary subdomains for credentialed endpoints.",
					Evidence:    "Origin: " + b.origin + " -> Access-Control-Allow-Origin: " + acao,
					CWE:         "CWE-942",
				}}
			}
		}
	}

	// 2) The "null" origin (reachable from a sandboxed iframe / data: document).
	if acao, reflected, creds := corsOrigin(ctx, s, base, "null"); reflected || strings.EqualFold(acao, "null") {
		sev := scan.SeverityMedium
		note := ""
		if creds {
			sev = scan.SeverityHigh
			note = " and allows credentials"
		}
		return []*scan.Issue{{
			Check: "cors-misconfig", Name: "CORS: null origin allowed",
			URL:      acaoFor,
			Severity: sev, Confidence: scan.ConfidenceFirm,
			Detail:      "The response allows the \"null\" origin in Access-Control-Allow-Origin" + note + ". An attacker can obtain a null origin from a sandboxed iframe or data: document and make cross-origin reads.",
			Remediation: "Never allow the null origin. Validate Origin against an exact allow-list.",
			Evidence:    "Origin: null -> Access-Control-Allow-Origin: " + acao,
			CWE:         "CWE-942",
		}}
	}

	// 3) Arbitrary reflected origin / wildcard (the original checks).
	acao, reflects, creds := corsOrigin(ctx, s, base, evilOrigin)
	if acao == "" {
		return nil
	}
	wildcard := acao == "*"

	if reflects && creds {
		return []*scan.Issue{{
			Check: "cors-misconfig", Name: "CORS: arbitrary origin reflected with credentials",
			URL:      base.AbsoluteURL().String(),
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "The response reflects an attacker-supplied Origin in Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true, allowing a malicious site to read authenticated responses.",
			Remediation: "Validate Origin against an allow-list. Never reflect arbitrary origins while allowing credentials, and never combine credentials with a wildcard.",
			Evidence:    "Access-Control-Allow-Origin: " + acao + " / Allow-Credentials: true",
			CWE:         "CWE-942",
		}}
	}
	if reflects {
		return []*scan.Issue{{
			Check: "cors-misconfig", Name: "CORS: arbitrary origin reflected",
			URL:      base.AbsoluteURL().String(),
			Severity: scan.SeverityMedium, Confidence: scan.ConfidenceFirm,
			Detail:      "The response reflects an attacker-supplied Origin in Access-Control-Allow-Origin, relaxing the same-origin policy for any site.",
			Remediation: "Validate Origin against an allow-list instead of reflecting it.",
			Evidence:    "Access-Control-Allow-Origin: " + acao,
			CWE:         "CWE-942",
		}}
	}
	if wildcard && creds {
		return []*scan.Issue{{
			Check: "cors-misconfig", Name: "CORS: wildcard origin with credentials",
			URL:      base.AbsoluteURL().String(),
			Severity: scan.SeverityMedium, Confidence: scan.ConfidenceTentative,
			Detail:      "Access-Control-Allow-Origin is * together with credentials handling; browsers block this combination but it signals a misconfigured CORS policy.",
			Remediation: "Do not use a wildcard ACAO for credentialed endpoints; use an explicit allow-list.",
			Evidence:    "Access-Control-Allow-Origin: *",
			CWE:         "CWE-942",
		}}
	}
	return nil
}
