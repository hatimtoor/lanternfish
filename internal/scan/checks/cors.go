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

func (CORSMisconfig) Request(ctx context.Context, s scan.Sender, base *httpmsg.Request) []*scan.Issue {
	probe := base.Clone()
	probe.Header.Set("Origin", evilOrigin)
	resp, err := s.Send(ctx, probe)
	if err != nil || resp == nil {
		return nil
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return nil
	}
	reflects := acao == evilOrigin
	wildcard := acao == "*"
	creds := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")

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
