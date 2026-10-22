package checks

import (
	"context"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// DangerousMethods is a request-level check that asks the server which methods
// it allows (via OPTIONS) and flags risky ones (PUT, DELETE, TRACE, CONNECT).
type DangerousMethods struct{}

func (DangerousMethods) ID() string { return "dangerous-http-methods" }

func (DangerousMethods) Request(ctx context.Context, s scan.Sender, base *httpmsg.Request) []*scan.Issue {
	probe := base.Clone()
	probe.Method = "OPTIONS"
	probe.Body = nil
	resp, err := s.Send(ctx, probe)
	if err != nil || resp == nil {
		return nil
	}
	allow := resp.Header.Get("Allow")
	if allow == "" {
		return nil
	}
	var risky []string
	for _, m := range []string{"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"} {
		if strings.Contains(strings.ToUpper(allow), m) {
			risky = append(risky, m)
		}
	}
	if len(risky) == 0 {
		return nil
	}
	sev := scan.SeverityLow
	for _, m := range risky {
		if m == "PUT" || m == "DELETE" || m == "TRACE" {
			sev = scan.SeverityMedium
		}
	}
	return []*scan.Issue{{
		Check: "dangerous-http-methods", Name: "Dangerous HTTP methods enabled",
		URL:      base.AbsoluteURL().String(),
		Severity: sev, Confidence: scan.ConfidenceFirm,
		Detail:      "The server advertises potentially dangerous HTTP methods: " + strings.Join(risky, ", ") + ". TRACE enables cross-site tracing; PUT/DELETE may allow unauthorized content changes.",
		Remediation: "Disable unused methods; restrict PUT/DELETE and disable TRACE at the web server.",
		Evidence:    "Allow: " + allow, CWE: "CWE-650",
	}}
}
