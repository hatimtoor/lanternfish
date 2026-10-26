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
	// TRACE and CONNECT are dangerous regardless of app type (cross-site tracing,
	// proxy abuse). PUT/DELETE/PATCH are ordinary REST methods — merely
	// advertising them is informational, not a vulnerability, so they do not
	// raise the severity (this keeps API scans from flagging the API itself).
	sev := scan.SeverityInfo
	for _, m := range risky {
		if m == "TRACE" || m == "CONNECT" {
			sev = scan.SeverityMedium
		}
	}
	detail := "The server advertises these HTTP methods via OPTIONS: " + strings.Join(risky, ", ") + "."
	if sev == scan.SeverityMedium {
		detail += " TRACE enables cross-site tracing and CONNECT can be abused as a proxy."
	} else {
		detail += " PUT/DELETE/PATCH are normal for REST APIs but should be confirmed to enforce authorization."
	}
	return []*scan.Issue{{
		Check: "dangerous-http-methods", Name: "Uncommon HTTP methods advertised",
		URL:      base.AbsoluteURL().String(),
		Severity: sev, Confidence: scan.ConfidenceFirm,
		Detail:      detail,
		Remediation: "Disable methods the application does not use; disable TRACE and CONNECT at the web server; ensure PUT/DELETE/PATCH enforce authorization.",
		Evidence:    "Allow: " + allow, CWE: "CWE-650",
	}}
}
