package checks

import (
	"context"
	"fmt"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// CRLFInjection detects HTTP response header injection: if a CR/LF encoded
// payload in a parameter causes an attacker-named header to appear in the
// response, the value is written unsanitized into the response headers.
type CRLFInjection struct{}

func (CRLFInjection) ID() string { return "crlf-injection" }

func (CRLFInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	marker := randMarker("Lanternfish-Crlf-")
	payloads := []string{
		fmt.Sprintf("%%0d%%0a%s: 1", marker),
		fmt.Sprintf("%%0a%s: 1", marker),
		fmt.Sprintf("\r\n%s: 1", marker),
	}
	for _, pl := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := s.Send(ctx, p.Mutate(pl))
		if err != nil || resp == nil {
			continue
		}
		if resp.Header.Get(marker) != "" {
			return []*scan.Issue{{
				Check: "crlf-injection", Name: "HTTP response header injection (CRLF)",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityMedium, Confidence: scan.ConfidenceCertain,
				Detail:      fmt.Sprintf("Parameter %q allowed injection of a CRLF sequence that added the response header %q, indicating unsanitized output into response headers (enables header/cookie injection and cache poisoning).", p.Name, marker),
				Remediation: "Strip or reject CR and LF characters in values that reach response headers or redirects.",
				Evidence:    marker + ": " + resp.Header.Get(marker),
				CWE:         "CWE-113",
			}}
		}
	}
	return nil
}
