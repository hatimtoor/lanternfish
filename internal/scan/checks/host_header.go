package checks

import (
	"context"
	"fmt"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// HostHeaderInjection is a request-level check: it sends a poisoned Host and
// X-Forwarded-Host and reports if the attacker-controlled host is reflected in
// the response body or a redirect Location (password-reset poisoning, cache
// poisoning). Public technique.
type HostHeaderInjection struct{}

func (HostHeaderInjection) ID() string { return "host-header-injection" }

func (HostHeaderInjection) Request(ctx context.Context, s scan.Sender, base *httpmsg.Request) []*scan.Issue {
	evil := randMarker("lanternfish-evil-") + ".example"

	// Try X-Forwarded-Host first (doesn't break routing), then a poisoned Host.
	for _, variant := range []struct{ header, value string }{
		{"X-Forwarded-Host", evil},
		{"Host", evil},
	} {
		if ctx.Err() != nil {
			return nil
		}
		probe := base.Clone()
		if variant.header == "Host" {
			probe.Host = evil
		} else {
			probe.Header.Set(variant.header, evil)
		}
		resp, err := s.Send(ctx, probe)
		if err != nil || resp == nil {
			continue
		}
		loc := resp.Header.Get("Location")
		inLoc := strings.Contains(loc, evil)
		inBody := strings.Contains(resp.BodyString(), evil)
		if inLoc || inBody {
			where := "response body"
			ev := excerpt(resp.BodyString(), evil)
			if inLoc {
				where = "redirect Location"
				ev = "Location: " + loc
			}
			return []*scan.Issue{{
				Check: "host-header-injection", Name: "Host header injection",
				URL:      base.AbsoluteURL().String(),
				Severity: scan.SeverityMedium, Confidence: scan.ConfidenceFirm,
				Detail: fmt.Sprintf("An attacker-controlled %s value was reflected in the %s, which enables password-reset poisoning and web cache poisoning.",
					variant.header, where),
				Remediation: "Do not build absolute URLs or trust the Host/X-Forwarded-Host from the request; use a configured canonical host and validate against an allow-list.",
				Evidence:    ev, CWE: "CWE-644",
			}}
		}
	}
	return nil
}
