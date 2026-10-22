package checks

import (
	"context"
	"net/url"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// OpenRedirect injects an external URL into a parameter and checks whether the
// application issues a redirect (Location header) to that external origin.
type OpenRedirect struct{}

func (OpenRedirect) ID() string { return "open-redirect" }

const canaryHost = "lanternfish-redirect.example"

func (OpenRedirect) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	// Only parameters whose value looks URL-ish or path-ish are worth probing,
	// but we try all to keep it simple; the response check is specific.
	payloads := []string{
		"https://" + canaryHost + "/",
		"//" + canaryHost + "/",
		"https:/" + canaryHost + "/",
	}
	for _, pl := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := s.Send(ctx, p.Mutate(pl))
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			continue
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			continue
		}
		if redirectsToCanary(loc) {
			return []*scan.Issue{{
				Check: "open-redirect", Name: "Open redirect",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityMedium, Confidence: scan.ConfidenceFirm,
				Detail:      "Parameter " + p.Name + " controls the Location header; a crafted value redirected to an attacker-controlled external host (" + canaryHost + ").",
				Remediation: "Do not build redirect targets from user input. Use an allow-list of permitted destinations or server-side mapping keys.",
				Evidence:    "Location: " + loc,
				CWE:         "CWE-601",
			}}
		}
	}
	return nil
}

func redirectsToCanary(loc string) bool {
	if strings.Contains(loc, canaryHost) {
		// Confirm the canary is the host, not just a path fragment.
		if u, err := url.Parse(loc); err == nil {
			return strings.EqualFold(u.Hostname(), canaryHost)
		}
		// Protocol-relative //host/ form.
		return strings.HasPrefix(loc, "//"+canaryHost) || strings.HasPrefix(loc, "/\\"+canaryHost)
	}
	return false
}
