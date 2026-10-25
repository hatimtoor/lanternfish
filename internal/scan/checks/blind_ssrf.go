package checks

import (
	"context"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// BlindSSRF detects server-side request forgery out of band: it injects an
// OAST callback URL into a parameter and reports if the target calls back.
// It only runs when an out-of-band interactor is available in the context.
type BlindSSRF struct{}

func (BlindSSRF) ID() string { return "blind-ssrf" }

// ProbeOOB injects an out-of-band callback URL and returns a watch for the
// engine to poll once after the audit pass.
func (BlindSSRF) ProbeOOB(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []scan.OOBWatch {
	interactor, ok := scan.InteractorFrom(ctx)
	if !ok {
		return nil
	}
	// Only probe parameters that plausibly take a URL/host, to limit noise.
	if !looksURLish(p.Name, p.Base) {
		return nil
	}
	token, callback := interactor.NewPayload()

	// Try the full URL and a scheme-less host form.
	for _, payload := range []string{callback, strings.TrimPrefix(callback, "http://")} {
		if ctx.Err() != nil {
			return nil
		}
		if _, err := s.Send(ctx, p.Mutate(payload)); err != nil {
			continue
		}
	}
	return []scan.OOBWatch{{
		Tokens: []string{token},
		Issue: &scan.Issue{
			Check: "blind-ssrf", Name: "Blind server-side request forgery (out-of-band)",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceCertain,
			Detail:      "Injecting an out-of-band callback URL into parameter " + p.Name + " caused the server to make a request to the Lanternfish OAST listener, confirming server-side request forgery.",
			Remediation: "Validate and allow-list outbound request targets. Reject user-supplied URLs/hosts, and block requests to internal ranges and metadata endpoints.",
			CWE:         "CWE-918",
		},
	}}
}

func (c BlindSSRF) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	return waitOOB(ctx, c.ProbeOOB(ctx, s, base, p))
}

func looksURLish(name, value string) bool {
	n := strings.ToLower(name)
	for _, k := range []string{"url", "uri", "link", "src", "dest", "redirect", "next", "target", "host", "domain", "site", "page", "feed", "callback", "webhook", "proxy", "fetch", "load", "file", "path", "ref", "return", "continue", "image", "img"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	v := strings.ToLower(value)
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.Contains(v, "://")
}
