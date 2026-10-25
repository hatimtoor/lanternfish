package checks

import (
	"context"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
	"lanternfish/internal/smuggle"
)

// RequestSmuggling detects HTTP/1.1 request-smuggling (desync) via raw-socket
// timing probes (CL.TE, TE.CL, and Transfer-Encoding obfuscation variants).
//
// It is INTRUSIVE and therefore opt-in: it sends deliberately malformed
// requests and ties up a back-end connection, so Lanternfish only registers it
// when the operator passes --intrusive. Detection is timing-only — it stalls
// the connection Lanternfish opened and never appends a request that would be
// served to another user — which keeps even this intrusive check from harming
// the target or other clients.
type RequestSmuggling struct {
	Insecure bool
}

func (RequestSmuggling) ID() string { return "request-smuggling" }

func (c RequestSmuggling) Request(ctx context.Context, _ scan.Sender, base *httpmsg.Request) []*scan.Issue {
	u := base.AbsoluteURL()
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	findings, err := smuggle.Detect(ctx, u, smuggle.Options{ReadTimeout: 10 * time.Second, Insecure: c.Insecure})
	if err != nil {
		return nil
	}
	var issues []*scan.Issue
	for _, f := range findings {
		issues = append(issues, &scan.Issue{
			Check: "request-smuggling", Name: "HTTP request smuggling (" + f.Kind + ")",
			URL: u.String(), Param: f.Kind + "/" + f.Variant,
			Severity: scan.SeverityCritical, Confidence: scan.ConfidenceFirm,
			Detail: "A " + f.Kind + " desync was detected: with the Transfer-Encoding obfuscation \"" + f.Variant +
				"\", a probe hung (" + msStr(f.ProbeMs) + " vs a " + msStr(f.BaselineMs) + " baseline), meaning the front-end and back-end disagree on where the request body ends. An attacker can smuggle a request prefix to poison other users' responses, bypass front-end controls, or hijack sessions.",
			Remediation: "Make the front-end and back-end agree on request parsing: reject ambiguous requests carrying both Content-Length and Transfer-Encoding, normalise/forbid obfuscated Transfer-Encoding, and prefer HTTP/2 end-to-end.",
			Evidence:    f.String(),
			CWE:         "CWE-444",
		})
	}
	return issues
}

func msStr(ms int64) string {
	return time.Duration(ms * int64(time.Millisecond)).String()
}
