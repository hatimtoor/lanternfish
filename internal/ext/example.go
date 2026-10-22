package ext

import (
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// SampleExtension is a worked example of a native extension. It shows the three
// things a native extension can do, mirroring a Burp Montoya extension:
//
//  1. edit responses passing through the proxy (here: tag them with a header),
//  2. edit requests (here: add a marker header), and
//  3. contribute a passive scan check (here: flag a debug-mode leak).
//
// Enable it by setting LANTERNFISH_EXT_DEMO=1. Use it as a template for your own.
type SampleExtension struct{}

func (SampleExtension) Name() string { return "sample" }

func (SampleExtension) Register(r *Registry) {
	r.OnRequest(func(req *httpmsg.Request) {
		if req.Header != nil {
			req.Header.Set("X-Lanternfish-Ext", "sample")
		}
	})
	r.OnResponse(func(_ *httpmsg.Request, resp *httpmsg.Response) {
		if resp != nil && resp.Header != nil {
			resp.Header.Set("X-Lanternfish-Scanned", "1")
		}
	})
	r.AddPassiveCheck(debugLeakCheck{})
}

// debugLeakCheck flags a response body that advertises debug mode.
type debugLeakCheck struct{}

func (debugLeakCheck) ID() string { return "ext-sample-debug-leak" }

func (debugLeakCheck) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	body := tx.Response.BodyString()
	if !strings.Contains(body, "DEBUG=true") && !strings.Contains(strings.ToLower(body), "debug mode is on") {
		return nil
	}
	return []*scan.Issue{{
		Check: "ext:sample", Name: "Debug mode enabled (sample extension)",
		URL:      tx.Request.AbsoluteURL().String(),
		Severity: scan.SeverityLow, Confidence: scan.ConfidenceFirm,
		Detail:      "The response indicates the application is running with debug mode enabled, which can leak internal details.",
		Remediation: "Disable debug mode in production.",
		Evidence:    "debug indicator found in response body",
		CWE:         "CWE-489",
	}}
}
