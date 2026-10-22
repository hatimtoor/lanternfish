package checks

import (
	"context"
	"fmt"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// ReflectedXSS probes an insertion point by injecting a unique marker wrapped
// in characters significant to HTML. If the marker is reflected without
// encoding of those characters, the point is likely XSS-injectable. This is a
// standard reflection technique documented publicly (OWASP).
type ReflectedXSS struct{}

func (ReflectedXSS) ID() string { return "reflected-xss" }

func (ReflectedXSS) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	marker := randMarker("axs")
	// Breakout characters that must survive unencoded for injection to work.
	payload := fmt.Sprintf("'\"><%s>", marker)

	req := p.Mutate(payload)
	resp, err := s.Send(ctx, req)
	if err != nil || resp == nil {
		return nil
	}
	if !strings.Contains(resp.ContentType(), "html") {
		return nil
	}
	body := resp.BodyString()

	// The signature we injected, reflected verbatim, indicates the angle
	// brackets and quotes were not encoded.
	needle := fmt.Sprintf("<%s>", marker)
	if !strings.Contains(body, needle) {
		return nil
	}

	conf := scan.ConfidenceFirm
	// If the full breakout (including quotes) is present, confidence is higher.
	if strings.Contains(body, payload) {
		conf = scan.ConfidenceCertain
	}
	sev := scan.SeverityHigh
	detail := fmt.Sprintf("Input in parameter %q is reflected into an HTML response without encoding the characters < > \" '. Injected marker %q was returned verbatim.", p.Name, needle)
	// Reflection-context awareness: if the marker only lands inside an HTML
	// comment, it is far less likely to be exploitable, so downgrade rather than
	// report it as a confident high-severity finding.
	if rc := classifyReflection(body, needle); rc.found && rc.inComment {
		conf = scan.ConfidenceTentative
		sev = scan.SeverityLow
		detail += " The reflection appears only inside an HTML comment, which limits exploitability unless the comment can be broken out of."
	}

	return []*scan.Issue{{
		Check: "reflected-xss", Name: "Reflected cross-site scripting",
		URL: base.AbsoluteURL().String(), Param: p.Name,
		Severity: sev, Confidence: conf,
		Detail:      detail,
		Remediation: "Contextually encode output and validate input. Prefer a templating layer that auto-escapes HTML.",
		Evidence:    excerpt(body, needle),
		CWE:         "CWE-79",
	}}
}

// excerpt returns a short window of text around the first occurrence of needle.
func excerpt(body, needle string) string {
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	end := i + len(needle) + 40
	if end > len(body) {
		end = len(body)
	}
	return "..." + body[start:end] + "..."
}
