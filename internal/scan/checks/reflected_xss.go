package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

var scriptBlock = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)

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
		// Not HTML, but a JavaScript response can still reflect into a string.
		return (ReflectedXSS{}).jsContext(ctx, s, base, p)
	}
	body := resp.BodyString()

	// The injected tag-start, reflected verbatim, indicates the opening angle
	// bracket was not encoded — the marker immediately follows "<", so this
	// concatenation can only come from our injection. We key on the tag-start
	// rather than the full "<marker>" because some sinks mangle or drop the
	// trailing ">" (or truncate the reflection) while still leaving an
	// injectable "<marker" that an attacker can complete; requiring the closing
	// bracket would miss those real cases.
	open := "<" + marker
	needle := fmt.Sprintf("<%s>", marker)
	if !strings.Contains(body, open) {
		// Tag injection didn't survive; try the JavaScript-string context.
		return (ReflectedXSS{}).jsContext(ctx, s, base, p)
	}

	conf := scan.ConfidenceFirm
	// If the full breakout (including quotes) is present, confidence is higher.
	if strings.Contains(body, payload) || strings.Contains(body, needle) {
		conf = scan.ConfidenceCertain
	}
	sev := scan.SeverityHigh
	detail := fmt.Sprintf("Input in parameter %q is reflected into an HTML response without encoding the character %q. Injected tag-start %q was returned verbatim.", p.Name, "<", open)
	// Reflection-context awareness: if the marker only lands inside an HTML
	// comment, it is far less likely to be exploitable, so downgrade rather than
	// report it as a confident high-severity finding.
	if rc := classifyReflection(body, open); rc.found && rc.inComment {
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
		Evidence:    excerpt(body, open),
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

// jsContext detects reflection inside a JavaScript string where the injected
// string-terminating quote survives unescaped — the classic XSS case the
// tag-based probe above misses when "<" is encoded but quotes are not. It fires
// only when the quote-breaking marker lands inside a <script> block (or a
// JavaScript response body), so a page that escapes or encodes the quote never
// matches: zero false positives.
func (ReflectedXSS) jsContext(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	m := randMarker("ajs")
	// Each payload ends the string with its own quote style and starts a new
	// statement; the needle is the part that only appears if the quote survived.
	for _, q := range []string{"'", "\"", "`"} {
		payload := m + q + ";lf=1//"
		needle := m + q + ";lf=1"
		resp, err := s.Send(ctx, p.Mutate(payload))
		if err != nil || resp == nil {
			continue
		}
		ct := resp.ContentType()
		body := resp.BodyString()
		var inScript bool
		switch {
		case strings.Contains(ct, "javascript"), strings.Contains(ct, "ecmascript"):
			inScript = strings.Contains(body, needle)
		case strings.Contains(ct, "html"):
			inScript = insideScript(body, needle)
		}
		if inScript {
			return []*scan.Issue{{
				Check: "reflected-xss", Name: "Reflected cross-site scripting (JavaScript string context)",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
				Detail:      fmt.Sprintf("Input in parameter %q is reflected inside a <script> block with the string-terminating quote (%s) left unescaped (injected sequence %q returned verbatim). An attacker can break out of the JavaScript string and execute arbitrary script.", p.Name, q, needle),
				Remediation: "Encode data placed into JavaScript contexts (e.g. JSON-encode and HTML-encode), or avoid reflecting input into inline script. Prefer data attributes read by external scripts.",
				Evidence:    excerpt(body, needle),
				CWE:         "CWE-79",
			}}
		}
	}
	return nil
}

// insideScript reports whether needle appears within any <script>...</script>
// block of body.
func insideScript(body, needle string) bool {
	for _, mm := range scriptBlock.FindAllStringSubmatch(body, -1) {
		if strings.Contains(mm[1], needle) {
			return true
		}
	}
	return false
}
