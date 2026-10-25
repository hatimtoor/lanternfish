package checks

import (
	"context"
	"fmt"
	"regexp"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// LDAPInjection detects error-based LDAP injection by injecting characters that
// break an LDAP filter and matching directory error signatures.
type LDAPInjection struct{}

func (LDAPInjection) ID() string { return "ldap-injection" }

var ldapErrors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)javax\.naming\.directory`),
	regexp.MustCompile(`(?i)javax\.naming\.NamingException`),
	regexp.MustCompile(`(?i)InvalidSearchFilterException`),
	regexp.MustCompile(`(?i)LDAPException`),
	regexp.MustCompile(`(?i)com\.sun\.jndi\.ldap`),
	regexp.MustCompile(`(?i)org\.apache\.directory`),
	regexp.MustCompile(`(?i)Invalid DN syntax`),
	regexp.MustCompile(`(?i)LDAP: error code \d+`),
	regexp.MustCompile(`(?i)Bad search filter`),
	regexp.MustCompile(`(?i)ERR_\d+ .*filter`),
}

func (LDAPInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	if sig := matchAny(ctx, s, p, []string{`*)(&`, `*))(|`, `)(cn=*`, `*)(uid=*`}, ldapErrors); sig != "" {
		return []*scan.Issue{{
			Check: "ldap-injection", Name: "LDAP injection",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "Injecting LDAP filter metacharacters into " + vectorLabel(p) + " produced an LDAP error, indicating the value reaches an LDAP query unsafely.",
			Remediation: "Escape LDAP special characters per RFC 4515, or use parameterized directory APIs.",
			Evidence:    sig, CWE: "CWE-90",
		}}
	}
	// Boolean/differential fallback: a wildcard that matches every entry returns
	// a different result set (and response size) than a value that matches none.
	if ev, ok := boolDiffInjection(ctx, s, p, "*", "ZZnomatchZZ837"); ok {
		return []*scan.Issue{{
			Check: "ldap-injection", Name: "LDAP injection (boolean)",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "A wildcard injected into " + vectorLabel(p) + " changed the result set returned by the backend directory: " + ev + ". This indicates the value is placed into an LDAP filter without escaping.",
			Remediation: "Escape LDAP special characters per RFC 4515, or use parameterized directory APIs.",
			Evidence:    ev, CWE: "CWE-90",
		}}
	}
	return nil
}

// XPathInjection detects error-based XPath injection.
type XPathInjection struct{}

func (XPathInjection) ID() string { return "xpath-injection" }

var xpathErrors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)XPathException`),
	regexp.MustCompile(`(?i)XPathExpressionException`),
	regexp.MustCompile(`(?i)javax\.xml\.xpath`),
	regexp.MustCompile(`(?i)Error parsing XPath`),
	regexp.MustCompile(`(?i)System\.Xml\.XPath`),
	regexp.MustCompile(`(?i)MS\.Internal\.Xml`),
	regexp.MustCompile(`(?i)Unknown error in XPath`),
	regexp.MustCompile(`(?i)org\.apache\.xpath`),
	regexp.MustCompile(`(?i)net\.sf\.saxon`),
	regexp.MustCompile(`(?i)A closing bracket expected in`),
	regexp.MustCompile(`(?i)Expression must evaluate to a node-set`),
	regexp.MustCompile(`(?i)xmlXPathEval`),
}

func (XPathInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	if sig := matchAny(ctx, s, p, []string{`'`, `"`, `1'"`, `']`}, xpathErrors); sig != "" {
		return []*scan.Issue{{
			Check: "xpath-injection", Name: "XPath injection",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "Injecting XPath metacharacters into " + vectorLabel(p) + " produced an XPath error, indicating the value reaches an XPath query unsafely.",
			Remediation: "Use parameterized XPath (variable binding) and validate input; never concatenate input into XPath.",
			Evidence:    sig, CWE: "CWE-643",
		}}
	}
	// Boolean/differential fallback: a tautology selects the whole node-set while
	// a contradiction selects nothing, so the reflected result differs in size.
	if ev, ok := boolDiffInjection(ctx, s, p, "' or '1'='1", "' and '1'='2"); ok {
		return []*scan.Issue{{
			Check: "xpath-injection", Name: "XPath injection (boolean)",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "A tautology vs. contradiction injected into " + vectorLabel(p) + " changed the reflected XPath result: " + ev + ". This indicates the value is concatenated into an XPath expression.",
			Remediation: "Use parameterized XPath (variable binding) and validate input; never concatenate input into XPath.",
			Evidence:    ev, CWE: "CWE-643",
		}}
	}
	return nil
}

// matchAny sends each payload and returns the first error signature matched
// that was not already present in a benign baseline.
func matchAny(ctx context.Context, s scan.Sender, p scan.InsertionPoint, payloads []string, sigs []*regexp.Regexp) string {
	baseResp, err := s.Send(ctx, p.Mutate(p.Base))
	if err != nil || baseResp == nil {
		return ""
	}
	if firstSig(baseResp.BodyString(), sigs) != "" {
		return "" // already errors on benign input; not attributable
	}
	for _, pl := range payloads {
		if ctx.Err() != nil {
			return ""
		}
		resp, err := s.Send(ctx, p.Mutate(p.Base+pl))
		if err != nil || resp == nil {
			continue
		}
		if sig := firstSig(resp.BodyString(), sigs); sig != "" {
			return sig
		}
	}
	return ""
}

func firstSig(body string, sigs []*regexp.Regexp) string {
	for _, re := range sigs {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// boolDiffInjection appends a "true" and a "false" payload to the base value
// and reports evidence when the two responses differ substantially in size
// while the un-injected page is stable. This catches reflected query injection
// (SQL/XPath/LDAP) whose result set — and therefore response length — the
// injected condition changed, even when no error message is emitted. It is a
// standard, public boolean-based inference technique.
func boolDiffInjection(ctx context.Context, s scan.Sender, p scan.InsertionPoint, truePL, falsePL string) (string, bool) {
	b, ok := stableBaseline(ctx, s, p)
	if !ok || !b.stable {
		return "", false
	}
	tr, err := s.Send(ctx, p.Mutate(p.Base+truePL))
	if err != nil || tr == nil {
		return "", false
	}
	fr, err := s.Send(ctx, p.Mutate(p.Base+falsePL))
	if err != nil || fr == nil {
		return "", false
	}
	// A 5xx means we broke the request rather than steered a query; not a
	// reliable boolean signal.
	if tr.StatusCode >= 500 || fr.StatusCode >= 500 {
		return "", false
	}
	lt, lf := len(tr.Body), len(fr.Body)
	d := lt - lf
	if d < 0 {
		d = -d
	}
	// The true/false difference must clear both a floor and the page's natural
	// jitter (×3), so a lively page's own variation cannot look like injection.
	thresh := 16
	if j := b.jitter * 3; j > thresh {
		thresh = j
	}
	if d >= thresh && !similarLen(lt, lf) {
		return fmt.Sprintf("true-condition response %d bytes vs false-condition %d bytes (page jitter ~%d)", lt, lf, b.jitter), true
	}
	return "", false
}
