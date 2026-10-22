package checks

import (
	"context"
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
	regexp.MustCompile(`(?i)LDAPException`),
	regexp.MustCompile(`(?i)com\.sun\.jndi\.ldap`),
	regexp.MustCompile(`(?i)Invalid DN syntax`),
	regexp.MustCompile(`(?i)LDAP: error code \d+`),
	regexp.MustCompile(`(?i)Bad search filter`),
}

func (LDAPInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	if sig := matchAny(ctx, s, p, []string{`*)(&`, `*))(|`, `)(cn=*`}, ldapErrors); sig != "" {
		return []*scan.Issue{{
			Check: "ldap-injection", Name: "LDAP injection",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "Injecting LDAP filter metacharacters into parameter " + p.Name + " produced an LDAP error, indicating the value reaches an LDAP query unsafely.",
			Remediation: "Escape LDAP special characters per RFC 4515, or use parameterized directory APIs.",
			Evidence:    sig, CWE: "CWE-90",
		}}
	}
	return nil
}

// XPathInjection detects error-based XPath injection.
type XPathInjection struct{}

func (XPathInjection) ID() string { return "xpath-injection" }

var xpathErrors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)XPathException`),
	regexp.MustCompile(`(?i)MS\.Internal\.Xml`),
	regexp.MustCompile(`(?i)Unknown error in XPath`),
	regexp.MustCompile(`(?i)org\.apache\.xpath`),
	regexp.MustCompile(`(?i)A closing bracket expected in`),
	regexp.MustCompile(`(?i)Expression must evaluate to a node-set`),
	regexp.MustCompile(`(?i)xmlXPathEval`),
}

func (XPathInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	if sig := matchAny(ctx, s, p, []string{`'`, `"`, `1'"`}, xpathErrors); sig != "" {
		return []*scan.Issue{{
			Check: "xpath-injection", Name: "XPath injection",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "Injecting XPath metacharacters into parameter " + p.Name + " produced an XPath error, indicating the value reaches an XPath query unsafely.",
			Remediation: "Use parameterized XPath (variable binding) and validate input; never concatenate input into XPath.",
			Evidence:    sig, CWE: "CWE-643",
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
