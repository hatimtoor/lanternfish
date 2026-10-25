package checks

import (
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// CSPWeakness is a passive analyzer for a *present* Content-Security-Policy that
// is too permissive to actually stop XSS. A missing CSP is already flagged by
// the security-headers check; this one reads the policy that exists and points
// out the directives that defeat its purpose, so a learner sees not just "add a
// CSP" but "this CSP looks strict but 'unsafe-inline' means an injected
// <script> still runs." All signals are factual (the token is literally in the
// policy), so there are no false positives. Guidance follows Google's CSP
// Evaluator and the OWASP CSP Cheat Sheet.
type CSPWeakness struct{}

func (CSPWeakness) ID() string { return "csp-weakness" }

func (CSPWeakness) Passive(tx *httpmsg.Transaction) []*scan.Issue {
	if tx.Response == nil {
		return nil
	}
	raw := tx.Response.Header.Get("Content-Security-Policy")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	url := tx.Request.AbsoluteURL().String()
	dirs := parseCSP(raw)

	// The directive that governs script execution: script-src, else default-src.
	scriptSrc, hasScript := dirs["script-src"]
	if !hasScript {
		scriptSrc, hasScript = dirs["default-src"]
	}

	var issues []*scan.Issue
	add := func(name, detail, rem string, sev scan.Severity) {
		issues = append(issues, &scan.Issue{
			Check: "csp-weakness", Name: name, URL: url,
			Severity: sev, Confidence: scan.ConfidenceFirm,
			Detail: detail, Remediation: rem, Evidence: raw, CWE: "CWE-1021",
		})
	}

	if hasScript {
		set := tokenSet(scriptSrc)
		if set["'unsafe-inline'"] {
			add("CSP allows 'unsafe-inline' scripts",
				"The effective script-src includes 'unsafe-inline', so an attacker who injects a <script> tag or inline event handler still executes — the CSP does not stop reflected or stored XSS.",
				"Remove 'unsafe-inline'; use nonces ('nonce-...') or hashes for the scripts you need, and move inline handlers into external files.",
				scan.SeverityMedium)
		}
		if set["'unsafe-eval'"] {
			add("CSP allows 'unsafe-eval'",
				"The effective script-src includes 'unsafe-eval', permitting eval()/new Function()/setTimeout(string), which enables many DOM-XSS and gadget-based bypasses.",
				"Remove 'unsafe-eval' and refactor code that relies on dynamic evaluation.",
				scan.SeverityLow)
		}
		if set["*"] || set["http:"] || set["https:"] {
			add("CSP script-src is effectively wildcard",
				"The effective script-src allows scripts from any host (* or a bare http:/https: scheme), so an attacker can load executable script from a domain they control.",
				"Restrict script-src to specific trusted origins (or 'self' plus nonces/hashes).",
				scan.SeverityMedium)
		}
		if set["data:"] {
			add("CSP script-src allows data: URIs",
				"The effective script-src allows the data: scheme, letting an attacker smuggle an executable script as an inline data URL.",
				"Remove data: from script-src.",
				scan.SeverityLow)
		}
	}

	if _, ok := dirs["object-src"]; !ok {
		if _, okd := dirs["default-src"]; !okd {
			add("CSP missing object-src",
				"No object-src (and no default-src to fall back on) is set, so <object>/<embed> plugin content is unrestricted — a classic CSP bypass vector.",
				"Add object-src 'none'.",
				scan.SeverityLow)
		}
	}
	if _, ok := dirs["base-uri"]; !ok {
		add("CSP missing base-uri",
			"No base-uri directive is set, so an injected <base> tag can repoint relative script URLs to an attacker's host even under an otherwise strict CSP.",
			"Add base-uri 'none' (or 'self').",
			scan.SeverityLow)
	}

	return issues
}

// parseCSP splits a CSP header into a directive -> source-list map (directive
// names lowercased).
func parseCSP(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, " ")
		out[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(val)
	}
	return out
}

// tokenSet returns the source list as a set (keywords lowercased; host/scheme
// tokens kept as-is but compared case-insensitively for schemes).
func tokenSet(sources string) map[string]bool {
	set := map[string]bool{}
	for _, tok := range strings.Fields(sources) {
		t := strings.TrimSpace(tok)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "'") || t == "*" {
			set[strings.ToLower(t)] = true
		} else {
			set[strings.ToLower(t)] = true
		}
	}
	return set
}
