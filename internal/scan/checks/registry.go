// Package checks contains Lanternfish's bundled passive and active scan checks.
// Each check implements an independent detection technique drawn from public
// web-security references (OWASP, CWE). Register new checks here.
package checks

import "lanternfish/internal/scan"

// Passive returns the registered passive checks (including the data-driven
// secret-detection and technology-fingerprint databases).
func Passive() []scan.PassiveCheck {
	base := []scan.PassiveCheck{
		SecurityHeaders{},
		CSPWeakness{},
		ExposedSecrets{},
		VerboseError{},
		DirectoryListing{},
		PrivateIPDisclosure{},
		MixedContent{},
		PasswordAutocomplete{},
		SessionTokenInURL{},
		BannerDisclosure{},
		CookieSameSite{},
		SourceMapDisclosure{},
		SensitiveComment{},
		CreditCardDisclosure{},
		InsecureFormTarget{},
		VulnerableJSLibrary{},
		InsecureDeserialization{},
		JWTWeakness{},
		EmailDisclosure{},
		CacheableSensitive{},
		AdditionalHeaders{},
	}
	base = append(base, Secrets()...)
	base = append(base, Fingerprints()...)
	return base
}

// Active returns the registered per-insertion-point active checks (including
// the data-driven per-engine injection database).
func Active() []scan.ActiveCheck {
	base := []scan.ActiveCheck{
		ReflectedXSS{},
		StoredXSS{},
		SQLiError{},
		PathTraversal{},
		PathTraversalOracle{},
		OpenRedirect{},
		SSTI{},
		CRLFInjection{},
		CommandInjection{},
		BlindCommandInjection{},
		BlindSQLiOOB{},
		SSRFMetadata{},
		BlindSSRF{},
		LDAPInjection{},
		XPathInjection{},
		BooleanBlindSQLi{},
		TimeBlindSQLi{},
		LFI{},
		CommandInjectionInband{},
		NoSQLInjection{},
	}
	base = append(base, InjectionDB()...)
	return base
}

// slowActiveIDs are active checks that add fixed per-insertion-point waits
// (out-of-band callbacks or time-based inference). Fast mode skips them.
var slowActiveIDs = map[string]bool{
	"blind-ssrf":            true,
	"command-injection":     true, // time-based
	"command-injection-oob": true, // out-of-band callback wait
	"sqli-oob":              true, // out-of-band callback wait
	"sqli-time-blind":       true,
	"path-traversal-oracle": true, // many extra differential requests per point
}

// ActiveFast returns the active checks minus the slow (wait-heavy) ones.
func ActiveFast() []scan.ActiveCheck {
	all := Active()
	out := make([]scan.ActiveCheck, 0, len(all))
	for _, c := range all {
		if !slowActiveIDs[c.ID()] {
			out = append(out, c)
		}
	}
	return out
}

// Request returns the registered request-level checks (run once per request).
func Request() []scan.RequestCheck {
	return []scan.RequestCheck{
		CORSMisconfig{},
		XXE{},
		HostHeaderInjection{},
		DangerousMethods{},
		GraphQLIntrospection{},
		ContentDiscovery{},
		CachePoisoning{},
	}
}
