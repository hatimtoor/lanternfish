package checks

import (
	"context"
	"strings"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// dnsInteractor is the optional DNS-capable extension of scan.Interactor. The
// local OAST server implements it when a delegated DNS zone is configured, so
// checks can mint a bare hostname whose lookup is recorded out of band.
type dnsInteractor interface {
	NewDNSPayload() (token, fqdn string, ok bool)
}

// BlindCommandInjection detects OS command injection out of band: it injects
// payloads that make the target resolve or fetch a unique OAST callback and
// reports a finding if the callback fires. This catches blind injection that
// changes nothing in the response and gives no reliable timing signal — e.g.
// input concatenated into a command whose output never returns to the client,
// the real-world case the time-based check alone misses. Payloads are drawn
// from public OWASP command-injection references.
//
// It only runs when an out-of-band interactor is available in the context, and
// (like the time-based check) applies to the usual parameter/cookie vectors
// plus a curated set of request headers (gated in Active).
type BlindCommandInjection struct{}

func (BlindCommandInjection) ID() string { return "command-injection-oob" }

func (BlindCommandInjection) AppliesTo(k scan.Kind) bool {
	switch k {
	case scan.KindQuery, scan.KindBody, scan.KindJSON, scan.KindCookie, scan.KindHeader:
		return true
	default:
		return false
	}
}

func (BlindCommandInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	interactor, ok := scan.InteractorFrom(ctx)
	if !ok {
		return nil
	}

	// Mint a DNS callback when available (egress DNS is almost always permitted
	// and a bare hostname lookup needs no outbound TCP connection) and always an
	// HTTP callback (for curl/wget/certutil-style fetches). Both tokens are
	// polled, so a hit on either confirms execution.
	var tokens []string
	var dnsHost string
	if di, ok := interactor.(dnsInteractor); ok {
		if t, fqdn, ok := di.NewDNSPayload(); ok {
			tokens = append(tokens, t)
			dnsHost = fqdn
		}
	}
	httpToken, callback := interactor.NewPayload()
	tokens = append(tokens, httpToken)
	httpHost := callbackHost(callback)

	// A hostname target for lookup/ping payloads: the delegated DNS name if we
	// have one, otherwise the HTTP callback host (works when the listener is
	// directly reachable, e.g. on a local network).
	host := dnsHost
	if host == "" {
		host = httpHost
	}

	// Separator-based command injection covering POSIX shells and Windows cmd.
	payloads := []string{
		";nslookup " + host,
		"|nslookup " + host,
		"& nslookup " + host + " &",
		"`nslookup " + host + "`",
		"$(nslookup " + host + ")",
		";ping -c 1 " + host,
		"& ping -n 1 " + host + " &",
		";curl " + callback,
		"|curl " + callback,
		"& curl " + callback,
		";wget -qO- " + callback,
		"& certutil -urlcache -f " + callback + " %TEMP%\\x &",
	}
	for _, pl := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		if _, err := s.Send(ctx, p.Mutate(pl)); err != nil {
			continue
		}
	}

	// Give the target a moment to make the out-of-band request.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, tok := range tokens {
			if interactor.Hits(tok) > 0 {
				return []*scan.Issue{{
					Check: "command-injection-oob",
					Name:  "OS command injection (out-of-band)",
					URL:   base.AbsoluteURL().String(), Param: p.Name,
					Severity: scan.SeverityCritical, Confidence: scan.ConfidenceCertain,
					Detail:      "Injecting a command that resolves/fetches a unique Lanternfish OAST callback into " + vectorLabel(p) + " caused the server to contact the listener, confirming out-of-band OS command injection.",
					Remediation: "Never pass user input to a shell or OS command. Use parameterized process APIs with an argument array (no shell), validate against a strict allow-list, and drop shell-metacharacter interpretation.",
					Evidence:    strings.Join(interactor.HitDetails(tok), "; "),
					CWE:         "CWE-78",
				}}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return nil
}

// callbackHost extracts host[:port] from an OAST callback URL.
func callbackHost(cb string) string {
	h := cb
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	return h
}
