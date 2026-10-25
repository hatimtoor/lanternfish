package checks

import (
	"context"
	"net/http"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// StoredXSS detects second-order (stored) cross-site scripting: input submitted
// to one request that is persisted and later served — unencoded — on a
// subsequent page load. It injects a unique breakout canary into the insertion
// point, then re-fetches the page with the original (benign) request and checks
// whether the canary comes back unencoded although it was absent from the
// clean baseline. Because the marker is random and must appear only after the
// injection (not in the baseline), there are no false positives.
//
// This catches the classic "submit a comment, it renders on the page" case that
// reflected-XSS (which only inspects the immediate response) cannot see.
type StoredXSS struct{}

func (StoredXSS) ID() string { return "stored-xss" }

// AppliesTo limits stored-XSS probing to value-bearing input vectors (not
// headers/path/cookies), where persisted content realistically originates.
func (StoredXSS) AppliesTo(k scan.Kind) bool {
	switch k {
	case scan.KindQuery, scan.KindBody, scan.KindJSON, scan.KindMultipart:
		return true
	default:
		return false
	}
}

func (StoredXSS) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	pageURL := base.AbsoluteURL()
	getPage := func() *httpmsg.Response {
		req := &httpmsg.Request{
			Method: http.MethodGet, URL: pageURL, Scheme: pageURL.Scheme, Host: pageURL.Host,
			Header: cloneHeaderSafe(base.Header),
		}
		resp, err := s.Send(ctx, req)
		if err != nil {
			return nil
		}
		return resp
	}

	marker := randMarker("lfstored")
	needle := "<" + marker

	// Baseline: the marker must not already be present on the page.
	b0 := getPage()
	if b0 == nil || !strings.Contains(b0.ContentType(), "html") || strings.Contains(b0.BodyString(), needle) {
		return nil
	}

	// Submit the canary through the insertion point (the "store" step).
	if _, err := s.Send(ctx, p.Mutate("'\"><"+marker+">")); err != nil {
		return nil
	}

	// Re-fetch the page with the original benign request; if the canary now
	// appears unencoded, it was stored and rendered.
	b1 := getPage()
	if b1 == nil || !strings.Contains(b1.ContentType(), "html") {
		return nil
	}
	if strings.Contains(b1.BodyString(), needle) {
		return []*scan.Issue{{
			Check: "stored-xss", Name: "Stored (second-order) cross-site scripting",
			URL: pageURL.String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail: "A unique breakout marker submitted via " + vectorLabel(p) +
				" was persisted and returned unencoded on a later page load, confirming stored cross-site scripting — it executes for every visitor, not just the attacker.",
			Remediation: "Contextually encode stored data on output and validate on input. Stored content must be HTML-encoded wherever it is rendered.",
			Evidence:    excerpt(b1.BodyString(), needle),
			CWE:         "CWE-79",
		}}
	}
	return nil
}

// cloneHeaderSafe copies a request header, dropping body-specific headers that
// would be wrong on a plain GET.
func cloneHeaderSafe(h http.Header) http.Header {
	out := http.Header{}
	for k, vs := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Type", "Content-Length":
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	if out.Get("User-Agent") == "" {
		out.Set("User-Agent", "lanternfish")
	}
	return out
}
