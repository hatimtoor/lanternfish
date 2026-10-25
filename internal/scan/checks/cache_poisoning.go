package checks

import (
	"context"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// CachePoisoning detects web cache poisoning via an unkeyed header. Many sites
// sit behind a cache that keys entries on the URL but not on headers like
// X-Forwarded-Host. If such a header is reflected into the response (a link, a
// redirect, an absolute resource URL) and the response is cacheable, an
// attacker can send one poisoned request and have the malicious response served
// to every subsequent visitor. This check injects a marker host into the
// common unkeyed headers and reports only when the marker is reflected AND the
// response looks cacheable — and only when a clean baseline did not already
// contain the marker, so there are no false positives. Public technique
// (PortSwigger web cache poisoning research).
type CachePoisoning struct{}

func (CachePoisoning) ID() string { return "cache-poisoning" }

// unkeyedHeaders are request headers caches commonly exclude from the cache key
// but applications still trust when building absolute URLs.
var unkeyedHeaders = []string{
	"X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
	"X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Original-URL",
	"X-Rewrite-URL", "X-Forwarded-Prefix",
}

func (CachePoisoning) Request(ctx context.Context, s scan.Sender, base *httpmsg.Request) []*scan.Issue {
	// Baseline: the marker must not already be present without our injection.
	baseResp, err := s.Send(ctx, base.Clone())
	if err != nil || baseResp == nil {
		return nil
	}
	const marker = "lanternfish-cp.example"
	if strings.Contains(baseResp.BodyString(), marker) {
		return nil
	}

	for _, hdr := range unkeyedHeaders {
		if ctx.Err() != nil {
			return nil
		}
		probe := base.Clone()
		probe.Header.Set(hdr, marker)
		resp, err := s.Send(ctx, probe)
		if err != nil || resp == nil {
			continue
		}
		if !strings.Contains(resp.BodyString(), marker) {
			continue
		}
		// Reflected. It is only poisonable if the response is cacheable.
		if !looksCacheable(resp) {
			continue
		}
		return []*scan.Issue{{
			Check: "cache-poisoning", Name: "Web cache poisoning via unkeyed header",
			URL:      base.AbsoluteURL().String(),
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail: "The request header " + hdr + " is reflected into a response that appears cacheable. An attacker can send a request with a malicious " + hdr +
				" and have the poisoned response (e.g. a hijacked script/link host) served from the cache to other users.",
			Remediation: "Do not build absolute URLs or resource hosts from untrusted headers like " + hdr + ". If such a header is needed, include it in the cache key, or strip it at the edge.",
			Evidence:    hdr + ": " + marker + " reflected; " + cacheEvidence(resp),
			CWE:         "CWE-444",
		}}
	}
	return nil
}

// looksCacheable reports whether a response is likely stored by a shared cache.
func looksCacheable(resp *httpmsg.Response) bool {
	cc := strings.ToLower(resp.Header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}
	if strings.Contains(cc, "public") || strings.Contains(cc, "max-age") || strings.Contains(cc, "s-maxage") {
		return true
	}
	// Signals that a cache is actually in front of the origin.
	if resp.Header.Get("Age") != "" || resp.Header.Get("X-Cache") != "" ||
		resp.Header.Get("X-Cache-Hits") != "" || resp.Header.Get("CF-Cache-Status") != "" {
		return true
	}
	return false
}

func cacheEvidence(resp *httpmsg.Response) string {
	for _, h := range []string{"Cache-Control", "Age", "X-Cache", "CF-Cache-Status"} {
		if v := resp.Header.Get(h); v != "" {
			return h + ": " + v
		}
	}
	return "cacheable response"
}
