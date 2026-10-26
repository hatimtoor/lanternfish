package checks

import (
	"context"
	"net/url"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// ContentDiscovery is a request-level check that probes the target host for a
// small set of commonly-exposed sensitive files, comparing against a random
// path baseline so catch-all 200 pages don't cause false positives. This is
// the practical core of Burp's engagement "content discovery".
type ContentDiscovery struct{}

func (ContentDiscovery) ID() string { return "content-discovery" }

var sensitivePaths = []struct{ path, signal string }{
	{"/.git/config", "[core]"},
	{"/.env", "="},
	{"/.htaccess", ""},
	{"/.htpasswd", ":"},
	{"/web.config", "<configuration"},
	{"/.DS_Store", ""},
	{"/backup.zip", ""},
	{"/.svn/entries", ""},
	{"/server-status", "Apache Server Status"},
	{"/actuator/env", "\"propertySources\""},
	{"/phpinfo.php", "phpinfo()"},
	{"/.aws/credentials", "aws_access_key_id"},
}

func (ContentDiscovery) Request(ctx context.Context, s scan.Sender, base *httpmsg.Request) []*scan.Issue {
	root := &url.URL{Scheme: base.Scheme, Host: base.Host}

	// Baseline: a random path should 404 (or at least differ from real hits).
	baseReq := rootReq(base, root, "/"+randMarker("lanternfish")+"-nope")
	baseResp, err := s.Send(ctx, baseReq)
	baseStatus := 404
	baseLen := -1
	if err == nil && baseResp != nil {
		baseStatus = baseResp.StatusCode
		baseLen = len(baseResp.Body)
	}

	var issues []*scan.Issue
	for _, sp := range sensitivePaths {
		if ctx.Err() != nil {
			break
		}
		resp, err := s.Send(ctx, rootReq(base, root, sp.path))
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		// When a random path already returns 200, this host serves a catch-all
		// fallback (common for SPAs, which return index.html for every route).
		// A hit is only real if it is clearly NOT that fallback page:
		//   1. it must differ in size from the baseline shell, and
		//   2. it must contain the file-specific signal.
		// Weak signals like "=" or ":" appear in any HTML, so the size check is
		// what actually distinguishes a real file from the Angular shell.
		if baseStatus == 200 {
			if baseLen >= 0 && similarLen(len(resp.Body), baseLen) {
				continue // identical to the catch-all fallback, not a real file
			}
			if sp.signal == "" || !strings.Contains(resp.BodyString(), sp.signal) {
				continue
			}
			// A config/secret/backup file is never served as HTML; a text/html
			// body on a catch-all host is the fallback wearing a different size.
			if strings.Contains(resp.ContentType(), "html") && sp.signal != "Apache Server Status" && sp.signal != "phpinfo()" {
				continue
			}
		}
		issues = append(issues, &scan.Issue{
			Check: "content-discovery", Name: "Sensitive file exposed: " + sp.path,
			URL:      root.String() + sp.path,
			Severity: scan.SeverityMedium, Confidence: scan.ConfidenceFirm,
			Detail:      "The path " + sp.path + " is accessible and returned 200, exposing configuration, source control, or backup data.",
			Remediation: "Remove the file from the web root or block access to it.",
			Evidence:    "HTTP 200 at " + sp.path, CWE: "CWE-538",
		})
	}
	return issues
}

func rootReq(base *httpmsg.Request, root *url.URL, path string) *httpmsg.Request {
	u := *root
	u.Path = path
	c := base.Clone()
	c.Method = "GET"
	c.URL = &u
	c.Body = nil
	return c
}
