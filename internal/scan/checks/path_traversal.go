package checks

import (
	"context"
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// PathTraversal injects directory-traversal sequences targeting well-known
// files and looks for their signature content in the response. Payloads and
// signatures are public.
type PathTraversal struct{}

func (PathTraversal) ID() string { return "path-traversal" }

var (
	unixPasswd = regexp.MustCompile(`root:.*:0:0:`)
	winIni     = regexp.MustCompile(`(?i)\[(extensions|fonts|mci extensions)\]`)
)

var traversalPayloads = []struct {
	payload string
	sig     *regexp.Regexp
	what    string
}{
	{"../../../../../../etc/passwd", unixPasswd, "/etc/passwd"},
	{"....//....//....//....//etc/passwd", unixPasswd, "/etc/passwd"},
	{"..\\..\\..\\..\\..\\..\\windows\\win.ini", winIni, "windows\\win.ini"},
	{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", unixPasswd, "/etc/passwd"},
}

func (PathTraversal) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	for _, tp := range traversalPayloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := s.Send(ctx, p.Mutate(tp.payload))
		if err != nil || resp == nil {
			continue
		}
		body := resp.BodyString()
		if m := tp.sig.FindString(body); m != "" {
			return []*scan.Issue{{
				Check: "path-traversal", Name: "Path traversal / local file disclosure",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityHigh, Confidence: scan.ConfidenceCertain,
				Detail:      "Parameter " + p.Name + " returned the contents of " + tp.what + " when a directory-traversal sequence was supplied, indicating unsanitized file path handling.",
				Remediation: "Resolve and canonicalize paths, reject traversal sequences, and confine file access to an allow-listed base directory.",
				Evidence:    excerpt(body, firstNonEmpty(tp.sig.FindString(body), m)),
				CWE:         "CWE-22",
			}}
		}
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
