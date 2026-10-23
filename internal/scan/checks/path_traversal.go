package checks

import (
	"context"
	"html"
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
	winIni     = regexp.MustCompile(`(?i)\[(extensions|fonts|mci extensions|files|mail)\]`)
	winHosts   = regexp.MustCompile(`(?i)Microsoft TCP/IP for Windows|# .*localhost name resolution`)
)

type travPayload struct {
	payload string
	sig     *regexp.Regexp
	what    string
}

// traversalPayloads climbs several depths because a vulnerable sink often
// prepends a deep absolute base directory to the input, so a few "../" never
// reach the filesystem root. It covers both Unix ("/") and Windows ("\")
// separators, URL-encoded and nested ("....//") forms that bypass naive
// single-pass strip filters, and absolute paths for sinks that use the input as
// a full path.
var traversalPayloads = buildTraversalPayloads()

func buildTraversalPayloads() []travPayload {
	var out []travPayload
	for _, depth := range []int{6, 8, 10, 12, 16} {
		up := strings.Repeat("../", depth)
		upWin := strings.Repeat("..\\", depth)
		upEnc := strings.Repeat("%2e%2e%2f", depth)
		out = append(out,
			travPayload{up + "etc/passwd", unixPasswd, "/etc/passwd"},
			// Forward slashes resolve on Windows too and, unlike backslashes,
			// survive cookie/header transport intact — so target Windows files
			// with "/" as well.
			travPayload{up + "Windows/win.ini", winIni, "Windows/win.ini"},
			travPayload{up + "Windows/System32/drivers/etc/hosts", winHosts, "Windows hosts file"},
			travPayload{upWin + "Windows\\win.ini", winIni, "Windows\\win.ini"},
			travPayload{upWin + "Windows\\System32\\drivers\\etc\\hosts", winHosts, "Windows hosts file"},
			travPayload{upEnc + "etc%2fpasswd", unixPasswd, "/etc/passwd"},
		)
	}
	// Nested "....//" (defeats a single strip of "../") and absolute paths.
	out = append(out,
		travPayload{strings.Repeat("....//", 12) + "etc/passwd", unixPasswd, "/etc/passwd"},
		travPayload{strings.Repeat("....\\/", 12) + "Windows\\win.ini", winIni, "Windows\\win.ini"},
		travPayload{"/etc/passwd", unixPasswd, "/etc/passwd"},
		travPayload{"C:\\Windows\\win.ini", winIni, "C:\\Windows\\win.ini"},
	)
	return out
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
		// Apps often HTML-encode reflected file content as an XSS defense (e.g.
		// "[fonts]" becomes "&#x5b;fonts&#x5d;"). That still discloses the file,
		// so match against the HTML-decoded body as well as the raw body.
		decoded := html.UnescapeString(body)
		m := tp.sig.FindString(body)
		src := body
		if m == "" {
			if m = tp.sig.FindString(decoded); m != "" {
				src = decoded
			}
		}
		if m != "" {
			return []*scan.Issue{{
				Check: "path-traversal", Name: "Path traversal / local file disclosure",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityHigh, Confidence: scan.ConfidenceCertain,
				Detail:      "Input in " + vectorLabel(p) + " returned the contents of " + tp.what + " when a directory-traversal sequence was supplied, indicating unsanitized file path handling.",
				Remediation: "Resolve and canonicalize paths, reject traversal sequences, and confine file access to an allow-listed base directory.",
				Evidence:    excerpt(src, m),
				CWE:         "CWE-22",
			}}
		}
	}
	return nil
}
