package checks

import (
	"context"
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// SSRFMetadata detects in-band server-side request forgery: an SSRF where the
// fetched content comes back in the response. It aims the request at the cloud
// instance-metadata endpoints and at local files, and looks for their highly
// distinctive content. Unlike blind SSRF (confirmed out of band), this needs no
// collaborator and catches the highest-impact case — reading cloud IAM
// credentials — directly. The signatures are specific enough that a normal
// application never returns them, so there are no false positives.
//
// It only probes parameters that plausibly take a URL/host, to stay quiet.
type SSRFMetadata struct{}

func (SSRFMetadata) ID() string { return "ssrf" }

type ssrfProbe struct {
	payload string
	sig     *regexp.Regexp
	what    string
}

// Signatures must match only what the metadata service *returns*, never a
// substring of the probe URL itself — otherwise an endpoint that merely
// reflects our payload would look like a hit. GCP/Azure IMDS are omitted here
// because they require a special request header (Metadata-Flavor / Metadata:
// true) that cannot be set through a URL parameter, so they are never reachable
// in-band; blind SSRF still covers general SSRF to them.
var ssrfProbes = []ssrfProbe{
	{"http://169.254.169.254/latest/meta-data/", regexp.MustCompile(`(?i)ami-launch-index|block-device-mapping|ami-manifest-path|instance-action|reservation-id`), "AWS instance metadata"},
	{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", regexp.MustCompile(`(?i)"AccessKeyId"|"SecretAccessKey"|"Token"\s*:`), "AWS IAM credentials"},
	{"file:///etc/passwd", unixPasswd, "local file /etc/passwd"},
}

func (SSRFMetadata) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	if !looksURLish(p.Name, p.Base) {
		return nil
	}
	// Baseline: if the page already contains a signature on benign input, it is
	// not attributable to our probe.
	baseResp, err := s.Send(ctx, p.Mutate(p.Base))
	if err != nil || baseResp == nil {
		return nil
	}
	baseBody := baseResp.BodyString()

	for _, pr := range ssrfProbes {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := s.Send(ctx, p.Mutate(pr.payload))
		if err != nil || resp == nil {
			continue
		}
		body := resp.BodyString()
		m := pr.sig.FindString(body)
		// Guard: a signature that also appears in the probe URL would match a
		// mere reflection of our payload, so require it to be absent from both
		// the payload and the benign baseline.
		if m != "" && !strings.Contains(pr.payload, m) && pr.sig.FindString(baseBody) == "" {
			sev := scan.SeverityHigh
			if pr.what == "AWS IAM credentials" {
				sev = scan.SeverityCritical
			}
			return []*scan.Issue{{
				Check: "ssrf", Name: "Server-side request forgery (in-band)",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: sev, Confidence: scan.ConfidenceCertain,
				Detail:      "Setting parameter " + p.Name + " to an internal URL caused the server to fetch it and return " + pr.what + " in the response, confirming server-side request forgery.",
				Remediation: "Validate and allow-list outbound request targets, reject user-supplied URLs/hosts, block link-local/metadata ranges (169.254.0.0/16, metadata.google.internal) and the file:// scheme, and require IMDSv2 on AWS.",
				Evidence:    excerpt(body, m),
				CWE:         "CWE-918",
			}}
		}
	}
	return nil
}
