package checks

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// LFI detects local file inclusion via PHP stream wrappers and well-known
// files. The php://filter base64 wrapper is a high-precision signal: the
// response contains a base64 blob that decodes to PHP source.
type LFI struct{}

func (LFI) ID() string { return "lfi" }

func (LFI) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	// php://filter returning base64-encoded source.
	for _, res := range []string{"index.php", "index", "config.php", "/etc/passwd"} {
		if ctx.Err() != nil {
			return nil
		}
		payload := "php://filter/convert.base64-encode/resource=" + res
		resp, err := s.Send(ctx, p.Mutate(payload))
		if err != nil || resp == nil {
			continue
		}
		if blob := longBase64.FindString(resp.BodyString()); blob != "" {
			if dec, err := base64.StdEncoding.DecodeString(blob); err == nil {
				ds := string(dec)
				if strings.Contains(ds, "<?php") || unixPasswd.MatchString(ds) {
					return []*scan.Issue{{
						Check: "lfi", Name: "Local file inclusion (php:// wrapper)",
						URL: base.AbsoluteURL().String(), Param: p.Name,
						Severity: scan.SeverityHigh, Confidence: scan.ConfidenceCertain,
						Detail:      "Parameter " + p.Name + " accepted a php://filter wrapper and returned base64-encoded file contents, confirming local file inclusion.",
						Remediation: "Never pass user input to include/require or file APIs; use an allow-list of known resources.",
						Evidence:    "base64 decodes to file content (" + firstLine(ds) + ")",
						CWE:         "CWE-98",
					}}
				}
			}
		}
	}
	return nil
}

var longBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// CommandInjectionInband detects OS command injection by injecting a shell
// arithmetic expansion and matching its computed result, which proves the
// shell evaluated the payload (reflection would echo the literal expression).
type CommandInjectionInband struct{}

func (CommandInjectionInband) ID() string { return "command-injection-inband" }

func (CommandInjectionInband) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	a, b := 13, 17
	tag := randMarker("ar")
	want := fmt.Sprintf("%s%d%s", tag, a*b, tag)
	// Shell arithmetic expansion; the wrappers try several injection contexts.
	payloads := []string{
		fmt.Sprintf(";echo %s$((%d*%d))%s", tag, a, b, tag),
		fmt.Sprintf("|echo %s$((%d*%d))%s", tag, a, b, tag),
		fmt.Sprintf("& echo %s$((%d*%d))%s", tag, a, b, tag),
		fmt.Sprintf("`echo %s$((%d*%d))%s`", tag, a, b, tag),
		fmt.Sprintf("$(echo %s$((%d*%d))%s)", tag, a, b, tag),
	}
	for _, pl := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := s.Send(ctx, p.Mutate(p.Base+pl))
		if err != nil || resp == nil {
			continue
		}
		if strings.Contains(resp.BodyString(), want) {
			return []*scan.Issue{{
				Check: "command-injection-inband", Name: "OS command injection (in-band)",
				URL: base.AbsoluteURL().String(), Param: p.Name,
				Severity: scan.SeverityCritical, Confidence: scan.ConfidenceCertain,
				Detail:      "Parameter " + p.Name + " executed a shell arithmetic expansion: the injected expression evaluated to " + want + " in the response, confirming OS command injection.",
				Remediation: "Never pass user input to a shell. Use argument arrays without a shell and validate input.",
				Evidence:    want, CWE: "CWE-78",
			}}
		}
	}
	return nil
}

// NoSQLInjection detects error-based NoSQL (MongoDB/CouchDB) injection.
type NoSQLInjection struct{}

func (NoSQLInjection) ID() string { return "nosql-injection" }

var nosqlErrors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)MongoError`),
	regexp.MustCompile(`(?i)MongoServerError`),
	regexp.MustCompile(`(?i)CastError.*ObjectId`),
	regexp.MustCompile(`(?i)E11000 duplicate key`),
	regexp.MustCompile(`(?i)couchdb`),
	regexp.MustCompile(`(?i)unexpected token.*in JSON`),
	regexp.MustCompile(`(?i)\$where`),
}

func (NoSQLInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	if sig := matchAny(ctx, s, p, []string{`'`, `"`, `';return true;var x='`, `[$ne]`}, nosqlErrors); sig != "" {
		return []*scan.Issue{{
			Check: "nosql-injection", Name: "NoSQL injection",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "Injecting NoSQL metacharacters into parameter " + p.Name + " produced a NoSQL database error, indicating the value reaches a NoSQL query unsafely.",
			Remediation: "Validate and type-check input; use the driver's query builders and reject object/operator syntax in string fields.",
			Evidence:    sig, CWE: "CWE-943",
		}}
	}
	return nil
}
