package checks

import (
	"context"
	"regexp"
	"strings"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// SQLiError looks for error-based SQL injection: injecting a syntactically
// breaking value and detecting database error messages that were not present
// in a baseline response. Error signatures are public and vendor-documented.
type SQLiError struct{}

func (SQLiError) ID() string { return "sqli-error" }

var sqlErrorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)warning:\s+mysqli?`),
	regexp.MustCompile(`(?i)unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)pg_query\(\)|postgresql.*error|PSQLException`),
	regexp.MustCompile(`(?i)ORA-\d{5}`),
	regexp.MustCompile(`(?i)sqlite3?::|SQLiteException|unrecognized token`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)System\.Data\.SqlClient\.SqlException`),
}

func (SQLiError) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	// Baseline with a benign value so we don't flag errors already present.
	baseResp, err := s.Send(ctx, p.Mutate(p.Base))
	if err != nil || baseResp == nil {
		return nil
	}
	baseBody := baseResp.BodyString()
	if sig := matchSQLError(baseBody); sig != "" {
		return nil // target already shows DB errors; not attributable.
	}

	// A single quote is the classic syntax-breaking probe.
	resp, err := s.Send(ctx, p.Mutate(p.Base+"'"))
	if err != nil || resp == nil {
		return nil
	}
	body := resp.BodyString()
	sig := matchSQLError(body)
	if sig == "" {
		return nil
	}

	return []*scan.Issue{{
		Check: "sqli-error", Name: "SQL injection (error-based)",
		URL: base.AbsoluteURL().String(), Param: p.Name,
		Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
		Detail:      "Appending a single quote to parameter " + p.Name + " elicited a database error message absent from the baseline response, indicating the value reaches a SQL query unsafely.",
		Remediation: "Use parameterized queries / prepared statements. Never build SQL by string concatenation of user input.",
		Evidence:    excerpt(body, firstMatch(body)),
		CWE:         "CWE-89",
	}}
}

func matchSQLError(body string) string {
	for _, re := range sqlErrorSignatures {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

func firstMatch(body string) string {
	m := matchSQLError(body)
	if m == "" {
		return ""
	}
	// Return the exact substring for excerpting.
	idx := strings.Index(strings.ToLower(body), strings.ToLower(m))
	if idx < 0 {
		return m
	}
	return body[idx : idx+len(m)]
}
