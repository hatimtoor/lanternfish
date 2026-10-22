package checks

import (
	"context"
	"regexp"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// sigInjection is a data-driven error-based active check: it injects a few
// syntax-breaking payloads and reports if an engine-specific error signature
// appears that was absent from the baseline. Each entry registers as its own
// check so per-DBMS / per-engine detection is tracked separately, like Burp.
type sigInjection struct {
	id       string
	name     string
	cwe      string
	sev      scan.Severity
	payloads []string
	sigs     []*regexp.Regexp
}

func (c sigInjection) ID() string { return c.id }

func (c sigInjection) Active(ctx context.Context, s scan.Sender, base *httpmsg.Request, p scan.InsertionPoint) []*scan.Issue {
	sig := matchAny(ctx, s, p, c.payloads, c.sigs)
	if sig == "" {
		return nil
	}
	return []*scan.Issue{{
		Check: c.id, Name: c.name, URL: base.AbsoluteURL().String(), Param: p.Name,
		Severity: c.sev, Confidence: scan.ConfidenceFirm,
		Detail:      "Injecting metacharacters into parameter " + p.Name + " produced a " + c.name + " signature absent from the baseline, indicating unsafe handling.",
		Remediation: "Use parameterized queries / safe APIs and validate input.",
		Evidence:    sig, CWE: c.cwe,
	}}
}

func res(pats ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(pats))
	for i, p := range pats {
		out[i] = regexp.MustCompile(p)
	}
	return out
}

var sqlPayloads = []string{"'", "\"", "')", "';"}

func dbms(id, name string, pats ...string) sigInjection {
	return sigInjection{id: "sqli-" + id, name: "SQL injection error (" + name + ")", cwe: "CWE-89",
		sev: scan.SeverityHigh, payloads: sqlPayloads, sigs: res(pats...)}
}

// injectionRules registers per-DBMS SQL error checks plus template/XML engines.
var injectionRules = []sigInjection{
	dbms("mysql", "MySQL", `(?i)SQL syntax.*MySQL`, `(?i)Warning.*mysqli?`, `(?i)MySqlException`, `(?i)valid MySQL result`, `(?i)check the manual that corresponds to your (MySQL|MariaDB)`),
	dbms("mariadb", "MariaDB", `(?i)MariaDB server version`),
	dbms("postgres", "PostgreSQL", `(?i)PostgreSQL.*ERROR`, `(?i)pg_query\(\)`, `(?i)PSQLException`, `(?i)valid PostgreSQL result`, `(?i)Npgsql\.`),
	dbms("mssql", "Microsoft SQL Server", `(?i)Microsoft SQL (Server|Native Client)`, `(?i)ODBC SQL Server Driver`, `(?i)System\.Data\.SqlClient\.SqlException`, `(?i)Unclosed quotation mark after the character string`),
	dbms("oracle", "Oracle", `(?i)ORA-[0-9]{5}`, `(?i)Oracle error`, `(?i)quoted string not properly terminated`, `(?i)oracle\.jdbc`),
	dbms("sqlite", "SQLite", `(?i)SQLite/JDBCDriver`, `(?i)SQLiteException`, `(?i)System\.Data\.SQLite\.SQLiteException`, `(?i)unrecognized token:`),
	dbms("db2", "IBM DB2", `(?i)CLI Driver.*DB2`, `(?i)DB2 SQL error`, `(?i)SQLCODE`),
	dbms("sybase", "Sybase", `(?i)Sybase message`, `(?i)Warning.*sybase`, `(?i)com\.sybase\.jdbc`),
	dbms("access", "Microsoft Access", `(?i)Microsoft Access (Driver|ODBC)`, `(?i)JET Database Engine`),
	dbms("informix", "Informix", `(?i)com\.informix\.jdbc`, `(?i)Dynamic SQL Error.*Informix`),
	dbms("firebird", "Firebird", `(?i)Dynamic SQL Error`, `(?i)org\.firebirdsql\.jdbc`),
	dbms("ingres", "Ingres", `(?i)Ingres SQLSTATE`, `(?i)Warning.*ingres_`),
	dbms("hsqldb", "HSQLDB", `(?i)org\.hsqldb\.jdbc`, `(?i)Unexpected token.*in statement`),
	dbms("h2", "H2", `(?i)org\.h2\.jdbc`, `(?i)Syntax error in SQL statement`),
	{id: "ssti-spel", name: "Spring SpEL injection error", cwe: "CWE-917", sev: scan.SeverityHigh,
		payloads: []string{"${7*7}", "#{7*7}"}, sigs: res(`(?i)EL1008E`, `(?i)SpelEvaluationException`, `(?i)org\.springframework\.expression`)},
	{id: "ssti-ognl", name: "OGNL injection error", cwe: "CWE-917", sev: scan.SeverityHigh,
		payloads: []string{"%{7*7}", "${7*7}"}, sigs: res(`(?i)ognl\.`, `(?i)OgnlException`, `(?i)org\.apache\.struts`)},
	{id: "ssti-jinja", name: "Jinja2/Python template injection error", cwe: "CWE-1336", sev: scan.SeverityHigh,
		payloads: []string{"{{7*7}}", "{%- for"}, sigs: res(`(?i)jinja2\.exceptions`, `(?i)TemplateSyntaxError`, `(?i)flask\.app`)},
	{id: "xml-injection", name: "XML parser error", cwe: "CWE-91", sev: scan.SeverityMedium,
		payloads: []string{"<", "'\"<>", "]]>"}, sigs: res(`(?i)xmlParseEntityRef`, `(?i)SAXParseException`, `(?i)org\.xml\.sax`, `(?i)XML Parsing Error`)},
}

// InjectionDB returns the data-driven error-based injection checks.
func InjectionDB() []scan.ActiveCheck {
	out := make([]scan.ActiveCheck, 0, len(injectionRules))
	for _, r := range injectionRules {
		out = append(out, r)
	}
	return out
}
