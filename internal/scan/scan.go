// Package scan defines Lanternfish's scanning engine: the issue model, the insertion
// points active checks mutate, and the Check interfaces.
//
// The design is independent and derived from public web-security knowledge
// (OWASP Testing Guide, CWE). Detection techniques and payloads used by the
// bundled checks are openly documented; nothing here is lifted from a
// proprietary scanner.
package scan

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"time"

	"lanternfish/internal/httpmsg"
)

// Severity ranks the impact of an issue.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// Confidence expresses how sure the check is that the issue is real.
type Confidence int

const (
	ConfidenceTentative Confidence = iota
	ConfidenceFirm
	ConfidenceCertain
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceCertain:
		return "certain"
	case ConfidenceFirm:
		return "firm"
	default:
		return "tentative"
	}
}

// Issue is a single finding.
type Issue struct {
	Check       string     `json:"check"`
	Name        string     `json:"name"`
	Severity    Severity   `json:"-"`
	SeverityStr string     `json:"severity"`
	Confidence  Confidence `json:"-"`
	ConfStr     string     `json:"confidence"`
	URL         string     `json:"url"`
	Param       string     `json:"param,omitempty"`
	Detail      string     `json:"detail"`
	Remediation string     `json:"remediation,omitempty"`
	Evidence    string     `json:"evidence,omitempty"`
	CWE         string     `json:"cwe,omitempty"`
	FoundAt     time.Time  `json:"found_at"`

	// HostScoped marks a finding that is a property of the whole host (a server
	// banner, a tech fingerprint, a site-wide missing header) rather than of one
	// URL. The collector de-duplicates these per host so they are reported once,
	// not repeated on every endpoint. Not serialized.
	HostScoped bool `json:"-"`
}

// finalize fills the string projections used in JSON output.
func (i *Issue) finalize() {
	i.SeverityStr = i.Severity.String()
	i.ConfStr = i.Confidence.String()
	if i.FoundAt.IsZero() {
		i.FoundAt = time.Now()
	}
}

// Kind classifies where an insertion point lives in the request.
type Kind int

const (
	KindQuery     Kind = iota // query-string parameter (Burp PARAM_URL)
	KindBody                  // x-www-form-urlencoded body parameter (PARAM_BODY)
	KindHeader                // request header value (HEADER)
	KindJSON                  // value inside a JSON body (PARAM_JSON)
	KindCookie                // cookie value (PARAM_COOKIE)
	KindPath                  // URL path segment (URL_PATH_FOLDER / URL_PATH_FILENAME)
	KindXML                   // value or attribute inside an XML body (PARAM_XML / PARAM_XML_ATTR)
	KindMultipart             // multipart/form-data field value (PARAM_MULTIPART_ATTR)
	KindParamName             // a parameter's name rather than its value (PARAM_NAME_URL / PARAM_NAME_BODY)
)

// String names the insertion-point kind, mirroring Burp's taxonomy.
func (k Kind) String() string {
	switch k {
	case KindQuery:
		return "url-param"
	case KindBody:
		return "body-param"
	case KindHeader:
		return "header"
	case KindJSON:
		return "json-param"
	case KindCookie:
		return "cookie"
	case KindPath:
		return "path"
	case KindXML:
		return "xml"
	case KindMultipart:
		return "multipart"
	case KindParamName:
		return "param-name"
	default:
		return "unknown"
	}
}

// InsertionPoint is one place an active check can inject a payload. It knows
// how to produce a mutated copy of the base request with a new value.
type InsertionPoint struct {
	Kind Kind
	Name string
	Base string // the original value

	build func(value string) *httpmsg.Request
}

// Mutate returns a request clone with this insertion point set to value.
func (p InsertionPoint) Mutate(value string) *httpmsg.Request { return p.build(value) }

// Sender performs an HTTP exchange for a mutated request. The proxy, replayer,
// and scanner all share this so checks are transport-agnostic.
//
// Send must be safe for concurrent use: the engine and the fuzzer call it from
// many goroutines at once. The shared client.Client satisfies this.
type Sender interface {
	Send(ctx context.Context, r *httpmsg.Request) (*httpmsg.Response, error)
}

// PassiveCheck inspects an already-observed transaction without sending traffic.
type PassiveCheck interface {
	ID() string
	Passive(tx *httpmsg.Transaction) []*Issue
}

// ActiveCheck probes a single insertion point by sending crafted requests.
type ActiveCheck interface {
	ID() string
	Active(ctx context.Context, s Sender, base *httpmsg.Request, p InsertionPoint) []*Issue
}

// KindAwareCheck lets an active check restrict itself to certain
// insertion-point kinds. Checks that do not implement it run against every
// kind. Wait-heavy checks use this to avoid probing low-yield points (e.g.
// time-based inference on every path segment), keeping scans fast and focused.
type KindAwareCheck interface {
	AppliesTo(k Kind) bool
}

// RequestCheck probes a request as a whole (independent of insertion points),
// e.g. header or CORS behaviour. It runs once per audited request.
type RequestCheck interface {
	ID() string
	Request(ctx context.Context, s Sender, base *httpmsg.Request) []*Issue
}

// Collector gathers issues, de-duplicating on (check, url, param).
type Collector struct {
	seen   map[string]bool
	issues []*Issue
}

func NewCollector() *Collector { return &Collector{seen: map[string]bool{}} }

func (c *Collector) Add(issues ...*Issue) {
	for _, is := range issues {
		if is == nil {
			continue
		}
		// De-dup key. The Name is included so distinct findings of one check
		// (e.g. "Missing CSP" vs "Missing nosniff" from security-headers) are not
		// collapsed together. Host-scoped findings key on the host instead of the
		// full URL, so a site-wide fact is reported once rather than per endpoint.
		scope := is.URL
		if is.HostScoped {
			if u, err := url.Parse(is.URL); err == nil && u.Host != "" {
				scope = u.Scheme + "://" + u.Host
			}
		}
		key := is.Check + "\x00" + is.Name + "\x00" + scope + "\x00" + is.Param
		if c.seen[key] {
			continue
		}
		is.finalize()
		c.seen[key] = true
		c.issues = append(c.issues, is)
	}
}

// Issues returns the collected issues sorted by descending severity.
func (c *Collector) Issues() []*Issue {
	out := suppressAmbiguousInjection(c.issues)
	out = append([]*Issue(nil), out...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Severity > out[j].Severity
	})
	return out
}

// suppressAmbiguousInjection drops boolean-differential XPath/LDAP findings on a
// param that also has a SQL-injection finding. A tautology-vs-contradiction
// differential (e.g. "' or '1'='1") is valid in SQL, XPath and LDAP alike, so
// on a SQL backend the XPath/LDAP boolean checks fire on the same signal and
// mislabel the bug. A SQLi finding (error-, boolean- or time-based) is the
// stronger, more specific evidence, so it wins; error-based XPath/LDAP findings
// (which match real engine error text) are never suppressed.
func suppressAmbiguousInjection(in []*Issue) []*Issue {
	sqliParam := map[string]bool{}
	for _, is := range in {
		if strings.HasPrefix(is.Check, "sqli-") {
			sqliParam[is.URL+"\x00"+is.Param] = true
		}
	}
	if len(sqliParam) == 0 {
		return in
	}
	out := in[:0:0]
	for _, is := range in {
		ambiguous := (is.Check == "xpath-injection" || is.Check == "ldap-injection") &&
			strings.Contains(is.Name, "(boolean)")
		if ambiguous && sqliParam[is.URL+"\x00"+is.Param] {
			continue // yields to the confirmed SQL injection on this param
		}
		out = append(out, is)
	}
	return out
}

// InsertionPoints derives the query, body, and selected header insertion
// points for a base request.
func InsertionPoints(base *httpmsg.Request) []InsertionPoint {
	var pts []InsertionPoint

	// Query parameters.
	if base.URL != nil {
		q := base.URL.Query()
		for name, vals := range q {
			name, orig := name, firstOr(vals, "")
			pts = append(pts, InsertionPoint{
				Kind: KindQuery, Name: name, Base: orig,
				build: func(value string) *httpmsg.Request {
					c := base.Clone()
					nq := c.URL.Query()
					nq.Set(name, value)
					c.URL.RawQuery = nq.Encode()
					return c
				},
			})
		}
	}

	// Form body parameters.
	if ct := base.Header.Get("Content-Type"); isFormURLEncoded(ct) && len(base.Body) > 0 {
		if form, err := url.ParseQuery(string(base.Body)); err == nil {
			for name, vals := range form {
				name, orig := name, firstOr(vals, "")
				pts = append(pts, InsertionPoint{
					Kind: KindBody, Name: name, Base: orig,
					build: func(value string) *httpmsg.Request {
						c := base.Clone()
						nf, _ := url.ParseQuery(string(c.Body))
						nf.Set(name, value)
						c.Body = []byte(nf.Encode())
						return c
					},
				})
			}
		}
	}

	// JSON body values, cookies, selected headers, and URL path segments —
	// mirroring Burp's insertion-point taxonomy so active checks reach modern
	// APIs and non-parameter inputs, not just query/form parameters.
	pts = append(pts, jsonPoints(base)...)
	pts = append(pts, cookiePoints(base)...)
	pts = append(pts, headerPoints(base)...)
	pts = append(pts, pathPoints(base)...)
	pts = append(pts, xmlPoints(base)...)
	pts = append(pts, multipartPoints(base)...)
	pts = append(pts, paramNamePoints(base)...)

	return pts
}

func firstOr(v []string, d string) string {
	if len(v) > 0 {
		return v[0]
	}
	return d
}

func isFormURLEncoded(ct string) bool {
	return len(ct) >= 33 && ct[:33] == "application/x-www-form-urlencoded"
}
