// Package service exposes high-level operations over a session that both the
// web API and the MCP server call, so a human and an LLM drive identical logic.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lanternfish/internal/browser"
	"lanternfish/internal/clickjack"
	"lanternfish/internal/client"
	"lanternfish/internal/comparer"
	"lanternfish/internal/crawl"
	"lanternfish/internal/csrf"
	"lanternfish/internal/decoder"
	"lanternfish/internal/ext"
	"lanternfish/internal/fuzz"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/macro"
	"lanternfish/internal/oast"
	"lanternfish/internal/report"
	"lanternfish/internal/scan"
	"lanternfish/internal/scan/checks"
	"lanternfish/internal/sequencer"
	"lanternfish/internal/session"
)

// Service bundles a session with an upstream client and scan engine.
type Service struct {
	Sess       *session.Session
	OAST       *oast.Server  // optional out-of-band listener for blind checks
	Ext        *ext.Manager  // optional extension (webhook) manager
	Reg        *ext.Registry // native (in-process) extension registry
	up         *client.Client
	sender     scan.Sender  // up, optionally rate-limited, used for scan audits
	eng        *scan.Engine // full engine
	engFast    *scan.Engine // engine without wait-heavy checks
	insecure   bool
	sched      *scheduler
	oastMu     sync.Mutex
	interactor scan.Interactor // out-of-band provider (local OAST or hosted collaborator)
	live       liveAudit       // auto-audit of observed proxy traffic
}

// scanCtx augments ctx with the out-of-band interactor if one is set.
func (s *Service) scanCtx(ctx context.Context) context.Context {
	if s.interactor != nil {
		return scan.WithInteractor(ctx, s.interactor)
	}
	if s.OAST != nil {
		return scan.WithInteractor(ctx, s.OAST)
	}
	return ctx
}

// interactshFromEnv builds an Interactsh client when LANTERNFISH_OAST selects
// it. Value forms: "interactsh" (auto-pick a public server) or
// "interactsh:oast.live" (a specific server). Returns false otherwise.
func interactshFromEnv() (scan.Interactor, bool) {
	v := strings.TrimSpace(os.Getenv("LANTERNFISH_OAST"))
	if !strings.HasPrefix(v, "interactsh") {
		return nil, false
	}
	server := strings.TrimPrefix(v, "interactsh")
	server = strings.TrimPrefix(server, ":")
	var (
		c   *oast.Interactsh
		err error
	)
	if server == "" {
		c, err = oast.NewInteractshAuto()
	} else {
		c, err = oast.NewInteractsh(server)
	}
	if err != nil {
		return nil, false
	}
	return c, true
}

// UseInteractsh switches the out-of-band provider to a public Interactsh server
// (empty server = auto-pick). Used by the --oob interactsh CLI flag.
func (s *Service) UseInteractsh(server string) error {
	var (
		c   *oast.Interactsh
		err error
	)
	if server == "" {
		c, err = oast.NewInteractshAuto()
	} else {
		c, err = oast.NewInteractsh(server)
	}
	if err != nil {
		return err
	}
	s.oastMu.Lock()
	s.interactor = c
	s.oastMu.Unlock()
	return nil
}

// SetInteractor sets the out-of-band provider the scanner uses (e.g. a hosted
// collaborator). Overrides any local listener for new scans.
func (s *Service) SetInteractor(i scan.Interactor) {
	s.oastMu.Lock()
	defer s.oastMu.Unlock()
	s.interactor = i
}

// New builds a Service.
func New(sess *session.Session, insecure bool) *Service {
	up := client.New(client.Options{InsecureSkipVerify: insecure, FollowRedirects: false, HTTP3: os.Getenv("LANTERNFISH_HTTP3") != ""})
	return &Service{
		Sess:     sess,
		Reg:      ext.NewRegistry(),
		up:       up,
		sender:   up,
		eng:      scan.NewEngine(checks.Passive(), checks.Active()).WithRequestChecks(checks.Request()),
		engFast:  scan.NewEngine(checks.Passive(), checks.ActiveFast()).WithRequestChecks(checks.Request()),
		insecure: insecure,
		sched:    newScheduler(),
	}
}

// BrowserLogin drives a headless browser through a login form and applies the
// resulting session cookies as the session's auth, so a subsequent crawl/scan
// runs authenticated. Returns the number of cookies captured.
func (s *Service) BrowserLogin(c browser.Creds) (int, error) {
	cookies, err := browser.Login(c, 0)
	if err != nil {
		return 0, err
	}
	if h := browser.CookieHeader(cookies); h != "" {
		s.Sess.SetAuthHeader("Cookie", h)
	}
	return len(cookies), nil
}

// SetRateLimit caps scan requests per second across all concurrent probes (0 =
// unlimited). Use it to scan a third-party target politely.
func (s *Service) SetRateLimit(perSec float64) {
	if perSec > 0 {
		s.sender = scan.NewThrottle(s.up, perSec)
	} else {
		s.sender = s.up
	}
}

// scanSender returns the Sender for scan audits (rate-limited if configured).
func (s *Service) scanSender() scan.Sender {
	if s.sender != nil {
		return s.sender
	}
	return s.up
}

// UseExtension registers a native in-process extension and applies the passive
// and active checks it contributes to both scan engines. Call it before
// scanning. Request/response editors it registers are wired into the proxy by
// the caller via s.Reg.
func (s *Service) UseExtension(e ext.NativeExtension) {
	pBefore := len(s.Reg.PassiveChecks())
	aBefore := len(s.Reg.ActiveChecks())
	s.Reg.Use(e)
	for _, c := range s.Reg.PassiveChecks()[pBefore:] {
		s.eng.AddPassive(c)
		s.engFast.AddPassive(c)
	}
	for _, c := range s.Reg.ActiveChecks()[aBefore:] {
		s.eng.AddActive(c)
		s.engFast.AddActive(c)
	}
}

// EnsureOAST starts an out-of-band listener on an ephemeral loopback port and
// attaches it, if one is not already set. Safe to call repeatedly. This lets
// blind checks work from any entry point, not just the GUI/server.
func (s *Service) EnsureOAST() {
	s.oastMu.Lock()
	defer s.oastMu.Unlock()
	if s.interactor != nil || s.OAST != nil {
		return
	}
	// Prefer a hosted collaborator when configured, so blind checks reach
	// targets that cannot call back to this machine.
	if r, ok := oast.RemoteFromEnv(); ok {
		s.interactor = r
		return
	}
	// Zero-config public OOB: when requested (LANTERNFISH_OAST=interactsh, or a
	// specific server like interactsh:oast.live), register with a public
	// Interactsh server so blind checks fire against *remote* targets that can
	// never reach this machine — no DNS/infra setup required. This is the path
	// bug-bounty and research use; learners on their own box can omit it and use
	// the local listener below.
	if c, ok := interactshFromEnv(); ok {
		s.interactor = c
		return
	}
	o := oast.New("")
	if _, err := o.Start("127.0.0.1:0"); err == nil {
		s.OAST = o
		s.interactor = o
	}
}

// ReplayParams describes a request to send.
type ReplayParams struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// Replay sends a request, records it under the repeater source, and returns it.
func (s *Service) Replay(ctx context.Context, p ReplayParams) (*session.Record, error) {
	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, v := range p.Headers {
		h.Set(k, v)
	}
	if h.Get("User-Agent") == "" {
		h.Set("User-Agent", "lanternfish")
	}
	s.Sess.ApplyAuth(h)
	req := &httpmsg.Request{
		Method: strings.ToUpper(orDefault(p.Method, "GET")),
		URL:    u, Scheme: u.Scheme, Host: u.Host,
		Header: h, Body: []byte(p.Body),
	}
	resp, err := s.up.Send(ctx, req)
	if err != nil {
		return nil, err
	}
	tx := &httpmsg.Transaction{Request: req, Response: resp}
	return s.Sess.Add(session.SourceRepeater, tx), nil
}

// ScanResult summarizes a scan run.
type ScanResult struct {
	Target   string        `json:"target"`
	Issues   []*scan.Issue `json:"issues"`
	Duration string        `json:"duration"`
}

// ScanURL runs the full set of passive + active checks against one URL.
func (s *Service) ScanURL(ctx context.Context, target string) (*ScanResult, error) {
	return s.ScanURLMode(ctx, target, false)
}

// ScanURLMode scans one URL with a GET. When fast is true it uses the engine
// without the wait-heavy checks (out-of-band and time-based).
func (s *Service) ScanURLMode(ctx context.Context, target string, fast bool) (*ScanResult, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	hdr := http.Header{"User-Agent": {"lanternfish"}}
	base := &httpmsg.Request{
		Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: hdr,
	}
	return s.ScanRequestMode(ctx, base, fast)
}

// ScanRequestMode runs the full passive + active pipeline against an arbitrary
// request, so callers can exercise any method, body, headers, or cookies (and
// thus every insertion-point kind). ScanURLMode is the GET shortcut.
func (s *Service) ScanRequestMode(ctx context.Context, base *httpmsg.Request, fast bool) (*ScanResult, error) {
	if base.Header == nil {
		base.Header = http.Header{}
	}
	if base.Header.Get("User-Agent") == "" {
		base.Header.Set("User-Agent", "lanternfish")
	}
	eng := s.eng
	if fast {
		eng = s.engFast
	}
	s.Sess.ApplyAuth(base.Header)
	start := time.Now()
	col := scan.NewCollector()
	if resp, err := s.scanSender().Send(ctx, base); err == nil {
		s.Sess.Add(session.SourceScanner, &httpmsg.Transaction{Request: base, Response: resp})
		eng.Passive(&httpmsg.Transaction{Request: base, Response: resp}, col)
	}
	ctx2 := ctx
	if !fast {
		ctx2 = s.scanCtx(ctx) // only full mode needs the OAST interactor
	}
	eng.Audit(ctx2, s.scanSender(), base, col)
	issues := col.Issues()
	s.Sess.AddIssues(issues...)
	return &ScanResult{Target: base.AbsoluteURL().String(), Issues: issues, Duration: time.Since(start).Round(time.Millisecond).String()}, nil
}

// AuditRequest runs active checks against one request's insertion points,
// recording any issues in the session.
func (s *Service) AuditRequest(ctx context.Context, base *httpmsg.Request) []*scan.Issue {
	if base.Header == nil {
		base.Header = http.Header{}
	}
	s.Sess.ApplyAuth(base.Header)
	col := scan.NewCollector()
	s.eng.Audit(s.scanCtx(ctx), s.scanSender(), base, col)
	issues := col.Issues()
	s.Sess.AddIssues(issues...)
	return issues
}

// CrawlParams bounds a crawl and says whether to audit what is found.
type CrawlParams struct {
	Seeds    []string `json:"seeds"`
	MaxPages int      `json:"max_pages"`
	MaxDepth int      `json:"max_depth"`
	Audit    bool     `json:"audit"`
}

// CrawlResult reports crawl coverage and any issues found when auditing.
type CrawlResult struct {
	*crawl.Result
	IssuesFound int `json:"issues_found"`
}

// Crawl discovers in-scope URLs and forms from the seeds and, when requested,
// audits every discovered request.
func (s *Service) Crawl(ctx context.Context, p CrawlParams) *CrawlResult {
	cr := crawl.New(s.Sess, s.insecure, crawl.Options{MaxPages: p.MaxPages, MaxDepth: p.MaxDepth})
	res, reqs := cr.Crawl(ctx, p.Seeds)
	out := &CrawlResult{Result: res}
	if p.Audit {
		seen := map[string]bool{}
		for _, r := range reqs {
			key := r.Method + " " + r.AbsoluteURL().String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out.IssuesFound += len(s.AuditRequest(ctx, r))
		}
	}
	return out
}

// BrowserCrawl drives a headless browser to crawl a JavaScript-rendered page,
// then fetches and records the in-scope URLs and fetch/XHR endpoints it found
// (bounded), so they populate history, the sitemap, and passive checks.
func (s *Service) BrowserCrawl(ctx context.Context, target string) (*browser.Result, error) {
	res, err := browser.Crawl(target, 0)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	fetch := func(raw string) {
		if len(seen) >= 100 {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || seen[u.String()] {
			return
		}
		if !s.Sess.Scope.InScope(u) {
			return
		}
		seen[u.String()] = true
		req := &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{"User-Agent": {"lanternfish-headless"}}}
		s.Sess.ApplyAuth(req.Header)
		if resp, err := s.up.Send(ctx, req); err == nil {
			s.Sess.Add(session.SourceCrawler, &httpmsg.Transaction{Request: req, Response: resp})
		}
	}
	for _, l := range res.Links {
		fetch(l)
	}
	for _, x := range res.XHR {
		fetch(x)
	}
	for _, r := range res.Routes {
		fetch(r)
	}
	return res, nil
}

// DOMXSS probes a page for DOM-based XSS using headless browser sink
// instrumentation, recording confirmed source->sink flows as issues.
func (s *Service) DOMXSS(ctx context.Context, target string) (*browser.DOMResult, error) {
	res, err := browser.DOMXSS(target, 0)
	if err != nil {
		return nil, err
	}
	for _, h := range res.Hits {
		issue := &scan.Issue{
			Check: "dom-xss", Name: "DOM-based cross-site scripting (" + h.Sink + ")",
			URL: target, Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			Detail:      "A canary placed in the URL reached the dangerous DOM sink " + h.Sink + " without sanitization, indicating DOM-based XSS.",
			Remediation: "Avoid passing URL-derived data to HTML/script sinks; use safe DOM APIs (textContent, setAttribute) and sanitize.",
			Evidence:    h.Value, CWE: "CWE-79",
		}
		if h.Sink == "prototype-pollution" {
			issue.Check = "dom-prototype-pollution"
			issue.Name = "Client-side prototype pollution"
			issue.Detail = "A prototype-pollution gadget in the URL query reached Object.prototype, so a client-side parser merges attacker-controlled keys into object prototypes. This can escalate to DOM XSS or logic bypasses via a gadget."
			issue.Remediation = "Reject __proto__/constructor/prototype keys when merging untrusted input; use Map or null-prototype objects and safe merge helpers."
			issue.CWE = "CWE-1321"
		}
		s.Sess.AddIssues(issue)
	}
	return res, nil
}

// Fuzz runs an Intruder-style attack against the service's upstream client.
func (s *Service) Fuzz(ctx context.Context, spec fuzz.Spec) *fuzz.Result {
	return fuzz.Run(ctx, s.up, spec)
}

// FuzzAttack runs a positional Intruder attack (sniper/battering ram/pitchfork/
// cluster bomb) over a raw request template.
func (s *Service) FuzzAttack(ctx context.Context, a fuzz.Attack) *fuzz.AttackResult {
	return fuzz.RunAttack(ctx, s.up, a)
}

// RunMacro executes a login/session macro and applies the credentials it
// establishes (cookies and/or an extracted token header) to the session, so
// subsequent scanner/crawler/replayer traffic is authenticated.
func (s *Service) RunMacro(ctx context.Context, m macro.Macro) *macro.Result {
	res := macro.Run(ctx, m, s.insecure)
	for k, v := range res.Headers {
		s.Sess.SetAuthHeader(k, v)
	}
	return res
}

// ExportReport renders the session's issues as a report in the given format
// (json, xml, html, or text) and returns it as a string.
func (s *Service) ExportReport(format string) (string, error) {
	rep := report.Build("0.4.0", "session", time.Now(), s.Sess.Issues())
	var b strings.Builder
	var err error
	switch strings.ToLower(format) {
	case "xml":
		err = rep.WriteXML(&b)
	case "html":
		err = rep.WriteHTML(&b)
	case "text", "txt":
		rep.WriteText(&b)
	default:
		err = rep.WriteJSON(&b)
	}
	return b.String(), err
}

// CSRFPoC generates a CSRF proof-of-concept HTML page for a request.
func (s *Service) CSRFPoC(method, url, contentType, body string) string {
	return csrf.Generate(method, url, contentType, body)
}

// ClickjackPoC generates a clickjacking proof-of-concept page framing url.
func (s *Service) ClickjackPoC(url string, opacity float64) string {
	return clickjack.Generate(url, opacity)
}

// Decode applies a Decoder transform.
func (s *Service) Decode(input, op string) (string, error) { return decoder.Transform(input, op) }

// Compare diffs two texts.
func (s *Service) Compare(a, b, mode string) *comparer.Result { return comparer.Compare(a, b, mode) }

// Sequence analyzes token randomness.
func (s *Service) Sequence(tokens []string) *sequencer.Result { return sequencer.Analyze(tokens) }

// SaveProject writes the session snapshot to path as JSON.
func (s *Service) SaveProject(path string) error {
	if err := validateProjectPath(path); err != nil {
		return err
	}
	snap := s.Sess.Export()
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// validateProjectPath guards the project save/load path so a caller (an LLM
// over MCP, or a same-origin API request) cannot read or overwrite arbitrary
// files. It rejects parent-directory traversal and requires a project
// extension, so the path can only ever be an ordinary project file.
func validateProjectPath(path string) error {
	if path == "" {
		return errors.New("project path is required")
	}
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return errors.New("project path must not contain '..'")
	}
	l := strings.ToLower(clean)
	if !strings.HasSuffix(l, ".json") && !strings.HasSuffix(l, ".lanternfish") {
		return errors.New("project files must end in .json or .lanternfish")
	}
	return nil
}

// LoadProject replaces the session state from a JSON project file.
func (s *Service) LoadProject(path string) error {
	if err := validateProjectPath(path); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snap session.Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return err
	}
	s.Sess.Import(&snap)
	return nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
