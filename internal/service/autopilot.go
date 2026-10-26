package service

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"lanternfish/internal/browser"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// AutopilotParams drives a hands-off end-to-end assessment of a target.
type AutopilotParams struct {
	Target   string `json:"target"`    // seed URL
	Fast     bool   `json:"fast"`      // skip wait-heavy checks
	Browser  bool   `json:"browser"`   // headless crawl + DOM-XSS when a browser is present
	MaxPages int    `json:"max_pages"` // crawl page budget (default 100)
	MaxDepth int    `json:"max_depth"` // crawl link depth (default 3)
}

// AutopilotPhase records the outcome of one stage of the pipeline.
type AutopilotPhase struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | skipped | error
	Detail string `json:"detail"`
}

// AutopilotResult summarizes everything the pipeline did and found.
type AutopilotResult struct {
	Target          string           `json:"target"`
	Phases          []AutopilotPhase `json:"phases"`
	PagesCrawled    int              `json:"pages_crawled"`
	RequestsAudited int              `json:"requests_audited"`
	Issues          []*scan.Issue    `json:"issues"`
	Counts          map[string]int   `json:"counts"` // issues by severity
	Duration        string           `json:"duration"`
}

// Autopilot runs the full workflow against one target with no manual steps:
// it scopes to the target, enables out-of-band checks, scans the seed, crawls
// and audits every in-scope request it finds, optionally drives a headless
// browser for JavaScript-rendered endpoints and DOM-XSS, then reports every
// issue found. The same method backs the CLI `auto` command, the REST
// /api/auto endpoint, and the MCP auto_scan tool, so a human, a script, and an
// LLM all get identical behavior.
func (s *Service) Autopilot(ctx context.Context, p AutopilotParams) (*AutopilotResult, error) {
	u, err := url.Parse(p.Target)
	if err != nil {
		return nil, err
	}
	if p.MaxPages <= 0 {
		p.MaxPages = 100
	}
	if p.MaxDepth <= 0 {
		p.MaxDepth = 3
	}
	start := time.Now()
	res := &AutopilotResult{Target: p.Target, Counts: map[string]int{}}
	add := func(name, status, detail string) {
		res.Phases = append(res.Phases, AutopilotPhase{Name: name, Status: status, Detail: detail})
	}

	// 1. Scope to the target host so the crawl and browser stay on-target.
	s.Sess.Scope.Include(u.Hostname(), "")
	add("scope", "ok", "limited to host "+u.Hostname())

	// 2. Enable out-of-band checks for the whole run (unless fast).
	if p.Fast {
		add("out-of-band", "skipped", "fast mode skips blind/out-of-band checks")
	} else {
		s.EnsureOAST()
		if s.OAST != nil {
			add("out-of-band", "ok", "listener on "+s.OAST.Advertised())
		} else {
			add("out-of-band", "error", "listener unavailable; blind checks limited")
		}
	}

	// 3. Scan the seed URL itself (passive + active on its own parameters).
	if sr, err := s.ScanURLMode(ctx, p.Target, p.Fast); err != nil {
		add("scan-seed", "error", err.Error())
	} else {
		res.RequestsAudited++
		add("scan-seed", "ok", pluralIssues(len(sr.Issues))+" on the seed")
	}

	// 4. Crawl in-scope and audit every discovered request.
	cr := s.Crawl(ctx, CrawlParams{Seeds: []string{p.Target}, MaxPages: p.MaxPages, MaxDepth: p.MaxDepth, Audit: true})
	res.PagesCrawled = cr.PagesVisited
	res.RequestsAudited += cr.PagesVisited
	add("crawl+audit", "ok", crawlDetail(cr))

	// 5. Optional headless-browser crawl + DOM-XSS.
	if p.Browser {
		if !browser.Available() {
			add("browser-crawl", "skipped", "no headless Chrome/Edge found")
			add("dom-xss", "skipped", "no headless Chrome/Edge found")
		} else {
			var br *browser.Result
			if b, err := s.BrowserCrawl(ctx, p.Target); err != nil {
				add("browser-crawl", "error", err.Error())
			} else {
				br = b
				n := s.auditBrowserFindings(ctx, br, p.Fast)
				res.RequestsAudited += n
				add("browser-crawl", "ok", browserDetail(br, n))
			}
			// Probe the seed and every discovered SPA route/query-bearing URL:
			// a single-page app's dangerous sink usually lives on a client-side
			// route, not the landing page.
			targets := s.DOMProbeTargets(br, p.Target, domProbeBudget(p.Fast))
			hits, failed := 0, 0
			for _, t := range targets {
				if ctx.Err() != nil {
					break
				}
				if dr, err := s.DOMXSS(ctx, t); err != nil {
					failed++
				} else {
					hits += len(dr.Hits)
				}
			}
			detail := pluralIssues(hits) + " across " + strconv.Itoa(len(targets)) + " route(s)"
			if failed > 0 {
				detail += " (" + strconv.Itoa(failed) + " failed)"
			}
			add("dom-xss", "ok", detail)
		}
	}

	// 6. Aggregate every issue recorded in the session this run.
	res.Issues = s.Sess.Issues()
	for _, is := range res.Issues {
		res.Counts[is.SeverityStr]++
	}
	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res, nil
}

// auditBrowserFindings actively audits the in-scope links and XHR/fetch
// endpoints a headless crawl surfaced, deduplicated. Returns the count audited.
func (s *Service) auditBrowserFindings(ctx context.Context, br *browser.Result, fast bool) int {
	eng := s.eng
	if fast {
		eng = s.engFast
	}
	seen := map[string]bool{}
	count := 0
	audit := func(raw string) {
		if ctx.Err() != nil || count >= 200 {
			return
		}
		pu, err := url.Parse(raw)
		if err != nil || !pu.IsAbs() || seen[pu.String()] || !s.Sess.Scope.InScope(pu) {
			return
		}
		seen[pu.String()] = true
		req := &httpmsg.Request{Method: "GET", URL: pu, Scheme: pu.Scheme, Host: pu.Host, Header: http.Header{"User-Agent": {"lanternfish"}}}
		s.Sess.ApplyAuth(req.Header)
		col := scan.NewCollector()
		eng.Audit(s.auditCtx(ctx, fast), s.up, req, col)
		s.Sess.AddIssues(col.Issues()...)
		count++
	}
	for _, l := range br.Links {
		audit(l)
	}
	for _, x := range br.XHR {
		audit(x)
	}
	return count
}

// auditCtx returns a scan context carrying the OAST interactor in full mode.
func (s *Service) auditCtx(ctx context.Context, fast bool) context.Context {
	if fast {
		return ctx
	}
	return s.scanCtx(ctx)
}

// ---- live auto-audit of observed proxy traffic ("send to scanner" automated) ----

// liveAudit holds the toggle and dedup/bound state for auto-auditing traffic
// seen through the proxy. It is safe for concurrent use.
type liveAudit struct {
	mu   sync.Mutex
	on   bool
	seen map[string]bool
	sem  chan struct{}
}

// SetLiveAudit turns automatic active auditing of in-scope proxy traffic on or
// off. When on, every in-scope request observed through the proxy is scanned in
// the background, so browsing a target drives the scanner with no manual "send
// to scanner" step. It requires a narrowed scope (an include rule) and refuses
// to enable otherwise, so it can never audit arbitrary third-party sites.
func (s *Service) SetLiveAudit(on bool) error {
	if on && !s.Sess.Scope.HasIncludes() {
		return errNoScope
	}
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	s.live.on = on
	if on {
		if s.live.seen == nil {
			s.live.seen = map[string]bool{}
		}
		if s.live.sem == nil {
			s.live.sem = make(chan struct{}, 8)
		}
		s.EnsureOAST()
	}
	return nil
}

// LiveAuditEnabled reports whether live auto-audit is on.
func (s *Service) LiveAuditEnabled() bool {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	return s.live.on
}

// MaybeAudit audits a transaction's request in the background when live
// auto-audit is on, the request is in scope, and it has not already been
// audited (keyed by method+URL). Non-blocking: it drops work when the bounded
// worker pool is saturated. Wire it onto proxy.OnTransaction.
func (s *Service) MaybeAudit(tx *httpmsg.Transaction) {
	if tx == nil || tx.Request == nil {
		return
	}
	s.live.mu.Lock()
	if !s.live.on || !s.Sess.Scope.InScope(tx.Request.AbsoluteURL()) {
		s.live.mu.Unlock()
		return
	}
	key := tx.Request.Method + " " + tx.Request.AbsoluteURL().String()
	if s.live.seen[key] {
		s.live.mu.Unlock()
		return
	}
	s.live.seen[key] = true
	sem := s.live.sem
	s.live.mu.Unlock()

	req := tx.Request.Clone()
	select {
	case sem <- struct{}{}:
	default:
		return // pool saturated; skip to keep browsing responsive
	}
	go func() {
		defer func() { <-sem }()
		s.AuditRequest(context.Background(), req)
	}()
}

func pluralIssues(n int) string {
	if n == 1 {
		return "1 issue"
	}
	return itoa(n) + " issues"
}

func crawlDetail(cr *CrawlResult) string {
	return itoa(cr.PagesVisited) + " pages, " + itoa(len(cr.URLsFound)) + " URLs, " +
		itoa(cr.Forms) + " forms; " + pluralIssues(cr.IssuesFound) + " while auditing"
}

// domProbeBudget caps how many URLs the DOM-XSS stage loads in a headless
// browser. Each probe costs a page load plus a settle window, so --fast keeps
// it small; a normal run trades time for coverage of a SPA's routes.
func domProbeBudget(fast bool) int {
	if fast {
		return 8
	}
	return 25
}

func browserDetail(br *browser.Result, audited int) string {
	return itoa(len(br.Links)) + " links, " + itoa(len(br.XHR)) + " XHR; audited " + itoa(audited)
}

// errNoScope is returned when live auto-audit is requested without a scope.
var errNoScope = &scopeError{}

type scopeError struct{}

func (*scopeError) Error() string {
	return "live auto-audit needs a scope: add an include rule (e.g. the target host) first"
}

func itoa(n int) string { return strconv.Itoa(n) }
