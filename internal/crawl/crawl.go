// Package crawl is a bounded, scope-aware web crawler. It fetches in-scope
// pages, extracts links and forms, records each transaction in the session
// (so passive checks and the sitemap populate), and returns the discovered
// requests — including form submissions — as scan targets.
//
// HTML is scanned with conservative regexes rather than a full parser to keep
// the build dependency-free; this finds hrefs, src, and forms well enough to
// drive discovery.
package crawl

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"lanternfish/internal/client"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scope"
	"lanternfish/internal/session"
)

var (
	reHref  = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)
	reForm  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	reAttr  = regexp.MustCompile(`(?i)\b(action|method)\s*=\s*["']([^"']*)["']`)
	reInput = regexp.MustCompile(`(?is)<(?:input|textarea|select)\b([^>]*)>`)
	reName  = regexp.MustCompile(`(?i)\bname\s*=\s*["']([^"']+)["']`)
	reValue = regexp.MustCompile(`(?i)\bvalue\s*=\s*["']([^"']*)["']`)
)

// Options bounds the crawl.
type Options struct {
	MaxPages    int
	MaxDepth    int
	Concurrency int
}

// Result summarizes a crawl.
type Result struct {
	Seeds        []string `json:"seeds"`
	PagesVisited int      `json:"pages_visited"`
	URLsFound    []string `json:"urls_found"`
	Forms        int      `json:"forms"`
}

// Crawler performs scope-aware discovery.
type Crawler struct {
	sess  *session.Session
	scope *scope.Scope
	up    *client.Client
	opt   Options
}

// New builds a crawler.
func New(sess *session.Session, insecure bool, opt Options) *Crawler {
	if opt.MaxPages == 0 {
		opt.MaxPages = 100
	}
	if opt.MaxDepth == 0 {
		opt.MaxDepth = 3
	}
	if opt.Concurrency == 0 {
		opt.Concurrency = 6
	}
	return &Crawler{
		sess:  sess,
		scope: sess.Scope,
		up:    client.New(client.Options{InsecureSkipVerify: insecure, FollowRedirects: false}),
		opt:   opt,
	}
}

type item struct {
	u     *url.URL
	depth int
}

// Crawl runs discovery from the seed URLs. Discovered form submissions are
// recorded and their requests returned so an audit can target them.
func (c *Crawler) Crawl(ctx context.Context, seeds []string) (*Result, []*httpmsg.Request) {
	res := &Result{Seeds: seeds}
	var (
		mu      sync.Mutex
		visited = map[string]bool{}
		found   = map[string]bool{}
		reqs    []*httpmsg.Request
	)

	// process fetches one page and returns the in-scope child items it found.
	process := func(it item) []item {
		key := it.u.String()
		mu.Lock()
		if visited[key] || len(visited) >= c.opt.MaxPages {
			mu.Unlock()
			return nil
		}
		visited[key] = true
		mu.Unlock()

		if !c.scope.InScope(it.u) {
			return nil
		}
		hdr := http.Header{"User-Agent": {"lanternfish-crawler"}}
		c.sess.ApplyAuth(hdr)
		req := &httpmsg.Request{
			Method: "GET", URL: it.u, Scheme: it.u.Scheme, Host: it.u.Host,
			Header: hdr,
		}
		resp, err := c.up.Send(ctx, req)
		if err != nil {
			return nil
		}
		c.sess.Add(session.SourceCrawler, &httpmsg.Transaction{Request: req, Response: resp})
		if !strings.Contains(resp.ContentType(), "html") {
			return nil
		}
		body := resp.BodyString()

		var next []item
		for _, m := range reHref.FindAllStringSubmatch(body, -1) {
			ref := strings.TrimSpace(m[1])
			if ref == "" || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") {
				continue
			}
			abs, err := it.u.Parse(ref)
			if err != nil {
				continue
			}
			abs.Fragment = ""
			if !c.scope.InScope(abs) {
				continue
			}
			mu.Lock()
			if !found[abs.String()] {
				found[abs.String()] = true
				res.URLsFound = append(res.URLsFound, abs.String())
			}
			mu.Unlock()
			if it.depth < c.opt.MaxDepth {
				next = append(next, item{u: abs, depth: it.depth + 1})
			}
		}
		for _, fm := range reForm.FindAllStringSubmatch(body, -1) {
			if fr := c.parseForm(it.u, fm[1], fm[2]); fr != nil {
				mu.Lock()
				reqs = append(reqs, fr)
				res.Forms++
				mu.Unlock()
			}
		}
		return next
	}

	// Wave-based BFS: process the whole frontier concurrently, collect the
	// next frontier, and repeat. This waits for in-flight work each wave.
	frontier := make([]item, 0, len(seeds))
	for _, s := range seeds {
		if u, err := url.Parse(s); err == nil {
			frontier = append(frontier, item{u: u, depth: 0})
		}
	}
	sem := make(chan struct{}, c.opt.Concurrency)
	for len(frontier) > 0 {
		mu.Lock()
		stop := len(visited) >= c.opt.MaxPages
		mu.Unlock()
		if stop {
			break
		}
		var wg sync.WaitGroup
		nextCh := make(chan []item, len(frontier))
		for _, it := range frontier {
			wg.Add(1)
			sem <- struct{}{}
			go func(it item) {
				defer wg.Done()
				defer func() { <-sem }()
				nextCh <- process(it)
			}(it)
		}
		wg.Wait()
		close(nextCh)

		seen := map[string]bool{}
		var nextFrontier []item
		for kids := range nextCh {
			for _, k := range kids {
				ks := k.u.String()
				if seen[ks] {
					continue
				}
				seen[ks] = true
				nextFrontier = append(nextFrontier, k)
			}
		}
		frontier = nextFrontier
	}

	res.PagesVisited = len(visited)
	// GET requests with query params are also audit targets.
	mu.Lock()
	for u := range found {
		if pu, err := url.Parse(u); err == nil && pu.RawQuery != "" {
			reqs = append(reqs, &httpmsg.Request{Method: "GET", URL: pu, Scheme: pu.Scheme, Host: pu.Host, Header: http.Header{}})
		}
	}
	mu.Unlock()
	return res, reqs
}

func (c *Crawler) parseForm(base *url.URL, attrs, inner string) *httpmsg.Request {
	method := "GET"
	action := ""
	for _, a := range reAttr.FindAllStringSubmatch(attrs, -1) {
		switch strings.ToLower(a[1]) {
		case "method":
			if strings.EqualFold(a[2], "post") {
				method = "POST"
			}
		case "action":
			action = a[2]
		}
	}
	target := base
	if action != "" {
		if u, err := base.Parse(action); err == nil {
			target = u
		}
	}
	if !c.scope.InScope(target) {
		return nil
	}

	form := url.Values{}
	for _, in := range reInput.FindAllStringSubmatch(inner, -1) {
		nameM := reName.FindStringSubmatch(in[1])
		if nameM == nil {
			continue
		}
		val := "test"
		if vM := reValue.FindStringSubmatch(in[1]); vM != nil && vM[1] != "" {
			val = vM[1]
		}
		form.Set(nameM[1], val)
	}
	if len(form) == 0 {
		return nil
	}

	req := &httpmsg.Request{Method: method, Scheme: target.Scheme, Host: target.Host, Header: http.Header{}}
	if method == "POST" {
		u := *target
		req.URL = &u
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = []byte(form.Encode())
	} else {
		u := *target
		q := u.Query()
		for k, vs := range form {
			q.Set(k, vs[0])
		}
		u.RawQuery = q.Encode()
		req.URL = &u
	}
	return req
}
