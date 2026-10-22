// Package session holds Lanternfish's shared runtime state: the proxy history, a
// derived sitemap, discovered issues, the target scope, and the interception
// hold-queue. Both the web GUI/API and the MCP server operate on one Session,
// so an LLM and a human see the same live state.
package session

import (
	"net/http"
	"sort"
	"sync"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
	"lanternfish/internal/scope"
)

// Source labels where a transaction came from.
type Source string

const (
	SourceProxy    Source = "proxy"
	SourceRepeater Source = "repeater"
	SourceScanner  Source = "scanner"
	SourceCrawler  Source = "crawler"
)

// Record is one history entry.
type Record struct {
	ID       int64                `json:"id"`
	Source   Source               `json:"source"`
	Request  *httpmsg.Request     `json:"-"`
	Response *httpmsg.Response    `json:"-"`
	Time     time.Time            `json:"time"`
	Tx       *httpmsg.Transaction `json:"-"`
	Note     string               `json:"note,omitempty"`
	Flagged  bool                 `json:"flagged,omitempty"`
}

// SetNote attaches a note to a history record (organizer). Returns false if the
// id is unknown.
func (s *Session) SetNote(id int64, note string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.history {
		if r.ID == id {
			r.Note = note
			return true
		}
	}
	return false
}

// Flag marks or unmarks a history record for later review (organizer).
func (s *Session) Flag(id int64, flagged bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.history {
		if r.ID == id {
			r.Flagged = flagged
			return true
		}
	}
	return false
}

// Flagged returns the records that are flagged or have a note, newest first.
func (s *Session) FlaggedRecords() []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Record
	for i := len(s.history) - 1; i >= 0; i-- {
		if s.history[i].Flagged || s.history[i].Note != "" {
			out = append(out, s.history[i])
		}
	}
	return out
}

// Session is the shared state container.
type Session struct {
	Scope     *scope.Scope
	Intercept *Intercept
	Rewrite   *Rewriter
	WS        *WSLog

	mu      sync.RWMutex
	nextID  int64
	history []*Record
	issues  *scan.Collector
	auth    map[string]string // headers injected into tool-originated requests
}

// New builds an empty session.
func New() *Session {
	return &Session{
		Scope:     scope.New(),
		Intercept: newIntercept(),
		Rewrite:   newRewriter(),
		WS:        newWSLog(),
		issues:    scan.NewCollector(),
		auth:      map[string]string{},
	}
}

// SetAuthHeader sets (or with empty value, deletes) a header injected into
// scanner/crawler/replayer requests for authenticated testing.
func (s *Session) SetAuthHeader(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value == "" {
		delete(s.auth, name)
		return
	}
	s.auth[name] = value
}

// AuthHeaders returns a copy of the injected headers.
func (s *Session) AuthHeaders() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.auth))
	for k, v := range s.auth {
		out[k] = v
	}
	return out
}

// ApplyAuth adds the session's auth headers to h (without overwriting ones
// already set on the request).
func (s *Session) ApplyAuth(h http.Header) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.auth {
		if h.Get(k) == "" {
			h.Set(k, v)
		}
	}
}

// MaxHistory bounds how many transactions are retained in memory; the oldest
// are evicted beyond this so a long-running session cannot exhaust memory.
const MaxHistory = 100000

// Add records a completed transaction and returns its assigned record.
func (s *Session) Add(src Source, tx *httpmsg.Transaction) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	rec := &Record{
		ID: s.nextID, Source: src,
		Request: tx.Request, Response: tx.Response,
		Time: time.Now(), Tx: tx,
	}
	tx.Request.ID = s.nextID
	s.history = append(s.history, rec)
	if len(s.history) > MaxHistory {
		// Drop the oldest, keeping a stable slice without leaking the backing array.
		s.history = append([]*Record(nil), s.history[len(s.history)-MaxHistory:]...)
	}
	return rec
}

// History returns up to limit most-recent records (0 = all), newest first.
func (s *Session) History(limit int) []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Record, len(s.history))
	copy(out, s.history)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Get returns the record with the given id, or nil.
func (s *Session) Get(id int64) *Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.history {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// AddIssues records scan issues (de-duplicated by the collector).
func (s *Session) AddIssues(issues ...*scan.Issue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issues.Add(issues...)
}

// Issues returns the collected issues, most-severe first.
func (s *Session) Issues() []*scan.Issue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.issues.Issues()
}

// SiteNode is a host/path node in the derived sitemap.
type SiteNode struct {
	Host    string         `json:"host"`
	Paths   map[string]int `json:"paths"` // path -> last status code
	Methods map[string]int `json:"methods"`
}

// SiteMap derives a host/path tree from history.
func (s *Session) SiteMap() map[string]*SiteNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tree := map[string]*SiteNode{}
	for _, r := range s.history {
		u := r.Request.AbsoluteURL()
		host := u.Scheme + "://" + u.Host
		node := tree[host]
		if node == nil {
			node = &SiteNode{Host: host, Paths: map[string]int{}, Methods: map[string]int{}}
			tree[host] = node
		}
		code := 0
		if r.Response != nil {
			code = r.Response.StatusCode
		}
		node.Paths[u.Path] = code
		node.Methods[r.Request.Method]++
	}
	return tree
}

// Stats returns quick counts for dashboards.
func (s *Session) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]int{
		"history":    len(s.history),
		"issues":     len(s.issues.Issues()),
		"pending":    s.Intercept.PendingCount(),
		"websockets": s.WS.Count(),
	}
}
