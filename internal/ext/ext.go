// Package ext is Lanternfish's extension mechanism. Extensions are external HTTP
// webhooks: each observed transaction is POSTed to them as JSON, and an
// extension may return issues, which are added to the session. This lets users
// add detection logic in any language without recompiling Lanternfish.
package ext

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
	"lanternfish/internal/session"
)

// Extension is a registered webhook.
type Extension struct {
	ID      int64  `json:"id"`
	URL     string `json:"url"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// Manager holds extensions and dispatches transactions to them.
type Manager struct {
	sess *session.Session
	hc   *http.Client
	sem  chan struct{} // bounds concurrent webhook calls

	mu     sync.RWMutex
	nextID int64
	exts   []*Extension
}

// New builds a Manager bound to a session.
func New(sess *session.Session) *Manager {
	return &Manager{
		sess: sess,
		hc:   &http.Client{Timeout: 8 * time.Second},
		sem:  make(chan struct{}, 16), // cap in-flight webhook calls
	}
}

// Add registers an extension webhook.
func (m *Manager) Add(url, name string) *Extension {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	e := &Extension{ID: m.nextID, URL: url, Name: name, Enabled: true}
	m.exts = append(m.exts, e)
	return e
}

// Remove deletes an extension.
func (m *Manager) Remove(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.exts {
		if e.ID == id {
			m.exts = append(m.exts[:i], m.exts[i+1:]...)
			return true
		}
	}
	return false
}

// List returns copies of the extensions.
func (m *Manager) List() []Extension {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Extension, 0, len(m.exts))
	for _, e := range m.exts {
		out = append(out, *e)
	}
	return out
}

func (m *Manager) enabled() []Extension {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Extension
	for _, e := range m.exts {
		if e.Enabled {
			out = append(out, *e)
		}
	}
	return out
}

// txPayload is the JSON POSTed to extensions.
type txPayload struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Host        string      `json:"host"`
	ReqHeaders  http.Header `json:"request_headers"`
	ReqBody     string      `json:"request_body"`
	Status      int         `json:"status"`
	RespHeaders http.Header `json:"response_headers"`
	RespBody    string      `json:"response_body"`
}

// extIssue is the issue shape an extension may return (untrusted input).
type extIssue struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Detail     string `json:"detail"`
	URL        string `json:"url"`
	Param      string `json:"param"`
	Evidence   string `json:"evidence"`
	CWE        string `json:"cwe"`
}

type extReply struct {
	Issues []extIssue `json:"issues"`
}

// Dispatch sends tx to every enabled extension (concurrently, non-blocking for
// the caller) and adds any returned issues to the session.
func (m *Manager) Dispatch(tx *httpmsg.Transaction) {
	exts := m.enabled()
	if len(exts) == 0 {
		return
	}
	payload := txPayload{
		Method: tx.Request.Method, URL: tx.Request.AbsoluteURL().String(), Host: tx.Request.Host,
		ReqHeaders: tx.Request.Header, ReqBody: string(tx.Request.Body),
	}
	if tx.Response != nil {
		payload.Status = tx.Response.StatusCode
		payload.RespHeaders = tx.Response.Header
		payload.RespBody = tx.Response.BodyString()
	}
	body, _ := json.Marshal(payload)
	for _, e := range exts {
		select {
		case m.sem <- struct{}{}: // acquired a slot
			go func(e Extension) { defer func() { <-m.sem }(); m.call(e, body) }(e)
		default:
			// Too many in-flight webhook calls; skip this one rather than
			// spawning unbounded goroutines under heavy traffic.
		}
	}
}

func (m *Manager) call(e Extension, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", e.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.hc.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var reply extReply
	if json.NewDecoder(resp.Body).Decode(&reply) != nil {
		return
	}
	for _, ei := range reply.Issues {
		m.sess.AddIssues(&scan.Issue{
			Check: "ext:" + e.Name, Name: ei.Name,
			Severity: parseSeverity(ei.Severity), Confidence: parseConfidence(ei.Confidence),
			URL: ei.URL, Param: ei.Param, Detail: ei.Detail, Evidence: ei.Evidence, CWE: ei.CWE,
		})
	}
}

func parseSeverity(s string) scan.Severity {
	switch s {
	case "critical":
		return scan.SeverityCritical
	case "high":
		return scan.SeverityHigh
	case "medium":
		return scan.SeverityMedium
	case "low":
		return scan.SeverityLow
	default:
		return scan.SeverityInfo
	}
}

func parseConfidence(s string) scan.Confidence {
	switch s {
	case "certain":
		return scan.ConfidenceCertain
	case "firm":
		return scan.ConfidenceFirm
	default:
		return scan.ConfidenceTentative
	}
}
