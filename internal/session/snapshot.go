package session

import (
	"net/http"
	"net/url"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
	"lanternfish/internal/scope"
)

// recordSnap is the serializable form of one history record.
type recordSnap struct {
	ID         int64       `json:"id"`
	Source     string      `json:"source"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Scheme     string      `json:"scheme"`
	Host       string      `json:"host"`
	ReqHeaders http.Header `json:"req_headers"`
	ReqBody    []byte      `json:"req_body"`
	Status     int         `json:"status"`
	RespProto  string      `json:"resp_proto"`
	RespStatus string      `json:"resp_status"`
	RespHdr    http.Header `json:"resp_headers"`
	RespBody   []byte      `json:"resp_body"`
	Time       time.Time   `json:"time"`
	HasResp    bool        `json:"has_resp"`
}

// Snapshot is the full serializable session state.
type Snapshot struct {
	Version  int           `json:"version"`
	Records  []recordSnap  `json:"records"`
	Issues   []*scan.Issue `json:"issues"`
	ScopeInc []scope.Rule  `json:"scope_includes"`
	ScopeExc []scope.Rule  `json:"scope_excludes"`
}

// Export captures the current state as a serializable snapshot.
func (s *Session) Export() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := &Snapshot{Version: 1}
	for _, r := range s.history {
		rs := recordSnap{
			ID: r.ID, Source: string(r.Source),
			Method: r.Request.Method, URL: r.Request.AbsoluteURL().String(),
			Scheme: r.Request.Scheme, Host: r.Request.Host,
			ReqHeaders: r.Request.Header, ReqBody: r.Request.Body,
			Time: r.Time,
		}
		if r.Response != nil {
			rs.HasResp = true
			rs.Status = r.Response.StatusCode
			rs.RespProto = r.Response.Proto
			rs.RespStatus = r.Response.Status
			rs.RespHdr = r.Response.Header
			rs.RespBody = r.Response.Body
		}
		snap.Records = append(snap.Records, rs)
	}
	snap.Issues = s.issues.Issues()
	snap.ScopeInc, snap.ScopeExc = s.Scope.Rules()
	return snap
}

// Import replaces the session state with a snapshot.
func (s *Session) Import(snap *Snapshot) {
	s.mu.Lock()
	s.history = nil
	s.nextID = 0
	s.issues = scan.NewCollector()
	for _, rs := range snap.Records {
		u, _ := url.Parse(rs.URL)
		req := &httpmsg.Request{
			ID: rs.ID, Method: rs.Method, URL: u, Scheme: rs.Scheme, Host: rs.Host,
			Header: rs.ReqHeaders, Body: rs.ReqBody, Received: rs.Time,
		}
		var resp *httpmsg.Response
		if rs.HasResp {
			resp = &httpmsg.Response{
				Proto: rs.RespProto, Status: rs.RespStatus, StatusCode: rs.Status,
				Header: rs.RespHdr, Body: rs.RespBody,
			}
		}
		rec := &Record{ID: rs.ID, Source: Source(rs.Source), Request: req, Response: resp, Time: rs.Time,
			Tx: &httpmsg.Transaction{Request: req, Response: resp}}
		s.history = append(s.history, rec)
		if rs.ID > s.nextID {
			s.nextID = rs.ID
		}
	}
	s.issues.Add(snap.Issues...)
	s.mu.Unlock()

	s.Scope.Clear()
	for _, r := range snap.ScopeInc {
		s.Scope.Include(r.Host, r.PathPrefix)
	}
	for _, r := range snap.ScopeExc {
		s.Scope.Exclude(r.Host, r.PathPrefix)
	}
}
