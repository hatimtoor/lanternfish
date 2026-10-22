// Package api exposes the session over a small REST interface and serves the
// embedded web GUI. The same operations are available to the MCP server, so
// the human UI and an LLM share one engine and one live state.
package api

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"lanternfish/internal/fuzz"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/kb"
	"lanternfish/internal/macro"
	"lanternfish/internal/service"
	"lanternfish/internal/session"
)

//go:embed web/*
var webFS embed.FS

// Server is the HTTP API + GUI server.
type Server struct {
	svc *service.Service
	mux *http.ServeMux
}

// New builds the API server.
func New(svc *service.Service) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the root http.Handler, wrapped with a same-origin guard that
// blocks cross-site requests (CSRF / DNS-rebinding) and a body-size cap that
// bounds memory against oversized request bodies to the local API.
func (s *Server) Handler() http.Handler {
	return originGuard(http.MaxBytesHandler(s.mux, 64<<20))
}

// originGuard rejects requests carrying a cross-origin Origin header. Browsers
// set Origin on cross-site requests, so this stops a malicious web page (or a
// DNS-rebinding attack) from driving the local API while leaving same-origin
// GUI calls and non-browser clients (no Origin) unaffected.
func originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "lanternfish: cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/stats", s.stats)
	s.mux.HandleFunc("GET /api/history", s.history)
	s.mux.HandleFunc("GET /api/history/{id}", s.historyDetail)
	s.mux.HandleFunc("POST /api/history/{id}/note", s.setNote)
	s.mux.HandleFunc("POST /api/history/{id}/flag", s.setFlag)
	s.mux.HandleFunc("GET /api/organizer", s.organizer)
	s.mux.HandleFunc("GET /api/scope/test", s.scopeTest)
	s.mux.HandleFunc("GET /api/schedule", s.listSchedules)
	s.mux.HandleFunc("POST /api/schedule", s.postSchedule)
	s.mux.HandleFunc("POST /api/replay", s.replay)
	s.mux.HandleFunc("POST /api/scan", s.scan)
	s.mux.HandleFunc("POST /api/auto", s.auto)
	s.mux.HandleFunc("GET /api/explain", s.explain)
	s.mux.HandleFunc("GET /api/live-audit", s.getLiveAudit)
	s.mux.HandleFunc("POST /api/live-audit", s.postLiveAudit)
	s.mux.HandleFunc("POST /api/crawl", s.crawl)
	s.mux.HandleFunc("POST /api/browser-crawl", s.browserCrawl)
	s.mux.HandleFunc("POST /api/dom-xss", s.domXSS)
	s.mux.HandleFunc("POST /api/fuzz", s.fuzz)
	s.mux.HandleFunc("POST /api/intruder", s.intruder)
	s.mux.HandleFunc("POST /api/decode", s.decode)
	s.mux.HandleFunc("POST /api/compare", s.compare)
	s.mux.HandleFunc("POST /api/sequence", s.sequence)
	s.mux.HandleFunc("POST /api/macro", s.macro)
	s.mux.HandleFunc("GET /api/report", s.report)
	s.mux.HandleFunc("POST /api/csrf-poc", s.csrfPoC)
	s.mux.HandleFunc("POST /api/clickjack-poc", s.clickjackPoC)
	s.mux.HandleFunc("POST /api/project/save", s.saveProject)
	s.mux.HandleFunc("POST /api/project/load", s.loadProject)
	s.mux.HandleFunc("GET /api/issues", s.issues)
	s.mux.HandleFunc("GET /api/interactions", s.interactions)
	s.mux.HandleFunc("GET /api/websockets", s.websockets)
	s.mux.HandleFunc("GET /api/sitemap", s.sitemap)
	s.mux.HandleFunc("GET /api/scope", s.getScope)
	s.mux.HandleFunc("POST /api/scope", s.postScope)
	s.mux.HandleFunc("GET /api/auth", s.getAuth)
	s.mux.HandleFunc("POST /api/auth", s.postAuth)
	s.mux.HandleFunc("GET /api/rewrite", s.getRewrite)
	s.mux.HandleFunc("POST /api/rewrite", s.postRewrite)
	s.mux.HandleFunc("GET /api/extensions", s.getExtensions)
	s.mux.HandleFunc("POST /api/extensions", s.postExtensions)
	s.mux.HandleFunc("GET /api/intercept", s.getIntercept)
	s.mux.HandleFunc("POST /api/intercept/toggle", s.toggleIntercept)
	s.mux.HandleFunc("POST /api/intercept/{id}/forward", s.forwardIntercept)
	s.mux.HandleFunc("POST /api/intercept/{id}/drop", s.dropIntercept)

	sub, _ := fs.Sub(webFS, "web")
	s.mux.Handle("/", http.FileServer(http.FS(sub)))
}

// ---- DTOs ----

type recordDTO struct {
	ID     int64  `json:"id"`
	Source string `json:"source"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Status int    `json:"status"`
	Length int    `json:"length"`
	MIME   string `json:"mime"`
	Time   string `json:"time"`
}

func toRecordDTO(r *session.Record) recordDTO {
	d := recordDTO{
		ID: r.ID, Source: string(r.Source),
		Method: r.Request.Method, URL: r.Request.AbsoluteURL().String(),
		Host: r.Request.Host, Time: r.Time.Format("15:04:05"),
	}
	if r.Response != nil {
		d.Status = r.Response.StatusCode
		d.Length = len(r.Response.Body)
		d.MIME = r.Response.ContentType()
	}
	return d
}

type detailDTO struct {
	recordDTO
	RequestRaw  string              `json:"request_raw"`
	RespHeaders map[string][]string `json:"response_headers"`
	RespBody    string              `json:"response_body"`
}

// ---- handlers ----

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Sess.Stats())
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	recs := s.svc.Sess.History(limit)
	out := make([]recordDTO, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toRecordDTO(rec))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) historyDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rec := s.svc.Sess.Get(id)
	if rec == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	d := detailDTO{recordDTO: toRecordDTO(rec), RequestRaw: rec.Request.DumpRequestLine() + "\n" + string(rec.Request.Body)}
	if rec.Response != nil {
		d.RespHeaders = rec.Response.Header
		d.RespBody = rec.Response.BodyString()
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) replay(w http.ResponseWriter, r *http.Request) {
	var p service.ReplayParams
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := s.svc.Replay(r.Context(), p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.historyDetailByRecord(w, rec)
}

func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	var p struct {
		URL  string `json:"url"`
		Fast bool   `json:"fast"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !p.Fast {
		s.svc.EnsureOAST() // enable blind/out-of-band checks for full scans
	}
	res, err := s.svc.ScanURLMode(r.Context(), p.URL, p.Fast)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	check := r.URL.Query().Get("check")
	if check == "" {
		writeJSON(w, http.StatusOK, map[string]any{"checks": kb.Keys()})
		return
	}
	e, ok := kb.Lookup(check)
	if !ok {
		http.Error(w, "no explanation for "+check, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) auto(w http.ResponseWriter, r *http.Request) {
	var p service.AutopilotParams
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if p.Target == "" {
		http.Error(w, "target required", http.StatusBadRequest)
		return
	}
	res, err := s.svc.Autopilot(r.Context(), p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) getLiveAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": s.svc.LiveAuditEnabled()})
}

func (s *Server) postLiveAudit(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.svc.SetLiveAudit(p.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": s.svc.LiveAuditEnabled()})
}

func (s *Server) crawl(w http.ResponseWriter, r *http.Request) {
	var p service.CrawlParams
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(p.Seeds) == 0 {
		http.Error(w, "seeds required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.svc.Crawl(r.Context(), p))
}

func (s *Server) browserCrawl(w http.ResponseWriter, r *http.Request) {
	var p struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	res, err := s.svc.BrowserCrawl(r.Context(), p.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) domXSS(w http.ResponseWriter, r *http.Request) {
	var p struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	res, err := s.svc.DOMXSS(r.Context(), p.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) fuzz(w http.ResponseWriter, r *http.Request) {
	var spec fuzz.Spec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if spec.URL == "" || len(spec.Payloads) == 0 {
		http.Error(w, "url and payloads required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.svc.Fuzz(r.Context(), spec))
}

func (s *Server) intruder(w http.ResponseWriter, r *http.Request) {
	var a fuzz.Attack
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if a.Template == "" {
		http.Error(w, "template required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.svc.FuzzAttack(r.Context(), a))
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request) {
	var p struct{ Input, Op string }
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, err := s.svc.Decode(p.Input, p.Op)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": out})
}

func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	var p struct{ A, B, Mode string }
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.svc.Compare(p.A, p.B, p.Mode))
}

func (s *Server) sequence(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Tokens []string `json:"tokens"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.svc.Sequence(p.Tokens))
}

func (s *Server) macro(w http.ResponseWriter, r *http.Request) {
	var m macro.Macro
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(m.Steps) == 0 {
		http.Error(w, "at least one step required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.svc.RunMacro(r.Context(), m))
}

func (s *Server) setNote(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var p struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)
	if !s.svc.Sess.SetNote(id, p.Note) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "note": p.Note})
}

func (s *Server) setFlag(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var p struct {
		Flagged bool `json:"flagged"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)
	if !s.svc.Sess.Flag(id, p.Flagged) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "flagged": p.Flagged})
}

func (s *Server) organizer(w http.ResponseWriter, r *http.Request) {
	recs := s.svc.Sess.FlaggedRecords()
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]any{
			"id": rec.ID, "method": rec.Request.Method, "url": rec.Request.AbsoluteURL().String(),
			"note": rec.Note, "flagged": rec.Flagged,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) scopeTest(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		writeJSON(w, http.StatusOK, map[string]any{"url": raw, "valid": false, "error": "not an absolute URL"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"url": raw, "valid": true, "in_scope": s.svc.Sess.Scope.InScope(u)})
}

func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Schedules())
}

func (s *Server) postSchedule(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Action      string `json:"action"`
		ID          int64  `json:"id"`
		URL         string `json:"url"`
		IntervalSec int    `json:"interval_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch p.Action {
	case "remove":
		s.svc.Unschedule(p.ID)
	default:
		if p.URL == "" {
			http.Error(w, "url required", http.StatusBadRequest)
			return
		}
		s.svc.Schedule(p.URL, p.IntervalSec)
	}
	writeJSON(w, http.StatusOK, s.svc.Schedules())
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	out, err := s.svc.ExportReport(format)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch strings.ToLower(format) {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case "xml":
		w.Header().Set("Content-Type", "application/xml")
	case "text", "txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/json")
	}
	_, _ = io.WriteString(w, out)
}

func (s *Server) csrfPoC(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Method      string `json:"method"`
		URL         string `json:"url"`
		ContentType string `json:"content_type"`
		Body        string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"html": s.svc.CSRFPoC(p.Method, p.URL, p.ContentType, p.Body)})
}

func (s *Server) clickjackPoC(w http.ResponseWriter, r *http.Request) {
	var p struct {
		URL     string  `json:"url"`
		Opacity float64 `json:"opacity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"html": s.svc.ClickjackPoC(p.URL, p.Opacity)})
}

func (s *Server) saveProject(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Path string `json:"path"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)
	if p.Path == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}
	if err := s.svc.SaveProject(p.Path); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": p.Path})
}

func (s *Server) loadProject(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Path string `json:"path"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)
	if err := s.svc.LoadProject(p.Path); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loaded": p.Path})
}

func (s *Server) issues(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Sess.Issues())
}

func (s *Server) websockets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Sess.WS.Messages(1000))
}

func (s *Server) interactions(w http.ResponseWriter, r *http.Request) {
	if s.svc.OAST == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "base": s.svc.OAST.Advertised(), "interactions": s.svc.OAST.All()})
}

func (s *Server) sitemap(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Sess.SiteMap())
}

func (s *Server) getScope(w http.ResponseWriter, r *http.Request) {
	inc, exc := s.svc.Sess.Scope.Rules()
	writeJSON(w, http.StatusOK, map[string]any{"includes": inc, "excludes": exc})
}

func (s *Server) postScope(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Action     string `json:"action"` // include | exclude | clear
		Host       string `json:"host"`
		PathPrefix string `json:"path_prefix"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch p.Action {
	case "include":
		s.svc.Sess.Scope.Include(p.Host, p.PathPrefix)
	case "exclude":
		s.svc.Sess.Scope.Exclude(p.Host, p.PathPrefix)
	case "clear":
		s.svc.Sess.Scope.Clear()
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	s.getScope(w, r)
}

func (s *Server) getAuth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Sess.AuthHeaders())
}

func (s *Server) postAuth(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	s.svc.Sess.SetAuthHeader(p.Name, p.Value)
	writeJSON(w, http.StatusOK, s.svc.Sess.AuthHeaders())
}

type pendingDTO struct {
	ID         int64  `json:"id"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	RequestRaw string `json:"request_raw"`
}

func (s *Server) getExtensions(w http.ResponseWriter, r *http.Request) {
	if s.svc.Ext == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.svc.Ext.List())
}

func (s *Server) postExtensions(w http.ResponseWriter, r *http.Request) {
	if s.svc.Ext == nil {
		http.Error(w, "extensions unavailable", http.StatusServiceUnavailable)
		return
	}
	var p struct {
		Action string `json:"action"` // add | remove
		ID     int64  `json:"id"`
		URL    string `json:"url"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch p.Action {
	case "add":
		if p.URL == "" {
			http.Error(w, "url required", http.StatusBadRequest)
			return
		}
		name := p.Name
		if name == "" {
			name = "ext"
		}
		s.svc.Ext.Add(p.URL, name)
	case "remove":
		s.svc.Ext.Remove(p.ID)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.svc.Ext.List())
}

func (s *Server) getRewrite(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Sess.Rewrite.List())
}

func (s *Server) postRewrite(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Action      string `json:"action"` // add | remove | toggle
		ID          int64  `json:"id"`
		Target      string `json:"target"`
		Pattern     string `json:"pattern"`
		Replacement string `json:"replacement"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch p.Action {
	case "add":
		if _, err := s.svc.Sess.Rewrite.Add(p.Target, p.Pattern, p.Replacement, true); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "remove":
		s.svc.Sess.Rewrite.Remove(p.ID)
	case "toggle":
		s.svc.Sess.Rewrite.Toggle(p.ID, p.Enabled)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.svc.Sess.Rewrite.List())
}

func (s *Server) getIntercept(w http.ResponseWriter, r *http.Request) {
	ic := s.svc.Sess.Intercept
	pend := ic.List()
	out := make([]pendingDTO, 0, len(pend))
	for _, p := range pend {
		out = append(out, pendingDTO{
			ID: p.ID, Method: p.Request.Method, URL: p.Request.AbsoluteURL().String(),
			RequestRaw: p.Request.DumpRequestLine() + "\n" + string(p.Request.Body),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": ic.Enabled(), "pending": out})
}

func (s *Server) toggleIntercept(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)
	s.svc.Sess.Intercept.SetEnabled(p.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.svc.Sess.Intercept.Enabled()})
}

func (s *Server) forwardIntercept(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var p struct {
		Raw string `json:"raw"`
	}
	_ = json.NewDecoder(r.Body).Decode(&p)
	pend := s.svc.Sess.Intercept.Peek(id)
	if pend == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var modified *httpmsg.Request
	if strings.TrimSpace(p.Raw) != "" {
		orig := pend.Request
		m, err := httpmsg.ParseRawRequest([]byte(p.Raw), orig.Scheme, orig.Host)
		if err != nil {
			http.Error(w, "parse edited request: "+err.Error(), http.StatusBadRequest)
			return
		}
		modified = m
	}
	if !s.svc.Sess.Intercept.Forward(id, modified) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"forwarded": id})
}

func (s *Server) dropIntercept(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if !s.svc.Sess.Intercept.Drop(id) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dropped": id})
}

func (s *Server) historyDetailByRecord(w http.ResponseWriter, rec *session.Record) {
	d := detailDTO{recordDTO: toRecordDTO(rec), RequestRaw: rec.Request.DumpRequestLine() + "\n" + string(rec.Request.Body)}
	if rec.Response != nil {
		d.RespHeaders = rec.Response.Header
		d.RespBody = rec.Response.BodyString()
	}
	writeJSON(w, http.StatusOK, d)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
