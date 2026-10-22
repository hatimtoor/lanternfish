// Package mcp exposes the Lanternfish engine as a Model Context Protocol server over
// stdio, so an LLM agent can drive the proxy session, scanner, and replayer as
// tools. It speaks newline-delimited JSON-RPC 2.0 (the MCP stdio transport) and
// uses only the standard library.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	neturl "net/url"

	"lanternfish/internal/fuzz"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/kb"
	"lanternfish/internal/macro"
	"lanternfish/internal/service"
)

const protocolVersion = "2024-11-05"

// Server is an MCP stdio server over a shared service.
type Server struct {
	svc *service.Service
	in  *bufio.Reader
	out io.Writer
}

// New builds an MCP server reading from in and writing to out.
func New(svc *service.Service, in io.Reader, out io.Writer) *Server {
	br := bufio.NewReader(in)
	return &Server{svc: svc, in: br, out: out}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve runs the read/dispatch loop until EOF.
func (s *Server) Serve(ctx context.Context) error {
	// Allow long lines (large request/response bodies).
	buf := make([]byte, 0, 1024*1024)
	sc := bufio.NewScanner(s.in)
	sc.Buffer(buf, 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.send(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		s.dispatch(ctx, &req)
	}
	return sc.Err()
}

func (s *Server) dispatch(ctx context.Context, req *rpcRequest) {
	switch req.Method {
	case "initialize":
		s.reply(req, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "lanternfish", "version": "0.2.0"},
		})
	case "notifications/initialized":
		// notification: no response
	case "ping":
		s.reply(req, map[string]any{})
	case "tools/list":
		s.reply(req, map[string]any{"tools": toolDefs})
	case "tools/call":
		s.toolsCall(ctx, req)
	default:
		if len(req.ID) > 0 {
			s.send(rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}})
		}
	}
}

func (s *Server) reply(req *rpcRequest, result any) {
	if len(req.ID) == 0 {
		return // notification
	}
	s.send(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
}

func (s *Server) send(resp rpcResponse) {
	b, _ := json.Marshal(resp)
	b = append(b, '\n')
	_, _ = s.out.Write(b)
}

// toolResult wraps text content per MCP tools/call result shape.
func toolResult(text string, isErr bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	}
}

func jsonText(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("marshal error: %v", err)
	}
	return string(b)
}

func (s *Server) toolsCall(ctx context.Context, req *rpcRequest) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.reply(req, toolResult("invalid params: "+err.Error(), true))
		return
	}
	text, isErr := s.runTool(ctx, p.Name, p.Arguments)
	s.reply(req, toolResult(text, isErr))
}

func (s *Server) runTool(ctx context.Context, name string, args json.RawMessage) (string, bool) {
	switch name {
	case "scan_url":
		var a struct {
			URL  string `json:"url"`
			Fast bool   `json:"fast"`
		}
		_ = json.Unmarshal(args, &a)
		if a.URL == "" {
			return "url is required", true
		}
		if !a.Fast {
			s.svc.EnsureOAST() // enable blind/out-of-band checks for full scans
		}
		res, err := s.svc.ScanURLMode(ctx, a.URL, a.Fast)
		if err != nil {
			return "scan failed: " + err.Error(), true
		}
		return jsonText(res), false

	case "auto_scan":
		var a service.AutopilotParams
		_ = json.Unmarshal(args, &a)
		if a.Target == "" {
			return "target is required", true
		}
		res, err := s.svc.Autopilot(ctx, a)
		if err != nil {
			return "autopilot failed: " + err.Error(), true
		}
		return jsonText(res), false

	case "explain_check":
		var a struct {
			Check string `json:"check"`
		}
		_ = json.Unmarshal(args, &a)
		if a.Check == "" {
			return jsonText(map[string]any{"checks": kb.Keys()}), false
		}
		e, ok := kb.Lookup(a.Check)
		if !ok {
			return "no explanation for " + a.Check, true
		}
		return jsonText(e), false

	case "set_live_audit":
		var a struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.Unmarshal(args, &a)
		if err := s.svc.SetLiveAudit(a.Enabled); err != nil {
			return err.Error(), true
		}
		return jsonText(map[string]bool{"enabled": s.svc.LiveAuditEnabled()}), false

	case "replay_request":
		var a service.ReplayParams
		_ = json.Unmarshal(args, &a)
		if a.URL == "" {
			return "url is required", true
		}
		rec, err := s.svc.Replay(ctx, a)
		if err != nil {
			return "replay failed: " + err.Error(), true
		}
		out := map[string]any{"id": rec.ID}
		if rec.Response != nil {
			out["status"] = rec.Response.StatusCode
			out["length"] = len(rec.Response.Body)
			out["headers"] = rec.Response.Header
			out["body"] = rec.Response.BodyString()
		}
		return jsonText(out), false

	case "list_history":
		var a struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(args, &a)
		recs := s.svc.Sess.History(a.Limit)
		out := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			m := map[string]any{"id": r.ID, "source": r.Source, "method": r.Request.Method, "url": r.Request.AbsoluteURL().String()}
			if r.Response != nil {
				m["status"] = r.Response.StatusCode
				m["length"] = len(r.Response.Body)
			}
			out = append(out, m)
		}
		return jsonText(out), false

	case "get_message":
		var a struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(args, &a)
		rec := s.svc.Sess.Get(a.ID)
		if rec == nil {
			return fmt.Sprintf("no message with id %d", a.ID), true
		}
		out := map[string]any{
			"id": rec.ID, "source": rec.Source,
			"request": rec.Request.DumpRequestLine() + "\n" + string(rec.Request.Body),
		}
		if rec.Response != nil {
			out["status"] = rec.Response.StatusCode
			out["response_headers"] = rec.Response.Header
			out["response_body"] = rec.Response.BodyString()
		}
		return jsonText(out), false

	case "intruder":
		var a fuzz.Attack
		_ = json.Unmarshal(args, &a)
		if a.Template == "" {
			return "template is required (raw request with §...§ positions)", true
		}
		return jsonText(s.svc.FuzzAttack(ctx, a)), false

	case "annotate_message":
		var a struct {
			ID      int64  `json:"id"`
			Note    string `json:"note"`
			Flagged bool   `json:"flagged"`
		}
		_ = json.Unmarshal(args, &a)
		ok1 := s.svc.Sess.SetNote(a.ID, a.Note)
		s.svc.Sess.Flag(a.ID, a.Flagged)
		if !ok1 {
			return fmt.Sprintf("no message %d", a.ID), true
		}
		return jsonText(map[string]any{"id": a.ID, "note": a.Note, "flagged": a.Flagged}), false

	case "list_flagged":
		recs := s.svc.Sess.FlaggedRecords()
		out := make([]map[string]any, 0, len(recs))
		for _, rec := range recs {
			out = append(out, map[string]any{"id": rec.ID, "url": rec.Request.AbsoluteURL().String(), "note": rec.Note, "flagged": rec.Flagged})
		}
		return jsonText(out), false

	case "test_scope":
		var a struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(args, &a)
		u, err := neturl.Parse(a.URL)
		if err != nil || !u.IsAbs() {
			return "not an absolute URL", true
		}
		return jsonText(map[string]any{"url": a.URL, "in_scope": s.svc.Sess.Scope.InScope(u)}), false

	case "schedule_scan":
		var a struct {
			URL         string `json:"url"`
			IntervalSec int    `json:"interval_sec"`
		}
		_ = json.Unmarshal(args, &a)
		if a.URL == "" {
			return "url is required", true
		}
		return jsonText(s.svc.Schedule(a.URL, a.IntervalSec)), false

	case "list_schedules":
		return jsonText(s.svc.Schedules()), false

	case "unschedule":
		var a struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(args, &a)
		if !s.svc.Unschedule(a.ID) {
			return fmt.Sprintf("no schedule %d", a.ID), true
		}
		return jsonText(map[string]any{"removed": a.ID}), false

	case "export_report":
		var a struct {
			Format string `json:"format"`
		}
		_ = json.Unmarshal(args, &a)
		out, err := s.svc.ExportReport(a.Format)
		if err != nil {
			return "report: " + err.Error(), true
		}
		return out, false

	case "csrf_poc":
		var a struct {
			Method, URL, ContentType, Body string
		}
		var raw map[string]string
		_ = json.Unmarshal(args, &raw)
		a.Method, a.URL, a.ContentType, a.Body = raw["method"], raw["url"], raw["content_type"], raw["body"]
		if a.URL == "" {
			return "url is required", true
		}
		return s.svc.CSRFPoC(a.Method, a.URL, a.ContentType, a.Body), false

	case "clickjack_poc":
		var a struct {
			URL     string  `json:"url"`
			Opacity float64 `json:"opacity"`
		}
		_ = json.Unmarshal(args, &a)
		if a.URL == "" {
			return "url is required", true
		}
		return s.svc.ClickjackPoC(a.URL, a.Opacity), false

	case "run_macro":
		var m macro.Macro
		_ = json.Unmarshal(args, &m)
		if len(m.Steps) == 0 {
			return "at least one step is required", true
		}
		return jsonText(s.svc.RunMacro(ctx, m)), false

	case "decode":
		var a struct{ Input, Op string }
		_ = json.Unmarshal(args, &a)
		out, err := s.svc.Decode(a.Input, a.Op)
		if err != nil {
			return "decode: " + err.Error(), true
		}
		return jsonText(map[string]any{"output": out}), false

	case "compare":
		var a struct{ A, B, Mode string }
		_ = json.Unmarshal(args, &a)
		return jsonText(s.svc.Compare(a.A, a.B, a.Mode)), false

	case "sequence":
		var a struct {
			Tokens []string `json:"tokens"`
		}
		_ = json.Unmarshal(args, &a)
		return jsonText(s.svc.Sequence(a.Tokens)), false

	case "dom_xss":
		var a struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(args, &a)
		if a.URL == "" {
			return "url is required", true
		}
		res, err := s.svc.DOMXSS(ctx, a.URL)
		if err != nil {
			return "dom-xss probe failed: " + err.Error(), true
		}
		return jsonText(res), false

	case "browser_crawl":
		var a struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(args, &a)
		if a.URL == "" {
			return "url is required", true
		}
		res, err := s.svc.BrowserCrawl(ctx, a.URL)
		if err != nil {
			return "browser crawl failed: " + err.Error(), true
		}
		return jsonText(res), false

	case "crawl_site":
		var a service.CrawlParams
		_ = json.Unmarshal(args, &a)
		if len(a.Seeds) == 0 {
			return "seeds is required", true
		}
		return jsonText(s.svc.Crawl(ctx, a)), false

	case "fuzz":
		var spec fuzz.Spec
		_ = json.Unmarshal(args, &spec)
		if spec.URL == "" || len(spec.Payloads) == 0 {
			return "url and payloads are required", true
		}
		return jsonText(s.svc.Fuzz(ctx, spec)), false

	case "save_project":
		var a struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(args, &a)
		if a.Path == "" {
			return "path is required", true
		}
		if err := s.svc.SaveProject(a.Path); err != nil {
			return "save failed: " + err.Error(), true
		}
		return jsonText(map[string]any{"saved": a.Path}), false

	case "load_project":
		var a struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(args, &a)
		if err := s.svc.LoadProject(a.Path); err != nil {
			return "load failed: " + err.Error(), true
		}
		return jsonText(map[string]any{"loaded": a.Path}), false

	case "list_issues":
		return jsonText(s.svc.Sess.Issues()), false

	case "get_sitemap":
		return jsonText(s.svc.Sess.SiteMap()), false

	case "set_scope":
		var a struct {
			Action     string `json:"action"`
			Host       string `json:"host"`
			PathPrefix string `json:"path_prefix"`
		}
		_ = json.Unmarshal(args, &a)
		switch a.Action {
		case "include":
			s.svc.Sess.Scope.Include(a.Host, a.PathPrefix)
		case "exclude":
			s.svc.Sess.Scope.Exclude(a.Host, a.PathPrefix)
		case "clear":
			s.svc.Sess.Scope.Clear()
		default:
			return "action must be include|exclude|clear", true
		}
		inc, exc := s.svc.Sess.Scope.Rules()
		return jsonText(map[string]any{"includes": inc, "excludes": exc}), false

	case "intercept_toggle":
		var a struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.Unmarshal(args, &a)
		s.svc.Sess.Intercept.SetEnabled(a.Enabled)
		return jsonText(map[string]any{"enabled": s.svc.Sess.Intercept.Enabled()}), false

	case "intercept_list":
		pend := s.svc.Sess.Intercept.List()
		out := make([]map[string]any, 0, len(pend))
		for _, p := range pend {
			out = append(out, map[string]any{"id": p.ID, "method": p.Request.Method, "url": p.Request.AbsoluteURL().String(),
				"request": p.Request.DumpRequestLine() + "\n" + string(p.Request.Body)})
		}
		return jsonText(map[string]any{"enabled": s.svc.Sess.Intercept.Enabled(), "pending": out}), false

	case "intercept_forward":
		var a struct {
			ID  int64  `json:"id"`
			Raw string `json:"raw"`
		}
		_ = json.Unmarshal(args, &a)
		pend := s.svc.Sess.Intercept.Peek(a.ID)
		if pend == nil {
			return fmt.Sprintf("no held request %d", a.ID), true
		}
		var modified *httpmsg.Request
		if a.Raw != "" {
			m, err := httpmsg.ParseRawRequest([]byte(a.Raw), pend.Request.Scheme, pend.Request.Host)
			if err != nil {
				return "parse edited request: " + err.Error(), true
			}
			modified = m
		}
		if !s.svc.Sess.Intercept.Forward(a.ID, modified) {
			return "forward failed", true
		}
		return jsonText(map[string]any{"forwarded": a.ID}), false

	case "intercept_drop":
		var a struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(args, &a)
		if !s.svc.Sess.Intercept.Drop(a.ID) {
			return fmt.Sprintf("no held request %d", a.ID), true
		}
		return jsonText(map[string]any{"dropped": a.ID}), false

	case "set_auth_header":
		var a struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		_ = json.Unmarshal(args, &a)
		if a.Name == "" {
			return "name is required", true
		}
		s.svc.Sess.SetAuthHeader(a.Name, a.Value)
		return jsonText(s.svc.Sess.AuthHeaders()), false

	case "list_auth_headers":
		return jsonText(s.svc.Sess.AuthHeaders()), false

	case "list_rewrite_rules":
		return jsonText(s.svc.Sess.Rewrite.List()), false

	case "add_rewrite_rule":
		var a struct {
			Target      string `json:"target"`
			Pattern     string `json:"pattern"`
			Replacement string `json:"replacement"`
		}
		_ = json.Unmarshal(args, &a)
		r, err := s.svc.Sess.Rewrite.Add(a.Target, a.Pattern, a.Replacement, true)
		if err != nil {
			return "bad rule: " + err.Error(), true
		}
		return jsonText(r), false

	case "remove_rewrite_rule":
		var a struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(args, &a)
		if !s.svc.Sess.Rewrite.Remove(a.ID) {
			return fmt.Sprintf("no rule %d", a.ID), true
		}
		return jsonText(map[string]any{"removed": a.ID}), false

	case "list_extensions":
		if s.svc.Ext == nil {
			return jsonText([]any{}), false
		}
		return jsonText(s.svc.Ext.List()), false

	case "add_extension":
		if s.svc.Ext == nil {
			return "extensions unavailable", true
		}
		var a struct {
			URL  string `json:"url"`
			Name string `json:"name"`
		}
		_ = json.Unmarshal(args, &a)
		if a.URL == "" {
			return "url is required", true
		}
		name := a.Name
		if name == "" {
			name = "ext"
		}
		return jsonText(s.svc.Ext.Add(a.URL, name)), false

	case "remove_extension":
		if s.svc.Ext == nil {
			return "extensions unavailable", true
		}
		var a struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(args, &a)
		if !s.svc.Ext.Remove(a.ID) {
			return fmt.Sprintf("no extension %d", a.ID), true
		}
		return jsonText(map[string]any{"removed": a.ID}), false

	case "list_websockets":
		return jsonText(s.svc.Sess.WS.Messages(1000)), false

	case "list_interactions":
		if s.svc.OAST == nil {
			return jsonText(map[string]any{"enabled": false}), false
		}
		return jsonText(map[string]any{"enabled": true, "base": s.svc.OAST.Advertised(), "interactions": s.svc.OAST.All()}), false

	case "stats":
		return jsonText(s.svc.Sess.Stats()), false

	default:
		return "unknown tool: " + name, true
	}
}
