package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"lanternfish/internal/ext"
	"lanternfish/internal/mcp"
	"lanternfish/internal/oast"
	"lanternfish/internal/service"
	"lanternfish/internal/session"
)

// vulnTarget mirrors the deliberately-vulnerable endpoints used elsewhere so
// the MCP tools have something real to act on.
func vulnTarget(oastHook func()) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><a href="/search?q=1">s</a><a href="/user?name=x">u</a></body></html>`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + r.URL.Query().Get("q") + "</body></html>"))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(r.URL.Query().Get("name"), "'") {
			w.Write([]byte("You have an error in your SQL syntax near ''"))
			return
		}
		w.Write([]byte("ok"))
	})
	return httptest.NewServer(mux)
}

type rpcResp struct {
	ID     json.RawMessage `json:"id"`
	Result struct {
		ServerInfo map[string]any   `json:"serverInfo"`
		Tools      []map[string]any `json:"tools"`
		Content    []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// runMCP feeds newline-delimited JSON-RPC requests and returns parsed responses
// keyed by id.
func runMCP(t *testing.T, svc *service.Service, requests []string) map[string]rpcResp {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out bytes.Buffer
	if err := mcp.New(svc, in, &out).Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	byID := map[string]rpcResp{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var r rpcResp
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad response line %q: %v", line, err)
		}
		byID[string(r.ID)] = r
	}
	return byID
}

func call(id int, name string, args map[string]any) string {
	a, _ := json.Marshal(args)
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, name, a)
}

func toolText(t *testing.T, r rpcResp) string {
	t.Helper()
	if len(r.Result.Content) == 0 {
		t.Fatalf("no content in response: %+v", r)
	}
	return r.Result.Content[0].Text
}

func TestMCPProtocolHandshake(t *testing.T) {
	target := vulnTarget(nil)
	defer target.Close()
	svc := service.New(session.New(), false)

	resp := runMCP(t, svc, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"no_such_method"}`,
	})

	if resp["1"].Result.ServerInfo["name"] != "lanternfish" {
		t.Errorf("initialize: bad serverInfo %v", resp["1"].Result.ServerInfo)
	}
	if _, ok := resp[""]; ok {
		t.Error("notification should not get a response")
	}
	if _, ok := resp["2"]; !ok {
		t.Error("ping should get a response")
	}
	if n := len(resp["3"].Result.Tools); n < 20 {
		t.Errorf("tools/list returned %d tools, want >=20", n)
	}
	// Every tool must have name + inputSchema.
	for _, tl := range resp["3"].Result.Tools {
		if tl["name"] == nil || tl["inputSchema"] == nil {
			t.Errorf("tool missing name/inputSchema: %v", tl)
		}
	}
	if resp["4"].Error == nil {
		t.Error("unknown method should return an error object")
	}
}

func TestMCPEveryTool(t *testing.T) {
	target := vulnTarget(nil)
	defer target.Close()

	sess := session.New()
	svc := service.New(sess, false)
	svc.Ext = ext.New(sess)
	oastSrv := oast.New("")
	if _, err := oastSrv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("oast start: %v", err)
	}
	svc.OAST = oastSrv

	proj := filepath.Join(t.TempDir(), "p.json")

	reqs := []string{
		call(10, "stats", nil),
		call(11, "set_scope", map[string]any{"action": "include", "host": "127.0.0.1"}),
		call(12, "scan_url", map[string]any{"url": target.URL + "/search?q=hi"}),
		call(13, "scan_url", map[string]any{"url": target.URL + "/user?name=x"}),
		call(14, "list_issues", nil),
		call(15, "replay_request", map[string]any{"method": "GET", "url": target.URL + "/"}),
		call(16, "list_history", map[string]any{"limit": 10}),
		call(17, "get_message", map[string]any{"id": 1}),
		call(18, "get_message", map[string]any{"id": 999999}),
		call(19, "get_sitemap", nil),
		call(20, "crawl_site", map[string]any{"seeds": []string{target.URL + "/"}, "max_pages": 10, "audit": true}),
		call(21, "fuzz", map[string]any{"url": target.URL + "/user?name=FUZZ", "payloads": []string{"a", "b", "'"}}),
		call(22, "set_auth_header", map[string]any{"name": "Authorization", "value": "Bearer t"}),
		call(23, "list_auth_headers", nil),
		call(24, "add_rewrite_rule", map[string]any{"target": "header", "pattern": "secret", "replacement": "X"}),
		call(25, "list_rewrite_rules", nil),
		call(26, "remove_rewrite_rule", map[string]any{"id": 1}),
		call(27, "remove_rewrite_rule", map[string]any{"id": 4242}),
		call(28, "add_extension", map[string]any{"url": "http://127.0.0.1:1/hook", "name": "demo"}),
		call(29, "list_extensions", nil),
		call(30, "remove_extension", map[string]any{"id": 1}),
		call(31, "intercept_toggle", map[string]any{"enabled": true}),
		call(32, "intercept_list", nil),
		call(33, "intercept_toggle", map[string]any{"enabled": false}),
		call(34, "intercept_forward", map[string]any{"id": 777}),
		call(35, "intercept_drop", map[string]any{"id": 777}),
		call(36, "list_websockets", nil),
		call(37, "list_interactions", nil),
		call(38, "save_project", map[string]any{"path": proj}),
		call(39, "load_project", map[string]any{"path": proj}),
		call(40, "scan_url", nil),                                                     // missing url -> error
		call(41, "fuzz", map[string]any{}),                                            // missing fields -> error
		call(42, "does_not_exist", nil),                                               // unknown tool -> error
		call(43, "add_rewrite_rule", map[string]any{"target": "url", "pattern": "("}), // bad regex -> error
	}
	resp := runMCP(t, svc, reqs)

	// Tools expected to succeed.
	okIDs := []int{10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26, 28, 29, 30, 31, 32, 33, 36, 37, 38, 39}
	for _, id := range okIDs {
		r := resp[fmt.Sprint(id)]
		if r.Result.IsError {
			t.Errorf("tool call id=%d unexpectedly errored: %s", id, toolText(t, r))
		}
	}
	// Tools expected to return isError.
	errIDs := []int{18, 27, 34, 35, 40, 41, 42, 43}
	for _, id := range errIDs {
		if !resp[fmt.Sprint(id)].Result.IsError {
			t.Errorf("tool call id=%d should have errored", id)
		}
	}

	// Substantive assertions.
	if !strings.Contains(toolText(t, resp["12"]), "reflected-xss") {
		t.Errorf("scan /search should find reflected-xss: %s", toolText(t, resp["12"]))
	}
	if !strings.Contains(toolText(t, resp["13"]), "sqli-error") {
		t.Errorf("scan /user should find sqli-error: %s", toolText(t, resp["13"]))
	}
	if !strings.Contains(toolText(t, resp["23"]), "Authorization") {
		t.Error("auth header should be listed")
	}
	if !strings.Contains(toolText(t, resp["37"]), "enabled") {
		t.Error("interactions should report enabled")
	}
	// load_project should restore state (history non-empty).
	hist := runMCP(t, svc, []string{call(50, "list_history", map[string]any{"limit": 100})})
	if strings.TrimSpace(toolText(t, hist["50"])) == "[]" {
		t.Error("history empty after load_project")
	}
}

// TestMCPNewTools exercises the Burp-parity tools added later.
func TestMCPNewTools(t *testing.T) {
	target := vulnTarget(nil)
	defer target.Close()
	sess := session.New()
	svc := service.New(sess, false)
	svc.Ext = ext.New(sess)
	// Seed one history entry to annotate.
	svc.Replay(context.Background(), service.ReplayParams{Method: "GET", URL: target.URL + "/search?q=1"})

	reqs := []string{
		call(60, "intruder", map[string]any{"scheme": "http", "host": strings.TrimPrefix(target.URL, "http://"),
			"template": "GET /search?q=§x§ HTTP/1.1\r\nHost: " + strings.TrimPrefix(target.URL, "http://") + "\r\n\r\n",
			"type":     "sniper", "payload_sets": [][]string{{"a", "b"}}}),
		call(61, "decode", map[string]any{"input": "aGVsbG8=", "op": "base64-decode"}),
		call(62, "compare", map[string]any{"a": "one\ntwo", "b": "one\n2", "mode": "line"}),
		call(63, "sequence", map[string]any{"tokens": []string{"aaaa", "bbbb", "cccc", "dddd"}}),
		call(64, "run_macro", map[string]any{"steps": []map[string]any{{"method": "GET", "url": target.URL + "/search?q=1"}}}),
		call(65, "export_report", map[string]any{"format": "html"}),
		call(66, "csrf_poc", map[string]any{"method": "POST", "url": "https://x/t", "content_type": "application/x-www-form-urlencoded", "body": "a=1"}),
		call(67, "annotate_message", map[string]any{"id": 1, "note": "look here", "flagged": true}),
		call(68, "list_flagged", nil),
		call(69, "test_scope", map[string]any{"url": target.URL + "/x"}),
		call(70, "schedule_scan", map[string]any{"url": target.URL + "/search?q=1", "interval_sec": 10}),
		call(71, "list_schedules", nil),
		call(72, "unschedule", map[string]any{"id": 1}),
		call(73, "decode", map[string]any{"input": "x", "op": "bogus-op"}), // error
		call(74, "test_scope", map[string]any{"url": "not a url"}),         // error
	}
	resp := runMCP(t, svc, reqs)

	okIDs := []int{60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72}
	for _, id := range okIDs {
		if resp[fmt.Sprint(id)].Result.IsError {
			t.Errorf("tool id=%d errored: %s", id, toolText(t, resp[fmt.Sprint(id)]))
		}
	}
	for _, id := range []int{73, 74} {
		if !resp[fmt.Sprint(id)].Result.IsError {
			t.Errorf("tool id=%d should have errored", id)
		}
	}
	if !strings.Contains(toolText(t, resp["61"]), "hello") {
		t.Errorf("decode base64 wrong: %s", toolText(t, resp["61"]))
	}
	if !strings.Contains(toolText(t, resp["65"]), "<!doctype html>") {
		t.Error("export_report html wrong")
	}
	if !strings.Contains(toolText(t, resp["66"]), "<form") {
		t.Error("csrf_poc should produce a form")
	}
	if !strings.Contains(toolText(t, resp["68"]), "look here") {
		t.Error("list_flagged should include the annotated message")
	}
}
