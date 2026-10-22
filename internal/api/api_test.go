package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"lanternfish/internal/api"
	"lanternfish/internal/ext"
	"lanternfish/internal/service"
	"lanternfish/internal/session"
)

func vulnTarget() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + r.URL.Query().Get("q") + "</body></html>"))
	})
	return httptest.NewServer(mux)
}

func newAPI(t *testing.T) (*httptest.Server, *session.Session) {
	t.Helper()
	sess := session.New()
	svc := service.New(sess, false)
	svc.Ext = ext.New(sess)
	return httptest.NewServer(api.New(svc).Handler()), sess
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func post(t *testing.T, url, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPIEndpoints(t *testing.T) {
	target := vulnTarget()
	defer target.Close()
	srv, _ := newAPI(t)
	defer srv.Close()
	b := srv.URL

	// GUI index.
	if code, body := get(t, b+"/"); code != 200 || !strings.Contains(body, "LANTERNFISH") {
		t.Errorf("index not served: %d", code)
	}

	// Read endpoints return 200 JSON.
	for _, ep := range []string{"/api/stats", "/api/history", "/api/issues", "/api/sitemap", "/api/interactions", "/api/websockets", "/api/extensions", "/api/rewrite", "/api/auth", "/api/scope"} {
		if code, _ := get(t, b+ep); code != 200 {
			t.Errorf("%s returned %d", ep, code)
		}
	}

	// Scan.
	code, body := post(t, b+"/api/scan", `{"url":"`+target.URL+`/search?q=hi"}`)
	if code != 200 || !strings.Contains(body, "reflected-xss") {
		t.Errorf("scan failed: %d %s", code, body)
	}

	// Replay.
	if code, _ := post(t, b+"/api/replay", `{"method":"GET","url":"`+target.URL+`/search?q=1"}`); code != 200 {
		t.Errorf("replay failed: %d", code)
	}

	// History detail + 404.
	if code, _ := get(t, b+"/api/history/1"); code != 200 {
		t.Errorf("history/1 should exist after scan/replay: %d", code)
	}
	if code, _ := get(t, b+"/api/history/99999"); code != 404 {
		t.Errorf("missing history id should be 404, got %d", code)
	}

	// Scope add.
	if code, body := post(t, b+"/api/scope", `{"action":"include","host":"x.test"}`); code != 200 || !strings.Contains(body, "x.test") {
		t.Errorf("scope add failed: %d %s", code, body)
	}

	// Auth header.
	if code, body := post(t, b+"/api/auth", `{"name":"Authorization","value":"Bearer t"}`); code != 200 || !strings.Contains(body, "Authorization") {
		t.Errorf("auth add failed: %d %s", code, body)
	}

	// Rewrite add + bad regex.
	if code, _ := post(t, b+"/api/rewrite", `{"action":"add","target":"header","pattern":"x","replacement":"y"}`); code != 200 {
		t.Error("rewrite add failed")
	}
	if code, _ := post(t, b+"/api/rewrite", `{"action":"add","target":"url","pattern":"("}`); code != 400 {
		t.Errorf("bad regex should be 400, got %d", code)
	}

	// Extensions.
	if code, _ := post(t, b+"/api/extensions", `{"action":"add","url":"http://127.0.0.1:1/h","name":"d"}`); code != 200 {
		t.Error("extension add failed")
	}

	// Intercept toggle + list.
	if code, _ := post(t, b+"/api/intercept/toggle", `{"enabled":true}`); code != 200 {
		t.Error("intercept toggle failed")
	}
	if code, body := get(t, b+"/api/intercept"); code != 200 || !strings.Contains(body, "pending") {
		t.Errorf("intercept get failed: %d", code)
	}
	post(t, b+"/api/intercept/toggle", `{"enabled":false}`)

	// Project save + load.
	proj := filepath.Join(t.TempDir(), "p.json")
	projJSON, _ := json.Marshal(map[string]string{"path": proj})
	if code, _ := post(t, b+"/api/project/save", string(projJSON)); code != 200 {
		t.Error("project save failed")
	}
	if code, _ := post(t, b+"/api/project/load", string(projJSON)); code != 200 {
		t.Error("project load failed")
	}
}

func TestAPIRejectsCrossOrigin(t *testing.T) {
	srv, _ := newAPI(t)
	defer srv.Close()
	// A cross-site Origin (as a browser would send during DNS-rebinding/CSRF)
	// must be rejected.
	req, _ := http.NewRequest("POST", srv.URL+"/api/scan", bytes.NewReader([]byte(`{"url":"http://x/"}`)))
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin request should be 403, got %d", resp.StatusCode)
	}
}
