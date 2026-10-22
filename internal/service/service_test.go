package service_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"lanternfish/internal/fuzz"
	"lanternfish/internal/service"
	"lanternfish/internal/session"
)

func target() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><a href="/x?q=1">x</a><form action="/f" method="post"><input name="p" value="1"></form></html>`))
	})
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>" + r.URL.Query().Get("q") + "</html>")) // reflected
	})
	mux.HandleFunc("/f", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return httptest.NewServer(mux)
}

func TestServiceReplay(t *testing.T) {
	ts := target()
	defer ts.Close()
	sess := session.New()
	svc := service.New(sess, false)
	rec, err := svc.Replay(context.Background(), service.ReplayParams{Method: "GET", URL: ts.URL + "/x?q=hi"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Response == nil || rec.Response.StatusCode != 200 {
		t.Fatalf("replay response wrong: %+v", rec.Response)
	}
	if rec.Source != session.SourceRepeater {
		t.Errorf("replay should be recorded as repeater, got %s", rec.Source)
	}
	if len(sess.History(0)) != 1 {
		t.Error("replay not recorded in history")
	}
}

func TestServiceScanURL(t *testing.T) {
	ts := target()
	defer ts.Close()
	sess := session.New()
	svc := service.New(sess, false)
	res, err := svc.ScanURL(context.Background(), ts.URL+"/x?q=hi")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range res.Issues {
		if i.Check == "reflected-xss" {
			found = true
		}
	}
	if !found {
		t.Error("scan should find reflected-xss")
	}
	if len(sess.Issues()) == 0 {
		t.Error("issues should be stored in the session")
	}
}

func TestServiceCrawlAndAudit(t *testing.T) {
	ts := target()
	defer ts.Close()
	sess := session.New()
	svc := service.New(sess, false)
	// Scope to the target host so the crawl stays on target.
	host := strings.TrimPrefix(ts.URL, "http://")
	sess.Scope.Include(strings.Split(host, ":")[0], "")
	res := svc.Crawl(context.Background(), service.CrawlParams{Seeds: []string{ts.URL + "/"}, MaxPages: 10, MaxDepth: 2, Audit: true})
	if res.PagesVisited < 1 {
		t.Error("crawl visited nothing")
	}
	if res.Forms < 1 {
		t.Error("crawl should discover the form")
	}
}

func TestServiceFuzz(t *testing.T) {
	ts := target()
	defer ts.Close()
	svc := service.New(session.New(), false)
	res := svc.Fuzz(context.Background(), fuzz.Spec{URL: ts.URL + "/x?q=FUZZ", Payloads: []string{"a", "b", "c"}})
	if res.Count != 3 || len(res.Rows) != 3 {
		t.Errorf("fuzz rows wrong: %d", len(res.Rows))
	}
}

func TestServiceProjectRoundTrip(t *testing.T) {
	ts := target()
	defer ts.Close()
	sess := session.New()
	svc := service.New(sess, false)
	svc.Replay(context.Background(), service.ReplayParams{Method: "GET", URL: ts.URL + "/x?q=1"})
	path := filepath.Join(t.TempDir(), "p.json")
	if err := svc.SaveProject(path); err != nil {
		t.Fatal(err)
	}
	sess2 := session.New()
	svc2 := service.New(sess2, false)
	if err := svc2.LoadProject(path); err != nil {
		t.Fatal(err)
	}
	if len(sess2.History(0)) != 1 {
		t.Error("project load did not restore history")
	}
	if err := svc2.LoadProject(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("loading a missing project should error")
	}
}
