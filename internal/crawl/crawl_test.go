package crawl_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"lanternfish/internal/crawl"
	"lanternfish/internal/session"
)

func TestCrawlFollowsLinksAndForms(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body>leaf</body></html>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<a href="/a">a</a><a href="/b">b</a><a href="/c?x=1">c</a>
			<form action="/submit" method="post"><input name="q" value="1"></form>
			</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sess := session.New()
	u, _ := url.Parse(srv.URL)
	sess.Scope.Include(u.Hostname(), "")

	c := crawl.New(sess, false, crawl.Options{MaxPages: 50, MaxDepth: 3})
	res, reqs := c.Crawl(context.Background(), []string{srv.URL + "/"})

	if res.PagesVisited < 4 {
		t.Errorf("expected to visit seed + 3 links (>=4), visited %d", res.PagesVisited)
	}
	if res.Forms != 1 {
		t.Errorf("expected 1 form discovered, got %d", res.Forms)
	}
	// A POST form request plus the GET-with-query link should be audit targets.
	var sawPost bool
	for _, r := range reqs {
		if r.Method == "POST" {
			sawPost = true
		}
	}
	if !sawPost {
		t.Error("expected a POST form request among audit targets")
	}
}

func TestCrawlRespectsScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="https://external.example/x">ext</a>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sess := session.New()
	u, _ := url.Parse(srv.URL)
	sess.Scope.Include(u.Hostname(), "")
	c := crawl.New(sess, false, crawl.Options{MaxPages: 50, MaxDepth: 3})
	res, _ := c.Crawl(context.Background(), []string{srv.URL + "/"})
	for _, f := range res.URLsFound {
		if f == "https://external.example/x" {
			t.Error("out-of-scope URL should not be recorded as found")
		}
	}
}
