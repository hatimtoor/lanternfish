package browser

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHeadlessCrawlExecutesJS(t *testing.T) {
	if !Available() {
		t.Skip("no Chromium-family browser available")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// A static link, a JS-injected link, and a fetch() call.
		w.Write([]byte(`<html><body>
<a href="/static">s</a>
<script>
  var a=document.createElement('a'); a.href='/dynamic?x=1'; a.textContent='d'; document.body.appendChild(a);
  fetch('/api/data?q=2');
</script></body></html>`))
	})
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Crawl(srv.URL+"/", 2*time.Second)
	if err != nil {
		t.Fatalf("headless crawl failed: %v", err)
	}
	joined := strings.Join(append(append([]string{}, res.Links...), res.XHR...), " ")
	if !strings.Contains(joined, "/static") {
		t.Errorf("should find the static link; got links=%v", res.Links)
	}
	if !strings.Contains(joined, "/dynamic?x=1") {
		t.Errorf("should find the JS-injected link; got links=%v", res.Links)
	}
	if !strings.Contains(joined, "/api/data?q=2") {
		t.Errorf("should capture the fetch() endpoint; got xhr=%v", res.XHR)
	}
}
