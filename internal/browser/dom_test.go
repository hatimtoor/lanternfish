package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDOMXSSDetectsSinkFlow(t *testing.T) {
	if !Available() {
		t.Skip("no Chromium-family browser available")
	}
	mux := http.NewServeMux()
	// Deliberately vulnerable: writes location.hash into innerHTML.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><div id="out"></div>
<script>
  document.getElementById('out').innerHTML = decodeURIComponent(location.hash.slice(1));
</script></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := DOMXSS(srv.URL+"/", 2*time.Second)
	if err != nil {
		t.Fatalf("DOM-XSS probe failed: %v", err)
	}
	if len(res.Hits) == 0 {
		t.Fatalf("expected an innerHTML sink hit, got none")
	}
	var sawInnerHTML bool
	for _, h := range res.Hits {
		if h.Sink == "innerHTML" {
			sawInnerHTML = true
		}
	}
	if !sawInnerHTML {
		t.Errorf("expected innerHTML sink, got %+v", res.Hits)
	}
}

func TestDOMXSSCleanPage(t *testing.T) {
	if !Available() {
		t.Skip("no Chromium-family browser available")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Safe: uses textContent, never a dangerous sink.
		w.Write([]byte(`<html><body><div id="out"></div>
<script>document.getElementById('out').textContent = location.hash;</script></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := DOMXSS(srv.URL+"/", 1500*time.Millisecond)
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if len(res.Hits) != 0 {
		t.Errorf("clean page should have no sink hits, got %+v", res.Hits)
	}
}

func TestDOMXSSDetectsNewSinks(t *testing.T) {
	if !Available() {
		t.Skip("no Chromium-family browser available")
	}
	mux := http.NewServeMux()
	// Vulnerable: location.hash flows into DOMParser.parseFromString (a sink
	// added this cycle). Non-navigating, so the probe stays on the page.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
<script>
  var h = decodeURIComponent(location.hash.slice(1));
  new DOMParser().parseFromString('<div>'+h+'</div>', 'text/html');
</script></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := DOMXSS(srv.URL+"/", 2*time.Second)
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	var saw bool
	for _, h := range res.Hits {
		if h.Sink == "DOMParser.parseFromString" {
			saw = true
		}
	}
	if !saw {
		t.Errorf("expected DOMParser.parseFromString sink, got %+v", res.Hits)
	}
}
