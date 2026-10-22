package httpmsg

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestParseRawRequest(t *testing.T) {
	raw := "POST /submit?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=1&b=2"
	r, err := ParseRawRequest([]byte(raw), "https", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "POST" || r.Host != "example.com" || r.Scheme != "https" {
		t.Errorf("parsed fields wrong: %+v", r)
	}
	if string(r.Body) != "a=1&b=2" {
		t.Errorf("body wrong: %q", r.Body)
	}
}

func TestCloneIsDeep(t *testing.T) {
	u, _ := url.Parse("http://h/p?a=1")
	r := &Request{Method: "GET", URL: u, Scheme: "http", Host: "h", Header: http.Header{"A": {"1"}}, Body: []byte("x")}
	c := r.Clone()
	c.Header.Set("A", "2")
	c.Body[0] = 'y'
	c.URL.Path = "/changed"
	if r.Header.Get("A") != "1" {
		t.Error("header not deep-copied")
	}
	if string(r.Body) != "x" {
		t.Error("body not deep-copied")
	}
	if r.URL.Path != "/p" {
		t.Error("url not deep-copied")
	}
}

func TestAbsoluteURLOriginForm(t *testing.T) {
	// Origin-form URL (as captured inside a TLS tunnel) with scheme/host set.
	u, _ := url.Parse("/path?q=1")
	r := &Request{Method: "GET", URL: u, Scheme: "https", Host: "h.test"}
	abs := r.AbsoluteURL()
	if abs.String() != "https://h.test/path?q=1" {
		t.Errorf("absolute url wrong: %s", abs)
	}
}

func TestFromHTTPAndResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	hr, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	req, err := FromHTTP(hr)
	if err != nil {
		t.Fatal(err)
	}
	if req.Scheme != "http" {
		t.Errorf("scheme inference wrong: %s", req.Scheme)
	}
	resp, _ := http.Get(srv.URL)
	r, err := FromHTTPResponse(resp, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if r.ContentType() != "application/json" {
		t.Errorf("content type parse wrong: %q", r.ContentType())
	}
	if r.BodyString() != `{"ok":true}` {
		t.Errorf("body wrong: %q", r.BodyString())
	}
}

func TestToHTTPRoundTrip(t *testing.T) {
	u, _ := url.Parse("http://h.test/p?a=1")
	r := &Request{Method: "POST", URL: u, Scheme: "http", Host: "h.test", Header: http.Header{"X-A": {"1"}}, Body: []byte("body")}
	hr, err := r.ToHTTP()
	if err != nil {
		t.Fatal(err)
	}
	if hr.Host != "h.test" || hr.Header.Get("X-A") != "1" {
		t.Error("ToHTTP lost fields")
	}
}
