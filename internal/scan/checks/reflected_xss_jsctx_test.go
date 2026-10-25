package checks

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

func xssPoint(t *testing.T, raw string) (*httpmsg.Request, scan.InsertionPoint) {
	t.Helper()
	u, _ := url.Parse(raw)
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}}
	for _, ip := range scan.InsertionPoints(base) {
		if ip.Name == "q" {
			return base, ip
		}
	}
	t.Fatal("no q point")
	return nil, scan.InsertionPoint{}
}

func htmlHdr() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	return h
}

func TestReflectedXSSJavaScriptContext(t *testing.T) {
	// Vulnerable: input reflected raw inside an inline script string; only the
	// angle brackets are encoded, so the tag-based probe misses but the quote
	// survives and breaks the JS string.
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		v := strings.ReplaceAll(r.URL.Query().Get("q"), "<", "&lt;")
		body := "<html><head><script>var greeting='" + v + "';</script></head><body>hi</body></html>"
		return &httpmsg.Response{StatusCode: 200, Header: htmlHdr(), Body: []byte(body)}
	}}
	base, p := xssPoint(t, "http://x/p?q=hi")
	issues := (ReflectedXSS{}).Active(context.Background(), sender, base, p)
	if len(issues) == 0 || !strings.Contains(issues[0].Name, "JavaScript") {
		t.Fatalf("expected a JS-context XSS finding, got %v", issues)
	}
}

func TestReflectedXSSJavaScriptContextCleanWhenQuotesStripped(t *testing.T) {
	// Safe: the app strips quotes and angle brackets, so no breakout is possible.
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		v := strings.Map(func(c rune) rune {
			switch c {
			case '<', '>', '\'', '"', '`':
				return -1
			}
			return c
		}, r.URL.Query().Get("q"))
		body := "<html><script>var g='" + v + "';</script></html>"
		return &httpmsg.Response{StatusCode: 200, Header: htmlHdr(), Body: []byte(body)}
	}}
	base, p := xssPoint(t, "http://x/p?q=hi")
	if issues := (ReflectedXSS{}).Active(context.Background(), sender, base, p); len(issues) != 0 {
		t.Errorf("stripped quotes => no finding, got %v", issues)
	}
}
