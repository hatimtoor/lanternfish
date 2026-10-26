package checks

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
)

// spaShell mimics an Angular/SPA host that serves the same index.html for every
// route (including unknown ones), so every path returns 200. The shell contains
// "=" and ":" like any HTML page, which used to defeat the weak-signal check and
// produce false "Sensitive file exposed: /.env" / "/.htpasswd" findings.
func spaShell() fakeSender {
	shell := "<!doctype html><html><head><base href=\"/\"><title>Juice Shop</title>" +
		strings.Repeat("<link rel=stylesheet href=\"x.css\"> ", 400) + "</head><body></body></html>"
	return fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		h := http.Header{}
		h.Set("Content-Type", "text/html; charset=utf-8")
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte(shell)}
	}}
}

func TestContentDiscoverySPACatchAllNoFalsePositive(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:3000/")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "127.0.0.1:3000", Header: http.Header{}}

	iss := (ContentDiscovery{}).Request(context.Background(), spaShell(), req)
	if len(iss) != 0 {
		names := make([]string, len(iss))
		for i, is := range iss {
			names[i] = is.Name
		}
		t.Fatalf("SPA catch-all should yield no sensitive-file findings, got %d: %v", len(iss), names)
	}
}

// A normal host 404s unknown paths but genuinely exposes /.git/config as a small
// text/plain file — that must still be reported.
func TestContentDiscoveryRealFileStillReported(t *testing.T) {
	u, _ := url.Parse("http://victim.example/")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "victim.example", Header: http.Header{}}

	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		h := http.Header{}
		if r.URL.Path == "/.git/config" {
			h.Set("Content-Type", "text/plain")
			return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte("[core]\n\trepositoryformatversion = 0\n")}
		}
		h.Set("Content-Type", "text/html")
		return &httpmsg.Response{StatusCode: 404, Header: h, Body: []byte("<h1>404 Not Found</h1>")}
	}}

	iss := (ContentDiscovery{}).Request(context.Background(), sender, req)
	if len(iss) != 1 || !strings.Contains(iss[0].Name, "/.git/config") {
		t.Fatalf("expected one /.git/config finding, got %d: %+v", len(iss), iss)
	}
}
