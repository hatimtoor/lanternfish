package checks

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
)

func getReq(raw string) *httpmsg.Request {
	u, _ := url.Parse(raw)
	return &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}}
}

func TestCachePoisoningReflectedAndCacheable(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		h := http.Header{}
		h.Set("Cache-Control", "public, max-age=60")
		body := "<link href='//cdn/app.js'>"
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			body = "<link href='//" + xfh + "/app.js'>" // reflects the header host
		}
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte(body)}
	}}
	issues := (CachePoisoning{}).Request(context.Background(), sender, getReq("http://x/home"))
	if len(issues) == 0 || issues[0].Check != "cache-poisoning" {
		t.Fatalf("expected cache-poisoning finding, got %v", issues)
	}
}

func TestCachePoisoningReflectedButNotCacheable(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		h := http.Header{}
		h.Set("Cache-Control", "no-store")
		body := "safe"
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			body = "<link href='//" + xfh + "/app.js'>"
		}
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte(body)}
	}}
	if issues := (CachePoisoning{}).Request(context.Background(), sender, getReq("http://x/home")); len(issues) != 0 {
		t.Errorf("reflected but no-store => no finding, got %v", issues)
	}
}

func TestCachePoisoningNotReflected(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		h := http.Header{}
		h.Set("Cache-Control", "public, max-age=60")
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte(strings.Repeat("x", 50))}
	}}
	if issues := (CachePoisoning{}).Request(context.Background(), sender, getReq("http://x/home")); len(issues) != 0 {
		t.Errorf("no reflection => no finding, got %v", issues)
	}
}
