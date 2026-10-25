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

func urlParamPoint(t *testing.T, raw, name string) (*httpmsg.Request, scan.InsertionPoint) {
	t.Helper()
	u, _ := url.Parse(raw)
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}}
	for _, ip := range scan.InsertionPoints(base) {
		if ip.Name == name {
			return base, ip
		}
	}
	t.Fatalf("no insertion point %q", name)
	return nil, scan.InsertionPoint{}
}

func TestSSRFMetadataDetectsAWS(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		body := "home page"
		if strings.Contains(r.URL.RawQuery, "169.254.169.254") {
			body = "ami-launch-index\nblock-device-mapping/\nreservation-id\ninstance-action"
		}
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte(body)}
	}}
	base, p := urlParamPoint(t, "http://x/fetch?url=http://example.com", "url")
	issues := (SSRFMetadata{}).Active(context.Background(), sender, base, p)
	if len(issues) == 0 || issues[0].Check != "ssrf" {
		t.Fatalf("expected ssrf finding, got %v", issues)
	}
}

func TestSSRFMetadataNoFalsePositive(t *testing.T) {
	// A normal endpoint that never fetches internal content.
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("welcome, nothing to see")}
	}}
	base, p := urlParamPoint(t, "http://x/fetch?url=http://example.com", "url")
	if issues := (SSRFMetadata{}).Active(context.Background(), sender, base, p); len(issues) != 0 {
		t.Errorf("expected no finding, got %v", issues)
	}
}

func TestSSRFMetadataSkipsNonURLParam(t *testing.T) {
	called := false
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		called = true
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("ok")}
	}}
	base, p := urlParamPoint(t, "http://x/p?comment=hi", "comment")
	(SSRFMetadata{}).Active(context.Background(), sender, base, p)
	if called {
		t.Error("should not probe a non-URL-ish parameter")
	}
}
