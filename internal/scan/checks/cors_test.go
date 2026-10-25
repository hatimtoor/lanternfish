package checks

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
)

func corsReq() *httpmsg.Request {
	u, _ := url.Parse("https://api.example.com/data")
	return &httpmsg.Request{Method: "GET", URL: u, Scheme: "https", Host: "api.example.com", Header: http.Header{}}
}

// reflectOrigin returns a sender that reflects the request Origin in ACAO only
// when the predicate accepts it (modelling a specific broken allow-list).
func reflectOrigin(accept func(origin string) bool, creds bool) fakeSender {
	return fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		h := http.Header{}
		o := r.Header.Get("Origin")
		if o != "" && accept(o) {
			h.Set("Access-Control-Allow-Origin", o)
			if creds {
				h.Set("Access-Control-Allow-Credentials", "true")
			}
		}
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte("{}")}
	}}
}

func TestCORSSuffixBypass(t *testing.T) {
	// Broken check: endsWith("example.com").
	s := reflectOrigin(func(o string) bool { return strings.HasSuffix(o, "example.com") }, true)
	issues := (CORSMisconfig{}).Request(context.Background(), s, corsReq())
	if len(issues) == 0 || !strings.Contains(issues[0].Name, "bypass") {
		t.Fatalf("expected a CORS bypass finding, got %v", issues)
	}
}

func TestCORSNullOrigin(t *testing.T) {
	s := reflectOrigin(func(o string) bool { return o == "null" }, true)
	issues := (CORSMisconfig{}).Request(context.Background(), s, corsReq())
	if len(issues) == 0 || !strings.Contains(issues[0].Name, "null") {
		t.Fatalf("expected a null-origin finding, got %v", issues)
	}
}

func TestCORSReflectArbitrary(t *testing.T) {
	s := reflectOrigin(func(o string) bool { return true }, true) // reflects anything
	issues := (CORSMisconfig{}).Request(context.Background(), s, corsReq())
	if len(issues) == 0 {
		t.Fatal("expected a CORS finding when any origin is reflected")
	}
}

func TestCORSStrictNoFinding(t *testing.T) {
	// Only the real origin is allowed — correct behaviour, no finding.
	s := reflectOrigin(func(o string) bool { return o == "https://api.example.com" }, true)
	if issues := (CORSMisconfig{}).Request(context.Background(), s, corsReq()); len(issues) != 0 {
		t.Errorf("a strict allow-list should produce no finding, got %v", issues)
	}
}
