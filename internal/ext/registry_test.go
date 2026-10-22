package ext_test

import (
	"net/http"
	"net/url"
	"testing"

	"lanternfish/internal/ext"
	"lanternfish/internal/httpmsg"
)

func TestRegistrySampleExtension(t *testing.T) {
	r := ext.NewRegistry()
	r.Use(ext.SampleExtension{})

	if len(r.RequestEditors()) != 1 {
		t.Fatalf("want 1 request editor, got %d", len(r.RequestEditors()))
	}
	if len(r.ResponseEditors()) != 1 {
		t.Fatalf("want 1 response editor, got %d", len(r.ResponseEditors()))
	}
	if len(r.PassiveChecks()) != 1 {
		t.Fatalf("want 1 passive check, got %d", len(r.PassiveChecks()))
	}
	if names := r.Names(); len(names) != 1 || names[0] != "sample" {
		t.Fatalf("want [sample], got %v", names)
	}

	// Request editor tags the request.
	u, _ := url.Parse("http://x/")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x", Header: http.Header{}}
	r.RequestEditors()[0](req)
	if req.Header.Get("X-Lanternfish-Ext") != "sample" {
		t.Fatalf("request editor did not tag request")
	}

	// Response editor tags the response.
	resp := &httpmsg.Response{Header: http.Header{}}
	r.ResponseEditors()[0](req, resp)
	if resp.Header.Get("X-Lanternfish-Scanned") != "1" {
		t.Fatalf("response editor did not tag response")
	}

	// Passive check fires on a debug-leak body.
	pc := r.PassiveChecks()[0]
	tx := &httpmsg.Transaction{
		Request:  req,
		Response: &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("env: DEBUG=true")},
	}
	if issues := pc.Passive(tx); len(issues) != 1 {
		t.Fatalf("want 1 issue from sample passive check, got %d", len(issues))
	}
	// And stays quiet on a clean body.
	clean := &httpmsg.Transaction{Request: req, Response: &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("all good")}}
	if issues := pc.Passive(clean); len(issues) != 0 {
		t.Fatalf("sample check false-positived: %d", len(issues))
	}
}
