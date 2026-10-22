package checks

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
)

// fakeSender returns a canned response, optionally reacting to the request.
type fakeSender struct {
	fn func(r *httpmsg.Request) *httpmsg.Response
}

func (f fakeSender) Send(_ context.Context, r *httpmsg.Request) (*httpmsg.Response, error) {
	return f.fn(r), nil
}

func xmlReq() *httpmsg.Request {
	u, _ := url.Parse("http://x/api")
	h := http.Header{}
	h.Set("Content-Type", "application/xml")
	return &httpmsg.Request{Method: "POST", URL: u, Scheme: "http", Host: "x", Header: h, Body: []byte("<data>1</data>")}
}

func TestXXEInBandDetectsFileDisclosure(t *testing.T) {
	// A vulnerable parser echoes /etc/passwd when the external entity is used.
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		body := "ok"
		if strings.Contains(string(r.Body), "file:///etc/passwd") {
			body = "<lanternfish>root:x:0:0:root:/root:/bin/bash</lanternfish>"
		}
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte(body)}
	}}
	issues := (XXE{}).Request(context.Background(), sender, xmlReq())
	if len(issues) == 0 || issues[0].Check != "xxe" {
		t.Fatalf("expected an XXE finding, got %v", issues)
	}
}

func TestXXESkipsNonXML(t *testing.T) {
	u, _ := url.Parse("http://x/p?a=1")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x", Header: http.Header{}}
	called := false
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		called = true
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("ok")}
	}}
	if issues := (XXE{}).Request(context.Background(), sender, req); len(issues) != 0 {
		t.Error("XXE should not fire on a non-XML request")
	}
	if called {
		t.Error("XXE should not send requests for a non-XML base")
	}
}
