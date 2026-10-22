package replay

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
)

type stubSender struct{}

func (stubSender) Send(_ context.Context, r *httpmsg.Request) (*httpmsg.Response, error) {
	return &httpmsg.Response{
		Proto: "HTTP/1.1", Status: "200 OK", StatusCode: 200,
		Header: http.Header{"Content-Type": {"text/plain"}}, Body: []byte("hello body"),
	}, nil
}

func TestOnceAndRender(t *testing.T) {
	u, _ := url.Parse("http://h.test/path?a=1")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "h.test", Header: http.Header{"X-A": {"1"}}}
	resp, err := Once(context.Background(), stubSender{}, req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("Once failed: %v", err)
	}
	out := Render(req, resp)
	for _, want := range []string{"GET", "/path?a=1", "Host: h.test", "HTTP/1.1 200 OK", "hello body"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderTruncatesLargeBody(t *testing.T) {
	u, _ := url.Parse("http://h/")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "h", Header: http.Header{}}
	big := strings.Repeat("x", 5000)
	resp := &httpmsg.Response{Proto: "HTTP/1.1", Status: "200 OK", StatusCode: 200, Header: http.Header{}, Body: []byte(big)}
	out := Render(req, resp)
	if !strings.Contains(out, "truncated") {
		t.Error("large body should be truncated in render")
	}
}
