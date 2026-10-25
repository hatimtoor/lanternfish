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

func boardPoint(t *testing.T) (*httpmsg.Request, scan.InsertionPoint) {
	t.Helper()
	u, _ := url.Parse("http://x/board?comment=hi")
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x", Header: http.Header{}}
	for _, ip := range scan.InsertionPoints(base) {
		if ip.Name == "comment" {
			return base, ip
		}
	}
	t.Fatal("no comment point")
	return nil, scan.InsertionPoint{}
}

func TestStoredXSSDetectsPersistedMarker(t *testing.T) {
	var stored string
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		q := r.URL.Query().Get("comment")
		if strings.Contains(q, "lfstored") { // the injection request stores it
			stored = q
		}
		h := http.Header{}
		h.Set("Content-Type", "text/html")
		body := "<html><body><div class=comments>" + stored + "</div></body></html>"
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte(body)}
	}}
	base, p := boardPoint(t)
	issues := (StoredXSS{}).Active(context.Background(), sender, base, p)
	if len(issues) == 0 || issues[0].Check != "stored-xss" {
		t.Fatalf("expected stored-xss finding, got %v", issues)
	}
}

func TestStoredXSSCleanWhenEncoded(t *testing.T) {
	var stored string
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		q := r.URL.Query().Get("comment")
		if strings.Contains(q, "lfstored") {
			// Safe app: store, but HTML-encode on output.
			stored = strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(q)
		}
		h := http.Header{}
		h.Set("Content-Type", "text/html")
		return &httpmsg.Response{StatusCode: 200, Header: h, Body: []byte("<html>" + stored + "</html>")}
	}}
	base, p := boardPoint(t)
	if issues := (StoredXSS{}).Active(context.Background(), sender, base, p); len(issues) != 0 {
		t.Errorf("encoded output => no finding, got %v", issues)
	}
}
