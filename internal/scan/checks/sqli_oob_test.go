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

// stubInteractor records a hit once a payload containing its host is sent.
type stubInteractor struct {
	host            string
	dnsTok, httpTok string
	hit             bool
}

func (s *stubInteractor) NewPayload() (string, string) {
	return s.httpTok, "http://" + s.host + "/" + s.httpTok
}
func (s *stubInteractor) NewDNSPayload() (string, string, bool) { return s.dnsTok, s.host, true }
func (s *stubInteractor) Hits(tok string) int {
	if s.hit && (tok == s.dnsTok || tok == s.httpTok) {
		return 1
	}
	return 0
}
func (s *stubInteractor) HitDetails(tok string) []string {
	if s.Hits(tok) > 0 {
		return []string{"DNS from 203.0.113.9 (" + s.host + ")"}
	}
	return nil
}

func queryPoint(t *testing.T, raw string) (*httpmsg.Request, scan.InsertionPoint) {
	t.Helper()
	u, _ := url.Parse(raw)
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}}
	for _, ip := range scan.InsertionPoints(base) {
		if ip.Name == "id" {
			return base, ip
		}
	}
	t.Fatal("no insertion point for id")
	return nil, scan.InsertionPoint{}
}

func TestBlindSQLiOOBFiresOnCallback(t *testing.T) {
	stub := &stubInteractor{host: "abc123xyz.oast.test", dnsTok: "dtok", httpTok: "htok"}
	// A vulnerable DB performs the UNC/DNS lookup: seeing the host go out, the
	// collaborator records a hit.
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		if strings.Contains(r.URL.RawQuery, "oast.test") || strings.Contains(string(r.Body), "oast.test") {
			stub.hit = true
		}
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("ok")}
	}}
	base, p := queryPoint(t, "http://x/p?id=1")
	ctx := scan.WithInteractor(context.Background(), stub)
	issues := (BlindSQLiOOB{}).Active(ctx, sender, base, p)
	if len(issues) == 0 || issues[0].Check != "sqli-oob" {
		t.Fatalf("expected sqli-oob finding, got %v", issues)
	}
	if issues[0].Severity != scan.SeverityCritical {
		t.Errorf("expected critical severity")
	}
}

func TestBlindSQLiOOBSilentWithoutCallback(t *testing.T) {
	stub := &stubInteractor{host: "abc123xyz.oast.test", dnsTok: "dtok", httpTok: "htok"}
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("ok")}
	}}
	base, p := queryPoint(t, "http://x/p?id=1")
	ctx := scan.WithInteractor(context.Background(), stub)
	if issues := (BlindSQLiOOB{}).Active(ctx, sender, base, p); len(issues) != 0 {
		t.Errorf("no callback => no finding, got %v", issues)
	}
}

func TestBlindSQLiOOBNoInteractorNoop(t *testing.T) {
	sender := fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		t.Error("should not send without an interactor")
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("")}
	}}
	base, p := queryPoint(t, "http://x/p?id=1")
	if issues := (BlindSQLiOOB{}).Active(context.Background(), sender, base, p); len(issues) != 0 {
		t.Error("expected no finding without an interactor")
	}
}
