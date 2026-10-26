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

func qPoint(t *testing.T, raw, name string) (*httpmsg.Request, scan.InsertionPoint) {
	t.Helper()
	u, _ := url.Parse(raw)
	base := &httpmsg.Request{Method: "GET", URL: u, Scheme: u.Scheme, Host: u.Host, Header: http.Header{}}
	for _, ip := range scan.InsertionPoints(base) {
		if ip.Name == name {
			return base, ip
		}
	}
	t.Fatalf("no insertion point for %q", name)
	return nil, scan.InsertionPoint{}
}

// likeSearchSender emulates a search endpoint whose SQL is
//
//	... WHERE name LIKE '%<q>%' OR description LIKE '%<q>%' ...
//
// An empty query matches all rows (big). "' OR '1'='1" keeps the match
// universal (big ≈ baseline); "' AND '1'='2" collapses to no rows (small).
// Plain AND-tautologies ("' AND '1'='1") are broken by the trailing "%'" of the
// LIKE pattern and also return no rows — exactly the context where AND/AND pairs
// miss the injection and OR-true/AND-false pairs are required.
func likeSearchSender() fakeSender {
	big := strings.Repeat("x", 2000)
	small := strings.Repeat("y", 40)
	return fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		q := r.URL.Query().Get("q")
		universal := q == "" ||
			strings.Contains(q, "OR '1'='1") ||
			strings.Contains(q, `OR "1"="1`)
		body := small
		if universal {
			body = big
		}
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte(body)}
	}}
}

func TestBooleanBlindSQLiFiresOnLikeContext(t *testing.T) {
	base, p := qPoint(t, "http://x/rest/products/search?q=", "q")
	iss := (BooleanBlindSQLi{}).Active(context.Background(), likeSearchSender(), base, p)
	if len(iss) != 1 || iss[0].Check != "sqli-boolean-blind" {
		t.Fatalf("expected one sqli-boolean-blind finding in a LIKE context, got %+v", iss)
	}
	if iss[0].CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %q", iss[0].CWE)
	}
}
