package fuzz

import (
	"context"
	"strings"
	"sync"
	"testing"

	"lanternfish/internal/httpmsg"
)

// capSender records the requests it is asked to send. Run calls Send from
// multiple goroutines, so (like any real scan.Sender) it must be safe for
// concurrent use.
type capSender struct {
	mu   sync.Mutex
	seen []string
}

func (c *capSender) Send(_ context.Context, r *httpmsg.Request) (*httpmsg.Response, error) {
	c.mu.Lock()
	c.seen = append(c.seen, r.AbsoluteURL().String()+"|"+string(r.Body))
	c.mu.Unlock()
	body := []byte("len" + r.URL.Query().Get("q"))
	return &httpmsg.Response{StatusCode: 200, Header: map[string][]string{}, Body: body}, nil
}

func TestMarkerSubstitutionURLAndBody(t *testing.T) {
	cs := &capSender{}
	res := Run(context.Background(), cs, Spec{
		Method: "POST", URL: "http://h/p?q=FUZZ", Body: "x=FUZZ",
		Payloads: []string{"a", "bb"},
	})
	if res.Count != 2 || len(res.Rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(res.Rows))
	}
	joined := strings.Join(cs.seen, " ")
	if !strings.Contains(joined, "q=a") || !strings.Contains(joined, "x=a") {
		t.Errorf("marker not substituted in url and body: %v", cs.seen)
	}
}

func TestDefaultMarkerAndSort(t *testing.T) {
	cs := &capSender{}
	res := Run(context.Background(), cs, Spec{URL: "http://h/p?q=FUZZ", Payloads: []string{"aaa", "a", "aa"}})
	// Rows sorted by status then length; all status 200, so by length asc.
	for i := 1; i < len(res.Rows); i++ {
		if res.Rows[i-1].Length > res.Rows[i].Length {
			t.Errorf("rows not sorted by length: %+v", res.Rows)
		}
	}
}

type errSender struct{}

func (errSender) Send(_ context.Context, r *httpmsg.Request) (*httpmsg.Response, error) {
	return nil, context.DeadlineExceeded
}

func TestBadURLAndSendErrorRecorded(t *testing.T) {
	res := Run(context.Background(), errSender{}, Spec{URL: "http://h/p?q=FUZZ", Payloads: []string{"x"}})
	if len(res.Rows) != 1 || res.Rows[0].Error == "" {
		t.Errorf("send error should be recorded in the row: %+v", res.Rows)
	}
}
