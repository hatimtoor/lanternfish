package checks

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"lanternfish/internal/httpmsg"
)

// jitterSender returns benign responses whose length varies by `jitter` bytes
// each call, and fixed lengths for the true/false payloads.
func jitterSender(jitter, trueLen, falseLen int) fakeSender {
	call := 0
	return fakeSender{fn: func(r *httpmsg.Request) *httpmsg.Response {
		q := r.URL.Query().Get("id")
		var n int
		switch {
		case strings.Contains(q, "TRUEPL"):
			n = trueLen
		case strings.Contains(q, "FALSEPL"):
			n = falseLen
		default: // benign baseline sample
			n = 600 + (call%3)*jitter
			call++
		}
		return &httpmsg.Response{StatusCode: 200, Header: http.Header{}, Body: []byte(strings.Repeat("x", n))}
	}}
}

func TestBoolDiffIgnoresJitter(t *testing.T) {
	_, p := queryPoint(t, "http://x/p?id=1")
	// Big natural jitter (~120 across benign samples); true/false differ by only
	// ~30 bytes -> must NOT be reported.
	ev, ok := boolDiffInjection(context.Background(), jitterSender(60, 640, 610), p, "TRUEPL", "FALSEPL")
	if ok {
		t.Errorf("jittery page with small true/false delta should not fire: %q", ev)
	}
}

func TestBoolDiffFiresOnClearDifference(t *testing.T) {
	_, p := queryPoint(t, "http://x/p?id=1")
	// Stable page (jitter 0), true/false differ hugely -> reported.
	ev, ok := boolDiffInjection(context.Background(), jitterSender(0, 2000, 300), p, "TRUEPL", "FALSEPL")
	if !ok {
		t.Errorf("clear true/false difference on a stable page should fire")
	}
	_ = ev
}
