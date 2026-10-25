package scan

import (
	"context"
	"net/url"
	"testing"
	"time"

	"lanternfish/internal/httpmsg"
)

type countSender struct{ n int }

func (c *countSender) Send(_ context.Context, _ *httpmsg.Request) (*httpmsg.Response, error) {
	c.n++
	return &httpmsg.Response{StatusCode: 200, Body: []byte("ok")}, nil
}

func TestThrottleDisabledReturnsSame(t *testing.T) {
	cs := &countSender{}
	if NewThrottle(cs, 0) != Sender(cs) {
		t.Error("rate 0 should return the sender unchanged")
	}
}

func TestThrottleCapsRate(t *testing.T) {
	cs := &countSender{}
	th := NewThrottle(cs, 100) // 100/s => ~10ms apart
	u, _ := url.Parse("http://x/")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "http", Host: "x"}
	start := time.Now()
	for i := 0; i < 6; i++ {
		th.Send(context.Background(), req)
	}
	elapsed := time.Since(start)
	// 6 requests at 10ms spacing => at least ~40ms (generous slack for CI).
	if elapsed < 35*time.Millisecond {
		t.Errorf("throttle too fast: %v for 6 requests at 100/s", elapsed)
	}
	if cs.n != 6 {
		t.Errorf("sent %d, want 6", cs.n)
	}
}
