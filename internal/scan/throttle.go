package scan

import (
	"context"
	"sync"
	"time"

	"lanternfish/internal/httpmsg"
)

// throttle wraps a Sender to cap the request rate across all concurrent
// probes. Scanning someone else's production system politely — without
// hammering it, tripping rate limits, or causing harm — matters as much as
// finding the bug, so this bounds requests per second globally while still
// allowing the engine's concurrency up to that ceiling.
type throttle struct {
	s        Sender
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// NewThrottle returns a Sender that admits at most perSec requests per second.
// perSec <= 0 disables throttling and returns s unchanged.
func NewThrottle(s Sender, perSec float64) Sender {
	if perSec <= 0 {
		return s
	}
	return &throttle{s: s, interval: time.Duration(float64(time.Second) / perSec)}
}

func (t *throttle) Send(ctx context.Context, r *httpmsg.Request) (*httpmsg.Response, error) {
	t.mu.Lock()
	now := time.Now()
	var wait time.Duration
	if t.next.After(now) {
		wait = t.next.Sub(now)
		t.next = t.next.Add(t.interval)
	} else {
		t.next = now.Add(t.interval)
	}
	t.mu.Unlock()

	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return t.s.Send(ctx, r)
}
