package service

import (
	"context"
	"sync"
	"time"
)

// Schedule is a recurring scan.
type Schedule struct {
	ID          int64  `json:"id"`
	URL         string `json:"url"`
	IntervalSec int    `json:"interval_sec"`
	Runs        int    `json:"runs"`
	LastIssues  int    `json:"last_issues"`
	cancel      context.CancelFunc
}

type scheduler struct {
	mu     sync.Mutex
	nextID int64
	items  map[int64]*Schedule
}

func newScheduler() *scheduler { return &scheduler{items: map[int64]*Schedule{}} }

// Schedule registers a recurring scan of url every intervalSec seconds and
// starts it in the background. Minimum interval is 10s.
func (s *Service) Schedule(url string, intervalSec int) *Schedule {
	if intervalSec < 10 {
		intervalSec = 10
	}
	s.sched.mu.Lock()
	s.sched.nextID++
	id := s.sched.nextID
	ctx, cancel := context.WithCancel(context.Background())
	sc := &Schedule{ID: id, URL: url, IntervalSec: intervalSec, cancel: cancel}
	s.sched.items[id] = sc
	s.sched.mu.Unlock()

	go func() {
		ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				res, err := s.ScanURL(ctx, url)
				s.sched.mu.Lock()
				if cur, ok := s.sched.items[id]; ok {
					cur.Runs++
					if err == nil {
						cur.LastIssues = len(res.Issues)
					}
				}
				s.sched.mu.Unlock()
			}
		}
	}()
	return sc
}

// Schedules lists the active recurring scans.
func (s *Service) Schedules() []Schedule {
	s.sched.mu.Lock()
	defer s.sched.mu.Unlock()
	out := make([]Schedule, 0, len(s.sched.items))
	for _, sc := range s.sched.items {
		out = append(out, *sc)
	}
	return out
}

// Unschedule stops and removes a recurring scan.
func (s *Service) Unschedule(id int64) bool {
	s.sched.mu.Lock()
	defer s.sched.mu.Unlock()
	sc, ok := s.sched.items[id]
	if !ok {
		return false
	}
	sc.cancel()
	delete(s.sched.items, id)
	return true
}
