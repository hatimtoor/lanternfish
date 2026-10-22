package scan

import (
	"context"
	"sync"

	"lanternfish/internal/httpmsg"
)

// Engine runs registered checks against transactions and requests.
type Engine struct {
	passive []PassiveCheck
	active  []ActiveCheck
	request []RequestCheck

	// Concurrency bounds simultaneous active probes.
	Concurrency int
}

// NewEngine builds an engine from registered checks.
func NewEngine(passive []PassiveCheck, active []ActiveCheck) *Engine {
	return &Engine{passive: passive, active: active, Concurrency: 10}
}

// WithRequestChecks adds request-level checks and returns the engine.
func (e *Engine) WithRequestChecks(rc []RequestCheck) *Engine {
	e.request = rc
	return e
}

// AddPassive registers an extra passive check (e.g. from an extension).
func (e *Engine) AddPassive(c ...PassiveCheck) { e.passive = append(e.passive, c...) }

// AddActive registers an extra active check (e.g. from an extension).
func (e *Engine) AddActive(c ...ActiveCheck) { e.active = append(e.active, c...) }

// Passive runs all passive checks over one transaction.
func (e *Engine) Passive(tx *httpmsg.Transaction, col *Collector) {
	for _, c := range e.passive {
		col.Add(c.Passive(tx)...)
	}
}

// Audit runs all active checks against every insertion point of base,
// bounded by Concurrency. The Collector is safe for concurrent Add.
func (e *Engine) Audit(ctx context.Context, s Sender, base *httpmsg.Request, col *Collector) {
	var mu0 sync.Mutex
	// Request-level checks run once, regardless of insertion points.
	for _, rc := range e.request {
		if ctx.Err() != nil {
			break
		}
		issues := rc.Request(ctx, s, base)
		if len(issues) > 0 {
			mu0.Lock()
			col.Add(issues...)
			mu0.Unlock()
		}
	}

	points := InsertionPoints(base)
	if len(points) == 0 {
		return
	}
	sem := make(chan struct{}, e.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, pt := range points {
		for _, chk := range e.active {
			if ctx.Err() != nil {
				break
			}
			if ka, ok := chk.(KindAwareCheck); ok && !ka.AppliesTo(pt.Kind) {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(chk ActiveCheck, pt InsertionPoint) {
				defer wg.Done()
				defer func() { <-sem }()
				issues := chk.Active(ctx, s, base, pt)
				if len(issues) > 0 {
					mu.Lock()
					col.Add(issues...)
					mu.Unlock()
				}
			}(chk, pt)
		}
	}
	wg.Wait()
}
