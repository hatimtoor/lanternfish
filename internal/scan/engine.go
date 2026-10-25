package scan

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lanternfish/internal/httpmsg"
)

// OOBWatch pairs the callback tokens an out-of-band probe is waiting on with the
// issue to report if any of them is hit. The Issue's Evidence is filled in by
// the engine from the interactor when a callback arrives.
type OOBWatch struct {
	Tokens []string
	Issue  *Issue
}

// OOBCheck is an active check whose detection is an out-of-band callback. The
// engine calls ProbeOOB to fire payloads for an insertion point *without*
// waiting, then polls every watch once after the whole audit pass. That turns N
// insertion points from N separate multi-second sleeps into a single settle
// window for the entire scan — the difference between a usable scan and one that
// crawls once out-of-band checks are enabled.
type OOBCheck interface {
	ProbeOOB(ctx context.Context, s Sender, base *httpmsg.Request, p InsertionPoint) []OOBWatch
}

// oobSettleWindow is how long the engine waits, once, for out-of-band callbacks
// to arrive after all probes have been fired.
const oobSettleWindow = 6 * time.Second

// Engine runs registered checks against transactions and requests.
type Engine struct {
	passive []PassiveCheck
	active  []ActiveCheck
	request []RequestCheck

	// Concurrency bounds simultaneous active probes.
	Concurrency int

	// OnProgress, if set, is called as active-check tasks complete, with the
	// number done and the total planned. It may be called from many goroutines,
	// so an implementation must be safe for concurrent use.
	OnProgress func(done, total int)
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

// AddRequestChecks registers extra request-level checks (e.g. opt-in intrusive
// checks enabled at the CLI).
func (e *Engine) AddRequestChecks(c ...RequestCheck) { e.request = append(e.request, c...) }

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
	// Count the planned tasks up front so progress can be reported as a fraction.
	total := 0
	for _, pt := range points {
		for _, chk := range e.active {
			if ka, ok := chk.(KindAwareCheck); ok && !ka.AppliesTo(pt.Kind) {
				continue
			}
			total++
		}
	}
	var done int64

	sem := make(chan struct{}, e.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var watches []OOBWatch

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
				defer func() {
					if e.OnProgress != nil {
						e.OnProgress(int(atomic.AddInt64(&done, 1)), total)
					}
				}()
				// Out-of-band checks fire their payloads now and are polled once
				// after the pass, instead of each sleeping for a callback.
				if oob, ok := chk.(OOBCheck); ok {
					ws := oob.ProbeOOB(ctx, s, base, pt)
					if len(ws) > 0 {
						mu.Lock()
						watches = append(watches, ws...)
						mu.Unlock()
					}
					return
				}
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

	e.collectOOB(ctx, watches, col)
}

// collectOOB waits once for out-of-band callbacks after all probes have been
// fired, then emits an issue for every watch whose token was hit.
func (e *Engine) collectOOB(ctx context.Context, watches []OOBWatch, col *Collector) {
	if len(watches) == 0 {
		return
	}
	inter, ok := InteractorFrom(ctx)
	if !ok {
		return
	}
	// Poll periodically within a single window so we return as soon as every
	// watch is resolved rather than always waiting the full time.
	deadline := time.Now().Add(oobSettleWindow)
	pending := make([]bool, len(watches))
	for i := range pending {
		pending[i] = true
	}
	for {
		remaining := 0
		for i, w := range watches {
			if !pending[i] {
				continue
			}
			hit := false
			for _, tok := range w.Tokens {
				if inter.Hits(tok) > 0 {
					hit = true
					if w.Issue != nil {
						w.Issue.Evidence = strings.Join(inter.HitDetails(tok), "; ")
						col.Add(w.Issue)
					}
					break
				}
			}
			if hit {
				pending[i] = false
			} else {
				remaining++
			}
		}
		if remaining == 0 || time.Now().After(deadline) || ctx.Err() != nil {
			return
		}
		time.Sleep(400 * time.Millisecond)
	}
}
