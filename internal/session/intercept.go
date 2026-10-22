package session

import (
	"sync"

	"lanternfish/internal/httpmsg"
)

// Decision is how a held request is resolved.
type Decision struct {
	Drop     bool
	Modified *httpmsg.Request // if non-nil, forward this instead of the original
}

// Pending is a request held for operator review.
type Pending struct {
	ID      int64            `json:"id"`
	Request *httpmsg.Request `json:"-"`
	resolve chan Decision
}

// Intercept is the hold-queue. When enabled, the proxy submits each in-scope
// request and blocks until the operator forwards or drops it.
type Intercept struct {
	// enabled is guarded by mu so that toggling off and draining the queue is
	// atomic with respect to Hold enqueuing a request. Guarding it with a
	// separate atomic created a race where a request that passed the enabled
	// check could enqueue after a drain and block forever.
	mu      sync.Mutex
	enabled bool
	nextID  int64
	pending map[int64]*Pending
	order   []int64
}

func newIntercept() *Intercept {
	return &Intercept{pending: map[int64]*Pending{}}
}

// Enabled reports whether interception is on.
func (i *Intercept) Enabled() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.enabled
}

// SetEnabled toggles interception. Disabling forwards all held requests as-is.
func (i *Intercept) SetEnabled(on bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.enabled = on
	if !on {
		for _, p := range i.pending {
			select {
			case p.resolve <- Decision{}:
			default:
			}
		}
		i.pending = map[int64]*Pending{}
		i.order = nil
	}
}

// Hold submits req for review and blocks until resolved. If interception is
// off it returns immediately with the original request. The returned request
// is what should actually be sent (possibly edited); drop is true to drop it.
func (i *Intercept) Hold(req *httpmsg.Request) (send *httpmsg.Request, drop bool) {
	i.mu.Lock()
	if !i.enabled {
		i.mu.Unlock()
		return req, false
	}
	i.nextID++
	id := i.nextID
	p := &Pending{ID: id, Request: req, resolve: make(chan Decision, 1)}
	i.pending[id] = p
	i.order = append(i.order, id)
	i.mu.Unlock()

	d := <-p.resolve
	if d.Drop {
		return nil, true
	}
	if d.Modified != nil {
		return d.Modified, false
	}
	return req, false
}

// List returns the currently held requests in arrival order.
func (i *Intercept) List() []*Pending {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]*Pending, 0, len(i.order))
	for _, id := range i.order {
		if p := i.pending[id]; p != nil {
			out = append(out, p)
		}
	}
	return out
}

// Peek returns one held request by id.
func (i *Intercept) Peek(id int64) *Pending {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.pending[id]
}

// Forward releases a held request, optionally replacing it with modified.
func (i *Intercept) Forward(id int64, modified *httpmsg.Request) bool {
	return i.resolve(id, Decision{Modified: modified})
}

// Drop discards a held request.
func (i *Intercept) Drop(id int64) bool {
	return i.resolve(id, Decision{Drop: true})
}

func (i *Intercept) resolve(id int64, d Decision) bool {
	i.mu.Lock()
	p := i.pending[id]
	if p == nil {
		i.mu.Unlock()
		return false
	}
	delete(i.pending, id)
	for idx, oid := range i.order {
		if oid == id {
			i.order = append(i.order[:idx], i.order[idx+1:]...)
			break
		}
	}
	i.mu.Unlock()
	p.resolve <- d
	return true
}

// PendingCount returns the number of held requests.
func (i *Intercept) PendingCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.pending)
}
