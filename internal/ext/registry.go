package ext

import (
	"sync"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// Registry holds in-process ("native") extensions. Where the webhook Manager
// lets other-language extensions observe traffic over JSON, the Registry lets
// an extension compiled into Lanternfish participate in the core workflow the way a
// Burp Montoya extension does: edit requests and responses as they pass through
// the proxy, and contribute passive and active scan checks. It is an
// independent, clean-room API — conceptually similar to Montoya, not a port of
// it, and it does not load Burp's Java extensions.
//
// An extension is any value implementing Extension. It is given the Registry at
// registration time and wires itself up by calling the On*/Add* methods.
type Registry struct {
	mu          sync.RWMutex
	reqEditors  []func(*httpmsg.Request)
	respEditors []func(*httpmsg.Request, *httpmsg.Response)
	passive     []scan.PassiveCheck
	active      []scan.ActiveCheck
	names       []string
}

// Extension is a native extension. Register is called once with the Registry,
// where the extension attaches its handlers and checks.
type NativeExtension interface {
	Name() string
	Register(r *Registry)
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Use registers an extension, invoking its Register hook.
func (r *Registry) Use(e NativeExtension) {
	r.mu.Lock()
	r.names = append(r.names, e.Name())
	r.mu.Unlock()
	e.Register(r)
}

// OnRequest registers a proxy request editor.
func (r *Registry) OnRequest(f func(*httpmsg.Request)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqEditors = append(r.reqEditors, f)
}

// OnResponse registers a proxy response editor.
func (r *Registry) OnResponse(f func(*httpmsg.Request, *httpmsg.Response)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.respEditors = append(r.respEditors, f)
}

// AddPassiveCheck registers a passive scan check.
func (r *Registry) AddPassiveCheck(c scan.PassiveCheck) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passive = append(r.passive, c)
}

// AddActiveCheck registers an active scan check.
func (r *Registry) AddActiveCheck(c scan.ActiveCheck) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = append(r.active, c)
}

// RequestEditors / ResponseEditors / PassiveChecks / ActiveChecks / Names
// return copies of what has been registered, for the host to wire in.

func (r *Registry) RequestEditors() []func(*httpmsg.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]func(*httpmsg.Request){}, r.reqEditors...)
}

func (r *Registry) ResponseEditors() []func(*httpmsg.Request, *httpmsg.Response) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]func(*httpmsg.Request, *httpmsg.Response){}, r.respEditors...)
}

func (r *Registry) PassiveChecks() []scan.PassiveCheck {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]scan.PassiveCheck(nil), r.passive...)
}

func (r *Registry) ActiveChecks() []scan.ActiveCheck {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]scan.ActiveCheck(nil), r.active...)
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.names...)
}
