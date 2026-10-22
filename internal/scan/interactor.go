package scan

import "context"

// Interactor is an out-of-band callback provider (implemented by the oast
// package). Checks use it to detect blind vulnerabilities: they mint a payload
// URL, inject it, and see whether the target called back.
type Interactor interface {
	NewPayload() (token, url string)
	Hits(token string) int
	HitDetails(token string) []string
}

type interactorKey struct{}

// WithInteractor attaches an Interactor to ctx for checks to use.
func WithInteractor(ctx context.Context, i Interactor) context.Context {
	return context.WithValue(ctx, interactorKey{}, i)
}

// InteractorFrom returns the Interactor attached to ctx, if any.
func InteractorFrom(ctx context.Context) (Interactor, bool) {
	i, ok := ctx.Value(interactorKey{}).(Interactor)
	return i, ok && i != nil
}
