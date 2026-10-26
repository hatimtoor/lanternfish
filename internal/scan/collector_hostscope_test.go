package scan

import "testing"

func TestCollectorHostScopedDedup(t *testing.T) {
	c := NewCollector()
	// Same host-scoped finding on two URLs of one host -> kept once.
	c.Add(&Issue{Check: "fingerprint-flask", Name: "Technology detected: Flask", URL: "http://x/a", HostScoped: true})
	c.Add(&Issue{Check: "fingerprint-flask", Name: "Technology detected: Flask", URL: "http://x/b", HostScoped: true})
	// A non-host-scoped finding on two URLs -> kept twice.
	c.Add(&Issue{Check: "reflected-xss", Name: "XSS", URL: "http://x/a", Param: "q"})
	c.Add(&Issue{Check: "reflected-xss", Name: "XSS", URL: "http://x/b", Param: "q"})
	// Two distinct names of one check on one URL -> both kept (Name in key).
	c.Add(&Issue{Check: "security-headers", Name: "Missing CSP", URL: "http://x/a", HostScoped: true})
	c.Add(&Issue{Check: "security-headers", Name: "Missing nosniff", URL: "http://x/a", HostScoped: true})

	n := func(check string) int {
		k := 0
		for _, is := range c.Issues() {
			if is.Check == check {
				k++
			}
		}
		return k
	}
	if got := n("fingerprint-flask"); got != 1 {
		t.Errorf("host-scoped fingerprint should dedup to 1, got %d", got)
	}
	if got := n("reflected-xss"); got != 2 {
		t.Errorf("per-URL XSS should keep 2, got %d", got)
	}
	if got := n("security-headers"); got != 2 {
		t.Errorf("distinct header findings should both survive, got %d", got)
	}
}
