package kb

import "testing"

func TestLookup(t *testing.T) {
	// Exact id.
	if e, ok := Lookup("reflected-xss"); !ok || e.Title == "" || len(e.Refs) == 0 {
		t.Fatalf("reflected-xss: ok=%v title=%q refs=%d", ok, e.Title, len(e.Refs))
	}
	// Family prefix: a specific SQLi engine id resolves to the shared sqli entry.
	if e, ok := Lookup("sqli-postgres"); !ok || e.Title == "" {
		t.Fatalf("sqli-postgres should resolve via prefix, got ok=%v", ok)
	}
	// Secret family.
	if _, ok := Lookup("secret-stripe-key"); !ok {
		t.Fatalf("secret-* should resolve via prefix")
	}
	// Unknown.
	if _, ok := Lookup("totally-unknown-check"); ok {
		t.Fatalf("unknown check should not resolve")
	}
}

func TestEntriesWellFormed(t *testing.T) {
	for _, k := range Keys() {
		e, _ := Lookup(k)
		if e.Title == "" || e.What == "" || e.Fix == "" {
			t.Fatalf("entry %q missing required fields", k)
		}
	}
}
