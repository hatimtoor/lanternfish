package comparer

import "testing"

func TestLineDiff(t *testing.T) {
	a := "one\ntwo\nthree"
	b := "one\ntwoX\nthree"
	r := Compare(a, b, "line")
	if r.Added == 0 || r.Removed == 0 {
		t.Errorf("expected add+remove for the changed line: %+v", r)
	}
	if r.Same == 0 {
		t.Error("expected some equal segments")
	}
}

func TestIdentical(t *testing.T) {
	r := Compare("same\ntext", "same\ntext", "line")
	if r.Added != 0 || r.Removed != 0 {
		t.Errorf("identical inputs should have no changes: %+v", r)
	}
}

func TestWordMode(t *testing.T) {
	r := Compare("the quick brown fox", "the slow brown fox", "word")
	if r.Mode != "word" {
		t.Errorf("mode not honored: %s", r.Mode)
	}
	if r.Added == 0 || r.Removed == 0 {
		t.Error("expected a word change")
	}
}
