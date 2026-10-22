package clickjack

import "strings"

import "testing"

func TestGenerate(t *testing.T) {
	out := Generate("https://bank.test/transfer", 0.2)
	for _, want := range []string{"<iframe", `src="https://bank.test/transfer"`, "opacity:0.20", "Clickbandit"} {
		if !strings.Contains(out, want) {
			t.Errorf("PoC missing %q:\n%s", want, out)
		}
	}
}

func TestGenerateEscapesURL(t *testing.T) {
	out := Generate(`https://x/"><script>alert(1)</script>`, 1.5) // bad opacity clamps
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("URL not escaped in PoC")
	}
	if !strings.Contains(out, "opacity:0.10") {
		t.Error("out-of-range opacity should clamp to default 0.10")
	}
}
