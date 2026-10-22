package csrf

import "testing"

func TestFormPoCAutoSubmits(t *testing.T) {
	out := Generate("POST", "https://bank.test/transfer", "application/x-www-form-urlencoded", "to=attacker&amount=1000")
	for _, want := range []string{`action="https://bank.test/transfer"`, `method="POST"`, `name="to"`, `value="attacker"`, "document.forms[0].submit()"} {
		if !contains(out, want) {
			t.Errorf("form PoC missing %q:\n%s", want, out)
		}
	}
}

func TestGETPoC(t *testing.T) {
	out := Generate("GET", "https://x.test/action?id=5", "", "")
	if !contains(out, `method="GET"`) || !contains(out, `name="id"`) {
		t.Errorf("GET PoC wrong:\n%s", out)
	}
}

func TestJSONPoCUsesFetch(t *testing.T) {
	out := Generate("POST", "https://api.test/x", "application/json", `{"a":1}`)
	if !contains(out, "fetch(") || !contains(out, "credentials: 'include'") {
		t.Errorf("JSON PoC should use fetch with credentials:\n%s", out)
	}
	// Angle brackets in the body must be escaped so an injected </script> in
	// the body cannot break out of the PoC's own script block.
	out2 := Generate("POST", "https://api.test/x", "application/json", `{"x":"</script><img>"}`)
	if !contains(out2, `\x3c/script\x3e`) {
		t.Errorf("body angle brackets not escaped in fetch PoC:\n%s", out2)
	}
	if contains(out2, `"</script><img>`) {
		t.Error("raw injected markup from the body survived into the PoC")
	}
}

func contains(h, n string) bool { return len(h) >= len(n) && indexOf(h, n) >= 0 }
func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
