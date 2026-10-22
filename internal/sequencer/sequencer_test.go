package sequencer

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestInsufficientTokens(t *testing.T) {
	if Analyze(nil).Verdict != "insufficient" {
		t.Error("nil tokens should be insufficient")
	}
	if Analyze([]string{"a"}).Verdict != "insufficient" {
		t.Error("single token should be insufficient")
	}
}

func TestConstantTokensHaveZeroEntropy(t *testing.T) {
	toks := make([]string, 50)
	for i := range toks {
		toks[i] = "AAAAAAAA"
	}
	r := Analyze(toks)
	if r.TotalEntropyBits != 0 {
		t.Errorf("identical tokens should have 0 entropy, got %f", r.TotalEntropyBits)
	}
	if r.Verdict != "weak" {
		t.Errorf("constant tokens should be weak, got %s", r.Verdict)
	}
}

func TestRandomTokensHaveHighEntropy(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	toks := make([]string, 400)
	for i := range toks {
		b := make([]byte, 32)
		for j := range b {
			b[j] = charset[rand.Intn(len(charset))]
		}
		toks[i] = string(b)
	}
	r := Analyze(toks)
	if r.TotalEntropyBits < 64 {
		t.Errorf("random 32-char tokens should estimate high entropy, got %f", r.TotalEntropyBits)
	}
	if r.Verdict != "strong" && r.Verdict != "excellent" {
		t.Errorf("random tokens should be strong/excellent, got %s", r.Verdict)
	}
}

var _ = fmt.Sprint
