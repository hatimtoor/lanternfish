// Package sequencer estimates the randomness of a set of tokens (e.g. session
// IDs or CSRF tokens) using per-position Shannon entropy, the practical core of
// Burp's Sequencer.
package sequencer

import (
	"math"
	"sort"
)

// Result summarizes the randomness analysis.
type Result struct {
	Count              int       `json:"count"`
	MinLen             int       `json:"min_len"`
	MaxLen             int       `json:"max_len"`
	PerPositionEntropy []float64 `json:"per_position_entropy"` // bits per character position
	TotalEntropyBits   float64   `json:"total_entropy_bits"`
	EffectiveCharset   int       `json:"effective_charset"` // distinct chars observed
	Verdict            string    `json:"verdict"`
	Note               string    `json:"note"`
}

// Analyze computes entropy estimates over the tokens.
func Analyze(tokens []string) *Result {
	r := &Result{Count: len(tokens)}
	if len(tokens) < 2 {
		r.Verdict = "insufficient"
		r.Note = "Need at least 2 tokens; more (ideally 100+) gives a meaningful estimate."
		return r
	}
	minLen, maxLen := len(tokens[0]), len(tokens[0])
	for _, t := range tokens {
		if len(t) < minLen {
			minLen = len(t)
		}
		if len(t) > maxLen {
			maxLen = len(t)
		}
	}
	r.MinLen, r.MaxLen = minLen, maxLen

	charset := map[rune]bool{}
	for _, t := range tokens {
		for _, c := range t {
			charset[c] = true
		}
	}
	r.EffectiveCharset = len(charset)

	// Per-position Shannon entropy over the common prefix length.
	r.PerPositionEntropy = make([]float64, minLen)
	for pos := 0; pos < minLen; pos++ {
		freq := map[byte]int{}
		for _, t := range tokens {
			freq[t[pos]]++
		}
		r.PerPositionEntropy[pos] = shannon(freq, len(tokens))
		r.TotalEntropyBits += r.PerPositionEntropy[pos]
	}

	switch {
	case r.TotalEntropyBits >= 128:
		r.Verdict = "excellent"
	case r.TotalEntropyBits >= 64:
		r.Verdict = "strong"
	case r.TotalEntropyBits >= 40:
		r.Verdict = "moderate"
	default:
		r.Verdict = "weak"
	}
	r.Note = "Per-position Shannon entropy summed over the common prefix. An estimate, not a FIPS test; sample at least 100 tokens for confidence."
	return r
}

func shannon(freq map[byte]int, total int) float64 {
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

// SortedCharset returns the distinct characters observed, sorted (for display).
func SortedCharset(tokens []string) []string {
	seen := map[string]bool{}
	for _, t := range tokens {
		for _, c := range t {
			seen[string(c)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
