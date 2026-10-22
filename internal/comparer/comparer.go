// Package comparer diffs two texts (e.g. two responses) at word or line
// granularity, the equivalent of Burp's Comparer.
package comparer

import "strings"

// Op is a diff operation.
type Op string

const (
	Equal  Op = "equal"
	Insert Op = "insert" // present in b, not a
	Delete Op = "delete" // present in a, not b
)

// Segment is one piece of the diff.
type Segment struct {
	Op   Op     `json:"op"`
	Text string `json:"text"`
}

// Result is the diff plus summary counts.
type Result struct {
	Mode     string    `json:"mode"`
	Segments []Segment `json:"segments"`
	Added    int       `json:"added"`
	Removed  int       `json:"removed"`
	Same     int       `json:"same"`
}

// maxTokens caps the diff size to keep the O(n*m) LCS bounded.
const maxTokens = 6000

// Compare diffs a and b. mode is "line" or "word" (default line).
func Compare(a, b, mode string) *Result {
	var sa, sb []string
	switch mode {
	case "word":
		sa, sb = strings.Fields(a), strings.Fields(b)
	default:
		mode = "line"
		sa, sb = strings.Split(a, "\n"), strings.Split(b, "\n")
	}
	if len(sa) > maxTokens {
		sa = sa[:maxTokens]
	}
	if len(sb) > maxTokens {
		sb = sb[:maxTokens]
	}
	sep := "\n"
	if mode == "word" {
		sep = " "
	}
	segs := diff(sa, sb, sep)
	r := &Result{Mode: mode, Segments: segs}
	for _, s := range segs {
		switch s.Op {
		case Insert:
			r.Added++
		case Delete:
			r.Removed++
		default:
			r.Same++
		}
	}
	return r
}

// diff computes an LCS-based diff of the token slices.
func diff(a, b []string, sep string) []Segment {
	n, m := len(a), len(b)
	// LCS length table.
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out []Segment
	emit := func(op Op, text string) {
		if len(out) > 0 && out[len(out)-1].Op == op {
			out[len(out)-1].Text += sep + text
		} else {
			out = append(out, Segment{Op: op, Text: text})
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		if a[i] == b[j] {
			emit(Equal, a[i])
			i++
			j++
		} else if lcs[i+1][j] >= lcs[i][j+1] {
			emit(Delete, a[i])
			i++
		} else {
			emit(Insert, b[j])
			j++
		}
	}
	for ; i < n; i++ {
		emit(Delete, a[i])
	}
	for ; j < m; j++ {
		emit(Insert, b[j])
	}
	return out
}
