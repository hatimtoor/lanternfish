package fuzz

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// AttackType selects how payloads map onto positions, mirroring Burp Intruder.
type AttackType string

const (
	Sniper       AttackType = "sniper"       // one position at a time, one payload set
	BatteringRam AttackType = "batteringram" // same payload in every position
	Pitchfork    AttackType = "pitchfork"    // payload set per position, in lockstep
	ClusterBomb  AttackType = "clusterbomb"  // payload set per position, cartesian product
)

// MaxAttackRequests caps a single attack so cluster-bomb products cannot blow up.
const MaxAttackRequests = 20000

// Attack describes an Intruder-style attack over a raw request template whose
// payload positions are marked with the section sign, e.g. id=§1§&u=§bob§.
type Attack struct {
	Scheme      string     `json:"scheme"`
	Host        string     `json:"host"`
	Template    string     `json:"template"` // raw HTTP request with §...§ positions
	Type        AttackType `json:"type"`
	PayloadSets [][]string `json:"payload_sets"`
	GrepExtract string     `json:"grep_extract"` // optional regex; first group captured per response
	Concurrency int        `json:"concurrency"`
}

// AttackRow is one result.
type AttackRow struct {
	Payloads  []string `json:"payloads"`
	Status    int      `json:"status"`
	Length    int      `json:"length"`
	Millis    int64    `json:"millis"`
	Extracted string   `json:"extracted,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// AttackResult is the full outcome.
type AttackResult struct {
	Type      AttackType  `json:"type"`
	Positions int         `json:"positions"`
	Count     int         `json:"count"`
	Rows      []AttackRow `json:"rows"`
	Truncated bool        `json:"truncated,omitempty"`
}

var positionRE = regexp.MustCompile(`§([^§]*)§`)

// positions returns the baseline value of each §...§ marker in order.
func positions(tmpl string) []string {
	var out []string
	for _, m := range positionRE.FindAllStringSubmatch(tmpl, -1) {
		out = append(out, m[1])
	}
	return out
}

// render substitutes values into the template's positions in order. If fewer
// values than positions are supplied, remaining positions use their baseline.
func render(tmpl string, values []string) string {
	i := 0
	return positionRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		var v string
		if i < len(values) {
			v = values[i]
		} else {
			v = positionRE.FindStringSubmatch(m)[1] // baseline
		}
		i++
		return v
	})
}

// combos generates the ordered list of payload tuples for the attack type.
func combos(t AttackType, baselines []string, sets [][]string) [][]string {
	n := len(baselines)
	set := func(i int) []string {
		if i < len(sets) {
			return sets[i]
		}
		return nil
	}
	switch t {
	case BatteringRam:
		var out [][]string
		for _, p := range set(0) {
			row := make([]string, n)
			for i := range row {
				row[i] = p
			}
			out = append(out, row)
		}
		return out
	case Pitchfork:
		minLen := -1
		for i := 0; i < n; i++ {
			l := len(set(i))
			if minLen < 0 || l < minLen {
				minLen = l
			}
		}
		var out [][]string
		for k := 0; k < minLen; k++ {
			row := make([]string, n)
			for i := 0; i < n; i++ {
				row[i] = set(i)[k]
			}
			out = append(out, row)
		}
		return out
	case ClusterBomb:
		out := [][]string{append([]string(nil), baselines...)}
		for i := 0; i < n; i++ {
			s := set(i)
			if len(s) == 0 {
				continue
			}
			var next [][]string
			for _, prefix := range out {
				for _, p := range s {
					row := append([]string(nil), prefix...)
					row[i] = p
					next = append(next, row)
					if len(next) > MaxAttackRequests {
						return next
					}
				}
			}
			out = next
		}
		return out
	default: // Sniper
		var out [][]string
		for pi := 0; pi < n; pi++ {
			for _, p := range set(0) {
				row := append([]string(nil), baselines...)
				row[pi] = p
				out = append(out, row)
			}
		}
		return out
	}
}

// RunAttack executes the attack against sender.
func RunAttack(ctx context.Context, sender scan.Sender, a Attack) *AttackResult {
	baselines := positions(a.Template)
	conc := a.Concurrency
	if conc <= 0 {
		conc = 10
	}
	var grep *regexp.Regexp
	if a.GrepExtract != "" {
		grep, _ = regexp.Compile(a.GrepExtract)
	}

	tuples := combos(a.Type, baselines, a.PayloadSets)
	res := &AttackResult{Type: a.Type, Positions: len(baselines)}
	if len(tuples) > MaxAttackRequests {
		tuples = tuples[:MaxAttackRequests]
		res.Truncated = true
	}
	res.Count = len(tuples)
	rows := make([]AttackRow, len(tuples))

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for idx, tuple := range tuples {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, tuple []string) {
			defer wg.Done()
			defer func() { <-sem }()
			raw := render(a.Template, tuple)
			req, err := httpmsg.ParseRawRequest([]byte(raw), a.Scheme, a.Host)
			row := AttackRow{Payloads: tuple}
			if err != nil {
				row.Error = "parse: " + err.Error()
				rows[idx] = row
				return
			}
			start := time.Now()
			resp, err := sender.Send(ctx, req)
			row.Millis = time.Since(start).Milliseconds()
			if err != nil {
				row.Error = err.Error()
			} else {
				row.Status = resp.StatusCode
				row.Length = len(resp.Body)
				if grep != nil {
					if m := grep.FindStringSubmatch(resp.BodyString()); m != nil {
						row.Extracted = lastGroup(m)
					}
				}
			}
			rows[idx] = row
		}(idx, tuple)
	}
	wg.Wait()
	res.Rows = rows
	return res
}

func lastGroup(m []string) string {
	if len(m) > 1 {
		return m[1]
	}
	return m[0]
}

// CountPositions reports how many payload positions a template declares.
func CountPositions(tmpl string) int { return len(positions(tmpl)) }

var _ = strings.TrimSpace
