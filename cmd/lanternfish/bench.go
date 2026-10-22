package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"lanternfish/internal/service"
	"lanternfish/internal/session"
)

// benchSpec is a labeled benchmark: a base URL and cases whose expected (or
// absent) findings are known, so we can score detection and false positives.
type benchSpec struct {
	Name  string      `json:"name"`
	Base  string      `json:"base"`
	Cases []benchCase `json:"cases"`
}

type benchCase struct {
	Path   string   `json:"path"`             // appended to Base
	Expect []string `json:"expect,omitempty"` // check ids that should fire (prefix match)
	Clean  bool     `json:"clean,omitempty"`  // true = no high/critical finding should fire
	Note   string   `json:"note,omitempty"`
}

// cmdBench scores Lanternfish against a labeled benchmark spec. It is how we
// measure accuracy over time — the open equivalent of the feedback a commercial
// scanner gets from its users.
func cmdBench(args []string) {
	fs := newFlagSet("bench")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	fast := fs.Bool("fast", false, "skip wait-heavy checks (faster, misses blind/time-based)")
	asJSON := fs.Bool("json", false, "emit the scorecard as JSON")
	pos := mustParse(fs, args)

	specPath := firstArg(pos)
	if specPath == "" {
		log.Fatal("bench: a spec file is required (e.g. benchmarks/testbed.json)")
	}
	raw, err := os.ReadFile(specPath)
	if err != nil {
		log.Fatalf("bench: %v", err)
	}
	var spec benchSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		log.Fatalf("bench: parse %s: %v", specPath, err)
	}

	svc := service.New(session.New(), *insecure)
	if !*fast {
		svc.EnsureOAST()
	}
	// Wait for the target to be reachable so a cold-start connection refusal is
	// not scored as a missed finding.
	waitReady(spec.Base)
	ctx, cancel := signalContext()
	defer cancel()

	var expectedTotal, detected, falsePos, cleanCases int
	type row struct {
		Path   string   `json:"path"`
		Expect []string `json:"expect,omitempty"`
		Missed []string `json:"missed,omitempty"`
		FPs    []string `json:"false_positives,omitempty"`
		Clean  bool     `json:"clean,omitempty"`
	}
	var rows []row

	start := time.Now()
	for _, c := range spec.Cases {
		res, err := svc.ScanURLMode(ctx, spec.Base+c.Path, *fast)
		got := map[string]string{} // check id -> severity
		if err == nil {
			for _, is := range res.Issues {
				got[is.Check] = is.SeverityStr
			}
		}
		r := row{Path: c.Path, Expect: c.Expect, Clean: c.Clean}
		for _, want := range c.Expect {
			expectedTotal++
			if matchFound(got, want) {
				detected++
			} else {
				r.Missed = append(r.Missed, want)
			}
		}
		if c.Clean {
			cleanCases++
			for id, sev := range got {
				if sev == "high" || sev == "critical" {
					falsePos++
					r.FPs = append(r.FPs, id)
				}
			}
		}
		rows = append(rows, r)
	}
	dur := time.Since(start).Round(time.Millisecond)

	if *asJSON {
		out := map[string]any{
			"benchmark": spec.Name, "expected": expectedTotal, "detected": detected,
			"recall": pct(detected, expectedTotal), "clean_cases": cleanCases,
			"false_positives": falsePos, "duration": dur.String(), "cases": rows,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	name := spec.Name
	if name == "" {
		name = specPath
	}
	fmt.Printf("Benchmark: %s (%s)\n\n", name, dur)
	for _, r := range rows {
		status := "ok"
		if len(r.Missed) > 0 {
			status = "MISSED " + strings.Join(r.Missed, ",")
		}
		if len(r.FPs) > 0 {
			status = "FALSE-POSITIVE " + strings.Join(r.FPs, ",")
		}
		fmt.Printf("  %-34s %s\n", r.Path, status)
	}
	fmt.Printf("\nDetection: %d/%d expected findings (%s recall)\n", detected, expectedTotal, pct(detected, expectedTotal))
	fmt.Printf("False positives: %d across %d clean case(s)\n", falsePos, cleanCases)
}

// matchFound reports whether any detected check id equals or is prefixed by want
// (so "sqli" matches sqli-error, sqli-mysql, etc.).
func matchFound(got map[string]string, want string) bool {
	for id := range got {
		if id == want || strings.HasPrefix(id, want) {
			return true
		}
	}
	return false
}

// waitReady polls base until it responds (or gives up after ~6s), so a target
// that is still starting up does not produce spurious misses.
func waitReady(base string) {
	c := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < 30; i++ {
		if resp, err := c.Get(base); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func pct(n, d int) string {
	if d == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(n)/float64(d))
}
