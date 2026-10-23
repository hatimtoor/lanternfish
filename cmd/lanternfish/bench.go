package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"lanternfish/internal/httpmsg"
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
	Path    string            `json:"path"`              // appended to Base
	Method  string            `json:"method,omitempty"`  // default GET
	Headers map[string]string `json:"headers,omitempty"` // extra request headers
	Cookie  string            `json:"cookie,omitempty"`  // Cookie header value
	Body    string            `json:"body,omitempty"`    // request body (sets JSON CT if it looks like JSON)
	Expect  []string          `json:"expect,omitempty"`  // check ids that should fire (prefix match)
	Clean   bool              `json:"clean,omitempty"`   // true = no high/critical finding should fire
	Note    string            `json:"note,omitempty"`
}

// buildRequest turns a case into an HTTP request against base.
func buildRequest(base string, c benchCase) (*httpmsg.Request, error) {
	u, err := url.Parse(base + c.Path)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, v := range c.Headers {
		h.Set(k, v)
	}
	if c.Cookie != "" {
		h.Set("Cookie", c.Cookie)
	}
	method := strings.ToUpper(c.Method)
	if method == "" {
		method = "GET"
	}
	if c.Body != "" && h.Get("Content-Type") == "" {
		if strings.HasPrefix(strings.TrimSpace(c.Body), "{") {
			h.Set("Content-Type", "application/json")
		} else {
			h.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	return &httpmsg.Request{Method: method, URL: u, Scheme: u.Scheme, Host: u.Host, Header: h, Body: []byte(c.Body)}, nil
}

// cmdBench scores Lanternfish against a labeled benchmark spec. It is how we
// measure accuracy over time — the open equivalent of the feedback a commercial
// scanner gets from its users.
func cmdBench(args []string) {
	fs := newFlagSet("bench")
	insecure := fs.Bool("insecure", false, "skip upstream TLS verification")
	fast := fs.Bool("fast", false, "skip wait-heavy checks (faster, misses blind/time-based)")
	asJSON := fs.Bool("json", false, "emit the scorecard as JSON")
	minRecall := fs.Int("min-recall", -1, "exit non-zero if detection recall (percent) is below this (gate for CI)")
	maxFP := fs.Int("max-fp", -1, "exit non-zero if false positives exceed this (gate for CI)")
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
	progress := !*asJSON || os.Getenv("LANTERNFISH_BENCH_PROGRESS") != ""
	for i, c := range spec.Cases {
		if progress {
			fmt.Fprintf(os.Stderr, "[%d/%d] scanning %s\n", i+1, len(spec.Cases), c.Path)
		}
		got := map[string]string{} // check id -> severity
		if req, err := buildRequest(spec.Base, c); err == nil {
			if res, err := svc.ScanRequestMode(ctx, req, *fast); err == nil {
				for _, is := range res.Issues {
					got[is.Check] = is.SeverityStr
				}
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

	recall := 0
	if expectedTotal > 0 {
		recall = 100 * detected / expectedTotal
	}

	if *asJSON {
		out := map[string]any{
			"benchmark": spec.Name, "expected": expectedTotal, "detected": detected,
			"recall": fmt.Sprintf("%d%%", recall), "clean_cases": cleanCases,
			"false_positives": falsePos, "duration": dur.String(), "cases": rows,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
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
		fmt.Printf("\nDetection: %d/%d expected findings (%d%% recall)\n", detected, expectedTotal, recall)
		fmt.Printf("False positives: %d across %d clean case(s)\n", falsePos, cleanCases)
	}

	// Gating for CI: fail the run if accuracy regressed past the thresholds.
	failed := false
	if *minRecall >= 0 && recall < *minRecall {
		fmt.Fprintf(os.Stderr, "FAIL: recall %d%% is below the required %d%%\n", recall, *minRecall)
		failed = true
	}
	if *maxFP >= 0 && falsePos > *maxFP {
		fmt.Fprintf(os.Stderr, "FAIL: %d false positive(s) exceeds the allowed %d\n", falsePos, *maxFP)
		failed = true
	}
	if failed {
		os.Exit(1)
	}
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
