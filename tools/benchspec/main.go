// Command benchspec converts an OWASP Benchmark expected-results CSV into a
// Lanternfish benchmark spec (see `lanternfish bench`). The Benchmark ships a
// labeled answer key (test name, category, real-vulnerability true/false), so
// this turns that into cases: a true vulnerability becomes an `expect`, a
// non-vulnerability a `clean` case. Categories a black-box scanner cannot see
// (source-level crypto/hash/weak-randomness/trust-boundary) are skipped.
//
// Usage:
//
//	go run ./tools/benchspec -base http://localhost:8443 expectedresults-1.2.csv > benchmarks/owasp-benchmark.json
//
// Note: OWASP Benchmark endpoints often need specific parameters or POST
// bodies to trigger; a plain GET per path will under-detect. Treat the produced
// spec as a labeling starting point and drive complex endpoints via crawling.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// category maps OWASP Benchmark categories to Lanternfish check ids (prefix
// match). Empty => not detectable by a black-box scanner; those rows are skipped.
var category = map[string]string{
	"pathtraver":   "path-traversal",
	"sqli":         "sqli",
	"xss":          "reflected-xss",
	"cmdi":         "command-injection",
	"ldapi":        "ldap-injection",
	"xpathi":       "xpath-injection",
	"securecookie": "cookie-samesite",
	// not observable black-box: crypto, hash, weakrand, trustbound
}

type benchCase struct {
	Path   string   `json:"path"`
	Expect []string `json:"expect,omitempty"`
	Clean  bool     `json:"clean,omitempty"`
}

type benchSpec struct {
	Name  string      `json:"name"`
	Base  string      `json:"base"`
	Cases []benchCase `json:"cases"`
}

func main() {
	base := flag.String("base", "http://localhost:8443", "base URL the Benchmark is served at")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: benchspec [-base URL] expectedresults.csv > spec.json")
		os.Exit(2)
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.Comment = '#'
	r.FieldsPerRecord = -1

	spec := benchSpec{Name: "OWASP Benchmark", Base: strings.TrimRight(*base, "/")}
	var skipped int
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 3 {
			continue
		}
		name := strings.TrimSpace(rec[0])
		cat := strings.TrimSpace(rec[1])
		isVuln := strings.EqualFold(strings.TrimSpace(rec[2]), "true")
		if name == "" || strings.EqualFold(name, "name") {
			continue // header
		}
		check, ok := category[cat]
		if !ok {
			skipped++
			continue
		}
		c := benchCase{Path: "/benchmark/" + name}
		if isVuln {
			c.Expect = []string{check}
		} else {
			c.Clean = true
		}
		spec.Cases = append(spec.Cases, c)
	}

	b, _ := json.MarshalIndent(spec, "", "  ")
	os.Stdout.Write(append(b, '\n'))
	fmt.Fprintf(os.Stderr, "wrote %d cases (skipped %d rows in non-observable categories)\n", len(spec.Cases), skipped)
}
