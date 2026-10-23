// Command benchspec converts the OWASP Benchmark answer key into a Lanternfish
// benchmark spec (see `lanternfish bench`). It reads the expected-results CSV
// (test name, category, real-vulnerability true/false) and, when given the
// Benchmark crawler file (-crawler data/benchmark-crawler-http.xml), the exact
// request each test needs — the cookie, header, query, or form parameter that
// carries the input — so endpoints are exercised correctly rather than with a
// bare GET. Categories a black-box scanner cannot see (crypto, hashing, weak
// randomness, trust boundary) are skipped.
//
// Usage:
//
//	go run ./tools/benchspec -base https://localhost:8443 \
//	    -crawler BenchmarkJava/data/benchmark-crawler-http.xml \
//	    -sample 40 BenchmarkJava/expectedresults-1.2.csv > benchmarks/owasp-benchmark.json
//
// -sample N caps cases per category (a stratified sample) for a quicker run; 0 = all.
package main

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

// category maps OWASP Benchmark categories to Lanternfish check ids (prefix
// match). Only black-box-observable categories are included.
var category = map[string]string{
	"pathtraver": "path-traversal",
	"sqli":       "sqli",
	"xss":        "reflected-xss",
	"cmdi":       "command-injection",
	"ldapi":      "ldap-injection",
	"xpathi":     "xpath-injection",
}

type benchCase struct {
	Path    string            `json:"path"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookie  string            `json:"cookie,omitempty"`
	Body    string            `json:"body,omitempty"`
	Expect  []string          `json:"expect,omitempty"`
	Clean   bool              `json:"clean,omitempty"`
}

type benchSpec struct {
	Name  string      `json:"name"`
	Base  string      `json:"base"`
	Cases []benchCase `json:"cases"`
}

// crawler file model.
type cxSuite struct {
	Tests []cxTest `xml:"benchmarkTest"`
}
type cxTest struct {
	URL        string `xml:"URL,attr"`
	Name       string `xml:"tcName,attr"`
	Cookies    []cxKV `xml:"cookie"`
	Headers    []cxKV `xml:"header"`
	GetParams  []cxKV `xml:"getparam"`
	FormParams []cxKV `xml:"formparam"`
}
type cxKV struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

func main() {
	base := flag.String("base", "https://localhost:8443", "base URL the Benchmark is served at")
	crawler := flag.String("crawler", "", "path to benchmark-crawler-http.xml (for exact requests)")
	sample := flag.Int("sample", 0, "cap cases per category (stratified sample); 0 = all")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: benchspec [-base URL] [-crawler xml] [-sample N] expectedresults.csv > spec.json")
		os.Exit(2)
	}

	tests := map[string]cxTest{}
	if *crawler != "" {
		data, err := os.ReadFile(*crawler)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var suite cxSuite
		if err := xml.Unmarshal(data, &suite); err != nil {
			fmt.Fprintln(os.Stderr, "parse crawler:", err)
			os.Exit(1)
		}
		for _, t := range suite.Tests {
			tests[t.Name] = t
		}
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
	perCat := map[string]int{}
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
			continue
		}
		check, ok := category[cat]
		if !ok {
			skipped++
			continue
		}
		if *sample > 0 && perCat[cat] >= *sample {
			continue
		}
		perCat[cat]++

		c := benchCase{}
		if ct, ok := tests[name]; ok {
			buildFromCrawler(&c, ct)
		} else {
			c.Path = "/benchmark/" + name
		}
		if isVuln {
			c.Expect = []string{check}
		} else {
			c.Clean = true
		}
		spec.Cases = append(spec.Cases, c)
	}

	b, _ := json.MarshalIndent(spec, "", "  ")
	os.Stdout.Write(append(b, '\n'))
	cats := make([]string, 0, len(perCat))
	for k := range perCat {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	fmt.Fprintf(os.Stderr, "wrote %d cases (skipped %d non-observable)\n", len(spec.Cases), skipped)
	for _, k := range cats {
		fmt.Fprintf(os.Stderr, "  %-12s %d\n", k, perCat[k])
	}
}

// buildFromCrawler fills a case from the crawler's exact request details.
func buildFromCrawler(c *benchCase, t cxTest) {
	path := "/benchmark/" + t.Name
	if u, err := url.Parse(t.URL); err == nil {
		path = u.Path
	}
	if len(t.GetParams) > 0 {
		q := url.Values{}
		for _, p := range t.GetParams {
			q.Set(p.Name, p.Value)
		}
		path += "?" + q.Encode()
	}
	c.Path = path
	if len(t.Headers) > 0 {
		c.Headers = map[string]string{}
		for _, h := range t.Headers {
			c.Headers[h.Name] = h.Value
		}
	}
	if len(t.Cookies) > 0 {
		var parts []string
		for _, ck := range t.Cookies {
			parts = append(parts, ck.Name+"="+ck.Value)
		}
		c.Cookie = strings.Join(parts, "; ")
	}
	if len(t.FormParams) > 0 {
		c.Method = "POST"
		body := url.Values{}
		for _, p := range t.FormParams {
			body.Set(p.Name, p.Value)
		}
		c.Body = body.Encode()
	}
}
