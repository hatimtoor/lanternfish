// Package fuzz is an Intruder-style request fuzzer. It takes a request
// template containing a marker, substitutes each payload for the marker, sends
// the requests (with bounded concurrency), and returns per-payload results
// (status, length, timing) for comparison.
package fuzz

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"lanternfish/internal/httpmsg"
	"lanternfish/internal/scan"
)

// DefaultMarker is the placeholder replaced by each payload.
const DefaultMarker = "FUZZ"

// Spec describes a fuzzing attack.
type Spec struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Marker      string            `json:"marker"`
	Payloads    []string          `json:"payloads"`
	Concurrency int               `json:"concurrency"`
}

// Row is one payload's result.
type Row struct {
	Payload string `json:"payload"`
	Status  int    `json:"status"`
	Length  int    `json:"length"`
	Millis  int64  `json:"millis"`
	Error   string `json:"error,omitempty"`
}

// Result is the full attack outcome.
type Result struct {
	Target string `json:"target"`
	Marker string `json:"marker"`
	Count  int    `json:"count"`
	Rows   []Row  `json:"rows"`
}

// Run executes the attack against sender.
func Run(ctx context.Context, sender scan.Sender, spec Spec) *Result {
	marker := spec.Marker
	if marker == "" {
		marker = DefaultMarker
	}
	conc := spec.Concurrency
	if conc <= 0 {
		conc = 10
	}
	method := spec.Method
	if method == "" {
		method = "GET"
	}

	res := &Result{Target: spec.URL, Marker: marker, Count: len(spec.Payloads)}
	rows := make([]Row, len(spec.Payloads))

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, payload := range spec.Payloads {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, payload string) {
			defer wg.Done()
			defer func() { <-sem }()

			rawURL := strings.ReplaceAll(spec.URL, marker, payload)
			u, err := url.Parse(rawURL)
			if err != nil {
				rows[i] = Row{Payload: payload, Error: "bad url: " + err.Error()}
				return
			}
			h := http.Header{}
			for k, v := range spec.Headers {
				h.Set(strings.ReplaceAll(k, marker, payload), strings.ReplaceAll(v, marker, payload))
			}
			if h.Get("User-Agent") == "" {
				h.Set("User-Agent", "lanternfish-fuzz")
			}
			body := strings.ReplaceAll(spec.Body, marker, payload)
			req := &httpmsg.Request{
				Method: strings.ToUpper(method), URL: u, Scheme: u.Scheme, Host: u.Host,
				Header: h, Body: []byte(body),
			}
			start := time.Now()
			resp, err := sender.Send(ctx, req)
			row := Row{Payload: payload, Millis: time.Since(start).Milliseconds()}
			if err != nil {
				row.Error = err.Error()
			} else {
				row.Status = resp.StatusCode
				row.Length = len(resp.Body)
			}
			rows[i] = row
		}(i, payload)
	}
	wg.Wait()

	// Sort by status then length so anomalies group together.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Status != rows[j].Status {
			return rows[i].Status < rows[j].Status
		}
		return rows[i].Length < rows[j].Length
	})
	res.Rows = rows
	return res
}
