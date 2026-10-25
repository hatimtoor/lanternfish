// Package smuggle implements HTTP/1.1 request-smuggling (desync) detection with
// a raw socket client, because net/http deliberately normalises the conflicting
// Content-Length / Transfer-Encoding headers a smuggling probe needs.
//
// Only the *timing-based* technique is used: a probe that, when the front-end
// and back-end disagree on where the body ends, leaves one of them waiting for
// bytes that never arrive, so the response hangs until our read timeout. This
// is a safe detection method — it stalls the connection we opened and never
// appends a request that would be served to another user. It covers CL.TE,
// TE.CL, and TE.TE header-obfuscation variants (the methodology is public,
// from PortSwigger's HTTP request smuggling research).
//
// This is intrusive (it ties up a back-end worker/connection and relies on
// malformed requests), so callers must gate it behind an explicit opt-in.
package smuggle

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Finding is one detected desync.
type Finding struct {
	Kind       string // "CL.TE" or "TE.CL"
	Variant    string // the Transfer-Encoding obfuscation that triggered it
	BaselineMs int64
	ProbeMs    int64
}

// teVariants are Transfer-Encoding header forms that a non-conforming parser may
// accept or ignore, each of which can split front-end and back-end agreement.
var teVariants = []struct{ name, header string }{
	{"plain", "Transfer-Encoding: chunked"},
	{"space-before-colon", "Transfer-Encoding : chunked"},
	{"tab-separator", "Transfer-Encoding:\tchunked"},
	{"leading-space-value", "Transfer-Encoding:  chunked"},
	{"vertical-tab", "Transfer-Encoding:\x0bchunked"},
	{"prefixed", "Transfer-Encoding: xchunked"},
	{"quoted", "Transfer-Encoding: \"chunked\""},
	{"double-te-chunked-last", "Transfer-Encoding: x\r\nTransfer-Encoding: chunked"},
	{"double-te-chunked-first", "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"},
}

// Options tune the detector.
type Options struct {
	ReadTimeout time.Duration // how long to wait for a response before calling it a hang
	Insecure    bool          // skip TLS verification
	HangFloorMs int64         // a probe must exceed baseline by this many ms to count (default 5000)
}

// Detect probes target for request smuggling and returns confirmed findings.
// It establishes a baseline round-trip time, then for each technique/variant
// sends a timing probe; a probe that hangs well past the baseline (and is
// confirmed by a repeat) is reported.
func Detect(ctx context.Context, target *url.URL, opt Options) ([]Finding, error) {
	if opt.ReadTimeout <= 0 {
		opt.ReadTimeout = 10 * time.Second
	}
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	useTLS := target.Scheme == "https"

	// Baseline: a well-formed, promptly-answered chunked POST.
	base, ok := roundTripMS(ctx, host, port, useTLS, opt,
		buildRaw("POST", path, hostHeader(host, port, useTLS),
			[]string{"Transfer-Encoding: chunked", "Content-Type: application/x-www-form-urlencoded"}, "0\r\n\r\n"))
	// If we cannot even get a baseline, or the server is already slow, we cannot
	// tell a desync hang apart from a sluggish server — bail to avoid false
	// positives.
	if !ok || base >= 4000 {
		return nil, nil
	}

	floor := opt.HangFloorMs
	if floor <= 0 {
		floor = 5000
	}
	hang := base + floor // ms: a probe must exceed baseline by `floor` to count
	if hang < floor {
		hang = floor
	}

	var findings []Finding
	for _, v := range teVariants {
		if ctx.Err() != nil {
			break
		}
		// CL.TE: front-end honours Content-Length, back-end honours TE and waits
		// for a terminating chunk that never comes.
		clte := buildRaw("POST", path, hostHeader(host, port, useTLS),
			[]string{v.header, "Content-Length: 4"}, "1\r\nA\r\nX")
		if t, ok := roundTripMS(ctx, host, port, useTLS, opt, clte); ok && t >= hang {
			if t2, ok2 := roundTripMS(ctx, host, port, useTLS, opt, clte); ok2 && t2 >= hang {
				findings = append(findings, Finding{Kind: "CL.TE", Variant: v.name, BaselineMs: base, ProbeMs: t})
				continue // one desync per variant is enough
			}
		}
		// TE.CL: front-end honours TE (reads the 0-length chunk and stops),
		// back-end honours Content-Length and waits for more body bytes.
		tecl := buildRaw("POST", path, hostHeader(host, port, useTLS),
			[]string{v.header, "Content-Length: 6"}, "0\r\n\r\nX")
		if t, ok := roundTripMS(ctx, host, port, useTLS, opt, tecl); ok && t >= hang {
			if t2, ok2 := roundTripMS(ctx, host, port, useTLS, opt, tecl); ok2 && t2 >= hang {
				findings = append(findings, Finding{Kind: "TE.CL", Variant: v.name, BaselineMs: base, ProbeMs: t})
			}
		}
	}
	return findings, nil
}

// hostHeader builds the Host header value, including a non-default port.
func hostHeader(host, port string, isTLS bool) string {
	if (isTLS && port == "443") || (!isTLS && port == "80") {
		return host
	}
	return host + ":" + port
}

// buildRaw assembles an exact HTTP/1.1 request. The caller supplies full header
// lines (so malformed CL/TE forms survive verbatim). Connection: close is added
// so the server responds and releases the socket.
func buildRaw(method, path, host string, headers []string, body string) []byte {
	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// roundTripMS dials the target, writes raw, and returns milliseconds until the
// first response byte (or the read timeout if the server hangs). ok is false on
// a connection error (not a hang).
func roundTripMS(ctx context.Context, host, port string, isTLS bool, opt Options, raw []byte) (int64, bool) {
	d := net.Dialer{Timeout: 8 * time.Second}
	addr := net.JoinHostPort(host, port)
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	if isTLS {
		tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: opt.Insecure})
		tc.SetDeadline(time.Now().Add(8 * time.Second))
		if err := tc.Handshake(); err != nil {
			return 0, false
		}
		conn = tc
	}
	if err := conn.SetWriteDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return 0, false
	}
	if _, err := conn.Write(raw); err != nil {
		return 0, false
	}
	start := time.Now()
	_ = conn.SetReadDeadline(start.Add(opt.ReadTimeout))
	r := bufio.NewReader(conn)
	_, err = r.ReadByte() // first response byte
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return opt.ReadTimeout.Milliseconds(), true // hung: no response in time
		}
		// Connection reset/closed without a response: treat as a prompt (non-hang)
		// answer so we do not misread a hard rejection as a desync.
		return elapsed, true
	}
	return elapsed, true
}

// String renders a finding for logs.
func (f Finding) String() string {
	return fmt.Sprintf("%s via %s (baseline %dms, probe %dms)", f.Kind, f.Variant, f.BaselineMs, f.ProbeMs)
}
