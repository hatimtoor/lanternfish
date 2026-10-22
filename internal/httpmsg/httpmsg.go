// Package httpmsg defines Lanternfish's core HTTP message model.
//
// It is an independent, clean-room representation of HTTP requests and
// responses designed around Go's net/http and the needs of a proxy and
// scanner: byte-accurate bodies, raw header order preservation, and helpers
// for the point-mutation that active scanning relies on. It intentionally
// does not depend on, copy, or mirror any proprietary tool's internals.
package httpmsg

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Request is a captured HTTP request plus the metadata Lanternfish attaches to it.
type Request struct {
	Method string
	URL    *url.URL
	Proto  string
	Header http.Header
	Body   []byte

	// Scheme/Host are kept explicitly so a request intercepted off a proxy
	// CONNECT tunnel (where the request line is origin-form) still knows its
	// absolute target.
	Scheme string
	Host   string

	ID       int64
	Received time.Time
}

// Response is a captured HTTP response.
type Response struct {
	Proto      string
	Status     string
	StatusCode int
	Header     http.Header
	Body       []byte

	Elapsed  time.Duration
	Received time.Time
}

// Transaction pairs a request with its response (response may be nil until
// the exchange completes).
type Transaction struct {
	Request  *Request
	Response *Response
}

// FromHTTP converts a *http.Request into our model, fully buffering the body.
// The caller is responsible for closing the original body if needed.
func FromHTTP(r *http.Request) (*Request, error) {
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBody+1))
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		if len(b) > MaxRequestBody {
			b = b[:MaxRequestBody] // cap to bound memory against a hostile client
		}
		body = b
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return &Request{
		Method:   r.Method,
		URL:      r.URL,
		Proto:    r.Proto,
		Header:   r.Header.Clone(),
		Body:     body,
		Scheme:   scheme,
		Host:     host,
		Received: time.Now(),
	}, nil
}

// ToHTTP builds a *http.Request suitable for sending with http.Client or a
// RoundTripper. ctx-less; callers can wrap with WithContext.
func (r *Request) ToHTTP() (*http.Request, error) {
	u := r.AbsoluteURL()
	hr, err := http.NewRequest(r.Method, u.String(), bytes.NewReader(r.Body))
	if err != nil {
		return nil, err
	}
	hr.Header = r.Header.Clone()
	// Host header takes precedence over URL host when explicitly set.
	if r.Host != "" {
		hr.Host = r.Host
	}
	return hr, nil
}

// AbsoluteURL reconstructs the absolute URL from Scheme/Host/URL, tolerating
// origin-form request URLs captured inside a TLS tunnel.
func (r *Request) AbsoluteURL() *url.URL {
	if r.URL != nil && r.URL.IsAbs() {
		return r.URL
	}
	u := &url.URL{Scheme: r.Scheme, Host: r.Host}
	if r.URL != nil {
		u.Path = r.URL.Path
		u.RawQuery = r.URL.RawQuery
		u.Fragment = r.URL.Fragment
	}
	return u
}

// Clone makes a deep copy so a scanner can mutate a request without touching
// the original captured traffic.
func (r *Request) Clone() *Request {
	c := *r
	c.Header = r.Header.Clone()
	if r.Body != nil {
		c.Body = append([]byte(nil), r.Body...)
	}
	if r.URL != nil {
		u := *r.URL
		c.URL = &u
	}
	return &c
}

// MaxRequestBody caps how many bytes of a request body we buffer, so a hostile
// client cannot exhaust memory with a huge POST. Matches the response cap.
const MaxRequestBody = 50 << 20 // 50 MiB

// MaxResponseBody caps how many bytes of a response body we buffer, so a huge
// or malicious response cannot exhaust memory. Bodies larger than this are
// truncated and flagged.
const MaxResponseBody = 50 << 20 // 50 MiB

// FromHTTPResponse converts a *http.Response, buffering the body (bounded by
// MaxResponseBody) and closing it.
func FromHTTPResponse(resp *http.Response, elapsed time.Duration) (*Response, error) {
	defer resp.Body.Close()
	// Read one byte past the cap to detect truncation.
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	hdr := resp.Header.Clone()
	truncated := false
	if len(b) > MaxResponseBody {
		b = b[:MaxResponseBody]
		truncated = true
		hdr.Set("X-Lanternfish-Truncated", "true")
	}
	_ = truncated
	return &Response{
		Proto:      resp.Proto,
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Header:     hdr,
		Body:       b,
		Elapsed:    elapsed,
		Received:   time.Now(),
	}, nil
}

// BodyString returns the response body as a string (callers use this for
// substring matching in scan checks).
func (resp *Response) BodyString() string {
	if resp == nil {
		return ""
	}
	return string(resp.Body)
}

// ContentType returns the lowercased media type without parameters.
func (resp *Response) ContentType() string {
	if resp == nil {
		return ""
	}
	ct := resp.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// DumpRequestLine renders the request line and headers for display/logging.
func (r *Request) DumpRequestLine() string {
	var b strings.Builder
	u := r.AbsoluteURL()
	path := u.RequestURI()
	fmt.Fprintf(&b, "%s %s %s\n", r.Method, path, orDefault(r.Proto, "HTTP/1.1"))
	fmt.Fprintf(&b, "Host: %s\n", r.Host)
	_ = r.Header.Write(&b)
	return b.String()
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ParseRawRequest parses a raw HTTP request (as a user might paste into a
// replayer) against a known scheme/host. Useful for the replay command.
func ParseRawRequest(raw []byte, scheme, host string) (*Request, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	hr, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("parse raw request: %w", err)
	}
	var body []byte
	if hr.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(hr.Body, MaxRequestBody+1))
		if len(body) > MaxRequestBody {
			body = body[:MaxRequestBody]
		}
	}
	if host == "" {
		host = hr.Host
	}
	return &Request{
		Method:   hr.Method,
		URL:      hr.URL,
		Proto:    hr.Proto,
		Header:   hr.Header.Clone(),
		Body:     body,
		Scheme:   orDefault(scheme, "https"),
		Host:     host,
		Received: time.Now(),
	}, nil
}
