// Package macro runs a login/session sequence (a "macro") through a cookie jar
// and extracts a session token, so subsequent scanning can be authenticated.
// This is the practical core of Burp's session-handling rules and macros.
package macro

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"
)

func insecureTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}

// Step is one request in the macro.
type Step struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Macro is an ordered login sequence plus how to turn it into credentials.
type Macro struct {
	Steps []Step `json:"steps"`
	// ExtractRegex, if set, is applied to the final response body; its first
	// group is stored and can be injected into later requests.
	ExtractRegex string `json:"extract_regex"`
	// ExtractInto names the header to set with the extracted value (e.g.
	// "Authorization"). If empty, extraction is reported but not auto-applied.
	ExtractInto string `json:"extract_into"`
	// UseCookies carries cookies from the sequence into the session (default true).
	UseCookies bool `json:"use_cookies"`
}

// StepResult summarizes one executed step.
type StepResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Result is the macro outcome: the headers it produced (to inject into later
// tool requests) plus per-step status.
type Result struct {
	Steps     []StepResult      `json:"steps"`
	Cookies   string            `json:"cookies,omitempty"`
	Extracted string            `json:"extracted,omitempty"`
	Headers   map[string]string `json:"headers"` // headers to apply to the session
}

// Run executes the macro and returns the credentials it established.
func Run(ctx context.Context, m Macro, insecure bool) *Result {
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if insecure {
		hc.Transport = insecureTransport()
	}

	res := &Result{Headers: map[string]string{}}
	useCookies := m.UseCookies
	// Default to carrying cookies unless explicitly disabled.
	if !m.UseCookies && len(m.Steps) > 0 {
		useCookies = true
	}

	var lastBody string
	var lastURL string
	for _, st := range m.Steps {
		method := st.Method
		if method == "" {
			method = "GET"
		}
		req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), st.URL, strings.NewReader(st.Body))
		sr := StepResult{URL: st.URL}
		if err != nil {
			sr.Error = err.Error()
			res.Steps = append(res.Steps, sr)
			continue
		}
		for k, v := range st.Headers {
			req.Header.Set(k, v)
		}
		if st.Body != "" && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := hc.Do(req)
		if err != nil {
			sr.Error = err.Error()
			res.Steps = append(res.Steps, sr)
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		lastBody = string(b)
		lastURL = st.URL
		sr.Status = resp.StatusCode
		res.Steps = append(res.Steps, sr)
	}

	// Collect cookies for the last step's URL.
	if useCookies && lastURL != "" {
		if u, err := http.NewRequest("GET", lastURL, nil); err == nil {
			var parts []string
			for _, c := range jar.Cookies(u.URL) {
				parts = append(parts, c.Name+"="+c.Value)
			}
			if len(parts) > 0 {
				res.Cookies = strings.Join(parts, "; ")
				res.Headers["Cookie"] = res.Cookies
			}
		}
	}

	// Extract a token from the final response.
	if m.ExtractRegex != "" {
		if re, err := regexp.Compile(m.ExtractRegex); err == nil {
			if mm := re.FindStringSubmatch(lastBody); mm != nil {
				res.Extracted = lastGroup(mm)
				if m.ExtractInto != "" {
					res.Headers[m.ExtractInto] = res.Extracted
				}
			}
		}
	}
	return res
}

func lastGroup(m []string) string {
	if len(m) > 1 {
		return m[1]
	}
	return m[0]
}
