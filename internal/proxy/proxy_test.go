package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"lanternfish/internal/ca"
	"lanternfish/internal/client"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/proxy"
	"lanternfish/internal/session"
)

// proxied builds an http.Client routed through a proxy served at proxyURL.
func proxied(proxyURL string) *http.Client {
	pu, _ := url.Parse(proxyURL)
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
}

func newProxy(t *testing.T, sess *session.Session) *httptest.Server {
	t.Helper()
	authority, err := ca.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	up := client.New(client.Options{FollowRedirects: false})
	p := proxy.New(authority, up, sess, nil)
	return httptest.NewServer(p)
}

// newProxyWithCA returns a proxy plus its CA so a client can trust the MITM.
func newProxyWithCA(t *testing.T, sess *session.Session) (*httptest.Server, *ca.Authority) {
	t.Helper()
	authority, err := ca.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Upstream must skip verification to reach the self-signed test TLS server.
	up := client.New(client.Options{FollowRedirects: false, InsecureSkipVerify: true})
	p := proxy.New(authority, up, sess, nil)
	return httptest.NewServer(p), authority
}

func TestHTTPSInterceptionMITM(t *testing.T) {
	// A TLS target with its own self-signed cert.
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen", r.URL.Path)
		w.Write([]byte("secure-hello"))
	}))
	defer target.Close()

	sess := session.New()
	px, authority := newProxyWithCA(t, sess)
	defer px.Close()

	// Client trusts the Lanternfish CA and routes through the proxy (CONNECT).
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.CertPEM()) {
		t.Fatal("bad CA PEM")
	}
	pu, _ := url.Parse(px.URL)
	hc := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
	resp, err := hc.Get(target.URL + "/private")
	if err != nil {
		t.Fatalf("MITM request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secure-hello" {
		t.Errorf("decrypted body wrong: %q", body)
	}
	// The proxy must have decrypted and recorded the HTTPS request.
	h := sess.History(0)
	if len(h) != 1 || h[0].Request.Scheme != "https" || h[0].Request.URL.Path != "/private" {
		t.Errorf("HTTPS transaction not recorded correctly: %+v", h)
	}
}

func TestPlainProxyingRecordsHistory(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.URL.Query().Get("q"))
		w.Write([]byte("hello"))
	}))
	defer target.Close()

	sess := session.New()
	px := newProxy(t, sess)
	defer px.Close()

	resp, err := proxied(px.URL).Get(target.URL + "/page?q=abc")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello" {
		t.Errorf("body not proxied: %q", body)
	}
	if len(sess.History(0)) != 1 {
		t.Fatalf("expected 1 history record, got %d", len(sess.History(0)))
	}
}

func TestProxyRewriteApplied(t *testing.T) {
	var gotHeader string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Test")
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	sess := session.New()
	sess.Rewrite.Add("header", "secret", "REDACTED", true)
	px := newProxy(t, sess)
	defer px.Close()

	req, _ := http.NewRequest("GET", target.URL+"/", nil)
	req.Header.Set("X-Test", "my secret")
	resp, err := proxied(px.URL).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotHeader != "my REDACTED" {
		t.Errorf("rewrite not applied upstream: %q", gotHeader)
	}
}

func TestProxyInterceptDrop(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should not reach"))
	}))
	defer target.Close()

	sess := session.New()
	sess.Intercept.SetEnabled(true)
	px := newProxy(t, sess)
	defer px.Close()

	// Drop the held request from another goroutine.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if p := sess.Intercept.List(); len(p) == 1 {
				sess.Intercept.Drop(p[0].ID)
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	resp, err := proxied(px.URL).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("dropped request should yield 403, got %d", resp.StatusCode)
	}
}

func TestProxyScopePassThrough(t *testing.T) {
	// Out-of-scope requests pass through without interception even when
	// interception is enabled.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	sess := session.New()
	sess.Scope.Include("some-other-host.test", "") // target is not in scope
	sess.Intercept.SetEnabled(true)
	px := newProxy(t, sess)
	defer px.Close()

	resp, err := proxied(px.URL).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("out-of-scope request should pass through, got %d", resp.StatusCode)
	}
}

var _ = httpmsg.Request{}
