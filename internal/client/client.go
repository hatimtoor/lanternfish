// Package client provides the shared upstream HTTP sender used by the proxy,
// the replayer, and the scanner. It implements scan.Sender.
package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"lanternfish/internal/httpmsg"
)

// Client sends requests upstream and returns captured responses.
type Client struct {
	hc *http.Client
}

// Options configures the client.
type Options struct {
	// InsecureSkipVerify disables upstream TLS verification (common when
	// testing targets with self-signed certs). Default false.
	InsecureSkipVerify bool
	Timeout            time.Duration
	// FollowRedirects controls whether 3xx are followed. Scanners usually
	// want this off so a redirect is observable.
	FollowRedirects bool
	// HTTP3 forces the upstream transport to speak HTTP/3 (QUIC). The target
	// must support h3. Default false (HTTP/1.1 + HTTP/2).
	HTTP3 bool
}

// New builds a Client.
func New(opt Options) *Client {
	if opt.Timeout == 0 {
		opt.Timeout = 30 * time.Second
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opt.InsecureSkipVerify},
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   opt.Timeout,
	}
	if opt.HTTP3 {
		hc.Transport = newHTTP3Transport(opt.InsecureSkipVerify)
	}
	if !opt.FollowRedirects {
		hc.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &Client{hc: hc}
}

// Send implements scan.Sender.
func (c *Client) Send(ctx context.Context, r *httpmsg.Request) (*httpmsg.Response, error) {
	hr, err := r.ToHTTP()
	if err != nil {
		return nil, err
	}
	hr = hr.WithContext(ctx)
	start := time.Now()
	resp, err := c.hc.Do(hr)
	if err != nil {
		return nil, err
	}
	return httpmsg.FromHTTPResponse(resp, time.Since(start))
}
