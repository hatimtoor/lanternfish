package client

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

// newHTTP3Transport returns an HTTP/3 (QUIC) round tripper. It speaks only h3,
// so it is used when the caller explicitly opts in and the target supports
// HTTP/3. Kept in its own file so the quic-go dependency is isolated here.
func newHTTP3Transport(insecure bool) http.RoundTripper {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
}
