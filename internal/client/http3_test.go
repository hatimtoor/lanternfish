package client_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"lanternfish/internal/ca"
	"lanternfish/internal/client"
	"lanternfish/internal/httpmsg"

	"github.com/quic-go/quic-go/http3"
)

// TestHTTP3RoundTrip stands up a real HTTP/3 (QUIC) server and confirms the
// HTTP/3 client reaches it, proving end-to-end h3 support.
func TestHTTP3RoundTrip(t *testing.T) {
	authority, err := ca.Load(t.TempDir())
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	leaf, err := authority.LeafFor("127.0.0.1")
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udp.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.Write([]byte("h3 ok"))
	})
	srv := &http3.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}},
	}
	go func() { _ = srv.Serve(udp) }()
	defer srv.Close()

	port := udp.LocalAddr().(*net.UDPAddr).Port
	c := client.New(client.Options{HTTP3: true, InsecureSkipVerify: true, Timeout: 8 * time.Second})

	u, _ := url.Parse("https://127.0.0.1:" + itoa(port) + "/")
	req := &httpmsg.Request{Method: "GET", URL: u, Scheme: "https", Host: u.Host, Header: http.Header{}}

	// QUIC may need a moment to be ready; retry briefly.
	var resp *httpmsg.Response
	for i := 0; i < 20; i++ {
		resp, err = c.Send(context.Background(), req)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("h3 send: %v", err)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "h3 ok" {
		t.Fatalf("unexpected response: %d %q", resp.StatusCode, resp.Body)
	}
	if got := resp.Header.Get("X-Proto"); got != "HTTP/3.0" {
		t.Fatalf("expected HTTP/3.0, got %q", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
