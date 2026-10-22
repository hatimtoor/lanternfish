// Package proxy implements Lanternfish's intercepting HTTP/HTTPS proxy.
//
// Plain HTTP requests arrive in absolute form and are forwarded upstream.
// HTTPS arrives as CONNECT: the proxy answers 200, performs a TLS handshake
// with a per-host leaf certificate minted by the local CA, then reads and
// forwards the decrypted requests. Every exchange is recorded and offered to
// registered observers (e.g. passive scan checks).
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"lanternfish/internal/ca"
	"lanternfish/internal/client"
	"lanternfish/internal/httpmsg"
	"lanternfish/internal/session"
)

// Observer is notified of each completed transaction. Implementations must be
// safe for concurrent use and must not block for long.
type Observer func(tx *httpmsg.Transaction)

// Proxy is an intercepting proxy server backed by a shared session.
type Proxy struct {
	ca     *ca.Authority
	up     *client.Client
	sess   *session.Session
	logger *log.Logger

	mu          sync.Mutex
	observers   []Observer
	reqEditors  []func(*httpmsg.Request)
	respEditors []func(*httpmsg.Request, *httpmsg.Response)
}

// AddRequestEditor registers a function that may modify each request before it
// is sent upstream (an extension's request handler). Applied to all requests,
// after match/replace rules and before scope/interception.
func (p *Proxy) AddRequestEditor(f func(*httpmsg.Request)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqEditors = append(p.reqEditors, f)
}

// AddResponseEditor registers a function that may modify each response before
// it is returned to the client and recorded (an extension's response handler).
func (p *Proxy) AddResponseEditor(f func(*httpmsg.Request, *httpmsg.Response)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.respEditors = append(p.respEditors, f)
}

// editResponse applies registered response editors in order.
func (p *Proxy) editResponse(req *httpmsg.Request, resp *httpmsg.Response) {
	if resp == nil {
		return
	}
	p.mu.Lock()
	eds := append([]func(*httpmsg.Request, *httpmsg.Response){}, p.respEditors...)
	p.mu.Unlock()
	for _, f := range eds {
		f(req, resp)
	}
}

// New builds a proxy using the given CA, upstream client, and session.
func New(authority *ca.Authority, up *client.Client, sess *session.Session, logger *log.Logger) *Proxy {
	return &Proxy{ca: authority, up: up, sess: sess, logger: logger}
}

// OnTransaction registers an observer.
func (p *Proxy) OnTransaction(o Observer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observers = append(p.observers, o)
}

func (p *Proxy) record(tx *httpmsg.Transaction) {
	p.sess.Add(session.SourceProxy, tx)
	p.mu.Lock()
	obs := append([]Observer(nil), p.observers...)
	p.mu.Unlock()
	for _, o := range obs {
		o(tx)
	}
}

// gate applies scope and interception to a request about to be sent. It
// returns the request to send (possibly edited) and whether to drop it.
func (p *Proxy) gate(req *httpmsg.Request) (send *httpmsg.Request, drop bool) {
	// Match-and-replace rules rewrite the request before anything else.
	p.sess.Rewrite.Apply(req)
	// Extension request editors run next, able to modify any request.
	p.mu.Lock()
	eds := append([]func(*httpmsg.Request){}, p.reqEditors...)
	p.mu.Unlock()
	for _, f := range eds {
		f(req)
	}
	if !p.sess.Scope.InScope(req.AbsoluteURL()) {
		return req, false // out of scope: pass through untouched, do not intercept
	}
	return p.sess.Intercept.Hold(req)
}

// ServeHTTP makes Proxy an http.Handler. CONNECT is handled specially.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// Serve the CA certificate for easy trust installation.
	if r.URL.Path == "/cert" && (r.Host == "lanternfish.ca" || r.Host == "lanternfish") {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=lanternfish-ca.pem")
		_, _ = w.Write(p.ca.CertPEM())
		return
	}
	p.handlePlain(w, r)
}

func (p *Proxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	req, err := httpmsg.FromHTTP(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if req.Scheme == "" {
		req.Scheme = "http"
	}
	if isWebSocketUpgrade(r.Header) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		p.relayWebSocket(conn, brw.Reader, req, false)
		return
	}
	send, drop := p.gate(req)
	if drop {
		http.Error(w, "lanternfish: request dropped", http.StatusForbidden)
		return
	}
	resp, err := p.up.Send(r.Context(), send)
	if err != nil {
		p.debugf("upstream error for %s: %v", send.Host, err)
		http.Error(w, "lanternfish: upstream connection failed", http.StatusBadGateway)
		return
	}
	p.editResponse(send, resp)
	p.record(&httpmsg.Transaction{Request: send, Response: resp})
	writeResponse(w, resp)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	leaf, err := p.ca.LeafFor(host)
	if err != nil {
		http.Error(w, "lanternfish cert error", http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, brw, err := hj.Hijack()
	if err != nil {
		p.debugf("hijack %s: %v", host, err)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		p.debugf("connect ack %s: %v", host, err)
		return
	}

	// If the server's buffered reader already pulled bytes off the socket
	// (e.g. a client that sent the TLS ClientHello before reading our 200),
	// those bytes must be fed to the TLS server first, ahead of the raw conn.
	var tlsSource net.Conn = clientConn
	if n := brw.Reader.Buffered(); n > 0 {
		buffered, _ := brw.Reader.Peek(n)
		tlsSource = &prefixConn{Conn: clientConn, prefix: append([]byte(nil), buffered...)}
	}

	tlsConn := tls.Server(tlsSource, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		p.debugf("tls handshake %s: %v", host, err)
		return
	}
	defer tlsConn.Close()

	// Read decrypted requests off the tunnel until it closes.
	br := bufio.NewReader(tlsConn)
	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		creq, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF {
				p.debugf("read tunneled request %s: %v", host, err)
			}
			return
		}
		creq.URL.Scheme = "https"
		creq.URL.Host = r.Host

		req, err := httpmsg.FromHTTP(creq)
		if err != nil {
			return
		}
		req.Scheme = "https"
		req.Host = hostOnly(r.Host)

		if isWebSocketUpgrade(creq.Header) {
			p.relayWebSocket(tlsConn, br, req, true)
			return
		}

		send, drop := p.gate(req)
		if drop {
			writeRawDropped(tlsConn)
			return
		}
		resp, err := p.up.Send(context.Background(), send)
		if err != nil {
			p.debugf("upstream error for %s: %v", send.Host, err)
			writeRawError(tlsConn, err)
			return
		}
		p.editResponse(send, resp)
		if err := writeRawResponse(tlsConn, resp); err != nil {
			p.debugf("write response %s: %v", host, err)
			return
		}
		p.record(&httpmsg.Transaction{Request: send, Response: resp})
		if creq.Close || resp.Header.Get("Connection") == "close" {
			return
		}
	}
}

func (p *Proxy) debugf(format string, args ...any) {
	if p.logger != nil {
		p.logger.Printf(format, args...)
	}
}

// Server wraps the proxy in an http.Server configured for proxying.
func (p *Proxy) Server(addr string) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler:      p,
		ReadTimeout:  0, // proxies keep connections open
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}
}

// hopByHop are connection-specific headers that must not be forwarded by a
// proxy; copying them (e.g. Transfer-Encoding while we send a fixed body) can
// corrupt the response.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}

func writeResponse(w http.ResponseWriter, resp *httpmsg.Response) {
	for k, vals := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(resp.Body)
}

func isHopByHop(key string) bool {
	for _, k := range hopByHop {
		if http.CanonicalHeaderKey(key) == k {
			return true
		}
	}
	return false
}

func writeRawResponse(conn net.Conn, resp *httpmsg.Response) error {
	// Clone the header so stripping does not mutate the recorded response.
	hdr := resp.Header.Clone()
	stripHopByHop(hdr)
	hr := &http.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(resp.Body)),
		ContentLength: int64(len(resp.Body)),
	}
	return hr.Write(conn)
}

func writeRawDropped(conn net.Conn) {
	const body = "lanternfish: request dropped"
	fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func writeRawError(conn net.Conn, err error) {
	// Return a generic message to the client; the detailed error (which can
	// disclose internal hostnames/IPs and TLS internals) stays out of the
	// response. Callers log the real error to the debug log.
	const body = "lanternfish: upstream connection failed"
	fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	_ = err
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// prefixConn is a net.Conn that returns prefix bytes before reading from the
// underlying connection. Used to replay bytes the HTTP server buffered during
// Hijack into the TLS layer.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
