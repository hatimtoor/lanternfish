// Package browser drives a headless Chromium (Edge/Chrome) over the Chrome
// DevTools Protocol to crawl JavaScript-heavy single-page apps: it executes the
// page's scripts and collects the links, forms, and fetch/XHR endpoints that a
// static crawler cannot see. The CDP transport is a minimal, dependency-free
// WebSocket client.
package browser

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// wsConn is a tiny WebSocket client connection (client frames are masked).
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
}

func dialWS(wsURL string) (*wsConn, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return nil, err
	}
	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	key := base64.StdEncoding.EncodeToString(keyRaw)
	path := u.RequestURI()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	// Read the handshake response headers.
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		conn.Close()
		return nil, fmt.Errorf("websocket handshake failed: %q", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	return &wsConn{conn: conn, br: br}, nil
}

func (w *wsConn) writeText(payload []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	var hdr []byte
	hdr = append(hdr, 0x81) // FIN + text
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(0x80|n))
	case n < 65536:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	mask := make([]byte, 4)
	_, _ = rand.Read(mask)
	hdr = append(hdr, mask...)
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := w.conn.Write(hdr); err != nil {
		return err
	}
	_, err := w.conn.Write(masked)
	return err
}

// readMessage reassembles a full (possibly fragmented) server message.
func (w *wsConn) readMessage() ([]byte, error) {
	var out []byte
	for {
		fin, _, payload, err := readFrame(w.br)
		if err != nil {
			return nil, err
		}
		out = append(out, payload...)
		if fin {
			return out, nil
		}
	}
}

func (w *wsConn) close() { w.conn.Close() }

// readFrame reads one server frame (server->client frames are unmasked).
func readFrame(r *bufio.Reader) (fin bool, opcode int, payload []byte, err error) {
	h0, err := r.ReadByte()
	if err != nil {
		return false, 0, nil, err
	}
	h1, err := r.ReadByte()
	if err != nil {
		return false, 0, nil, err
	}
	fin = h0&0x80 != 0
	opcode = int(h0 & 0x0f)
	masked := h1&0x80 != 0
	length := int64(h1 & 0x7f)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return false, 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return false, 0, nil, err
		}
		length = int64(binary.BigEndian.Uint64(ext))
	}
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err = io.ReadFull(r, mask); err != nil {
			return false, 0, nil, err
		}
	}
	if length < 0 || length > 64<<20 {
		return false, 0, nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, length)
	if _, err = io.ReadFull(r, data); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range data {
			data[i] ^= mask[i%4]
		}
	}
	return fin, opcode, data, nil
}

// CDP is a DevTools Protocol session over a WebSocket.
type CDP struct {
	ws     *wsConn
	mu     sync.Mutex
	nextID int
	wait   map[int]chan cdpResponse
	events chan cdpMessage
	closed chan struct{}
}

type cdpMessage struct {
	ID        int             `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *cdpError       `json:"error,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cdpResponse struct {
	result json.RawMessage
	err    *cdpError
}

// connectCDP connects to a DevTools WebSocket URL and starts the read loop.
func connectCDP(wsURL string) (*CDP, error) {
	ws, err := dialWS(wsURL)
	if err != nil {
		return nil, err
	}
	c := &CDP{ws: ws, wait: map[int]chan cdpResponse{}, events: make(chan cdpMessage, 256), closed: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

func (c *CDP) readLoop() {
	for {
		raw, err := c.ws.readMessage()
		if err != nil {
			close(c.closed)
			return
		}
		var m cdpMessage
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.wait[m.ID]
			delete(c.wait, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- cdpResponse{result: m.Result, err: m.Error}
			}
			continue
		}
		select {
		case c.events <- m:
		default: // drop events if the buffer is full
		}
	}
}

// call sends a CDP command and waits for its result.
func (c *CDP) call(method string, params map[string]any, sessionID string, timeout time.Duration) (json.RawMessage, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan cdpResponse, 1)
	c.wait[id] = ch
	c.mu.Unlock()

	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if sessionID != "" {
		msg["sessionId"] = sessionID
	}
	b, _ := json.Marshal(msg)
	if err := c.ws.writeText(b); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		if resp.err != nil {
			return nil, fmt.Errorf("cdp %s: %s", method, resp.err.Message)
		}
		return resp.result, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("cdp %s: timeout", method)
	case <-c.closed:
		return nil, fmt.Errorf("cdp %s: connection closed", method)
	}
}

// waitEvent waits for a specific event method (ignoring others) until timeout.
func (c *CDP) waitEvent(method string, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		select {
		case m := <-c.events:
			if m.Method == method {
				return true
			}
		case <-deadline:
			return false
		case <-c.closed:
			return false
		}
	}
}

func (c *CDP) Close() { c.ws.close() }
