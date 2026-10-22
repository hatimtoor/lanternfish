package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"lanternfish/internal/httpmsg"
)

// isWebSocketUpgrade reports whether req is a WebSocket handshake.
func isWebSocketUpgrade(h http.Header) bool {
	return strings.EqualFold(h.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(h.Get("Connection")), "upgrade")
}

// relayWebSocket completes the WebSocket handshake upstream and relays frames
// in both directions, recording text/binary messages. clientConn is the raw
// (already decrypted, if TLS) client connection; secure selects ws vs wss.
func (p *Proxy) relayWebSocket(clientConn net.Conn, clientReader *bufio.Reader, req *httpmsg.Request, secure bool) {
	host := req.Host
	if !strings.Contains(host, ":") {
		if secure {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var upstream net.Conn
	var err error
	if secure {
		upstream, err = tls.Dial("tcp", host, &tls.Config{ServerName: hostOnly(req.Host)})
	} else {
		upstream, err = net.DialTimeout("tcp", host, 10*time.Second)
	}
	if err != nil {
		p.debugf("ws upstream dial %s: %v", host, err)
		return
	}
	defer upstream.Close()

	// Replay the client's handshake request upstream verbatim.
	hr, err := req.ToHTTP()
	if err != nil {
		return
	}
	hr.Header = req.Header.Clone()
	if err := hr.Write(upstream); err != nil {
		return
	}
	// Read the upstream 101 response and forward it to the client.
	upReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upReader, hr)
	if err != nil {
		p.debugf("ws upstream handshake %s: %v", host, err)
		return
	}
	if err := resp.Write(clientConn); err != nil {
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return // not an accepted upgrade; nothing to relay
	}

	url := req.AbsoluteURL().String()
	if secure {
		url = "wss://" + req.Host + req.URL.RequestURI()
	} else {
		url = "ws://" + req.Host + req.URL.RequestURI()
	}

	// Relay both directions, decoding frames for logging while forwarding
	// the exact bytes so the protocol is preserved.
	done := make(chan struct{}, 2)
	go func() { p.pumpWS(clientReader, upstream, url, "c2s"); done <- struct{}{} }()
	go func() { p.pumpWS(upReader, clientConn, url, "s2c"); done <- struct{}{} }()
	<-done
}

// pumpWS reads WebSocket frames from src, records data frames, and writes the
// exact bytes to dst until either side closes.
func (p *Proxy) pumpWS(src *bufio.Reader, dst io.Writer, url, direction string) {
	for {
		raw, opcode, payload, err := readWSFrame(src)
		if err != nil {
			return
		}
		if _, err := dst.Write(raw); err != nil {
			return
		}
		switch opcode {
		case 1, 2: // text, binary
			p.sess.WS.Add(url, direction, opcode, payload)
		case 8: // close
			return
		}
	}
}

// readWSFrame reads one frame, returning the raw bytes, opcode, and unmasked
// payload. It handles client-masked frames.
func readWSFrame(r *bufio.Reader) (raw []byte, opcode int, payload []byte, err error) {
	h0, err := r.ReadByte()
	if err != nil {
		return nil, 0, nil, err
	}
	h1, err := r.ReadByte()
	if err != nil {
		return nil, 0, nil, err
	}
	raw = []byte{h0, h1}
	opcode = int(h0 & 0x0f)
	masked := h1&0x80 != 0
	length := int64(h1 & 0x7f)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return nil, 0, nil, err
		}
		raw = append(raw, ext...)
		length = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return nil, 0, nil, err
		}
		raw = append(raw, ext...)
		length = int64(binary.BigEndian.Uint64(ext))
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err = io.ReadFull(r, maskKey); err != nil {
			return nil, 0, nil, err
		}
		raw = append(raw, maskKey...)
	}

	// Guard against absurd frame sizes while still forwarding. 16 MiB is ample
	// for real traffic and bounds the per-frame allocation.
	if length < 0 || length > 16<<20 {
		return nil, 0, nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, length)
	if _, err = io.ReadFull(r, data); err != nil {
		return nil, 0, nil, err
	}
	raw = append(raw, data...)

	payload = data
	if masked {
		payload = make([]byte, length)
		for i := range data {
			payload[i] = data[i] ^ maskKey[i%4]
		}
	}
	return raw, opcode, payload, nil
}
