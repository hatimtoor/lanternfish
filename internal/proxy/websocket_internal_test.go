package proxy

import (
	"bufio"
	"bytes"
	"net/http"
	"testing"
)

func TestIsWebSocketUpgrade(t *testing.T) {
	h := http.Header{}
	h.Set("Upgrade", "websocket")
	h.Set("Connection", "keep-alive, Upgrade")
	if !isWebSocketUpgrade(h) {
		t.Error("should detect websocket upgrade")
	}
	if isWebSocketUpgrade(http.Header{"Connection": {"keep-alive"}}) {
		t.Error("non-upgrade should be false")
	}
}

func TestIsHopByHop(t *testing.T) {
	for _, k := range []string{"Connection", "Transfer-Encoding", "Upgrade", "keep-alive"} {
		if !isHopByHop(k) {
			t.Errorf("%s should be hop-by-hop", k)
		}
	}
	if isHopByHop("Content-Type") {
		t.Error("Content-Type is not hop-by-hop")
	}
}

// buildFrame constructs a WebSocket frame for testing.
func buildFrame(opcode byte, payload []byte, mask bool) []byte {
	var b []byte
	b = append(b, 0x80|opcode) // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		b = append(b, maskBit(mask)|byte(n))
	case n < 65536:
		b = append(b, maskBit(mask)|126, byte(n>>8), byte(n))
	}
	data := payload
	if mask {
		key := []byte{0x11, 0x22, 0x33, 0x44}
		b = append(b, key...)
		data = make([]byte, n)
		for i := range payload {
			data[i] = payload[i] ^ key[i%4]
		}
	}
	return append(b, data...)
}

func maskBit(m bool) byte {
	if m {
		return 0x80
	}
	return 0
}

func TestReadWSFrameMaskedAndUnmasked(t *testing.T) {
	// Masked client text frame.
	r := bufio.NewReader(bytes.NewReader(buildFrame(1, []byte("hello"), true)))
	raw, opcode, payload, err := readWSFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 1 || string(payload) != "hello" {
		t.Errorf("masked frame decoded wrong: op=%d payload=%q", opcode, payload)
	}
	if len(raw) == 0 {
		t.Error("raw bytes should be captured for forwarding")
	}

	// Unmasked server binary frame.
	r2 := bufio.NewReader(bytes.NewReader(buildFrame(2, []byte{1, 2, 3}, false)))
	_, opcode2, payload2, err := readWSFrame(r2)
	if err != nil {
		t.Fatal(err)
	}
	if opcode2 != 2 || !bytes.Equal(payload2, []byte{1, 2, 3}) {
		t.Errorf("unmasked binary frame decoded wrong: op=%d payload=%v", opcode2, payload2)
	}
}

func TestReadWSFrameExtendedLength(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 300) // forces 16-bit extended length
	r := bufio.NewReader(bytes.NewReader(buildFrame(1, payload, true)))
	_, _, got, err := readWSFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 300 {
		t.Errorf("extended-length frame decoded wrong length: %d", len(got))
	}
}
