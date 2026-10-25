package smuggle

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rawServer runs a minimal TCP server. If hangOnCLTE is set, it stalls (never
// responds) when it sees the CL.TE probe (Content-Length: 4), simulating a
// back-end that waits for a terminating chunk; otherwise it answers promptly.
func rawServer(t *testing.T, hangOnCLTE bool) (*url.URL, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 8192)
				n, _ := c.Read(buf)
				req := string(buf[:n])
				if hangOnCLTE && strings.Contains(req, "Content-Length: 4") {
					time.Sleep(700 * time.Millisecond) // > detector read timeout
					return
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}(c)
		}
	}()
	u, _ := url.Parse("http://" + ln.Addr().String() + "/")
	return u, func() { ln.Close() }
}

func TestDetectCLTE(t *testing.T) {
	u, stop := rawServer(t, true)
	defer stop()
	findings, err := Detect(context.Background(), u, Options{ReadTimeout: 300 * time.Millisecond, HangFloorMs: 150})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a CL.TE finding")
	}
	for _, f := range findings {
		if f.Kind != "CL.TE" {
			t.Errorf("expected CL.TE, got %s", f.Kind)
		}
	}
}

func TestDetectCleanServer(t *testing.T) {
	u, stop := rawServer(t, false) // answers everything promptly
	defer stop()
	findings, err := Detect(context.Background(), u, Options{ReadTimeout: 300 * time.Millisecond, HangFloorMs: 150})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("a server with no desync should yield no findings, got %v", findings)
	}
}
