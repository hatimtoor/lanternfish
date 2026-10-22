package oast

import (
	"net"
	"testing"
	"time"
)

// buildQuery encodes a minimal DNS A query for name.
func buildQuery(name string) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range splitName(name) {
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0x00)       // end of name
	q = append(q, 0x00, 0x01) // QTYPE A
	q = append(q, 0x00, 0x01) // QCLASS IN
	return q
}

func splitName(name string) []string {
	var out []string
	cur := ""
	for _, c := range name {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestDNSCollaboratorRecordsLookup(t *testing.T) {
	s := New("")
	addr, err := s.StartDNS("127.0.0.1:0", "oast.test", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	token, fqdn, ok := s.NewDNSPayload()
	if !ok || fqdn != token+".oast.test" {
		t.Fatalf("payload wrong: %q ok=%v", fqdn, ok)
	}

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(buildQuery(fqdn)); err != nil {
		t.Fatal(err)
	}
	// Read the A-record answer.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no DNS answer: %v", err)
	}
	if n < 4 || resp[2]&0x80 == 0 {
		t.Error("response QR bit not set")
	}
	// The last 4 bytes should be the configured answer IP.
	if n >= 4 {
		ip := resp[n-4 : n]
		if ip[0] != 1 || ip[1] != 2 || ip[2] != 3 || ip[3] != 4 {
			t.Errorf("answer IP wrong: %v", ip)
		}
	}

	// The lookup must be recorded against the token.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.Hits(token) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Hits(token) == 0 {
		t.Error("DNS lookup not recorded")
	}
}

func TestParseDNSQuestion(t *testing.T) {
	name, ok := parseDNSQuestion(buildQuery("abc.oast.test"))
	if !ok || name != "abc.oast.test" {
		t.Errorf("parse wrong: %q ok=%v", name, ok)
	}
	if _, ok := parseDNSQuestion([]byte{0, 1, 2}); ok {
		t.Error("short packet should fail")
	}
}
