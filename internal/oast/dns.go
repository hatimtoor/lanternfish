package oast

import (
	"net"
	"strings"
	"time"
)

// dnsBase is the delegated zone (e.g. "oast.example.com"); when set and the DNS
// listener is running, NewDNSPayload mints <token>.<dnsBase> names and lookups
// of them are recorded. The zone's NS must point at the host running this.
type dnsState struct {
	base string
	ip   net.IP // A-record answer handed back to resolvers
}

// StartDNS binds a UDP DNS listener on addr (e.g. ":53") for the delegated zone
// baseDomain, answering A queries with answerIP and recording every lookup.
// Returns an error if the socket cannot be bound (port 53 needs privileges).
func (s *Server) StartDNS(addr, baseDomain, answerIP string) (string, error) {
	ip := net.ParseIP(answerIP)
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.dns = &dnsState{base: strings.TrimPrefix(strings.ToLower(baseDomain), "."), ip: ip.To4()}
	s.mu.Unlock()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			name, ok := parseDNSQuestion(buf[:n])
			if !ok {
				continue
			}
			s.recordDNS(name, raddr.String())
			if resp := buildDNSAnswer(buf[:n], ip.To4()); resp != nil {
				_, _ = pc.WriteTo(resp, raddr)
			}
		}
	}()
	return pc.LocalAddr().String(), nil
}

func (s *Server) recordDNS(name, remote string) {
	token := strings.SplitN(name, ".", 2)[0]
	s.mu.Lock()
	s.interactions = append(s.interactions, Interaction{
		Token: token, Time: time.Now(), RemoteAddr: remote,
		Method: "DNS", Path: name, Host: name, UserAgent: "dns-resolver",
	})
	if len(s.interactions) > maxInteractions {
		s.interactions = append([]Interaction(nil), s.interactions[len(s.interactions)-maxInteractions:]...)
	}
	s.mu.Unlock()
}

// NewDNSPayload mints a token and a DNS name under the delegated zone. ok is
// false if the DNS listener/zone is not configured.
func (s *Server) NewDNSPayload() (token, fqdn string, ok bool) {
	s.mu.Lock()
	base := ""
	if s.dns != nil {
		base = s.dns.base
	}
	s.mu.Unlock()
	if base == "" {
		return "", "", false
	}
	token, _ = s.NewPayload()
	return token, token + "." + base, true
}

// parseDNSQuestion extracts the queried name (lowercased, dot-joined) from a
// DNS query packet. Returns ok=false on malformed input.
func parseDNSQuestion(p []byte) (string, bool) {
	if len(p) < 13 {
		return "", false
	}
	// qdcount must be >= 1; question starts at offset 12.
	off := 12
	var labels []string
	for off < len(p) {
		l := int(p[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // compression pointer not expected in a question
			return "", false
		}
		if off+l > len(p) {
			return "", false
		}
		labels = append(labels, strings.ToLower(string(p[off:off+l])))
		off += l
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}

// buildDNSAnswer constructs a minimal response echoing the question and adding
// one A record pointing at ip. Returns nil if the query is malformed.
func buildDNSAnswer(query []byte, ip net.IP) []byte {
	if len(query) < 12 || ip == nil || len(ip) != 4 {
		return nil
	}
	// Find the end of the question section.
	off := 12
	for off < len(query) {
		l := int(query[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || off+l > len(query) {
			return nil
		}
		off += l
	}
	off += 4 // QTYPE + QCLASS
	if off > len(query) {
		return nil
	}
	resp := make([]byte, 0, off+16)
	resp = append(resp, query[:off]...) // header + question
	// Flags: set QR=1, AA=1, keep opcode/RD from the query.
	resp[2] = 0x84 | (query[2] & 0x01)
	resp[3] = 0x00
	// ANCOUNT = 1.
	resp[6], resp[7] = 0x00, 0x01
	// Answer: name pointer to the question (0xC00C), A/IN, TTL 60, RDLENGTH 4.
	resp = append(resp, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04)
	resp = append(resp, ip[0], ip[1], ip[2], ip[3])
	return resp
}
