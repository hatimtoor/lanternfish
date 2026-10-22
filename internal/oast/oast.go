// Package oast provides out-of-band application security testing: a small HTTP
// listener that mints unique callback URLs and records any interaction with
// them. Active checks inject these URLs to detect blind vulnerabilities
// (e.g. blind SSRF) where the target makes a request back to us out of band.
//
// This is the local, self-hosted analogue of a "collaborator" server. For it
// to catch interactions from a remote target, the advertised base URL must be
// an address the target can reach; on loopback it catches local targets.
package oast

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interaction is a single recorded callback.
type Interaction struct {
	Token      string    `json:"token"`
	Time       time.Time `json:"time"`
	RemoteAddr string    `json:"remote_addr"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Host       string    `json:"host"`
	UserAgent  string    `json:"user_agent"`
}

// maxInteractions bounds retained OAST interactions to cap memory.
const maxInteractions = 50000

// Server is an OAST listener and interaction store.
type Server struct {
	advertised string // base URL the target should call, no trailing slash

	mu           sync.Mutex
	interactions []Interaction
	dns          *dnsState

	srv *http.Server
	ln  net.Listener
}

// New creates a server advertising baseURL (e.g. http://10.0.0.5:8088). If
// baseURL is empty it is filled in from the bound address on Start.
func New(baseURL string) *Server {
	return &Server{advertised: strings.TrimRight(baseURL, "/")}
}

// Start binds addr and serves the interaction recorder in the background.
// Returns the actual base URL being advertised.
func (s *Server) Start(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	if s.advertised == "" {
		s.advertised = "http://" + ln.Addr().String()
	}
	srv := &http.Server{Handler: http.HandlerFunc(s.record)}
	s.srv = srv
	s.ln = ln
	go func() { _ = srv.Serve(ln) }()
	return s.advertised, nil
}

// Close stops the HTTP listener. The interaction store remains readable.
func (s *Server) Close() error {
	if s.srv != nil {
		return s.srv.Close()
	}
	return nil
}

func (s *Server) record(w http.ResponseWriter, r *http.Request) {
	token := strings.Trim(r.URL.Path, "/")
	if i := strings.IndexByte(token, '/'); i >= 0 {
		token = token[:i]
	}
	// Also accept the token as the left-most DNS label of the Host header.
	if token == "" {
		if h := r.Host; h != "" {
			token = strings.SplitN(h, ".", 2)[0]
		}
	}
	s.mu.Lock()
	s.interactions = append(s.interactions, Interaction{
		Token: token, Time: time.Now(), RemoteAddr: r.RemoteAddr,
		Method: r.Method, Path: r.URL.Path, Host: r.Host, UserAgent: r.UserAgent(),
	})
	if len(s.interactions) > maxInteractions {
		s.interactions = append([]Interaction(nil), s.interactions[len(s.interactions)-maxInteractions:]...)
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "lanternfish-oast")
}

// NewPayload returns a unique token and a callback URL embedding it.
func (s *Server) NewPayload() (token, url string) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	token = "oa" + hex.EncodeToString(b)
	return token, s.advertised + "/" + token
}

// Hits returns how many interactions matched the token.
func (s *Server) Hits(token string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, it := range s.interactions {
		if it.Token == token {
			n++
		}
	}
	return n
}

// HitDetails returns short descriptions of interactions for a token.
func (s *Server) HitDetails(token string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, it := range s.interactions {
		if it.Token == token {
			out = append(out, fmt.Sprintf("%s %s from %s", it.Method, it.Path, it.RemoteAddr))
		}
	}
	return out
}

// Interactions returns the recorded interactions for one token (newest first).
func (s *Server) Interactions(token string) []Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Interaction
	for i := len(s.interactions) - 1; i >= 0; i-- {
		if s.interactions[i].Token == token {
			out = append(out, s.interactions[i])
		}
	}
	return out
}

// All returns every recorded interaction (newest first).
func (s *Server) All() []Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Interaction, len(s.interactions))
	for i, it := range s.interactions {
		out[len(s.interactions)-1-i] = it
	}
	return out
}

// Advertised returns the base URL targets should call.
func (s *Server) Advertised() string { return s.advertised }
