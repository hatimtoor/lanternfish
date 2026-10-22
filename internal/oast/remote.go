package oast

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// This file turns Lanternfish's OAST listener into a hosted ("public") collaborator:
// a server anyone can deploy so blind/out-of-band checks work without each
// scanner running its own listener, and a client that points the scanner at
// such a server. It mirrors the role of Burp Collaborator while being an
// independent implementation.

// ServeControl starts the collaborator's control API on addr. Clients poll
// GET /interactions?token=<token> (header X-Lanternfish-Token: <secret>, when a
// secret is set) and receive the interactions recorded for that token as JSON.
// This runs on a different port from the interaction listener so polling is not
// itself recorded as a callback. Returns the bound address.
func (s *Server) ServeControl(addr, secret string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/interactions", func(w http.ResponseWriter, r *http.Request) {
		if secret != "" {
			got := r.Header.Get("X-Lanternfish-Token")
			if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Interactions(token))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), nil
}

// Remote is a scan.Interactor backed by a hosted collaborator server. Payload
// URLs point at the collaborator's interaction domain; hit lookups poll its
// control API.
type Remote struct {
	domain     string // interaction base URL targets call, e.g. http://oast.example.com
	controlURL string // control API base, e.g. http://oast.example.com:8085
	secret     string
	hc         *http.Client
}

// NewRemote builds a Remote collaborator client.
func NewRemote(domain, controlURL, secret string) *Remote {
	return &Remote{
		domain:     strings.TrimRight(domain, "/"),
		controlURL: strings.TrimRight(controlURL, "/"),
		secret:     secret,
		hc:         &http.Client{Timeout: 10 * time.Second},
	}
}

// NewPayload mints a unique token and a callback URL on the collaborator domain.
func (r *Remote) NewPayload() (token, callback string) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	token = "oa" + hex.EncodeToString(b)
	return token, r.domain + "/" + token
}

func (r *Remote) poll(token string) []Interaction {
	u := r.controlURL + "/interactions?token=" + url.QueryEscape(token)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil
	}
	if r.secret != "" {
		req.Header.Set("X-Lanternfish-Token", r.secret)
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out []Interaction
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	return out
}

// Hits reports how many interactions the collaborator recorded for the token.
func (r *Remote) Hits(token string) int { return len(r.poll(token)) }

// HitDetails returns short descriptions of the token's interactions.
func (r *Remote) HitDetails(token string) []string {
	var out []string
	for _, it := range r.poll(token) {
		out = append(out, fmt.Sprintf("%s %s from %s", it.Method, it.Path, it.RemoteAddr))
	}
	return out
}

// RemoteFromEnv builds a Remote from LANTERNFISH_COLLABORATOR_URL (required),
// LANTERNFISH_COLLABORATOR_CONTROL (required) and LANTERNFISH_COLLABORATOR_SECRET
// (optional), so any entry point can use a hosted collaborator by configuration
// alone. Returns false when it is not configured.
func RemoteFromEnv() (*Remote, bool) {
	domain := os.Getenv("LANTERNFISH_COLLABORATOR_URL")
	control := os.Getenv("LANTERNFISH_COLLABORATOR_CONTROL")
	if domain == "" || control == "" {
		return nil, false
	}
	return NewRemote(domain, control, os.Getenv("LANTERNFISH_COLLABORATOR_SECRET")), true
}
