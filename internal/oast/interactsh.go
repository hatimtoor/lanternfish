package oast

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interactsh is a client for the public Interactsh out-of-band (OAST) service
// used by the wider security community (the same protocol nuclei uses). It lets
// Lanternfish catch blind vulnerabilities on *remote* targets without the user
// standing up any DNS/HTTP infrastructure of their own: the public server
// receives the DNS/HTTP callback, and the client polls it over HTTPS and
// decrypts the interactions with a locally generated RSA key.
//
// This is the piece that makes out-of-band detection usable for bug-bounty and
// research work against third-party systems, where the self-hosted local
// listener can never be reached. Learners testing on their own machine can keep
// using the local listener instead.
//
// Interactions are end-to-end encrypted: the server encrypts each interaction
// with a random AES key, encrypts that key to the client's RSA public key, and
// only this client (holding the private key) can read them. It implements
// scan.Interactor plus the optional DNS-payload method.
type Interactsh struct {
	server string
	http   *http.Client
	priv   *rsa.PrivateKey
	corrID string // 20-char correlation id the server groups interactions under
	secret string // registration secret required to poll

	mu   sync.Mutex
	seen map[string]Interaction // de-duplicated interactions, keyed by unique id+time
}

// DefaultInteractshServers are the free public Interactsh servers operated by
// ProjectDiscovery. The first reachable one is used.
var DefaultInteractshServers = []string{"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"}

// NewInteractsh generates a key pair and registers with the given Interactsh
// server (e.g. "oast.pro"). It returns an error if registration fails so the
// caller can fall back to the local listener.
func NewInteractsh(server string) (*Interactsh, error) {
	server = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(server, "https://"), "http://"))
	server = strings.TrimSuffix(server, "/")
	if server == "" {
		return nil, fmt.Errorf("interactsh: empty server")
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	c := &Interactsh{
		server: server,
		http:   &http.Client{Timeout: 15 * time.Second},
		priv:   priv,
		corrID: randLower(20),
		secret: uuidV4(),
		seen:   map[string]Interaction{},
	}
	if err := c.register(); err != nil {
		return nil, err
	}
	return c, nil
}

// NewInteractshAuto tries each default public server and returns the first that
// registers successfully.
func NewInteractshAuto() (*Interactsh, error) {
	var lastErr error
	for _, srv := range DefaultInteractshServers {
		if c, err := NewInteractsh(srv); err == nil {
			return c, nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("interactsh: no servers configured")
	}
	return nil, fmt.Errorf("interactsh: all public servers failed: %w", lastErr)
}

// Server returns the Interactsh server host this client registered with.
func (c *Interactsh) Server() string { return c.server }

func (c *Interactsh) register() error {
	pubDER, err := x509.MarshalPKIXPublicKey(&c.priv.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	body, _ := json.Marshal(map[string]string{
		"public-key":     base64.StdEncoding.EncodeToString(pubPEM),
		"secret-key":     c.secret,
		"correlation-id": c.corrID,
	})
	req, _ := http.NewRequest(http.MethodPost, "https://"+c.server+"/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("interactsh: register %s: status %d", c.server, resp.StatusCode)
	}
	return nil
}

// NewPayload mints a unique callback URL on the public server. The returned
// token is the per-payload random label, matched against recorded interactions.
func (c *Interactsh) NewPayload() (token, url string) {
	token = randLower(13)
	host := c.corrID + token + "." + c.server
	return token, "https://" + host
}

// NewDNSPayload mints a bare hostname whose DNS lookup the server records.
func (c *Interactsh) NewDNSPayload() (token, fqdn string, ok bool) {
	token = randLower(13)
	return token, c.corrID + token + "." + c.server, true
}

// Hits reports how many recorded interactions match the token.
func (c *Interactsh) Hits(token string) int {
	c.pollOnce()
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, it := range c.seen {
		if strings.Contains(it.Host, token) || strings.Contains(it.Path, token) {
			n++
		}
	}
	return n
}

// HitDetails returns short descriptions of the token's interactions.
func (c *Interactsh) HitDetails(token string) []string {
	c.pollOnce()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, it := range c.seen {
		if strings.Contains(it.Host, token) || strings.Contains(it.Path, token) {
			out = append(out, fmt.Sprintf("%s from %s (%s)", it.Method, it.RemoteAddr, it.Host))
		}
	}
	return out
}

// pollOnce fetches and decrypts any new interactions from the server.
func (c *Interactsh) pollOnce() {
	req, _ := http.NewRequest(http.MethodGet, "https://"+c.server+"/poll?id="+c.corrID+"&secret="+c.secret, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	var pr struct {
		Data   []string `json:"data"`
		AESKey string   `json:"aes_key"`
	}
	if err := json.Unmarshal(raw, &pr); err != nil {
		return
	}
	its, err := c.decodePoll(pr.AESKey, pr.Data)
	if err != nil {
		return
	}
	c.mu.Lock()
	for _, it := range its {
		c.seen[it.Host+it.Time.String()] = it
	}
	c.mu.Unlock()
}

// decodePoll decrypts a poll response (the AES key is RSA-OAEP encrypted to our
// public key; each data item is AES-CFB encrypted with a leading IV). It is
// separated from the HTTP transport so the crypto path can be unit-tested.
func (c *Interactsh) decodePoll(aesKeyB64 string, data []string) ([]Interaction, error) {
	if aesKeyB64 == "" || len(data) == 0 {
		return nil, nil
	}
	encKey, err := base64.StdEncoding.DecodeString(aesKeyB64)
	if err != nil {
		return nil, err
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.priv, encKey, nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	var out []Interaction
	for _, d := range data {
		buf, err := base64.StdEncoding.DecodeString(d)
		if err != nil || len(buf) < aes.BlockSize {
			continue
		}
		iv := buf[:aes.BlockSize]
		ct := buf[aes.BlockSize:]
		pt := make([]byte, len(ct))
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(pt, ct)
		var m struct {
			Protocol  string `json:"protocol"`
			UniqueID  string `json:"unique-id"`
			FullID    string `json:"full-id"`
			QType     string `json:"q-type"`
			Address   string `json:"remote-address"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(pt, &m); err != nil {
			continue
		}
		ts, _ := time.Parse(time.RFC3339, m.Timestamp)
		if ts.IsZero() {
			ts = time.Now()
		}
		id := m.FullID
		if id == "" {
			id = m.UniqueID
		}
		proto := strings.ToUpper(m.Protocol)
		if m.QType != "" {
			proto += " " + m.QType
		}
		out = append(out, Interaction{
			Token: id, Time: ts, RemoteAddr: m.Address,
			Method: proto, Path: id, Host: id, UserAgent: m.QType,
		})
	}
	return out, nil
}

const lowerAlnum = "abcdefghijklmnopqrstuvwxyz0123456789"

// randLower returns n random lowercase-alphanumeric characters (the character
// set Interactsh subdomains must use).
func randLower(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = lowerAlnum[int(b[i])%len(lowerAlnum)]
	}
	return string(b)
}

// uuidV4 returns a random RFC 4122 version-4 UUID string.
func uuidV4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
