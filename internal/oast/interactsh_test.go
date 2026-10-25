package oast

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// TestInteractshDecodePoll verifies the end-to-end decryption and parsing of an
// Interactsh poll response: an interaction is encrypted exactly as the public
// server would (random AES key, RSA-OAEP-encrypted to the client's public key,
// AES-CFB data with a leading IV) and must come back out matchable by token.
func TestInteractshDecodePoll(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := &Interactsh{server: "oast.test", priv: priv, corrID: randLower(20), seen: map[string]Interaction{}}

	token, fqdn, ok := c.NewDNSPayload()
	if !ok || token == "" {
		t.Fatal("NewDNSPayload returned not-ok")
	}

	// Build the interaction JSON the server would send.
	inter := map[string]string{
		"protocol": "dns", "unique-id": fqdn, "full-id": fqdn, "q-type": "A",
		"remote-address": "203.0.113.9", "timestamp": time.Now().Format(time.RFC3339),
	}
	plain, _ := json.Marshal(inter)

	// Encrypt like the server: random AES-256 key, AES-CFB with leading IV.
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	block, _ := aes.NewCipher(aesKey)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	ct := make([]byte, len(plain))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ct, plain)
	dataItem := base64.StdEncoding.EncodeToString(append(append([]byte{}, iv...), ct...))

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, aesKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	aesKeyB64 := base64.StdEncoding.EncodeToString(encKey)

	its, err := c.decodePoll(aesKeyB64, []string{dataItem})
	if err != nil {
		t.Fatalf("decodePoll: %v", err)
	}
	if len(its) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(its))
	}
	if its[0].RemoteAddr != "203.0.113.9" {
		t.Errorf("remote addr = %q", its[0].RemoteAddr)
	}

	// Feed it into the store and confirm token matching works.
	c.seen[its[0].Host+its[0].Time.String()] = its[0]
	if n := countMatches(c, token); n != 1 {
		t.Errorf("Hits-style match for token = %d, want 1", n)
	}
	if n := countMatches(c, "nonexistenttoken"); n != 0 {
		t.Errorf("match for bogus token = %d, want 0", n)
	}
}

// countMatches mirrors Hits without the network poll.
func countMatches(c *Interactsh, token string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, it := range c.seen {
		if contains(it.Host, token) || contains(it.Path, token) {
			n++
		}
	}
	return n
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestInteractshPayloadFormat(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	c := &Interactsh{server: "oast.pro", priv: priv, corrID: randLower(20), seen: map[string]Interaction{}}
	tok, url := c.NewPayload()
	if len(tok) != 13 {
		t.Errorf("token len = %d, want 13", len(tok))
	}
	wantSuffix := c.corrID + tok + ".oast.pro"
	if !contains(url, wantSuffix) {
		t.Errorf("url %q missing host %q", url, wantSuffix)
	}
}
