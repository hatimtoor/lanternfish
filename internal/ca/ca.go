// Package ca manages Lanternfish's local certificate authority used for TLS
// interception. It generates a CA keypair on first use, persists it, and mints
// short-lived leaf certificates per host on the fly. This is the standard
// man-in-the-middle approach used by intercepting proxies; the user installs
// the generated CA into their own trust store to inspect their own traffic.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Authority holds the CA cert/key and a cache of minted leaf certificates.
type Authority struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// Load loads a CA from dir, creating one if absent. Files: lanternfish-ca.pem and
// lanternfish-ca-key.pem.
func Load(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "lanternfish-ca.pem")
	keyPath := filepath.Join(dir, "lanternfish-ca-key.pem")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return parse(certPEM, keyPEM)
	}

	// Generate a fresh CA.
	a, err := generate()
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(a.caKey)
	if err != nil {
		return nil, err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, a.caPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return nil, err
	}
	return a, nil
}

func parse(certPEM, keyPEM []byte) (*Authority, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &Authority{caCert: cert, caKey: key, caPEM: certPEM, cache: map[string]*tls.Certificate{}}, nil
}

func generate() (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Lanternfish Local CA",
			Organization: []string{"Lanternfish"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &Authority{caCert: cert, caKey: key, caPEM: caPEM, cache: map[string]*tls.Certificate{}}, nil
}

// CertPEM returns the CA certificate in PEM form (for the user to trust).
func (a *Authority) CertPEM() []byte { return a.caPEM }

// maxLeafCache bounds how many per-host leaf certificates are retained.
const maxLeafCache = 10000

// LeafFor returns (minting if necessary) a TLS certificate for host, signed by
// the CA. Results are cached per host, bounded by maxLeafCache.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cache[host]; ok {
		return c, nil
	}
	// Bound the cache so a long session (or a host serving endless unique
	// subdomains) cannot grow memory without limit. Drop half when full; the
	// dropped hosts are simply re-minted on next use.
	if len(a.cache) >= maxLeafCache {
		drop := maxLeafCache / 2
		for k := range a.cache {
			delete(a.cache, k)
			if drop--; drop <= 0 {
				break
			}
		}
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// Use an IP SAN for IP-literal hosts and a DNS SAN otherwise, so the minted
	// leaf validates whether the target is reached by name or by address.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &leafKey.PublicKey, a.caKey)
	if err != nil {
		return nil, err
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, a.caCert.Raw},
		PrivateKey:  leafKey,
	}
	a.cache[host] = tlsCert
	return tlsCert, nil
}
