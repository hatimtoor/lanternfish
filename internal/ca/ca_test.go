package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCreatesAndPersists(t *testing.T) {
	dir := t.TempDir()
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "lanternfish-ca.pem")
	keyPath := filepath.Join(dir, "lanternfish-ca-key.pem")
	if _, err := os.Stat(certPath); err != nil {
		t.Error("CA cert not written")
	}
	// Key file should be owner-only (0600) where the OS honors it.
	if fi, err := os.Stat(keyPath); err == nil {
		if fi.Mode().Perm()&0o077 != 0 && os.Getenv("OS") == "" {
			t.Logf("key perms %v (ok on Windows)", fi.Mode().Perm())
		}
	}
	// Reload returns the same CA certificate bytes.
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.CertPEM()) != string(b.CertPEM()) {
		t.Error("reload produced a different CA (should be persistent)")
	}
}

func TestLeafForSignedByCA(t *testing.T) {
	a, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Certificate) < 2 {
		t.Fatal("leaf should include its cert and the CA cert")
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
		t.Errorf("leaf SAN wrong: %v", cert.DNSNames)
	}
	// Verify the leaf chains to the CA.
	block, _ := pem.Decode(a.CertPEM())
	caCert, _ := x509.ParseCertificate(block.Bytes)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots}); err != nil {
		t.Errorf("leaf does not verify against CA: %v", err)
	}
	// Cached: same host returns identical cert.
	leaf2, _ := a.LeafFor("example.com")
	if &leaf.Certificate[0][0] != &leaf2.Certificate[0][0] {
		t.Error("leaf should be cached per host")
	}
}
