package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeyPair writes a fresh self-signed PEM cert/key with the given serial
// to certFile/keyFile and returns the certificate DER for identity checks.
func writeKeyPair(t *testing.T, certFile, keyFile string, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return der
}

// forceCheck rewinds the loader's throttle and marks the files newer than
// the last load, so the next get() re-stats and reloads without sleeping.
func forceCheck(t *testing.T, l *certLoader) {
	t.Helper()
	future := time.Now().Add(time.Hour)
	for _, f := range []string{l.certFile, l.keyFile} {
		if err := os.Chtimes(f, future, future); err != nil {
			t.Fatal(err)
		}
	}
	l.mu.Lock()
	l.checked = time.Time{}
	l.mu.Unlock()
}

func TestCertLoaderReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")

	first := writeKeyPair(t, certFile, keyFile, 1)
	l, err := newCertLoader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := l.get(); !bytes.Equal(c.Certificate[0], first) {
		t.Fatal("initial certificate is not the one on disk")
	}

	// Rotate: the loader must pick up the new pair on the next handshake.
	second := writeKeyPair(t, certFile, keyFile, 2)
	forceCheck(t, l)
	if c, _ := l.get(); !bytes.Equal(c.Certificate[0], second) {
		t.Fatal("certificate not reloaded after rotation")
	}

	// A botched rotation (unparsable key) must keep the last good pair.
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	forceCheck(t, l)
	if c, _ := l.get(); !bytes.Equal(c.Certificate[0], second) {
		t.Fatal("broken reload replaced the working certificate")
	}
}

func TestCertLoaderThrottles(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	first := writeKeyPair(t, certFile, keyFile, 1)
	l, err := newCertLoader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	// Rotate but do NOT rewind the throttle: within a second of the last
	// check, get() must not hit the disk again.
	writeKeyPair(t, certFile, keyFile, 2)
	future := time.Now().Add(time.Hour)
	for _, f := range []string{certFile, keyFile} {
		if err := os.Chtimes(f, future, future); err != nil {
			t.Fatal(err)
		}
	}
	if c, _ := l.get(); !bytes.Equal(c.Certificate[0], first) {
		t.Fatal("loader re-statted inside the throttle window")
	}
}

func TestCertLoaderBadStartup(t *testing.T) {
	if _, err := newCertLoader("/nonexistent/cert.pem", "/nonexistent/key.pem"); err == nil {
		t.Fatal("expected startup error for missing files")
	}
}
