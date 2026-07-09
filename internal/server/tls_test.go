package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"stun/internal/stunmsg"
)

// testCert builds a throwaway self-signed certificate for 127.0.0.1.
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// STUN over TLS is served by the plain ServeTCP loop over a TLS listener;
// this covers the whole stack: handshake, framing inside the stream, reuse.
func TestTLSBinding(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCert(t)},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); ServeTCP(ln) }()
	t.Cleanup(func() { ln.Close(); <-done })

	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))

	for range 2 { // stream reuse works through TLS too
		req := newRequest(t)
		if _, err := c.Write(req.Marshal()); err != nil {
			t.Fatal(err)
		}
		resp, err := stunmsg.Parse(readMessage(t, c))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Type != stunmsg.BindingSuccess || resp.TransactionID != req.TransactionID {
			t.Fatalf("bad response: %v", resp)
		}
		ap, err := resp.XORMappedAddress()
		if err != nil {
			t.Fatal(err)
		}
		want := c.NetConn().LocalAddr().(*net.TCPAddr).AddrPort()
		if ap != want {
			t.Fatalf("mapped = %v, want %v", ap, want)
		}
	}
}
