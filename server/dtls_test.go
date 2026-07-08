package server

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/dtls/v3"

	"stun/stunmsg"
)

func startDTLSServer(t *testing.T) *dtls.Conn {
	t.Helper()
	ln, err := dtls.ListenWithOptions("udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dtls.WithCertificates(testCert(t)))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); ServeDTLS(ln) }()
	t.Cleanup(func() { ln.Close(); <-done })

	c, err := dtls.DialWithOptions("udp", ln.Addr().(*net.UDPAddr), dtls.WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	return c
}

func TestDTLSBinding(t *testing.T) {
	c := startDTLSServer(t)
	req := newRequest(t)
	if _, err := c.Write(req.Marshal()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxConnMessage)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stunmsg.Parse(buf[:n])
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
	// pion reports a wildcard LocalAddr for dialed conns, so only the
	// port is comparable; the IP must be the loopback we dialed over.
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"),
		c.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	if ap != want {
		t.Fatalf("mapped = %v, want %v", ap, want)
	}
}

// Unlike TCP, a bad record must not kill the association: records frame
// one message each, so the server drops the junk and answers what follows.
func TestDTLSSurvivesGarbage(t *testing.T) {
	c := startDTLSServer(t)
	if _, err := c.Write([]byte("this is not stun")); err != nil {
		t.Fatal(err)
	}
	req := newRequest(t)
	if _, err := c.Write(req.Marshal()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxConnMessage)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal("association should have survived the garbage record:", err)
	}
	resp, err := stunmsg.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if resp.Type != stunmsg.BindingSuccess || resp.TransactionID != req.TransactionID {
		t.Fatalf("bad response: %v", resp)
	}
}

// RFC 8489 §11: classic STUN must never ride DTLS — requests draw a 500
// and the association survives to serve modern messages.
func TestDTLSRejectsClassic(t *testing.T) {
	c := startDTLSServer(t)
	classic := newRequest(t)
	classic.Cookie = 0xDEADBEEF
	if _, err := c.Write(classic.Marshal()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxConnMessage)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stunmsg.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if code := errorCode(t, resp); code != 500 {
		t.Fatalf("error code = %d, want 500", code)
	}
	if resp.Cookie != classic.Cookie || resp.TransactionID != classic.TransactionID {
		t.Fatal("classic 128-bit transaction ID not echoed")
	}

	modern := newRequest(t)
	if _, err := c.Write(modern.Marshal()); err != nil {
		t.Fatal(err)
	}
	n, err = c.Read(buf)
	if err != nil {
		t.Fatal("association should have survived the classic request:", err)
	}
	if resp, err = stunmsg.Parse(buf[:n]); err != nil || resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("modern follow-up failed: %v (%v)", resp, err)
	}
}
