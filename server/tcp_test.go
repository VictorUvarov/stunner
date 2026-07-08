package server

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"stun/stunmsg"
)

func startTCPServer(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); ServeTCP(ln) }()
	t.Cleanup(func() { ln.Close(); <-done })

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	return c.(*net.TCPConn)
}

// readMessage reads one length-framed STUN message off the stream.
func readMessage(t *testing.T, c net.Conn) []byte {
	t.Helper()
	buf := make([]byte, maxConnMessage)
	if _, err := io.ReadFull(c, buf[:stunmsg.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	n := stunmsg.HeaderSize + int(binary.BigEndian.Uint16(buf[2:4]))
	if _, err := io.ReadFull(c, buf[stunmsg.HeaderSize:n]); err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestTCPBinding(t *testing.T) {
	c := startTCPServer(t)

	// Two requests on the same connection: TCP conns are reusable.
	for i := 0; i < 2; i++ {
		req := newRequest(t)
		if _, err := c.Write(req.Marshal()); err != nil {
			t.Fatal(err)
		}
		raw := readMessage(t, c)
		if !stunmsg.VerifyFingerprint(raw) {
			t.Fatal("bad response fingerprint")
		}
		resp, err := stunmsg.Parse(raw)
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
		want := c.LocalAddr().(*net.TCPAddr).AddrPort()
		if ap != netip.AddrPortFrom(want.Addr().Unmap(), want.Port()) {
			t.Fatalf("mapped = %v, want %v", ap, want)
		}
	}
}

func TestTCPStaysOpenOnSilentDiscard(t *testing.T) {
	c := startTCPServer(t)

	// Neither a Binding Indication (no response, RFC 8489 §6.3.2) nor an
	// unsupported method (silently discarded, §6.3) may cost the client
	// its connection: §6.2.2 has the server let the client close it.
	for _, typ := range []uint16{stunmsg.BindingIndication, 0x0003} {
		m := newRequest(t)
		m.Type = typ
		if _, err := c.Write(m.Marshal()); err != nil {
			t.Fatal(err)
		}
	}

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
}

func TestTCPHangsUpOnGarbage(t *testing.T) {
	c := startTCPServer(t)
	if _, err := c.Write([]byte("this is not stun and is padded to 20+ bytes....")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close, got data")
	}
}
