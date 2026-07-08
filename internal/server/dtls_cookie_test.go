package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"

	"stun/internal/stunmsg"
)

// DTLS record and handshake framing constants (RFC 6347 §4.1, §4.2.2),
// just enough to recognize handshake flights on the wire.
const (
	dtlsContentHandshake = 22
	dtlsRecordHeaderLen  = 13 // type(1) version(2) epoch(2) seq(6) length(2)
	handshakeServerHello = 2
	handshakeHelloVerify = 3
)

// TestDTLSCookieExchange pins the RFC 8489 §13 DoS countermeasure: a server
// offering DTLS MUST implement the RFC 6347 §4.2.1 cookie exchange. We rely
// on pion/dtls for it (and never set its insecure skip option), so this test
// watches a real handshake through a recording UDP proxy and asserts the
// server's first flight answering the initial ClientHello is a
// HelloVerifyRequest — not a ServerHello, which would mean the server
// committed handshake state to an unverified (spoofable) source address.
func TestDTLSCookieExchange(t *testing.T) {
	ln, err := dtls.ListenWithOptions("udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dtls.WithCertificates(testCert(t)))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); ServeDTLS(ln) }()
	t.Cleanup(func() { ln.Close(); <-done })

	// A one-client UDP proxy in front of the server, recording every
	// server → client datagram in arrival order.
	proxy, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Close() })
	upstream, err := net.DialUDP("udp", nil, ln.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upstream.Close() })

	var (
		mu            sync.Mutex
		serverFlights [][]byte
		clientAddr    *net.UDPAddr
	)
	go func() { // client → server
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := proxy.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = addr
			mu.Unlock()
			upstream.Write(buf[:n])
		}
	}()
	go func() { // server → client
		buf := make([]byte, 64<<10)
		for {
			n, err := upstream.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			serverFlights = append(serverFlights, append([]byte(nil), buf[:n]...))
			dst := clientAddr
			mu.Unlock()
			if dst != nil {
				proxy.WriteToUDP(buf[:n], dst)
			}
		}
	}()

	c, err := dtls.DialWithOptions("udp", proxy.LocalAddr().(*net.UDPAddr),
		dtls.WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))

	// The handshake finished through the proxy; make sure STUN works over
	// it too, so the recording captured a genuine end-to-end exchange.
	req := newRequest(t)
	if _, err := c.Write(req.Marshal()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxConnMessage)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := stunmsg.Parse(buf[:n]); err != nil || resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("binding through proxy failed: %v (%v)", resp, err)
	}

	mu.Lock()
	flights := serverFlights
	mu.Unlock()
	if len(flights) == 0 {
		t.Fatal("recorded no server flights")
	}
	first := flights[0]
	if len(first) < dtlsRecordHeaderLen+1 || first[0] != dtlsContentHandshake {
		t.Fatalf("first server flight is not a handshake record: % x", first[:min(len(first), 16)])
	}
	if got := first[dtlsRecordHeaderLen]; got != handshakeHelloVerify {
		t.Fatalf("first server handshake message type = %d, want %d (HelloVerifyRequest): "+
			"server committed to an unverified source address", got, handshakeHelloVerify)
	}
	for _, msg := range handshakeTypes(t, first) {
		if msg == handshakeServerHello {
			t.Fatal("ServerHello sent alongside HelloVerifyRequest, before the cookie round trip")
		}
	}
}

// handshakeTypes returns the handshake message type of every plaintext
// handshake record in one datagram.
func handshakeTypes(t *testing.T, datagram []byte) []byte {
	t.Helper()
	var types []byte
	for off := 0; off+dtlsRecordHeaderLen <= len(datagram); {
		length := int(datagram[off+11])<<8 | int(datagram[off+12])
		if datagram[off] == dtlsContentHandshake && off+dtlsRecordHeaderLen < len(datagram) {
			types = append(types, datagram[off+dtlsRecordHeaderLen])
		}
		off += dtlsRecordHeaderLen + length
	}
	return types
}
