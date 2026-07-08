package server

import (
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"stun/internal/stunmsg"
)

// startServer runs Serve on a loopback socket and returns a client conn
// already "connected" to it. Both close on test cleanup.
func startServer(t *testing.T) *net.UDPConn {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	// Join the serve goroutine on cleanup: it may still be mid-handle when
	// the socket closes, and the next test could be rewriting Credentials.
	done := make(chan struct{})
	go func() { defer close(done); Serve(srv) }()
	t.Cleanup(func() { srv.Close(); <-done })

	client, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(2 * time.Second))
	return client
}

func newRequest(t *testing.T) *stunmsg.Message {
	t.Helper()
	m := &stunmsg.Message{Type: stunmsg.BindingRequest}
	if _, err := rand.Read(m.TransactionID[:]); err != nil {
		t.Fatal(err)
	}
	return m
}

func roundTrip(t *testing.T, client *net.UDPConn, pkt []byte) *stunmsg.Message {
	t.Helper()
	if _, err := client.Write(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !stunmsg.VerifyFingerprint(buf[:n]) {
		t.Fatal("response fingerprint invalid")
	}
	resp, err := stunmsg.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestBinding(t *testing.T) {
	client := startServer(t)
	req := newRequest(t)
	resp := roundTrip(t, client, req.Marshal())

	if resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v", resp)
	}
	if resp.TransactionID != req.TransactionID {
		t.Fatal("transaction ID not echoed")
	}
	ap, err := resp.XORMappedAddress()
	if err != nil {
		t.Fatal(err)
	}
	want := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if ap != netip.AddrPortFrom(want.Addr().Unmap(), want.Port()) {
		t.Fatalf("mapped = %v, want %v", ap, want)
	}
}

func TestUnknownRequiredAttrGets420(t *testing.T) {
	client := startServer(t)
	req := newRequest(t)
	req.Add(0x7FFF, []byte{1, 2, 3, 4})
	resp := roundTrip(t, client, req.Marshal())

	if resp.Type != stunmsg.BindingError {
		t.Fatalf("type = %v", resp)
	}
	ec, ok := resp.Get(stunmsg.AttrErrorCode)
	if !ok || int(ec[2])*100+int(ec[3]) != 420 {
		t.Fatalf("error code attr = %x", ec)
	}
	ua, ok := resp.Get(stunmsg.AttrUnknownAttributes)
	if !ok || len(ua) != 2 || ua[0] != 0x7F || ua[1] != 0xFF {
		t.Fatalf("unknown-attributes = %x", ua)
	}
}

func TestIgnorableRequiredAttrStillSucceeds(t *testing.T) {
	client := startServer(t)
	req := newRequest(t)
	req.Add(0x0006, []byte("user:name")) // USERNAME
	if resp := roundTrip(t, client, req.Marshal()); resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v", resp)
	}
}

func TestAttrsAfterIntegrityIgnored(t *testing.T) {
	client := startServer(t)
	req := newRequest(t)
	req.Add(stunmsg.AttrMessageIntegrity, make([]byte, 20))
	// Outside the HMAC's coverage, so it must be ignored (RFC 8489 §9),
	// not answered with a 420.
	req.Add(0x7FFF, []byte{1, 2, 3, 4})
	if resp := roundTrip(t, client, req.Marshal()); resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v", resp)
	}
}

func TestDropsSilently(t *testing.T) {
	bad := newRequest(t)
	bad.AddFingerprint()
	badPkt := bad.Marshal()
	badPkt[len(badPkt)-1] ^= 0xFF // corrupt the CRC

	for name, pkt := range map[string][]byte{
		"garbage":         []byte("definitely not stun"),
		"bad fingerprint": badPkt,
	} {
		client := startServer(t)
		if _, err := client.Write(pkt); err != nil {
			t.Fatal(err)
		}
		client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, err := client.Read(make([]byte, 1500)); err == nil {
			t.Errorf("%s: got %d-byte reply, want silence", name, n)
		}
	}
}

func TestClassicBinding(t *testing.T) {
	client := startServer(t)
	req := newRequest(t)
	req.Cookie = 0xDEADBEEF // no magic cookie: an RFC 3489 client
	resp := roundTrip(t, client, req.Marshal())

	if resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v", resp)
	}
	if resp.Cookie != req.Cookie || resp.TransactionID != req.TransactionID {
		t.Fatal("classic 128-bit transaction ID not echoed")
	}
	ap, err := resp.Address(stunmsg.AttrMappedAddress)
	if err != nil {
		t.Fatal(err)
	}
	want := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if ap != netip.AddrPortFrom(want.Addr().Unmap(), want.Port()) {
		t.Fatalf("mapped = %v, want %v", ap, want)
	}
	// A classic parser knows no attribute padding and rejects unknown
	// mandatory attributes, so the response must carry MAPPED-ADDRESS
	// alone: no XOR form, no SOFTWARE, no FINGERPRINT.
	if len(resp.Attrs) != 1 {
		t.Fatalf("attrs = %v, want MAPPED-ADDRESS alone", resp)
	}
}

func TestClassic420StaysAligned(t *testing.T) {
	client := startServer(t)
	req := newRequest(t)
	req.Cookie = 0xDEADBEEF
	req.Add(0x7FFF, []byte{1, 2, 3, 4})
	resp := roundTrip(t, client, req.Marshal())

	if code := errorCode(t, resp); code != 420 {
		t.Fatalf("error code = %d, want 420", code)
	}
	if resp.Cookie != req.Cookie {
		t.Fatal("cookie not echoed")
	}
	ec, _ := resp.Get(stunmsg.AttrErrorCode)
	if len(ec)%4 != 0 {
		t.Fatalf("classic ERROR-CODE length %d not 4-aligned", len(ec))
	}
	if ua, _ := resp.Get(stunmsg.AttrUnknownAttributes); len(ua) != 4 {
		t.Fatalf("UNKNOWN-ATTRIBUTES = %x, want the odd list doubled", ua)
	}
}

func TestClassicAuthDrawsBare401(t *testing.T) {
	client := startAuthServer(t)
	req := newRequest(t)
	req.Cookie = 0xDEADBEEF
	resp := roundTrip(t, client, req.Marshal())

	if code := errorCode(t, resp); code != 401 {
		t.Fatalf("error code = %d, want 401", code)
	}
	// REALM and NONCE are mandatory attributes a classic parser must
	// reject, and classic clients can't run long-term auth anyway.
	if len(resp.Attrs) != 1 {
		t.Fatalf("attrs = %v, want ERROR-CODE alone", resp)
	}
	if ec, _ := resp.Get(stunmsg.AttrErrorCode); len(ec)%4 != 0 {
		t.Fatalf("classic ERROR-CODE length %d not 4-aligned", len(ec))
	}
}
