package server

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"stun/internal/stunmsg"
)

// startDiscovery builds a Discovery from four loopback sockets on random
// ports. Same IP for both rows — index mechanics are identical, and
// loopback offers no second address.
func startDiscovery(t *testing.T) *Discovery {
	t.Helper()
	d := &Discovery{}
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			d.conns[i][j] = conn
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); d.Serve() }()
	t.Cleanup(func() { d.Close(); <-done })
	return d
}

func discoveryClient(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.SetWriteBuffer(1 << 16) // Darwin caps datagrams at SO_SNDBUF; padded requests are bigger
	return c
}

// sendTo sends req to socket [i][j] of d and returns the parsed response
// and the address it arrived from.
func sendTo(t *testing.T, c *net.UDPConn, d *Discovery, req *stunmsg.Message, i, j int) (*stunmsg.Message, netip.AddrPort) {
	t.Helper()
	if _, err := c.WriteToUDPAddrPort(req.Marshal(), localAddrPort(d.conns[i][j])); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1<<16) // padded responses overshoot the MTU by design
	n, from, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stunmsg.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return resp, from
}

func TestDiscoveryPlainRequest(t *testing.T) {
	d := startDiscovery(t)
	c := discoveryClient(t)
	resp, from := sendTo(t, c, d, newRequest(t), 0, 0)

	if resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v", resp)
	}
	// No CHANGE-REQUEST: response comes from the receiving socket.
	if want := localAddrPort(d.conns[0][0]); from != want {
		t.Fatalf("from = %v, want %v", from, want)
	}
	origin, err := resp.Address(stunmsg.AttrResponseOrigin)
	if err != nil || origin != localAddrPort(d.conns[0][0]) {
		t.Fatalf("RESPONSE-ORIGIN = %v (%v)", origin, err)
	}
	other, err := resp.Address(stunmsg.AttrOtherAddress)
	if err != nil || other != localAddrPort(d.conns[1][1]) {
		t.Fatalf("OTHER-ADDRESS = %v (%v)", other, err)
	}
	// Both mapped-address forms present and equal.
	xor, err := resp.XORMappedAddress()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := resp.Address(stunmsg.AttrMappedAddress)
	if err != nil || plain != xor {
		t.Fatalf("MAPPED-ADDRESS = %v, XOR = %v (%v)", plain, xor, err)
	}
	if want := localAddrPort(c); plain != want {
		t.Fatalf("mapped = %v, want %v", plain, want)
	}
}

func TestDiscoveryChangeRequest(t *testing.T) {
	d := startDiscovery(t)
	cases := []struct {
		flags  byte
		oi, oj int
	}{
		{stunmsg.ChangePort, 0, 1},
		{stunmsg.ChangeIP, 1, 0},
		{stunmsg.ChangeIP | stunmsg.ChangePort, 1, 1},
	}
	for _, tc := range cases {
		c := discoveryClient(t)
		req := newRequest(t)
		req.Add(stunmsg.AttrChangeRequest, []byte{0, 0, 0, tc.flags})
		resp, from := sendTo(t, c, d, req, 0, 0)

		if resp.Type != stunmsg.BindingSuccess {
			t.Fatalf("flags %#x: type = %v", tc.flags, resp)
		}
		if want := localAddrPort(d.conns[tc.oi][tc.oj]); from != want {
			t.Errorf("flags %#x: from = %v, want %v", tc.flags, from, want)
		}
		origin, err := resp.Address(stunmsg.AttrResponseOrigin)
		if err != nil || origin != from {
			t.Errorf("flags %#x: RESPONSE-ORIGIN = %v, sent from %v", tc.flags, origin, from)
		}
	}
}

func TestDiscoveryResponsePort(t *testing.T) {
	d := startDiscovery(t)
	sender := discoveryClient(t)
	receiver := discoveryClient(t)

	req := newRequest(t)
	port := localAddrPort(receiver).Port()
	req.Add(stunmsg.AttrResponsePort, []byte{byte(port >> 8), byte(port), 0, 0})
	if _, err := sender.WriteToUDPAddrPort(req.Marshal(), localAddrPort(d.conns[0][0])); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	n, from, err := receiver.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal("no response on the RESPONSE-PORT socket:", err)
	}
	resp, err := stunmsg.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v", resp)
	}
	if want := localAddrPort(d.conns[0][0]); from != want {
		t.Fatalf("from = %v, want receiving socket %v", from, want)
	}
	// The mapped address reflects where the request came from, not where
	// the response was redirected to.
	xor, err := resp.XORMappedAddress()
	if err != nil || xor != localAddrPort(sender) {
		t.Fatalf("mapped = %v (%v), want sender %v", xor, err, localAddrPort(sender))
	}
}

func TestDiscoveryResponsePortMalformedIsDropped(t *testing.T) {
	d := startDiscovery(t)
	c := discoveryClient(t)
	req := newRequest(t)
	req.Add(stunmsg.AttrResponsePort, []byte{0x12, 0x34}) // missing RFFU bytes
	if _, err := c.WriteToUDPAddrPort(req.Marshal(), localAddrPort(d.conns[0][0])); err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := c.ReadFromUDPAddrPort(make([]byte, 1500)); err == nil {
		t.Fatalf("got %d-byte response, want silence", n)
	}
}

func TestDiscoveryPadding(t *testing.T) {
	d := startDiscovery(t)
	c := discoveryClient(t)
	req := newRequest(t)
	// An oversized request also proves the read loop takes datagrams
	// beyond a typical MTU, which the request-direction fragment test needs.
	req.Add(stunmsg.AttrPadding, make([]byte, 20*1024))
	resp, _ := sendTo(t, c, d, req, 0, 0)

	if resp.Type != stunmsg.BindingSuccess {
		t.Fatalf("type = %v", resp)
	}
	pad, ok := resp.Get(stunmsg.AttrPadding)
	if !ok {
		t.Fatal("response has no PADDING")
	}
	if want := paddingLen(d.conns[0][0]); len(pad) != want {
		t.Fatalf("padding length = %d, want %d", len(pad), want)
	}
	if len(pad)%4 != 0 || len(pad) < 1280 {
		t.Fatalf("padding length = %d, want a 4-multiple >= min MTU", len(pad))
	}
}

func TestDiscoveryPaddingWithResponsePortIs400(t *testing.T) {
	d := startDiscovery(t)
	c := discoveryClient(t)
	req := newRequest(t)
	req.Add(stunmsg.AttrPadding, make([]byte, 4))
	req.Add(stunmsg.AttrResponsePort, []byte{0x12, 0x34, 0, 0})
	// Arrives back at the sender itself: the redirect must not apply.
	resp, from := sendTo(t, c, d, req, 0, 0)

	if resp.Type != stunmsg.BindingError {
		t.Fatalf("type = %v", resp)
	}
	if code := errorCode(t, resp); code != 400 {
		t.Fatalf("error code = %d, want 400", code)
	}
	if want := localAddrPort(d.conns[0][0]); from != want {
		t.Fatalf("error from = %v, want receiving socket %v", from, want)
	}
}

func TestDiscoveryStillRejectsUnknownAttrs(t *testing.T) {
	d := startDiscovery(t)
	c := discoveryClient(t)
	req := newRequest(t)
	req.Add(0x7FFF, []byte{1})
	// Error responses leave from the receiving socket even with flags set.
	req.Add(stunmsg.AttrChangeRequest, []byte{0, 0, 0, stunmsg.ChangeIP | stunmsg.ChangePort})
	resp, from := sendTo(t, c, d, req, 0, 0)

	if resp.Type != stunmsg.BindingError {
		t.Fatalf("type = %v", resp)
	}
	if want := localAddrPort(d.conns[0][0]); from != want {
		t.Fatalf("error from = %v, want receiving socket %v", from, want)
	}
}

// Classic NAT-type detection (RFC 3489 §10.1) reads SOURCE-ADDRESS and
// CHANGED-ADDRESS; the modern RFC 5780 names would be unknown mandatory
// attributes to a classic parser, which must reject messages carrying them.
func TestDiscoveryClassic(t *testing.T) {
	d := startDiscovery(t)
	c := discoveryClient(t)
	req := newRequest(t)
	req.Cookie = 0xDEADBEEF
	req.Add(stunmsg.AttrChangeRequest, []byte{0, 0, 0, stunmsg.ChangePort})
	resp, from := sendTo(t, c, d, req, 0, 0)

	if resp.Type != stunmsg.BindingSuccess || resp.Cookie != req.Cookie {
		t.Fatalf("type = %v, cookie = %08x", resp, resp.Cookie)
	}
	if want := localAddrPort(d.conns[0][1]); from != want {
		t.Fatalf("from = %v, want changed-port socket %v", from, want)
	}
	if ap, err := resp.Address(stunmsg.AttrMappedAddress); err != nil || ap != localAddrPort(c) {
		t.Fatalf("MAPPED-ADDRESS = %v (%v)", ap, err)
	}
	if src, err := resp.Address(stunmsg.AttrSourceAddress); err != nil || src != from {
		t.Fatalf("SOURCE-ADDRESS = %v (%v), sent from %v", src, err, from)
	}
	if ch, err := resp.Address(stunmsg.AttrChangedAddress); err != nil || ch != localAddrPort(d.conns[1][1]) {
		t.Fatalf("CHANGED-ADDRESS = %v (%v)", ch, err)
	}
	for _, a := range resp.Attrs {
		switch a.Type {
		case stunmsg.AttrXORMappedAddress, stunmsg.AttrResponseOrigin,
			stunmsg.AttrOtherAddress, stunmsg.AttrSoftware, stunmsg.AttrFingerprint:
			t.Fatalf("classic response carries post-3489 attribute %04x", a.Type)
		}
	}
}
