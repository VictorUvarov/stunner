package server

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"stun/stunmsg"
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
	go d.Serve()
	t.Cleanup(func() { d.Close() })
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
	return c
}

// sendTo sends req to socket [i][j] of d and returns the parsed response
// and the address it arrived from.
func sendTo(t *testing.T, c *net.UDPConn, d *Discovery, req *stunmsg.Message, i, j int) (*stunmsg.Message, netip.AddrPort) {
	t.Helper()
	if _, err := c.WriteToUDPAddrPort(req.Marshal(), localAddrPort(d.conns[i][j])); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
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
