package server

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"stun/internal/stunmsg"
)

// Discovery serves the NAT behavior discovery usage (RFC 5780): the Binding
// service on four UDP sockets — two IPs × two ports — plus CHANGE-REQUEST,
// RESPONSE-ORIGIN, and OTHER-ADDRESS so clients can probe how their NAT maps
// and filters, RESPONSE-PORT for binding-lifetime tests, and PADDING for
// fragment tests.
type Discovery struct {
	conns [2][2]*net.UDPConn // [ip][port]
}

// discoveryIgnorable is the plain ignorable set plus the RFC 5780 request
// attributes, which this usage understands and honors.
var discoveryIgnorable = map[uint16]bool{
	stunmsg.AttrUsername:               true,
	stunmsg.AttrMessageIntegrity:       true,
	stunmsg.AttrMessageIntegritySHA256: true,
	stunmsg.AttrRealm:                  true,
	stunmsg.AttrNonce:                  true,
	stunmsg.AttrPasswordAlgorithm:      true,
	stunmsg.AttrUserhash:               true,
	stunmsg.AttrChangeRequest:          true,
	stunmsg.AttrPadding:                true,
	stunmsg.AttrResponsePort:           true,
}

// ListenDiscovery opens the four sockets discovery needs: each of ip1 and
// ip2 on each of port and altPort. The RFC requires two distinct public
// IPs for a spec-compliant deployment.
func ListenDiscovery(ip1, ip2 netip.Addr, port, altPort uint16) (*Discovery, error) {
	d := &Discovery{}
	for i, ip := range []netip.Addr{ip1, ip2} {
		for j, p := range []uint16{port, altPort} {
			conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, p)))
			if err != nil {
				if cerr := d.Close(); cerr != nil {
					slog.Warn("close during discovery setup failed", "err", cerr)
				}
				return nil, err
			}
			d.conns[i][j] = conn
		}
	}
	return d, nil
}

// Close closes all sockets, ending Serve. It closes every socket even if one
// fails and returns the first error.
func (d *Discovery) Close() error {
	var err error
	for _, row := range d.conns {
		for _, c := range row {
			if c == nil {
				continue
			}
			if e := c.Close(); e != nil && err == nil {
				err = e
			}
		}
	}
	return err
}

// Serve answers on all four sockets until they are closed; the four read
// loops share one rate limiter. Like Serve, closed sockets mean a nil return.
func (d *Discovery) Serve() error {
	var lim *limiter
	if RPS > 0 {
		lim = newLimiter(RPS, Burst)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := range d.conns {
		for j := range d.conns[i] {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				errs <- d.serveSocket(i, j, lim)
			}(i, j)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// serveSocket is the read loop for socket [i][j]. The buffer takes the
// largest possible datagram, not an MTU: fragment tests (PADDING) send
// requests deliberately bigger than the path MTU, and a short read here
// would truncate them into silence.
func (d *Discovery) serveSocket(i, j int, lim *limiter) error {
	conn := d.conns[i][j]
	// Padded responses can exceed the OS default datagram ceiling (Darwin
	// caps sends at SO_SNDBUF, 9216 by default). Best effort: on failure,
	// oversized sends just keep failing as they would have anyway.
	_ = conn.SetWriteBuffer(1 << 16)
	m := Metrics["discovery"]
	buf := make([]byte, 1<<16)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		m.Received.Add(1)
		if !lim.allow(src.Addr(), time.Now()) {
			m.Limited.Add(1)
			continue
		}
		if resp, out, dst := d.handle(buf[:n], src, i, j); resp != nil {
			m.countReply(resp)
			// Best-effort send, like plain UDP: to the client a failed reply
			// is just a lost packet, and it retransmits.
			_, _ = out.WriteToUDPAddrPort(resp, dst)
		}
	}
}

// handle builds the response for a datagram received on socket [i][j] and
// picks the socket to send it from and the address to send it to:
// CHANGE-REQUEST flags flip the IP and/or port index (RFC 5780 §6.1,
// Table 1), RESPONSE-PORT redirects a success to that port on the source
// IP (§7.5). Error responses always leave from the receiving socket back
// to the true source, so a misbehaving request can't aim even a small
// reply at a port its sender doesn't hold.
func (d *Discovery) handle(pkt []byte, src netip.AddrPort, i, j int) ([]byte, *net.UDPConn, netip.AddrPort) {
	req, _ := validate(pkt)
	if req == nil {
		return nil, nil, netip.AddrPort{}
	}
	key, sha2, errResp := authenticate(pkt, req)
	if errResp != nil {
		return seal(errResp, nil, false), d.conns[i][j], src
	}

	_, padding := req.Get(stunmsg.AttrPadding)
	rp, redirect := req.Get(stunmsg.AttrResponsePort)
	dst := src
	if redirect {
		if padding {
			// §6.1: PADDING plus RESPONSE-PORT is a 400 — a fragment
			// test redirected elsewhere could never be observed anyway.
			resp := &stunmsg.Message{Type: stunmsg.BindingError, TransactionID: req.TransactionID, Cookie: req.Cookie}
			resp.AddErrorCode(400, "Bad Request")
			return seal(resp, key, sha2), d.conns[i][j], src
		}
		if len(rp) != 4 { // 16-bit port + 2 bytes RFFU (§7.5)
			return nil, nil, netip.AddrPort{}
		}
		dst = netip.AddrPortFrom(src.Addr(), binary.BigEndian.Uint16(rp[:2]))
	}

	oi, oj := i, j
	if v, found := req.Get(stunmsg.AttrChangeRequest); found {
		if len(v) != 4 {
			return nil, nil, netip.AddrPort{}
		}
		if v[3]&stunmsg.ChangeIP != 0 {
			oi ^= 1
		}
		if v[3]&stunmsg.ChangePort != 0 {
			oj ^= 1
		}
	}

	resp := respond(req, src, discoveryIgnorable)
	if resp.Type != stunmsg.BindingSuccess {
		return seal(resp, key, sha2), d.conns[i][j], src
	}
	// RFC 5780 §6.1: success responses carry MAPPED-ADDRESS too,
	// where the response actually originates, and the full alternate.
	// Classic clients already got MAPPED-ADDRESS from respond, and their
	// NAT-type detection (RFC 3489 §10.1) reads the same two values under
	// the pre-5780 names SOURCE-ADDRESS and CHANGED-ADDRESS — which they
	// understand, so CHANGE-REQUEST probing keeps working for them.
	out := d.conns[oi][oj]
	if req.Classic() {
		resp.AddAddress(stunmsg.AttrSourceAddress, localAddrPort(out))
		resp.AddAddress(stunmsg.AttrChangedAddress, localAddrPort(d.conns[i^1][j^1]))
	} else {
		resp.AddAddress(stunmsg.AttrMappedAddress, src)
		resp.AddAddress(stunmsg.AttrResponseOrigin, localAddrPort(out))
		resp.AddAddress(stunmsg.AttrOtherAddress, localAddrPort(d.conns[i^1][j^1]))
	}
	if padding {
		resp.Add(stunmsg.AttrPadding, make([]byte, paddingLen(out)))
	}
	return seal(resp, key, sha2), out, dst
}

// localAddrPort returns conn's bound address as a netip.AddrPort.
func localAddrPort(conn *net.UDPConn) netip.AddrPort {
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// paddingLen returns the PADDING value size for responses leaving conn:
// the outgoing interface's MTU rounded up to a multiple of four
// (RFC 5780 §6.1), so the padded response overshoots the MTU and
// exercises response-direction fragmentation. Clamped to keep the whole
// datagram under the 64 KiB IP limit (Linux loopback reports MTU 65536);
// an interface we can't identify gets the Ethernet default.
func paddingLen(conn *net.UDPConn) int {
	mtu := 1500
	if ifi := interfaceByAddr(localAddrPort(conn).Addr()); ifi != nil {
		mtu = ifi.MTU
	}
	return min((mtu+3)/4*4, 65000)
}

// interfaceByAddr finds the network interface bound to ip, or nil.
func interfaceByAddr(ip netip.Addr) *net.Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifs {
		addrs, err := ifs[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if got, ok := netip.AddrFromSlice(ipn.IP); ok && got.Unmap() == ip.Unmap() {
				return &ifs[i]
			}
		}
	}
	return nil
}
