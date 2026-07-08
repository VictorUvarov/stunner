package server

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"stun/stunmsg"
)

// Discovery serves the NAT behavior discovery usage (RFC 5780): the Binding
// service on four UDP sockets — two IPs × two ports — plus CHANGE-REQUEST,
// RESPONSE-ORIGIN, and OTHER-ADDRESS so clients can probe how their NAT
// maps and filters. PADDING and RESPONSE-PORT (fragment and lifetime tests)
// are not implemented; being comprehension-required, they correctly draw a
// 420 response.
type Discovery struct {
	conns [2][2]*net.UDPConn // [ip][port]
}

// discoveryIgnorable is the plain ignorable set plus CHANGE-REQUEST, which
// this usage understands and honors.
var discoveryIgnorable = map[uint16]bool{
	stunmsg.AttrUsername:               true,
	stunmsg.AttrMessageIntegrity:       true,
	stunmsg.AttrMessageIntegritySHA256: true,
	stunmsg.AttrChangeRequest:          true,
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
				d.Close()
				return nil, err
			}
			d.conns[i][j] = conn
		}
	}
	return d, nil
}

// Close closes all sockets, ending Serve.
func (d *Discovery) Close() error {
	for _, row := range d.conns {
		for _, c := range row {
			if c != nil {
				c.Close()
			}
		}
	}
	return nil
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

// serveSocket is the read loop for socket [i][j].
func (d *Discovery) serveSocket(i, j int, lim *limiter) error {
	conn := d.conns[i][j]
	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !lim.allow(src.Addr(), time.Now()) {
			continue
		}
		if resp, out := d.handle(buf[:n], src, i, j); resp != nil {
			out.WriteToUDPAddrPort(resp, src)
		}
	}
}

// handle builds the response for a datagram received on socket [i][j] and
// picks the socket to send it from: CHANGE-REQUEST flags flip the IP and/or
// port index (RFC 5780 §6.1, Table 1). Error responses always leave from
// the receiving socket.
func (d *Discovery) handle(pkt []byte, src netip.AddrPort, i, j int) ([]byte, *net.UDPConn) {
	req, ok := validate(pkt, discoveryIgnorable)
	if !ok {
		return nil, nil
	}

	oi, oj := i, j
	if v, found := req.Get(stunmsg.AttrChangeRequest); found {
		if len(v) != 4 {
			return nil, nil
		}
		if v[3]&stunmsg.ChangeIP != 0 {
			oi ^= 1
		}
		if v[3]&stunmsg.ChangePort != 0 {
			oj ^= 1
		}
	}

	resp := respond(req, src, discoveryIgnorable)
	out := d.conns[oi][oj]
	if resp.Type != stunmsg.BindingSuccess {
		out = d.conns[i][j]
	} else {
		// RFC 5780 §6.1: success responses carry MAPPED-ADDRESS too,
		// where the response actually originates, and the full alternate.
		resp.AddAddress(stunmsg.AttrMappedAddress, src)
		resp.AddAddress(stunmsg.AttrResponseOrigin, localAddrPort(out))
		resp.AddAddress(stunmsg.AttrOtherAddress, localAddrPort(d.conns[i^1][j^1]))
	}
	return seal(resp), out
}

// localAddrPort returns conn's bound address as a netip.AddrPort.
func localAddrPort(conn *net.UDPConn) netip.AddrPort {
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}
