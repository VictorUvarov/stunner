package server

import (
	"errors"
	"net"
	"time"

	"github.com/pion/transport/v4/udp"
)

// ServeDTLS answers Binding Requests on ln, a DTLS listener (STUN over
// DTLS-over-UDP, RFC 8489 §6.2.3; `stuns`, port 5349 — pion/dtls provides
// the listener, the one dependency this package takes beyond the stdlib).
// The accept-and-spawn lifecycle matches ServeTCP, but message handling
// follows the UDP rules: each DTLS record frames exactly one message, so
// bad input loses nothing — it is dropped and the association stays up.
// Transport-level trouble (handshake failure, idle timeout, failed write)
// hangs up.
func ServeDTLS(ln net.Listener) error {
	return acceptLoop(ln, serveDatagramConn)
}

// acceptLoop accepts connections until ln closes, serving each on its own
// goroutine; the per-connection loops share one rate limiter. pion's
// listener reports closure with its own sentinel instead of net.ErrClosed,
// so shutdown-is-nil needs both checks.
func acceptLoop(ln net.Listener, serve func(net.Conn, *limiter)) error {
	var lim *limiter
	if RPS > 0 {
		lim = newLimiter(RPS, Burst)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, udp.ErrClosedListener) {
				return nil
			}
			return err
		}
		go serve(c, lim)
	}
}

// serveDatagramConn answers records off one DTLS association. The first
// Read drives the handshake, so the idle deadline bounds that too. Requests
// over the rate budget are dropped without hanging up, like plain UDP: the
// record boundary survives, so silence stays cheaper than a reply.
func serveDatagramConn(c net.Conn, lim *limiter) {
	defer c.Close()
	src := c.RemoteAddr().(*net.UDPAddr).AddrPort()
	buf := make([]byte, maxConnMessage)
	for {
		c.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if !lim.allow(src.Addr(), time.Now()) {
			continue
		}
		if resp := handle(buf[:n], src); resp != nil {
			c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write(resp); err != nil {
				return
			}
		}
	}
}
