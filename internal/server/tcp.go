package server

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"time"

	"stun/internal/stunmsg"
)

// maxConnMessage caps a single message read off a connection-oriented
// transport; 4 KiB fits any Binding request many times over.
const maxConnMessage = 4096

// idleTimeout is how long a connection may sit between requests.
const idleTimeout = 40 * time.Second

// ServeTCP answers Binding Requests on ln until it is closed (which, like
// Serve, returns nil — that's the shutdown path). Each connection is handled
// on its own goroutine and may carry multiple requests back to back: STUN
// over TCP is self-framing via the header's length field (RFC 8489 §6.2.2).
//
// ln may be a TLS listener (tls.NewListener or tls.Listen): STUN over TLS
// (RFC 8489 §6.2.3, `stuns`, port 5349) is byte-for-byte STUN over TCP
// inside the secure stream, so the serve loop is identical and the
// handshake happens under the same idle deadline as the first read.
func ServeTCP(ln net.Listener) error {
	return acceptLoop(ln, serveConn)
}

// serveConn reads framed STUN messages off one connection and answers them.
// Unlike UDP, unparseable input can't be skipped on a stream — after a
// framing error we no longer know where the next message starts — so
// garbage, oversize frames, idle timeouts, and rate-limit hits hang up.
// Well-formed messages that draw no reply (a Binding Indication keepalive,
// an unsupported method — silently discarded per RFC 8489 §6.3) leave the
// connection open: the framing survived, and §6.2.2 has the server keep
// the connection open and let the client close it.
func serveConn(c net.Conn, lim *limiter) {
	defer func() {
		if err := c.Close(); err != nil {
			slog.Warn("close failed", "err", err)
		}
	}()
	m := Metrics["tcp"]
	if _, ok := c.(*tls.Conn); ok {
		m = Metrics["tls"]
	}
	src := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	buf := make([]byte, maxConnMessage)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		if _, err := io.ReadFull(c, buf[:stunmsg.HeaderSize]); err != nil {
			return
		}
		n := stunmsg.HeaderSize + int(binary.BigEndian.Uint16(buf[2:4]))
		if n > maxConnMessage {
			m.Received.Add(1)
			return
		}
		if _, err := io.ReadFull(c, buf[stunmsg.HeaderSize:n]); err != nil {
			return
		}
		m.Received.Add(1)
		if !lim.allow(src.Addr(), time.Now()) {
			m.Limited.Add(1)
			return
		}
		resp, stun := handle(buf[:n], src)
		if !stun {
			return
		}
		if resp == nil {
			continue
		}
		m.countReply(resp)
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}
