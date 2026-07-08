package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"stun/stunmsg"
)

// maxTCPMessage caps a single message read off a stream.
// ponytail: 4 KiB fits any Binding request many times over.
const maxTCPMessage = 4096

// tcpIdleTimeout is how long a connection may sit between requests.
const tcpIdleTimeout = 40 * time.Second

// ServeTCP answers Binding Requests on ln until it is closed (which, like
// Serve, returns nil — that's the shutdown path). Each connection is handled
// on its own goroutine and may carry multiple requests back to back: STUN
// over TCP is self-framing via the header's length field (RFC 8489 §6.2.2).
func ServeTCP(ln net.Listener) error {
	var lim *limiter
	if RPS > 0 {
		lim = newLimiter(RPS, Burst)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go serveConn(c, lim)
	}
}

// serveConn reads framed STUN messages off one connection and answers them.
// Unlike UDP, invalid input can't be skipped on a stream — after a framing
// error we no longer know where the next message starts — so any bad
// message, oversize frame, idle timeout, or rate-limit hit hangs up.
func serveConn(c net.Conn, lim *limiter) {
	defer c.Close()
	src := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	buf := make([]byte, maxTCPMessage)
	for {
		c.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		if _, err := io.ReadFull(c, buf[:stunmsg.HeaderSize]); err != nil {
			return
		}
		n := stunmsg.HeaderSize + int(binary.BigEndian.Uint16(buf[2:4]))
		if n > maxTCPMessage {
			return
		}
		if _, err := io.ReadFull(c, buf[stunmsg.HeaderSize:n]); err != nil {
			return
		}
		if !lim.allow(src.Addr(), time.Now()) {
			return
		}
		resp := handle(buf[:n], src)
		if resp == nil {
			return
		}
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}
