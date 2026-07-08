// Package server implements the STUN Binding service over UDP (RFC 8489).
package server

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"stun/stunmsg"
)

// Software is the SOFTWARE attribute value stamped on every response.
var Software = "stund"

// ignorable lists comprehension-required attributes we accept but don't act
// on (auth is not implemented; a Binding response needs none of them). Any
// other comprehension-required attribute triggers a 420 per RFC 8489 §6.3.1.
var ignorable = map[uint16]bool{
	0x0006: true, // USERNAME
	0x0008: true, // MESSAGE-INTEGRITY
	0x001C: true, // MESSAGE-INTEGRITY-SHA256
}

// Serve answers Binding Requests on conn until it is closed, replying to
// each with the source address the request arrived from. A closed conn
// returns nil, so shutdown is: close the conn. Sources over their rate
// budget (see RPS/Burst) are dropped without a reply — answering them
// would spend the bandwidth the limit is there to protect.
func Serve(conn *net.UDPConn) error {
	var lim *limiter
	if RPS > 0 {
		lim = newLimiter(RPS, Burst)
	}
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
		if resp := handle(buf[:n], src); resp != nil {
			if _, err := conn.WriteToUDPAddrPort(resp, src); err != nil {
				slog.Warn("write failed", "dst", src, "err", err)
			}
		}
	}
}

// handle turns one datagram into a response, or nil to stay silent.
// Non-STUN traffic, malformed messages, bad fingerprints, and non-Binding
// message types are all dropped without a reply, per RFC 8489 §6.3.
func handle(pkt []byte, src netip.AddrPort) []byte {
	req, err := stunmsg.Parse(pkt)
	if err != nil || req.Type != stunmsg.BindingRequest {
		return nil
	}
	if !stunmsg.VerifyFingerprint(pkt) {
		return nil
	}

	resp := &stunmsg.Message{TransactionID: req.TransactionID}
	if unknown := unknownRequired(req); len(unknown) > 0 {
		slog.Debug("unknown attributes", "src", src, "attrs", unknown)
		resp.Type = stunmsg.BindingError
		resp.AddErrorCode(420, "Unknown Attribute")
		v := make([]byte, 2*len(unknown))
		for i, t := range unknown {
			binary.BigEndian.PutUint16(v[2*i:], t)
		}
		resp.Add(stunmsg.AttrUnknownAttributes, v)
	} else {
		slog.Debug("binding", "src", src)
		resp.Type = stunmsg.BindingSuccess
		resp.AddXORMappedAddress(src)
	}
	resp.AddSoftware(Software)
	resp.AddFingerprint()
	return resp.Marshal()
}

// unknownRequired returns the comprehension-required attribute types in m
// that this server doesn't understand.
func unknownRequired(m *stunmsg.Message) []uint16 {
	var out []uint16
	for _, a := range m.Attrs {
		if a.Type < 0x8000 && !ignorable[a.Type] {
			out = append(out, a.Type)
		}
	}
	return out
}
