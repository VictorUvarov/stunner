// Package server implements the STUN Binding service over UDP (RFC 8489).
package server

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"stun/stunmsg"
)

// Software is the SOFTWARE attribute value stamped on every response.
var Software = "stund"

// ignorable lists comprehension-required attributes we understand and never
// count as unknown: the auth attributes (acted on when Credentials is set,
// harmless otherwise). Any other comprehension-required attribute triggers
// a 420 per RFC 8489 §6.3.1.
var ignorable = map[uint16]bool{
	stunmsg.AttrUsername:               true,
	stunmsg.AttrMessageIntegrity:       true,
	stunmsg.AttrMessageIntegritySHA256: true,
	stunmsg.AttrRealm:                  true,
	stunmsg.AttrNonce:                  true,
	stunmsg.AttrPasswordAlgorithm:      true,
	stunmsg.AttrUserhash:               true,
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
// Authentication (when enabled) runs before the unknown-attribute check,
// as RFC 8489 §6.3.1 orders it.
func handle(pkt []byte, src netip.AddrPort) []byte {
	req, ok := validate(pkt, ignorable)
	if !ok {
		return nil
	}
	key, sha2, errResp := authenticate(pkt, req)
	if errResp != nil {
		return seal(errResp, nil, false)
	}
	if resp := redirect(req, src); resp != nil {
		return seal(resp, key, sha2)
	}
	return seal(respond(req, src, ignorable), key, sha2)
}

// validate parses pkt and reports whether it is a Binding Request with an
// intact fingerprint — everything else means "stay silent".
func validate(pkt []byte, ignore map[uint16]bool) (*stunmsg.Message, bool) {
	req, err := stunmsg.Parse(pkt)
	if err != nil || req.Type != stunmsg.BindingRequest {
		return nil, false
	}
	return req, stunmsg.VerifyFingerprint(pkt)
}

// respond builds the response skeleton for a validated request: a success
// carrying XOR-MAPPED-ADDRESS, or a 420 error if req has comprehension-
// required attributes outside ignore. Callers may append usage-specific
// attributes to a success before sealing it.
func respond(req *stunmsg.Message, src netip.AddrPort, ignore map[uint16]bool) *stunmsg.Message {
	resp := &stunmsg.Message{TransactionID: req.TransactionID}
	if unknown := unknownRequired(req, ignore); len(unknown) > 0 {
		slog.Debug("unknown attributes", "src", src, "attrs", unknown)
		resp.Type = stunmsg.BindingError
		resp.AddErrorCode(420, "Unknown Attribute")
		resp.AddUnknownAttributes(unknown)
	} else {
		slog.Debug("binding", "src", src)
		resp.Type = stunmsg.BindingSuccess
		resp.AddXORMappedAddress(src)
	}
	return resp
}

// seal appends the trailing attributes every response carries and marshals:
// SOFTWARE, then — for authenticated exchanges — the integrity HMAC keyed
// with key (MESSAGE-INTEGRITY-SHA256 when the client negotiated a password
// algorithm, legacy MESSAGE-INTEGRITY otherwise, per RFC 8489 §9.2.4),
// then FINGERPRINT, which must be last.
func seal(resp *stunmsg.Message, key []byte, sha2 bool) []byte {
	resp.AddSoftware(Software)
	if key != nil {
		if sha2 {
			resp.AddMessageIntegritySHA256(key)
		} else {
			resp.AddMessageIntegrity(key)
		}
	}
	resp.AddFingerprint()
	return resp.Marshal()
}

// unknownRequired returns the comprehension-required attribute types in m
// outside the ignore set.
func unknownRequired(m *stunmsg.Message, ignore map[uint16]bool) []uint16 {
	var out []uint16
	for _, a := range m.Attrs {
		if stunmsg.Required(a.Type) && !ignore[a.Type] {
			out = append(out, a.Type)
		}
	}
	return out
}
