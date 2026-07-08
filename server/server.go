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
		if resp, _ := handle(buf[:n], src); resp != nil {
			if _, err := conn.WriteToUDPAddrPort(resp, src); err != nil {
				slog.Warn("write failed", "dst", src, "err", err)
			}
		}
	}
}

// handle turns one message into a response, or nil to stay silent.
// Non-STUN traffic, malformed messages, bad fingerprints, and non-Binding
// message types are all dropped without a reply, per RFC 8489 §6.3.
// Authentication (when enabled) runs before the unknown-attribute check,
// as RFC 8489 §6.3 orders it. The boolean tells the two silences apart
// for stream transports: false means pkt wasn't STUN at all, true means a
// well-formed message that simply warrants no reply (an indication, an
// unsupported method, a bad fingerprint).
func handle(pkt []byte, src netip.AddrPort) ([]byte, bool) {
	req, stun := validate(pkt)
	if req == nil {
		return nil, stun
	}
	key, sha2, errResp := authenticate(pkt, req)
	if errResp != nil {
		return seal(errResp, nil, false), true
	}
	if resp := redirect(req, src); resp != nil {
		return seal(resp, key, sha2), true
	}
	return seal(respond(req, src, ignorable), key, sha2), true
}

// validate parses pkt and returns it if it is a Binding Request with an
// intact fingerprint — everything else means "stay silent". The boolean
// reports the weaker fact of whether pkt parsed as STUN at all. Attributes
// after MESSAGE-INTEGRITY(-SHA256) are dropped here, before anything can
// act on them (RFC 8489 §9): they sit outside the HMAC's coverage, so an
// attacker could have appended them to a signed request.
func validate(pkt []byte) (*stunmsg.Message, bool) {
	req, err := stunmsg.Parse(pkt)
	if err != nil {
		return nil, false
	}
	if req.Type != stunmsg.BindingRequest || !stunmsg.VerifyFingerprint(pkt) {
		return nil, true
	}
	req.TrimAfterIntegrity()
	return req, true
}

// respond builds the response skeleton for a validated request: a success
// carrying XOR-MAPPED-ADDRESS, or a 420 error if req has comprehension-
// required attributes outside ignore. Callers may append usage-specific
// attributes to a success before sealing it. Classic requests get
// MAPPED-ADDRESS instead — XOR-MAPPED-ADDRESS postdates RFC 3489, and a
// classic client discards responses with mandatory attributes it doesn't
// know — and echo the request's cookie bits, which the classic client
// matches as part of its 128-bit transaction ID (RFC 5389 §12.2).
func respond(req *stunmsg.Message, src netip.AddrPort, ignore map[uint16]bool) *stunmsg.Message {
	resp := &stunmsg.Message{TransactionID: req.TransactionID, Cookie: req.Cookie}
	if unknown := unknownRequired(req, ignore); len(unknown) > 0 {
		slog.Debug("unknown attributes", "src", src, "attrs", unknown)
		resp.Type = stunmsg.BindingError
		resp.AddErrorCode(420, "Unknown Attribute")
		resp.AddUnknownAttributes(unknown)
	} else {
		slog.Debug("binding", "src", src, "classic", req.Classic())
		resp.Type = stunmsg.BindingSuccess
		if req.Classic() {
			resp.AddAddress(stunmsg.AttrMappedAddress, src)
		} else {
			resp.AddXORMappedAddress(src)
		}
	}
	return resp
}

// seal appends the trailing attributes every response carries and marshals:
// SOFTWARE, then — for authenticated exchanges — the integrity HMAC keyed
// with key (MESSAGE-INTEGRITY-SHA256 when the client negotiated a password
// algorithm, legacy MESSAGE-INTEGRITY otherwise, per RFC 8489 §9.2.4),
// then FINGERPRINT, which must be last. Classic responses stay bare:
// RFC 3489 parsers know no attribute padding, so SOFTWARE's odd length
// would desync them, and the FINGERPRINT mechanism explicitly isn't
// backwards compatible (RFC 8489 §7).
func seal(resp *stunmsg.Message, key []byte, sha2 bool) []byte {
	if resp.Classic() {
		return resp.Marshal()
	}
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
