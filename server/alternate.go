package server

import (
	"net/netip"

	"stun/stunmsg"
)

// AlternateServer configures the ALTERNATE-SERVER mechanism (RFC 8489 §10):
// a server that wants clients to go elsewhere — draining for maintenance,
// splitting load — answers Binding Requests with a 300 (Try Alternate)
// error naming the server to use instead.
type AlternateServer struct {
	// V4 and V6 are the redirect targets by address family. §10 requires
	// the ALTERNATE-SERVER address to be of the same family as the request
	// source; requests from a family with no target are served here.
	V4, V6 netip.AddrPort

	// Domain, when set, is sent as ALTERNATE-DOMAIN (§14.16): the name
	// TLS/DTLS clients must validate the target's certificate against.
	// §10 makes it mandatory when redirecting an authenticated TLS/DTLS
	// client to a server with a different certificate.
	Domain string
}

// Alternate, when non-nil, redirects every Binding Request via a 300
// instead of serving it. Like Credentials, set it before calling any Serve
// function. The NAT discovery usage never redirects: its value is the
// specific four-socket topology of *this* server, so sending those clients
// elsewhere is never what the operator means.
var Alternate *AlternateServer

// redirect builds the 300 response for req, or nil when no redirect applies
// to src's address family. It runs after authentication, so when auth is
// enabled the 300 carries MESSAGE-INTEGRITY like any other response and an
// off-path attacker can't forge a redirect to a server they control.
func redirect(req *stunmsg.Message, src netip.AddrPort) *stunmsg.Message {
	alt := Alternate
	if alt == nil {
		return nil
	}
	target := alt.V4
	if src.Addr().Unmap().Is6() {
		target = alt.V6
	}
	if !target.IsValid() {
		return nil
	}
	resp := &stunmsg.Message{Type: stunmsg.BindingError, TransactionID: req.TransactionID}
	resp.AddErrorCode(300, "Try Alternate")
	resp.AddAddress(stunmsg.AttrAlternateServer, target)
	if alt.Domain != "" {
		resp.Add(stunmsg.AttrAlternateDomain, []byte(alt.Domain))
	}
	return resp
}
