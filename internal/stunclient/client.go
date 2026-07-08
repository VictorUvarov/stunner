// Package stunclient implements the client side of the STUN Binding usage
// (RFC 8489 §6.2): ask a server "what's my address from the outside?" and
// return the reflexive transport address it saw. It speaks every transport
// the server does — datagram (UDP, DTLS) with the §6.2.1 retransmission
// schedule, stream (TCP, TLS) with length framing — and runs the long-term
// credential handshake of §9.2, including password-algorithm negotiation,
// when given a username and password.
package stunclient

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/text/secure/precis"

	"stun/internal/stunmsg"
)

// Config tunes a Client. The zero value works: anonymous requests with the
// RFC 8489 §6.2.1 default timing.
type Config struct {
	// Username and Password, when both set, answer 401 challenges with
	// long-term credentials (RFC 8489 §9.2). They are OpaqueString-processed
	// (RFC 8265) at first use, as the spec requires.
	Username, Password string

	// Software is the SOFTWARE attribute stamped on requests; empty sends none.
	Software string

	// Retransmission schedule for datagram transports (RFC 8489 §6.2.1):
	// initial timeout RTO doubling per retransmission, Rc transmissions in
	// total, and a final wait of Rm×RTO. Stream transports use the schedule's
	// total duration as their overall deadline. Zero values mean the RFC
	// defaults: 500ms, 7, 16.
	RTO time.Duration
	Rc  int
	Rm  int
}

func (c Config) withDefaults() Config {
	if c.RTO == 0 {
		c.RTO = 500 * time.Millisecond
	}
	if c.Rc == 0 {
		c.Rc = 7
	}
	if c.Rm == 0 {
		c.Rm = 16
	}
	return c
}

// total is the transaction's worst-case duration: every retransmission wait
// plus the final Rm×RTO listen.
func (c Config) total() time.Duration {
	d, rto := time.Duration(c.Rm)*c.RTO, c.RTO
	for i := 1; i < c.Rc; i++ {
		d += rto
		rto *= 2
	}
	return d
}

// ErrTimeout is returned when a transaction ends with no response
// (RFC 8489 §6.2.1's "the transaction has failed").
var ErrTimeout = errors.New("stunclient: transaction timed out")

// ErrorResponse is a STUN error response that isn't part of a handshake the
// client can continue (so not a 401/438 answered by configured credentials).
type ErrorResponse struct {
	Code   int
	Reason string
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("stunclient: server answered %d %s", e.Code, e.Reason)
}

// Redirect is a 300 Try Alternate (RFC 8489 §10): the server wants this
// client elsewhere. Callers decide whether to follow — over TLS/DTLS the
// Domain must validate the alternate's certificate (§14.16).
type Redirect struct {
	Alternate netip.AddrPort
	Domain    string
}

func (r *Redirect) Error() string {
	return fmt.Sprintf("stunclient: redirected to %v (domain %q)", r.Alternate, r.Domain)
}

// Client runs Binding transactions over one connection. Not safe for
// concurrent use; a transaction owns the connection.
type Client struct {
	conn     net.Conn
	datagram bool
	cfg      Config
	buf      []byte

	// Long-term credential state absorbed from the server's challenge.
	user, realm, nonce []byte
	key                []byte
	algs               []uint16 // server's PASSWORD-ALGORITHMS, echoed verbatim
	chosen             uint16   // algorithm picked from algs
	negotiated         bool     // true → sign with MESSAGE-INTEGRITY-SHA256
}

// NewDatagram wraps an established datagram-framed connection — a connected
// UDP socket or a DTLS association (each Read returns exactly one message) —
// with retransmission per RFC 8489 §6.2.1.
func NewDatagram(conn net.Conn, cfg Config) *Client {
	return &Client{conn: conn, datagram: true, cfg: cfg.withDefaults(), buf: make([]byte, 4096)}
}

// NewStream wraps an established stream connection — TCP, or TLS with the
// handshake left to the first write — using the length framing of §6.2.2.
func NewStream(conn net.Conn, cfg Config) *Client {
	return &Client{conn: conn, cfg: cfg.withDefaults(), buf: make([]byte, 4096)}
}

// DialUDP connects to a STUN server over UDP.
func DialUDP(addr string, cfg Config) (*Client, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return NewDatagram(conn, cfg), nil
}

// DialTCP connects to a STUN server over TCP.
func DialTCP(addr string, cfg Config) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewStream(conn, cfg), nil
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// Binding runs one Binding transaction (plus the credential handshake when
// the server demands one and credentials are configured) and returns the
// reflexive transport address the server saw. Authenticated success
// responses must carry a valid MESSAGE-INTEGRITY(-SHA256) or the call fails.
func (c *Client) Binding() (netip.AddrPort, error) {
	// At most three sends: anonymous, after a 401 challenge, and once more
	// for a stale nonce (438) — the server refreshes the nonce in that reply.
	for attempt := 0; ; attempt++ {
		req, err := c.newRequest()
		if err != nil {
			return netip.AddrPort{}, err
		}
		raw, resp, err := c.roundTrip(req)
		if err != nil {
			return netip.AddrPort{}, err
		}
		resp.TrimAfterIntegrity()

		if resp.Type == stunmsg.BindingSuccess {
			if c.key != nil && !c.verifyResponse(raw) {
				return netip.AddrPort{}, errors.New("stunclient: response failed integrity check")
			}
			return resp.XORMappedAddress()
		}
		code, reason := errorCode(resp)
		switch {
		case (code == 401 || code == 438) && c.cfg.Username != "" && attempt < 2:
			if err := c.absorbChallenge(resp); err != nil {
				return netip.AddrPort{}, err
			}
		case code == 300:
			return netip.AddrPort{}, redirect(resp)
		default:
			return netip.AddrPort{}, &ErrorResponse{code, reason}
		}
	}
}

// newRequest builds the next Binding Request, authenticated once a
// challenge has been absorbed (attribute set per RFC 8489 §9.2.5).
func (c *Client) newRequest() (*stunmsg.Message, error) {
	m := &stunmsg.Message{Type: stunmsg.BindingRequest}
	if _, err := rand.Read(m.TransactionID[:]); err != nil {
		return nil, err
	}
	if c.cfg.Software != "" {
		m.AddSoftware(c.cfg.Software)
	}
	if c.key != nil {
		m.Add(stunmsg.AttrUsername, c.user)
		m.Add(stunmsg.AttrRealm, c.realm)
		m.Add(stunmsg.AttrNonce, c.nonce)
		if c.negotiated {
			m.AddPasswordAlgorithms(c.algs)
			m.AddPasswordAlgorithm(c.chosen)
			m.AddMessageIntegritySHA256(c.key)
		} else {
			m.AddMessageIntegrity(c.key)
		}
	}
	m.AddFingerprint()
	return m, nil
}

// absorbChallenge takes the REALM/NONCE (and PASSWORD-ALGORITHMS, §9.2.5)
// out of a 401/438 and derives the signing key for the retry. The
// negotiation only engages when the nonce cookie carries the "Password
// algorithms" security-feature bit — echoing the list without it would let
// an attacker who stripped the bit downgrade silently.
func (c *Client) absorbChallenge(resp *stunmsg.Message) error {
	realm, hasRealm := resp.Get(stunmsg.AttrRealm)
	nonce, hasNonce := resp.Get(stunmsg.AttrNonce)
	if !hasRealm || !hasNonce {
		return errors.New("stunclient: challenge missing REALM or NONCE")
	}
	user, err := precis.OpaqueString.String(c.cfg.Username)
	if err != nil {
		return fmt.Errorf("stunclient: username: %w", err)
	}
	pass, err := precis.OpaqueString.String(c.cfg.Password)
	if err != nil {
		return fmt.Errorf("stunclient: password: %w", err)
	}
	c.user = []byte(user)
	c.realm = append([]byte(nil), realm...)
	c.nonce = append([]byte(nil), nonce...)

	c.negotiated = false
	if algs, err := resp.PasswordAlgorithms(); err == nil && algs != nil && passwordAlgorithmsBit(nonce) {
		for _, alg := range algs {
			if alg == stunmsg.PasswordAlgorithmSHA256 || alg == stunmsg.PasswordAlgorithmMD5 {
				c.algs, c.chosen, c.negotiated = algs, alg, true
				break
			}
		}
	}
	switch {
	case c.negotiated && c.chosen == stunmsg.PasswordAlgorithmSHA256:
		c.key = stunmsg.LongTermKeySHA256(user, string(c.realm), pass)
	default: // legacy servers and the negotiated-MD5 case share the derivation
		c.key = stunmsg.LongTermKey(user, string(c.realm), pass)
	}
	return nil
}

// verifyResponse checks the response's integrity attribute against the
// request's key. Per §9.2.4 the server signs with MESSAGE-INTEGRITY-SHA256
// exactly when the client negotiated an algorithm.
func (c *Client) verifyResponse(raw []byte) bool {
	if c.negotiated {
		return stunmsg.VerifyMessageIntegritySHA256(raw, c.key)
	}
	return stunmsg.VerifyMessageIntegrity(raw, c.key)
}

// roundTrip sends req and returns the first well-formed response matching
// its transaction ID, dispatching on transport semantics.
func (c *Client) roundTrip(req *stunmsg.Message) ([]byte, *stunmsg.Message, error) {
	raw := req.Marshal()
	if c.datagram {
		return c.roundTripDatagram(raw, req.TransactionID)
	}
	return c.roundTripStream(raw, req.TransactionID)
}

// roundTripDatagram runs the RFC 8489 §6.2.1 schedule: send, wait RTO,
// double and resend, Rc sends in total, then a final Rm×RTO listen.
// Responses that don't parse, don't match the transaction, or fail their
// fingerprint are ignored where UDP would ignore any stray datagram.
func (c *Client) roundTripDatagram(raw []byte, tid [12]byte) ([]byte, *stunmsg.Message, error) {
	rto := c.cfg.RTO
	for i := 0; i < c.cfg.Rc; i++ {
		if _, err := c.conn.Write(raw); err != nil {
			return nil, nil, err
		}
		wait := rto
		if i == c.cfg.Rc-1 {
			wait = time.Duration(c.cfg.Rm) * c.cfg.RTO
		}
		deadline := time.Now().Add(wait)
		for {
			c.conn.SetReadDeadline(deadline)
			n, err := c.conn.Read(c.buf)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break // retransmit
				}
				return nil, nil, err
			}
			if respRaw, resp := c.match(c.buf[:n], tid); resp != nil {
				return respRaw, resp, nil
			}
		}
		rto *= 2
	}
	return nil, nil, ErrTimeout
}

// roundTripStream writes once (the transport is reliable) and reads
// length-framed messages until the transaction's response arrives, bounded
// by the schedule's total duration as an overall deadline.
func (c *Client) roundTripStream(raw []byte, tid [12]byte) ([]byte, *stunmsg.Message, error) {
	deadline := time.Now().Add(c.cfg.total())
	c.conn.SetDeadline(deadline)
	defer c.conn.SetDeadline(time.Time{})
	if _, err := c.conn.Write(raw); err != nil {
		return nil, nil, err
	}
	for {
		if _, err := io.ReadFull(c.conn, c.buf[:stunmsg.HeaderSize]); err != nil {
			return nil, nil, timeoutOr(err)
		}
		n := stunmsg.HeaderSize + int(uint16(c.buf[2])<<8|uint16(c.buf[3]))
		if n > len(c.buf) {
			return nil, nil, fmt.Errorf("stunclient: oversized frame (%d bytes)", n)
		}
		if _, err := io.ReadFull(c.conn, c.buf[stunmsg.HeaderSize:n]); err != nil {
			return nil, nil, timeoutOr(err)
		}
		if respRaw, resp := c.match(c.buf[:n], tid); resp != nil {
			return respRaw, resp, nil
		}
	}
}

// match parses pkt and returns it (raw copied out of the read buffer) when
// it is this transaction's response with an intact fingerprint.
func (c *Client) match(pkt []byte, tid [12]byte) ([]byte, *stunmsg.Message) {
	resp, err := stunmsg.Parse(pkt)
	if err != nil || resp.TransactionID != tid || !stunmsg.VerifyFingerprint(pkt) {
		return nil, nil
	}
	if resp.Type != stunmsg.BindingSuccess && resp.Type != stunmsg.BindingError {
		return nil, nil
	}
	return append([]byte(nil), pkt...), resp
}

// errorCode extracts an ERROR-CODE attribute (RFC 8489 §14.8).
func errorCode(resp *stunmsg.Message) (int, string) {
	v, ok := resp.Get(stunmsg.AttrErrorCode)
	if !ok || len(v) < 4 {
		return 0, ""
	}
	return int(v[2])*100 + int(v[3]), string(v[4:])
}

// redirect builds the Redirect error for a 300 response, preferring the
// mandatory same-family ALTERNATE-SERVER (the first one, §10).
func redirect(resp *stunmsg.Message) error {
	ap, err := resp.Address(stunmsg.AttrAlternateServer)
	if err != nil {
		return &ErrorResponse{300, "Try Alternate (no usable ALTERNATE-SERVER)"}
	}
	domain, _ := resp.Get(stunmsg.AttrAlternateDomain)
	return &Redirect{Alternate: ap, Domain: string(domain)}
}

// passwordAlgorithmsBit reports whether nonce starts with the RFC 8489 §9.2
// nonce cookie with the "Password algorithms" security-feature bit set —
// the rightmost bit of the 24-bit set, per verified erratum 6290.
func passwordAlgorithmsBit(nonce []byte) bool {
	if len(nonce) < 13 || string(nonce[:9]) != "obMatJos2" {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(string(nonce[9:13]))
	return err == nil && len(b) == 3 && b[2]&1 != 0
}

// timeoutOr maps deadline errors to ErrTimeout and passes the rest through.
func timeoutOr(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrTimeout
	}
	return err
}
