// Package stunmsg encodes and decodes STUN messages (RFC 8489).
package stunmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
)

// Message types used by a Binding server.
const (
	BindingRequest    = 0x0001
	BindingIndication = 0x0011
	BindingSuccess    = 0x0101
	BindingError      = 0x0111
)

// Attribute types (comprehension-required < 0x8000, optional >= 0x8000).
// CHANGE-REQUEST, PADDING, RESPONSE-PORT, RESPONSE-ORIGIN, and OTHER-ADDRESS
// are from RFC 5780 (NAT behavior discovery); the rest are RFC 8489.
const (
	AttrMappedAddress          = 0x0001
	AttrChangeRequest          = 0x0003
	AttrSourceAddress          = 0x0004 // RFC 3489 only; RFC 5780 renamed it RESPONSE-ORIGIN
	AttrChangedAddress         = 0x0005 // RFC 3489 only; RFC 5780 renamed it OTHER-ADDRESS
	AttrUsername               = 0x0006
	AttrMessageIntegrity       = 0x0008
	AttrErrorCode              = 0x0009
	AttrUnknownAttributes      = 0x000A
	AttrRealm                  = 0x0014
	AttrNonce                  = 0x0015
	AttrMessageIntegritySHA256 = 0x001C
	AttrPasswordAlgorithm      = 0x001D
	AttrUserhash               = 0x001E
	AttrXORMappedAddress       = 0x0020
	AttrPadding                = 0x0026
	AttrResponsePort           = 0x0027
	AttrPasswordAlgorithms     = 0x8002
	AttrAlternateDomain        = 0x8003
	AttrSoftware               = 0x8022
	AttrAlternateServer        = 0x8023
	AttrFingerprint            = 0x8028
	AttrResponseOrigin         = 0x802B
	AttrOtherAddress           = 0x802C
)

// Password algorithm numbers (RFC 8489 §18.5), carried in the
// PASSWORD-ALGORITHM(S) attributes.
const (
	PasswordAlgorithmMD5    = 0x0001
	PasswordAlgorithmSHA256 = 0x0002
)

// CHANGE-REQUEST flag bits (RFC 5780 §7.2), in the last byte of the value.
const (
	ChangeIP   = 0x04
	ChangePort = 0x02
)

// Required reports whether attribute type t is comprehension-required: a
// receiver that doesn't understand it must reject the message (RFC 8489 §14).
func Required(t uint16) bool { return t < 0x8000 }

// HeaderSize is the fixed STUN header length in bytes.
const HeaderSize = 20

const (
	magicCookie    = 0x2112A442
	fingerprintXOR = 0x5354554e // "STUN", per RFC 8489 §14.7
)

var (
	ErrNotSTUN   = errors.New("stunmsg: not a STUN message")
	ErrMalformed = errors.New("stunmsg: malformed message")
)

// Attr is a single attribute as raw type-value; padding is handled by the codec.
type Attr struct {
	Type  uint16
	Value []byte
}

// Message is a parsed or under-construction STUN message.
type Message struct {
	Type          uint16
	TransactionID [12]byte
	Attrs         []Attr

	// Cookie is the wire value of the magic-cookie field. Parse always
	// sets it; the zero value means "RFC 8489" and marshals as the magic
	// cookie, so hand-built messages need not touch it. Classic (RFC 3489)
	// clients predate the cookie and treat these four bytes as the top of
	// their 128-bit transaction ID, so responses to them must echo the
	// request's value verbatim. (A classic client whose random ID has 32
	// zero bits exactly here is indistinguishable from the zero value and
	// gets a modern response; at 2^-32 per transaction we accept that.)
	Cookie uint32
}

// Classic reports whether the message came from an RFC 3489 ("classic
// STUN") sender, detected by the absence of the magic cookie
// (RFC 5389 §12.2).
func (m *Message) Classic() bool {
	return m.Cookie != 0 && m.Cookie != magicCookie
}

// IsRequest reports whether message type t has the request class
// (RFC 8489 §5: class bits 0b00).
func IsRequest(t uint16) bool { return t&0x0110 == 0 }

// Parse decodes a single STUN message from buf. It returns ErrNotSTUN if the
// buffer can't be STUN at all (too short or wrong first bits), and
// ErrMalformed if the header or attribute framing is inconsistent.
// A message without the magic cookie parses as classic STUN (see Cookie),
// which is what RFC 8489 §11 compatibility needs — but it means the cookie
// no longer helps reject non-STUN input, so Parse MUST NOT be used to
// demultiplex STUN from other protocols sharing a port (RFC 5389 §12.2
// forbids that combination outright).
func Parse(buf []byte) (*Message, error) {
	if len(buf) < HeaderSize || buf[0]&0xC0 != 0 {
		return nil, ErrNotSTUN
	}
	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length%4 != 0 || HeaderSize+length != len(buf) {
		return nil, ErrMalformed
	}
	m := &Message{
		Type:   binary.BigEndian.Uint16(buf[0:2]),
		Cookie: binary.BigEndian.Uint32(buf[4:8]),
	}
	copy(m.TransactionID[:], buf[8:HeaderSize])

	for rest := buf[HeaderSize:]; len(rest) > 0; {
		if len(rest) < 4 {
			return nil, ErrMalformed
		}
		t := binary.BigEndian.Uint16(rest[0:2])
		n := int(binary.BigEndian.Uint16(rest[2:4]))
		padded := 4 + (n+3)/4*4
		if padded > len(rest) {
			return nil, ErrMalformed
		}
		m.Attrs = append(m.Attrs, Attr{t, rest[4 : 4+n]})
		rest = rest[padded:]
	}
	return m, nil
}

// Marshal serializes the message, computing the header length field.
func (m *Message) Marshal() []byte { return m.marshal(0) }

// marshal serializes with extraLen added to the header length field, which
// AddFingerprint needs: the CRC is computed with the length already counting
// the not-yet-appended FINGERPRINT attribute (RFC 8489 §14.7).
func (m *Message) marshal(extraLen int) []byte {
	length := extraLen
	for _, a := range m.Attrs {
		length += 4 + (len(a.Value)+3)/4*4
	}
	cookie := m.Cookie
	if cookie == 0 {
		cookie = magicCookie
	}
	buf := make([]byte, HeaderSize, HeaderSize+length)
	binary.BigEndian.PutUint16(buf[0:2], m.Type)
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	binary.BigEndian.PutUint32(buf[4:8], cookie)
	copy(buf[8:], m.TransactionID[:])
	var pad [3]byte
	for _, a := range m.Attrs {
		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], a.Type)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(a.Value)))
		buf = append(buf, hdr[:]...)
		buf = append(buf, a.Value...)
		buf = append(buf, pad[:(4-len(a.Value)%4)%4]...)
	}
	return buf
}

// Add appends a raw attribute.
func (m *Message) Add(t uint16, v []byte) {
	m.Attrs = append(m.Attrs, Attr{t, v})
}

// Get returns the value of the first attribute of type t.
func (m *Message) Get(t uint16) ([]byte, bool) {
	for _, a := range m.Attrs {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// TrimAfterIntegrity drops the attributes a receiving agent must ignore
// (RFC 8489 §9): everything after MESSAGE-INTEGRITY except
// MESSAGE-INTEGRITY-SHA256 and FINGERPRINT, or — when MESSAGE-INTEGRITY is
// absent — everything after MESSAGE-INTEGRITY-SHA256 except FINGERPRINT.
// The HMACs cover only what precedes them, so anything else back there
// could have been appended without invalidating the signature; a receiver
// that acted on it would be acting on unauthenticated input.
func (m *Message) TrimAfterIntegrity() {
	for i, a := range m.Attrs {
		if a.Type != AttrMessageIntegrity && a.Type != AttrMessageIntegritySHA256 {
			continue
		}
		kept := m.Attrs[:i+1]
		for _, b := range m.Attrs[i+1:] {
			if b.Type == AttrFingerprint ||
				(a.Type == AttrMessageIntegrity && b.Type == AttrMessageIntegritySHA256) {
				kept = append(kept, b)
			}
		}
		m.Attrs = kept
		return
	}
}

// AddAddress appends ap as an attribute of type t in the plain (non-XOR)
// MAPPED-ADDRESS format shared by MAPPED-ADDRESS, RESPONSE-ORIGIN, and
// OTHER-ADDRESS.
func (m *Message) AddAddress(t uint16, ap netip.AddrPort) {
	ip := ap.Addr().Unmap()
	family := byte(1)
	if ip.Is6() {
		family = 2
	}
	b := ip.AsSlice()
	v := make([]byte, 4+len(b))
	v[1] = family
	binary.BigEndian.PutUint16(v[2:4], ap.Port())
	copy(v[4:], b)
	m.Add(t, v)
}

// Address decodes the first attribute of type t as a plain (non-XOR)
// MAPPED-ADDRESS-format transport address.
func (m *Message) Address(t uint16) (netip.AddrPort, error) {
	v, ok := m.Get(t)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("stunmsg: no attribute 0x%04x", t)
	}
	if len(v) != 8 && len(v) != 20 {
		return netip.AddrPort{}, ErrMalformed
	}
	ip, ok := netip.AddrFromSlice(v[4:])
	if !ok {
		return netip.AddrPort{}, ErrMalformed
	}
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(v[2:4])), nil
}

// AddXORMappedAddress appends ap as an XOR-MAPPED-ADDRESS attribute,
// XORing port and IP with the magic cookie (and transaction ID for IPv6).
func (m *Message) AddXORMappedAddress(ap netip.AddrPort) {
	ip := ap.Addr().Unmap() // 4-byte encoding for IPv4-mapped addresses
	family := byte(1)
	if ip.Is6() {
		family = 2
	}
	b := ip.AsSlice()
	v := make([]byte, 4+len(b))
	v[1] = family
	binary.BigEndian.PutUint16(v[2:4], ap.Port()^uint16(magicCookie>>16))
	copy(v[4:], b)
	key := m.xorKey()
	for i, k := range key[:len(b)] {
		v[4+i] ^= k
	}
	m.Add(AttrXORMappedAddress, v)
}

// XORMappedAddress decodes the message's XOR-MAPPED-ADDRESS attribute.
func (m *Message) XORMappedAddress() (netip.AddrPort, error) {
	v, ok := m.Get(AttrXORMappedAddress)
	if !ok {
		return netip.AddrPort{}, errors.New("stunmsg: no XOR-MAPPED-ADDRESS")
	}
	if len(v) != 8 && len(v) != 20 {
		return netip.AddrPort{}, ErrMalformed
	}
	port := binary.BigEndian.Uint16(v[2:4]) ^ uint16(magicCookie>>16)
	b := append([]byte(nil), v[4:]...)
	key := m.xorKey()
	for i, k := range key[:len(b)] {
		b[i] ^= k
	}
	ip, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.AddrPort{}, ErrMalformed
	}
	return netip.AddrPortFrom(ip, port), nil
}

// xorKey is the 16-byte XOR mask for addresses: magic cookie ‖ transaction ID.
func (m *Message) xorKey() [16]byte {
	var k [16]byte
	binary.BigEndian.PutUint32(k[:4], magicCookie)
	copy(k[4:], m.TransactionID[:])
	return k
}

// AddErrorCode appends an ERROR-CODE attribute (e.g. 420, "Unknown Attribute").
// On classic messages the reason is space-padded to a 4-byte multiple:
// RFC 3489 has no attribute padding, so the value itself must keep the
// alignment (§11.2.9), and set Cookie before calling this.
func (m *Message) AddErrorCode(code int, reason string) {
	if m.Classic() {
		reason += "    "[:(4-len(reason)%4)%4]
	}
	v := make([]byte, 4+len(reason))
	v[2] = byte(code / 100)
	v[3] = byte(code % 100)
	copy(v[4:], reason)
	m.Add(AttrErrorCode, v)
}

// AddSoftware appends a SOFTWARE attribute identifying this server.
func (m *Message) AddSoftware(name string) {
	m.Add(AttrSoftware, []byte(name))
}

// AddUnknownAttributes appends an UNKNOWN-ATTRIBUTES attribute listing the
// given types; it accompanies a 420 error response. On classic messages an
// odd list gets one type repeated: RFC 3489 §11.2.10 demands an even count
// to keep its padding-free framing aligned, so set Cookie before calling.
func (m *Message) AddUnknownAttributes(types []uint16) {
	if m.Classic() && len(types)%2 == 1 {
		types = append(types[:len(types):len(types)], types[0])
	}
	v := make([]byte, 2*len(types))
	for i, t := range types {
		binary.BigEndian.PutUint16(v[2*i:], t)
	}
	m.Add(AttrUnknownAttributes, v)
}

// AddPasswordAlgorithms appends a PASSWORD-ALGORITHMS attribute listing the
// given algorithm numbers in preference order (RFC 8489 §14.11), each with
// empty parameters (neither registered algorithm defines any).
func (m *Message) AddPasswordAlgorithms(algs []uint16) {
	v := make([]byte, 4*len(algs))
	for i, a := range algs {
		binary.BigEndian.PutUint16(v[4*i:], a) // parameter length stays zero
	}
	m.Add(AttrPasswordAlgorithms, v)
}

// PasswordAlgorithms decodes the PASSWORD-ALGORITHMS attribute into its
// algorithm numbers, skipping the per-algorithm parameters. A missing
// attribute yields (nil, nil); a malformed one, ErrMalformed.
func (m *Message) PasswordAlgorithms() ([]uint16, error) {
	v, ok := m.Get(AttrPasswordAlgorithms)
	if !ok {
		return nil, nil
	}
	var out []uint16
	for off := 0; off < len(v); {
		if off+4 > len(v) {
			return nil, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(v[off+2 : off+4]))
		out = append(out, binary.BigEndian.Uint16(v[off:off+2]))
		if off += 4 + (n+3)/4*4; off > len(v) {
			return nil, ErrMalformed
		}
	}
	return out, nil
}

// AddPasswordAlgorithm appends a PASSWORD-ALGORITHM attribute (RFC 8489
// §14.12) selecting alg, with empty parameters.
func (m *Message) AddPasswordAlgorithm(alg uint16) {
	v := make([]byte, 4)
	binary.BigEndian.PutUint16(v, alg)
	m.Add(AttrPasswordAlgorithm, v)
}

// PasswordAlgorithm decodes the PASSWORD-ALGORITHM attribute's algorithm
// number.
func (m *Message) PasswordAlgorithm() (uint16, bool) {
	v, ok := m.Get(AttrPasswordAlgorithm)
	if !ok || len(v) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(v[:2]), true
}

// AddFingerprint appends a FINGERPRINT attribute; it must be added last.
func (m *Message) AddFingerprint() {
	crc := crc32.ChecksumIEEE(m.marshal(8)) ^ fingerprintXOR
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, crc)
	m.Add(AttrFingerprint, v)
}

// VerifyFingerprint checks a raw message's FINGERPRINT attribute against its
// content. It returns true when the message has no fingerprint (nothing to
// verify) or the CRC matches, false on mismatch.
func VerifyFingerprint(buf []byte) bool {
	if len(buf) < HeaderSize {
		return false
	}
	for off := HeaderSize; off+4 <= len(buf); {
		t := binary.BigEndian.Uint16(buf[off : off+2])
		n := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		if t == AttrFingerprint {
			if n != 4 || off+8 > len(buf) {
				return false
			}
			got := binary.BigEndian.Uint32(buf[off+4 : off+8])
			return got == crc32.ChecksumIEEE(buf[:off])^fingerprintXOR
		}
		off += 4 + (n+3)/4*4
	}
	return true
}

// String renders the message compactly for logs, e.g. "BindingRequest[attrs=3]".
func (m *Message) String() string {
	name := fmt.Sprintf("0x%04x", m.Type)
	switch m.Type {
	case BindingRequest:
		name = "BindingRequest"
	case BindingIndication:
		name = "BindingIndication"
	case BindingSuccess:
		name = "BindingSuccess"
	case BindingError:
		name = "BindingError"
	}
	return fmt.Sprintf("%s[attrs=%d]", name, len(m.Attrs))
}
