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
	BindingRequest = 0x0001
	BindingSuccess = 0x0101
	BindingError   = 0x0111
)

// Attribute types (comprehension-required < 0x8000, optional >= 0x8000).
const (
	AttrUsername               = 0x0006
	AttrMessageIntegrity       = 0x0008
	AttrErrorCode              = 0x0009
	AttrUnknownAttributes      = 0x000A
	AttrMessageIntegritySHA256 = 0x001C
	AttrXORMappedAddress       = 0x0020
	AttrSoftware               = 0x8022
	AttrFingerprint            = 0x8028
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
}

// Parse decodes a single STUN message from buf. It returns ErrNotSTUN if the
// buffer can't be STUN at all (wrong first bits or magic cookie), and
// ErrMalformed if the header or attribute framing is inconsistent.
func Parse(buf []byte) (*Message, error) {
	if len(buf) < HeaderSize || buf[0]&0xC0 != 0 ||
		binary.BigEndian.Uint32(buf[4:8]) != magicCookie {
		return nil, ErrNotSTUN
	}
	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length%4 != 0 || HeaderSize+length != len(buf) {
		return nil, ErrMalformed
	}
	m := &Message{Type: binary.BigEndian.Uint16(buf[0:2])}
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
	buf := make([]byte, HeaderSize, HeaderSize+length)
	binary.BigEndian.PutUint16(buf[0:2], m.Type)
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	binary.BigEndian.PutUint32(buf[4:8], magicCookie)
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
func (m *Message) AddErrorCode(code int, reason string) {
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
// given types; it accompanies a 420 error response.
func (m *Message) AddUnknownAttributes(types []uint16) {
	v := make([]byte, 2*len(types))
	for i, t := range types {
		binary.BigEndian.PutUint16(v[2*i:], t)
	}
	m.Add(AttrUnknownAttributes, v)
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
	case BindingSuccess:
		name = "BindingSuccess"
	case BindingError:
		name = "BindingError"
	}
	return fmt.Sprintf("%s[attrs=%d]", name, len(m.Attrs))
}
