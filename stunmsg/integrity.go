package stunmsg

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// LongTermKey derives the long-term credential key of RFC 8489 §9.2.2:
// MD5(username ":" realm ":" password). MD5 here is the spec-mandated
// derivation for wire compatibility, not a security choice of ours.
// All inputs must already be OpaqueString-processed (RFC 8265) where the
// spec requires it — the codec does no string preparation.
func LongTermKey(username, realm, password string) []byte {
	h := md5.Sum([]byte(username + ":" + realm + ":" + password))
	return h[:]
}

// LongTermKeySHA256 derives the 32-byte key of the SHA-256 password
// algorithm (RFC 8489 §18.5.1.2), selected via PASSWORD-ALGORITHM:
// SHA-256(username ":" realm ":" password). Inputs as with LongTermKey.
func LongTermKeySHA256(username, realm, password string) []byte {
	h := sha256.Sum256([]byte(username + ":" + realm + ":" + password))
	return h[:]
}

// Userhash computes the USERHASH attribute value of RFC 8489 §14.4,
// which replaces USERNAME when username anonymity is in use:
// SHA-256(username ":" realm). Inputs as with LongTermKey.
func Userhash(username, realm string) []byte {
	h := sha256.Sum256([]byte(username + ":" + realm))
	return h[:]
}

// AddMessageIntegrity appends a MESSAGE-INTEGRITY attribute: an HMAC-SHA1
// over the message so far, keyed with key (see LongTermKey). FINGERPRINT,
// if used, must still come after.
func (m *Message) AddMessageIntegrity(key []byte) {
	m.addIntegrity(AttrMessageIntegrity, sha1.New, key)
}

// AddMessageIntegritySHA256 is AddMessageIntegrity with the HMAC-SHA256
// variant of RFC 8489 §14.6 (full 32-byte output, no truncation).
func (m *Message) AddMessageIntegritySHA256(key []byte) {
	m.addIntegrity(AttrMessageIntegritySHA256, sha256.New, key)
}

func (m *Message) addIntegrity(attr uint16, h func() hash.Hash, key []byte) {
	mac := hmac.New(h, key)
	mac.Write(m.marshal(4 + mac.Size())) // length counts the pending attribute
	m.Add(attr, mac.Sum(nil))
}

// VerifyMessageIntegrity checks raw's MESSAGE-INTEGRITY attribute against
// key, returning false when the attribute is absent or the HMAC mismatches.
func VerifyMessageIntegrity(raw, key []byte) bool {
	return verifyIntegrity(raw, AttrMessageIntegrity, sha1.New, sha1.Size, key)
}

// VerifyMessageIntegritySHA256 is VerifyMessageIntegrity for the SHA-256
// variant. Truncated MACs are accepted down to the 16-byte minimum of
// RFC 8489 §14.6 (multiples of 4 only), compared against the leading
// bytes of the full HMAC.
func VerifyMessageIntegritySHA256(raw, key []byte) bool {
	return verifyIntegrity(raw, AttrMessageIntegritySHA256, sha256.New, 16, key)
}

func verifyIntegrity(raw []byte, attr uint16, h func() hash.Hash, minLen int, key []byte) bool {
	if len(raw) < HeaderSize {
		return false
	}
	for off := HeaderSize; off+4 <= len(raw); {
		t := binary.BigEndian.Uint16(raw[off : off+2])
		n := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
		if t != attr {
			off += 4 + (n+3)/4*4
			continue
		}
		mac := hmac.New(h, key)
		if n < minLen || n > mac.Size() || n%4 != 0 || off+4+n > len(raw) {
			return false
		}
		// The HMAC input is the message up to this attribute, with the
		// header length rewritten as if the integrity attribute were the
		// last one — anything after it (e.g. FINGERPRINT) is excluded
		// (RFC 8489 §14.5).
		input := append([]byte(nil), raw[:off]...)
		binary.BigEndian.PutUint16(input[2:4], uint16(off-HeaderSize+4+n))
		mac.Write(input)
		return hmac.Equal(mac.Sum(nil)[:n], raw[off+4:off+4+n])
	}
	return false
}
