package stunmsg

import (
	"bytes"
	"net/netip"
	"testing"
)

// RFC 5769 §2.4: request with long-term authentication.
// Username "マトリックス", realm "example.org", password "TheMatrIX"
// (after SASLprep), nonce "f//499k954d6OL34oL9FSTvy64sA".
var vecAuth = unhex(`
	00010060 2112a442 78ad3433c6ad72c029da412e
	00060012 e3839ee38388e383aae38383e382afe382b9 0000
	0015001c 662f2f3439396b39353464364f4c33346f4c39465354767936347341
	0014000b 6578616d706c652e6f7267 00
	00080014 f67024656dd64a3e02b8e0712e85c9a28ca89666`)

var vecAuthKey = LongTermKey("マトリックス", "example.org", "TheMatrIX")

func TestVerifyMessageIntegrityVector(t *testing.T) {
	if !VerifyMessageIntegrity(vecAuth, vecAuthKey) {
		t.Fatal("RFC 5769 §2.4 MESSAGE-INTEGRITY did not verify")
	}
	if VerifyMessageIntegrity(vecAuth, LongTermKey("マトリックス", "example.org", "wrong")) {
		t.Fatal("verified with wrong password")
	}
	tampered := append([]byte(nil), vecAuth...)
	tampered[25] ^= 0xFF // flip a username byte
	if VerifyMessageIntegrity(tampered, vecAuthKey) {
		t.Fatal("verified tampered message")
	}
	if VerifyMessageIntegrity(vecIPv4, vecAuthKey) {
		t.Fatal("verified message with no MESSAGE-INTEGRITY")
	}
}

// Rebuilding the vector from parts must reproduce it byte for byte,
// proving AddMessageIntegrity's length-adjustment logic.
func TestAddMessageIntegrityReproducesVector(t *testing.T) {
	m := &Message{Type: BindingRequest}
	copy(m.TransactionID[:], unhex("78ad3433c6ad72c029da412e"))
	m.Add(AttrUsername, []byte("マトリックス"))
	m.Add(AttrNonce, []byte("f//499k954d6OL34oL9FSTvy64sA"))
	m.Add(AttrRealm, []byte("example.org"))
	m.AddMessageIntegrity(vecAuthKey)
	if got := m.Marshal(); !bytes.Equal(got, vecAuth) {
		t.Fatalf("rebuilt message differs from RFC vector:\ngot  %x\nwant %x", got, vecAuth)
	}
}

// No RFC test vector exists for MESSAGE-INTEGRITY-SHA256, so round-trip:
// add, verify, tamper, verify again.
func TestMessageIntegritySHA256RoundTrip(t *testing.T) {
	m := &Message{Type: BindingRequest, TransactionID: [12]byte{7}}
	m.Add(AttrUsername, []byte("user"))
	m.AddMessageIntegritySHA256(vecAuthKey)
	raw := m.Marshal()
	if !VerifyMessageIntegritySHA256(raw, vecAuthKey) {
		t.Fatal("SHA-256 integrity did not verify")
	}
	if VerifyMessageIntegritySHA256(raw, LongTermKey("a", "b", "c")) {
		t.Fatal("verified with wrong key")
	}
	raw[25] ^= 0xFF
	if VerifyMessageIntegritySHA256(raw, vecAuthKey) {
		t.Fatal("verified tampered message")
	}
	if VerifyMessageIntegrity(m.Marshal(), vecAuthKey) {
		t.Fatal("SHA-1 verify accepted a message with only the SHA-256 attribute")
	}
}

// MESSAGE-INTEGRITY followed by FINGERPRINT: both must verify, since the
// HMAC excludes what follows it but FINGERPRINT covers the whole message.
func TestIntegrityThenFingerprint(t *testing.T) {
	m := &Message{Type: BindingSuccess, TransactionID: [12]byte{1}}
	m.AddXORMappedAddress(netip.MustParseAddrPort("192.0.2.1:32853"))
	m.AddMessageIntegrity(vecAuthKey)
	m.AddFingerprint()
	raw := m.Marshal()
	if !VerifyMessageIntegrity(raw, vecAuthKey) {
		t.Fatal("MESSAGE-INTEGRITY failed with trailing FINGERPRINT")
	}
	if !VerifyFingerprint(raw) {
		t.Fatal("FINGERPRINT failed")
	}
}
