package stunmsg

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
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

// RFC 8489 Appendix B.1 as corrected by verified erratum 6268: long-term
// auth with USERHASH, the "obMatJos2" nonce cookie (username-anonymity
// feature bit), PASSWORD-ALGORITHM = SHA-256, and MESSAGE-INTEGRITY-SHA256.
// Same credentials as vecAuth; password after OpaqueString processing.
var vecB1 = unhex(`
	00010090 2112a442 78ad3433c6ad72c029da412e
	001e0020 4a3cf38fef6992bda952c6780417da0f24819415569e60b205c46e41407f1704
	00150029 6f624d61744a6f733241414143662f2f3439396b3935346436
	         4f4c33346f4c39465354767936347341 000000
	0014000b 6578616d706c652e6f7267 00
	001d0004 00020000
	001c0020 b5c7bf005b6c52a21c51c5e892f81924136296cb927c43149309278cc6518e65`)

var vecB1Key = LongTermKeySHA256("マトリックス", "example.org", "TheMatrIX")

func TestVectorB1(t *testing.T) {
	if !VerifyMessageIntegritySHA256(vecB1, vecB1Key) {
		t.Fatal("RFC 8489 B.1 MESSAGE-INTEGRITY-SHA256 did not verify")
	}
	m, err := Parse(vecB1)
	if err != nil {
		t.Fatal(err)
	}
	if uh, _ := m.Get(AttrUserhash); !bytes.Equal(uh, Userhash("マトリックス", "example.org")) {
		t.Fatalf("Userhash mismatch: vector has %x", uh)
	}
	if alg, ok := m.PasswordAlgorithm(); !ok || alg != PasswordAlgorithmSHA256 {
		t.Fatalf("PASSWORD-ALGORITHM = %#x, %v", alg, ok)
	}
}

// Rebuilding B.1 from parts must reproduce it byte for byte.
func TestRebuildVectorB1(t *testing.T) {
	m := &Message{Type: BindingRequest}
	copy(m.TransactionID[:], unhex("78ad3433c6ad72c029da412e"))
	m.Add(AttrUserhash, Userhash("マトリックス", "example.org"))
	m.Add(AttrNonce, []byte("obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA"))
	m.Add(AttrRealm, []byte("example.org"))
	m.AddPasswordAlgorithm(PasswordAlgorithmSHA256)
	m.AddMessageIntegritySHA256(vecB1Key)
	if got := m.Marshal(); !bytes.Equal(got, vecB1) {
		t.Fatalf("rebuilt message differs from vector:\ngot  %x\nwant %x", got, vecB1)
	}
}

// RFC 8489 §14.6 allows MESSAGE-INTEGRITY-SHA256 truncated to a multiple
// of 4 no shorter than 16 bytes; the sender computes the HMAC with the
// header length counting the truncated attribute.
func TestTruncatedSHA256(t *testing.T) {
	m := &Message{Type: BindingRequest, TransactionID: [12]byte{9}}
	m.Add(AttrUsername, []byte("user"))
	mac := hmac.New(sha256.New, vecAuthKey)
	mac.Write(m.marshal(4 + 16))
	m.Add(AttrMessageIntegritySHA256, mac.Sum(nil)[:16])
	if !VerifyMessageIntegritySHA256(m.Marshal(), vecAuthKey) {
		t.Fatal("16-byte truncated MAC did not verify")
	}

	for _, n := range []int{12, 20} { // below minimum; wrong sender length
		m.Attrs = m.Attrs[:1]
		m.Add(AttrMessageIntegritySHA256, mac.Sum(nil)[:n])
		if VerifyMessageIntegritySHA256(m.Marshal(), vecAuthKey) {
			t.Fatalf("%d-byte MAC verified, want reject", n)
		}
	}
}

func TestPasswordAlgorithmsCodec(t *testing.T) {
	m := &Message{}
	m.AddPasswordAlgorithms([]uint16{PasswordAlgorithmSHA256, PasswordAlgorithmMD5})
	algs, err := m.PasswordAlgorithms()
	if err != nil || len(algs) != 2 || algs[0] != PasswordAlgorithmSHA256 || algs[1] != PasswordAlgorithmMD5 {
		t.Fatalf("round trip = %v, %v", algs, err)
	}

	// Unknown parameters must be skipped, not choked on.
	m2 := &Message{}
	m2.Add(AttrPasswordAlgorithms, unhex("7fff0003 aabbcc00 00020000"))
	if algs, err = m2.PasswordAlgorithms(); err != nil || len(algs) != 2 || algs[1] != PasswordAlgorithmSHA256 {
		t.Fatalf("params skip = %v, %v", algs, err)
	}

	m3 := &Message{}
	m3.Add(AttrPasswordAlgorithms, unhex("0002ffff 0000"))
	if _, err = m3.PasswordAlgorithms(); err == nil {
		t.Fatal("overrunning parameter length did not error")
	}
}

// No RFC test vector exists for a full-length MESSAGE-INTEGRITY-SHA256
// without USERHASH, so round-trip: add, verify, tamper, verify again.
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
