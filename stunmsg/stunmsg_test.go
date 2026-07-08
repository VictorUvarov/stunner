package stunmsg

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// RFC 5769 test vectors.
var (
	// §2.1: Binding request with SOFTWARE, PRIORITY, ICE-CONTROLLED,
	// USERNAME, MESSAGE-INTEGRITY, FINGERPRINT.
	vecRequest = unhex(`
		00010058 2112a442 b7e7a701bc34d686fa87dfae
		80220010 5354554e2074657374 20636c69656e74
		00240004 6e0001ff
		80290008 932ff9b151263b36
		00060009 6576746a3a68367659 202020
		00080014 9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2
		80280004 e57a3bcf`)
	// §2.2: Binding success, XOR-MAPPED-ADDRESS 192.0.2.1:32853.
	vecIPv4 = unhex(`
		0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563
		746f7220002000080001a147e112a64300080014 2b91f599fd9e90c38c7489
		f92af9ba53f06be7d780280004c07d4c96`)
	// §2.3: Binding success, XOR-MAPPED-ADDRESS [2001:db8:1234:5678:11:2233:4455:6677]:32853.
	vecIPv6 = unhex(`
		010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563
		746f722000200014 0002a1470113a9faa5d3f179bc25f4b5bed2b9d9000800
		14a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c`)
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseIPv4Vector(t *testing.T) {
	m, err := Parse(vecIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != BindingSuccess {
		t.Fatalf("type = %#x", m.Type)
	}
	ap, err := m.XORMappedAddress()
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("192.0.2.1:32853"); ap != want {
		t.Fatalf("addr = %v, want %v", ap, want)
	}
	if sw, _ := m.Get(AttrSoftware); string(sw) != "test vector" {
		t.Fatalf("software = %q", sw)
	}
	if !VerifyFingerprint(vecIPv4) {
		t.Fatal("fingerprint check failed")
	}
}

func TestParseIPv6Vector(t *testing.T) {
	m, err := Parse(vecIPv6)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := m.XORMappedAddress()
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("[2001:db8:1234:5678:11:2233:4455:6677]:32853"); ap != want {
		t.Fatalf("addr = %v, want %v", ap, want)
	}
	if !VerifyFingerprint(vecIPv6) {
		t.Fatal("fingerprint check failed")
	}
}

func TestRequestVectorFingerprint(t *testing.T) {
	m, err := Parse(vecRequest)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != BindingRequest {
		t.Fatalf("type = %#x", m.Type)
	}
	if !VerifyFingerprint(vecRequest) {
		t.Fatal("fingerprint check failed")
	}
}

func TestRoundTrip(t *testing.T) {
	m := &Message{Type: BindingSuccess, TransactionID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}
	m.AddSoftware("stund")
	m.AddXORMappedAddress(netip.MustParseAddrPort("203.0.113.9:49152"))
	m.AddFingerprint()
	raw := m.Marshal()

	if !VerifyFingerprint(raw) {
		t.Fatal("self-produced fingerprint doesn't verify")
	}
	m2, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := m2.XORMappedAddress()
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("203.0.113.9:49152"); ap != want {
		t.Fatalf("addr = %v, want %v", ap, want)
	}
	if !bytes.Equal(m2.Marshal(), raw) {
		t.Fatal("re-marshal differs")
	}
}

func TestRejectsGarbage(t *testing.T) {
	// Note no wrong-cookie case: a message without the magic cookie is
	// valid classic STUN (RFC 5389 §12.2), not garbage.
	cases := [][]byte{
		nil,
		[]byte("hello"),
		append([]byte{0xC0, 1}, vecIPv4[2:]...), // wrong leading bits
		vecIPv4[:len(vecIPv4)-1],                // truncated
		append(append([]byte{}, vecIPv4...), 0, 0, 0), // trailing junk
	}
	for i, c := range cases {
		if _, err := Parse(c); err == nil {
			t.Errorf("case %d: garbage accepted", i)
		}
	}
}

func TestErrorCode(t *testing.T) {
	m := &Message{Type: BindingError}
	m.AddErrorCode(420, "Unknown Attribute")
	v, ok := m.Get(AttrErrorCode)
	if !ok || v[2] != 4 || v[3] != 20 || string(v[4:]) != "Unknown Attribute" {
		t.Fatalf("bad ERROR-CODE encoding: %x", v)
	}
}

func TestTrimAfterIntegrity(t *testing.T) {
	cases := []struct {
		name        string
		attrs, want []uint16
	}{
		{"no integrity", []uint16{AttrUsername, AttrXORMappedAddress},
			[]uint16{AttrUsername, AttrXORMappedAddress}},
		{"after MI", []uint16{AttrUsername, AttrMessageIntegrity, 0x7FFF, AttrFingerprint},
			[]uint16{AttrUsername, AttrMessageIntegrity, AttrFingerprint}},
		{"MI keeps MI-SHA256", []uint16{AttrMessageIntegrity, 0x7FFF, AttrMessageIntegritySHA256, AttrFingerprint},
			[]uint16{AttrMessageIntegrity, AttrMessageIntegritySHA256, AttrFingerprint}},
		{"after MI-SHA256", []uint16{AttrUsername, AttrMessageIntegritySHA256, 0x7FFF, AttrFingerprint, AttrSoftware},
			[]uint16{AttrUsername, AttrMessageIntegritySHA256, AttrFingerprint}},
	}
	for _, c := range cases {
		m := &Message{Type: BindingRequest}
		for _, a := range c.attrs {
			m.Add(a, []byte{0, 0, 0, 0})
		}
		m.TrimAfterIntegrity()
		var got []uint16
		for _, a := range m.Attrs {
			got = append(got, a.Type)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: attrs = %04x, want %04x", c.name, got, c.want)
		}
	}
}

func TestClassic(t *testing.T) {
	// A classic request is a modern one with arbitrary bytes where the
	// magic cookie would be: build modern, stamp the cookie field.
	m := &Message{Type: BindingRequest}
	raw := m.Marshal()
	copy(raw[4:8], []byte{0xDE, 0xAD, 0xBE, 0xEF})

	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Classic() || got.Cookie != 0xDEADBEEF {
		t.Fatalf("Classic() = %v, Cookie = %08x", got.Classic(), got.Cookie)
	}
	if !bytes.Equal(got.Marshal(), raw) {
		t.Fatal("classic re-marshal lost the cookie bytes")
	}

	modern, err := Parse(m.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if modern.Classic() {
		t.Fatal("magic cookie parsed as classic")
	}
	if (&Message{Type: BindingRequest}).Classic() {
		t.Fatal("zero-value message reports classic")
	}
}

func TestClassicWireAlignment(t *testing.T) {
	classic := &Message{Type: BindingError, Cookie: 0xDEADBEEF}
	classic.AddErrorCode(420, "Unknown Attribute") // 17 bytes: needs padding
	classic.AddUnknownAttributes([]uint16{0x7FFF}) // odd count: needs doubling

	ec, _ := classic.Get(AttrErrorCode)
	if len(ec)%4 != 0 || string(ec[4:]) != "Unknown Attribute   " {
		t.Fatalf("classic reason not space-padded to 4: %q", ec[4:])
	}
	ua, _ := classic.Get(AttrUnknownAttributes)
	if len(ua) != 4 || ua[0] != 0x7F || ua[1] != 0xFF || ua[2] != 0x7F || ua[3] != 0xFF {
		t.Fatalf("classic odd unknown-attr list not doubled: %x", ua)
	}

	modern := &Message{Type: BindingError}
	modern.AddErrorCode(420, "Unknown Attribute")
	modern.AddUnknownAttributes([]uint16{0x7FFF})
	if ec, _ := modern.Get(AttrErrorCode); string(ec[4:]) != "Unknown Attribute" {
		t.Fatalf("modern reason altered: %q", ec[4:])
	}
	if ua, _ := modern.Get(AttrUnknownAttributes); len(ua) != 2 {
		t.Fatalf("modern unknown-attr list altered: %x", ua)
	}
}

func TestIsRequest(t *testing.T) {
	for typ, want := range map[uint16]bool{
		BindingRequest:    true,
		BindingIndication: false,
		BindingSuccess:    false,
		BindingError:      false,
		0x0003:            true, // another method, request class
	} {
		if IsRequest(typ) != want {
			t.Errorf("IsRequest(%04x) = %v, want %v", typ, !want, want)
		}
	}
}
