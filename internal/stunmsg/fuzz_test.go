package stunmsg

import (
	"bytes"
	"net/netip"
	"testing"
)

// Fuzz targets for the codec's hostile-input surface: everything here reads
// raw bytes off the network before any authentication has happened. Run with
// `just fuzz` (or `go test -fuzz FuzzParse ./stunmsg`); without -fuzz these
// execute the seed corpus as regular tests.

// FuzzParse throws arbitrary bytes at every raw-buffer entry point. None may
// panic, and anything Parse accepts must survive a marshal → reparse round
// trip with its meaning intact.
func FuzzParse(f *testing.F) {
	for _, seed := range [][]byte{vecRequest, vecIPv4, vecIPv6, vecAuth, vecB1} {
		f.Add(seed)
	}
	// A classic (RFC 3489, no magic cookie) request and a bare header.
	f.Add(unhex("00010000 0000000a 000000000000000000000bad"))
	f.Add(unhex("00010000 2112a442 000000000000000000000000"))
	f.Fuzz(func(t *testing.T, data []byte) {
		key := []byte("fuzz-key")
		VerifyFingerprint(data)
		VerifyMessageIntegrity(data, key)
		VerifyMessageIntegritySHA256(data, key)

		m, err := Parse(data)
		if err != nil {
			return
		}
		// Attribute accessors must tolerate whatever Parse let through.
		m.XORMappedAddress()
		m.Address(AttrMappedAddress)
		m.PasswordAlgorithms()
		m.PasswordAlgorithm()
		trimmed := *m
		trimmed.Attrs = append([]Attr(nil), m.Attrs...)
		trimmed.TrimAfterIntegrity()

		out := m.Marshal()
		m2, err := Parse(out)
		if err != nil {
			t.Fatalf("re-parse of marshaled message failed: %v\nin  %x\nout %x", err, data, out)
		}
		// A zero wire cookie is indistinguishable from an unset field and
		// marshals as the magic cookie (documented on Message.Cookie), so
		// compare through that normalization.
		normalize := func(c uint32) uint32 {
			if c == 0 {
				return magicCookie
			}
			return c
		}
		if m2.Type != m.Type || m2.TransactionID != m.TransactionID ||
			normalize(m2.Cookie) != normalize(m.Cookie) || len(m2.Attrs) != len(m.Attrs) {
			t.Fatalf("round trip changed the message: %v -> %v", m, m2)
		}
		for i := range m.Attrs {
			if m2.Attrs[i].Type != m.Attrs[i].Type || !bytes.Equal(m2.Attrs[i].Value, m.Attrs[i].Value) {
				t.Fatalf("round trip changed attribute %d: %x -> %x", i, m.Attrs[i].Value, m2.Attrs[i].Value)
			}
		}
	})
}

// FuzzBuild drives the construction path with arbitrary in-contract inputs:
// a built, signed, fingerprinted message must parse back and verify, and the
// XOR address transform must invert exactly.
func FuzzBuild(f *testing.F) {
	f.Add(uint16(BindingRequest), uint32(0), []byte("txn-id-12byt"), uint16(0x8099), []byte("value"), false, uint16(32853), []byte("192.0.2.1---16by"), []byte("secret"))
	f.Add(uint16(BindingSuccess), uint32(0x0bad0bad), []byte(""), uint16(0x7fff), []byte{}, true, uint16(1), []byte("fe80::1"), []byte("k"))
	f.Fuzz(func(t *testing.T, typ uint16, cookie uint32, tid []byte, attrType uint16, val []byte, v6 bool, port uint16, ipBytes []byte, key []byte) {
		typ &= 0x3FFF // the two leading zero bits of every STUN type (§5)
		if len(val) > 512 {
			val = val[:512]
		}
		if len(key) == 0 || len(key) > 64 {
			t.Skip()
		}
		switch attrType {
		case AttrMessageIntegrity, AttrMessageIntegritySHA256, AttrFingerprint:
			t.Skip() // the sealing attributes are appended below, once
		case AttrXORMappedAddress:
			t.Skip() // would shadow the real one added below
		}

		var ip netip.Addr
		var ok bool
		if v6 {
			if len(ipBytes) < 16 {
				t.Skip()
			}
			ip, ok = netip.AddrFromSlice(ipBytes[:16])
		} else {
			if len(ipBytes) < 4 {
				t.Skip()
			}
			ip, ok = netip.AddrFromSlice(ipBytes[:4])
		}
		if !ok {
			t.Skip()
		}
		ap := netip.AddrPortFrom(ip, port)

		m := &Message{Type: typ, Cookie: cookie}
		copy(m.TransactionID[:], tid)
		m.AddXORMappedAddress(ap)
		m.Add(attrType, val)
		m.AddMessageIntegritySHA256(key)
		m.AddFingerprint()
		raw := m.Marshal()

		if !VerifyFingerprint(raw) {
			t.Fatalf("fresh fingerprint does not verify: %x", raw)
		}
		if !VerifyMessageIntegritySHA256(raw, key) {
			t.Fatal("fresh MESSAGE-INTEGRITY-SHA256 does not verify")
		}
		wrong := append([]byte(nil), key...)
		wrong[0] ^= 0xFF
		if VerifyMessageIntegritySHA256(raw, wrong) {
			t.Fatal("MESSAGE-INTEGRITY-SHA256 verified with the wrong key")
		}

		m2, err := Parse(raw)
		if err != nil {
			t.Fatalf("built message does not parse: %v\n%x", err, raw)
		}
		got, err := m2.XORMappedAddress()
		if err != nil {
			t.Fatal(err)
		}
		if want := netip.AddrPortFrom(ip.Unmap(), port); got != want {
			t.Fatalf("XOR-MAPPED-ADDRESS round trip: got %v, want %v", got, want)
		}
		if v, _ := m2.Get(attrType); !bytes.Equal(v, val) {
			t.Fatalf("attribute round trip: got %x, want %x", v, val)
		}
	})
}
