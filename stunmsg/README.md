# stunmsg

Pure STUN message codec (RFC 8489): parse, build, and serialize messages.
No networking, no state — just bytes in, `Message` out, and back.

## Usage

```go
// Parse an incoming datagram.
m, err := stunmsg.Parse(pkt)          // ErrNotSTUN / ErrMalformed on bad input

// Build a response.
resp := &stunmsg.Message{Type: stunmsg.BindingSuccess, TransactionID: m.TransactionID}
resp.AddXORMappedAddress(clientAddr)  // netip.AddrPort, IPv4 or IPv6
resp.AddSoftware("stund")
resp.AddFingerprint()                 // must be added last
out := resp.Marshal()
```

Attributes are exposed as raw `[]Attr` (type + value bytes); typed helpers
exist only for the attributes a Binding server actually produces or reads:
XOR-MAPPED-ADDRESS, ERROR-CODE, SOFTWARE, FINGERPRINT.

## Correctness

`stunmsg_test.go` checks the package against the RFC 5769 test vectors
byte-for-byte (§2.1 request, §2.2 IPv4 response, §2.3 IPv6 response),
including FINGERPRINT CRC verification, plus round-trip and
garbage-rejection tests.

## Gotchas encoded here

- Addresses in XOR-MAPPED-ADDRESS are XORed with the magic cookie (IPv4)
  or magic cookie ‖ transaction ID (IPv6) — so the XOR key depends on the
  message it's in.
- The FINGERPRINT CRC is computed with the header length field *already
  counting* the not-yet-appended attribute; `AddFingerprint` handles this.
- Attribute values are padded to 4 bytes on the wire, but the length field
  counts the unpadded value. Padding bytes may be non-zero (RFC 5769 uses
  spaces) and must be ignored, not validated.
