# stunmsg

This package converts STUN messages between raw network bytes and Go values.
It does nothing else — no sockets, no state. Bytes in, `Message` out, and back.

## STUN messages in two minutes

A STUN message is a small binary packet with two parts:

- A fixed **20-byte header**: the message type (e.g. "Binding Request"),
  the payload length, a constant called the **magic cookie** (`0x2112A442`,
  used to recognize STUN traffic), and a random 12-byte **transaction ID**
  that lets a client match a response to its request.
- Zero or more **attributes** — typed key-value entries, like a very compact
  binary version of HTTP headers. Example: the answer to "what's my public
  address?" travels as an attribute called XOR-MAPPED-ADDRESS.

Two attribute details matter to understand this code:

- **Why "XOR" in XOR-MAPPED-ADDRESS?** The address is not stored plainly —
  it's XORed with the magic cookie (and, for IPv6, the transaction ID).
  This isn't encryption; it stops buggy routers (NATs) that scan packets
  for their own IP address from "helpfully" rewriting it in transit.
- **FINGERPRINT** is a CRC32 checksum over the whole message, so a receiver
  can tell a real STUN packet from other traffic on the same port.

Full spec: [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489).

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
exist only for the attributes the server actually produces or reads:
XOR-MAPPED-ADDRESS, ERROR-CODE, UNKNOWN-ATTRIBUTES, SOFTWARE, FINGERPRINT,
and the long-term-credential set — MESSAGE-INTEGRITY(-SHA256) add/verify,
key derivation (`LongTermKey`, `LongTermKeySHA256`), `Userhash`, and the
PASSWORD-ALGORITHM(S) codec. Key-derivation inputs must already be
OpaqueString-processed (RFC 8265); this package does no string preparation.

## How we know it's correct

The IETF published [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769),
a set of official example messages with every byte spelled out.
`stunmsg_test.go` embeds them byte-for-byte and checks that this package
parses them, decodes the right addresses, and validates their checksums —
plus round-trip and garbage-rejection tests of our own. The long-term-auth
code is additionally checked against [RFC 8489 Appendix B.1](https://www.rfc-editor.org/rfc/rfc8489#appendix-B.1)
(as corrected by [verified erratum 6268](https://www.rfc-editor.org/errata/eid6268)),
which covers USERHASH, the nonce cookie, and MESSAGE-INTEGRITY-SHA256.

## Gotchas encoded here

- The XOR key for addresses depends on the message it's in (magic cookie
  for IPv4, magic cookie ‖ transaction ID for IPv6).
- The FINGERPRINT checksum is computed with the header's length field
  *already counting* the not-yet-appended attribute — an easy spec detail
  to get wrong; `AddFingerprint` handles it.
- Attribute values are padded to 4-byte boundaries on the wire, but the
  length field counts the unpadded value. Padding bytes may be non-zero
  (the RFC 5769 vectors deliberately pad with spaces) and must be ignored,
  not validated.
- A message *without* the magic cookie isn't garbage — it's classic STUN
  (RFC 3489), which used those four bytes as part of a 128-bit transaction
  ID. `Parse` accepts it and exposes the wire value via `Cookie` /
  `Classic()`; `Marshal` echoes a non-zero `Cookie` verbatim (zero means
  "modern" and writes the magic). The flip side: the cookie no longer
  screens out non-STUN input, so `Parse` must not be used to demultiplex
  STUN from other protocols on a shared port.
- Classic messages carry their alignment themselves — RFC 3489 has no
  attribute padding — so on classic messages `AddErrorCode` space-pads the
  reason and `AddUnknownAttributes` doubles an odd list. Set `Cookie`
  before calling either.
