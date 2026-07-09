# Chapter 2: Anatomy of a STUN message

In chapter 1 the client asked "what's my address?" and the server answered.
Now let's open the envelope. Both the question and the answer are STUN
messages, and they share one format. Learn it once and you can read every
packet in the protocol.

A STUN message has two parts: a fixed **20-byte header**, followed by zero or
more **attributes**. That's it. The header is always the same shape; the
attributes are where the variety lives.

In this codebase, one package owns this format and nothing else:
[`internal/stunmsg`](../internal/stunmsg/). It turns raw bytes into a Go
`Message` and back. No sockets, no state — bytes in, `Message` out. Keeping it
that pure is what makes it easy to test against the official examples, which
we'll get to at the end.

## The 20-byte header

Every message starts with the same twenty bytes:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     message type          |         message length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         magic cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Four fields:

- **Message type** (2 bytes) — what kind of message this is. "Binding
  Request," "Binding Success Response," and so on. The top two bits are always
  zero, which is the first thing a receiver checks to weed out non-STUN traffic.
- **Message length** (2 bytes) — how many bytes of attributes follow the
  header. The header itself doesn't count.
- **Magic cookie** (4 bytes) — the constant `0x2112A442`. Always these exact
  bytes. It's a fixed marker that says "this is modern STUN."
- **Transaction ID** (12 bytes) — a random number the client picks. The server
  copies it into the reply unchanged, so the client can match an answer to the
  question it asked. If you have three requests in flight, the transaction ID
  is how you tell the three answers apart.

The magic cookie earns a second look. Why bake a constant into every message?
Because STUN often shares a UDP port with other protocols, and a receiver needs
a fast way to guess "is this even STUN?" before spending effort parsing it. The
cookie is that guess. (There's a wrinkle here for the 2003 version of the
protocol, which predates the cookie — chapter 7 covers it. For now, assume the
cookie is always present.)

## Attributes: the payload

After the header come the attributes. An attribute is a **TLV** — Type,
Length, Value — which is a fancy way of saying "a labeled box." Think of them
as an extremely compact binary version of HTTP headers: a small type number
says what this is, a length says how big the value is, and then the value
itself.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         attribute type        |        value length           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         value (variable)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The answer to "what's my address?" travels as an attribute called
XOR-MAPPED-ADDRESS. A 401 challenge travels as ERROR-CODE plus a few others.
The name of the software travels as SOFTWARE. Every capability in the protocol
is really just "define a new attribute type and agree on what its value means."

Two details about attributes trip people up, and the code has to get both
right:

- **Values are padded to 4-byte boundaries.** If a value is 5 bytes long, it's
  followed by 3 bytes of padding so the next attribute starts on a clean
  boundary. But the length field records the *real* length (5), not the padded
  length (8). And the padding bytes can be anything — you must skip them, not
  check them. (The official test messages deliberately pad with space
  characters to catch parsers that wrongly expect zeros.)
- **The message length counts padded attributes.** The header's length field
  includes all that padding, even though each attribute's own length field
  doesn't.

This codebase keeps attributes as a raw list — type plus value bytes — and adds
typed accessors only for the handful of attributes the server actually reads or
writes. There's no attempt to model all 30-odd defined attributes as Go
structs. Most of them this server never touches, so they stay as opaque bytes.

## Why the address is scrambled: XOR-MAPPED-ADDRESS

Here's the protocol's cleverest little trick. When the server reports your
address, it doesn't write it plainly. It writes it **XORed** with the magic
cookie. (For IPv6, it XORs with the cookie followed by the transaction ID.)
The attribute is literally named for this: *XOR*-MAPPED-ADDRESS.

Why bother? Not for secrecy — XOR against a known constant hides nothing from
anyone who wants to look. The reason is stranger and more practical. Some older
NAT routers were "helpful": they scanned every packet passing through for
anything that looked like their own IP address, and rewrote it, assuming it
was a mistake. That would corrupt the very answer STUN is trying to deliver. By
scrambling the address, STUN makes sure it doesn't appear verbatim in the
packet, so a meddling NAT leaves it alone. The client unscrambles it on
arrival.

So the XOR isn't encryption. It's camouflage against well-meaning routers. Keep
that straight and the name stops being confusing.

## FINGERPRINT: "yes, this really is STUN"

The last piece is an optional attribute called FINGERPRINT: a CRC32 checksum
over the entire message. When STUN shares a port with another protocol, the
magic cookie is a good first guess that a packet is STUN, but FINGERPRINT is
near-certain proof. A receiver recomputes the checksum and, if it matches,
knows this wasn't some other protocol's packet that happened to have the right
bytes in the cookie position.

FINGERPRINT hides a subtle rule that's easy to implement wrong: the checksum is
computed with the header's length field *already counting the fingerprint
attribute that hasn't been added yet*. Get the ordering wrong and every
checksum you produce is invalid. In this code, `AddFingerprint` handles that
bookkeeping for you, and the tests would scream if it stopped. FINGERPRINT also
has to be the *last* attribute in the message, since it checksums everything
before it.

## How we know the parser is correct

A message parser is exactly the kind of code where a subtle bug hides for
years. This one has two defenses.

First, the IETF published [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769):
a set of example STUN messages with every byte written out, alongside the
values they decode to. The tests embed those messages byte-for-byte and check
that this package parses them, decodes the right addresses, and validates their
checksums. If the parser drifts from the spec, a published example breaks.

Second, the codec is **fuzzed**. Two fuzz targets throw arbitrary and
arbitrary-but-valid bytes at the parser and the builder, checking that anything
accepted survives a round trip — parse, re-serialize, re-parse — with its
meaning intact, and that a wrong key never validates. Roughly 50 million
executions ran clean before this landed.

## Where this is going

You can now read any STUN packet: a header telling you the type and giving you
a transaction ID to match on, followed by labeled attributes, one of which
carries the answer. The next chapter puts the format to work. We'll follow a
single Binding Request into the server and watch it build the response — and
meet the rule that governs everything the server does with input it doesn't
like.

---

**Read the code**

- [`internal/stunmsg/stunmsg.go`](../internal/stunmsg/stunmsg.go) — the
  `Message` type, `Parse`, `Marshal`, and the attribute accessors.
- [`internal/stunmsg/integrity.go`](../internal/stunmsg/integrity.go) — the
  authentication attributes (chapter 5 returns to these).
- [`internal/stunmsg/README.md`](../internal/stunmsg/README.md) — the same wire
  format as a reference, with the gotchas listed.
- The RFC 5769 vector tests and the two fuzz targets live beside the code in
  `internal/stunmsg/` — grep for `FuzzParse` and `FuzzBuild`.

---

[← Chapter 1: The NAT problem](01-the-nat-problem.md) · [Contents](README.md) · **Next:** [Chapter 3: The Binding exchange →](03-the-binding-exchange.md)
