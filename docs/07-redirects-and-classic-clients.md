# Chapter 7: Redirects and classic clients

This chapter covers two features that don't fit the "answer the question"
mold. The first is the server telling a client *go ask someone else*. The
second is the server answering clients that speak a version of STUN from 2003,
before half the format in chapter 2 existed. They're grouped together because
both are edge behaviors you can ignore until you need them — and both are
opt-in or automatic, never in the way of the common case.

## Redirects: ALTERNATE-SERVER

Sometimes a server wants to hand a client off. Maybe it's draining for
maintenance. Maybe it's a front door that spreads load across a pool. STUN's
mechanism is the **300 (Try Alternate)** error, carrying an **ALTERNATE-SERVER**
attribute that names where to go instead
([RFC 8489 §10](https://datatracker.ietf.org/doc/html/rfc8489#section-10)).

It's opt-in, through the `Alternate` package variable (and the `-redirect`
flag). Turn it on and every Binding Request draws a 300 pointing elsewhere:

```go
server.Alternate = &server.AlternateServer{
    V4:     netip.MustParseAddrPort("198.51.100.20:3478"),
    Domain: "stun.example.org", // ALTERNATE-DOMAIN, for TLS/DTLS cert checks
}
```

Three details make it correct rather than merely functional:

- **Per address family.** The RFC requires the alternate to match the client's
  IP family — you can't send an IPv6 client to an IPv4 address. So targets are
  configured per family, and a request from a family with no configured target
  is served normally instead of redirected. (There's also a §10 SHOULD, easy to
  miss, that a redirect list the *other* family's alternate after the mandatory
  same-family one; the codec does this.)
- **Redirect after auth.** If authentication is on, the 300 is only sent after
  the client's credentials verify, so the redirect is integrity-protected
  (chapter 5). An off-path attacker can't forge a 300 to steer your clients to
  a server they control.
- **Discovery never redirects.** The NAT-discovery usage (chapter 6) depends on
  *this* server's specific four-socket topology, so handing a discovery client
  to a different server would break the measurement. Discovery ignores the
  redirect setting entirely.

On the client side, following a redirect is a decision, not a reflex — because
over TLS or DTLS the ALTERNATE-DOMAIN has to be validated against the new
server's certificate before you trust it. Chapter 8 shows how the client
surfaces that choice to its caller.

## Classic clients: RFC 3489 backwards compatibility

Now the time machine. STUN was first defined in 2003 by
[RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489) — "classic STUN."
That version had **no magic cookie**. The four bytes that chapter 2 called the
magic cookie were, back then, just the first four bytes of a 128-bit
transaction ID. The cookie was carved out of the transaction ID later, in RFC
5389.

This creates a neat detection rule. A Binding Request *without* the magic
cookie in those four bytes isn't garbage — it's a classic client
([RFC 5389 §12.2](https://datatracker.ietf.org/doc/html/rfc5389#section-12.2)).
And [RFC 8489 §12](https://datatracker.ietf.org/doc/html/rfc8489#section-12)
says a standalone server SHOULD still answer them. This server does, though it
was a deliberate call — the design log shows the feature was first declined,
then added at the operator's request, because true cookie-less clients are
nearly extinct.

Answering a classic client means writing the 2003 wire format, which differs on
several points, all forced by the older, simpler format that had no concept of
attribute padding:

- **Plain MAPPED-ADDRESS, never the XOR form.** XOR-MAPPED-ADDRESS postdates
  RFC 3489, and a classic parser rejects any message carrying a mandatory
  attribute it doesn't recognize. So a classic client gets its address in the
  clear.
- **The full 128-bit transaction ID echoed** — including the four bytes where a
  modern message would put the cookie.
- **No SOFTWARE or FINGERPRINT, space-padded error reasons, even-count
  UNKNOWN-ATTRIBUTES lists.** Because classic STUN has no attribute padding,
  every attribute value has to keep 4-byte alignment on its own, so the codec
  adjusts these to stay aligned. SOFTWARE has an odd length, FINGERPRINT isn't
  backwards compatible per §7, so both are simply omitted.
- **Classic never rides DTLS.** Per
  [RFC 8489 §11](https://datatracker.ietf.org/doc/html/rfc8489#section-11), a
  classic request over DTLS draws a 500 (Server Error) for any method; the rest
  is ignored and the association survives.
- **Auth-enabled servers give a classic client a bare 401**, since REALM and
  NONCE are meaningless to a parser that must reject them.
- **Discovery uses the era-correct names.** Classic NAT-type detection (RFC
  3489 §10.1) wants SOURCE-ADDRESS and CHANGED-ADDRESS — the attributes RFC
  5780 renamed to RESPONSE-ORIGIN and OTHER-ADDRESS. Classic clients get the
  old names, so CHANGE-REQUEST probing works for them too.

In the code, all of this keys off a single `Cookie` field added to the
`Message` type. A zero value marshals as the magic cookie, so every existing
modern construction site kept working untouched; a non-zero value is echoed
verbatim as a classic ID. The two alignment rules (space-padding, even-count
lists) live in the codec, switched on by that same field.

There's one real cost, straight from the spec, and it's worth understanding.
Once the parser accepts cookie-less messages, the magic cookie can no longer
screen out non-STUN traffic — which is exactly why RFC 5389 forbids combining
3489 compatibility with multiplexing STUN alongside another protocol on a
shared port. A standalone STUN server doesn't multiplex, so it can pay this
cost. A server sharing a port couldn't.

## Where this is going

That completes the server: every question it answers, every way it declines,
and every client generation it speaks to. The next chapter switches sides. We
look at the *client* — the code that asks the question — where the interesting
problems are the ones the server never has to face: what to do when your packet
gets lost, and how to run the authentication dance from chapter 5 in reverse.

---

**Read the code**

- [`internal/server/alternate.go`](../internal/server/alternate.go) — the
  `AlternateServer` config and the 300 redirect logic.
- [`internal/server/server.go`](../internal/server/server.go) and
  [`internal/stunmsg/stunmsg.go`](../internal/stunmsg/stunmsg.go) — classic
  detection via `Cookie` / `Classic()`, and the classic wire alignment.
- [`internal/server/README.md`](../internal/server/README.md) — the "Redirects"
  and "Classic clients" sections.

---

[← Chapter 6: NAT behavior discovery](06-nat-behavior-discovery.md) · [Contents](README.md) · **Next:** [Chapter 8: The client side →](08-the-client-side.md)
