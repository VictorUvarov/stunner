# Chapter 1: The NAT problem

Ask your computer what its IP address is and it will tell you something like
`192.168.1.42`. That address only means something locally: your home router
handed it out on your private network. To the rest of the
internet, you don't have that address at all. You share one public address with
every other device in the house, and your router juggles them behind it. This
juggling act is called **NAT**, Network Address Translation, and it's why the
internet didn't run out of addresses a decade ago.

NAT is invisible almost all the time. When you load a web page, your request
goes out through the router, the router remembers "this reply belongs to the
laptop," and the answer comes back. You never needed to know your public
address, because you started the conversation.

## The trouble starts when two devices want to talk directly

Now imagine a video call. For the audio and video to flow without bouncing
through a middleman server (which costs money and adds delay), the two devices
want to send packets straight to each other. But neither one knows its own
public address. Each sees only its private `192.168.x.x` address, which is
useless to the other side. It's like trying to give someone directions to your
house when all you know is which bedroom you're standing in.

You could ask the router, but home routers generally won't tell you, and even
if they did, the answer depends on where the packet is going. What you really
need is an outside observer: someone on the public internet who can look at a
packet you sent and report back the address it appears to come from.

## That outside observer is a STUN server

The idea is almost too simple. Your device sends a small packet to a STUN
server and asks, in effect, "what address did this arrive from?" On the way
out, your router rewrites the packet's source address to the public one. That's
just NAT doing its normal job. The STUN server sees the rewritten address,
copies it into a reply, and sends it back. Now your device knows how the
outside world sees it.

```mermaid
sequenceDiagram
    participant C as Client<br/>(behind NAT)
    participant N as Home router<br/>(NAT)
    participant S as STUN server
    C->>N: "What's my address?"
    Note over N: rewrites source to<br/>public IP:port
    N->>S: "What's my address?"
    S-->>N: "You look like<br/>203.0.113.7:51234"
    N-->>C: "You look like<br/>203.0.113.7:51234"
    Note over C: now knows its<br/>public address
```

That single answer is usually enough. Once each side knows its own public
address, they can trade those addresses (through a signaling channel, a
chat server, say) and start sending packets directly. This is the foundation
under WebRTC video calls, voice chat, and peer-to-peer multiplayer games.

## What STUN is not

STUN tells you your address and nothing else. It doesn't relay your traffic,
hold your call open, or remember anything about you between packets. A sister
protocol, TURN, relays traffic for the hard cases where a direct connection is
impossible. TURN has a different cost profile, and this server doesn't
implement it. STUN is the cheap, stateless first thing you try.

The server keeps no memory of you, and that fact shapes every later chapter.
Every request is answered entirely from the packet in front of it, since the
return address is right there on the envelope. This is why a STUN server on the
smallest VPS you can rent will shrug off enormous traffic: it has no per-user
state that could fill up.

## Why run your own

If STUN is so simple, why not use a public server? This project exists for
three reasons. A STUN server sees the IP of every user of your app, and a
public one hands that visibility to a stranger. A free public server can vanish
or get overloaded the day your product launches, while your own stays up. And
STUN is cheap enough that "just run your own" is a real answer; the most it
costs you is the ten minutes it takes to set up.

## Where this is going

The rest of this tutorial takes that one exchange apart. The next chapter looks
at exactly what those "what's my address?" packets contain, down to the byte,
since every answer the server gives is written in that format.

---

**Read the code**

- [`README.md`](../README.md): the same pitch, aimed at someone deciding
  whether to run the server.
- [`internal/server/README.md`](../internal/server/README.md): a one-paragraph
  restatement of the job, from the server's point of view.

---

[Contents](README.md) · **Next:** [Chapter 2: Anatomy of a STUN message →](02-anatomy-of-a-message.md)
