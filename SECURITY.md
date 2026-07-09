# Security policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue or pull
request. That gives the fix time to ship before the problem is widely known.

Use GitHub's private reporting: go to the **Security** tab and choose
**Report a vulnerability**
([Security Advisories](https://github.com/VictorUvarov/stunner/security/advisories/new)).
It opens a private thread with the maintainer.

Helpful things to include, if you have them:

- what you were doing and what happened,
- the smallest steps or input that reproduce it,
- the affected version or commit, and
- the impact you think it has.

You don't need all of that to report — send what you have.

## What to expect

- An acknowledgement within a few days.
- An honest assessment of whether it's a vulnerability and how severe.
- A fix on a private branch, then a release, then public disclosure crediting
  you (unless you'd rather stay anonymous).

## Supported versions

stunner is pre-1.0 and moves fast. Fixes land on the latest release and on
`main`; there are no backports to older tags. Run a recent build.

## Scope

stunner speaks STUN on the network and, when configured, terminates TLS and
DTLS and checks long-term credentials. Reports about any of that — the wire
protocol parsing, the auth handshake, the transports, rate limiting, or the
`stund`/`stunc` commands — are in scope.

Out of scope: how you deploy it (firewall rules, TLS certificate management,
credential storage), and issues in third-party dependencies, which should go
to those projects directly.
