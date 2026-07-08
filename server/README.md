# server

The STUN Binding service over UDP. One exported entry point:

```go
conn, _ := net.ListenUDP("udp", addr)
err := server.Serve(conn)   // blocks; returns nil when conn is closed
```

Shutdown model: there is no Stop method — close the socket and `Serve`
returns. That's the whole lifecycle.

## Behavior

For every datagram received:

| Input | Response |
|---|---|
| Valid Binding Request | Binding Success with XOR-MAPPED-ADDRESS = source address |
| … with unknown comprehension-required attribute | 420 error with UNKNOWN-ATTRIBUTES |
| … with USERNAME / MESSAGE-INTEGRITY(-SHA256) | Treated as ignorable (no auth), normal success |
| Non-STUN bytes, malformed framing, bad FINGERPRINT, non-Binding type | Silence (RFC 8489 §6.3) |

Every response carries SOFTWARE (the `Software` package variable) and a
FINGERPRINT, and echoes the request's transaction ID.

Replies go out the same socket the request came in on — required so the
client sees the response from the ip:port it sent to.

## Tests

`server_test.go` runs the real loop over loopback sockets: success path,
420 path, ignorable-attribute path, and silent-drop cases (garbage, corrupt
fingerprint) verified by read timeout.
