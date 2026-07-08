#!/usr/bin/env python3
"""Independent STUN Binding checks against a running stund (no auth).

Exercises UDP and TCP from outside the Go toolchain: success response with
a correct XOR-MAPPED-ADDRESS, the 420 path for an unknown
comprehension-required attribute, and a classic (RFC 3489, no magic
cookie) exchange answered with a bare MAPPED-ADDRESS.

Usage:  ./stund -addr 127.0.0.1:3478 &
        python3 test/binding_client.py [host] [port]
"""
import os
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
MAGIC = 0x2112A442


def msg(mtype, tid, attrlist=()):
    body = b""
    for t, v in attrlist:
        body += struct.pack(">HH", t, len(v)) + v + b"\0" * ((4 - len(v) % 4) % 4)
    return struct.pack(">HHI", mtype, len(body), MAGIC) + tid + body


def attrs(body):
    out, off = {}, 0
    while off < len(body):
        t, n = struct.unpack_from(">HH", body, off)
        out[t] = body[off + 4:off + 4 + n]
        off += 4 + (n + 3) // 4 * 4
    return out


def check_response(data, tid, local):
    mtype, length = struct.unpack_from(">HH", data)
    assert mtype == 0x0101, f"type {mtype:#06x}, want success"
    assert data[8:20] == tid, "transaction ID not echoed"
    a = attrs(data[20:20 + length])
    v = a[0x0020]  # XOR-MAPPED-ADDRESS
    port = struct.unpack_from(">H", v, 2)[0] ^ (MAGIC >> 16)
    ip = bytes(b ^ k for b, k in zip(v[4:8], struct.pack(">I", MAGIC)))
    got = (socket.inet_ntoa(ip), port)
    assert got == local, f"mapped {got}, sent from {local}"


# UDP success
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
sock.connect((HOST, PORT))  # so getsockname() reports the real local IP
tid = os.urandom(12)
sock.send(msg(0x0001, tid))
data = sock.recv(1500)
check_response(data, tid, sock.getsockname())

# UDP 420 for unknown comprehension-required attribute
tid = os.urandom(12)
sock.send(msg(0x0001, tid, [(0x7FFF, b"\1\2\3\4")]))
data = sock.recv(1500)
mtype = struct.unpack_from(">H", data)[0]
a = attrs(data[20:])
ec = a[0x0009]
assert mtype == 0x0111 and ec[2] * 100 + ec[3] == 420, "expected 420 error"
assert a[0x000A] == b"\x7f\xff", "UNKNOWN-ATTRIBUTES should list 0x7FFF"

# Classic STUN (RFC 3489): 128-bit transaction ID, no magic cookie. The
# response must echo all 16 ID bytes and answer with plain MAPPED-ADDRESS
# only — a classic parser rejects unknown mandatory attributes and has no
# concept of attribute padding.
tid16 = os.urandom(16)
sock.send(struct.pack(">HH", 0x0001, 0) + tid16)
data = sock.recv(1500)
mtype, length = struct.unpack_from(">HH", data)
assert mtype == 0x0101, f"classic: type {mtype:#06x}, want success"
assert data[4:20] == tid16, "classic: 128-bit transaction ID not echoed"
a = attrs(data[20:20 + length])
assert set(a) == {0x0001}, f"classic: attrs {sorted(map(hex, a))}, want MAPPED-ADDRESS alone"
port = struct.unpack_from(">H", a[0x0001], 2)[0]
got = (socket.inet_ntoa(a[0x0001][4:8]), port)
assert got == sock.getsockname(), f"classic: mapped {got}, sent from {sock.getsockname()}"

# TCP success (multiple requests on one connection)
tcp = socket.create_connection((HOST, PORT), timeout=2)
for _ in range(2):
    tid = os.urandom(12)
    tcp.sendall(msg(0x0001, tid))
    hdr = tcp.recv(20, socket.MSG_WAITALL)
    length = struct.unpack_from(">H", hdr, 2)[0]
    body = tcp.recv(length, socket.MSG_WAITALL)
    check_response(hdr + body, tid, tcp.getsockname())
tcp.close()

print("binding OK: UDP success, UDP 420, classic 3489, TCP x2")
