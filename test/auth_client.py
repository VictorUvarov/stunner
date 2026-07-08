#!/usr/bin/env python3
"""Independent long-term-credential handshake against a running stund.

Speaks the RFC 5389-era flow (USERNAME + MESSAGE-INTEGRITY with the MD5 key)
so it doubles as a backward-compatibility check: 401 challenge, signed
retry, response MESSAGE-INTEGRITY verification, wrong-password rejection.

Usage:  ./stund -addr 127.0.0.1:3489 -realm example.org -user alice:s3cret &
        python3 test/auth_client.py [host] [port]
"""
import hashlib
import hmac
import os
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3489
MAGIC = 0x2112A442
USER, REALM_EXPECT, PASS = "alice", "example.org", "s3cret"


def attrs(body):
    out, off = {}, 0
    while off < len(body):
        t, n = struct.unpack_from(">HH", body, off)
        out[t] = body[off + 4:off + 4 + n]
        off += 4 + (n + 3) // 4 * 4
    return out


def msg(mtype, tid, attrlist):
    body = b""
    for t, v in attrlist:
        body += struct.pack(">HH", t, len(v)) + v + b"\0" * ((4 - len(v) % 4) % 4)
    return struct.pack(">HHI", mtype, len(body), MAGIC) + tid + body


def send(sock, pkt):
    sock.sendto(pkt, (HOST, PORT))
    data, _ = sock.recvfrom(1500)
    mtype, _, _ = struct.unpack_from(">HHI", data)
    return mtype, attrs(data[20:]), data


def signed_request(tid, key, attrlist):
    """Build a request with MESSAGE-INTEGRITY over attrlist (RFC 8489 §14.5)."""
    unsigned = msg(0x0001, tid, attrlist + [(0x0008, b"\0" * 20)])
    mac = hmac.new(key, unsigned[:-24], hashlib.sha1).digest()
    return msg(0x0001, tid, attrlist + [(0x0008, mac)])


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)

# 1: bare request draws a 401 challenge with REALM + NONCE
tid = os.urandom(12)
mtype, a, _ = send(sock, msg(0x0001, tid, []))
ec = a[0x0009]
code = ec[2] * 100 + ec[3]
assert mtype == 0x0111 and code == 401, (hex(mtype), code)
realm, nonce = a[0x0014], a[0x0015]
assert realm == REALM_EXPECT.encode(), realm

# 2: signed retry succeeds; response MESSAGE-INTEGRITY verifies
key = hashlib.md5(f"{USER}:{realm.decode()}:{PASS}".encode()).digest()
tid = os.urandom(12)
al = [(0x0006, USER.encode()), (0x0014, realm), (0x0015, nonce)]
mtype, a, raw = send(sock, signed_request(tid, key, al))
assert mtype == 0x0101, hex(mtype)
assert 0x0020 in a, "no XOR-MAPPED-ADDRESS"
mi_off = raw.find(struct.pack(">HH", 0x0008, 20))
covered = bytearray(raw[:mi_off])
struct.pack_into(">H", covered, 2, mi_off - 20 + 24)
assert hmac.new(key, bytes(covered), hashlib.sha1).digest() == raw[mi_off + 4:mi_off + 24], "resp MI bad"

# 3: wrong password draws 401
badkey = hashlib.md5(f"{USER}:{realm.decode()}:nope".encode()).digest()
tid = os.urandom(12)
mtype, a, _ = send(sock, signed_request(tid, badkey, al))
ec = a[0x0009]
assert mtype == 0x0111 and ec[2] * 100 + ec[3] == 401

print("auth handshake OK: 401 challenge, signed success + response MI, wrong-password 401")
