#!/usr/bin/env python3
"""Independent STUN-over-TLS check against a running stund (RFC 8489 §6.2.3).

Same Binding exchange as binding_client.py, but inside a TLS stream —
verifies the handshake, in-stream framing, and connection reuse.

Usage:  ./stund -tls-addr 127.0.0.1:5349 -tls-cert cert.pem -tls-key key.pem &
        python3 test/tls_client.py [host] [port]
"""
import os
import socket
import ssl
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5349
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


def read_message(sock):
    hdr = b""
    while len(hdr) < 20:
        hdr += sock.recv(20 - len(hdr))
    length = struct.unpack(">H", hdr[2:4])[0]
    body = b""
    while len(body) < length:
        body += sock.recv(length - len(body))
    return hdr, body


def xor_mapped(body, tid):
    v = attrs(body)[0x0020]
    port = struct.unpack(">H", v[2:4])[0] ^ (MAGIC >> 16)
    ip = bytes(b ^ k for b, k in zip(v[4:8], struct.pack(">I", MAGIC)))
    return socket.inet_ntoa(ip), port


ctx = ssl.create_default_context()
ctx.check_hostname = False          # self-signed test certs
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((HOST, PORT), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname=HOST) as s:
        for i in range(2):          # two requests: the stream is reusable
            tid = os.urandom(12)
            s.sendall(msg(0x0001, tid))
            hdr, body = read_message(s)
            assert hdr[0:2] == b"\x01\x01", f"expected success, got {hdr[0:2].hex()}"
            assert hdr[8:20] == tid, "transaction ID mismatch"
            ip, port = xor_mapped(body, tid)
            local_ip, local_port = s.getsockname()[:2]
            assert (ip, port) == (local_ip, local_port), \
                f"mapped {ip}:{port}, expected {local_ip}:{local_port}"

print("tls OK: handshake + binding x2 with correct XOR-MAPPED-ADDRESS")
