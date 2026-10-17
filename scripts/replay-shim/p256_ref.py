# SPDX-License-Identifier: AGPL-3.0-or-later
"""NIST P-256 ECDSA with SHA-256 in plain integer arithmetic, for scripts/verifier-vectors.py ONLY.

The replay signs one owner passkey assertion (to build the v2 export the owner rule is held to) and, where the
`cryptography` package is not installed, verifies it for the Python twin (cryptography/ is a thin adapter over this). It is
slow and not constant-time and holds no key that matters: the seed is the replay's own. The shipped verifier and the node
never import it. `selftest()` checks the public key and a signature of RFC 6979, appendix A.2.5, before the replay relies on it.
"""
import hashlib

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p, q):
    if p is None or q is None:
        return q if p is None else p
    if p[0] == q[0]:
        if (p[1] + q[1]) % P == 0:
            return None
        slope = (3 * p[0] * p[0] - 3) * pow(2 * p[1], -1, P) % P
    else:
        slope = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (slope * slope - p[0] - q[0]) % P
    return x, (slope * (p[0] - x) - p[1]) % P


def _mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _add(result, point)
        point, k = _add(point, point), k >> 1
    return result


def on_curve(point):
    return (point[1] * point[1] - (point[0] ** 3 - 3 * point[0] + B)) % P == 0


def public_point(d):
    return _mul(d, G)


def encode(point):
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def decode(data):
    """The point for a SEC1 encoding (uncompressed or compressed); ValueError when it is not on the curve."""
    if len(data) == 65 and data[0] == 4:
        point = int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big")
    elif len(data) == 33 and data[0] in (2, 3):
        x = int.from_bytes(data[1:], "big")
        y = pow((x ** 3 - 3 * x + B) % P, (P + 1) // 4, P)
        point = x, (y if y & 1 == data[0] & 1 else P - y)
    else:
        raise ValueError("not a SEC1 point")
    if not (0 <= point[0] < P and 0 <= point[1] < P and on_curve(point)):
        raise ValueError("not on the curve")
    return point


def _der(r, s):
    def integer(value):
        raw = value.to_bytes((value.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(raw)]) + raw
    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def _undo_der(signature):
    if len(signature) < 8 or signature[0] != 0x30 or signature[1] != len(signature) - 2 or signature[2] != 2:
        raise ValueError("not DER")
    n = signature[3]
    if signature[4 + n] != 2 or signature[5 + n] != len(signature) - 6 - n:
        raise ValueError("not DER")
    return int.from_bytes(signature[4:4 + n], "big"), int.from_bytes(signature[6 + n:], "big")


def sign(d, message):
    """DER ECDSA over SHA-256(message); the nonce is derived from the key and message (deterministic, fine for a replay)."""
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    counter = 0
    while True:
        k = int.from_bytes(hashlib.sha256(d.to_bytes(32, "big") + message + bytes([counter])).digest(), "big") % N
        point = _mul(k, G) if k else None
        r = point[0] % N if point else 0
        s = pow(k, -1, N) * (z + r * d) % N if r else 0
        if r and s:
            return _der(r, N - s if s > N // 2 else s)
        counter += 1


def verify(point, message, signature):
    try:
        r, s = _undo_der(signature)
    except (ValueError, IndexError):
        return False
    if not (0 < r < N and 0 < s < N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, N)
    candidate = _add(_mul(z * w % N, G), _mul(r * w % N, point))
    return candidate is not None and candidate[0] % N == r


def selftest():
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    point = public_point(d)
    assert point == (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
                     0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299), "P-256 public key"
    known = _der(0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
                 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8)
    assert verify(point, b"sample", known), "RFC 6979 A.2.5 signature"
    assert not verify(point, b"Sample", known), "a different message must not verify"
    assert verify(point, b"round trip", sign(d, b"round trip")), "sign then verify"
    assert decode(encode(point)) == point and decode(bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")) == point
