# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ed25519 (RFC 8032) in plain integer arithmetic, for scripts/verifier-vectors.py ONLY.

The replay needs to sign rows (to build the forged and re-signed ledgers the vectors describe) and, where PyNaCl is not
installed, to verify them for the Python twin (nacl/bindings.py is a thin adapter over this). It is slow and not
constant-time and holds no key that matters: the seeds are the vectors' own. The shipped verifier and the node never
import it. `selftest()` checks it against RFC 8032, section 7.1, before the replay relies on it.
"""
import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P != 0:
        return None
    if x == 0 and sign:
        return None
    return P - x if x & 1 != sign else x


_BY = 4 * pow(5, P - 2, P) % P
_BX = _recover_x(_BY, 0)
BASE = (_BX, _BY, 1, _BX * _BY % P)
IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _multiply(scalar, point):
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def _encode(point):
    zinv = pow(point[2], P - 2, P)
    x, y = point[0] * zinv % P, point[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(encoded):
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _expand(seed):
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    return (scalar & ((1 << 254) - 8)) | (1 << 254), digest[32:]


def public_key(seed):
    return _encode(_multiply(_expand(seed)[0], BASE))


def sign(seed, message):
    scalar, prefix = _expand(seed)
    public = _encode(_multiply(scalar, BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    commitment = _encode(_multiply(r, BASE))
    k = int.from_bytes(hashlib.sha512(commitment + public + message).digest(), "little") % L
    return commitment + ((r + k * scalar) % L).to_bytes(32, "little")


def is_valid_point(encoded):
    """A canonical encoding of a point that is not of small order and lies in the prime-order subgroup."""
    point = _decode(bytes(encoded))
    return point is not None and not _equal(_multiply(8, point), IDENTITY) and _equal(_multiply(L, point), IDENTITY)


def verify(signature, message, public):
    """True when `signature` over `message` verifies under `public` (canonical scalar, canonical points)."""
    if len(signature) != 64 or len(public) != 32:
        return False
    key, commitment = _decode(public), _decode(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    if key is None or commitment is None or scalar >= L:
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    return _equal(_multiply(scalar, BASE), _add(commitment, _multiply(challenge, key)))


# RFC 8032, section 7.1, tests 1 and 2: (secret seed, public key, message, signature), all hex.
_VECTORS = (
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
)


def selftest():
    """Raise AssertionError unless RFC 8032 keys and signatures reproduce and any single changed bit is refused."""
    for seed, public, message, signature in _VECTORS:
        seed, public, message, signature = (bytes.fromhex(item) for item in (seed, public, message, signature))
        assert public_key(seed) == public and sign(seed, message) == signature
        assert is_valid_point(public) and verify(signature, message, public)
        for position in (0, 31, 32, 63):
            changed = bytearray(signature)
            changed[position] ^= 1
            assert not verify(bytes(changed), message, public), "a changed signature was accepted"
    assert not is_valid_point(bytes(32))
