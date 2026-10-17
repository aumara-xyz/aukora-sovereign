# SPDX-License-Identifier: AGPL-3.0-or-later
"""The P-256 public-key calls tools/verify.py makes, over p256_ref (the replay's reference ECDSA). See ../../../__init__.py."""
import p256_ref

from cryptography.exceptions import InvalidSignature


class SECP256R1:
    name = "secp256r1"


class ECDSA:
    def __init__(self, algorithm):
        self.algorithm = algorithm


class EllipticCurvePublicKey:
    def __init__(self, point):
        self._point = point

    @classmethod
    def from_encoded_point(cls, curve, data):
        return cls(p256_ref.decode(bytes(data)))

    def public_bytes(self, encoding, format):
        return p256_ref.encode(self._point)

    def verify(self, signature, data, signature_algorithm):
        if not p256_ref.verify(self._point, bytes(data), bytes(signature)):
            raise InvalidSignature()


def selftest():
    p256_ref.selftest()
