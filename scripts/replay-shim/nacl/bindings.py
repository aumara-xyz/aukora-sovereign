# SPDX-License-Identifier: AGPL-3.0-or-later
"""The two PyNaCl calls tools/verify.py makes, over ed25519_ref (the replay's reference Ed25519). See __init__.py."""
import ed25519_ref

from .exceptions import BadSignatureError


def crypto_core_ed25519_is_valid_point(encoded):
    return ed25519_ref.is_valid_point(encoded)


def crypto_sign_open(signed, public):
    """The message when `signed` (signature then message) verifies under `public`; BadSignatureError otherwise."""
    signature, message = signed[:64], signed[64:]
    if not ed25519_ref.verify(signature, message, public):
        raise BadSignatureError()
    return message


def selftest():
    ed25519_ref.selftest()
