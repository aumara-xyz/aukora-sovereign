# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import binascii
import hashlib
import json
import re

COLD_PROOF_V1 = "aukora-aura-cold-proof-v1"
COLD_PROOF_V2 = "aukora-aura-cold-proof-v2"
RETAINED_HEAD_V1 = "aukora-aura-retained-head-v1"
PRESENTED_HEAD_V1 = "aukora-aura-presented-head-v1"
LEAF_CONVENTION = "rfc6962-leaf-sha256-0x00-prefixed-v1"
AURA_DOMAIN = "aukora:aura-record:v1"
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_INPUT = 8_388_608
KINDS = frozenset((
    "boot.facts gate.propose gate.review gate.consume gate.apply gate.retire "
    "gate.refuse gate.expire gate.recover floor.advance aumlok.enrol aumlok.bind "
    "aumlok.signin broker.grant broker.reserve broker.settle broker.revoke "
    "kira.save kira.demote kira.permission sandbox.start sandbox.exit nostr.bind"
).split())
ROW_KEYS = frozenset("seq prev hash sig at kind actor op phase body".split())
class Refusal(ValueError):
    """Stable refusal data, optionally locating a row in supplied observations."""
    def __init__(self, code, sequence=None, exact_location=True):
        super().__init__(code)
        self.code = code
        self.sequence = sequence
        self.exact_location = exact_location
def _require(condition, reason, sequence=None, exact=True):
    if not condition: raise Refusal("verifier:" + reason, sequence, exact)
def export_version(schema: str):
    _require(schema in (COLD_PROOF_V1, COLD_PROOF_V2), "unsupported-schema")
    return schema
def _cold(value):
    _require(isinstance(value, dict), "bundle-format")
    export_version(value.get("schema"))
    if value["schema"] == COLD_PROOF_V1:
        _require(set(value) == {"schema", "publicKey", "head", "rows"}, "bundle-format")
        return value, None
    body = value.get("body")
    _require(set(value) == {"schema", "body"} and isinstance(body, dict)
             and set(body) == {"proof", "owner_assertions"} and isinstance(body["owner_assertions"], list), "bundle-format")
    proof = body["proof"]
    _require(isinstance(proof, dict) and proof.get("schema") == COLD_PROOF_V1, "bundle-format")
    return _cold(proof)[0], body["owner_assertions"]
def _integer(token):
    _require(re.fullmatch(r"0|-?[1-9][0-9]*", token) is not None, "json-integer")
    _require(len(token) <= 17, "json-integer-range")
    number = int(token)
    _require(abs(number) <= MAX_SAFE_INTEGER, "json-integer-range")
    return number
def _forbidden_number(_token):
    raise Refusal("verifier:json-number")
def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "json-duplicate-key")
        result[key] = value
    return result
def _validate(value, depth=0):
    if isinstance(value, (dict, list)):
        _require(depth < 64, "json-depth")
        children = list(value) + list(value.values()) if isinstance(value, dict) else value
        for child in children:
            _validate(child, depth + 1)
    elif isinstance(value, str):
        _require(all(not 0xD800 <= ord(char) <= 0xDFFF for char in value), "json-surrogate")
    elif type(value) is int:
        _require(abs(value) <= MAX_SAFE_INTEGER, "json-integer-range")
    else:
        _require(value is None or type(value) is bool, "json-value")
def _canonical(value):
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(_canonical(key) + ":" + _canonical(value[key]) for key in keys) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
def _bytes(value):
    return _canonical(value).encode("utf-8")
def _same(left, right):
    return _bytes(left) == _bytes(right)
def _parse(raw, canonical=False):
    _require(isinstance(raw, bytes), "expected-bytes")
    _require(len(raw) <= MAX_INPUT, "input-too-large")
    _require(not raw.startswith(b"\xef\xbb\xbf"), "json-bom")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                           parse_int=_integer, parse_float=_forbidden_number,
                           parse_constant=_forbidden_number)
        _validate(value)
        if canonical:
            _require(_bytes(value) == raw, "json-not-canonical")
        return value
    except Refusal:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("verifier:json") from None
def _hex(value, size=32, reason="bad-digest"):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % (size * 2), value) is not None, reason)
    return bytes.fromhex(value)
def _size(value):
    return type(value) is int and 0 <= value <= MAX_SAFE_INTEGER
def _sha(raw):
    return hashlib.sha256(raw).digest()
def _node(left, right):
    return _sha(b"\x01" + left + right)
def _root(leaves):
    if not leaves:
        return _sha(b"")
    if len(leaves) == 1:
        return leaves[0]
    cut = 1 << ((len(leaves) - 1).bit_length() - 1)
    return _node(_root(leaves[:cut]), _root(leaves[cut:]))
def _checked_key(key):
    try:
        from nacl.bindings import crypto_core_ed25519_is_valid_point
    except ImportError:
        raise Refusal("verifier:crypto-unavailable") from None
    _require(crypto_core_ed25519_is_valid_point(key), "key-weak")
    return key
def _key(raw):
    if isinstance(raw, str):
        raw = raw.encode("ascii")
    _require(isinstance(raw, bytes), "key-encoding")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise Refusal("verifier:key-encoding") from None
    if text.endswith("\n"):
        text = text[:-1]
    return _checked_key(_hex(text, reason="key-encoding"))
def _ed25519(key, message, text):
    try:
        from nacl.bindings import crypto_core_ed25519_is_valid_point, crypto_sign_open
        from nacl.exceptions import BadSignatureError
    except ImportError:
        raise Refusal("verifier:crypto-unavailable") from None
    _require(isinstance(text, str), "signature")
    try:
        signature = base64.b64decode(text, validate=True)
        _require(len(signature) == 64 and base64.b64encode(signature).decode("ascii") == text, "signature")
        _require(crypto_core_ed25519_is_valid_point(key)
                 and crypto_core_ed25519_is_valid_point(signature[:32]), "signature")
        _require(crypto_sign_open(signature + message, key) == message, "signature")
    except (ValueError, TypeError, binascii.Error, BadSignatureError):
        raise Refusal("verifier:signature") from None
def _schnorr(key, message, signature, reason):
    try:
        from coincurve import PublicKeyXOnly
    except ImportError:
        raise Refusal("verifier:crypto-unavailable") from None
    raw = _hex(signature, 64, reason)
    try:
        valid = PublicKeyXOnly(key).verify(raw, message)
    except (ValueError, TypeError):
        valid = False
    _require(valid, reason)
