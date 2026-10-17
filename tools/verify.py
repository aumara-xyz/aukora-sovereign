#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Standalone offline verifier; regenerate with python3 -B tools/verify/build.py."""
# Generated from tools/verify; implementation statements retain their parsed form.
import argparse, base64, binascii, hashlib, json, os, re, stat, sys
COLD_PROOF_V1 = "aukora-aura-cold-proof-v1"
COLD_PROOF_V2 = "aukora-aura-cold-proof-v2"
RETAINED_HEAD_V1 = "aukora-aura-retained-head-v1"
PRESENTED_HEAD_V1 = "aukora-aura-presented-head-v1"
LEAF_CONVENTION = "rfc6962-leaf-sha256-0x00-prefixed-v1"
AURA_DOMAIN = "aukora:aura-record:v1"
AUTHORITY_WRAPPER = "aukora-aura-authority-body-v1"
UNLINKED_OWNER_KINDS = ("broker.grant", "broker.revoke", "kira.permission")
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
def _finding(code, sequence=None, exact=True):
    return {"code": "verifier:" + code, "sequence": sequence, "exact_location": exact}
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
def _authorization(value, current=True):
    required = {"v", "node", "subject", "op", "proposal", "target", "base_sha256", "new_sha256",
                "cell", "display_sha256", "challenge", "expires_at"}
    metadata = {"epoch", "operation", "owner_epoch", "owner_root_id", "binding_sha256", "issued_at", "issued_at_ms", "gate", "pubkey_fp"}
    _require(isinstance(value, dict) and required <= set(value) <= required | metadata, "gate-evidence")
    has_epoch = "epoch" in value
    _require(has_epoch == ("operation" in value) and (not current or has_epoch), "gate-evidence")
    for field in ("node", "proposal", "challenge"):
        _hex(value[field], 16, "gate-evidence")
    for field in ("new_sha256", "display_sha256"):
        _hex(value[field], reason="gate-evidence")
    _require(type(value["v"]) is int and value["v"] == 1
             and _size(value["expires_at"]) and value["expires_at"] > 0 and isinstance(value["subject"], str)
             and re.fullmatch(r"aukora:1:[0-9a-f]{64}", value["subject"]) is not None
             and value["op"] in ("apply", "retire", "release", "grant", "permission")
             and isinstance(value["target"], str) and bool(value["target"])
             and (value["cell"] is None or isinstance(value["cell"], dict)), "gate-evidence")
    if value["base_sha256"] != "absent":
        _hex(value["base_sha256"], reason="gate-evidence")
    if value["cell"] is not None:
        _require(set(value["cell"]) == {"module_sha256", "input_sha256", "effect_sha256"}, "gate-evidence")
        for digest in value["cell"].values():
            _hex(digest, reason="gate-evidence")
    if has_epoch:
        _require(type(value["epoch"]) is int and value["epoch"] > 0, "gate-evidence")
        _hex(value["operation"], reason="gate-evidence")
        content = {field: value[field] for field in ("v", "node", "target", "base_sha256", "new_sha256", "cell")}
        _require(_sha(b"aukora:operation-content:v1\x00" + _bytes(content)).hex() == value["operation"], "gate-evidence")
        _require("owner_epoch" not in value or _same(value["owner_epoch"], value["epoch"]), "gate-evidence")
    for field in ("owner_root_id", "binding_sha256", "gate"):
        if field in value:
            _hex(value[field], reason="gate-evidence")
    _require(not {"owner_root_id", "binding_sha256"} <= set(value)
             or value["owner_root_id"] == value["binding_sha256"], "gate-evidence")
    for field in ("issued_at", "issued_at_ms"):
        if field in value:
            _require(_size(value[field]) and 0 < value[field] < value["expires_at"], "gate-evidence")
    _require(not {"issued_at", "issued_at_ms"} <= set(value)
             or _same(value["issued_at"], value["issued_at_ms"]), "gate-evidence")
    _require("pubkey_fp" not in value or isinstance(value.get("gate"), str)
             and value["pubkey_fp"] == value["gate"][:16], "gate-evidence")
    return value
def _owner_key(raw):
    try:
        value = raw.decode("ascii")
    except (AttributeError, UnicodeError):
        raise Refusal("verifier:owner-key-encoding") from None
    key = _hex(value.removesuffix("\n"), 65, "owner-key-encoding")
    _require(key[0] == 4, "owner-key-encoding")
    return key
def _standard(value, limit):
    _require(isinstance(value, str) and len(value) <= 4 * ((limit + 2) // 3), "owner-proof-format")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Refusal("verifier:owner-proof-format") from None
    _require(len(raw) <= limit and base64.b64encode(raw).decode("ascii") == value, "owner-proof-format")
    return raw
def _client_data(raw):
    def check(value, depth=0):
        if isinstance(value, (dict, list)):
            _require(depth < 512, "owner-proof-invalid")
            for item in (list(value) + list(value.values()) if isinstance(value, dict) else value):
                check(item, depth + 1)
        elif isinstance(value, str):
            _require(all(not 0xD800 <= ord(char) <= 0xDFFF for char in value), "owner-proof-invalid")
        elif type(value) in (int, float):
            _require(abs(value) <= MAX_SAFE_INTEGER, "owner-proof-invalid")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_object, parse_constant=_forbidden_number)
        _require(isinstance(value, dict), "owner-proof-invalid")
        check(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("verifier:owner-proof-invalid") from None
def _owner_assertion(entry, row, rows, pinned):
    binding, proof = entry["binding"], entry["proof"]
    _require(isinstance(binding, dict) and set(binding) == {
        "schema", "v", "algorithm", "credential", "key", "epoch", "relying_party", "owner_origin", "top_origin", "counter"}
        and binding["schema"] == "aukora-aura-owner-binding-storage-v1", "owner-proof-format")
    _require(isinstance(proof, dict) and set(proof) == {"authorization", "credential", "authenticator_data",
        "client_data_json", "signed_bytes", "public_keys", "signatures"}, "owner-proof-format")
    auth = _authorization(proof["authorization"])
    _require(set(auth) == set("v node subject op proposal target base_sha256 new_sha256 cell display_sha256 challenge expires_at epoch operation".split()), "owner-proof-format")
    _require(type(binding["v"]) is int and binding["v"] == 1 and binding["algorithm"] == "ecdsa-p256-sha256"
             and type(binding["epoch"]) is int and binding["epoch"] == auth["epoch"] and type(binding["counter"]) is int and 0 <= binding["counter"] <= 0xffffffff, "owner-proof-invalid")
    key, signatures = binding["key"], proof["signatures"]
    _require(isinstance(signatures, dict) and set(signatures) == {"v", "components"}
             and type(signatures["v"]) is int and signatures["v"] == 1 and isinstance(signatures["components"], list)
             and len(signatures["components"]) == 1, "owner-proof-format")
    signature = signatures["components"][0]
    for component in (key, signature):
        _require(isinstance(component, dict) and set(component) == {"v", "algorithm", "bytes"}
                 and type(component["v"]) is int and component["v"] == 1
                 and component["algorithm"] == binding["algorithm"], "owner-proof-format")
    _require(_same(proof["public_keys"], [key]), "owner-proof-invalid")
    public = _standard(key["bytes"], 65)
    _require(len(public) == 65 and public[0] == 4 or len(public) == 33 and public[0] in (2, 3), "owner-proof-invalid")
    credential = _standard(binding["credential"], 1024)
    _require(bool(credential) and proof["credential"] == base64.urlsafe_b64encode(credential).decode("ascii").rstrip("="), "owner-proof-invalid")
    _require(all(isinstance(binding[field], str) and bool(binding[field]) for field in ("relying_party", "owner_origin", "top_origin")), "owner-proof-invalid")
    authenticator = _standard(proof["authenticator_data"], 37)
    client, sig = _standard(proof["client_data_json"], 16_384), _standard(signature["bytes"], 128)
    _require(len(authenticator) == 37 and authenticator[32] in (5, 13, 29)
             and authenticator[:32] == _sha(binding["relying_party"].encode("utf-8")), "owner-proof-invalid")
    counter = int.from_bytes(authenticator[33:], "big")
    _require(binding["counter"] == 0 or counter > binding["counter"], "owner-counter-replay")
    fields = _client_data(client)
    challenge = base64.urlsafe_b64encode(_sha(b"aukora:owner-authorization:v1\0" + _bytes(auth))).decode("ascii").rstrip("=")
    _require(all(fields.get(name) == expected for name, expected in (
        ("type", "webauthn.get"), ("challenge", challenge), ("origin", binding["owner_origin"]),
        ("topOrigin", binding["top_origin"]))) and fields.get("crossOrigin") is True, "owner-proof-invalid")
    signed = authenticator + _sha(client)
    _require(_standard(proof["signed_bytes"], 69) == signed and bool(sig), "owner-proof-invalid")
    _owner_row(row, rows, auth, proof)
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        raise Refusal("verifier:crypto-unavailable") from None
    try:
        verification_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
        normalized = verification_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        _require(pinned is None or normalized == pinned, "owner-key-mismatch")
        verification_key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
    except Refusal:
        raise
    except UnsupportedAlgorithm:
        raise Refusal("verifier:crypto-unavailable") from None
    except (InvalidSignature, ValueError):
        raise Refusal("verifier:owner-signature") from None
    return normalized, counter
def _owner_assertions(rows, entries, owner_key):
    pinned = None if owner_key is None else _owner_key(owner_key)
    if entries is None: return False
    for row in rows: _owner_standing(rows, row)
    expected = [row for row in rows if _owner_required(rows, row)]
    _require(len(entries) == len(expected), "owner-assertions-coverage")
    counters, credentials, approvals, challenges = {}, {}, set(), set()
    for entry, row in zip(entries, expected):
        number = row["seq"]
        try:
            _require(isinstance(entry, dict) and set(entry) == {"sequence", "binding", "proof"}
                     and type(entry["sequence"]) is int and entry["sequence"] == number, "owner-assertions-coverage")
            credential, counter = _owner_assertion(entry, row, rows, pinned)
            _require(credentials.setdefault(entry["binding"]["credential"], credential) == credential, "owner-proof-invalid")
            approval = _sha(_bytes(entry["proof"]["authorization"]))
            _require(approval not in approvals and entry["proof"]["authorization"]["challenge"] not in challenges, "owner-proof-replay")
            approvals.add(approval); challenges.add(entry["proof"]["authorization"]["challenge"])
            previous = counters.get(credential)
            _require(previous is None or entry["binding"]["counter"] >= previous
                     and (previous == 0 and counter == 0 or counter > previous), "owner-counter-replay")
            counters[credential] = counter
        except Refusal as error:
            if error.sequence is None: error.sequence = number
            raise
        except (ValueError, TypeError, KeyError):
            raise Refusal("verifier:owner-proof-format", number) from None
    return pinned is not None and bool(entries)
def _owner_standing(rows, row):
    if row["kind"] != "gate.consume": return
    body = _owner_payload(row)
    _require("standing_permission" not in body, "owner-standing-format")
    if "standing" not in body: return
    reference = body["standing"]
    _require(isinstance(reference, dict) and set(reference) == {
        "permission", "permission_proposal", "permission_digest", "proposal", "operation", "use_number"}, "owner-standing-format")
    _require(row["phase"] == "settle" and row["actor"] == "owner" and body.get("state") == "consumed"
             and _size(reference["use_number"]) and reference["use_number"] > 0
             and all(reference[field] == body.get(field) for field in ("proposal", "operation"))
             and _sha(_bytes(reference)).hex() == body.get("consumed_approval"), "owner-proof-context")
    grants = [grant for grant in rows[:row["seq"] - 1] if grant["kind"] == "gate.apply" and grant["op"] == reference["permission"]]
    _require(len(grants) == 1, "owner-proof-context")
    grant, permission = grants[0], _owner_payload(grants[0])
    _require(_owner_required(rows, grant) and grant["phase"] == "terminal" and grant["actor"] == "owner"
             and permission.get("state") == "applied" and permission.get("proposal") == reference["permission_proposal"]
             and permission.get("new_sha256") == reference["permission_digest"]
             and grant["body"].get("epoch") == row["body"].get("epoch") and "epoch" in row["body"], "owner-proof-context")
def _owner_payload(row):
    body = row["body"]
    if body.get("schema") != AUTHORITY_WRAPPER: return body
    _require(set(body) == {"schema", "algorithm", "epoch", "sequence", "previous_hash", "payload"}
             and body["algorithm"] == "sha256" and type(body["sequence"]) is int
             and body["sequence"] == row["seq"] and body["previous_hash"] == row["prev"]
             and _size(body["epoch"]) and isinstance(body["payload"], dict), "owner-proof-context")
    return body["payload"]
def _owner_needed(rows):
    try: return any(_owner_required(rows, row) for row in rows)
    except Refusal: return True
def _owner_effect(same, row):
    payload = _owner_payload(row)
    if row["kind"] != "gate.apply" or payload.get("target") == "gate/permission": return
    consumed = [other for other in same if other["seq"] < row["seq"] and other["kind"] == "gate.consume" and _owner_linked(other, payload)]
    _require(bool(row["op"]) and len(consumed) == 1 and sum(other["kind"] == "gate.apply" for other in same) == 1, "gate-reference")
def _owner_linked(row, applied):
    try: earlier = _owner_payload(row)
    except Refusal: return False
    return row["phase"] == "settle" and earlier.get("state") == "consumed" and all(name in earlier and name in applied and earlier[name] == applied[name] for name in ("proposal", "target", "operation", "new_sha256"))
def _owner_required(rows, row):
    payload = _owner_payload(row)
    if row["kind"] == "gate.consume":
        try: _owner_standing(rows, row)
        except Refusal: return True
        return "standing" not in payload
    return (row["kind"] in ("gate.retire", "floor.advance")
            or row["kind"] == "gate.apply" and payload.get("target") == "gate/permission"
            or row["kind"] == "aumlok.bind" and payload.get("schema") not in (
                "aukora-aumlok-initial-binding-v2", "aukora-aumlok-envelope-refresh-v2"))
def _owner_row(row, rows, auth, proof):
    body, payload = row["body"], _owner_payload(row)
    _require(0 <= row["at"] < auth["expires_at"], "owner-proof-context")
    membership = "membership" in payload or isinstance(payload.get("body"), dict) and "membership" in payload["body"]
    _require(body.get("schema") == AUTHORITY_WRAPPER
             and body["epoch"] == auth["epoch"] + int(row["kind"] == "aumlok.bind" and membership)
             and row["actor"] == (auth["subject"] if row["kind"] in ("aumlok.bind", "floor.advance") else "owner"), "owner-proof-context")
    proposals = [_owner_payload(prior) for prior in rows[:row["seq"] - 1]
                 if prior["kind"] == "gate.propose" and prior["phase"] == "intent" and prior["op"] == row["op"]]
    _require(len(proposals) == 1 and all(proposals[0].get(field) == auth[field] for field in ("proposal", "target", "operation")), "owner-proof-context")
    digest = _sha(_bytes(auth)).hex()
    if row["kind"] in ("gate.consume", "gate.retire", "gate.apply"):
        action, phase, state = {"gate.consume": ("apply", "settle", "consumed"),
            "gate.retire": ("retire", "terminal", "retired"), "gate.apply": ("permission", "terminal", "applied")}[row["kind"]]
        _require(auth["op"] == action and row["phase"] == phase and payload.get("state") == state
                 and payload.get("consumed_approval") == digest
                 and all(payload.get(field) == auth[field] for field in ("proposal", "target", "operation", "new_sha256"))
                 and ("base_sha256" not in payload or payload["base_sha256"] == auth["base_sha256"]), "owner-proof-context")
    elif row["kind"] == "floor.advance":
        floor = payload.get("floor")
        _require(row["phase"] == "terminal" and auth["op"] == "release" and auth["target"] == "release"
                 and set(payload) == {"schema", "floor", "proposal", "authorization_sha256"}
                 and payload.get("schema") == "aukora-floor-advance-v1" and payload.get("proposal") == auth["proposal"]
                 and payload.get("authorization_sha256") == digest and isinstance(floor, dict)
                 and floor.get("record") == auth["new_sha256"] and type(floor.get("signer_epoch")) is int and floor["signer_epoch"] == auth["epoch"], "owner-proof-context")
    else: _owner_bind(row, payload, auth)
def _owner_bind(row, payload, auth):
    key_fields = "v algorithm key_id role material scope epoch operation_id"
    device_fields = "v algorithm subject node epoch membership device_key scope copresence operation_id"
    bounded, wrapper = payload, None
    if set(payload) == {"schema", "epoch", "body"}:
        _require(payload["schema"] == "aukora:aumlok-person-nostr-binding:v1"
                 and type(payload["epoch"]) is int and 0 <= payload["epoch"] <= 0xffffffff, "owner-proof-context")
        bounded, wrapper = payload["body"], "person-nostr-binding"
    elif set(payload) == {"v", "body", "possession"}:
        bounded, wrapper = payload["body"], "device-approval"
        _require(type(payload["v"]) is int and payload["v"] == 1, "owner-proof-context")
    _require(isinstance(bounded, dict), "owner-proof-context")
    shapes = ((key_fields, "key-binding", "key_id", "aumlok:key:"),
        ("v algorithm key_id epoch operation_id", "key-revocation", "key_id", "aumlok:key:"),
        ("v algorithm parent issuer delegate from to scope version id signatures", "delegation", "id", "aumlok:delegation:"),
        ("v algorithm delegation_id epoch operation_id", "delegation-revocation", "delegation_id", "aumlok:delegation:"),
        (device_fields, "device-approval", "subject", "aumlok.devices:"),
        ("v algorithm subject node device membership operation_id", "device-revocation", "subject", "aumlok.devices:"))
    matching = [(domain, field, prefix) for fields, domain, field, prefix in shapes if set(bounded) == set(fields.split())]
    _require(len(matching) == 1, "owner-proof-context")
    domain, field, prefix = matching[0]
    _require((wrapper is None and domain != "device-approval") or wrapper == domain
             or wrapper == "person-nostr-binding" and domain == "key-binding" and bounded["role"] == "person-nostr", "owner-proof-context")
    if field != "subject": _hex(bounded[field], reason="owner-proof-context")
    contexts = ([bounded] if "subject" in bounded else []) + ([bounded["scope"]] if "scope" in bounded else [])
    if "membership" in bounded:
        membership = bounded["membership"]
        _require(isinstance(membership, dict) and set(membership) == {"previous", "next", "expected", "next_epoch"}
                 and type(membership["next_epoch"]) is int and membership["next_epoch"] == auth["epoch"] + 1, "owner-proof-context")
        _owner_epoch(membership["expected"], auth["epoch"])
    if domain == "device-approval":
        key = bounded["device_key"]
        _require(isinstance(key, dict) and set(key) == set(key_fields.split()) and type(key["v"]) is int and key["v"] == 1
                 and key["role"] == "device" and type(key["epoch"]) is int and key["epoch"] == auth["epoch"] + 1
                 and key["operation_id"] == row["op"], "owner-proof-context")
        contexts.append(key["scope"])
    if domain == "device-revocation": _hex(bounded["device"], reason="owner-proof-context")
    if domain == "delegation": _owner_epoch(bounded["version"], auth["epoch"])
    _require(all(isinstance(context, dict) and all(context.get(name) == auth[name] for name in ("subject", "node"))
                 for context in contexts), "owner-proof-context")
    _require(type(bounded["v"]) is int and bounded["v"] == 1 and (domain == "key-binding" or bounded["algorithm"] == "sha256")
             and row["kind"] == "aumlok.bind" and row["phase"] == "terminal" and auth["op"] == "permission"
             and auth["cell"] is None and auth["target"] == prefix + bounded[field]
             and ("operation_id" not in bounded or bounded["operation_id"] == row["op"])
             and ("epoch" not in bounded or type(bounded["epoch"]) is int and bounded["epoch"] == row["body"]["epoch"])
             and _sha(("aukora:aumlok-" + (wrapper or domain) + ":v1\0").encode("ascii") + _bytes(payload)).hex() == auth["new_sha256"], "owner-proof-context")
def _owner_epoch(value, epoch):
    _require(isinstance(value, dict) and set(value) == {"epoch", "sequence", "previous_hash"} and type(value["epoch"]) is int and value["epoch"] == epoch, "owner-proof-context")
def _head(value):
    columns = {"schema", "leafConvention", "sequence", "hash", "treeSize", "root"}
    _require(isinstance(value, dict) and set(value) == columns, "retained-format")
    _require(value["schema"] == RETAINED_HEAD_V1 and value["leafConvention"] == LEAF_CONVENTION, "retained-format")
    _require(_size(value["treeSize"]) and value["treeSize"] > 0
             and type(value["sequence"]) is int and value["sequence"] == value["treeSize"], "head-size")
    _hex(value["hash"])
    _hex(value["root"])
    return value
def _anchor(head, rows, leaves):
    count = head["treeSize"]
    _require(count <= len(rows), "shorter-than-checkpoint", len(rows) + 1)
    _require(rows[count - 1]["hash"] == head["hash"] and _root(leaves[:count]).hex() == head["root"],
             "checkpoint-mismatch", count, False)
def _npub(key):
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    bits = int.from_bytes(key, "big") << 4
    data = [(bits >> shift) & 31 for shift in range(255, -1, -5)]
    prefix = [ord(char) >> 5 for char in "npub"] + [0] + [ord(char) & 31 for char in "npub"]
    checksum = 1
    for value in prefix + data + [0] * 6:
        high, checksum = checksum >> 25, ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, polynomial in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if high & (1 << index):
                checksum ^= polynomial
    checksum ^= 1
    suffix = [(checksum >> shift) & 31 for shift in range(25, -1, -5)]
    return "npub1" + "".join(alphabet[value] for value in data + suffix)
def _nostr_binding(row, aura_key):
    body = row["body"]
    expected = {"schema", "node", "agent", "aura_key", "statement_sha256", "node_sig", "agent_sig"}
    _require(row["phase"] == "fact" and set(body) == expected and body["schema"] == "aukora-nostr-bind-v1", "nostr-binding-shape")
    _require(_hex(body["aura_key"], reason="hex") == aura_key, "nostr-aura-key")
    public = {}
    for role in ("node", "agent"):
        identity = body[role]
        _require(isinstance(identity, dict) and set(identity) == {"pubkey", "npub"}, "nostr-binding-shape")
        public[role] = _hex(identity["pubkey"], reason="hex")
        _require(identity["npub"] == _npub(public[role]), "nostr-npub")
    statement = {"domain": "aukora:nostr-identity-binding:v1", "aura_key": body["aura_key"],
                 "node": body["node"]["pubkey"], "agent": body["agent"]["pubkey"]}
    digest = _sha(_bytes(statement))
    _require(digest == _hex(body["statement_sha256"], reason="hex"), "nostr-statement")
    for role in public:
        _schnorr(public[role], digest, body[role + "_sig"], "nostr-" + role + "-signature")
def _walk(rows, key):
    _require(isinstance(rows, list), "bundle-rows")
    previous, leaves, operations, found, bindings = AURA_DOMAIN, [], {}, [], 0
    for number, row in enumerate(rows, 1):
        try:
            _require(isinstance(row, dict) and set(row) == ROW_KEYS, "row-columns")
            _require(type(row["seq"]) is int and row["seq"] == number, "sequence")
            _require(type(row["at"]) is int and row["kind"] in KINDS and row["phase"] in ("intent", "settle", "terminal", "fact")
                     and isinstance(row["body"], dict) and all(isinstance(row[field], str) for field in ("prev", "sig", "actor", "op")),
                     "bundle-row-schema")
            if row["op"]:
                _hex(row["op"], 16, "operation-id")
                operations.setdefault(row["op"], []).append(row)
            digest = _hex(row["hash"])
            _require(row["prev"] == previous, "prev-link")
            signed = {field: row[field] for field in ("at", "kind", "actor", "op", "phase", "body", "prev")}
            signed.update(sequence=number, domain=AURA_DOMAIN)
            _require(_sha(_bytes(signed)) == digest, "entry-hash")
            _ed25519(key, digest, row["sig"])
            if row["kind"] == "nostr.bind":
                bindings += 1
                _require(bindings == 1, "nostr-second-binding")
                _nostr_binding(row, key)
            previous = row["hash"]
            leaves.append(_sha(b"\x00" + digest))
        except Refusal as error:
            if error.sequence is None: error.sequence = number
            raise
        except (ValueError, TypeError, KeyError):
            raise Refusal("verifier:bundle-row-schema", number) from None
    for row in rows:
        if row["kind"] in UNLINKED_OWNER_KINDS:
            found.append(_finding("owner-provenance", row["seq"]))  # an owner proof this verifier cannot yet link
        if row["kind"] not in ("gate.consume", "gate.apply"):
            continue
        if row["body"].get("schema") != AUTHORITY_WRAPPER:
            found.append(_finding("owner-provenance", row["seq"]))  # the archive's flat rows: nothing says who approved them
            continue
        try:
            _owner_effect(operations.get(row["op"], []), row)  # held against the owner assertions and the rows it rests on
        except Refusal as error:
            if error.sequence is None: error.sequence = row["seq"]
            raise
    if any(sum(other["phase"] == "terminal" for other in group) != 1 for group in operations.values()): found.append(_finding("terminal-count", exact=False))
    return leaves, found
def _report(count, *, identity=False, covering=False, consistency=False, found=(), tree_root=True, owner=None, findings=None):
    missing = list(found) + list(findings or [])
    for checked, code in ((identity, "identity-no-pinned-key"), (covering, "completeness-no-covering-checkpoint"),
                          (tree_root, "tree-root-no-anchor"), (owner is not False, "owner-signatures-unchecked")):
        if not checked:
            missing.append(_finding(code))
    return {"verdict": "VERIFIED" if not missing else "UNCHECKED", "rows": count,
            "integrity": {"signatures": True, "chain": True, "tree_root": tree_root, "owner_bindings": not found and owner is not False},
            "observations": {"pinned_identity": identity, "covering_checkpoint": covering, "consistency": consistency},
            "findings": missing}
def verify_bundle(bundle: bytes, *, pinned_key=None, checkpoint=None, owner_key=None):
    value, assertions = _cold(_parse(bundle, canonical=True))
    key = _checked_key(_hex(value["publicKey"]))
    if pinned_key is not None:
        _require(_key(pinned_key) == key, "bundle-key-mismatch")
    head = _head(value["head"])
    rows = value["rows"]
    leaves, found = _walk(rows, key)
    _require(len(rows) == head["treeSize"], "bundle-tail-size", min(len(rows), head["treeSize"]) + 1)
    _anchor(head, rows, leaves)
    covering = False
    if checkpoint is not None:
        retained = _head(_parse(checkpoint))
        _anchor(retained, rows, leaves)
        covering = retained["treeSize"] == len(rows)
    owner_checked = _owner_assertions(rows, assertions, owner_key)
    return {**_report(len(rows), identity=pinned_key is not None, covering=covering, found=found,
                      owner=owner_checked if _owner_needed(rows) else None), "owner_signatures": owner_checked}
def _proof_result(old, new, proof):
    m, n = old["treeSize"], new["treeSize"]
    if m > n:
        return "UNDETERMINED", "invalid-tree-sizes"
    first, second = _hex(old["root"]), _hex(new["root"])
    if m == 0:
        return "UNDETERMINED", "missing-prior-observation"
    if m == n:
        if proof:
            return "UNDETERMINED", "non-empty-proof-for-same-size"
        return ("APPEND_ONLY", "identical-trees-match") if first == second else ("OBSERVATION_CONFLICT", "same-size-root-mismatch")
    if not proof:
        return "UNDETERMINED", "empty-proof-for-different-sizes"
    power_two = m & (m - 1) == 0
    position = 0 if power_two else 1
    left = right = first if power_two else proof[0]
    a, b = m - 1, n - 1
    while a & 1:
        a, b = a >> 1, b >> 1
    while b:
        if position == len(proof):
            return "UNDETERMINED", "proof-path-truncated"
        sibling = proof[position]
        position += 1
        if a & 1 or a == b:
            left, right = _node(sibling, left), _node(sibling, right)
            while a and not a & 1:
                a, b = a >> 1, b >> 1
        else:
            right = _node(right, sibling)
        a, b = a >> 1, b >> 1
    if position != len(proof):
        return "UNDETERMINED", "unconsumed-proof-elements"
    if right != second:
        return "UNDETERMINED", "power-of-two-prefix-not-independently-derivable" if power_two else "proof-did-not-connect-to-presented-head"
    if left == first:
        return "APPEND_ONLY", "valid-append-only-extension"
    return ("UNDETERMINED", "power-of-two-prefix-not-independently-derivable") if power_two else ("OBSERVATION_CONFLICT", "consistency-prefix-mismatch")
def verify_consistency(retained: bytes, presented: bytes):
    old, new = _head(_parse(retained)), _parse(presented)
    _require(isinstance(new, dict) and set(new) == {"schema", "leafConvention", "treeSize", "root", "retainedTreeSize", "proofFromPrevious"}
             and new["schema"] == PRESENTED_HEAD_V1 and new["leafConvention"] == LEAF_CONVENTION
             and _size(new["treeSize"]) and new["treeSize"] > 0 and _size(new["retainedTreeSize"]) and new["retainedTreeSize"] > 0
             and isinstance(new["proofFromPrevious"], list) and len(new["proofFromPrevious"]) <= 64, "presented-format")
    _hex(new["root"])
    proof = [_hex(item) for item in new["proofFromPrevious"]]
    verdict, reason = (("UNDETERMINED", "retained-proof-size") if new["retainedTreeSize"] != old["treeSize"]
                       else _proof_result(old, new, proof))
    return {"verdict": verdict, "retained_size": old["treeSize"], "presented_size": new["treeSize"], "reason": "verifier:" + reason}
def _rows(raw):
    _require(isinstance(raw, bytes) and len(raw) <= MAX_INPUT, "input-too-large")
    _require(bool(raw), "rows-format")
    lines, values = raw.split(b"\n"), []
    for number, line in enumerate(lines, 1):
        try:
            _require(number < len(lines) or not line, "rows-truncated", number)
            if number < len(lines):
                _require(bool(line) and b"\r" not in line, "rows-format", number)
                values.append(_parse(line, canonical=True))
        except Refusal as error:
            if error.sequence is None: error.sequence = number
            return values, error
    return values, None
def verify_chain(rows: bytes, *, pinned_key: bytes, retained=None,
                 presented=None, retained_rows=None, checkpoint=None):
    values, malformed = _rows(rows)
    key = _key(pinned_key)
    leaves, found = _walk(values, key)
    if malformed: raise malformed
    findings, consistent, covering, anchored = [], False, False, False
    if retained_rows is not None:
        earlier, malformed = _rows(retained_rows)
        if malformed: raise malformed
        _walk(earlier, key)
        for index, entry in enumerate(earlier):
            _require(index < len(values), "shorter-than-checkpoint", index + 1)
            _require(_same(entry, values[index]), "retained-row-mismatch", index + 1)
    _require((retained is None) == (presented is None), "observation-pair")
    if retained is not None:
        old, new = _head(_parse(retained)), _parse(presented)
        _anchor(old, values, leaves)
        covering = old["treeSize"] == len(values)
        proof = verify_consistency(retained, presented)
        _require(new["treeSize"] == len(values) and new["root"] == _root(leaves).hex(), "presented-head-mismatch")
        anchored = True
        _require(proof["verdict"] != "OBSERVATION_CONFLICT", "consistency-prefix-mismatch", old["treeSize"], False)
        consistent = proof["verdict"] == "APPEND_ONLY"
        if not consistent:
            findings.append({"code": proof["reason"], "sequence": None, "exact_location": False})
    if checkpoint is not None:
        kept = _head(_parse(checkpoint))
        _anchor(kept, values, leaves)
        covering = covering or kept["treeSize"] == len(values)
        anchored = anchored or kept["treeSize"] == len(values)
    return _report(len(values), identity=True, covering=covering, consistency=consistent, found=found, tree_root=anchored,
                    owner=False if _owner_needed(values) else None, findings=findings)
def _event_value(raw):
    _require(len(raw) <= 65_536, "witness-malformed")
    event = _parse(raw)
    columns = {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
    _require(isinstance(event, dict) and set(event) == columns and _size(event["created_at"])
             and _size(event["kind"]) and isinstance(event["content"], str), "witness-malformed")
    _require(isinstance(event["tags"], list) and all(isinstance(tag, list) and tag
             and all(isinstance(item, str) for item in tag) for tag in event["tags"]), "witness-malformed")
    digest, public = _hex(event["id"]), _hex(event["pubkey"])
    commitment = [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]]
    _require(_sha(_bytes(commitment)) == digest, "witness-malformed")
    _schnorr(public, digest, event["sig"], "witness-signature")
    _require(event["kind"] == 30078 and event["tags"] == [["d", "aukora-aura-head"]], "witness-malformed")
    return event
def _event(raw):
    try:
        return _event_value(raw)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:  # a Refusal is a ValueError
        if getattr(error, "code", "") == "verifier:crypto-unavailable":
            raise
        raise Refusal("verifier:witness-malformed") from None
def verify_witness(bundle: bytes, event: bytes, *, pinned_key=None, checkpoint=None, owner_key=None):
    signed = _event(event)
    try:
        observed = _parse(signed["content"].encode("utf-8"), canonical=True)
        _require(isinstance(observed, dict), "witness-malformed")
    except (Refusal, ValueError, UnicodeError, RecursionError):
        raise Refusal("verifier:witness-malformed") from None
    _require(_size(observed.get("treeSize")) and observed["treeSize"] > 0
             and type(observed.get("sequence")) is int
             and observed["sequence"] == observed["treeSize"], "witness-size")
    try:
        _head(observed)
    except Refusal:
        raise Refusal("verifier:witness-malformed") from None
    try:
        value, _ = _cold(_parse(bundle, canonical=True))
        _require(isinstance(value, dict) and isinstance(value.get("rows"), list), "witness-proof")
    except Refusal:
        raise Refusal("verifier:witness-proof") from None
    bindings = [row for row in value["rows"] if isinstance(row, dict) and row.get("kind") == "nostr.bind"]
    _require(len(bindings) == 1, "witness-binding")
    try:
        signer = _hex(bindings[0]["body"]["node"]["pubkey"])
    except (Refusal, ValueError, TypeError, KeyError):
        raise Refusal("verifier:witness-binding") from None
    _require(_hex(signed["pubkey"]) == signer, "witness-signer")
    try:
        report = verify_bundle(bundle, pinned_key=pinned_key, checkpoint=checkpoint, owner_key=owner_key)
    except Refusal as error:
        if error.code == "verifier:crypto-unavailable":
            raise
        raise Refusal("verifier:witness-proof") from None
    leaves = [_sha(b"\x00" + _hex(row["hash"])) for row in value["rows"]]
    try:
        _anchor(observed, value["rows"], leaves)
    except Refusal as error:
        raise Refusal("verifier:witness-size" if error.code == "verifier:shorter-than-checkpoint" else "verifier:witness-fork",
                      error.sequence, error.exact_location) from None
    report["witness"] = {"prefix": observed["treeSize"], "proof": len(value["rows"]), "signature": True, "binding": True}
    return report
def _read(path, limit=MAX_INPUT):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode), "input-not-regular")
        _require(info.st_size <= limit, "input-too-large")
        chunks, count = [], 0
        while count <= limit:
            chunk = os.read(descriptor, min(65_536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        _require(count <= limit, "input-too-large")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
def _render(report):
    print(report["verdict"] + " rows=1.." + str(report["rows"]))
    for finding in report["findings"]:
        print("UNCHECKED " + ("" if finding["sequence"] is None else "seq=" + str(finding["sequence"]) + " ") + finding["code"])
    if "witness" in report:
        print("WITNESS verified prefix=" + str(report["witness"]["prefix"]) + " proof=" + str(report["witness"]["proof"]))
    print("PASSKEY " + ("VERIFIED C5 owner approval signatures against independently pinned credential key"
                       if report.get("owner_signatures") else "UNCHECKED; supply a v2 export and --owner-key PIN.hex"))
    print("SCOPE supplied bytes and observations; occurrence, human identity and physical effects are independently unchecked")
    return 0 if report["verdict"] == "VERIFIED" else 1
def _failure(error):
    if error.code in ("verifier:bundle-key-mismatch", "verifier:owner-key-mismatch", "verifier:owner-signature"):
        print(("FORGED " if error.code == "verifier:owner-signature" else "KEY_MISMATCH ") + error.code)
        return 2
    if error.sequence is not None and error.code in {"verifier:signature", "verifier:nostr-node-signature", "verifier:nostr-agent-signature"}:
        print("FORGED seq=" + str(error.sequence) + " " + error.code)
        return 2
    changes = {"entry-hash", "prev-link", "sequence", "rows-truncated", "checkpoint-mismatch", "shorter-than-checkpoint",
               "bundle-tail-size", "retained-row-mismatch", "consistency-prefix-mismatch", "presented-head-mismatch", "witness-fork",
               "gate-evidence", "gate-reference"}
    located = {"row-columns", "bundle-row-schema", "bad-digest"}
    name = error.code.removeprefix("verifier:")
    if name in changes or (error.sequence is not None and name in located):
        location = "" if error.sequence is None else " seq=" + str(error.sequence)
        print("REWRITTEN" + location + " " + error.code)
        if error.sequence is not None:
            print("REWRITTEN first bad seq " + (str(error.sequence) if error.exact_location else "unknown; at or before " + str(error.sequence)))
        return 2
    print("UNCHECKED " + error.code)
    return 1 if error.code == "verifier:crypto-unavailable" else 64
class _Arguments(argparse.ArgumentParser):
    def __init__(self, **options):
        super().__init__(allow_abbrev=False, **options)
    def error(self, _message):
        raise Refusal("verifier:usage")
def main(arguments):
    try:
        options = [argument.replace("--prefix", "--retained-rows") for argument in arguments if argument.startswith("--")]
        _require(all("=" not in option for option in options), "usage")
        _require(len(options) == len(set(options)), "usage")
        if arguments and arguments[0] == "witness":
            parser = _Arguments(prog="verify.py witness")
            parser.add_argument("bundle")
            parser.add_argument("event")
            parser.add_argument("--key")
            parser.add_argument("--checkpoint")
            parser.add_argument("--owner-key", help="independently retained uncompressed P-256 SEC1 public key in lowercase hex")
            args = parser.parse_args(arguments[1:])
            return _render(verify_witness(_read(args.bundle), _read(args.event, 65_536),
                           pinned_key=_read(args.key) if args.key else None,
                           checkpoint=_read(args.checkpoint) if args.checkpoint else None,
                           owner_key=_read(args.owner_key, 131) if args.owner_key else None))
        if arguments and (arguments[0] == "chain" or "--rows" in arguments):
            parser = _Arguments(prog="verify.py chain")
            parser.add_argument("rows" if arguments[0] == "chain" else "--rows", **({} if arguments[0] == "chain" else {"required": True}))
            parser.add_argument("--key", required=True)
            for flag in ("retained", "presented", "checkpoint"):
                parser.add_argument("--" + flag)
            parser.add_argument("--retained-rows", "--prefix", dest="retained_rows")
            args = parser.parse_args(arguments[1:] if arguments[0] == "chain" else arguments)
            options = {name: _read(getattr(args, name)) if getattr(args, name) else None
                       for name in ("retained", "presented", "retained_rows", "checkpoint")}
            return _render(verify_chain(_read(args.rows), pinned_key=_read(args.key), **options))
        if "--bundle" in arguments:
            parser = _Arguments(prog="verify.py")
            parser.add_argument("--bundle", required=True)
            parser.add_argument("--key")
            parser.add_argument("--checkpoint")
            parser.add_argument("--owner-key", help="independently retained uncompressed P-256 SEC1 public key in lowercase hex")
            args = parser.parse_args(arguments)
            return _render(verify_bundle(_read(args.bundle), pinned_key=_read(args.key) if args.key else None,
                                         checkpoint=_read(args.checkpoint) if args.checkpoint else None,
                                         owner_key=_read(args.owner_key, 131) if args.owner_key else None))
        if arguments and arguments[0] == "consistency":
            arguments = arguments[1:]
        _require(len(arguments) == 2 and all(not arg.startswith("--") for arg in arguments), "usage")
        report = verify_consistency(_read(arguments[0]), _read(arguments[1]))
        print(report["verdict"] + " " + report["reason"])
        return {"APPEND_ONLY": 0, "OBSERVATION_CONFLICT": 2, "UNDETERMINED": 1}[report["verdict"]]
    except Refusal as error:
        return _failure(error)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print("UNCHECKED verifier:malformed-or-unreadable")
        return 64
__all__ = ('COLD_PROOF_V1', 'COLD_PROOF_V2', 'RETAINED_HEAD_V1', 'PRESENTED_HEAD_V1', 'LEAF_CONVENTION', 'AURA_DOMAIN', 'AUTHORITY_WRAPPER', 'UNLINKED_OWNER_KINDS', 'MAX_SAFE_INTEGER', 'MAX_INPUT', 'KINDS', 'ROW_KEYS', 'Refusal', '_require', '_finding', 'export_version', '_cold', '_owner_key', '_standard', '_client_data', '_owner_assertion', '_owner_assertions', '_owner_standing', '_owner_payload', '_owner_effect', '_owner_linked', '_owner_needed', '_owner_required', '_owner_row', '_owner_bind', '_owner_epoch', '_integer', '_forbidden_number', '_object', '_validate', '_canonical', '_bytes', '_same', '_parse', '_hex', '_size', '_sha', '_node', '_root', '_checked_key', '_key', '_ed25519', '_schnorr', '_head', '_anchor', '_authorization', '_npub', '_nostr_binding', '_walk', '_report', 'verify_bundle', '_proof_result', 'verify_consistency', '_rows', 'verify_chain', '_event_value', '_event', 'verify_witness', '_read', '_render', '_failure', '_Arguments', 'main')
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
