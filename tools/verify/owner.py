# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import binascii
import json
from .common import (
    AUTHORITY_WRAPPER,
    MAX_SAFE_INTEGER,
    Refusal,
    _bytes,
    _forbidden_number,
    _hex,
    _object,
    _require,
    _same,
    _sha,
    _size,
)
from .gate import (
    _authorization,
)

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
    if body.get("standing") is None: return
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
# Whether any row needs a retained owner assertion; a row that cannot be read as one is held to the stricter answer.
def _owner_needed(rows):
    try: return any(_owner_required(rows, row) for row in rows)
    except Refusal: return True
# A wrapped apply rests on exactly one consume of its operation before it and is the only apply of it. A permission grant
# is approved by the assertion on its own row (bound to that row alone, see _owner_assertions), so it needs no consume.
def _owner_effect(same, row):
    try: payload = _owner_payload(row)
    except Refusal: raise Refusal("verifier:gate-evidence") from None
    if row["kind"] != "gate.apply": return
    consumed = [other for other in same if other["seq"] < row["seq"] and other["kind"] == "gate.consume" and _owner_linked(other, payload)]
    _require(bool(row["op"]) and sum(other["kind"] == "gate.apply" for other in same) == 1
             and (len(consumed) == 1 or payload.get("target") == "gate/permission"), "gate-reference")
def _owner_linked(row, applied):
    try: earlier = _owner_payload(row)
    except Refusal: return False
    return row["phase"] == "settle" and earlier.get("state") == "consumed" and all(name in earlier and name in applied and earlier[name] == applied[name] for name in ("proposal", "target", "operation", "new_sha256"))
def _owner_required(rows, row):
    payload = _owner_payload(row)
    if row["kind"] == "gate.consume":
        try: _owner_standing(rows, row)
        except Refusal: return True
        return payload.get("standing") is None
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
