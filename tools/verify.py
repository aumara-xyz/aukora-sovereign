#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cold Aura verification over supplied files, with no node or relay access.

Ed25519 uses PyNaCl; BIP340 uses coincurve when detached Nostr evidence
is present. Missing providers refuse verification. Neither provider is fetched.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys

COLD_PROOF_V1 = "aukora-aura-cold-proof-v1"
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
    if not condition:
        raise Refusal("verifier:" + reason, sequence, exact)


def export_version(schema: str):
    _require(schema == COLD_PROOF_V1, "unsupported-schema")
    return COLD_PROOF_V1


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


def _reference(rows, reference, before, kind, operation):
    _require(isinstance(reference, dict), "gate-evidence")
    number = reference.get("seq")
    _require(type(number) is int and 0 < number < before and number <= len(rows), "gate-reference")
    found = rows[number - 1]
    _require(found["seq"] == number and found["hash"] == reference.get("hash")
             and found["kind"] == kind and found["op"] == operation, "gate-evidence")
    for alias, field in (("ledger_seq", "seq"), ("ledger_hash", "hash")):
        _require(alias not in reference or _same(reference[alias], found[field]), "gate-evidence")
    return found


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


def _card(auth, card):
    _require(isinstance(card, dict) and set(card) == {"v", "risk", "says", "facts", "from_to", "model_note"}, "gate-evidence")
    _require(type(card["v"]) is int and card["v"] == 1 and card["risk"] in ("routine", "critical")
             and isinstance(card["says"], str) and "\r" not in card["says"] and "\n" not in card["says"]
             and isinstance(card["facts"], list) and isinstance(card["model_note"], str), "gate-evidence")
    _require(all(isinstance(fact, list) and len(fact) == 2 and isinstance(fact[0], str)
                 for fact in card["facts"]), "gate-evidence")
    _require(_sha(_bytes(card)).hex() == auth["display_sha256"], "gate-evidence")
    change = card.get("from_to")
    _require(isinstance(change, dict) and isinstance(change.get("new"), str), "gate-evidence")
    new = change["new"].encode("utf-8")
    _require(_sha(new).hex() == auth["new_sha256"], "gate-evidence")
    base = change.get("base")
    _require("base" in change and (base is None and auth["base_sha256"] == "absent"
             or isinstance(base, str) and _sha(base.encode("utf-8")).hex() == auth["base_sha256"]), "gate-evidence")
    cell = auth["cell"]
    if cell is not None:
        _require(set(cell) == {"module_sha256", "input_sha256", "effect_sha256"}
                 and cell["module_sha256"] == "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438"
                 and cell["effect_sha256"] == _sha(new).hex() and new.endswith(b"\n"), "cell-effect")
        arguments = _parse(new[:-1], canonical=True)
        _require(isinstance(arguments, dict) and set(arguments) == {"key", "value"}
                 and isinstance(arguments["key"], str), "cell-effect")
        key = arguments["key"].encode("utf-8")
        _require(re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", key) is not None
                 and len(key) + len(_bytes(arguments["value"])) <= 65_536
                 and _sha(new[:-1]).hex() == cell["input_sha256"], "cell-effect")


def _consume(rows, row):
    _require(row["phase"] == "settle", "gate-evidence")
    body = row["body"]
    auth = _authorization(body.get("authorization"))
    _require(auth["op"] in ("apply", "release", "grant", "permission")
             and auth["proposal"] == row["op"] and body.get("spent") is True, "gate-evidence")
    expected = _sha(b"aukora:owner-authorization:v1\x00" + _bytes(auth)).hex()
    _require(expected == body.get("authorization_sha256"), "authorization-digest")
    standing = "standing_permission" in body
    if not standing:
        proof = body.get("proof_hex")
        _require(isinstance(proof, str) and len(proof) > 0 and len(proof) % 2 == 0
                 and re.fullmatch(r"[0-9a-f]+", proof) is not None, "gate-evidence")
        _require(_sha(bytes.fromhex(proof)).hex() == body.get("proof_sha256"), "gate-evidence")
    review = _reference(rows, body.get("review_issue"), row["seq"], "gate.review", row["op"])
    reviewed = review["body"]
    _require(review["phase"] == "fact" and _same(reviewed.get("authorization"), auth)
             and _same(reviewed.get("owner_state"), body.get("owner_state")), "gate-evidence")
    owner = reviewed.get("owner_state")
    _require(isinstance(owner, dict) and owner.get("subject") == auth["subject"]
             and type(owner.get("epoch")) is int and owner["epoch"] == auth["epoch"], "gate-evidence")
    _require("binding_sha256" not in auth or owner.get("binding_sha256") == auth["binding_sha256"], "gate-evidence")
    _card(auth, reviewed.get("card"))
    proposals = [entry for entry in rows[:review["seq"] - 1]
                 if entry["kind"] == "gate.propose" and entry["phase"] == "intent" and entry["op"] == row["op"]]
    _require(len(proposals) == 1 and sum(entry["kind"] == "gate.consume" and entry["op"] == row["op"] for entry in rows) == 1,
             "gate-evidence")
    proposed = proposals[0]["body"]
    _require(all(proposed.get(field) == auth[field] for field in ("target", "base_sha256", "new_sha256"))
             and proposed.get("digest") == auth["operation"], "gate-evidence")
    if standing:
        _standing(rows, row, row["at"], row["seq"])
    return auth, True



def _permission(raw):
    value = _parse(raw, canonical=True)
    columns = {"v", "mode", "targets", "kinds", "max_count", "expires_at", "nonce"}
    _require(isinstance(value, dict) and set(value) == columns and len(raw) <= 4096
             and all(0x20 <= byte <= 0x7E for byte in raw), "standing-permission")
    targets = value["targets"]
    _require(type(value["v"]) is int and value["v"] == 1 and value["mode"] in ("ask", "risky", "limits")
             and isinstance(targets, list) and len(targets) <= 32 and value["kinds"] == ["put"]
             and type(value["max_count"]) is int and 0 <= value["max_count"] <= 1_000_000
             and type(value["expires_at"]) is int and value["expires_at"] > 0, "standing-permission")
    _hex(value["nonce"], 16, "standing-permission")
    _require((not targets and value["max_count"] == 0) if value["mode"] == "ask"
             else bool(targets) and value["max_count"] > 0, "standing-permission")
    protected = {"release", "broker", "grant", "floor", "identity", "aumlok", "gate", "slider", "permission"}
    extensions = {"js", "mjs", "cjs", "ts", "sh", "py", "node", "so"}
    for target in targets:
        _require(isinstance(target, str), "standing-permission")
        parts, lower = target.split("/"), target.lower()
        _require(len(target.encode("utf-16-be")) // 2 <= 200 and "\\" not in target
                 and all(ord(char) > 31 and ord(char) != 127 for char in target)
                 and len(parts) >= 3 and parts[0] == "plugins" and all(part and part not in (".", "..") for part in parts)
                 and not protected.intersection(re.split(r"[/._-]", lower))
                 and lower.rsplit(".", 1)[-1] not in extensions, "standing-permission")
    return value


def _standing(rows, consumed, at, before):
    body, auth = consumed["body"], consumed["body"]["authorization"]
    reference = body.get("standing_permission")
    columns = {"v", "proposal", "authorization_sha256", "proof_sha256", "consume", "kind"}
    _require(isinstance(reference, dict) and set(reference) == columns
             and type(reference["v"]) is int and reference["v"] == 1 and "proof_hex" not in body, "standing-reference")
    try:
        original = _reference(rows, reference["consume"], consumed["seq"], "gate.consume", reference["proposal"])
    except Refusal:
        raise Refusal("verifier:standing-reference") from None
    approved = original["body"]
    original_auth = approved.get("authorization")
    _require(isinstance(original_auth, dict) and "standing_permission" not in approved
             and original_auth.get("target") == "gate/permission" and original_auth.get("op") == "permission", "standing-permission")
    permission_auth, checked = _consume(rows, original)
    _require(checked and reference["authorization_sha256"] == approved.get("authorization_sha256")
             and reference["proof_sha256"] == approved.get("proof_sha256")
             and body.get("proof_sha256") == approved.get("proof_sha256"), "standing-reference")
    _require(_same(body.get("owner_state"), approved.get("owner_state"))
             and auth["node"] == permission_auth["node"], "standing-owner")
    applications = [row for row in rows[original["seq"]:consumed["seq"] - 1]
                    if row["kind"] == "gate.apply" and row["op"] == reference["proposal"]]
    _require(len(applications) == 1, "standing-permission")
    _gate(rows, applications[0])
    permission_consumptions = [row for row in rows[:before - 1] if row["kind"] == "gate.consume"
                               and isinstance(row["body"].get("authorization"), dict)
                               and row["body"]["authorization"].get("target") == "gate/permission"]
    _require(bool(permission_consumptions) and permission_consumptions[-1]["seq"] == original["seq"], "standing-revoked")
    review = _reference(rows, approved.get("review_issue"), original["seq"], "gate.review", reference["proposal"])
    try:
        permission = _permission(review["body"]["card"]["from_to"]["new"].encode("utf-8"))
    except (Refusal, KeyError, TypeError, AttributeError, UnicodeError):
        raise Refusal("verifier:standing-permission") from None
    _require(permission["mode"] != "ask" and auth["op"] == "apply" and auth["target"] in permission["targets"]
             and reference["kind"] == "put", "standing-scope")
    _require(type(at) is int and 0 <= at < permission["expires_at"]
             and at < auth["expires_at"] <= permission["expires_at"], "standing-expired")
    used = sum(row["kind"] == "gate.consume" and isinstance(row["body"].get("standing_permission"), dict)
               and row["body"]["standing_permission"].get("proposal") == reference["proposal"]
               for row in rows[:consumed["seq"]])
    _require(used <= permission["max_count"], "standing-count")
    current_review = _reference(rows, body.get("review_issue"), consumed["seq"], "gate.review", consumed["op"])
    card = current_review["body"].get("card")
    _require(isinstance(card, dict) and card.get("risk") == "routine", "standing-scope")
    change = card.get("from_to")
    _require(isinstance(change, dict) and "base" in change, "standing-scope")
    base = change["base"]
    _require(base is None or isinstance(base, str) and len(base.encode("utf-8")) <= 65_536, "standing-scope")
    return reference["authorization_sha256"]

def _gate(rows, row):
    if row["kind"] == "gate.consume":
        return _consume(rows, row)[1]
    body = row["body"]
    receipt = body.get("receipt")
    _require(row["phase"] == "terminal" and isinstance(receipt, dict), "gate-evidence")
    reference = receipt.get("owner_consumption")
    consumption = _reference(rows, reference, row["seq"], "gate.consume", row["op"])
    auth, semantic = _consume(rows, consumption)
    consumed = consumption["body"]
    _require(type(receipt.get("v")) is int and receipt["v"] == 3 and receipt.get("kind") == "change"
             and all(receipt.get(field) == auth[field] for field in ("proposal", "target", "node", "base_sha256", "new_sha256"))
             and receipt.get("approver") == auth["subject"], "gate-evidence")
    review = _reference(rows, reference.get("review_issue"), consumption["seq"], "gate.review", row["op"])
    _require(review["seq"] == consumed["review_issue"]["seq"] and review["hash"] == consumed["review_issue"]["hash"], "gate-evidence")
    authority = receipt.get("owner_authorization")
    _require(isinstance(authority, dict) and type(authority.get("version")) is int and authority["version"] == 1
             and authority.get("kind") == "aukora-owner-authorization-ref/v1"
             and authority.get("proof_sha256") == consumed.get("proof_sha256"), "gate-evidence")
    digest = consumed["authorization_sha256"]
    if "standing_permission" in consumed:
        _require(_same(receipt.get("standing_permission"), consumed["standing_permission"])
                 and type(receipt.get("applied_at")) is int and receipt["applied_at"] == row["at"], "gate-evidence")
        digest = _standing(rows, consumption, row["at"], row["seq"])
    else:
        _require(receipt.get("standing_permission") is None, "gate-evidence")
    _require(authority.get("authorization_id") == digest and authority.get("authorization_sha256") == digest, "gate-evidence")
    return semantic


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
    previous, leaves, terminals, semantic, bindings = AURA_DOMAIN, [], {}, True, 0
    for number, row in enumerate(rows, 1):
        try:
            _require(isinstance(row, dict) and set(row) == ROW_KEYS, "row-columns")
            _require(type(row["seq"]) is int and row["seq"] == number, "sequence")
            _require(type(row["at"]) is int and row["kind"] in KINDS and row["phase"] in ("intent", "settle", "terminal", "fact")
                     and isinstance(row["body"], dict) and all(isinstance(row[field], str) for field in ("prev", "sig", "actor", "op")),
                     "bundle-row-schema")
            if row["op"]:
                _hex(row["op"], 16, "operation-id")
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
            if row["op"]:
                terminals[row["op"]] = terminals.get(row["op"], 0) + int(row["phase"] == "terminal")
            previous = row["hash"]
            leaves.append(_sha(b"\x00" + digest))
        except Refusal as error:
            if error.sequence is None:
                error.sequence = number
            raise
        except (ValueError, TypeError, KeyError):
            raise Refusal("verifier:bundle-row-schema", number) from None
    for row in rows:
        if row["kind"] in ("gate.consume", "gate.apply"):
            try:
                if "auth" in row["body"]:
                    auth = _authorization(row["body"]["auth"], current=False)
                    if "authorization_digest" in row["body"]:
                        _require(_sha(b"aukora:owner-authorization:v1\x00" + _bytes(auth))
                                 == _hex(row["body"]["authorization_digest"]), "authorization-digest")
                    semantic = False
                elif "authorization" in row["body"] or "receipt" in row["body"]:
                    semantic = _gate(rows, row) and semantic
                else:
                    semantic = False
            except Refusal as error:
                if error.sequence is None:
                    error.sequence = row["seq"]
                raise
            except (ValueError, TypeError, KeyError):
                raise Refusal("verifier:gate-evidence", row["seq"]) from None
    return leaves, semantic and all(count == 1 for count in terminals.values())


def _report(count, *, identity=False, covering=False, consistency=False, semantic=True, tree_root=True, findings=None):
    missing = list(findings or [])
    for checked, code in ((identity, "identity-no-pinned-key"), (covering, "completeness-no-covering-checkpoint"),
                          (semantic, "owner-bindings-or-terminal-count"), (tree_root, "tree-root-no-anchor")):
        if not checked:
            missing.append({"code": "verifier:" + code, "sequence": None, "exact_location": True})
    return {"verdict": "VERIFIED" if not missing else "UNCHECKED", "rows": count,
            "integrity": {"signatures": True, "chain": True, "tree_root": tree_root, "owner_bindings": semantic},
            "observations": {"pinned_identity": identity, "covering_checkpoint": covering, "consistency": consistency},
            "findings": missing}


def verify_bundle(bundle: bytes, *, pinned_key=None, checkpoint=None):
    value = _parse(bundle, canonical=True)
    _require(isinstance(value, dict) and set(value) == {"schema", "publicKey", "head", "rows"}, "bundle-format")
    export_version(value["schema"])
    key = _checked_key(_hex(value["publicKey"]))
    if pinned_key is not None:
        _require(_key(pinned_key) == key, "bundle-key-mismatch")
    head = _head(value["head"])
    rows = value["rows"]
    leaves, semantic = _walk(rows, key)
    _require(len(rows) == head["treeSize"], "bundle-tail-size", min(len(rows), head["treeSize"]) + 1)
    _anchor(head, rows, leaves)
    covering = False
    if checkpoint is not None:
        retained = _head(_parse(checkpoint))
        _anchor(retained, rows, leaves)
        covering = retained["treeSize"] == len(rows)
    return _report(len(rows), identity=pinned_key is not None, covering=covering, semantic=semantic)


def _proof_result(old, new):
    m, n = old["treeSize"], new["treeSize"]
    if m > n:
        return "UNDETERMINED", "invalid-tree-sizes"
    proof = [_hex(item) for item in new["proofFromPrevious"]]
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
             and _size(new["treeSize"]) and type(new["retainedTreeSize"]) is int
             and new["retainedTreeSize"] == old["treeSize"] and isinstance(new["proofFromPrevious"], list)
             and len(new["proofFromPrevious"]) <= 64, "presented-format")
    _hex(new["root"])
    verdict, reason = _proof_result(old, new)
    return {"verdict": verdict, "retained_size": old["treeSize"], "presented_size": new["treeSize"], "reason": "verifier:" + reason}


def _rows(raw):
    _require(isinstance(raw, bytes) and len(raw) <= MAX_INPUT, "input-too-large")
    _require(bool(raw) and b"\r" not in raw, "rows-format")
    _require(raw.endswith(b"\n"), "rows-truncated", len(raw.split(b"\n")))
    lines = raw[:-1].split(b"\n")
    values = []
    for number, line in enumerate(lines, 1):
        _require(bool(line), "rows-format", number)
        try:
            values.append(_parse(line, canonical=True))
        except Refusal as error:
            if error.sequence is None:
                error.sequence = number
            raise
    return values


def verify_chain(rows: bytes, *, pinned_key: bytes, retained=None,
                 presented=None, retained_rows=None, checkpoint=None):
    values = _rows(rows)
    key = _key(pinned_key)
    leaves, semantic = _walk(values, key)
    findings, consistent, covering, anchored = [], False, False, False
    if retained_rows is not None:
        earlier = _rows(retained_rows)
        _walk(earlier, key)
        for index, entry in enumerate(earlier):
            _require(index < len(values), "shorter-than-checkpoint", index + 1)
            _require(_same(entry, values[index]), "retained-row-mismatch", index + 1)
    _require((retained is None) == (presented is None), "observation-pair")
    if retained is not None:
        old, new = _head(_parse(retained)), _parse(presented)
        _anchor(old, values, leaves)
        anchored = old["treeSize"] == len(values)
        covering = covering or old["treeSize"] == len(values)
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
    return _report(len(values), identity=True, covering=covering, consistency=consistent, semantic=semantic, tree_root=anchored, findings=findings)


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
    except Refusal as error:
        if error.code == "verifier:crypto-unavailable":
            raise
        raise Refusal("verifier:witness-malformed") from None
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise Refusal("verifier:witness-malformed") from None


def verify_witness(bundle: bytes, event: bytes, *, pinned_key=None, checkpoint=None):
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
        value = _parse(bundle, canonical=True)
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
        report = verify_bundle(bundle, pinned_key=pinned_key, checkpoint=checkpoint)
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
        print("UNCHECKED " + finding["code"])
    if "witness" in report:
        print("WITNESS verified prefix=" + str(report["witness"]["prefix"]) + " proof=" + str(report["witness"]["proof"]))
    print("SCOPE supplied bytes and observations; passkey signatures, occurrence, human identity and physical effects are independently unchecked")
    return 0 if report["verdict"] == "VERIFIED" else 1


def _failure(error):
    if error.code == "verifier:bundle-key-mismatch":
        print("FORGED " + error.code)
        return 2
    if error.sequence is not None and error.code in {"verifier:signature", "verifier:nostr-node-signature", "verifier:nostr-agent-signature"}:
        print("FORGED seq=" + str(error.sequence) + " " + error.code)
        return 2
    changes = {"entry-hash", "prev-link", "sequence", "rows-truncated", "checkpoint-mismatch", "shorter-than-checkpoint",
               "bundle-tail-size", "retained-row-mismatch", "consistency-prefix-mismatch", "presented-head-mismatch", "witness-fork",
               "gate-evidence", "gate-reference", "authorization-digest", "cell-effect", "standing-permission",
               "standing-reference", "standing-owner", "standing-revoked", "standing-scope", "standing-expired", "standing-count"}
    if error.code.removeprefix("verifier:") in changes:
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
            args = parser.parse_args(arguments[1:])
            return _render(verify_witness(_read(args.bundle), _read(args.event, 65_536),
                           pinned_key=_read(args.key) if args.key else None,
                           checkpoint=_read(args.checkpoint) if args.checkpoint else None))
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
            args = parser.parse_args(arguments)
            return _render(verify_bundle(_read(args.bundle), pinned_key=_read(args.key) if args.key else None,
                                         checkpoint=_read(args.checkpoint) if args.checkpoint else None))
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
