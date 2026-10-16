# SPDX-License-Identifier: AGPL-3.0-or-later
import re
from .common import (
    Refusal,
    _bytes,
    _hex,
    _parse,
    _require,
    _same,
    _sha,
    _size,
)

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
