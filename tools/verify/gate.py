# SPDX-License-Identifier: AGPL-3.0-or-later
import re
from .common import (
    _bytes,
    _hex,
    _require,
    _same,
    _sha,
    _size,
)

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
