# SPDX-License-Identifier: AGPL-3.0-or-later
from .common import (
    LEAF_CONVENTION,
    MAX_INPUT,
    PRESENTED_HEAD_V1,
    Refusal,
    _bytes,
    _checked_key,
    _cold,
    _hex,
    _key,
    _node,
    _parse,
    _require,
    _root,
    _same,
    _schnorr,
    _sha,
    _size,
)
from .owner import (
    _owner_assertions,
)
from .ledger import (
    _anchor,
    _head,
    _walk,
)

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
def verify_bundle(bundle: bytes, *, pinned_key=None, checkpoint=None, owner_key=None):
    value, assertions = _cold(_parse(bundle, canonical=True))
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
    owner_checked = _owner_assertions(rows, assertions, owner_key)
    findings = [] if owner_checked or assertions is None and owner_key is None else [{"code": "verifier:" + (
        "owner-assertions-unavailable" if not assertions else "owner-no-pinned-key"),
        "sequence": None, "exact_location": True}]
    report = _report(len(rows), identity=pinned_key is not None, covering=covering,
                     semantic=semantic, findings=findings)
    report["owner_signatures"] = owner_checked
    return report
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
             and _size(new["treeSize"]) and new["treeSize"] > 0 and _size(new["retainedTreeSize"]) and new["retainedTreeSize"] > 0
             and isinstance(new["proofFromPrevious"], list) and len(new["proofFromPrevious"]) <= 64, "presented-format")
    _hex(new["root"])
    if new["retainedTreeSize"] != old["treeSize"]:
        # A well-formed presented head that names a different earlier size than the one retained proves nothing.
        return {"verdict": "UNDETERMINED", "retained_size": old["treeSize"], "presented_size": new["treeSize"], "reason": "verifier:retained-proof-size"}
    verdict, reason = _proof_result(old, new)
    return {"verdict": verdict, "retained_size": old["treeSize"], "presented_size": new["treeSize"], "reason": "verifier:" + reason}
def _rows(raw):
    _require(isinstance(raw, bytes) and len(raw) <= MAX_INPUT, "input-too-large")
    _require(bool(raw) and b"\r" not in raw, "rows-format")
    lines, values = raw.split(b"\n"), []
    for number, line in enumerate(lines, 1):
        try:
            _require(number < len(lines) or not line, "rows-truncated", number)
            if number < len(lines):
                _require(bool(line), "rows-format", number)
                values.append(_parse(line, canonical=True))
        except Refusal as error:
            if error.sequence is None: error.sequence = number
            return values, error
    return values, None
def verify_chain(rows: bytes, *, pinned_key: bytes, retained=None,
                 presented=None, retained_rows=None, checkpoint=None):
    values, malformed = _rows(rows)
    key = _key(pinned_key)
    leaves, semantic = _walk(values, key)
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
