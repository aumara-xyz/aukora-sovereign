# SPDX-License-Identifier: AGPL-3.0-or-later
from .common import (
    AURA_DOMAIN,
    KINDS,
    LEAF_CONVENTION,
    RETAINED_HEAD_V1,
    ROW_KEYS,
    Refusal,
    _bytes,
    _ed25519,
    _hex,
    _require,
    _root,
    _schnorr,
    _sha,
    _size,
)
from .gate import (
    _authorization,
    _gate,
)

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
            if error.sequence is None: error.sequence = number
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
