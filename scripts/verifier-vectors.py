#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Replay crates/verifier/vectors/*.json through both verifiers: the Rust aukora-verify and tools/verify.py.

Each case becomes input files, one run of each engine, and a comparison with the case's expected verdict, exit code,
row, codes and scope marks. Cases whose recipe needs a signer (rehash_and_sign, sign_hash, rebuild_head, prepared or
prefix heads) and the vector files that assemble signed rows (witness, nostr binding, member exit) are counted as not
replayed and named in the summary, never silently passed. The Python engine reports
`crypto-unavailable` when PyNaCl or `cryptography` is missing and the replay's shim is not in use; those cases are
counted as skipped for that engine.

The last two sections, "owner-rule" and "owner-rule-v2", are not vector files. They build small signed ledgers here and
hold both engines to the owner rule: rows that need an owner assertion (what the real gate writes, the Aura authority
wrapper as the row body) verify only with the v2 export and every assertion verifying under the pinned owner key, so
without them both engines say UNCHECKED with exactly one finding, `owner-signatures-unchecked`, and ledgers without such
rows can verify; "owner-rule-v2" signs a real P-256 passkey assertion (scripts/replay-shim/p256_ref.py) and checks the
positive path and its refusals the same way, for the Python twin too (which needs `cryptography`, stood in for by the shim).

    python3 -B scripts/verifier-vectors.py [--engine rust|python|both] [--rust-bin PATH]
"""
import argparse
import atexit
import base64
import collections
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHIM = ROOT / "scripts/replay-shim"
_reference = importlib.util.spec_from_file_location("ed25519_ref", SHIM / "ed25519_ref.py")
ed25519_ref = importlib.util.module_from_spec(_reference)
_reference.loader.exec_module(ed25519_ref)
_p256 = importlib.util.spec_from_file_location("p256_ref", SHIM / "p256_ref.py")
p256_ref = importlib.util.module_from_spec(_p256)
_p256.loader.exec_module(p256_ref)
VECTORS = ROOT / "crates/verifier/vectors"
KNOWN = ROOT / "scripts/verifier-vectors-known.json"
ALL = ["admission-regressions-v1", "consistency-regressions-v1", "exit-v1", "nostr-binding-regressions-v1",
       "operator-inputs-v1", "regressions-v1", "witness-regressions-v1"]
NOT_REPLAYED = {
    "exit-v1": "member-exit export is read by verifier::restore only (no CLI, no Python twin)",
    "nostr-binding-regressions-v1": "assembles and signs Nostr binding rows",
    "witness-regressions-v1": "assembles signed rows and Nostr witness events",
}
AURA_DOMAIN = "aukora:aura-record:v1"
OWNER_SEED = "25" * 32
OPERATION = "ab" * 16
NODE_ID = "01" * 16
PROPOSAL = "cd" * 16
NEW = "22" * 32
TARGET = "app/theme"
RELYING_PARTY = "owner.example"
OWNER_ORIGIN = "https://owner.example"
TOP_ORIGIN = "https://top.example"
OWNER_D = int.from_bytes(bytes([0x42]) * 32, "big")
OTHER_D = int.from_bytes(bytes([0x43]) * 32, "big")
# Any valid uncompressed P-256 point will do as an owner pin where no assertion is supplied (the curve's generator).
P256_PIN = ("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e16"
            "2bce33576b315ececbb6406837bf51f5")
LEAF_CONVENTION = "rfc6962-leaf-sha256-0x00-prefixed-v1"
# Edits on the serialized document rather than the parsed one; applied after serialization, in listed order.
BYTE_OPS = {"bytes_insert_utf8", "bytes_append_hex", "row_bytes_replace"}


class NotReplayed(Exception):
    pass


def byte_edits(data, edits):
    """Edits the vectors make on the serialized document or rows file, after serialization."""
    for edit in edits:
        if edit["op"] == "bytes_append_hex":
            data += bytes.fromhex(edit["value"])
        elif edit["op"] == "bytes_insert_utf8":
            data = data[:edit["offset"]] + edit["value"].encode() + data[edit["offset"]:]
        elif edit["op"] == "row_bytes_replace":
            lines = data.split(b"\n")
            lines[edit["row"] - 1] = edit["utf8"].encode()
            data = b"\n".join(lines)
    return data


def c1(value):
    """C1 canonical bytes: object keys in UTF-16 code unit order, no whitespace, literal Unicode."""
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return b"{" + b",".join(c1(key) + b":" + c1(item) for key, item in members) + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(c1(item) for item in value) + b"]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def load(path):
    return json.loads((ROOT / path).read_text())


def merkle_root(leaves):
    """RFC 6962 tree hash over already-hashed leaves."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    cut = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + merkle_root(leaves[:cut]) + merkle_root(leaves[cut:])).digest()


def head_over(rows):
    """The six-key retained head over these rows."""
    leaves = [hashlib.sha256(b"\x00" + bytes.fromhex(row["hash"])).digest() for row in rows]
    return {"schema": "aukora-aura-retained-head-v1", "leafConvention": LEAF_CONVENTION, "sequence": len(rows),
            "hash": rows[-1]["hash"], "treeSize": len(rows), "root": merkle_root(leaves).hex()}


def row_hash(row, number, previous):
    fields = {"prev": previous, "at": row["at"], "kind": row["kind"], "actor": row["actor"], "op": row["op"],
              "phase": row["phase"], "body": row["body"], "sequence": number, "domain": AURA_DOMAIN}
    return hashlib.sha256(c1(fields)).hexdigest()


def sign_hex(seed_hex, digest_hex):
    return base64.b64encode(ed25519_ref.sign(bytes.fromhex(seed_hex), bytes.fromhex(digest_hex))).decode()


def rehash_and_sign(document, edit, seed):
    """Recompute every hash from `first_row` on, relink each predecessor, and sign the raw hashes (the vectors' recipe)."""
    rows, first = document["rows"], edit["first_row"]
    previous = AURA_DOMAIN if first == 1 else rows[first - 2]["hash"]
    for number in range(first, len(rows) + 1):
        row = rows[number - 1]
        if not (number == first and edit.get("preserve_first_predecessor")):
            row["prev"] = previous
        row["hash"] = row_hash(row, number, row["prev"])
        row["sig"] = sign_hex(edit.get("signing_seed_hex", seed), row["hash"])
        previous = row["hash"]


def pointer_parts(pointer):
    return [] if pointer == "" else [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]


def walk(document, parts):
    for part in parts:
        document = document[int(part)] if isinstance(document, list) else document[part]
    return document


def apply_edit(document, edit, seed=None):
    op, parts = edit["op"], pointer_parts(edit.get("pointer", ""))
    if op in BYTE_OPS or op == "copy":
        raise NotReplayed(op)
    if op == "rehash_and_sign":
        rehash_and_sign(document, edit, seed)
        return document
    if op == "rebuild_head":
        document["head"] = head_over(document["rows"])
        return document
    if op == "sign_hash":
        row = walk(document, parts)
        row["sig"] = sign_hex(edit["signing_seed_hex"], row["hash"])
        return document
    if op == "derive_public_key":
        walk(document, parts[:-1])[parts[-1]] = ed25519_ref.public_key(bytes.fromhex(edit["signing_seed_hex"])).hex()
        return document
    if op == "swap":
        left, right = pointer_parts(edit["left"]), pointer_parts(edit["right"])
        first, second = walk(document, left), walk(document, right)
        walk(document, left[:-1])[int(left[-1])] = second
        walk(document, right[:-1])[int(right[-1])] = first
        return document
    if op == "base64_set_unused_bits":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        text = walk(document, parts[:-1])[parts[-1]]
        at = text.index("=") - 1 if "=" in text else len(text) - 1
        mask = (1 << edit["unused_low_bits"]) - 1
        walk(document, parts[:-1])[parts[-1]] = text[:at] + alphabet[alphabet.index(text[at]) | mask] + text[at + 1:]
        return document
    if op == "string_truncate":
        walk(document, parts[:-1])[parts[-1]] = walk(document, parts)[:edit["length"]]
        return document
    parent = walk(document, parts[:-1]) if parts else None
    key = parts[-1] if parts else None
    index = int(key) if isinstance(parent, list) and key not in (None, "-") else key
    if op == "replace":
        if parent is None:
            return edit["value"]
        parent[index] = edit["value"]
    elif op == "remove":
        del parent[index]
    elif op == "add":
        if isinstance(parent, list):
            parent.insert(len(parent) if key == "-" else index, edit["value"])
        else:
            parent[key] = edit["value"]
    elif op == "add_repeated_text":
        parent[key] = edit["text"] * edit["count"]
    elif op == "repeat_array":
        parent[index] = [copy.deepcopy(edit["value"]) for _ in range(edit["count"])]
    elif op == "fill_array":
        target = walk(document, parts)
        for position in range(len(target)):
            target[position] = copy.deepcopy(edit["value"])
    elif op == "remove_last":
        walk(document, parts).pop()
    elif op == "append":
        walk(document, parts).append(edit["value"])
    elif op == "insert":
        walk(document, parts[:-1]).insert(int(parts[-1]), edit["value"])
    elif op == "reverse":
        walk(document, parts).reverse()
    else:
        raise NotReplayed(op)
    return document


def apply_edits(document, edits, seed=None):
    document = copy.deepcopy(document)
    for edit in edits:
        document = apply_edit(document, edit, seed)
    return document


def reference(source, ref, prepared=None):
    """A head, key or rows reference: a pointer into the original fixture (or, for `prepared`, into the document after the
    case's own edits and signing), with local edits. `prefix_rows` first rebuilds the head over that many leading rows."""
    if ref.get("source") not in ("original", "prepared") or (ref["source"] == "prepared" and prepared is None):
        raise NotReplayed("unknown reference source")
    document = source if ref["source"] == "original" else prepared
    if "prefix_rows" in ref:
        document = {**document, "head": head_over(document["rows"][:ref["prefix_rows"]])}
    value = walk(document, pointer_parts(ref["pointer"]))
    if "slice" in ref:
        value = value[ref["slice"][0]:ref["slice"][1]]
    return apply_edits(value, ref.get("edits", []))


def rows_bytes(rows, raw_edits):
    """Serialize rows one per line, then apply raw byte edits (no reserialization follows)."""
    lines = [c1(row) + b"\n" for row in rows]
    return raw_apply(lines, raw_edits)


def payload(edit):
    return bytes.fromhex(edit["hex"]) if "hex" in edit else edit["utf8"].encode()


def raw_apply(lines, raw_edits):
    prefix, suffix = b"", b""
    for edit in raw_edits:
        op, row = edit["op"], edit.get("row")
        if op in ("replace_once", "replace_once_bytes"):
            needle = edit["needle"].encode() if op == "replace_once" else bytes.fromhex(edit["needle_hex"])
            new = edit["replacement"].encode() if op == "replace_once" else bytes.fromhex(edit["replacement_hex"])
            if row is None:
                lines[:] = [b"".join(lines)]
                row = 1
            if needle not in lines[row - 1]:
                raise NotReplayed("replace_once needle missing")
            lines[row - 1] = lines[row - 1].replace(needle, new, 1)
        elif op == "suffix_row":
            lines[row - 1] = lines[row - 1][:-1] + payload(edit) + b"\n"
        elif op == "prefix_row":
            lines[row - 1] = payload(edit) + lines[row - 1]
        elif op == "insert_blank_line_before":
            lines.insert(row - 1, b"\n")
        elif op == "remove_final_lf":
            lines[-1] = lines[-1][:-1]
        elif op == "prefix_document":
            prefix = payload(edit) + prefix
        elif op == "suffix_document":
            suffix += payload(edit)
        else:
            raise NotReplayed(op)
    return prefix + b"".join(lines) + suffix


def authority_wrap(number, previous, payload):
    """The body the real gate writes: the Aura authority wrapper around the operation's payload."""
    return {"schema": "aukora-aura-authority-body-v1", "algorithm": "sha256", "epoch": 1, "sequence": number,
            "previous_hash": previous, "payload": payload}


def authority_body(number, previous, state, target="theme", **more):
    return authority_wrap(number, previous, {"proposal": PROPOSAL, "target": target, "operation": "ef" * 32,
                                             "base_sha256": "11" * 32, "new_sha256": NEW, "state": state, "retry": False,
                                             "consumed_approval": "33" * 32, **more})


def b64(data):
    return base64.b64encode(data).decode()


def owner_authorization():
    """The 14-member C5 owner authorization for a theme change, its operation digest recomputed as the spec says."""
    content = {"v": 1, "node": NODE_ID, "target": TARGET, "base_sha256": "absent", "new_sha256": NEW, "cell": None}
    return {**content, "subject": "aukora:1:" + "03" * 32, "op": "apply", "proposal": PROPOSAL, "display_sha256": "44" * 32,
            "challenge": "05" * 16, "expires_at": 1760000100000, "epoch": 1,
            "operation": hashlib.sha256(b"aukora:operation-content:v1\0" + c1(content)).hexdigest()}


def owner_entry(sequence, auth, signing_d, bound_d):
    """The retained assertion for the row at `sequence`: a passkey (key `bound_d`) approval signed with `signing_d`."""
    credential = bytes([7]) * 32
    key = {"v": 1, "algorithm": "ecdsa-p256-sha256", "bytes": b64(p256_ref.encode(p256_ref.public_point(bound_d)))}
    binding = {"schema": "aukora-aura-owner-binding-storage-v1", "v": 1, "algorithm": "ecdsa-p256-sha256",
               "credential": b64(credential), "key": key, "epoch": 1, "relying_party": RELYING_PARTY,
               "owner_origin": OWNER_ORIGIN, "top_origin": TOP_ORIGIN, "counter": 0}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(b"aukora:owner-authorization:v1\0" + c1(auth)).digest()).decode().rstrip("=")
    client = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": OWNER_ORIGIN, "topOrigin": TOP_ORIGIN,
                         "crossOrigin": True}, separators=(",", ":")).encode()
    authenticator = hashlib.sha256(RELYING_PARTY.encode()).digest() + b"\x05" + (1).to_bytes(4, "big")
    signed = authenticator + hashlib.sha256(client).digest()
    proof = {"authorization": auth, "credential": base64.urlsafe_b64encode(credential).decode().rstrip("="),
             "authenticator_data": b64(authenticator), "client_data_json": b64(client), "signed_bytes": b64(signed),
             "public_keys": [key], "signatures": {"v": 1, "components": [
                 {"v": 1, "algorithm": "ecdsa-p256-sha256", "bytes": b64(p256_ref.sign(signing_d, signed))}]}}
    return {"sequence": sequence, "binding": binding, "proof": proof}


def owner_ledger(consumed_new=NEW):
    """boot fact, propose, consume (needs the owner assertion), apply, all but the first in the authority wrapper.
    `consumed_new` is the new_sha256 the consume row records: a different one is a row the assertion does not describe."""
    auth = owner_authorization()
    operation = auth["operation"]
    payload = lambda state, new, **more: {"proposal": PROPOSAL, "target": TARGET, "operation": operation, "new_sha256": new,
                                          "state": state, **more}
    wrapped = lambda body: (lambda number, previous: authority_wrap(number, previous, body))
    bundle = signed_ledger([
        ("boot.facts", "fact", "supervisor", "", {"index": 0, "message": "honest"}),
        ("gate.propose", "intent", "owner", OPERATION, wrapped(payload("proposed", NEW))),
        ("gate.consume", "settle", "owner", OPERATION, wrapped(payload(
            "consumed", consumed_new, base_sha256="absent", consumed_approval=hashlib.sha256(c1(auth)).hexdigest()))),
        ("gate.apply", "terminal", "owner", OPERATION, wrapped(payload("applied", consumed_new)))])
    return bundle, auth


def export_v2(bundle, entries):
    return {"schema": "aukora-aura-cold-proof-v2", "body": {"proof": bundle, "owner_assertions": entries}}


def signed_ledger(specs):
    """A v1 cold export of rows (kind, phase, actor, op, body or body(number, previous)) signed with OWNER_SEED."""
    rows, previous = [], AURA_DOMAIN
    for number, (kind, phase, actor, op, body) in enumerate(specs, 1):
        row = {"seq": number, "prev": previous, "at": 1760000000000 + number, "kind": kind, "actor": actor, "op": op,
               "phase": phase, "body": body(number, previous) if callable(body) else body}
        row["hash"] = row_hash(row, number, previous)
        row["sig"] = sign_hex(OWNER_SEED, row["hash"])
        rows.append(row)
        previous = row["hash"]
    public = ed25519_ref.public_key(bytes.fromhex(OWNER_SEED)).hex()
    return {"schema": "aukora-aura-cold-proof-v1", "publicKey": public, "head": head_over(rows), "rows": rows}


def python_environment(force=False):
    """The Python engine's environment. tools/verify.py takes no Ed25519 provider but PyNaCl and no ES256 provider but
    `cryptography`. For each one that is not installed (or for both, with `force`) the replay puts a stand-in from
    scripts/replay-shim (verification only, self-tested here) first on the engine's path, so signature cases run instead of
    being skipped; a provider that is installed is never shadowed. Returns (environment, a note for the summary)."""
    environment = dict(os.environ)
    providers = (("PyNaCl", "nacl", "ed25519_ref.py", "Ed25519"), ("cryptography", "cryptography", "p256_ref.py", "P-256"))
    standing = [entry for entry in providers if force or importlib.util.find_spec(entry[1]) is None]
    note = " and ".join(f"{name} ({'reference ' + kind + ' in scripts/replay-shim' if (name, package, module, kind) in standing else 'installed'})"
                        for name, package, module, kind in providers)
    if standing:
        folder = pathlib.Path(tempfile.mkdtemp(prefix="replay-shim-"))
        atexit.register(shutil.rmtree, folder, True)
        for _, package, module, _ in standing:
            (folder / package).symlink_to(SHIM / package, target_is_directory=True)
            (folder / module).symlink_to(SHIM / module)
        environment["PYTHONPATH"] = os.pathsep.join([str(folder)] + ([environment["PYTHONPATH"]] if environment.get("PYTHONPATH") else []))
    return environment, note


class Engine:
    def __init__(self, name, command, environment=None):
        self.name, self.command, self.environment = name, command, environment

    def run(self, arguments, cwd):
        done = subprocess.run(self.command + arguments, cwd=cwd, capture_output=True, timeout=120, env=self.environment)
        out, err = done.stdout.decode(errors="replace"), done.stderr.decode(errors="replace")
        return done.returncode, out, err, (self.rust_report if self.name == "rust" else self.python_report)(out)

    @staticmethod
    def rust_report(out):
        for line in reversed(out.strip().splitlines()):
            try:
                return json.loads(line)
            except ValueError:
                continue
        return None

    @staticmethod
    def python_report(out):
        """tools/verify.py prints text; read it back into the shape the Rust CLI prints as JSON."""
        lines = out.strip().splitlines()
        if not lines:
            return None
        first = lines[0].split()
        if first[0] in ("APPEND_ONLY", "OBSERVATION_CONFLICT", "UNDETERMINED"):
            return {"consistency": first[0]}
        report = {"verdict": first[0], "rows": None, "findings": [], "integrity": {}, "observations": {}}
        if len(first) > 1 and first[1].startswith("rows=1.."):
            report["rows"] = int(first[1][8:])
        for line in lines:
            words = line.split()
            if words[0] == "REWRITTEN" and len(words) > 2 and words[1] == "first":
                report["findings"][-1]["exact_location"] = not words[-1].startswith("unknown") and words[-4:-1] != ["at", "or", "before"]
                continue
            if words[0] in ("UNCHECKED", "FORGED", "REWRITTEN", "KEY_MISMATCH") and words[-1].startswith("verifier:"):
                sequence = next((int(w[4:]) for w in words if w.startswith("seq=")), None)
                report["findings"].append({"code": words[-1], "sequence": sequence, "exact_location": True})
        if report["verdict"] == "UNCHECKED" and report["rows"] is None:
            report["verdict"] = "INVALID_INPUT"
        report["text_only"] = True  # a refusal's row location is not printed
        return report


def check_report(expected, code, out, err, report, row_index=None):
    """Compare a verification report with an expected block. Returns a list of mismatches."""
    bad = []
    if "exit" in expected and code != expected["exit"]:
        bad.append(f"exit {code} != {expected['exit']}")
    verdict = report["verdict"] if report else None
    if "verdict" in expected and verdict != expected["verdict"] and not (verdict is None and expected["verdict"] == "INVALID_INPUT" and code == 64):
        bad.append(f"verdict {verdict} != {expected['verdict']}")
    if "not_verdict" in expected and verdict == expected["not_verdict"]:
        bad.append(f"verdict is {verdict}")
    if report:
        if "rows" in expected and report["rows"] is not None and report["rows"] != expected["rows"]:
            bad.append(f"rows {report['rows']} != {expected['rows']}")
        merged = {**report["integrity"], **report["observations"]}
        for name in ("signatures", "chain", "tree_root", "owner_bindings", "pinned_identity", "covering_checkpoint",
                     "consistency"):
            if name in expected and name in merged and (expected[name] == "CHECKED") != merged[name]:
                bad.append(f"{name} {merged[name]} != {expected[name]}")
        findings = report["findings"]
        located = not (report.get("text_only") and report["verdict"] == "INVALID_INPUT")
        if "sequence" in expected and located:
            sequence = row_index + 1 if expected["sequence"] == "row_index + 1" else expected["sequence"]
            if not findings or findings[0]["sequence"] != sequence:
                bad.append(f"sequence {findings[0]['sequence'] if findings else None} != {sequence}")
        if expected.get("exact_location") and located and not (findings and findings[0]["exact_location"]):
            bad.append("location not exact")
        if "codes" in expected and [f["code"] for f in findings] != expected["codes"]:
            bad.append(f"codes {[f['code'] for f in findings]} != {expected['codes']}")
    elif "codes" in expected and not all(c in err or c in out for c in expected["codes"]):
        bad.append(f"codes {expected['codes']} not in {err.strip() or out.strip()!r}")
    if not report and "verdict" in expected and expected["verdict"] not in ("INVALID_INPUT",) and "exit" not in expected:
        bad.append("no report")
    return bad


def check_consistency(expected, code, report, err):
    bad = []
    if expected.get("result") == "REFUSED":
        if code != 64:
            bad.append(f"expected refusal, exit {code}")
        return bad
    if not report or "consistency" not in report:
        return [f"exit {code}, no report ({err.strip()})"]
    if expected.get("result") == "ADMITTED":
        if code == 64:
            bad.append("expected admission, got a refusal")
        if expected.get("arithmetic_verdict") and report["consistency"] != expected["arithmetic_verdict"]:
            bad.append(f"{report['consistency']} != {expected['arithmetic_verdict']}")
        return bad
    if "verdict" in expected and report["consistency"] != expected["verdict"]:
        bad.append(f"{report['consistency']} != {expected['verdict']}")
    for name in ("retained_size", "presented_size"):
        if name in expected and name in report and report[name] != expected[name]:
            bad.append(f"{name} {report[name]} != {expected[name]}")
    if "consistency" in expected and (expected["consistency"] == "CHECKED") != (report["consistency"] == "APPEND_ONLY"):
        bad.append(f"consistency {expected['consistency']} vs {report['consistency']}")
    return bad


def head_pair(tree, retained_size, presented_size):
    trees = tree["trees"]
    retained = {"schema": "aukora-aura-retained-head-v1", "leafConvention": tree["leafConvention"],
                "sequence": retained_size, "hash": tree["entryHashes"][retained_size - 1],
                "treeSize": retained_size, "root": trees[retained_size - 1]["root"]}
    presented = {"schema": "aukora-aura-presented-head-v1", "leafConvention": tree["leafConvention"],
                 "treeSize": presented_size, "root": trees[presented_size - 1]["root"],
                 "retainedTreeSize": retained_size,
                 "proofFromPrevious": trees[presented_size - 1]["retained"][retained_size - 1]["proof"]}
    return {"retained": retained, "presented": presented}


class Replay:
    def __init__(self, engines):
        self.engines = engines
        self.fixtures = {}
        self.counts = collections.Counter()
        self.notes = collections.defaultdict(list)
        self.failures = []
        self.known = json.loads(KNOWN.read_text()) if KNOWN.is_file() else {}
        self.seen = {}

    def fixture(self, document, name):
        path = document["fixtures"][name]["path"]
        if path not in self.fixtures:
            self.fixtures[path] = load(path)
        return self.fixtures[path]

    def record(self, file, case_id, engine, bad, skipped=None):
        key = f"{file}:{case_id}"
        known = self.known.get(engine.name, {})
        text = "; ".join(bad) if bad else None
        if skipped:
            self.counts[(file, engine.name, "skipped")] += 1
            self.notes[(file, engine.name)].append(f"{case_id}: {skipped}")
            return
        self.seen.setdefault(engine.name, {})[key] = text
        if text is None and key in known:
            self.counts[(file, engine.name, "failed")] += 1
            self.failures.append(f"{key} [{engine.name}] now matches its vector; remove it from the known list")
        elif text is None:
            self.counts[(file, engine.name, "passed")] += 1
        elif known.get(key) == text:
            self.counts[(file, engine.name, "known divergence")] += 1
        else:
            self.counts[(file, engine.name, "failed")] += 1
            self.failures.append(f"{key} [{engine.name}]: {text}" + (f" (known: {known[key]})" if key in known else ""))

    def not_replayed(self, file, case_id, reason):
        self.counts[(file, "both", "not replayed")] += 1
        self.notes[(file, "both")].append(f"{case_id}: {reason}")

    def run_all(self, work, file, case_id, runner):
        """Run `runner(engine, directory)` once per engine; a NotReplayed from preparation covers both engines."""
        for engine in self.engines:
            directory = pathlib.Path(tempfile.mkdtemp(dir=work))
            try:
                code, out, err, report = runner(engine, directory)
            except NotReplayed as why:
                self.not_replayed(file, case_id, f"needs a signer or unsupported edit ({why})")
                return
            if "crypto-unavailable" in out + err:
                self.record(file, case_id, engine, None, skipped="crypto provider unavailable")
                continue
            self.record(file, case_id, engine, runner.check(code, out, err, report))

    # -- document modes -------------------------------------------------------------------------------------

    def chain_or_bundle(self, work, file, document, case, expected, row_index=None, extra_edit=None):
        source = self.fixture(document, case["fixture"])
        edits = case.get("edits", []) + ([extra_edit] if extra_edit else [])
        mode = case["mode"]
        seed = document["fixtures"][case["fixture"]].get("signing_seed_hex")
        structured = [edit for edit in edits if edit["op"] not in BYTE_OPS]
        on_bytes = [edit for edit in edits if edit["op"] in BYTE_OPS]

        def runner(engine, directory):
            edited = apply_edits(source, structured, seed)
            arguments = []
            if mode == "bundle":
                (directory / "proof.json").write_bytes(byte_edits(raw_apply([c1(edited)], case.get("raw_edits", [])), on_bytes))
                arguments += ["--bundle", "proof.json"]
            else:
                (directory / "rows.jsonl").write_bytes(byte_edits(rows_bytes(edited["rows"], case.get("raw_edits", [])), on_bytes))
                arguments += ["--rows", "rows.jsonl"]
            key = reference(source, case["pinned_key"], edited) if isinstance(case.get("pinned_key"), dict) else (
                None if "pinned_key" in case else source["publicKey"])
            if key is not None:
                (directory / "key.hex").write_text(key)
                arguments += ["--key", "key.hex"]
            for name, flag in (("checkpoint", "--checkpoint"), ("retained", "--retained"), ("presented", "--presented")):
                ref = case.get(name, {"source": "original", "pointer": "/head"} if name == "checkpoint" else None)
                if isinstance(ref, dict):
                    (directory / f"{name}.json").write_bytes(c1(reference(source, ref, edited)))
                    arguments += [flag, f"{name}.json"]
            if isinstance(case.get("retained_rows"), dict):
                (directory / "prefix.jsonl").write_bytes(rows_bytes(reference(source, case["retained_rows"], edited), []))
                arguments += ["--prefix", "prefix.jsonl"]
            return engine.run(arguments, directory)

        runner.check = lambda code, out, err, report: check_report(expected, code, out, err, report, row_index)
        self.run_all(work, file, case["id"], runner)

    def head_admission(self, work, file, document, case, expected, target, edits=(), raw=None, raw_edits=()):
        tree = self.fixture(document, case["fixture"])
        pair = head_pair(tree, case["pair"]["retained_size"], case["pair"]["presented_size"])

        def runner(engine, directory):
            changed = apply_edits(pair, list(edits))
            texts = {name: c1(changed[name]) for name in ("retained", "presented")}
            if raw:
                marker = "@@raw@@"
                held = copy.deepcopy(pair)
                walk(held, pointer_parts("/" + target))[pointer_parts(raw[0])[-1]] = marker
                texts[target] = c1(held[target]).replace(f'"{marker}"'.encode(), raw[1].encode())
            if raw_edits:
                texts[target] = raw_apply([texts[target]], list(raw_edits))
            for name, text in texts.items():
                (directory / f"{name}.json").write_bytes(text)
            return engine.run(["consistency", "retained.json", "presented.json"], directory)

        runner.check = lambda code, out, err, report: check_consistency(expected, code, report, err)
        self.run_all(work, file, case["id"], runner)

    def admission(self, work, file, document):
        for matrix in document["matrices"]:
            mode = matrix["mode"]
            expected = matrix["expected_each"]
            if mode == "head-admission":
                for target in matrix["targets"]:
                    for value in matrix.get("replacement_values", []):
                        edit = {"op": "replace", "pointer": "/" + target["head"] + target["pointer"], "value": value}
                        self.head_admission(work, file, document,
                                            {**matrix, "id": f"{matrix['id']}:{target['head']}{target['pointer']}={value!r}"},
                                            expected, target["head"], [edit])
                    for token in matrix.get("replacement_raw_tokens", []):
                        self.head_admission(work, file, document, {**matrix, "id": f"{matrix['id']}:{target['head']}{target['pointer']}={token}"},
                                            expected, target["head"], [], raw=(target["pointer"], token))
            else:
                for index in matrix["row_indexes"]:
                    operation = matrix["operation"]
                    edit = {"op": operation["op"], "pointer": f"/rows/{index}" + operation["relative_pointer"], "value": operation["value"]}
                    self.chain_or_bundle(work, file, document, {**matrix, "id": f"{matrix['id']}:{index}", "edits": [edit]},
                                         expected, row_index=index)
        for case in document["cases"]:
            if case["mode"] == "head-admission":
                edits = case.get("edits", [])
                target = case["target"]
                self.head_admission(work, file, document, case, case["expected"], target,
                                    [{**e, "pointer": f"/{target}{e['pointer']}"} for e in edits], raw_edits=case.get("raw_edits", ()))
            else:
                self.chain_or_bundle(work, file, document, case, case["expected"])

    def regressions(self, work, file, document):
        for case in document["cases"]:
            if case.get("engine") == "rust" and not any(e.name == "rust" for e in self.engines):
                continue
            self.chain_or_bundle(work, file, document, case, case["expected"])

    def consistency(self, work, file, document):
        tree = self.fixture(document, "aura-proofs-32")
        for matrix in document["matrices"]:
            for retained in matrix["retained_sizes"]:
                for presented in matrix["presented_sizes"]:
                    if retained <= presented:
                        case = {"id": f"{matrix['id']}:{retained}-{presented}", "fixture": "aura-proofs-32",
                                "pair": {"retained_size": retained, "presented_size": presented}}
                        self.consistency_case(work, file, tree, case, [], matrix["expected_each"])
        for case in document["cases"]:
            self.consistency_case(work, file, tree, case, case["edits"], case["expected"])

    def consistency_case(self, work, file, tree, case, edits, expected):
        pair = head_pair(tree, case["pair"]["retained_size"], case["pair"]["presented_size"])

        def runner(engine, directory):
            changed = apply_edits(pair, edits)
            (directory / "retained.json").write_bytes(c1(changed["retained"]))
            (directory / "presented.json").write_bytes(c1(changed["presented"]))
            return engine.run(["consistency", "retained.json", "presented.json"], directory)

        runner.check = lambda code, out, err, report: check_consistency(expected, code, report, err)
        self.run_all(work, file, case["id"], runner)

    def owner_rule(self, work, file):
        boot = ("boot.facts", "fact", "supervisor", "", {"index": 0, "message": "honest"})
        wrapped = lambda state, **more: (lambda number, previous: authority_body(number, previous, state, **more))
        consume, apply_, propose_ = (("gate.consume", "settle", "owner", OPERATION, wrapped("consumed")),
                                     ("gate.apply", "terminal", "owner", OPERATION, wrapped("applied")),
                                     ("gate.propose", "intent", "owner", OPERATION, wrapped("proposed")))
        # The rows are the same bodies the real gate writes; each case varies one thing.
        cases = [
            # What the real gate writes for an owner-approved change: needs the owner assertions, which a v1 export lacks.
            ("wrapper-rows-need-owner-signatures", [boot, propose_, consume, apply_], False,
             {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": None,
              "codes": ["verifier:owner-signatures-unchecked"]}),
            # An owner pin alone does not help: there is nothing to check it against.
            ("wrapper-rows-pin-without-assertions", [boot, propose_, consume, apply_], True,
             {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": None,
              "codes": ["verifier:owner-signatures-unchecked"]}),
            # Wrapped rows with no effect (a proposal the node refused) need no owner assertion and verify.
            ("wrapper-rows-without-an-effect-verify", [boot, propose_, ("gate.refuse", "terminal", "owner", OPERATION, wrapped("refused"))], False,
             {"verdict": "VERIFIED", "exit": 0, "owner_bindings": "CHECKED", "signatures": "CHECKED", "chain": "CHECKED"}),
            # An effect the owner never approved is never VERIFIED, whatever else is supplied: no consume at all, a consume
            # that came after it, a second apply, an apply that is not what was consumed, an apply with no operation id.
            ("apply-without-a-consume", [boot, propose_, apply_], True,
             {"verdict": "REWRITTEN", "exit": 2, "sequence": 3, "owner_bindings": "UNCHECKED", "codes": ["verifier:gate-reference"]}),
            ("consume-after-the-apply", [boot, propose_, apply_, consume], True,
             {"verdict": "REWRITTEN", "exit": 2, "sequence": 3, "codes": ["verifier:gate-reference"]}),
            ("two-applies-for-one-consume", [boot, propose_, consume, apply_, apply_], True,
             {"verdict": "REWRITTEN", "exit": 2, "sequence": 4}),
            ("apply-of-something-else-than-was-consumed", [boot, propose_, consume,
                                                           ("gate.apply", "terminal", "owner", OPERATION, wrapped("applied", target="other"))], True,
             {"verdict": "REWRITTEN", "exit": 2, "sequence": 4, "codes": ["verifier:gate-reference"]}),
            ("apply-with-no-operation-id", [boot, ("gate.apply", "terminal", "owner", "", wrapped("applied"))], True,
             {"verdict": "REWRITTEN", "exit": 2, "sequence": 2, "codes": ["verifier:gate-reference"]}),
            # Null, malformed or unlinked `standing` is as good as none: the owner is needed. Only a use of an owner-signed
            # grant that is in the ledger is owner-free (checked with a real grant in the Rust tests).
            ("standing-null-needs-the-owner", [boot, propose_, ("gate.consume", "settle", "owner", OPERATION, wrapped("consumed", standing=None)), apply_], True,
             {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": None, "codes": ["verifier:owner-signatures-unchecked"]}),
            ("standing-without-a-grant-needs-the-owner", [boot, propose_, ("gate.consume", "settle", "owner", OPERATION, wrapped("consumed", standing={
                "permission": "ee" * 16, "permission_proposal": "99" * 16, "permission_digest": "55" * 32,
                "proposal": PROPOSAL, "operation": "ef" * 32, "use_number": 1})), apply_], True,
             {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": None, "codes": ["verifier:owner-signatures-unchecked"]}),
            # The archive's flat gate rows (a body that is not the authority wrapper) are not read at all: whatever they
            # carry, both engines say owner-provenance at the row, and a flat consume also needs the owner it names.
            ("flat-consume-and-apply-are-not-verifiable", [boot, ("gate.propose", "intent", "owner", OPERATION, {"state": "proposed"}),
                                                           ("gate.consume", "settle", "owner", OPERATION, {"authorization": {"v": 1}, "spent": True}),
                                                           ("gate.apply", "terminal", "owner", OPERATION, {"receipt": {"v": 3}})], False,
             {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": 3,
              "codes": ["verifier:owner-provenance", "verifier:owner-provenance", "verifier:owner-signatures-unchecked"]}),
            ("flat-authorization-digest-never-proves-the-owner", [boot, ("gate.propose", "intent", "owner", OPERATION, {"state": "proposed"}),
                                                                  ("gate.apply", "terminal", "owner", OPERATION,
                                                                   {"auth": {"v": 1}, "authorization_digest": "ab" * 32})], False,
             {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": 3,
              "codes": ["verifier:owner-provenance"]}),
            # A flat row with no owner proof is located by both engines, at its row.
            ("flat-apply-without-proof-is-located", [boot, ("gate.propose", "intent", "owner", OPERATION, {"state": "proposed"}),
                                                     ("gate.apply", "terminal", "owner", OPERATION, {"state": "applied"})], False,
             {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": 3,
              "codes": ["verifier:owner-provenance"]}),
            # Two terminal rows for one operation: one unlocated finding, the same code in both.
            ("two-terminals-are-unlocated", [boot, ("sandbox.exit", "terminal", "supervisor", OPERATION, {}),
                                             ("sandbox.exit", "terminal", "supervisor", OPERATION, {})], False,
             {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": None,
              "codes": ["verifier:terminal-count"]}),
        ]
        for case_id, specs, with_pin, expected in cases:
            self.export_case(work, file, case_id, signed_ledger(specs), None, P256_PIN if with_pin else None, expected)

    def export_case(self, work, file, case_id, bundle, export, pin, expected, passkeys=False):
        """One run of both engines on `export` (default: the v1 `bundle` itself) with the bundle's own key and head, and
        the owner pin `pin` (hex, or None). `passkeys` is whether the report must say the owner signatures were checked."""
        def runner(engine, directory):
            (directory / "proof.json").write_bytes(c1(bundle if export is None else export))
            (directory / "key.hex").write_text(bundle["publicKey"])
            (directory / "head.json").write_bytes(c1(bundle["head"]))
            arguments = ["--bundle", "proof.json", "--key", "key.hex", "--checkpoint", "head.json"]
            if pin is not None:
                (directory / "pin.hex").write_text(pin)
                arguments += ["--owner-key", "pin.hex"]
            return engine.run(arguments, directory)

        def check(code, out, err, report):
            bad = check_report(expected, code, out, err, report)
            checked = '"owner_signatures":true' in out or "PASSKEY VERIFIED" in out
            return bad + ([] if checked == passkeys else [f"owner signatures checked {checked}, expected {passkeys}"])

        runner.check = check
        self.run_all(work, file, case_id, runner)

    def owner_rule_v2(self, work, file):
        """The positive path with a real passkey assertion, and what each way of breaking it must say."""
        owner, other = (p256_ref.encode(p256_ref.public_point(d)).hex() for d in (OWNER_D, OTHER_D))
        bundle, auth = owner_ledger()
        honest = owner_entry(3, auth, OWNER_D, OWNER_D)
        export = export_v2(bundle, [honest])
        verified = {"verdict": "VERIFIED", "exit": 0, "owner_bindings": "CHECKED", "signatures": "CHECKED", "chain": "CHECKED"}
        unchecked = {"verdict": "UNCHECKED", "exit": 1, "owner_bindings": "UNCHECKED", "sequence": None,
                     "codes": ["verifier:owner-signatures-unchecked"]}
        # The engines name a refusal differently here, so these are held to the verdict and the exit code.
        refused = {"verdict": "INVALID_INPUT", "exit": 64}
        tampered, _ = owner_ledger("33" * 32)
        self.export_case(work, file, "assertions-verify-under-the-pinned-owner-key", bundle, export, owner, verified, True)
        self.export_case(work, file, "no-owner-pin", bundle, export, None, unchecked)
        self.export_case(work, file, "v1-export-with-owner-pin", bundle, None, owner, unchecked)
        self.export_case(work, file, "other-owner-pin", bundle, export, other,
                         {"verdict": "KEY_MISMATCH", "exit": 2, "codes": ["verifier:owner-key-mismatch"]})
        self.export_case(work, file, "missing-assertion", bundle, export_v2(bundle, []), owner, refused)
        self.export_case(work, file, "assertion-signed-by-another-key", bundle,
                         export_v2(bundle, [owner_entry(3, auth, OTHER_D, OWNER_D)]), owner,
                         {"verdict": "FORGED", "exit": 2, "codes": ["verifier:owner-signature"]})
        self.export_case(work, file, "row-resigned-after-its-payload-changed", tampered, export_v2(tampered, [honest]), owner, refused)

    def operator_inputs(self, work, file, document):
        for case in document["cases"]:
            variants = case.get("argument_variants") or [case.get("args")]
            if case.get("argument_templates"):
                variants = [[v if isinstance(v, str) else value for v in template]
                            for template in case["argument_templates"] for value in document_values(case)]
            expected = case.get("expected") or case["expected_each"]
            engines = case.get("engines") or [case["engine"]] if case.get("engine") or case.get("engines") else ["rust", "python"]
            for number, arguments in enumerate(variants):
                for engine in [e for e in self.engines if e.name in engines]:
                    directory = pathlib.Path(tempfile.mkdtemp(dir=work))
                    for name, spec in document["fixtures"].items():
                        place(directory / name, spec, document["fixtures"])
                    code, out, err, report = engine.run(list(arguments), directory)
                    bad = []
                    if code != expected["exit"]:
                        bad.append(f"exit {code} != {expected['exit']}")
                    if "last_line_prefix" in expected and not (out.strip().splitlines() or [""])[-1].startswith(expected["last_line_prefix"]):
                        bad.append("last line prefix")
                    for text in expected.get("forbidden_substrings", []):
                        if text in out:
                            bad.append(f"printed {text}")
                    for text in expected.get("codes", []):
                        if text not in err and text not in out:
                            bad.append(f"missing {text}")
                    if "not_verdict" in expected and report and report.get("verdict") == expected["not_verdict"]:
                        bad.append("verdict")
                    self.record(file, f"{case['id']}#{number}", engine, bad)


def document_values(case):
    return case["invalid_input_values"]


def place(path, spec, fixtures):
    if "utf8" in spec:
        path.write_bytes(spec["utf8"].encode())
    elif "hex" in spec:
        path.write_bytes(bytes.fromhex(spec["hex"]))
    elif "same_bytes_as" in spec:
        path.write_bytes((path.parent / spec["same_bytes_as"]).read_bytes())
    elif spec.get("filesystem_kind") == "directory":
        path.mkdir()
    elif spec.get("filesystem_kind") == "regular":
        path.write_bytes(bytes([spec["fill_byte"]]) * spec["byte_length"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--notes", action="store_true", help="list every case that was not replayed or skipped")
    parser.add_argument("--write-known", action="store_true", help="record today's divergences as the known list (review the diff)")
    parser.add_argument("--engine", choices=["rust", "python", "both"], default="both")
    parser.add_argument("--stand-ins", action="store_true", help="use the replay's own Ed25519 and P-256 even where PyNaCl and cryptography are installed")
    parser.add_argument("--rust-bin", default=str(pathlib.Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug/aukora-verify"))
    arguments = parser.parse_args()
    ed25519_ref.selftest()
    p256_ref.selftest()
    engines = []
    if arguments.engine in ("rust", "both"):
        engines.append(Engine("rust", [arguments.rust_bin]))
    if arguments.engine in ("python", "both"):
        environment, provider = python_environment(arguments.stand_ins)
        print(f"python engine signatures: {provider}")
        engines.append(Engine("python", [sys.executable, "-B", str(ROOT / "tools/verify.py")], environment))
    # Pinned vector files must all be present and named here; a new vector file needs a decision.
    present = sorted(p.stem for p in VECTORS.glob("*.json"))
    if present != sorted(ALL):
        print(f"FAIL verifier-vectors: vector files changed: {present}")
        return 1
    replay = Replay(engines)
    with tempfile.TemporaryDirectory() as work:
        for name in ALL:
            if name in NOT_REPLAYED:
                replay.not_replayed(name, "(whole file)", NOT_REPLAYED[name])
                continue
            document = json.loads((VECTORS / f"{name}.json").read_text())
            {"admission-regressions-v1": replay.admission, "regressions-v1": replay.regressions,
             "consistency-regressions-v1": replay.consistency, "operator-inputs-v1": replay.operator_inputs}[name](work, name, document)
        replay.owner_rule(work, "owner-rule")
        replay.owner_rule_v2(work, "owner-rule-v2")
    if arguments.write_known:
        if arguments.engine != "both":
            print("FAIL verifier-vectors: --write-known needs both engines")
            return 1
        known = {name: {k: v for k, v in sorted(cases.items()) if v is not None} for name, cases in replay.seen.items()}
        KNOWN.write_text(json.dumps(known, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
        print(f"wrote {KNOWN.name}: " + ", ".join(f"{k} {len(v)}" for k, v in known.items()))
        return 0
    totals = collections.Counter()
    for (file, engine, state), count in sorted(replay.counts.items()):
        totals[(engine, state)] += count
        print(f"{file:34} {engine:7} {state:12} {count}")
    for failure in replay.failures:
        print("FAIL", failure)
    print("summary:", ", ".join(f"{engine} {state} {count}" for (engine, state), count in sorted(totals.items())))
    for (file, engine), notes in sorted(replay.notes.items()):
        if arguments.notes:
            print(f"  {file} [{engine}]: " + "; ".join(notes))
    if replay.failures:
        print(f"FAIL verifier-vectors: {len(replay.failures)} cases differ from their expectations")
        return 1
    print("verifier-vectors: every replayed case matches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
