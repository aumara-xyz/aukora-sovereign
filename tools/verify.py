#!/usr/bin/env python3
"""
Aukora standalone Aura and RFC 6962 verifier
PERMITTED CLAIM: Retaining observation N enables checking presentation M.
FORBIDDEN CLAIMS: No occurrence, world truth, code execution, human identity.
NON-SUBJECT ASSUMPTION: Verification is executed cold on runner's own bytes.
LEGACY CONSISTENCY VERDICTS:
- APPEND_ONLY        : Proof connects to head and matches retained root.
- OBSERVATION_CONFLICT: Proof connects to head but derives DIFFERENT root.
- UNDETERMINED       : Proof fails to connect, corrupted, or 2^k limit.
"""
import sys, json, hashlib, re

MAX_SAFE_INT = 9007199254740991

def sha256_node(l: str, r: str) -> str:
    return hashlib.sha256(bytes([0x01]) + bytes.fromhex(l) + bytes.fromhex(r)).hexdigest()

def is_power_of_two(v: int) -> bool: return v > 0 and (v & (v - 1)) == 0
def is_digest(v: object) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v)
def is_size(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE_INT

def verify_consistency(m: int, n: int, root1: str, root2: str, proof: list) -> tuple:
    if not is_size(m) or not is_size(n) or m > n: return ("UNDETERMINED", "invalid_tree_sizes")
    if not is_digest(root1) or not is_digest(root2): return ("UNDETERMINED", "root_is_not_a_digest")
    if not isinstance(proof, list) or not all(is_digest(p) for p in proof):
        return ("UNDETERMINED", "proof_element_is_not_a_digest")

    if m == 0: return ("UNDETERMINED", "missing_prior_observation")
    if m == n:
        if len(proof) != 0: return ("UNDETERMINED", "non_empty_proof_for_same_size")
        if root1.lower() == root2.lower(): return ("APPEND_ONLY", "identical_trees_match")
        return ("OBSERVATION_CONFLICT", "same_size_root_mismatch")

    if not proof or len(proof) == 0: return ("UNDETERMINED", "empty_proof_for_different_sizes")

    p_idx = 0
    if is_power_of_two(m): fr, sr = root1, root1
    else:
        fr, sr = proof[p_idx], proof[p_idx]
        p_idx += 1

    fn, sn = m - 1, n - 1
    while (fn & 1) == 1: fn, sn = fn >> 1, sn >> 1

    while sn > 0:
        if (fn & 1) == 1 or fn == sn:
            if p_idx >= len(proof): return ("UNDETERMINED", "proof_path_truncated")
            nxt = proof[p_idx]
            p_idx += 1
            fr, sr = sha256_node(nxt, fr), sha256_node(nxt, sr)
            while fn > 0 and (fn & 1) == 0: fn, sn = fn >> 1, sn >> 1
        else:
            if p_idx >= len(proof): return ("UNDETERMINED", "proof_path_truncated")
            nxt = proof[p_idx]
            p_idx += 1
            sr = sha256_node(sr, nxt)
        fn, sn = fn >> 1, sn >> 1

    if sr.lower() != root2.lower():
        if is_power_of_two(m): return ("UNDETERMINED", "POWER_OF_TWO_PREFIX_NOT_INDEPENDENTLY_DERIVABLE")
        return ("UNDETERMINED", "proof_did_not_connect_to_presented_head")
    if p_idx != len(proof): return ("UNDETERMINED", "unconsumed_proof_elements")

    if fr.lower() == root1.lower(): return ("APPEND_ONLY", "valid_append_only_extension")
    if is_power_of_two(m): return ("UNDETERMINED", "POWER_OF_TWO_PREFIX_NOT_INDEPENDENTLY_DERIVABLE")
    return ("OBSERVATION_CONFLICT", "consistency:prefix-mismatch")

USAGE = """aukora minimal verifier — did the log you were shown extend the log you kept?

  python3 verify.py <retained.json> <presented.json>
  python3 verify.py --selftest
  python3 verify.py --bundle COLD_PROOF.json [--key PINNED_HEX_FILE] [--checkpoint HEAD.json]
  python3 verify.py witness COLD_PROOF.json EVENT.json

Legacy consistency mode verdicts:
  APPEND_ONLY           the proof folds to the presented head and reaches the root you retained
  OBSERVATION_CONFLICT  the proof folds to the presented head and reaches a DIFFERENT root
  UNDETERMINED          anything else — damaged, absent, or structurally underivable

UNDETERMINED IS NOT A SOFT NO AND APPEND_ONLY IS NOT TRUST. This checks arithmetic over two
observations. It says nothing about whether any leaf is true, whether the events occurred, or
whether the subject keeps only one log.

Cold --bundle mode verifies signatures, chain, root and exact exported tail.
Its embedded key and head are not independent witnesses. Identity and completeness stay
UNCHECKED unless --key pins the key independently and --checkpoint covers the full export."""

# ONE TOKENIZER HOOKS — SINGLE PARSER ADMISSION LAYER
# Refuses duplicate keys, non-canonical integers, floats, constants in ONE json.loads pass.
def no_duplicate_keys(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen: raise ValueError("duplicate key")
        seen.add(k)
    return dict(pairs)

def check_canonical_int(s: str) -> int:
    if not re.match(r'^(0|[1-9][0-9]{0,15})$', s):
        raise ValueError(f"non-canonical int token: {s}")
    val = int(s)
    if val < 0 or val > MAX_SAFE_INT:
        raise ValueError(f"integer out of safe range: {s}")
    return val

def reject_float(s: str):
    raise ValueError(f"float token forbidden: {s}")

def reject_constant(s: str):
    raise ValueError(f"constant token forbidden: {s}")

def run_selftest() -> bool:
    print("aukora minimal verifier — standalone in-memory self-test\n")
    r5 = "6f7f213a4c7fe7c7b034c3879840a49918481b4796c7f8583d3604e09158fa4b"
    r14 = "9fde8beaf87fd07070b5bc2068ef543e830653ab0245412e8a6d25a829db78de"
    p5_14 = [
        "2117942a52d6136b5020766f489c4c95063c3dd7d050743685f1e58af4189c56",
        "9fd396c9621758169909f320cd76d6d13c47e1df1f2a52615e9c6968fed6eb43",
        "f54a41ca7a75620fad5c51ab8310dbf6ca91e9c56ed2e48be64297b9ca8b6b99",
        "90283eea2a3492d5a7219a00a16389e132f01600e947b06392b47dd95f7f1567",
        "e72cc2893ebac0de5b880d9ebe2dbb26f1fba9f5d8d4196295dd3e8f4c580e23"
    ]
    v1, r1 = verify_consistency(5, 14, r5, r14, p5_14)
    ok1 = (v1 == "APPEND_ONLY")
    print(f"  {'ok' if ok1 else 'FAIL'}  positive control (m=5, n=14) -> {v1}")

    r4 = "90283eea2a3492d5a7219a00a16389e132f01600e947b06392b47dd95f7f1567"
    p4_14 = [
        "1ecf2a95d2edb667f8009d3d80730298b5375a959e62152e666ddc04aa9a181d",
        "e72cc2893ebac0de5b880d9ebe2dbb26f1fba9f5d8d4196295dd3e8f4c580e23"
    ]
    v2, r2 = verify_consistency(4, 14, r4, r14, p4_14)
    ok2 = (v2 == "APPEND_ONLY")
    print(f"  {'ok' if ok2 else 'FAIL'}  power-of-two valid extension (m=4, n=14) -> {v2}")

    r5_bad = "00" * 32
    v3, r3 = verify_consistency(5, 14, r5_bad, r14, p5_14)
    ok3 = (v3 == "OBSERVATION_CONFLICT")
    print(f"  {'ok' if ok3 else 'FAIL'}  earned accusation (m=5, n=14, modified root) -> {v3}")

    p4_bad = ["00"*32] + p4_14[1:]
    v4, r4_reason = verify_consistency(4, 14, r4, r14, p4_bad)
    ok4 = (v4 == "UNDETERMINED" and r4_reason == "POWER_OF_TWO_PREFIX_NOT_INDEPENDENTLY_DERIVABLE")
    print(f"  {'ok' if ok4 else 'FAIL'}  power-of-two blind spot limit (m=4, n=14, corrupted proof) -> {v4} ({r4_reason})")

    all_ok = ok1 and ok2 and ok3 and ok4
    print(f"\nSELFTEST: {'4/4 checks passed — all green' if all_ok else 'FAILURES DETECTED'}")
    return all_ok

MAX_INPUT_BYTES = 1_048_576

class InputNotRegular(Exception): pass
class InputTooLarge(Exception): pass

def read_input_path(path: str, max_bytes=MAX_INPUT_BYTES) -> bytes:
    import os, stat, fcntl
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as e:
        raise OSError(e.errno, f"open failed: {path}") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise InputNotRegular(path)
        if st.st_size > max_bytes:
            raise InputTooLarge(path)
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise InputTooLarge(path)
        return data
    finally:
        os.close(fd)

def main():
    if sys.argv[1:2] == ["witness"]:
        sys.exit(witness_main(sys.argv[2:]))
    if "--bundle" in sys.argv[1:]:
        sys.exit(cold_main(sys.argv[1:]))
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        ok = run_selftest()
        sys.exit(0 if ok else 1)
    if len(sys.argv) != 3 or any(arg.startswith("--") for arg in sys.argv[1:]):
        print(USAGE)
        print("UNCHECKED verifier:usage")
        sys.exit(64)
    try:
        ret_raw = read_input_path(sys.argv[1])
        pres_raw = read_input_path(sys.argv[2])
        print(f"RETAINED_SHA256 : {hashlib.sha256(ret_raw).hexdigest()}")
        print(f"PRESENTED_SHA256: {hashlib.sha256(pres_raw).hexdigest()}")
        try:
            ret_str = ret_raw.decode("utf-8")
            pres_str = pres_raw.decode("utf-8")
        except UnicodeDecodeError:
            print("UNCHECKED verifier:input-encoding"); sys.exit(64)

        try:
            ret = json.loads(
                ret_str, object_pairs_hook=no_duplicate_keys,
                parse_int=check_canonical_int, parse_float=reject_float, parse_constant=reject_constant
            )
            pres = json.loads(
                pres_str, object_pairs_hook=no_duplicate_keys,
                parse_int=check_canonical_int, parse_float=reject_float, parse_constant=reject_constant
            )
        except ValueError:
            print("VERDICT: UNDETERMINED\nREASON : document_is_not_admissible"); sys.exit(0)

        if "proofFromPrevious" not in pres:
            print("VERDICT: UNDETERMINED\nREASON : proof_field_absent"); sys.exit(0)

        verdict, reason = verify_consistency(
            ret.get("treeSize"), pres.get("treeSize"), ret.get("root"), pres.get("root"), pres["proofFromPrevious"])
        print(f"VERDICT: {verdict}\nREASON : {reason}")
        if verdict == "UNDETERMINED" and reason == "POWER_OF_TWO_PREFIX_NOT_INDEPENDENTLY_DERIVABLE":
            print("LIMIT: Retained m is 2^k; root1 is fold seed.")
        elif verdict == "OBSERVATION_CONFLICT":
            print(f"CLEAR: python3 verify.py {sys.argv[1]}")
    except InputNotRegular:
        print("UNCHECKED verifier:input-not-file"); sys.exit(64)
    except InputTooLarge:
        print("UNCHECKED verifier:input-too-large"); sys.exit(64)
    except (OSError, json.JSONDecodeError):
        print("UNCHECKED verifier:input-unreadable"); sys.exit(64)

# Cold proof admission and Ed25519 verification use only the Python standard library.
COLD_SCHEMA = "aukora-aura-cold-proof-v1"
AURA_DOMAIN = "aukora:aura-record:v1"
LEAF_CONVENTION = "rfc6962-leaf-sha256-0x00-prefixed-v1"
AURA_KINDS = frozenset(("boot.facts gate.propose gate.review gate.consume gate.apply "
    "gate.retire gate.refuse gate.expire gate.recover floor.advance aumlok.enrol "
    "aumlok.bind aumlok.signin broker.grant broker.reserve broker.settle broker.revoke "
    "kira.save kira.demote kira.permission sandbox.start sandbox.exit nostr.bind").split())

class ColdRefusal(ValueError):
    def __init__(self, code, seq=None, exact=True):
        super().__init__(code)
        self.seq, self.exact = seq, exact

def cold_require(condition, code):
    if not condition: raise ColdRefusal(code)

def cold_int(token):
    if not re.fullmatch(r"(?:0|-?[1-9][0-9]*)", token):
        raise ValueError("non-canonical integer")
    value = int(token)
    if abs(value) > MAX_SAFE_INT: raise ValueError("integer outside safe range")
    return value

def cold_validate(value, depth=0):
    if isinstance(value, (dict, list)):
        cold_require(depth < 64, "verifier:json-depth")
        items = list(value.keys()) + list(value.values()) if isinstance(value, dict) else value
        for item in items: cold_validate(item, depth + 1)
    elif isinstance(value, str):
        cold_require(not any(0xd800 <= ord(c) <= 0xdfff for c in value), "verifier:json-surrogate")

def cold_canonical(value):
    if isinstance(value, dict):
        keys = sorted(value, key=lambda item: item.encode("utf-16-be"))
        return "{" + ",".join(cold_canonical(k) + ":" + cold_canonical(value[k]) for k in keys) + "}"
    if isinstance(value, list): return "[" + ",".join(map(cold_canonical, value)) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

def cold_parse(raw, canonical=False):
    cold_require(not raw.startswith(b"\xef\xbb\xbf"), "verifier:json-bom")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
        parse_int=cold_int, parse_float=reject_float, parse_constant=reject_constant)
    cold_validate(value)
    if canonical:
        cold_require(cold_canonical(value).encode("utf-8") == raw, "verifier:json-not-canonical")
    return value

def cold_digest(value):
    cold_require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "verifier:bad-digest")
    return bytes.fromhex(value)

# RFC 8032 Edwards arithmetic; decoded points must have canonical encodings.
ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_I = pow(2, (ED_P - 1) // 4, ED_P)
ED_ID = (0, 1, 1, 0)

def ed_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % ED_P
    b = (y1 + x1) * (y2 + x2) % ED_P
    c = 2 * ED_D * t1 * t2 % ED_P
    d = 2 * z1 * z2 % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P)

def ed_mul(point, scalar):
    result = ED_ID
    while scalar:
        if scalar & 1: result = ed_add(result, point)
        point = ed_add(point, point)
        scalar >>= 1
    return result

def ed_equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % ED_P == 0 and (p[1] * q[2] - q[1] * p[2]) % ED_P == 0

def ed_decode(raw):
    cold_require(len(raw) == 32, "verifier:ed25519-point")
    encoded = int.from_bytes(raw, "little")
    sign, y = encoded >> 255, encoded & (2**255 - 1)
    cold_require(y < ED_P, "verifier:ed25519-point")
    y2 = y * y % ED_P
    x2 = (y2 - 1) * pow(ED_D * y2 + 1, ED_P - 2, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if x * x % ED_P != x2: x = x * ED_I % ED_P
    cold_require(x * x % ED_P == x2 and not (x == 0 and sign), "verifier:ed25519-point")
    if x & 1 != sign: x = ED_P - x
    return (x, y, 1, x * y % ED_P)

ED_BASE = ed_decode(bytes.fromhex("58" + "66" * 31))

def cold_key(raw):
    try:
        point = ed_decode(raw)
    except ColdRefusal:
        raise ColdRefusal("verifier:key-invalid") from None
    cold_require(not ed_equal(ed_mul(point, 8), ED_ID), "verifier:key-weak")
    return point

def cold_signature(key_bytes, point, message, text):
    import base64, binascii
    try:
        raw = base64.b64decode(text, validate=True)
        cold_require(len(raw) == 64 and base64.b64encode(raw).decode("ascii") == text, "verifier:signature")
        r = ed_decode(raw[:32])
        s = int.from_bytes(raw[32:], "little")
        cold_require(s < ED_L and not ed_equal(ed_mul(r, 8), ED_ID), "verifier:signature")
        h = int.from_bytes(hashlib.sha512(raw[:32] + key_bytes + message).digest(), "little") % ED_L
        return ed_equal(ed_mul(ED_BASE, s), ed_add(r, ed_mul(point, h)))
    except (ValueError, TypeError, binascii.Error):
        return False

def cold_root(leaves):
    if len(leaves) == 1: return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b"\x01" + cold_root(leaves[:split]) + cold_root(leaves[split:])).digest()

def cold_head(value):
    cold_require(isinstance(value, dict) and set(value) == {"schema", "leafConvention", "sequence", "hash", "treeSize", "root"}, "verifier:retained-format")
    cold_require(value["schema"] == "aukora-aura-retained-head-v1" and value["leafConvention"] == LEAF_CONVENTION, "verifier:retained-format")
    cold_require(is_size(value["treeSize"]) and value["treeSize"] > 0 and type(value["sequence"]) is int and value["sequence"] == value["treeSize"], "verifier:head-size")
    cold_digest(value["hash"])
    cold_digest(value["root"])
    return value

def cold_anchor(head, rows, leaves):
    size = head["treeSize"]
    if size > len(rows):
        raise ColdRefusal("verifier:shorter-than-checkpoint", len(rows) + 1)
    if rows[size - 1]["hash"] != head["hash"] or cold_root(leaves[:size]).hex() != head["root"]:
        raise ColdRefusal("verifier:checkpoint-mismatch", size, exact=False)

def cold_owner_binding(body):
    auth = body.get("auth")
    required = {"v", "node", "subject", "op", "proposal", "target", "new_sha256", "cell", "display_sha256", "challenge", "expires_at"}
    if not isinstance(auth, dict) or not required <= set(auth) or set(auth) - required - {"base_sha256"}: return False
    def hex_field(name, length):
        value = auth.get(name)
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    subject = auth.get("subject")
    shape = (type(auth["v"]) is int and auth["v"] == 1 and hex_field("node", 32)
        and hex_field("proposal", 32) and hex_field("challenge", 32)
        and isinstance(subject, str) and re.fullmatch(r"aukora:1:[0-9a-f]{64}", subject)
        and auth["op"] in ("apply", "retire", "release", "grant", "permission")
        and isinstance(auth["target"], str) and hex_field("new_sha256", 64)
        and hex_field("display_sha256", 64) and ("base_sha256" not in auth or hex_field("base_sha256", 64))
        and (auth["cell"] is None or isinstance(auth["cell"], dict)) and type(auth["expires_at"]) is int)
    if not shape or "authorization_digest" not in body: return False
    expected = cold_digest(body["authorization_digest"])
    actual = hashlib.sha256(b"aukora:owner-authorization:v1\x00" + cold_canonical(auth).encode("utf-8")).digest()
    cold_require(actual == expected, "verifier:authorization-digest")
    return True

GATE_MODULE_SHA256 = "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438"

def gate_require(condition):
    cold_require(condition, "verifier:gate-evidence")

def gate_equal(left, right):
    return cold_canonical(left) == cold_canonical(right)

def gate_object(value):
    cold_require(isinstance(value, dict), "verifier:expected-object")
    return value

def gate_field(value, name):
    cold_require(name in value, "verifier:missing-field-" + name)
    return value[name]

def gate_text(value, name):
    text = gate_field(value, name)
    cold_require(isinstance(text, str), "verifier:expected-string")
    return text

def gate_integer(value):
    cold_require(type(value) is int, "verifier:expected-integer")
    return value

def gate_hex(text, width):
    return isinstance(text, str) and len(text) == width and re.fullmatch(r"[0-9a-f]*", text) is not None

def gate_auth(authorization):
    auth = gate_object(authorization)
    required = {"v", "node", "subject", "op", "proposal", "target", "base_sha256",
        "new_sha256", "cell", "display_sha256", "challenge", "expires_at", "epoch", "operation"}
    metadata = {"owner_epoch", "owner_root_id", "binding_sha256", "issued_at", "issued_at_ms", "gate", "pubkey_fp"}
    gate_require(required <= set(auth) and set(auth) <= required | metadata)
    gate_require(type(auth["v"]) is int and auth["v"] == 1 and gate_hex(gate_text(auth, "node"), 32)
        and gate_hex(gate_text(auth, "proposal"), 32) and gate_hex(gate_text(auth, "challenge"), 64)
        and re.fullmatch(r"aukora:1:[0-9a-f]{64}", gate_text(auth, "subject")) is not None
        and gate_text(auth, "op") in ("apply", "retire", "release", "grant", "permission")
        and bool(gate_text(auth, "target")) and gate_integer(auth["epoch"]) > 0
        and gate_integer(auth["expires_at"]) >= 0
        and (gate_text(auth, "base_sha256") == "absent" or gate_hex(auth["base_sha256"], 64)))
    for name in ("new_sha256", "display_sha256", "operation"):
        cold_digest(auth[name])
    content = {name: auth[name] for name in ("v", "node", "target", "base_sha256", "new_sha256", "cell")}
    operation = hashlib.sha256(b"aukora:operation-content:v1\x00" + cold_canonical(content).encode("utf-8")).digest()
    gate_require(cold_digest(auth["operation"]) == operation)
    gate_require(auth["cell"] is None or isinstance(auth["cell"], dict))
    if "owner_epoch" in auth: gate_require(gate_equal(auth["owner_epoch"], auth["epoch"]))
    for name in ("binding_sha256", "owner_root_id", "gate"):
        if name in auth: cold_digest(auth[name])
    if "binding_sha256" in auth and "owner_root_id" in auth:
        gate_require(auth["binding_sha256"] == auth["owner_root_id"])
    for name in ("issued_at", "issued_at_ms"):
        if name in auth: gate_require(0 <= gate_integer(auth[name]) < auth["expires_at"])
    if "issued_at" in auth and "issued_at_ms" in auth:
        gate_require(auth["issued_at"] == auth["issued_at_ms"])
    if "pubkey_fp" in auth: gate_require(gate_text(auth, "pubkey_fp") == gate_text(auth, "gate")[:16])
    return auth

def gate_body(row):
    return gate_object(gate_field(gate_object(row), "body"))

def gate_referenced(rows, reference, before, kind, op):
    reference = gate_object(reference)
    seq = gate_integer(gate_field(reference, "seq"))
    gate_require(0 < seq < before)
    cold_require(seq <= len(rows), "verifier:gate-reference")
    row = gate_object(rows[seq - 1])
    gate_require(row["seq"] == seq and cold_digest(row["hash"]) == cold_digest(gate_field(reference, "hash"))
        and gate_text(row, "kind") == kind and gate_text(row, "op") == op)
    for alias, name in (("ledger_seq", "seq"), ("ledger_hash", "hash")):
        if alias in reference: gate_require(gate_equal(reference[alias], reference[name]))
    return row

def gate_cell_and_bytes(auth, card):
    from_to = gate_object(gate_field(card, "from_to"))
    new = gate_text(from_to, "new").encode("utf-8")
    gate_require(hashlib.sha256(new).digest() == cold_digest(auth["new_sha256"]))
    base = gate_field(from_to, "base")
    if base is None: gate_require(auth["base_sha256"] == "absent")
    elif isinstance(base, str): gate_require(hashlib.sha256(base.encode("utf-8")).hexdigest() == auth["base_sha256"])
    else: gate_require(False)
    cell = auth["cell"]
    if cell is None: return
    gate_require(set(cell) == {"module_sha256", "input_sha256", "effect_sha256"})
    gate_require(gate_text(cell, "module_sha256") == GATE_MODULE_SHA256
        and cold_digest(cell["effect_sha256"]) == hashlib.sha256(new).digest())
    cold_require(new.endswith(b"\n"), "verifier:cell-effect")
    arguments = gate_object(cold_parse(new[:-1], canonical=True))
    gate_require(set(arguments) == {"key", "value"})
    key = gate_text(arguments, "key").encode("utf-8")
    gate_require(1 <= len(key) <= 128 and re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9._:-]*", key) is not None
        and len(key) + len(cold_canonical(arguments["value"]).encode("utf-8")) <= 65_536
        and hashlib.sha256(new[:-1]).digest() == cold_digest(cell["input_sha256"]))

def gate_consume(rows, row):
    op = gate_text(row, "op")
    gate_require(gate_text(row, "kind") == "gate.consume" and gate_text(row, "phase") == "settle")
    consumed = gate_body(row)
    authorization = gate_field(consumed, "authorization")
    auth = gate_auth(authorization)
    gate_require(auth["op"] in ("apply", "release", "grant", "permission"))
    gate_require(auth["proposal"] == op and gate_field(consumed, "spent") is True)
    signed = hashlib.sha256(b"aukora:owner-authorization:v1\x00" + cold_canonical(authorization).encode("utf-8")).digest()
    cold_require(signed == cold_digest(gate_field(consumed, "authorization_sha256")), "verifier:authorization-digest")
    if "standing_permission" not in consumed:
        proof_text = gate_text(consumed, "proof_hex")
        gate_require(bool(proof_text) and gate_hex(proof_text, len(proof_text)) and len(proof_text) % 2 == 0)
        gate_require(hashlib.sha256(bytes.fromhex(proof_text)).digest() == cold_digest(gate_field(consumed, "proof_sha256")))
    review = gate_referenced(rows, gate_field(consumed, "review_issue"), row["seq"], "gate.review", op)
    gate_require(gate_text(review, "phase") == "fact")
    reviewed = gate_body(review)
    gate_require(gate_equal(gate_field(reviewed, "authorization"), authorization)
        and gate_equal(gate_field(reviewed, "owner_state"), gate_field(consumed, "owner_state")))
    owner = gate_object(reviewed["owner_state"])
    gate_require(gate_field(owner, "subject") == auth["subject"] and gate_equal(gate_field(owner, "epoch"), auth["epoch"]))
    if "binding_sha256" in auth: gate_require(gate_field(owner, "binding_sha256") == auth["binding_sha256"])
    card = gate_field(reviewed, "card")
    gate_require(hashlib.sha256(cold_canonical(card).encode("utf-8")).digest() == cold_digest(auth["display_sha256"]))
    gate_cell_and_bytes(auth, gate_object(card))
    proposals = [candidate for candidate in rows[:review["seq"] - 1] if isinstance(candidate, dict)
        and candidate.get("kind") == "gate.propose" and candidate.get("op") == op and candidate.get("phase") == "intent"]
    gate_require(len(proposals) == 1)
    proposed = gate_body(proposals[0])
    for name in ("target", "base_sha256", "new_sha256"):
        gate_require(gate_field(proposed, name) == auth[name])
    gate_require(gate_field(proposed, "digest") == auth["operation"])
    gate_require(sum(isinstance(candidate, dict) and candidate.get("kind") == "gate.consume"
        and candidate.get("op") == op for candidate in rows) == 1)
    if "standing_permission" in consumed:
        gate_standing(rows, row, row["at"], row["seq"])
    return auth

def gate_allowed_target(name):
    if not isinstance(name, str): return False
    parts = name.split("/")
    lower = name.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
    protected = {"release", "broker", "grant", "floor", "identity", "aumlok", "gate", "slider", "permission"}
    return (bool(name) and len(name.encode("utf-16-be")) // 2 <= 200 and "\\" not in name
        and not any(ord(char) <= 31 or ord(char) == 127 for char in name)
        and len(parts) >= 3 and parts[0] == "plugins"
        and all(part and part not in (".", "..") for part in parts)
        and not any(part in protected for part in re.split(r"[/._-]", lower))
        and not ("." in lower and lower.rsplit(".", 1)[1] in ("js", "mjs", "cjs", "ts", "sh", "py", "node", "so")))

def gate_permission(raw):
    value = gate_object(cold_parse(raw, canonical=True))
    cold_require(set(value) == {"v", "mode", "targets", "kinds", "max_count", "expires_at", "nonce"}, "verifier:standing-permission")
    targets = value["targets"]
    cold_require(isinstance(targets, list), "verifier:standing-permission")
    mode = gate_text(value, "mode")
    count = gate_integer(value["max_count"])
    cold_require(len(raw) <= 4096 and all(0x20 <= byte <= 0x7e for byte in raw)
        and type(value["v"]) is int and value["v"] == 1
        and mode in ("ask", "risky", "limits") and len(targets) <= 32
        and all(gate_allowed_target(target) for target in targets) and value["kinds"] == ["put"]
        and 0 <= count <= 1_000_000
        and ((not targets and count == 0) if mode == "ask" else (bool(targets) and count > 0))
        and gate_integer(value["expires_at"]) > 0 and gate_hex(gate_text(value, "nonce"), 32), "verifier:standing-permission")
    return value

def gate_standing(rows, row, at, before):
    consumed = gate_body(row)
    auth = gate_object(gate_field(consumed, "authorization"))
    reference = gate_object(gate_field(consumed, "standing_permission"))
    cold_require(set(reference) == {"v", "proposal", "authorization_sha256", "proof_sha256", "consume", "kind"}
        and type(gate_field(reference, "v")) is int and reference["v"] == 1
        and "proof_hex" not in consumed, "verifier:standing-reference")
    try:
        original = gate_referenced(rows, gate_field(reference, "consume"), row["seq"], "gate.consume", gate_text(reference, "proposal"))
    except (ColdRefusal, KeyError, TypeError):
        raise ColdRefusal("verifier:standing-reference") from None
    approved = gate_body(original)
    permission_auth = gate_object(gate_field(approved, "authorization"))
    cold_require("standing_permission" not in approved and gate_text(permission_auth, "target") == "gate/permission"
        and gate_text(permission_auth, "op") == "permission", "verifier:standing-permission")
    permission_auth = gate_consume(rows, original)
    cold_require(gate_field(reference, "authorization_sha256") == gate_field(approved, "authorization_sha256")
        and gate_field(reference, "proof_sha256") == gate_field(approved, "proof_sha256")
        and gate_field(consumed, "proof_sha256") == approved["proof_sha256"], "verifier:standing-reference")
    cold_require(gate_equal(gate_field(consumed, "owner_state"), gate_field(approved, "owner_state"))
        and gate_field(auth, "node") == permission_auth["node"], "verifier:standing-owner")
    applications = [candidate for candidate in rows[original["seq"]:row["seq"] - 1]
        if isinstance(candidate, dict) and candidate.get("kind") == "gate.apply" and candidate.get("op") == reference["proposal"]]
    cold_require(len(applications) == 1, "verifier:standing-permission")
    gate_owner_binding(rows, applications[0])
    latest = next((candidate for candidate in reversed(rows[:before - 1]) if isinstance(candidate, dict)
        and candidate.get("kind") == "gate.consume" and isinstance(candidate.get("body"), dict)
        and isinstance(candidate["body"].get("authorization"), dict)
        and candidate["body"]["authorization"].get("target") == "gate/permission"), None)
    cold_require(latest is not None and latest["seq"] == original["seq"], "verifier:standing-revoked")
    review = gate_referenced(rows, gate_field(approved, "review_issue"), original["seq"], "gate.review", reference["proposal"])
    card = gate_object(gate_field(gate_body(review), "card"))
    from_to = gate_object(gate_field(card, "from_to"))
    try:
        value = gate_permission(gate_text(from_to, "new").encode("utf-8"))
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise ColdRefusal("verifier:standing-permission") from None
    cold_require(value["mode"] != "ask" and auth["op"] == "apply" and auth["target"] in value["targets"]
        and gate_text(reference, "kind") == "put", "verifier:standing-scope")
    expires = gate_integer(value["expires_at"])
    cold_require(at >= 0 and at < expires and at < gate_integer(auth["expires_at"])
        and auth["expires_at"] <= expires, "verifier:standing-expired")
    used = sum(isinstance(candidate, dict) and candidate.get("kind") == "gate.consume"
        and isinstance(candidate.get("body"), dict) and isinstance(candidate["body"].get("standing_permission"), dict)
        and candidate["body"]["standing_permission"].get("proposal") == reference.get("proposal")
        for candidate in rows[:row["seq"]])
    cold_require(used <= gate_integer(value["max_count"]), "verifier:standing-count")
    review = gate_referenced(rows, gate_field(consumed, "review_issue"), row["seq"], "gate.review", auth["proposal"])
    card = gate_object(gate_field(gate_body(review), "card"))
    from_to = gate_object(gate_field(card, "from_to"))
    base = gate_field(from_to, "base")
    cold_require(gate_text(card, "risk") == "routine"
        and (base is None or isinstance(base, str) and len(base.encode("utf-8")) <= 65_536), "verifier:standing-scope")
    return reference["authorization_sha256"]

def gate_owner_binding(rows, row):
    if row["kind"] == "gate.consume":
        gate_consume(rows, row)
        return True
    gate_require(row["kind"] == "gate.apply" and row["phase"] == "terminal")
    receipt = gate_object(gate_field(gate_body(row), "receipt"))
    op = row["op"]
    consumption = gate_field(receipt, "owner_consumption")
    consumed_row = gate_referenced(rows, consumption, row["seq"], "gate.consume", op)
    auth = gate_consume(rows, consumed_row)
    consumed = gate_body(consumed_row)
    gate_require(type(gate_field(receipt, "v")) is int and receipt["v"] == 3 and gate_text(receipt, "kind") == "change")
    for name in ("proposal", "target", "node", "base_sha256", "new_sha256"):
        gate_require(gate_field(receipt, name) == auth[name])
    gate_require(gate_field(receipt, "approver") == auth["subject"])
    receipt_review = gate_field(gate_object(consumption), "review_issue")
    consume_review = gate_object(gate_field(consumed, "review_issue"))
    review = gate_referenced(rows, receipt_review, consumed_row["seq"], "gate.review", op)
    gate_require(review["seq"] == gate_integer(gate_field(consume_review, "seq"))
        and cold_digest(review["hash"]) == cold_digest(gate_field(consume_review, "hash")))
    authority = gate_object(gate_field(receipt, "owner_authorization"))
    if "standing_permission" in consumed:
        gate_require("standing_permission" in receipt and gate_equal(receipt["standing_permission"], consumed["standing_permission"]))
        gate_require(gate_integer(gate_field(receipt, "applied_at")) == row["at"])
        digest = gate_standing(rows, consumed_row, row["at"], row["seq"])
    else:
        digest = consumed["authorization_sha256"]
        gate_require(receipt.get("standing_permission") is None)
    gate_require(type(gate_field(authority, "version")) is int and authority["version"] == 1
        and gate_text(authority, "kind") == "aukora-owner-authorization-ref/v1"
        and gate_field(authority, "authorization_id") == digest
        and gate_field(authority, "authorization_sha256") == digest
        and gate_field(authority, "proof_sha256") == gate_field(consumed, "proof_sha256"))
    return True

# Verification arithmetic ported from BIP-0340 reference.py (BSD-2-Clause),
# vendored at crates/nostr/tests/vectors/bip340-reference.py; no signing code.
SCHNORR_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SCHNORR_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SCHNORR_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def schnorr_tagged_hash(tag, message):
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()

def schnorr_point_add(left, right):
    if left is None: return right
    if right is None: return left
    if left[0] == right[0] and left[1] != right[1]: return None
    if left == right:
        slope = 3 * left[0] * left[0] * pow(2 * left[1], SCHNORR_P - 2, SCHNORR_P) % SCHNORR_P
    else:
        slope = (right[1] - left[1]) * pow(right[0] - left[0], SCHNORR_P - 2, SCHNORR_P) % SCHNORR_P
    x = (slope * slope - left[0] - right[0]) % SCHNORR_P
    return x, (slope * (left[0] - x) - left[1]) % SCHNORR_P

def schnorr_point_mul(point, scalar):
    result = None
    for index in range(256):
        if (scalar >> index) & 1: result = schnorr_point_add(result, point)
        point = schnorr_point_add(point, point)
    return result

def schnorr_lift_x(x):
    if x >= SCHNORR_P: return None
    square = (pow(x, 3, SCHNORR_P) + 7) % SCHNORR_P
    y = pow(square, (SCHNORR_P + 1) // 4, SCHNORR_P)
    if pow(y, 2, SCHNORR_P) != square: return None
    return x, y if y & 1 == 0 else SCHNORR_P - y

def schnorr_verify(message, public_key, signature):
    if len(public_key) != 32 or len(signature) != 64: return False
    point = schnorr_lift_x(int.from_bytes(public_key, "big"))
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if point is None or r >= SCHNORR_P or s >= SCHNORR_N: return False
    challenge = int.from_bytes(schnorr_tagged_hash("BIP0340/challenge", signature[:32] + public_key + message), "big") % SCHNORR_N
    result = schnorr_point_add(schnorr_point_mul(SCHNORR_G, s), schnorr_point_mul(point, SCHNORR_N - challenge))
    return result is not None and result[1] % 2 == 0 and result[0] == r

def nostr_npub(public_key):
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    words, accumulator, bits = [], 0, 0
    for byte in public_key:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((accumulator >> bits) & 31)
    if bits: words.append((accumulator << (5 - bits)) & 31)
    hrp = "npub"
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = 1
    for word in expanded + words + [0] * 6:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ word
        for bit, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> bit) & 1: checksum ^= generator
    checksum ^= 1
    return hrp + "1" + "".join(alphabet[word] for word in words + [(checksum >> (5 * (5 - index))) & 31 for index in range(6)])

def cold_nostr_binding(row, aura_key):
    body = row["body"]
    cold_require(row["phase"] == "fact" and set(body) == {"schema", "node", "agent", "aura_key", "statement_sha256", "node_sig", "agent_sig"}
        and body["schema"] == "aukora-nostr-bind-v1", "verifier:nostr-binding-shape")
    cold_require(cold_digest(body["aura_key"]) == aura_key, "verifier:nostr-aura-key")
    public_keys = {}
    for role in ("node", "agent"):
        identity = body[role]
        cold_require(isinstance(identity, dict) and set(identity) == {"pubkey", "npub"}, "verifier:nostr-binding-shape")
        public_key = cold_digest(identity["pubkey"])
        cold_require(identity["npub"] == nostr_npub(public_key), "verifier:nostr-npub")
        public_keys[role] = public_key
    statement = {"domain": "aukora:nostr-identity-binding:v1", "aura_key": body["aura_key"],
        "node": body["node"]["pubkey"], "agent": body["agent"]["pubkey"]}
    digest = hashlib.sha256(cold_canonical(statement).encode("utf-8")).digest()
    cold_require(digest == cold_digest(body["statement_sha256"]), "verifier:nostr-statement")
    for role in ("node", "agent"):
        signature = body[role + "_sig"]
        cold_require(isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{128}", signature), "verifier:nostr-" + role + "-signature")
        cold_require(schnorr_verify(digest, public_keys[role], bytes.fromhex(signature)), "verifier:nostr-" + role + "-signature")

def verify_bundle_bytes(raw, pinned_key=None, checkpoint=None):
    bundle = cold_parse(raw, canonical=True)
    cold_require(isinstance(bundle, dict) and set(bundle) == {"schema", "publicKey", "head", "rows"} and bundle["schema"] == COLD_SCHEMA, "verifier:bundle-format")
    key_bytes = cold_digest(bundle["publicKey"])
    point = cold_key(key_bytes)
    if pinned_key is not None:
        text = pinned_key.decode("utf-8").strip()
        cold_require(re.fullmatch(r"[0-9a-fA-F]{64}", text), "verifier:key-encoding")
        pin = bytes.fromhex(text)
        cold_key(pin)
        cold_require(pin == key_bytes, "verifier:bundle-key-mismatch")
    head = cold_head(bundle["head"])
    rows = bundle["rows"]
    cold_require(isinstance(rows, list), "verifier:bundle-rows")
    retained = cold_head(cold_parse(checkpoint)) if checkpoint is not None else None
    previous, leaves, terminal, semantic, nostr_bindings = AURA_DOMAIN, [], {}, True, 0
    for seq, row in enumerate(rows, 1):
        try:
            cold_require(isinstance(row, dict) and set(row) == {"seq", "prev", "hash", "sig", "at", "kind", "actor", "op", "phase", "body"}, "verifier:row-columns")
            cold_require(type(row["seq"]) is int and row["seq"] == seq, "verifier:sequence")
            cold_require(type(row["at"]) is int and isinstance(row["kind"], str) and row["kind"] in AURA_KINDS and row["phase"] in ("intent", "settle", "terminal", "fact") and isinstance(row["body"], dict) and all(isinstance(row[k], str) for k in ("prev", "sig", "actor", "op")), "verifier:bundle-row-schema")
            entry_hash = cold_digest(row["hash"])
            cold_require(row["prev"] == previous, "verifier:prev-link")
            fields = {k: v for k, v in row.items() if k not in ("hash", "sig", "seq")}
            fields.update(sequence=seq, domain=AURA_DOMAIN)
            computed = hashlib.sha256(cold_canonical(fields).encode("utf-8")).digest()
            cold_require(computed == entry_hash, "verifier:entry-hash")
            cold_require(cold_signature(key_bytes, point, entry_hash, row["sig"]), "verifier:signature")
            if row["kind"] == "nostr.bind":
                nostr_bindings += 1
                cold_require(nostr_bindings <= 1, "verifier:nostr-second-binding")
                cold_nostr_binding(row, key_bytes)
            if row["kind"] in ("gate.consume", "gate.apply"):
                if "authorization" in row["body"] or "receipt" in row["body"]:
                    semantic = gate_owner_binding(rows, row) and semantic
                else:
                    cold_owner_binding(row["body"])
                    semantic = False
            if row["op"]:
                terminal[row["op"]] = terminal.get(row["op"], 0) + (row["phase"] == "terminal")
            previous = row["hash"]
            leaves.append(hashlib.sha256(b"\x00" + entry_hash).digest())
        except ColdRefusal as error:
            if error.seq is None: error.seq = seq
            raise
        except (ValueError, TypeError, KeyError):
            raise ColdRefusal("verifier:bundle-row-schema", seq) from None
    if len(rows) != head["treeSize"]:
        raise ColdRefusal("verifier:bundle-tail-size", min(len(rows), head["treeSize"]) + 1)
    cold_anchor(head, rows, leaves)
    independent_cover = False
    if retained is not None:
        cold_anchor(retained, rows, leaves)
        independent_cover = retained["treeSize"] == len(rows)
    semantic = semantic and all(count == 1 for count in terminal.values())
    return len(rows), pinned_key is not None, independent_cover, semantic

def cold_main(args):
    options = {}
    try:
        cold_require(len(args) % 2 == 0, "verifier:usage")
        for index in range(0, len(args), 2):
            flag, path = args[index:index + 2]
            cold_require(flag in ("--bundle", "--key", "--checkpoint") and flag not in options and path and not path.startswith("--"), "verifier:usage")
            options[flag] = path
        cold_require("--bundle" in options, "verifier:usage")
        raw = read_input_path(options["--bundle"], max_bytes=8_388_608)
        print(f"BUNDLE_SHA256 {hashlib.sha256(raw).hexdigest()}")
        pin = read_input_path(options["--key"]) if "--key" in options else None
        checkpoint = read_input_path(options["--checkpoint"]) if "--checkpoint" in options else None
        count, pinned, covered, semantic = verify_bundle_bytes(raw, pin, checkpoint)
        print(f"BUNDLE checked rows=1..{count} signatures, chain, root and exact exported tail")
        if not pinned: print("UNCHECKED verifier:identity-no-pinned-key (embedded public key is not independent identity)")
        if not covered: print("UNCHECKED verifier:completeness-no-covering-checkpoint")
        if not semantic: print("UNCHECKED verifier:owner-bindings-or-terminal-count")
        if pinned and covered and semantic:
            print(f"VERIFIED rows 1..{count}; signatures, chain, root and independently retained covering checkpoint")
            return 0
        print(f"UNCHECKED rows 1..{count}; see findings for unchecked scope")
        return 1
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, OSError, InputNotRegular, InputTooLarge) as error:
        code = str(error) if isinstance(error, ColdRefusal) else "verifier:bundle-malformed-or-unreadable"
        if code == "verifier:bundle-key-mismatch":
            print(f"FORGED {code}\nFORGED key mismatch")
            return 2
        if isinstance(error, ColdRefusal) and error.seq is not None:
            forged = code in ("verifier:signature", "verifier:nostr-node-signature", "verifier:nostr-agent-signature")
            print(f"{'FORGED' if forged else 'REWRITTEN'} seq={error.seq} {code}")
            if forged: print(f"FORGED bad signature at seq {error.seq}")
            elif error.exact: print(f"REWRITTEN first bad seq {error.seq}")
            else: print(f"REWRITTEN first bad seq unknown; changed entry at or before {error.seq} (retain rows to locate it)")
            return 2
        print(f"UNCHECKED {code}")
        return 64


def nostr_event_bytes(event):
    escapes = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f',
        '\n': '\\n', '\r': '\\r', '\t': '\\t'}
    def encode(value):
        if isinstance(value, str):
            return '"' + ''.join(escapes.get(char, char) for char in value) + '"'
        if isinstance(value, list): return '[' + ','.join(map(encode, value)) + ']'
        return str(value)
    return encode([0, event["pubkey"], event["created_at"], event["kind"],
        event["tags"], event["content"]]).encode("utf-8")

def witness_event(raw):
    try:
        cold_require(len(raw) <= 65_536, "verifier:witness-malformed")
        event = cold_parse(raw)
        cold_require(isinstance(event, dict) and set(event) ==
            {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}, "verifier:witness-malformed")
        event_id, public_key = cold_digest(event["id"]), cold_digest(event["pubkey"])
        cold_require(is_size(event["created_at"]) and is_size(event["kind"])
            and isinstance(event["content"], str), "verifier:witness-malformed")
        cold_require(isinstance(event["tags"], list) and all(isinstance(tag, list) and tag
            and all(isinstance(item, str) for item in tag) for tag in event["tags"]), "verifier:witness-malformed")
        cold_require(isinstance(event["sig"], str) and re.fullmatch(r"[0-9a-f]{128}", event["sig"]), "verifier:witness-malformed")
        cold_require(hashlib.sha256(nostr_event_bytes(event)).digest() == event_id, "verifier:witness-malformed")
        cold_require(schnorr_verify(event_id, public_key, bytes.fromhex(event["sig"])), "verifier:witness-malformed")
        cold_require(event["kind"] == 30078 and event["tags"] == [["d", "aukora-aura-head"]], "verifier:witness-malformed")
        return event
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ColdRefusal("verifier:witness-malformed") from None

def verify_witness_bytes(proof_raw, event_raw):
    event = witness_event(event_raw)
    try:
        retained = cold_parse(event["content"].encode("utf-8"), canonical=True)
        cold_require(isinstance(retained, dict), "verifier:witness-malformed")
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ColdRefusal("verifier:witness-malformed") from None
    cold_require(isinstance(retained.get("sequence"), int) and not isinstance(retained["sequence"], bool)
        and is_size(retained.get("treeSize")) and retained["treeSize"] > 0
        and retained["sequence"] == retained["treeSize"], "verifier:witness-size")
    try:
        cold_head(retained)
    except (ValueError, TypeError, KeyError):
        raise ColdRefusal("verifier:witness-malformed") from None
    try:
        bundle = cold_parse(proof_raw, canonical=True)
        rows = bundle["rows"]
        cold_require(isinstance(rows, list), "verifier:witness-proof")
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ColdRefusal("verifier:witness-proof") from None
    bindings = [row for row in rows if isinstance(row, dict) and row.get("kind") == "nostr.bind"]
    cold_require(len(bindings) == 1, "verifier:witness-binding")
    try:
        signer = cold_digest(bindings[0]["body"]["node"]["pubkey"])
    except (ValueError, TypeError, KeyError):
        raise ColdRefusal("verifier:witness-binding") from None
    cold_require(bytes.fromhex(event["pubkey"]) == signer, "verifier:witness-signer")
    try:
        verify_bundle_bytes(proof_raw)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ColdRefusal("verifier:witness-proof") from None
    size = retained["treeSize"]
    cold_require(size <= len(rows), "verifier:witness-size")
    hashes = [cold_digest(row["hash"]) for row in rows[:size]]
    leaves = [hashlib.sha256(b"\x00" + digest).digest() for digest in hashes]
    cold_require(cold_root(leaves).hex() == retained["root"] and hashes[-1].hex() == retained["hash"], "verifier:witness-fork")
    return size, len(rows)

def witness_main(args):
    try:
        if len(args) != 2 or not all(args):
            print("REFUSED verifier:usage")
            return 64
        try:
            proof = read_input_path(args[0], max_bytes=8_388_608)
        except (OSError, InputNotRegular, InputTooLarge):
            raise ColdRefusal("verifier:witness-unreadable") from None
        try:
            event = read_input_path(args[1], max_bytes=65_536)
        except InputTooLarge:
            raise ColdRefusal("verifier:witness-malformed") from None
        except (OSError, InputNotRegular):
            raise ColdRefusal("verifier:witness-unreadable") from None
        size, count = verify_witness_bytes(proof, event)
        print(f"WITNESS verified prefix={size} proof={count}")
        print("UNCHECKED independent identity and completeness after the witnessed prefix")
        return 0
    except ColdRefusal as error:
        print(f"REFUSED {error}")
        return 2


if __name__ == "__main__": main()
