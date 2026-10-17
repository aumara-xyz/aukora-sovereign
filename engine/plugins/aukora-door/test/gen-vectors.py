# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent implementation of C1 canonical JSON and the door call digest, used only to produce vectors.json.

It shares no code with src/canonical.ts. The TypeScript tests assert that both produce the same bytes, and the
Rust door must reproduce the same digests (crates/canon/src/json.rs is the C1 reference).

Run: python3 -B -I gen-vectors.py > vectors.json
"""
import base64
import hashlib
import json
import struct
import sys

DOMAIN = b"aukora:door-call:v1"
MAX_SAFE = 9007199254740991
SHORT = {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}


def quote(text):
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code in SHORT:
            out.append(SHORT[code])
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canon(value, depth=0):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE:
            raise ValueError("integer outside the safe range")
        return str(value)
    if isinstance(value, str):
        return quote(value)
    if depth + 1 > 64:
        raise ValueError("nesting beyond 64 containers")
    if isinstance(value, list):
        return "[" + ",".join(canon(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return "{" + ",".join(quote(key) + ":" + canon(value[key], depth + 1) for key in keys) + "}"
    raise TypeError("not JSON data")


def digest(tool, canonical_bytes):
    name = tool.encode("utf-8")
    return hashlib.sha256(DOMAIN + b"\0" + struct.pack(">I", len(name)) + name + canonical_bytes).hexdigest()


def nested(levels):
    value = 1
    for _ in range(levels):
        value = [value]
    return value


CASES = [
    ("simple", "read", {"file_path": "notes.txt"}),
    ("empty-object", "todo_write", {}),
    ("key-order-and-nesting", "edit", {"b": 1, "a": [True, None, {"z": 0, "y": -5}], "c": ""}),
    ("utf16-key-order", "write", {"": 1, "\U00010000": 2, "a": 3}),
    ("escapes", "bash", {"command": 'a"b\\c\n\t\b\f\r\u0001\u001f\u007f  end'}),
    ("safe-integers", "grep", {"hi": MAX_SAFE, "lo": -MAX_SAFE, "zero": 0}),
    ("empty-containers", "glob", {"a": [], "b": {}, "c": [[], {}]}),
    ("unicode-tool-and-text", "exécute", {"text": "café \U0001f600 中文"}),
    ("depth-64", "run_code", {"deep": nested(63)}),
]


def main():
    vectors = []
    for label, tool, args in CASES:
        text = canon(args)
        raw = text.encode("utf-8")
        vectors.append({
            "name": label,
            "tool": tool,
            "args": args,
            "canonical": text,
            "args_canonical_b64": base64.b64encode(raw).decode("ascii"),
            "digest_sha256": digest(tool, raw),
        })
    json.dump({"domain": DOMAIN.decode("ascii"), "vectors": vectors}, sys.stdout, indent=1, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
