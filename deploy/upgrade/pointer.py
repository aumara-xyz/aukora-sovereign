# SPDX-License-Identifier: AGPL-3.0-or-later
"""The deploy guard (row 131), second half: an existing node changes only to a commit that a release pointer
names, signed by its owner's passkey over the pointer's exact bytes. No worker writes that pointer or its key.

Three files come from outside the repository's tracked data and are checked here, before upgrade makes any host call:

  release pointer   canonical JSON {schema, node, commit, release, seq}; `release` is the sha256 of the release
                    manifest (release.json) the commit builds to, `seq` rises with every pointer for the node.
  assertion         the WebAuthn assertion over it {schema, credential_id, authenticator_data, client_data_json,
                    signature}, all base64url. The challenge is base64url(sha256("aukora:release-pointer:v1" 0x00
                    pointer bytes)).
  owner credential  {schema, node, rp_id, origin, top_origin, credential_id, alg, public_key}: what the owner's
                    passkey is on that node. public_key is the base64url SubjectPublicKeyInfo of an ES256 key.

The signature check uses the system openssl; nothing here implements a primitive. A pointer for another node, a
challenge for other bytes, a wrong origin or RP, a missing user-verification flag, another credential or another
algorithm all refuse. Sequence replay is refused again on the node itself (node_release.py)."""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "spawn"))
import core  # noqa: E402

POINTER_SCHEMA = "aukora-release-pointer-v1"
ASSERTION_SCHEMA = "aukora-release-assertion-v1"
CREDENTIAL_SCHEMA = "aukora-owner-credential-v1"
DOMAIN = b"aukora:release-pointer:v1"
ES256 = -7
# SubjectPublicKeyInfo header of a P-256 key, followed by the 65-byte uncompressed point.
P256_SPKI = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80


@dataclass(frozen=True)
class Pointer:
    node: str
    commit: str
    release: str
    seq: int
    sha256: str  # of the pointer bytes


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text, reason):
    """Strict unpadded base64url that re-encodes to the same text."""
    if not isinstance(text, str) or re.fullmatch("[A-Za-z0-9_-]*", text) is None or len(text) % 4 == 1:
        core.refuse("upgrade", reason)
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        core.refuse("upgrade", reason)
    if b64url(data) != text:
        core.refuse("upgrade", reason)
    return data


def challenge(pointer_bytes):
    return b64url(hashlib.sha256(DOMAIN + b"\x00" + pointer_bytes).digest())


def es256_verify(spki, message, signature):
    if (not spki.startswith(P256_SPKI) or len(spki) != len(P256_SPKI) + 65 or spki[len(P256_SPKI)] != 4):
        core.refuse("upgrade", "pointer-key")
    openssl = shutil.which("openssl")
    if openssl is None:
        core.refuse("upgrade", "openssl-missing")
    encoded = base64.b64encode(spki).decode("ascii")
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) \
        + "\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="aukora-pointer-") as scratch:
        for name, data in (("key.pem", pem.encode("ascii")), ("message", message), ("signature", signature)):
            with open(os.path.join(scratch, name), "wb") as target:
                target.write(data)
        done = subprocess.run([openssl, "dgst", "-sha256", "-verify", os.path.join(scratch, "key.pem"),
                               "-signature", os.path.join(scratch, "signature"), os.path.join(scratch, "message")],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if done.returncode != 0 or done.stdout.strip() != b"Verified OK":
        core.refuse("upgrade", "pointer-signature")


def read_credential(path, node):
    credential = core.parse_json(core.read_regular(path, 8192, "upgrade"), "upgrade", 8192)
    core.exact_keys(credential, ("schema", "node", "rp_id", "origin", "top_origin", "credential_id", "alg", "public_key"),
                    "upgrade", "pointer-key")
    top = credential["top_origin"]
    if (credential["schema"] != CREDENTIAL_SCHEMA or credential["node"] != node or credential["alg"] != ES256
            or not isinstance(credential["rp_id"], str) or not core.is_hostname(credential["rp_id"])
            or not isinstance(credential["origin"], str) or not credential["origin"].startswith("https://")
            or not (top is None or (isinstance(top, str) and top.startswith("https://")))):
        core.refuse("upgrade", "pointer-key")
    credential["_id"] = unb64url(credential["credential_id"], "pointer-key")
    credential["_spki"] = unb64url(credential["public_key"], "pointer-key")
    return credential


def verify(pointer_path, assertion_path, credential_path, node):
    """The Pointer if, and only if, the owner's passkey signed exactly these bytes for this node."""
    raw = core.read_regular(pointer_path, 4096, "upgrade")
    document = core.parse_json(raw, "upgrade", 4096)
    core.exact_keys(document, ("schema", "node", "commit", "release", "seq"), "upgrade", "pointer")
    if core.canonical(document) != raw:
        core.refuse("upgrade", "pointer-not-canonical")
    if (document["schema"] != POINTER_SCHEMA or document["node"] != node or not core.is_hex(document["commit"], 40)
            or not core.is_hex(document["release"], 64) or not core.is_int(document["seq"], 1)):
        core.refuse("upgrade", "pointer")
    credential = read_credential(credential_path, node)
    assertion = core.parse_json(core.read_regular(assertion_path, 16384, "upgrade"), "upgrade", 16384)
    core.exact_keys(assertion, ("schema", "credential_id", "authenticator_data", "client_data_json", "signature"),
                    "upgrade", "pointer-assertion")
    if assertion["schema"] != ASSERTION_SCHEMA or unb64url(assertion["credential_id"], "pointer-assertion") != credential["_id"]:
        core.refuse("upgrade", "pointer-assertion")
    authenticator = unb64url(assertion["authenticator_data"], "pointer-assertion")
    client_bytes = unb64url(assertion["client_data_json"], "pointer-assertion")
    signature = unb64url(assertion["signature"], "pointer-assertion")
    client = core.parse_json(client_bytes, "upgrade", 8192)
    if not isinstance(client, dict) or client.get("type") != "webauthn.get":
        core.refuse("upgrade", "pointer-client-data")
    if client.get("challenge") != challenge(raw) or client.get("origin") != credential["origin"]:
        core.refuse("upgrade", "pointer-client-data")
    top = credential["top_origin"]
    if top is not None:
        framed = client.get("crossOrigin") is True and client.get("topOrigin") == top
    else:
        framed = client.get("crossOrigin") in (None, False) and "topOrigin" not in client
    if not framed:
        core.refuse("upgrade", "pointer-client-data")
    if len(authenticator) != 37 or authenticator[:32] != hashlib.sha256(credential["rp_id"].encode("ascii")).digest():
        core.refuse("upgrade", "pointer-authenticator")
    flags = authenticator[32]
    if not flags & FLAG_UP or not flags & FLAG_UV or flags & (FLAG_AT | FLAG_ED):
        core.refuse("upgrade", "pointer-authenticator")
    es256_verify(credential["_spki"], authenticator + hashlib.sha256(client_bytes).digest(), signature)
    return Pointer(node, document["commit"], document["release"], document["seq"], core.sha256_hex(raw))


def main(argv):
    if len(argv) == 2 and argv[0] == "challenge":
        print(challenge(core.read_regular(argv[1], 4096, "upgrade")))
        return 0
    if len(argv) == 5 and argv[0] == "verify":
        found = verify(argv[2], argv[3], argv[4], argv[1])
        print("node=%s commit=%s release=%s seq=%d" % (found.node, found.commit, found.release, found.seq))
        return 0
    core.refuse("upgrade", "usage")


if __name__ == "__main__":
    core.run_main("upgrade", main)
