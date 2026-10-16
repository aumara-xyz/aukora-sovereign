# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator signature preflight for release-pointer v2.

The installed node uses its current sovereign binary to verify Aura authority and the passkey assertion. A supplied
credential can pass this local preflight but cannot authorize the node's release switch.

The canonical v2 object contains schema (aukora-release-pointer-v2) and body. The body's exact fields are node,
instance (64 lowercase hex digits), commit, release, seq and not_after (exclusive Unix milliseconds). The challenge
is base64url(SHA-256(aukora:release-pointer:v2, NUL, exact outer bytes)). V1 pointers refuse without changing v1.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "spawn"))
import core  # noqa: E402
import node_release  # noqa: E402

CREDENTIAL_SCHEMA = "aukora-owner-credential-v1"
ES256, EDDSA = node_release.ES256, node_release.EDDSA
Pointer = node_release.Pointer
challenge = node_release.challenge
require_live = node_release.require_live
unb64url = node_release.unb64url
read_assertion = node_release.read_assertion
verify_bytes = node_release.verify_bytes


def read_credential(path, node):
    credential = core.parse_json(core.read_regular(path, 8192, "upgrade"), "upgrade", 8192)
    core.exact_keys(credential, ("schema", "node", "rp_id", "origin", "top_origin", "credential_id", "alg", "public_key"),
                    "upgrade", "pointer-key")
    top = credential["top_origin"]
    if (credential["schema"] != CREDENTIAL_SCHEMA or credential["node"] != node
            or type(credential["alg"]) is not int or credential["alg"] not in (ES256, EDDSA)
            or not isinstance(credential["rp_id"], str) or not core.is_hostname(credential["rp_id"])
            or not isinstance(credential["origin"], str) or not credential["origin"].startswith("https://")
            or not (top is None or (isinstance(top, str) and top.startswith("https://")))):
        core.refuse("upgrade", "pointer-key")
    credential["_id"] = unb64url(credential["credential_id"], "pointer-key")
    credential["_spki"] = unb64url(credential["public_key"], "pointer-key")
    if not 1 <= len(credential["_id"]) <= 1024:
        core.refuse("upgrade", "pointer-key")
    return credential


def verify(pointer_path, assertion_path, credential_path, node):
    """Local signature preflight; only the node's stored binding authorizes its switch."""
    raw = core.read_regular(pointer_path, 4096, "upgrade")
    credential = read_credential(credential_path, node)
    assertion = read_assertion(assertion_path)
    return verify_bytes(raw, assertion, credential, node)


def main(argv):
    if len(argv) == 2 and argv[0] == "challenge":
        print(challenge(core.read_regular(argv[1], 4096, "upgrade")))
        return 0
    if len(argv) == 5 and argv[0] == "verify":
        found = verify(argv[2], argv[3], argv[4], argv[1])
        print("node=%s instance=%s commit=%s release=%s seq=%d not_after=%d" %
              (found.node, found.instance, found.commit, found.release, found.seq, found.not_after))
        return 0
    core.refuse("upgrade", "usage")


if __name__ == "__main__":
    core.run_main("upgrade", main)
