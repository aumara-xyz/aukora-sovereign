#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repository compatibility entry point for the standalone stranger verifier."""

import importlib.util
import pathlib
import sys

_SOURCE = pathlib.Path(__file__).resolve().parents[2] / "tools" / "verify.py"
_SPEC = importlib.util.spec_from_file_location("aukora_stranger_verifier", _SOURCE)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("verifier:implementation-unavailable")
_IMPLEMENTATION = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_IMPLEMENTATION)

COLD_PROOF_V1 = "aukora-aura-cold-proof-v1"
RETAINED_HEAD_V1 = "aukora-aura-retained-head-v1"
PRESENTED_HEAD_V1 = "aukora-aura-presented-head-v1"
Refusal = _IMPLEMENTATION.Refusal


def export_version(schema: str):
    return _IMPLEMENTATION.export_version(schema)


def verify_bundle(bundle: bytes, *, pinned_key=None, checkpoint=None, owner_key=None):
    return _IMPLEMENTATION.verify_bundle(bundle, pinned_key=pinned_key, checkpoint=checkpoint, owner_key=owner_key)


def verify_chain(rows: bytes, *, pinned_key: bytes, retained=None,
                 presented=None, retained_rows=None, checkpoint=None):
    return _IMPLEMENTATION.verify_chain(rows, pinned_key=pinned_key, retained=retained,
                                        presented=presented, retained_rows=retained_rows,
                                        checkpoint=checkpoint)


def verify_consistency(retained: bytes, presented: bytes):
    return _IMPLEMENTATION.verify_consistency(retained, presented)


def verify_witness(bundle: bytes, event: bytes, *, pinned_key=None, checkpoint=None, owner_key=None):
    return _IMPLEMENTATION.verify_witness(bundle, event, pinned_key=pinned_key, checkpoint=checkpoint,
                                          owner_key=owner_key)


def main(arguments):
    return _IMPLEMENTATION.main(arguments)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
