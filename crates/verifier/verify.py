#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wave-0 byte-only verifier entry points; no cryptography is implemented here."""

import sys

COLD_PROOF_V1 = "aukora-aura-cold-proof-v1"
RETAINED_HEAD_V1 = "aukora-aura-retained-head-v1"
PRESENTED_HEAD_V1 = "aukora-aura-presented-head-v1"


class Refusal(ValueError):
    """A refusal is data, never a positive verification verdict."""


def export_version(schema: str):
    """Only the frozen cold-proof-v1 schema is recognized."""
    if schema != COLD_PROOF_V1:
        raise Refusal("verifier:unsupported-schema")
    return COLD_PROOF_V1


def verify_bundle(bundle: bytes, *, pinned_key=None, checkpoint=None):
    """Reserved cold-proof verifier; always refuses until wave 1."""
    raise Refusal("verifier:unimplemented")


def verify_chain(rows: bytes, *, pinned_key: bytes, retained=None,
                 presented=None, retained_rows=None, checkpoint=None):
    """Reserved chain verifier; always refuses until wave 1."""
    raise Refusal("verifier:unimplemented")


def verify_consistency(retained: bytes, presented: bytes):
    """Reserved consistency verifier; unknown is never converted to success."""
    raise Refusal("verifier:unimplemented")


def verify_witness(bundle: bytes, event: bytes, *, pinned_key=None, checkpoint=None):
    """Reserved detached witness verifier; performs no external lookup."""
    raise Refusal("verifier:unimplemented")


def main(arguments):
    """No CLI invocation can report successful verification in wave 0."""
    if not arguments:
        print("verifier:usage", file=sys.stderr)
        return 64
    print("verifier:unimplemented", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
