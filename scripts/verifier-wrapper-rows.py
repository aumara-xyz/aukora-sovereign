#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Can a ledger written by the real gate ever verify? Run it: it builds one and asks both verifiers.

The gate writes its `gate.consume` and `gate.apply` rows with the Aura authority wrapper as the row body
(`aukora-aura-authority-body-v1`: schema, algorithm, epoch, sequence, previous_hash, payload). Both verifiers decide
`owner_bindings` from `auth` / `authorization` / `receipt` found at the top of the row body, the shape the archive's gate
wrote, and a wrapper body has none of them. This script signs a three-row ledger (a boot fact, a consume, an apply) with
the replay's reference Ed25519, gives each verifier the matching key and a covering checkpoint, and prints what they say.

Both say UNCHECKED, with a finding on each gate row, whatever else is supplied: a wrapper row is never "bound", and
`owner::check` (the v2 passkey check) only adds findings, never clears one. So VERIFIED is unreachable for any ledger
that holds a gate.consume or gate.apply written by the real gate. See scripts/verifier-vectors.py for the replay.

    python3 -B scripts/verifier-wrapper-rows.py
"""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("replay", HERE / "verifier-vectors.py")
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)

SEED = "25" * 32
OPERATION = "ab" * 16


def wrapper(number, previous, state):
    payload = {"proposal": "cd" * 16, "target": "theme", "operation": "ef" * 32, "base_sha256": "11" * 32,
               "new_sha256": "22" * 32, "state": state, "retry": False, "consumed_approval": "33" * 32}
    return {"schema": "aukora-aura-authority-body-v1", "algorithm": "sha256", "epoch": 1, "sequence": number,
            "previous_hash": previous, "payload": payload}


def ledger():
    rows, previous = [], replay.AURA_DOMAIN
    for number, (kind, phase, actor, op, state) in enumerate([("boot.facts", "fact", "supervisor", "", None),
                                                               ("gate.consume", "settle", "owner", OPERATION, "consumed"),
                                                               ("gate.apply", "terminal", "owner", OPERATION, "applied")], 1):
        body = {"index": 0, "message": "honest"} if state is None else wrapper(number, previous, state)
        row = {"seq": number, "prev": previous, "at": 1760000000000 + number, "kind": kind, "actor": actor, "op": op,
               "phase": phase, "body": body}
        row["hash"] = replay.row_hash(row, number, previous)
        row["sig"] = replay.sign_hex(SEED, row["hash"])
        rows.append(row)
        previous = row["hash"]
    public = replay.ed25519_ref.public_key(bytes.fromhex(SEED)).hex()
    head = replay.head_over(rows)
    return {"schema": "aukora-aura-cold-proof-v1", "publicKey": public, "head": head, "rows": rows}, public, head


def main():
    replay.ed25519_ref.selftest()
    bundle, public, head = ledger()
    environment, provider = replay.python_environment()
    engines = [replay.Engine("rust", [str(pathlib.Path(replay.ROOT / "target/debug/aukora-verify"))]),
               replay.Engine("python", [sys.executable, "-B", str(replay.ROOT / "tools/verify.py")], environment)]
    print("ledger: boot.facts, then a gate.consume and a gate.apply whose bodies are the Aura authority wrapper;")
    print("all hashes, links and Ed25519 signatures are valid; the key and a covering head are supplied independently.")
    with tempfile.TemporaryDirectory() as work:
        directory = pathlib.Path(work)
        (directory / "proof.json").write_bytes(replay.c1(bundle))
        (directory / "key.hex").write_text(public)
        (directory / "head.json").write_bytes(replay.c1(head))
        for engine in engines:
            code, out, _, report = engine.run(["--bundle", "proof.json", "--key", "key.hex", "--checkpoint", "head.json"], directory)
            findings = ", ".join(f"{f['code']}@{f['sequence']}" for f in report["findings"]) if report else out.strip()
            print(f"  {engine.name:7} verdict {report['verdict'] if report else None}  exit {code}  findings: {findings}")
    print("VERIFIED is unreachable for these rows: the owner binding is looked for where the real gate does not put it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
