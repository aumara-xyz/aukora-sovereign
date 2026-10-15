#!/usr/bin/env python3
"""Exercise the standalone verifier without importing any installed packages."""
import csv
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("cold_verifier", ROOT / "tools/verify.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

count = 0
with (ROOT / "crates/nostr/tests/vectors/bip340-test-vectors.csv").open(newline="") as vectors:
    for row in csv.DictReader(vectors):
        actual = verifier.schnorr_verify(bytes.fromhex(row["message"]),
            bytes.fromhex(row["public key"]), bytes.fromhex(row["signature"]))
        expected = row["verification result"] == "TRUE"
        assert actual == expected, f"BIP340 vector {row['index']}: {row['comment']}"
        count += 1
assert count == 19, count
print(f"BIP340 verification vectors: {count} passed")

assert not verifier.schnorr_verify(b"", bytes(31), bytes(64))
assert not verifier.schnorr_verify(b"", bytes(32), bytes(63))
assert verifier.nostr_npub(bytes(32)) == "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujme"
print("Standalone Nostr malformed-length and NIP-19 checks: 3 passed")
