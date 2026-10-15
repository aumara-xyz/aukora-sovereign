# tools/
verify.py, the stranger's verifier in Python: the twin of crates/verifier.

**Bricks:** none (NORTH-STAR.md).

The script reads local bytes and never contacts the node or a relay. Ed25519
verification requires PyNaCl; detached Nostr evidence also requires coincurve.
An unavailable provider refuses with `verifier:crypto-unavailable`.

`python3 -B tools/verify.py --bundle export.json --key owner-key.hex --checkpoint retained-head.json`
checks a cold export. The key and covering head must have been retained
independently. Embedded claims alone yield `UNCHECKED`.

The script also accepts `--key KEY --rows ROWS` with optional `--prefix OLD_ROWS`,
`--retained HEAD --presented HEAD`, and `--checkpoint HEAD`; `witness BUNDLE EVENT`
checks a detached Nostr observation, and `consistency RETAINED PRESENTED` checks
only the two supplied Merkle observations. None of these checks grants authority.
