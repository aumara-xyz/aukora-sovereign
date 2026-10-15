# crates/copresence
- **Owns:** the co-presence receipt verifier and met-in-person marks.
- **Never owns:** authority: a receipt is evidence.
- **May depend on:** canon.
- **Bricks:** 47, 77, 132, 137 (NORTH-STAR.md).

Wave 0 freezes `v0`, `v1`, `receipt_json`, `verdict` and `met`; unwritten entry points refuse.
Pinned v0 bytes stay unchanged; hardened frames use a separate version and domain.
New verdict/layout data awaits conductor pinning; cryptographic accept vectors remain wave-1 work.
Canon must register pinned co-presence refusal codes before FD wire use. `vectors/person-bloom-v2.json` records the portal's person-key/WASM display composition for conductor pinning; receipt formats and legacy Pentora bloom vectors are unchanged.
