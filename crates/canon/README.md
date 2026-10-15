# crates/canon
- **Owns:** canonical JSON (C1), FD 3 and FD 4 data contracts, ids, digests, algorithm ids, refusal codes, authority proof and transaction interfaces, the 110-check health registry, and the browser WASM ABI.
- **Never owns:** policy, storage or keys.
- **May depend on:** no organ crate. External primitives and encodings use only the allowlisted sha2, base64, bech32, serde and serde_json crates; clientDataJSON has its own parser, separate from C1.
- **Bricks:** 32, 139 (NORTH-STAR.md).
