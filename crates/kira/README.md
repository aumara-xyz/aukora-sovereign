# crates/kira
- **Owns:** encrypted memory, cited recall, demotion (never deletion), memory permissions, the OpenViking adapter.
- **Never owns:** authority or model calls.
- **May depend on:** canon, aura.
- **Bricks:** 57, 58, 59, 60, 124 (NORTH-STAR.md).
- **Storage:** SQLite note retention, authenticated encryption, demotion, cited recall, permissions and local indexing; Aura and key access use injected adapters.
- **Health:** 18 private checks and 8 corner sides; missing observers report failed, never verified.
- **Integration:** save has no per-note approval; Aura must supply its nonauthorizing append route before persistence.
- **Vectors:** `vectors/aead-v1.json` records note associated-data bytes; `vectors/permission-target-v1.json` and `vectors/backup-aad-v1.json` specify permission targets and backup chunk associated data.
- **Dependencies:** encryption uses `chacha20poly1305`; nonces and identifiers use `getrandom`; storage uses `rusqlite`; local model files use `rustix`; adapters use `serde` and `serde_json`; commitments use `sha2`; transient keys use `zeroize`. `hkdf` remains reserved for future owner-root-bound wrapping or backup key derivation; Kira currently receives unwrapped keys through `MemoryKeys` and performs no HKDF derivation.
