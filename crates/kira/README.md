# crates/kira
- **Owns:** encrypted memory, cited recall, demotion (never deletion), memory permissions, the OpenViking adapter.
- **Never owns:** authority or model calls.
- **May depend on:** canon, aura.
- **Bricks:** 57, 58, 59, 60, 124 (NORTH-STAR.md).
- **Wave 0:** typed storage, recall, permissions, local indexing and encrypted-backup interfaces; no runtime store.
- **Health:** 18 private checks and 8 corner sides; missing observers report failed, never verified.
- **Integration:** save has no per-note approval; Aura must supply its nonauthorizing append route before persistence.
- **Vectors:** `vectors/aead-v1.json` freezes associated-data bytes; cipher implementation belongs to wave 1.
