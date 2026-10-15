# crates/aura
- **Owns:** the signed append-only record, epochs, the ledger transaction, cold export.
- **Never owns:** approvals, keys or policy.
- **May depend on:** canon.
- **Bricks:** 27, 41, 50, 51, 56, 110, 139 (NORTH-STAR.md).
