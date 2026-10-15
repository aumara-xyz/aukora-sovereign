# crates/wasmcell
- **Owns:** the pinned 101-byte cell (data) run in the proposal path, and the theme adapter.
- **Never owns:** a sandbox for apps, or WASI.
- **May depend on:** canon.
- **Bricks:** 64 (NORTH-STAR.md).
