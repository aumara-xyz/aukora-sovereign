# crates/supervisor
- **Owns:** wiring only: it starts the organs and routes FD 3 (proposals to the gate, model calls to the broker, memory to Kira).
- **Never owns:** policy.
- **May depend on:** every organ crate.
- **Bricks:** 23, 61, 69, 128 (NORTH-STAR.md).
