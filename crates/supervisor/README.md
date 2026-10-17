# crates/supervisor
- **Owns:** wiring only: it starts the organs and routes FD 3 (proposals to the gate, model calls to the broker, memory to Kira).
- **Also owns:** the door for the engine's crossings (`sovereign door serve`, `src/door/`, see `DOOR.md`): it checks, rate-limits and records the engine's non-local tool calls and executes the few it allows (fetching allowlisted pages, forwarding memory calls with its own token).
- **Also owns:** assembling the engine's plugin closure from the owner-approved set (`src/engine_plugins.rs`): fingerprint the packages, load only approved digests, turn anything new into a `plugin` crossing for the passkey. Not yet called by the launcher.
- **Never owns:** policy of its own: the door follows a policy file the owner installs.
- **May depend on:** every organ crate.
- **Bricks:** 23, 61, 69, 128 (NORTH-STAR.md).
