# supervisor

**Owns:** Wiring only: starts the organs, owns process lifecycle, routes FD 3 frames and owner API calls to organ crates. Package and binary are named `sovereign`.

**Never owns:** Policy, SQL beyond wiring, domain logic (being moved out to the organ crates).

**May depend on:** every organ crate.

**Bricks:** #23, #25, #69, #103 in [NORTH-STAR.md](../../NORTH-STAR.md).
