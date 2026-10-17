# guest/
Our harness: Auma's agent loop inside the cage, one static Rust binary (package `guest`, binary `auma`). Her only operations are chat, threads, sessions, streaming replies, presets, compaction, proposals and memory. FD 3 carries proposals, model calls, memory and durable-session requests to the supervisor. FD 4 carries only bounded app commands and session events through the guest’s typed link. She never executes a command or opens a socket (superseded by Part 1, Peter 2026-10-16). May depend on: canon.

**Bricks:** 7, 8, 17, 25, 30, 31, 32, 122, 129, 130, 135 (NORTH-STAR.md).
