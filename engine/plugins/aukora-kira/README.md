# aukora-kira

The DeepSeek Harness (DSH) shared-memory plugin for AUKORA (`@aukora/kira`): registers the Kira 2 tools
(`kira_recall`, `kira_remember`, `kira_get`, `kira_list_recent`, `kira_supersede`) plus the read/mark-only
`kira_taint` door bridge, enforces durable provenance taint, and injects `aukora:self` (up to 4 KiB) and
`aukora:resume` (up to 2 KiB) into the system prompt at session start with `interpolate: false`.

Built by Argon against DSH 0.2.1-alpha.5 (master `1517a4d`) and run live there (12/12 tests, a live round trip through
the Rust door into Kira 2); landed here with the fixes listed in the commit. Paired with `@aukora/door`
(`engine/plugins/aukora-door`) and the Rust door's memory executor (`crates/supervisor/src/door/memory.rs`).

## What it is, and what it is not

Like the door plugin it is a **policy hook**, not a wall: a hostile plugin in the same Node process can bypass any
in-process hook. The walls are the OS confinement of the engine and the Rust side: the door holds the Kira token and
enforces the engine's ceilings (`capture-ceiling`, `owner-only`, `lane-closed`, no `quarantine_source`), and Kira
itself signs as the token's agent and never lets an agent claim more than `model-generated` or `web-derived`.

## Architectural invariants

1. **Zero credentials in the engine.** `@aukora/kira` holds no Kira socket path and no Kira bearer token. Every `kira_*`
   tool call is classified `memory` by `@aukora/door`, which intercepts `tools/execute` before `next()` and sends the
   canonical request to `sovereign door serve`. The Rust door handles `kira_taint` itself; for memory calls it
   attaches its own `0600` token file (refusing an owner token) and forwards to the Kira 2 service.
2. **Fail-closed local body.** If `@aukora/door` is not loaded or is bypassed and a `kira_*` tool body is ever invoked
   in-process, it throws `KiraDoorRequiredError` (`code: 'door-required'`).
3. **Judge-then-lock compatibility.** `@aukora/kira` registers its `tools/pre-execute` hook with `{ global: true }`
   (without `prepend: true`), so `@aukora/door` (`{ prepend: true, global: true }`) always binds and digests first and
   then passes through to this hook; a deny here is the decision. `@aukora/kira` never mutates `exec.arguments`.
4. **Durable engine provenance taint.** The engine is tainted when it calls `web_fetch`, `web_search` or `mcp__*`; when a Kira
   result (`kira_recall`, `kira_get`, `kira_list_recent`, or `kira_supersede`, which returns the superseded note with
   its text) carries a `web-derived` note; and on every delegation (`subagent`, `subagent_fork`, `ralph`, `workflow`,
   `wait_agent`, and agent-team `spawn_*` / `team_*` tools). A child may run in a fresh process whose taint this one
   never sees, and nothing authenticated says a child stayed clean, so every delegation counts. While tainted
   `kira_remember` (and `memory_remember`, should a door still forward it) must say `capture: "web-derived"`, or it is
   denied (`code: 'turn-tainted'`). Session history reads (`session_search`, `session_trace`, and related read tools)
   taint too. The plugin marks the door's durable `taint.json` before local external-input tools run and before
   their results are released; `web_fetch` and memory reads mark it in the door before releasing content. Every
   write re-reads the door, including after an engine restart.
   Unavailable or malformed taint state fails closed. Only the owner action `POST /api/engine/door/clear-taint`
   clears it, and existing controllers observe that clear on their next write. Turn, agent and compaction hooks
   cannot clear the door. This state covers every session and child in the engine, conservatively.
5. **Session-start `aukora:self` and `aukora:resume` injection.** At session start (`agent/created`, `agent/pre-step`,
   and the first `system-prompt/assemble`) the plugin reads each slot with one `kira_get { id: '<slot>' }` through
   `ctx.tools.execute` (so through `@aukora/door` -> Rust door -> Kira 2) and registers them as `SystemPrompt`
   sections with `interpolate: false`, outside the 4,800-character `kira_recall` budget. Kira resolves a slot to its
   newest live note by an author allowed to write it (the owner for `aukora:*`; an agent only its own
   `resume:<agent>`), so no other agent's note can become Auma's self file. The plugin injects a note only if it is
   live and carries the slot it asked for; `kira:not-found` is an empty slot, any other failure is retried next step.
   The slots are read again at `step === 1` of every turn, so a self file the owner has since superseded or
   quarantined, or a newer resume brief, reaches the next turn. Each slot refreshes independently: if its read fails,
   its text and cached head are withheld and retried next step; a successful read applies even if the other fails.
   The head used for `expected_head` stays at the session's first verified read, including an empty slot. Refreshing
   prompt text or retrying a failed read never advances it, so a concurrent handoff still refuses a stale write.

## Honest limits

- Files a tainted agent wrote are not tracked as a separate provenance channel.
- PL-7: Slot prompt text refreshes at the next turn's step 1; mid-turn owner changes wait, and the session's write head stays pinned. A door crash after Kira commits can return `door-connect` despite a committed write.
- The ceilings here repeat the Rust door's; the door's are the ones that hold.

## Build & test

Needs Node 24.11.1 (built-in TypeScript stripping; no install step, no dependencies):

```sh
~/.local/node-v24.11.1/bin/node --test engine/plugins/aukora-kira/test/*.test.ts
~/.local/node-v24.11.1/bin/node engine/plugins/aukora-kira/build.mjs
```

`build.mjs` is the door plugin's, byte for byte: `src/*.ts` to `lib/*.js` with Node's own type stripper; `lib/` is not
committed (`test/build.test.ts` rebuilds twice and compares). `cordis.patch.yml` mounts the plugin next to the door.
