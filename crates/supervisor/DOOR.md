# The Rust door

`sovereign door serve --socket PATH --policy FILE` is the server side of the engine's door
(`engine/plugins/aukora-door/PROTOCOL.md`, protocol v1). The DSH plugin sends every call that is not workspace-local
here, one request line per connection; the door decides and, only when the policy says allow, executes the crossing
itself. The engine never holds the credentials a crossing needs.

Source: `src/door/` (`wire`, `classify`, `policy`, `ledger`, `files`, `peer`, `fetch`, `memory`, `approver`, `standing`, `mod`, `tests`).
The unit tests run with `cargo test -p supervisor door` (the count changes with every edit: ask the command, not this
file).

## What it does with a request

1. **Peer, then rate, before anything is read.** The connecting uid comes from the kernel (`SO_PEERCRED`, Linux) and
   must be in `peers.uids`; anyone else is answered `peer` and dropped without costing a thread or a slot. A token bucket
   (`rate_per_second`, `rate_burst`; default 20 and 100) answers `rate-limited` beyond the rate. A uid allowlist refuses
   to start on a platform that cannot report the caller, and refuses a list that includes root or the door's own user;
   there `peers.mode = "socket-permissions"` makes the socket's own mode (0600) the only gate, for development.
2. **Strict parse.** One C1 canonical JSON line with exactly the six protocol fields; canon's parser, then a byte
   comparison with its own re-serialization. The arguments (base64) are decoded and held to the same rule, so floats,
   non-canonical order and anything C1 refuses are `args-not-canonical`. The line is read under a size cap and a 5 s
   overall deadline.
3. **Digest.** `sha256("aukora:door-call:v1" 00 u32be(len(tool)) tool args)` recomputed over the bytes the door will
   act on, compared in constant time. The nine vectors in the plugin's `test/vectors.json` (made by an independent
   Python implementation) are a unit test here.
4. **Class.** Derived again from the tool name and the argument shape (`classify.rs`, a mirror of the plugin's table).
   The plugin's claim must equal it, except that a tool the plugin calls `unknown` is served under the door's class.
   A call the door considers workspace-local, or a class it does not know, is refused.
5. **Policy, then consume once.** One action per class: `allow`, `ask` or `deny`; anything not listed is deny, and a
   policy deny burns no id. (Once the policy says allow or ask the id is spent, so a refusal after that point does burn
   it: the door's own checks before an ask or an allow, such as the host allowlist, bad arguments, the memory ceilings
   or an unavailable service.) For allow and ask the call id is appended to the ledger and `fsync`ed before anything runs; a
   repeat is `replay`. The ledger is segmented (`consumed.<n>.log`, 250,000 ids or 48 MiB each); the newest two are
   kept, so memory and disk stay bounded and the door never refuses everything because a counter filled. Replay
   protection therefore covers the last 250,000 to 500,000 ids. `door.lock` is `flock`ed, so two doors cannot share a
   state folder. (This stops a captured or approved request being run again; an engine that mints a fresh id is
   bounded by the class policy and the rate limit.)
6. **Ask.** Without an approver (`door serve` on its own) `ask` appends `{call_id, class, tool, digest, time}` to
   `asks.jsonl` (fsync; 16 MiB cap, then `asks-full`) and answers `ask` (`ask-<class>`); nothing else happens. Run
   inside the node (below), an ask is a real owner request:
   - Only a class with an executor is ever asked about, and only after the door's own checks pass (arguments, host on
     the allowlist, memory ceilings): the owner is never asked to approve a call the door would refuse anyway. Other
     classes answer `no-executor`.
   - The call becomes a gate proposal: the record `gate::door` writes (canonical JSON: `args`, `call_id`, `class`,
     `digest_sha256`, `kind`, `tool`, `v`) replaces `door/ask-NN.json`, the first free of eight critical content targets
     the installer ships. The owner origin renders it with the generic review/passkey flow; the card says "Let the engine
     run this one call, exactly as displayed", with tool, class, call digest and the exact record under "Exact changes".
     The guest's own `propose` refuses `door/` targets.
   - The approval belongs to the **call digest**, not the call id. The model repeats the identical call (fresh id): while
     the proposal is unanswered the reply is `ask-<class>:pending`; once applied, the door appends `used` to
     `approvals.jsonl` (fsync) and only then executes. One approval lets exactly one call through; a crash between the
     two loses the run and never repeats it. A refused, retired or expired proposal is raised afresh.
   - `approvals.jsonl` is the door's memory of open asks (16 MiB cap, 4,096 open); a torn or unreadable line can only
     lose an ask. When the table is full, asks older than the approval time limit are ended first (`gone`, durably), and
     room is made BEFORE the owner request is raised, so no card goes up for an ask that could not be remembered. Ended
     asks stay in the file as lines until the 16 MiB cap (about 140,000 events; at most eight asks per five minutes can
     be open, so that is weeks of a hostile engine); past it the door answers `approvals-full` until the file is rotated. A sweep every 60 s settles expired proposals (the gate expires a pending proposal only in `recover`,
     which otherwise runs at start-up, and a target holds one open proposal, so unanswered asks would hold their slots
     until a restart).
   - Refusals the engine can see: `approvals-unbound` (node not claimed), `approvals-not-installed` (no `door/` targets
     in the inventory), `approvals-busy` (eight asks already open), `ask-too-large` (record over 12 KiB), `approvals-full`.
7. **Executors** (only `net` and `memory` have one; a policy cannot `allow` any other class, and `fs-outside` is
   always denied):
   - `net`, `web_fetch`: the URL must be https (http only if the policy says so), carry no user info, name an
     allowlisted host exactly and use a listed web port (80, 443, 8080, 8443 only). The door resolves the name itself
     on a blocking thread under the policy deadline, refuses any private, loopback, link-local, CGNAT, multicast,
     documentation or IPv4-mapped-private address, and connects to the address it checked. No redirects, no proxies,
     body capped, deadline. The result has the shape of DSH's `web_fetch` output and is cut, on a character boundary
     with `truncated` set, until the whole reply line fits the frame limit.
   - `memory`, `kira_*`: forwarded to the Kira 2 service with the engine's own agent token, a file only the door reads.
     Before forwarding, the engine's ceilings are enforced on `remember`: `capture` must be `model-generated` or
     `web-derived`, no `owner_signed`, no `charter`/`ruling`/`decision`/`self`/`resume` lane or slot, and
     `kira_quarantine_source` is refused. The other methods pass straight to the service, which confines them by the
     token's agent: see the deployment requirements.

Every error is a refusal, and a refusal says nothing ran.

## Policy file

JSON, at most 64 KiB, a regular file owned by the door's user or root that is not group- or world-writable, opened
without following a symlink and checked on the open descriptor; unknown fields are refused.

```json
{
  "v": 1,
  "peers": { "mode": "peercred", "uids": [1001] },
  "workspace_roots": ["/sandbox"],
  "state_dir": "/var/lib/aukora-door",
  "classes": {
    "net": "allow", "memory": "allow",
    "plugin": "ask", "persist": "ask", "delegate": "ask",
    "mcp": "deny", "fs-outside": "deny", "unknown": "deny"
  },
  "net": { "hosts": ["docs.rs", "crates.io"], "ports": [443], "max_bytes": 1048576, "timeout_ms": 15000 },
  "rate_per_second": 20, "rate_burst": 100,
  "memory": { "socket": "/var/lib/aukora-kira/kira.sock", "token_file": "/etc/aukora/door-kira.token" }
}
```

`state_dir` (a real directory of the door's user, created or tightened to 0700; a symlink or a foreign owner is
refused) holds `door.lock`, `consumed.<n>.log`, `asks.jsonl` and, with an approver, `approvals.jsonl`. The socket is created with the umask's mode and then
set to 0666 when peers are checked by uid (any local user can connect, only the allowlisted uid is served) or 0600
for `socket-permissions`.

## Running inside the node

`sovereign serve --config` starts the door itself when the config directory holds `door-policy-v1.json` (root-owned,
not group- or world-writable, read like `gate-targets-v1.json`; absent means no door). It is the same policy text as
above plus `"socket": "/abs/path"` where the door listens. The door runs on plain threads in the node process (the gate
lives only there) and a door that cannot start is logged, never a node crash. The installer ships the eight
`door/ask-NN.json` targets; an older node needs them added to its inventory by an owner-approved sync (not built yet).
The policy file is **not** installed by default: enabling the door is the operator's decision.

## The slider and standing grants (Track 5)

Add `"standing": {"policy_file": "/abs", "grants_file": "/abs"}` (both optional) to the door policy and a class the policy
would `allow` or `ask` about is decided per call by Laya's slider (`laya::slider`, applied in `src/door/standing.rs`):

- Rust's floor comes from the owner's setting (`ask`, `risky` or `limits`), the live standing grants and today's counts;
  Laya's deterministic escalation can only raise it (`max(floor, laya)`); nothing in it approves. Only a "clear" runs the
  call without an owner request; everything else becomes an `ask`. `deny` stays `deny`, and the door's own checks (host
  allowlist, memory ceilings) run first, so a refused call spends nothing and is never asked about.
- `ask`: every call asks. `risky`: net and memory (the routine classes) clear inside a live grant; every other class asks.
  `limits`: any grantable class clears inside a live grant and today's per-class and per-grant counts, then asks again.
  `plugin`, `persist`, `shell-interactive` and `unknown` can never be granted and ask under every setting.
- A grant (`laya::grant`) names one class and what inside it (hosts for `net`, `read` / `write:<lane>` for `memory`,
  servers, providers, path prefixes), a window of at most seven days and a per-day count. It is non-onward (no field
  creates or widens a grant, and the closed memory lanes cannot be named), and revoking narrows without a passkey.
  Creating or widening one is a critical gate proposal for `door/standing-grants.json` (the installer must ship that
  target; not built yet, like the `door/ask-NN.json` sync).
- Files: root-owned, not group- or world-writable, read like the policy and re-read when they change. No policy file means
  the shipped starter (`crates/laya/data/starter-slider-v1.json`, "only risky things", pinned by sha256); a bad policy
  file means "ask for everything"; a missing or bad grants file means no grants. Counts are appended to
  `autoclear.jsonl` (synced before the call runs; compacted to today's lines at start; past 4 MiB nothing clears).
- Not done: the node does not yet read the grants from the applied gate target; the installer writes the two files.

## Deployment requirements (the code cannot check these)

- The socket's parent directory must not be writable by the engine's user (the door refuses group- or
  world-writable parents, but cannot know the engine's group); anyone who can add or rename entries there can wedge a
  restart.
- The engine's uid must not be root or the door's own user (the door refuses both).
- The door's Kira token must belong to a **non-owner agent** registered for the engine; with an owner token the
  service would let `supersede`, `get` and `list_recent` act with owner powers on the engine's behalf. The Kira socket
  directory must be 0700 and not engine-writable: the token is sent to whatever listens on that path.
- `workspace_roots` in the policy must match the plugin's `workspaceRoots`, or honest file calls will be
  `class-mismatch`. `max_frame_bytes` must not exceed the plugin's `maxFrameBytes`.
- The `net` allowlist is itself an exfiltration channel: up to 4 KiB per call leaves in the URL to an allowed host.
  Keep it short and keep the rate low.

## Not done, on purpose

- Executors for `mcp`, `plugin`, `persist`, `delegate`: they can be `deny` or `ask` only. `web_search` has none yet.
- A gate proposal for the classes that have no executor (`plugin`, `persist`, `delegate`, `mcp`): there is nothing the
  door could run after an approval, so they answer `no-executor` instead of asking.
- Existing nodes: the inventory sync that adds the `door/` targets.
- No integration test drives a real gate proposal through the owner flow (there is no gate harness in main); the door's
  ask flow is tested against a scripted approver, the record and card with unit tests, the adapter by compile only.
- A per-class quota of connection slots, and a limit on how fast a hostile engine can fill `asks.jsonl` below the
  rate limit.
- The Linux `SO_PEERCRED` path is three lines and compiles only on Linux; it was written on macOS and is covered by
  the platform-independent `Door::judge`/`serve_stream` tests, not by a live Linux socket. Run `cargo test -p
  supervisor door` on the Linux node before relying on it; two tests (the real socket pair) behave slightly
  differently there when a refused peer closes with unread data.

## Class `shell-interactive` (2026-10-17)
Interactive terminal tools (`terminal_*`) cross as `shell-interactive`: a persistent process takes input after the open call that nobody judged. The class has no executor, so a policy cannot allow it; an older door that does not know it refuses it as `bad-class`.
