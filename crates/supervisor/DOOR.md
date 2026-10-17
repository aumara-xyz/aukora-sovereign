# The Rust door

`sovereign door serve --socket PATH --policy FILE` is the server side of the engine's door
(`engine/plugins/aukora-door/PROTOCOL.md`, protocol v1). The DSH plugin sends every call that is not workspace-local
here, one request line per connection; the door decides and, only when the policy says allow, executes the crossing
itself. The engine never holds the credentials a crossing needs.

Source: `src/door/` (`wire`, `classify`, `policy`, `ledger`, `files`, `peer`, `fetch`, `memory`, `mod`). 58 unit tests run
with `cargo test -p supervisor door`.

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
   deny burns no id. For allow and ask the call id is appended to the ledger and `fsync`ed before anything runs; a
   repeat is `replay`. The ledger is segmented (`consumed.<n>.log`, 250,000 ids or 48 MiB each); the newest two are
   kept, so memory and disk stay bounded and the door never refuses everything because a counter filled. Replay
   protection therefore covers the last 250,000 to 500,000 ids. `door.lock` is `flock`ed, so two doors cannot share a
   state folder. (This stops a captured or approved request being run again; an engine that mints a fresh id is
   bounded by the class policy and the rate limit.)
6. **Ask.** `ask` appends `{call_id, class, tool, digest, time}` to `asks.jsonl` (fsync; 16 MiB cap, after which an ask
   is refused as `asks-full` until the owner drains the file) for the approval path, and answers `ask` (`ask-<class>`).
   No new Aura kind is needed and no gate proposal is made yet (the gate accepts only targets in its inventory, which
   the installer ships empty).
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
refused) holds `door.lock`, `consumed.<n>.log` and `asks.jsonl`. The socket is created with the umask's mode and then
set to 0666 when peers are checked by uid (any local user can connect, only the allowlisted uid is served) or 0600
for `socket-permissions`.

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
- A gate proposal for `ask` (needs inventory targets and a decision about the approval card's content).
- A per-class quota of connection slots, and a limit on how fast a hostile engine can fill `asks.jsonl` below the
  rate limit.
- The Linux `SO_PEERCRED` path is three lines and compiles only on Linux; it was written on macOS and is covered by
  the platform-independent `Door::judge`/`serve_stream` tests, not by a live Linux socket. Run `cargo test -p
  supervisor door` on the Linux node before relying on it; two tests (the real socket pair) behave slightly
  differently there when a refused peer closes with unread data.

## Class `shell-interactive` (2026-10-17)
Interactive terminal tools (`terminal_*`) cross as `shell-interactive`: a persistent process takes input after the open call that nobody judged. The class has no executor, so a policy cannot allow it; an older door that does not know it refuses it as `bad-class`.
