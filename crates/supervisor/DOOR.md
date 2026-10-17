# The Rust door

`sovereign door serve --socket PATH --policy FILE` is the server side of the engine's door
(`engine/plugins/aukora-door/PROTOCOL.md`, protocol v1). The DSH plugin sends every call that is not workspace-local
here, one request line per connection; the door decides and, only when the policy says allow, executes the crossing
itself. The engine never holds the credentials a crossing needs.

Source: `src/door/` (`wire`, `classify`, `policy`, `ledger`, `peer`, `fetch`, `memory`, `mod`). 40 unit tests run with
`cargo test -p supervisor door`.

## What it does with a request

1. **Peer.** The connecting uid comes from the kernel (`SO_PEERCRED`, Linux) and must be in `peers.uids`. A uid
   allowlist refuses to start on a platform that cannot report it; there `peers.mode = "socket-permissions"` makes the
   socket's own mode (0600) the only gate, for development.
2. **Strict parse.** One C1 canonical JSON line with exactly the six protocol fields; canon's parser, then a byte
   comparison with its own re-serialization. The arguments (base64) are decoded and held to the same rule, so floats,
   non-canonical order and anything C1 refuses are `args-not-canonical`.
3. **Digest.** `sha256("aukora:door-call:v1" 00 u32be(len(tool)) tool args)` recomputed over the bytes the door will
   act on, compared in constant time. The nine vectors in the plugin's `test/vectors.json` (made by an independent
   Python implementation) are a unit test here.
4. **Class.** Derived again from the tool name and the argument shape (`classify.rs`, a mirror of the plugin's table).
   The plugin's claim must equal it, except that a tool the plugin calls `unknown` is served under the door's class.
   A call the door considers workspace-local, or a class it does not know, is refused.
5. **Consume once.** The call id is appended to `consumed.log` and `fsync`ed before anything runs; a repeat, also
   after a restart, is `replay`. The file is `flock`ed, so two doors cannot share a state folder. (This stops a
   captured or approved request being run again. An engine that mints a fresh id is bounded by the class policy, not by
   this.)
6. **Policy.** One action per class: `allow`, `ask` or `deny`; anything not listed is deny. `ask` appends the call to
   `asks.jsonl` (call id, class, tool, digest, time) for the approval path and answers `ask` (`ask-<class>`); no new
   Aura kind is needed, and no gate proposal is made yet (the gate accepts only targets in its inventory, which the
   installer ships empty).
7. **Executors** (only `net` and `memory` have one; a policy cannot `allow` any other class, and `fs-outside` is
   always denied):
   - `net`, `web_fetch`: the URL must be https (http only if the policy says so), carry no user info, name an
     allowlisted host exactly and use a listed port. The door resolves the name itself, refuses any private, loopback,
     link-local, CGNAT, multicast, documentation or IPv4-mapped-private address, and connects to the address it
     checked. No redirects, no proxies, body capped, deadline. The result has the shape of DSH's `web_fetch` output.
   - `memory`, `kira_*`: forwarded to the Kira 2 service with the engine's own agent token, a 0600 file only the door
     reads. Before forwarding, the engine's ceilings are enforced: `capture` must be `model-generated` or
     `web-derived`, no `owner_signed`, no `charter`/`ruling`/`decision`/`self`/`resume` lane or slot, and
     `kira_quarantine_source` is refused. The service's reply is the result; its errors pass through as `kira:<reason>`.

Every error is a refusal, and a refusal says nothing ran.

## Policy file

JSON, at most 64 KiB, a regular file that is not group- or world-writable; unknown fields are refused.

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
  "memory": { "socket": "/home/node/aukora-memory/kira/kira.sock", "token_file": "/etc/aukora/door-kira.token" }
}
```

`state_dir` (created 0700) holds `consumed.log` and `asks.jsonl`. The socket is created with the umask's mode and then
set to 0666 when peers are checked by uid (any local user can connect, only the allowlisted uid is served) or 0600
for `socket-permissions`.

## Not done, on purpose

- Executors for `mcp`, `plugin`, `persist`, `delegate`: they can be `deny` or `ask` only.
- A gate proposal for `ask` (needs inventory targets and a decision about the approval card's content).
- Rate limits per peer, and rotation of `consumed.log` (the file is capped at 128 MiB, two million ids, and the door
  refuses to start beyond that).
- The Linux `SO_PEERCRED` path is three lines and compiles only on Linux; it was written on macOS and is covered by
  the platform-independent `Door::judge` tests, not by a live Linux socket. Run `cargo test -p supervisor door` on the
  Linux node before relying on it.
