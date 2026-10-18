# The node: everything on one Nebius VM (design, runbook and the test-node record)

One VM runs the Rust authority (Ring 3), Kira 2, and the DeepSeek Harness 0.2.1-alpha.5 inside OpenShell (Ring 1),
with the door as the engine's only way out. This file is the design and the runbook. NORTH-STAR.md Part 1 is the plan;
the wall is the one that passed the wall test (a builders' private report of 2026-10-17, not published; OpenShell 0.1.4,
enforce, docker compute driver).

Marks: **RAN** = executed for this branch (on the Mac unless stated); **NODE** = ran on the builders' disposable test
node (not an owner's node), Claude's rehearsal of 2026-10-17 (`aukora-rehearsal`, Nebius cpu 4 vCPU / 16 GiB, release
acc7a35; report private, not published); **LINUX** = runs only on the node, not run yet; **GUESS** = not verified
against the real tool.

## 1. What runs where

| Process | User | Listens / holds | Reaches |
|---|---|---|---|
| Caddy | caddy | :443 for `<shell>`, `owner.<shell>`, `engine.<shell>` | 127.0.0.1:18080 (frontdoor), 127.0.0.1:18081 (engine origin) |
| `sovereign serve` (supervisor, gate, AUMLOK, Aura, frontdoor, broker, **door**, **engine controller**, **engine origin**, **model broker**) | aukora | 18080, 18081, `/run/aukora-door/door.sock`, `/run/aukora-broker/broker.sock` | Kira socket (group kira-clients), engine web socket, `systemctl start/stop aukora-engine.service` (polkit, that unit only) |
| `sovereign kira serve` | kira | `/run/aukora-kira/kira.sock` (0660, dir 2750 kira:kira-clients) | llama servers on 127.0.0.1:8771/8772 |
| llama-server ×2 (embed, rerank) | kira | 127.0.0.1:8771, :8772 (nft: only uid kira may connect) | nothing (IPAddressDeny=any) |
| openshell-gateway | root (hardened unit; only CAP_NET_BIND_SERVICE) | 127.0.0.1:690 (privileged: no other user can bind it; the fence lets only root and 65534 connect: root's CLI and each sandbox's supervisor container, which OpenShell runs as 65534 on the host network; both still authenticate) | docker |
| the engine: `node entry.mjs` → `dsh --profile aukora` | **auma** (uid ≠ root, aukora, kira), inside the sandbox | 127.0.0.1:3080 and :3081 (model bridge) *inside* the sandbox; `/run/aukora-engine-io/web.sock` (bridge) | the door socket and the broker socket; nothing else (no network, no resolver) |

Keys: the owner's passkey stays on the owner's device; the node's signing keys, Aura, the gate, the claim digest and the
Kira agent keys are in Ring 3 state (`/var/lib/aukora`, `/var/lib/aukora-kira`), never mounted into the sandbox. The
engine holds no Kira token (the door holds the non-owner one), no model key (the broker holds it, section 7) and no
owner session.

## 2. When the engine runs (the supervisor decides, outside the wall)

`crates/supervisor/src/engine/control.rs`, every 5 s, in this order (each is a stop reason in the journal):

1. `awaiting-owner-binding`: the node has no owner yet (claim + passkey not done).
2. `awaiting-release-approval`: the running release is not one the owner's passkey approved: the floor names another
   release, or only the install's own starting floor (`is_install_genesis`), which lets the shell serve before the
   first card but is nobody's approval (O11). So the release card comes first, then the plugin set. A floor that
   cannot be read now (`floor:locked`, I/O) is neither answer: the read is retried within the tick, nothing starts on
   it (`release-unreadable`), and an engine this run started is kept for at most 30 s of it, then stopped. The floor
   store itself waits about a second for a lock another reader holds before it refuses.
3. `door-not-configured`: no `/etc/aukora/door-policy-v1.json`.
4. `awaiting-plugin-set-approval`: the owner has approved no plugin set. The controller raises one critical proposal for
   `engine/plugin-set.json` holding every staged package by name and fingerprint, the door marked `authority`. One card.
5. `authority-plugin-changed`: the door package on disk is not the approved bytes. The engine stops, and the changed
   door is still proposed (it keeps `authority: true`), so the owner sees it instead of a silent outage.
6. `running`: the controller writes the approved set and `admission.json` to `/run/aukora-engine-ctl` (0750
   aukora:root, tmpfiles; files 0600 aukora, written with that mode whatever the umask; never mounted into the
   sandbox) and runs `systemctl start aukora-engine.service`. The root side does not assume that ownership, it
   enforces it (Mistral review): `engine-prestart.sh` and `sovereign engine closure` refuse unless the folder is a
   real directory owned by root or aukora with no group/other write, and each file is a regular file opened without
   following links, owned by aukora, mode 0600 or 0640, one link. The engine's uid is neither root nor aukora. A newly approved set restarts it. Losing any condition stops it.

New or changed non-authority packages never load (the closure copies only approved bytes); they become one proposal
(the approved set plus all of them). A card that ran out of time (closed, never answered) is raised again after 10
minutes; a set the owner explicitly **Declined** is not raised again until the owner asks again (O19), and the engine
says `plugin-set-declined` meanwhile.
Hot reload and creator mode are never loaded and never approvable (`floor::plugins::is_hot_reload`).

## 3. The plugin fingerprint gate, end to end

- **Staged**: `/opt/aukora-engine/plugins/<folder>` (root-owned) from `engine-plugins.tar` (`build_plugins.py`,
  byte-reproducible: two builds gave the same SHA-256, RAN and NODE). Thirteen packages: `@aukora/door`,
  `@aukora/kira` (Kira 2's tools, every call through the door), the nine faces (`@aukora/face-<name>`),
  `@aukora/dsh-plugin-foundation`, `@aukora/face-bundle` (the composition patch).
- **Fingerprinted** by the supervisor, read-only (`engine_plugins::discover`): every file's path, executable bit, size,
  SHA-256, under a domain.
- **Approved** by the owner's passkey on the owner origin: the generic content card shows the exact set bytes.
  `sovereign engine fingerprint --from DIR` prints the set the owner will see and its pin (RAN on the built packages).
- **Copied** by root before every start (`sovereign engine closure`, `engine/closure.rs` → `copy_closure`): each staged
  file opened without following links, checked on its descriptor, read once under caps, **hashed from the bytes being
  copied**, `package.json` parsed from those same bytes; a package lands at `node_modules/<approved name>` only if its
  copied digest is the approved one; the closure is sealed read-only (dirs 0555, files 0444/0555) and swapped in whole.
  A changed door refuses the start and keeps the last good closure. RAN (unit tests + on the Mac against the real build).
- **Mounted**: the closure is the profile's `node_modules`; a face's relative import into a sibling folder
  (memory, messages, settings host code) finds only approved packages, so an unapproved helper fails closed.
- **Pin**: the authority is the gate target the passkey applied (the gate checks the observed digest). Each start
  that the supervisor decides (a new or changed set; not a restart systemd performs itself) appends `{set_hash, gate_sha256}` to `/var/lib/aukora/floor/engine-plugin-set.jsonl`. Storing the pin *inside* the signed
  floor (`floor::state::ProtectedState`) needs a floor schema change and an Aura migration: open item O5.

## 4. The wall (Ring 1)

The OpenShell policy is the wall test's, verbatim (`openshell-policy.yaml`), plus four NODE lines, each marked there:
`/engine-home` (the harness home), `/run/aukora-engine-io` (bridge socket + launch line), `/run/aukora-broker` (the
model broker socket, section 7) and the resolver posture.
`run_as_user` and `run_as_group` are the engine user's uid and its own gid (they differ: 994/984 on the node);
`network_policies: {}`; Landlock `hard_requirement`. The pre-start renders the policy from the ACTIVE release on every
start; `engine-run.sh verify` holds `openshell policy get --full -o json` to that file (NODE: an empty
`network_policies` is left out of OpenShell's payload, and the table form prints `Status:       Effective`).

Mounts (`engine-run.sh`): `/opt/aukora-engine` → `/engine` ro (node, pinned harness, in-wall scripts);
`/opt/rust` ro; `/var/lib/aukora-engine/work` → `/work` rw; `/var/lib/aukora-engine/home` → `/engine-home` rw;
`/run/aukora-door` rw (folder 0711 aukora, so not engine-writable); `/run/aukora-broker` rw (the same); `/run/aukora-engine/io` rw
(a 1 MiB host tmpfs, `run-aukora\x2dengine-io.mount`; wall-check proves 2 MiB is refused, NODE);
`/etc/aukora/engine/resolv.conf` → `/etc/resolv.conf` ro. Never: `/etc/aukora`, `/var/lib/aukora*`, the Kira socket,
the docker socket.

**The harness home.** The harness writes `.credentials.yaml`, `.anonymous-user-id`, `storages/`, `sessions/` at the top of
its home (RAN: observed on the Mac boot), so the home is writable. It is root-owned with the sticky bit (1770
root:auma): the engine can create its own files but cannot rename or delete root-owned entries, which are re-asserted by
`engine-prestart.sh` before every start: `profiles/` and `profiles/aukora/` (profile template + the closure),
`cordis.patch.yml` (`[]`), and an empty root-owned `node_modules/` guard so module resolution cannot walk up into
an engine-made package. One file in the profile is the engine group's to write: `profiles/aukora/cordis.yml`, which the
harness rewrites with its own constant empty list on every boot before loading anything (NODE: the first start died on
EACCES there); the pre-start resets it each start and the folder stays root's. `@deepseek-ai` resolves through one root-made link in the closure to the pinned install.
The authority overlay (`authority.patch.yml`) is passed with `--patch`, after every layer the engine can write: it
mounts the door with the node's values and disables `hmr`, `client-hmr`, the plugin manager (three rows), the web
terminal (two rows), desktop telemetry, open-in-app (two rows) and the harness-dev context; mounts Kira 2's tools after
the door; caps the DeepSeek adapter's inline images (4 MiB, quantum 2 MiB: NODE, the adapter refuses to activate
when its default 10 MiB quantum exceeds the cap, which a config dump never shows); and sets the apps face's Sovereign
switches off (row 6). RAN: `dsh --dump-config` composes with every row in place; NODE: `dsh web` boots the composition
inside the wall with all thirteen packages and no entry failing to activate.

**DNS posture (the wall test's one residual, B03).** Three layers: the sandbox's `/etc/resolv.conf` names 127.0.0.1
(nothing listens there); Docker's daemon resolver forwards only to 192.0.2.53 (`docker-daemon.json`); the host fence
(`aukora-engine-fence.nft`) drops 192.0.2.53 and any port 53/853 traffic from a container network. Names the engine
needs cross through the door, which resolves them itself. `wall-check.sh` proves it from inside the sandbox:
`getent hosts example.com`, node `dns.lookup`, `dns.resolve4`, a direct query to 127.0.0.11 and to 1.1.1.1 must all
fail. NODE: `wall ok`. (How it works in 0.1.4: the sandbox container has `NetworkMode none`; names resolved in the wall
test through OpenShell's transparent DNS in the supervisor container, using the sandbox's resolv.conf nameserver. With
127.0.0.1 there, every lookup fails; without it, the same probe resolves: both RAN on the wall-test VM.)

## 5. The front door and the engine origin

The harness's web UI is served on **`engine.<shell host>`**, not on the shell origin. Reason: everything the harness
serves is engine-controlled script. On the shell origin it would run with the owner's shell session (the Memory face's
Kira reads, the approvals list, the data bridge) and could frame and overlay the owner origin's ceremony (the
clickjack seam). A sibling origin gets none of that: host-only cookies stay on their hosts and the owner origin keeps
refusing every frame ancestor but the shell. This deviates from the brief ("the shell origin serves the DSH web UI");
see decision D1.

**Who may open it (SCOUT M18).** `GET /engine/open` mints a ticket (at most 32 a minute), and cookies are `SameSite=Strict`,
which is site-based: a page on `engine.<shell>` is same-site with the shell, so it could send credentialed no-cors GETs and
make the owner's open fail with `engine-busy` (the same for `GET /api/approvals`, which only burns its one-second poll
slot). The frontdoor now admits both only with `Sec-Fetch-Site: same-origin` (the shell's own page), and `/engine/open`
also with `none` (a typed or bookmarked address, a top-level navigation); `same-site` and `cross-site` are refused.

Flow: the owner, signed in on the shell, opens `https://<shell>/engine/open`. The host (`host/engine_routes.rs`)
checks the bound shell session against the ledger's binding and the release floor, mints a one-time ticket (60 s,
single use) and redirects to `https://engine.<shell>/.aukora/enter/<ticket>`. The engine origin
(`engine/proxy.rs`, listener 18081) redeems it for `__Host-aukora-engine` (12 h, `Secure; HttpOnly; SameSite=Strict`),
and on every request re-checks that scope against the ledger, the release floor (an unreadable floor answers 503
and keeps the session; a withdrawn approval answers 403 and ends it) and the **shell session** that minted the ticket
(O12): the ticket and the session name its store digest, the session never outlives it (expiry = min(12 h, the shell
session's end)), and an expired, revoked or re-epoched shell session ends every engine session minted from it with
403 at once. The shell's sign-out is `POST /api/session/end` (same-origin JSON, bound shell session); the shell's button is
"Sign out", pinned at the base of the right-hand menu (O18). It forwards an allowlist of
headers (never the browser's cookies) plus the harness's own cookie, which it obtained by exchanging the launch
token the harness printed inside the wall; the browser never sees the token or that cookie. Replies lose every
`Set-Cookie` and CORS header and gain `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `no-referrer` (the
single-valued ones replace the harness's own, so it cannot cancel them). Caddy and the proxy both refuse a query that
names `token`; a path segment that decodes to `.`, `..`, a separator or another escape is refused. The ticket is spent
only by a top-level navigation (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`), and no service worker can be
installed on the engine origin (its script request, `Service-Worker: script`, is refused), so no engine page can watch
the owner's next navigation for a ticket. A clock that cannot be read refuses.

**WebSocket (O9, `engine/socket.rs`).** The harness client's live connection (`/api/remote.mux`) is the one upgrade
forwarded, with the same admission plus: `GET`, a version-13 handshake with a well-formed key, a path on the allowlist
(the web terminal's is refused even if a composition re-enabled it), and an `Origin` that is exactly
`https://engine.<shell>`. Extension and subprotocol offers are admitted and never forwarded (Chrome offers
permessage-deflate on every socket), so nothing is negotiated. The harness must answer 101 first (its own cookie, the
browser's key); its `Sec-WebSocket-Accept` goes to the browser, which checks it. Frames are relayed one by one, each
header checked before its bytes pass: RSV clear, known opcodes, control frames whole and at most 125 bytes, browser
frames masked and harness frames not, fragments in order, a message at most 1 MiB up and 16 MiB down; a violation
ends the socket. Every 5 s the session is re-checked; sign-out, a binding or release change, an engine that stopped, or
a minute without a frame (the harness pings every 2 s) closes it (1008/1001) at a frame boundary. At most 16 sockets.
NODE: the Spatial face's chat runs over it (O9 in section 10).
RAN: unit tests with a fake harness on a unix socket (cookie isolation, exchange, re-exchange after a harness restart,
header stripping); the real harness's exchange (303 + `dsh-auth-*` cookie; 401 without it; 401 on a wrong Host).

The owner origin is unchanged and Rust-served. The guest's `propose` refuses `engine/` targets, as it does `door/` and `build/`.

## 6. Kira 2 and the door on the node

Kira: `aukora-kira.service` as user kira, in one private network namespace with its two model servers
(`PrivateNetwork` + `JoinsNamespaceOf`: no other host process can bind or reach 8771/8772, so the alias Kira checks
cannot be squatted; each model file is hashed against its pin before its server starts), state `/var/lib/aukora-kira`
(0700), socket 0660 in a 2750
kira:kira-clients folder (new `--group-socket` flag; every request still needs a token). Two agents are registered at
install: **auma** (scope `auma`, non-owner; token `/etc/aukora/door-kira.token`, aukora 0600: only the door reads it)
and **owner** (`--owner`; token `/root/aukora-kira-owner.token`, root 0600: the owner's tools only, never the door, never
the engine). Models: llama.cpp b10621 CPU build, the two GGUF files pinned by SHA-256 (the builders' own
copies; the digests are in `engine-pins.json`), each server started with `--alias <sha256>` so Kira refuses a swapped file.

The door: the in-node door (`sovereign serve` reads `door-policy-v1.json`), so `ask` becomes a real gate proposal. The
policy is the wall test's, verbatim, except: `memory` is `allow` with the Kira socket and token (the wall test had no
Kira), `socket` is set (in-node form), `state_dir` is under the supervisor's state, and `"standing"` turns on the
starter slider ("only risky things", pinned). Until node/pre-launch that section was `{}` with no grants, so the slider
cleared nothing and every net and memory call was a card, exactly as `ask` would have been; it now carries the starter
grant terms, which clear only once the owner's one card approves them (section 12, P3). One exception to the slider (O14): a policy `allow` of exactly
`kira_get {"id": "aukora:self" | "aukora:resume"}` (Auma's own slots, read by `@aukora/kira` at every session start)
runs without a card; every other memory call is the slider's. The door's allowlisted `net.hosts` are pinned in the
node's egress like the provider (`engine.py egress`, O10): the door resolves them from `/etc/hosts`, the sandbox still
has no resolver. `peers.uids` is the engine uid; workspace root `/work` matches the
overlay. The wall test ran the door as its own user (`aukora-door`); in the node it runs in the supervisor (user
aukora), because owner asks need the gate in the same process. Both keep the property the test relied on: the engine's
uid is neither the door's nor root, and the door's state and policy are not mounted. Decision D3.

## 7. The model: the broker path

The engine has no network and no key. Its DeepSeek adapter (`@deepseek-ai/dsh-llm-deepseek-api-key` 0.2.1-alpha.5)
speaks the **Anthropic Messages API** (not OpenAI chat-completions: `POST <baseURL>/v1/messages`, always streaming
SSE, `x-api-key`, `anthropic-version: 2023-06-01`; read from the installed package's `serialize()`, `parseSse()`,
`translate()`). The path, built in this branch:

```
harness (auma, in the wall) --http--> 127.0.0.1:3081 (entry.mjs bridge, bytes only)
  --unix--> /run/aukora-broker/broker.sock (bind-mounted, folder 0711 aukora)
  --> broker::engine_link inside `sovereign serve` (user aukora) --https--> api.deepseek.com/anthropic/v1/messages
```

- **Wiring.** `authority.patch.yml` row 4 points the adapter's `baseURL` at the bridge and keeps its own key a
  placeholder (`DEEPSEEK_API_KEY=aukora-broker-holds-the-key`, entry.mjs). The OpenShell policy keeps
  `network_policies: {}`; the broker socket is AF_UNIX through a read-write mount, like the door's.
- **Peer.** `SO_PEERCRED` uid must be the engine's (`model-broker-v1.json` `peer_uids`); anything else is 403 before
  the body is read. Without kernel peer credentials (not Linux) the link does not start.
- **Key** (`KeyInbox`; at rest one 0600 file, O7 below). The owner types it at `https://<shell>/engine/model-key` (a self-contained page
  served by the supervisor, script and style pinned by hash in its CSP); `POST /api/engine/model-key` needs the bound
  owner's shell session (frontdoor: same origin, JSON). The broker holds the key and proposes
  `engine/model-key.json` = `{key_sha256, kind, provider, v}`: the card shows the digest only; the page shows its
  first 12 hex digits (the fingerprint) to compare. A call uses the key only while its SHA-256 equals the approved
  one. Entering a different key pauses the engine's calls until the owner approves it. The key is never in the
  gate, Aura, a log or a reply, and never inside the wall. **At rest (O7):** once the owner's passkey has approved the
  card, the supervisor keeps the key in `/var/lib/aukora/model-key/model-key` (`broker::keyfile`: the folder 0700
  and the file 0600, both the supervisor's own; a regular file, one link, opened without following symlinks;
  written beside itself, synced, renamed in, the folder synced). At start it is loaded only if its SHA-256 equals the
  `key_sha256` of the currently approved `engine/model-key.json`; a different digest removes the file, and a file that
  is a symlink, not regular, shared, or not a key is not used (the journal says why, never the key). Entering a
  different key removes the file once that key's card is up (card first, O19: a key whose card cannot be raised, e.g.
  `awaiting-other-approval`, changes neither memory nor file); it is stored again only when that card is approved, and
  never for a declined one; `ModelBroker::clear_key` clears memory and file together.
- **Budget.** `model-broker-v1.json` holds the terms (models, prices per million tokens, total and per-call cap in
  µUSD, call count, `valid_days`). The supervisor proposes them as `engine/model-budget.json` (with an expiry) and
  spends only against the bytes the owner's passkey applied; changed terms, or one day before expiry, propose again.
  Each approved budget (by its SHA-256) is its own cap. Spend is kept in `/var/lib/aukora/model-broker/spend-v1.jsonl`
  (0600): a call reserves its worst case (input bounded by the request's bytes, output by `max_tokens`) before it is
  sent, and `max_tokens` is lowered so that worst case fits the per-call cap and what is left of the total; it
  settles at the reported cost (input, cache hits, cache writes, output). A call whose usage is incomplete, or that
  was cut, is charged its reservation; one that never settled (a crash) is charged in full at the next start.
  The file is whole lines only (its folder synced after it is created): a torn last record is cut away (and synced)
  at open, a complete line that does not
  read refuses to start the link, and a failed append is cut back before any further reservation. Past 64 MiB it is
  compacted at open into one summary line per budget (charged, calls), synced and renamed in; no charge is dropped.
- **Request.** Parsed and rebuilt (what was checked is what is sent): JSON object, only the members the adapter
  writes (`model stream messages max_tokens thinking output_config system temperature stop_sequences tools top_p
  top_k`), `stream: true`, model on the approved list, at most 8 MiB. The harness's upload extensions (`dsh_*`: the
  session log, the plugin inventory) are removed (and switched off in the overlay, row 5). Upstream gets only
  `x-api-key`, `content-type`, `accept`, `anthropic-version` and the one allowed beta
  (`mid-conversation-tool-changes-2026-07-01`); the harness's user id, session id and user agent stay behind. The
  Files API is not served (404): the adapter then sends images inline (row 4 caps that at 4 MiB).
- **Reply.** Streamed through unchanged, one whole event at a time, each released only after it was scanned: its
  raw bytes for every 12-byte window of the key (plain, without `sk-`, base64, hex; `EchoGuard`), every string it
  decodes to (JSON escapes undone), a rolling window of the decoded content text per (block, field) and per field
  across blocks, as the engine accumulates them (so a key handed out a few characters per delta is caught), and a
  tool call's whole arguments, decoded, when its block stops: every event of a tool block (pings included) is held
  until then, and a stream that ends inside one releases none of it. An event that cannot be parsed or exceeds 1 MiB stops the stream. The newest event is held until the call
  is settled and its receipt appended. On a hit the stream ends with an SSE `error` event (`reply-withheld`); a
  broken stream ends with one too. The reported model is recorded only as an approved name, else `unrecognized`.
- **Receipt.** One Aura `broker.settle` **fact** per call that reached the provider (`aukora-engine-model-receipt-v1`:
  request id, model, reported model, budget SHA-256, outcome, usage, reserved/charged µUSD, cost-unknown, request
  SHA-256 and sizes, times). Refusals before sending cost nothing and are only journaled (`model-broker:`). If a
  receipt cannot be written, the call's tail is withheld and the link admits nothing more until the node restarts.
- **Refusals** are Anthropic-style errors the adapter classifies: 401 no key / key not approved (`AUTH`), 402 no
  budget / expired / spent / per-call cap / call count (`QUOTA`), 400/413 bad, oversized or disallowed (`INVALID_REQUEST`),
  429 busy, 502/503 provider unreachable or receipts unavailable. A provider error passes its status and its error
  type (when it is a known token) with a FIXED message per status; the provider's own message never passes (O15:
  DeepSeek's 401 names the key's last four characters, which no 12-byte echo window can see).

RAN (Mac): `cargo test -p broker engine_link` against a fake DeepSeek on loopback (fake keys): streaming with
thinking, text and a tool call byte-for-byte, the stripped headers and members, the output cap, the receipt and the
spend; refusals for no key, unapproved key, no or expired budget, disallowed model, oversized, non-streaming, unknown
member, wrong peer; a spent budget and a used-up call count; the key echoed in an error, split across two stream
chunks, in base64, as JSON escapes, five characters per delta, escaped inside a tool call's arguments and as the
reported model; tool arguments split between pings, a stream ending inside a tool block, thinking pieces between
signature pieces; an incomplete stream; a reservation that never settled; a torn record followed by a new reservation and a
second crash; a malformed record; compaction. LINUX: the socket, `SO_PEERCRED`,
the bridge inside the wall, the composition with rows 4 and 5, DeepSeek itself.

The TEMPORARY alternative (an OpenShell provider plus a `network_policies` hole for `api.deepseek.com`) is not
needed and not wired.

## 8. Runbook: spawn a node and run the ceremony

Every step below ran on the node rehearsal of 2026-10-17 (Claude's own test node, software passkey, a fake model key)
with the commands as written; what differed there is said. Three machines: the **operator's Mac**, the **artifact
VM** (Linux, docker.io, the wall test's VM: builds the artifacts and the release; the Mac's disk never holds the ~1 GB
stage) and the **node** (a fresh Nebius VM made by `spawn.sh`). `R` = this repository on each machine.

**A. Artifacts (once per pin set), on the artifact VM**, in `~/art` (`~/art/stage` collects the five operator files):
1. Node: `curl -sSfLO https://nodejs.org/dist/v24.11.1/node-v24.11.1-linux-x64.tar.xz` and its `SHASUMS256.txt`;
   `grep " node-v24.11.1-linux-x64.tar.xz$" SHASUMS256.txt | sha256sum -c`; unpack to `~/art/node24`.
2. The harness: `mkdir ~/art/dsh && cd ~/art/dsh` (the folder must be named `dsh`: the lockfile records it), then with
   `PATH=~/art/node24/bin:$PATH`: `npm install --save-exact --ignore-scripts --no-audit --no-fund @deepseek-ai/dsh@0.2.1-alpha.5`;
   `tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 -czf ~/art/stage/dsh-engine-0.2.1-alpha.5-linux-x64.tar.gz package.json package-lock.json node_modules`.
3. OpenShell: download `openshell_0.1.4-1_amd64.deb` and `openshell-checksums-sha256.txt` from
   `https://github.com/NVIDIA/OpenShell/releases/download/v0.1.4/`, check it, `dpkg-deb -x` it, put `usr/bin/openshell` and
   `usr/bin/openshell-gateway` in a folder `openshell-0.1.4`, then
   `tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 --mode=go-w -cf - openshell-0.1.4 | gzip -n -9 > ~/art/stage/openshell-0.1.4-linux-x64.tar.gz`.
4. Images: `sudo docker save -o ~/art/stage/openshell-sandbox-image.tar node:24-bookworm ghcr.io/nvidia/openshell/sandbox:0.1.4 ghcr.io/nvidia/openshell/supervisor:0.1.4`
   (all three: the docker driver runs the sandbox runtime and the supervisor images beside the sandbox image, with
   `image_pull_policy = "never"`).
5. Rust: `RUSTUP_HOME=~/art/rustup CARGO_HOME=~/art/cargohome rustup toolchain install 1.99.1 --profile minimal --target wasm32-unknown-unknown --no-self-update`;
   in `~/art/rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu`:
   `tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 --mode=go-w -cf - . | gzip -n -9 > ~/art/stage/rust-1.99.1-x86_64-unknown-linux-gnu.tar.gz`.
6. llama.cpp: `llama-b10621-bin-ubuntu-x64.tar.gz` (a tar.gz; GitHub's asset digest is the pin). The installer
   downloads it, node and the two models itself, over HTTPS, against the pins.
7. `python3 -B R/deploy/engine/engine.py pin FILE` for each; fill `engine-pins.json` (sha256 and bytes). A changed pin
   is a reviewed commit. Steps 2, 4 and 5 and the plugins give the same bytes when repeated.

**B. Plugins.** On the Mac (the disposable harness checkout `~/face-scratch-dsh/src` at `dsh-v0.2.1-alpha.5` lives
there), with node 24.11.1 and pnpm on PATH: `python3 engine/plugins/aukora-face/build-face.py --dsh ~/face-scratch-dsh/src`.
Copy the built libs to the artifact VM's checkout of the same commit (`COPYFILE_DISABLE=1 tar -cf faces.tar
engine/plugins/aukora-face/*/lib engine/plugins/aukora-foundation/lib`), then there:
`python3 -B -I deploy/engine/build_plugins.py --dsh ~/art/dsh --faces engine/plugins/aukora-face --node ~/art/node24/bin/node --out ~/art/plugins-out --tar ~/art/stage/engine-plugins.tar`
(twice into two folders and `cmp` the tars: equal). After C1, `bin/sovereign engine fingerprint --from ~/art/plugins-out`
from the release prints the set (thirteen names, the door `authority: true`) and its pin; `sha256` of its first line is
the `new_sha256` the plugin-set card must show. Keep both for D4.

**C. Release and node.**
1. Commit (pins; plugins are not in git). On the artifact VM (Linux; it needs the wasm32 target for the app build:
   `rustup target add wasm32-unknown-unknown --toolchain 1.99.1`, and `cargo fetch --locked` once):
   `PATH=~/art/node24/bin:$PATH R/scripts/reproduce.sh build COMMIT ~/art/release --twice` (about 12 minutes on 4 vCPU).
   Copy `release.json` and `release.tar` (about 50 MB) to the Mac.
2. On the Mac, with the Nebius settings (`deploy/README.md`) and
   `AUKORA_VM_HOURLY_ESTIMATE` (cpu 4 vCPU / 16 GiB: about 0.12 USD/h with the 80 GiB disk and the address),
   `AUKORA_NEBIUS_SECURITY_GROUP_ID` (a group admitting 22 from the operator, and 80 and 443 for a public node: Nebius's
   default group admits every port) and, for a disposable node, `AUKORA_VM_DELETE_AFTER=YYYY-MM-DD`:
   `deploy/spawn/spawn.sh create NAME --on nebius-vm --release DIR --provider deepseek --spend-ok --claim-out CLAIM`.
   `--provider deepseek` is required: it pins `api.deepseek.com` in the node's egress, and the engine installer refuses
   without it. The VM is the smallest CPU preset with 4 vCPU and 16 GiB, 80 GiB disk (O1). The tenant's public IPv4
   quota (3 on the rehearsal's tenant) must have room. About 4 minutes.
3. The stage, VM to VM (never through the Mac): put a throwaway key's public half in the node's
   `~ubuntu/.ssh/authorized_keys`, copy `~/art/stage/*` from the artifact VM to the node's private address, then on the
   node `sudo install -d -m 0700 /root/aukora-engine-stage` and `sudo install -m 0600` each file into it; remove the key.
   On the Mac: `python3 -B deploy/engine/engine.py install NAME --stage-on-node --dry-run`, then without `--dry-run`
   (about 5 minutes). It first pins the door's allowlisted `net.hosts` in the node's egress (resolved on the Mac, a
   new egress epoch through the node's `node_release.py egress`; O10; `engine.py egress NAME` does that alone for a
   node installed before it). It needs `AUKORA_SSH_KEY_FILE`, `AUKORA_NEBIUS_PARENT_ID` and `AUKORA_SPAWN_STATE` as
   spawn does. Then it enables the fences, docker, the gateway (mTLS, its own PKI), the bridge tmpfs, the model
   servers, Kira, extends Caddy with the engine host and restarts the supervisor. The engine does not start.
4. On the node, as root: `sh /opt/aukora/current/deploy/units/check-units.sh` (NODE: `units ok`);
   `systemctl is-active aukora-kira aukora-openshell-gateway 'run-aukora\x2dengine-io.mount'`;
   `journalctl -u aukora-sovereign | grep engine:` shows `awaiting-owner-binding`.

**D. The ceremony (the owner, with the passkey device).**
1. Open the claim link from `CLAIM` (`https://<shell>/#claim=…`); the operator then deletes the file.
2. Bind: create the passkey on the owner origin, as today. Journal: `engine: awaiting-release-approval` (NODE, since
   O11; before it the install's starting floor counted as approval and the engine waited on the plugin set first).
   `https://<shell>/engine/open` answers `supervisor:release-not-approved` until the release card is approved.
3. Cards pop up one after another (also under Approvals): the release ("Approve the installed release as the owner's
   release floor", `release_sha256` = the release id from C1), `engine/model-budget.json` (the terms from
   `model-broker-v1.json`; proposed at start, before any key) and, once the release is approved, the plugin set.
   Approve the release. Journal: `engine: awaiting-plugin-set-approval`; the engine is still inactive (NODE).
4. Approve the plugin set: the critical card for `engine/plugin-set.json`; its `new_sha256` must equal the sha256 of
   the fingerprint's set line from B. Passkey.
5. Journal: `engine: running`, said only once the unit is active, i.e. after `engine-run.sh verify` passed. On the
   node `sh /opt/aukora/current/deploy/engine/wall-check.sh` prints `wall ok` (NODE: 27 probes, DNS included).
6. Open `https://<shell>/engine/open` in the signed-in browser: the Spatial face loads on `engine.<shell>` (NODE).
7. The model key and budget: open `https://<shell>/engine/model-key`, type **your own** DeepSeek key (nobody else
   enters, prints or stores it; never in a file). The page shows a fingerprint (12 hex digits); the
   `engine/model-key.json` card's `key_sha256` must begin with it; approve it and the budget card. A new chat needs a
   workspace first (New Chat, Choose workspace, Add workspace, Open: `/work`; a harness home that already has one opens
   on it). Journal on Auma's first turn:
   `model-broker: call … completed …` (NODE with a fake key: `provider-refused`, the harness recorded DeepSeek's own
   HTTP 401 "Authentication Fails": engine, bridge, broker and provider all reached). After a supervisor restart the
   stored key is loaded again when it is the approved one (journal: `model-broker: the stored key was loaded`); there is
   nothing to retype.
   The reply renders in the chat and the session history loads after a reload (NODE since O9, with the fake key:
   "This turn failed · API key is invalid · AUTH"). The harness's preview notice is acknowledged by the overlay
   (row 3): its own Continue cannot persist inside the wall.
8. Crossings: a `web_fetch` of an allowlisted host raises a door ask card (`door/ask-NN.json`: tool, class, call
   digest); approve; the repeated call runs once and returns the page (NODE since O10: example.com's HTML).
   `kira_remember` / `kira_recall` go through the door with the non-owner token after an ask card each (the starter
   slider asks for memory too; NODE: remembered, recalled with the real embed and rerank models); `kira_get` of
   `aukora:self` / `aukora:resume` runs without a card (O14); `kira_quarantine_source` is refused `owner-only`. A host off the allowlist is refused `host-not-allowed` without a card.
9. Negative checks: append a byte to `/opt/aukora-engine/plugins/aukora-door/lib/index.js` → within 5 s the engine
   stops (`authority-plugin-changed`; NODE: 1 s, sandbox removed) and a plugin-set card appears with the approved set
   as its base; restore the byte (or approve, deliberately not) → it starts again (NODE: 4 s). On the engine origin:
   no or a forged cookie 401, a ticket by fetch or a spent ticket 403, `?token=` 404, a service worker 403 (NODE); an
   upgrade to any path but `/api/remote.mux`, or from another Origin, is refused (unit tests). Signing out of the shell
   (`POST /api/session/end`) → the engine origin answers 403 at once and an open engine WebSocket closes 1008 within
   5 s (NODE, O12); re-bind or a release change → 403 as well.

**E. Upgrade a bound node (O17).** The node keeps serving its approved release (shell, owner origin, engine) until
the owner approves the new one; nothing switches before that.
1. Build the release as in C1 (`scripts/reproduce.sh build COMMIT DIR --twice`) and copy `release.json` and
   `release.tar` to the node (`/root/upgrade-stage`, 0700).
2. On the node, as root, from the CURRENT release's tools:
   `python3 -B /opt/aukora/current/deploy/upgrade/node_release.py stage --stage /root/upgrade-stage` (prints the id),
   then `... node_release.py offer --id ID`. This only makes the link `/opt/aukora/offered`.
3. The running release verifies the offered tree, then probes it (O20) in its own unit, never in its own process
   tree: it starts `aukora-release-probe@ID.service` (polkit: that template, start only). There root (the installed
   release's `release_probe.py prepare`) copies the identity, floor, targets, sessions and the ledger (SQLite
   `VACUUM INTO`) for a throwaway user (DynamicUser, no network, no capabilities, none of `/var/lib/aukora*`,
   `/etc/aukora`, the door, broker, engine or Kira sockets); the offered binary runs `sovereign release probe` on that
   copy; systemd kills the whole cgroup at 90 s; root (`release_probe.py finish`) records the outcome in
   `/var/lib/aukora-release/probe/ID.json`: passed only for a clean exit and exactly one stdout line in this run's
   journal, `probe ok <digest>`. The probe starts when the owner's shell polls Approvals (that is when the running
   release looks for an offer). Journal: `release: probing the offered release …`, then `… started on a
   copy of the state; its card can go up` or `… did not start …; no card` (tried again after 10 minutes). Only then does it raise the card "Upgrade this node to a new release"
   (`base_sha256` = the running release, `release_sha256` = the new `release.json`'s SHA-256). The engine keeps running.
4. The owner approves it with the passkey. The floor advances in one Aura transaction; the supervisor logs
   `release: the owner approved release …; restarting to switch to it` and exits 75; systemd starts it again and the
   unit's root pre-start (`node_release.py follow`, which reads the floor through the installed binary as aukora with
   `sovereign release floor`) checks the floor against root's anchor (`/var/lib/aukora-release/anchor.json`: the
   floor root last accepted; the new floor must extend it, later version and the same spent approvals plus more),
   advances the anchor, writes an activation intent (`activation.json`, synced), moves `current` to the new release
   and `previous` to the old one, writes `active.json`, removes the intent and drops the offer (a crash in between is
   finished at the next start from the intent) (journal: `node-release follow: switched to ID`). A floor behind or beside the anchor (a restored
   snapshot of the service's state) is refused (`refused: the floor is behind the anchored floor …`) and the
   supervisor will not serve it (`floor-behind-anchor`). Going back to an older release is an owner approval like any
   other: `offer` the older staged release and approve its card. The engine stops only for that restart and
   starts again on the new release (a release that changed the plugins still needs its plugin-set card).
5. Not approved: Decline (the owner's no; it stays declined until the owner asks again from Approvals), or the card
   simply stays up (release cards do not expire; other cards that run out of time are held back a day unless the owner
   asks again). `node_release.py withdraw` takes the offer back; the running release
   then withdraws the card (an expiry with reason `withdrawn`, never a decline). Either way the current release keeps
   running. Never withdraw after the owner approved: `follow` switches to the staged release the floor names even
   without the offer, but only while it is still staged.
**Before the first anchor.** Root writes its anchor at the first start that follows an owner floor (or the first
switch). Until then the only check is that the floor names the running release or moved on from it; an older
approved state restored in that window is not caught by the anchor (Codex re-review: no concrete bypass found in
this flow, but the window is real). The polkit rule that lets the supervisor start the probe is written by
`engine_install.py` (`aukora-engine.rules`); a node without an engine has no probe rule, so its offers never get a
card. A release from before the probe unit never offers a card through a running release that probes in a unit.
A node installed before this release has no `follow` step and no upgrade card: bring it to this release once by the
redeploy below (or the signed-pointer `upgrade.sh`, whose new binary then waits for the release card as before).
`upgrade.sh`/`node_release.py switch` (the owner-signed pointer) remain; on a bound node prefer `offer`.

**Redeploying a bound node (disposable test nodes only).** The rehearsal re-ran genesis on the same VM for each new
release, as root: stop the supervisor; MOVE (never delete) `/var/lib/aukora` to `/root/rehearsal-N-state` with copies
of `/var/lib/aukora-release`, `claim.sha256` and `egress.json`; remove `claim-delivered`; `node_release.stage` the new
release, point `previous` and `current`, `write_active(rid, manifest, digest, 0, None)`, `apply_units`; a new claim
commitment (`node_release.py claim --digest`, the secret made on the Mac, the link in a 0600 file); start the
supervisor; walk D1-D7; `claim --delivered`. Kira's state, the engine install, `/etc/aukora` and Caddy stay.

**Stop / roll back.** `systemctl stop aukora-sovereign` stops the engine too (`PartOf`). Remove `/etc/aukora/engine-v1.json`
and restart the supervisor to run the node without an engine. Upgrades: a new release changes the binary, so the floor
stops the engine until the owner approves that release; plugins changed by the release need a new set approval. The
root pre-start refuses unless the supervisor's `admission.json` names the active release (the closure refuses one with
no release id), and the admission belongs to one supervisor run: it is removed when the supervisor stops
(`ExecStopPost`), again when the controller starts (which also stops a running or still-activating engine), and on
every "stop" decision. The engine unit starts only after the supervisor (`After=`) and is skipped, not failed, while
there is no admission (`ExecCondition`), so a start systemd propagates by itself (`PartOf`) cannot outrun the
decision and cannot exhaust the start limit. A start still in `activating` counts as running and is stopped when a
condition is lost.

## 9. What is built, stubbed, Linux-only

Built and tested here (RAN): the model broker's engine link (section 7, fake provider), its config, the key card bytes; `floor::plugins` (a changed authority package is now a blocked assembly with the package
pending, not an error); `engine_plugins` (bootstrap set, one candidate set, hash-while-copy closure); the engine module
(config, controller decision, closure CLI, fingerprint CLI, tickets/sessions, proxy with its fake-harness test); the
`/engine/open` route; gate `approved_target` / `propose_plugin_set` and the guest refusal of `engine/`; Kira
`--group-socket`; `build_plugins.py` (reproducible), the profile, the authority overlay (composed and booted with the
real harness on the Mac); the release now ships `deploy/engine`; the inventory gains `engine/plugin-set.json`.

NODE (ran on the rehearsal node): `engine_install.py` via `engine.py install --stage-on-node`, `engine-prestart.sh`,
`engine-run.sh` (create, verify, delete), `wall-check.sh` (`wall ok`), the units (`check-units.sh`: `units ok`), the
polkit rule (the supervisor starts and stops the engine), tmpfiles, the bridge tmpfs mount, the nft fence (a non-root,
non-65534 user is refused at :690; only kira reaches 8771/8772), the mTLS gateway, the sticky-home protections, the
Kira units with the pinned models, Caddy's engine block, the model broker's socket and peer check behind the in-wall
bridge (a call reached DeepSeek), the door in the supervisor (asks and refusals on the starter slider with no
grants: standing grants did not run on the node before section 12, P3), the engine origin's ticket
flow. On Linux under umask 002: `cargo test -p supervisor door` (108), `-p broker engine_link` (12),
`-p supervisor engine` (25), `-p supervisor build::` (24), `tests/deploy` (6): all pass (O6).

RAN on the wall-test VM, not the node: the DNS control (the same probe resolves without the node's resolv.conf).

Not built: the face's own owner-approval surfaces pointing at the owner origin; an inventory sync for nodes
installed before this branch (they refuse `engine-install: inventory-lacks-engine-target`). The pre-swap probe (O20)
starts the candidate on a copy of the state but does not serve HTTP or run the engine with it.

## 10. Open items

Closed by the node rehearsal: **O1** (vm.py picks 4 vCPU / 16 GiB / 80 GiB), **O2** (the wall test's argv; the CLI is
the registered gateway `aukora`), **O3** (mTLS user auth, `allow_unauthenticated_users = false`), **O6** (above).

- **O4** `deploy/engine/*` is in the release (so the owner's release approval covers it) but not in `checks/run.py`'s
  `DEPLOY_PINS`; pin `engine_install.py` and `engine.py` once reviewed.
- **O5** The plugin-set pin in `ProtectedState` (floor schema change + Aura migration) instead of the audit file.
- **O7** CLOSED (Peter, 2026-10-17: persist the key, no retyping). The approved key is kept in
  `/var/lib/aukora/model-key/model-key` and loaded at start only if its SHA-256 matches the approved card (section 7,
  Key). Residual: the file is a secret at rest on the node's disk, readable by the `aukora` user and root, like the
  node's signing key beside it; a disk image of the node carries it.
- **O8** CLOSED (Peter, 2026-10-17: he controls the spend through his DeepSeek balance). The shipped terms
  (`engine_install.py` `MODEL_BUDGET` -> `/etc/aukora/model-broker-v1.json`) no longer stop a call: $1000 in all
  (1000000000 µUSD), $2 a call, 1000000 calls, 365 days (the supervisor accepts up to 366). The mechanism is unchanged:
  every call is still reserved against the cap, receipted, and refused outside the owner-approved terms. The card shows
  dollars beside the micro-dollar amounts. The prices stay placeholders above DeepSeek's published prices (the meter
  over-counts; harmless at these caps). The model names are the harness's catalog (`deepseek-flash`, `deepseek-v4-pro`),
  not checked against the live API (the harness asked for `deepseek-flash`; DeepSeek answered 401 to the fake key
  before judging the name). `engine_install.py` writes the file once: a node installed with the older terms keeps
  them until `/etc/aukora/model-broker-v1.json` is rewritten with the new `budget` and the supervisor restarted; it then
  proposes the new terms on a card (changed terms propose again).
- **O16** Nebius: the tenant's public IPv4 quota is 3 (pilot, the wall-test VM and an unassigned 2026-10-09 address
  held it; the rehearsal took the wall-test VM's address). The node's VM needs one. Note only, no code.
O17, O18, O19 and O20 (the pre-swap probe, Peter's decision) are closed by the owner-lifecycle branch (node/owner-lifecycle, 2026-10-17); see the table at the
end of this section.

Closed by the blockers branch (node/blockers, 2026-10-17), each verified on the rehearsal (test) node (`aukora-rehearsal`,
re-run genesis three times: releases 424b87a…-82ada51f, 28b6fc8…-a35e16a7, 6a64be9…-ea0195a3; software passkey,
fake DeepSeek key, headless Chrome through the SSH tunnel; screenshots kept privately, not published):

| Item | Fix | Test-node evidence |
|---|---|---|
| **O9** WebSocket | `engine/socket.rs`: the one upgrade (`/api/remote.mux`) forwarded under the session's admission, exact Origin, frames checked; permessage-deflate offers admitted, never forwarded; the overlay acknowledges the harness's preview notice (its Continue cannot persist in the wall and the modal covered the composer) | CDP: `HandshakeResponseReceived 101 Switching Protocols`, frames both ways, no "connection lost, retry"; chat "Hello Auma, please reply with one short sentence." → the turn renders "This turn failed · API key is invalid · AUTH" (`o9-chat-reply-rendered.png`); after a reload the session's history loads (no "Loading history…"); journal `model-broker: call … provider-refused model=deepseek-flash … charged=0`. Sign-out in another tab closed the open socket 1008 3.9 s later |
| **O10** door egress | `engine.py egress` / `install`: door `net.hosts` pinned like the provider (egress epoch 3: `api.deepseek.com`, `example.com`); installer refuses without them | from inside the wall: `web_fetch https://example.com/` → `ask-net` → card `door/ask-00.json` approved → repeat → `decision: allow`, 67 ms, body `<!doctype html>… Example Domain`; `wikipedia.org` → `host-not-allowed`, no card; `wall-check.sh` → `wall ok` after the egress change |
| **O11** release floor | start only on an owner-approved floor naming the running release; Unknown ≠ NotApproved (retry, hold ≤ 30 s, never start); the store waits ~1 s for a held lock; 503 not 403 on Unknown | each genesis: `awaiting-owner-binding` → bind → `awaiting-release-approval` (engine `inactive`, `/engine/open` → `supervisor:release-not-approved`) → release card → `awaiting-plugin-set-approval` → plugin set → `starting`, `running`. Root held `floor.lock` 12 s: `the release floor cannot be read now; the running engine is kept`, engine stayed `active`; held 45 s: kept, then `release-unreadable` at +31 s (stopped), `starting`/`running` when released. Release 1 still showed `floor:locked` on `GET /api/approvals`; none since the store wait |
| **O12** shell session | tickets and engine sessions bound to the shell session's digest, ≤ its life; re-checked per request and every 5 s on a socket; `POST /api/session/end`; ended sessions answer 403 | engine origin 200 → shell `POST /api/session/end` → `{"ended":true}` → engine origin `403 This engine session ended: you signed out of your node…`; open WebSocket closed 1008 |
| **O13** cards | spaces render as spaces; repeat warning only for pressure words or a word hammered 3× within 6 words | model-key and budget cards: plain spaces, no warning row (`o13-model-key-card.png`); the repeat rule matches every Prime vector (test) |
| **O14** own slots | a policy allow of `kira_get` `aukora:self`/`aukora:resume` skips the slider | inside the wall: both reached Kira at once (`kira:not-found`, no card); `resume:grok` and `kira_recall` → `ask-memory` |
| **O15** provider errors | fixed message per status, the provider's text never passes | inside the wall, fake key: `401 {"error":{"message":"aukora broker: the provider refused the key (HTTP 401; the provider's own message is withheld)","type":"authentication_error"}}` |

Also from a model review of d453016 (a builders' private report, not published), on release
bbe36d9…-95d2ffc1 (a fourth genesis; the new polkit rule copied by hand to `/etc/polkit-1/rules.d/50-aukora-engine.rules`,
as `engine_install.py` writes it only at install):

| Item | Fix | Test-node evidence |
|---|---|---|
| **C2** failed unit stuck | admitted + failed: `reset-failed` then the normal start, backoff 30 s doubling to 10 min; not admitted + failed: start `aukora-engine-cleanup.service` (root oneshot: `engine-run.sh delete`, then `reset-failed`); polkit allows exactly those | root SIGKILLed the engine until systemd said "Start request repeated too quickly" (unit `failed`, Result=signal): the same tick the journal said `the engine unit failed; resetting and starting it again (next try in 30 s)`, and `running` followed; a second start-limit hit recovered the same way. The not-admitted cleanup path is unit-tested only (backoff) and its unit is `static` (`check-units.sh`: units ok) |
| **C3** stop fallback | `engine-run.sh delete` waits 10 s, then `docker rm -f`; `TimeoutStopSec=90s` | root blocked its own connections to the gateway (:690) so OpenShell's delete could not run, then a changed door byte stopped the engine: both sandbox containers removed by the docker fallback, the unit `inactive` (not failed) 13 s after "Stopping"; the rule removed, the byte restored, `running` again. With the old 30 s wait inside a 30 s stop bound the fallback could never run |
| **Mistral** admission | `engine-prestart.sh` and `closure.rs` enforce the control folder's and files' owner, mode, links and no-link (above, section 2); the supervisor writes them 0600 explicitly | release 07c5c0b…-843855eb (genesis 5 and 6): folder `aukora:root 750`, files `aukora:aukora 600`, 1 link; `auma` writing the file: `Permission denied`; inside the sandbox the folder does not exist. Root set the admission 0666 and restarted the engine: `engine-prestart: the admission is not the supervisor's (owner, mode or links)`, the unit failed; the controller then reset it and started it again with a fresh 0600 admission (C2), `active` |
| **C16** docs | NODE.md section 1 and the gateway unit say the fence admits root and 65534; the stale [GUESS] is gone | — |

Tests (Linux, the node, umask 002): `cargo test -p supervisor -p broker -p gate -p floor -p frontdoor` (sovereign
170 + 1 ignored, broker 13, gate 17, floor 7, frontdoor 4), `tests/deploy` (8); `scripts/check.sh` CONSTRUCTION GREEN
on the node (the Mac stayed under its disk floor).

Closed by the owner-lifecycle branch (node/owner-lifecycle, 2026-10-17), verified on the rehearsal (test) node (genesis 7
with release 82254d3…-83c97646 (A), then upgraded in place to 8834ad9…-4c29ddb9 (B); software passkey, fake key,
headless Chrome through the SSH tunnel; screenshots kept privately,
not published):

| Item | Fix | Test-node evidence |
|---|---|---|
| **O17** upgrades | `node_release.py offer` (link `/opt/aukora/offered`); the running release raises the upgrade card from its floor and keeps serving; approval advances the floor (the supervisor's release proposal is ordering evidence for an owner floor too: `floor` and Aura's twin); exit 75; unit pre-start `node_release.py follow` switches to the staged release the floor names (read by `sovereign release floor` as aukora); a withdrawn offer withdraws its card (not a decline) | A running with the engine `active`; B staged and offered at 13:22:06; card "Upgrade this node to a new release" (`base_sha256` = A, `release_sha256` = B) while `current` stayed A and the engine stayed `active`; approved 13:23:34 → `release: the owner approved release 4c29ddb9…; restarting to switch to it`, `engine: awaiting-release-approval`, exit `status=75/TEMPFAIL` 13:23:36, `node-release follow: switched to 8834ad96a45c-4c29ddb97c0e` 13:23:39, `engine: running` 13:23:49 (the supervisor down 3 s, the engine about 15 s); `current` = B, `previous` = A, offer gone, `active.json` = B, floor `aukora-floor-state-v2` naming B with A in its history, `admission.json` names B, the plugin set needed no new card (unchanged plugins) |
| **O18** sign-in / sign-out | shell: one primitive button pinned at the base of the right-hand menu, "Sign in with your passkey" / "Sign out" (`POST /api/session/end`); session refusals are a calm signed-out state; the AUMLOK face's CSP (`connect-src 'self'`) no longer blanks it | on B: Sign out → the button reads "Sign in with your passkey", `/api/approvals` 400 `frontdoor:session-required` (`live-o18-signed-out.png`); clicking it opened the owner pane and signed in with the passkey, the button read "Sign out" again; on A the AUMLOK face rendered its own Sign in (it was blank before). The look needs Peter's preview (local shots `01`…`17`) |
| **O19** declines | only the owner's Decline (`gate.refuse`, reason `owner-declined`) is a decline; an expiry or another refusal frees the same bytes; `POST /api/v1/approvals/decline` (no passkey, ends a live review) and `/again` (fact `aukora-owner-again-v1` as new evidence; release cards raised afresh); the owner card has Decline and Ask again; the shell's Approvals says "N declined · ask again"; the model key: card before key, re-entering a declined or expired key raises a fresh card, another key's card up refuses `awaiting-other-approval` (SCOUT M5; SCOUT's own branch was not visible here) | upgrade card declined (`gate.refuse` seq 25; `live-o19-declined.png`, the shell's Approvals "1 declined · ask again"); for 20 s of shell polling nothing raised it again and `current` stayed A, engine `active`; Ask again 24 s after the decline raised a fresh card (seq 26, `live-o19-asked-again.png`), which was then approved (the upgrade above). Model key: fake key entered → card; Declined → the same key entered again → a fresh pending `engine/model-key.json` card (`refused`, then `pending`). Tests: an expired card's bytes raised again, a decline held until asked again, door asks per call (supervisor `adapters::gate`, 5) |

Then (Codex review of the branch, Peter's decisions on O20 and the re-proposal cap), on the same test node: release
D (ed7a900…-16c5a08c, the fixes below) through B's own card, then E (aff2272…-b66fdcab), then back to D:

| Item | Fix | Test-node evidence |
|---|---|---|
| **B30** (Codex HIGH) rollback by restore | root keeps `/var/lib/aukora-release/anchor.json` (root 0644, synced): the floor it last accepted; `follow` needs that floor or a successor (later version, spent approvals extended), refuses behind, divergent or a non-root anchor; the supervisor refuses to serve a floor behind it (`floor-behind-anchor`) | on D a restart anchored D's floor (`unchanged (anchored)`, seq 40, 3 spent); the D-era state was copied, E approved (anchor seq 46, 4 spent); the D-era copy was restored and the supervisor restarted: `node-release follow: refused: the floor is behind the anchored floor (restored or divergent state)`, `current` stayed E, the supervisor journaled `the floor is behind the floor root accepted …; refusing to serve it`, the engine stayed `inactive`; the real state put back: E served, engine `running` |
| owner-approved rollback | going back is a new card from the running floor to the older release | E offered D: probe passed, card, approved, `switched to ed7a900e3be3-16c5a08c4f1e`; anchor seq 51, 5 spent, history A, B, E |
| **O20** pre-swap probe | the offered release's own binary runs `sovereign release probe` on a copy of the state (ledger via `VACUUM INTO`); the card goes up only on `probe ok <digest>` | E offered on D: `probing the offered release b66fdcab…` then `… started on a copy of the state; its card can go up` within a second, then the card; B (no probe command) offered on E: `the offered release's probe said: supervisor:release-pointer-usage`, `… did not start …; no card`, no pending release card |
| re-proposal cap | bytes whose card simply expired are held back 24 h (`gate:recently-expired`) unless the owner asks again for that very card (its `aukora-owner-again-v1` fact; other evidence does not lift it, Codex re-review 3); listed beside the declines | unit tests (`adapters::gate`); not exercised live |
| Live, Zeta Harp, Lingwa faces | `connect-src 'self'` (their JSON module imports were blocked, the AUMLOK cause) | checks green; not opened on the node |

Codex's re-review (probe isolation, activation intent, the cooldown's binding), on the same test node with releases
F (d985805…-9080a0fd), H (c8e92b3…-73e7ff7a) and I (473b7ab…-ed80b9b0):

| Item | Test-node evidence |
|---|---|
| probe in its own unit (Codex HIGH) | `systemd-analyze security aukora-release-probe@…`: 0.5 SAFE. A FAKE staged release whose `bin/sovereign` is a hostile script, started in the unit: it ran as a throwaway uid (62669) with only its copy (`aura-signing-key aura.sqlite3 browser-sessions floor node-identity-v1 targets`); `live state unreadable`, `live signing key unreadable`, `/etc/aukora hidden`, `door and broker sockets hidden`, `no TCP connection`, `no socket of any family`, `release state not writable`; it forked a `setsid sleep 1000` survivor and printed the expected success line, then hung: at 90 s `Failed with result 'timeout'`, survivors 0 (the cgroup was killed), root's record `passed: false, result: timeout`, the copy and the configuration copy gone. A good candidate (D) in the unit: `probe ok <digest>`, `passed: true` |
| supervisor ↔ unit | F offered H: the supervisor started `aukora-release-probe@…` through polkit, root recorded passed, the card went up, approved, `switched to c8e92b338716-…`; H's follow installed the template from H's release; H offered I through that installed unit: `release-probe: passed`, card, approved, `switched to 473b7abc3995-…`, anchor seq 65, 8 spent, no activation intent left |
| found live and fixed | a stdout file under the unit's runtime folder could not be opened for the root step (209/STDOUT): the answer is read from the journal; the unit's UMask 0077 applies to root's steps: the configuration folder (config-unreadable), node.json's claim/egress paths (config-path) and the results folder (0700: the supervisor timed out on a passed probe) are now set explicitly (the last fix is after I; on this node the folder was set by hand) |
| activation intent, cooldown binding | unit tests only (a crash between the links and active.json finished at the next start; an unanchored intent dropped; unrelated evidence and another card's Ask again do not lift the day) |

Tests (Mac): `cargo test -p floor` (10, three new: genesis and upgrade ordering), `-p supervisor -- adapters::gate
release::owner` (7 new), `tests/deploy/test_node_release_upgrade.py` (6: offer switches nothing; follow waits for the
floor, switches to the approved release, survives a withdrawn offer, refuses an unstaged or tampered one).

## 11. Resource use (the rehearsal node, 4 vCPU / 16 GiB / 80 GiB)

Idle, engine running (10:12 UTC) and around a chat turn (11:15; with the fake key the turn ends at DeepSeek's 401,
so no generation load was measured):

| | idle | chat turn |
|---|---|---|
| RAM used (`free -m`, of 15 992 MiB; page cache excluded) | 1 590 MiB | 1 705 MiB |
| load average (1 min) | 0.47 | 0.37 |
| sandbox container / its supervisor container (`docker stats`) | 213 MiB / 16 MiB | 296 MiB / 15 MiB |
| aukora-sovereign | 29 MiB | 50 MiB |
| aukora-kira-embed / -rerank (llama-server) | 303 MiB / 140 MiB | same |
| aukora-openshell-gateway | 136 MiB | 147 MiB |
| aukora-kira / aukora-engine (unit, outside the container) / docker | 2 / 16 / 59 MiB | same |
| disk: `/opt/aukora-engine` 1.1 GB, `/opt/rust` 692 MB, docker images 1.76 GB, `/opt/aukora` 47 MB per release, `/var/lib/aukora*` < 15 MB | 12 GB of 77 GB used (incl. ~2 GB of the rehearsal's own build caches) | |

So the node idles at about 1.6 GiB and about 12 GB of disk. A cheaper node is plausible (8 GiB, 2 vCPU, a 40 GB disk);
4 GiB would be the floor and leaves little for a real turn's tool work (cargo inside the wall), which this rehearsal
could not measure without a real key.

## 12. Pre-launch hardening (node/pre-launch, 2026-10-18)

From Auma's own red-team of the node (a private report, not published), one commit each.

**P1. The passkey and the engine origin (R6).** The relying-party id is the owner host, exactly (`CeremonyContext`:
`owner.<shell>`, the RP the passkey was created for), never the shell host. WebAuthn lets a page name its own host or
a registrable parent as `rpId`; `owner.<shell>` is neither for `engine.<shell>`. NODE, from a page on the engine
origin of the rehearsal node (headless Chrome, software passkey): `navigator.credentials.get({rpId: "owner.<shell>"})`
→ `SecurityError` ("not a registrable domain suffix of, nor equal to the current domain"; the browser's
`/.well-known/webauthn` related-origin fetch on the owner host failed, 400); `rpId: "<shell>"` (the parent) →
`NotAllowedError` (no credential there). So the owner's passkey cannot be exercised from the engine origin: refuted.
What was true: the engine origin could run a WebAuthn ceremony of its own (`featurePolicy` allowed both, and
`credentials.create({rp: {id: "engine.<shell>"}})` made a look-alike passkey), the raw material of a fake "confirm your
passkey" panel. Fixed: every reply the supervisor's engine proxy sends carries one `Permissions-Policy` (ours replaces
the harness's; the WebSocket 101 too since P1b) and so does everything Caddy answers itself on the engine host (P1b)
denying `publickey-credentials-get`, `publickey-credentials-create`, `identity-credentials-get`, `otp-credentials` and
`payment`; and `engine-v1.json` is refused (`engine-config-relying-party`) when the engine host equals the owner host
or lies under it. Migration: none. The RP id did not change, so enrolled passkeys keep working. NODE after the fix
(release 791de25…-6dfa9e66, re-run genesis): every proxied engine-origin reply carries the header; in an engine-origin page
`featurePolicy` allows neither, and `get` (owner RP and parent RP) and `create` all end `NotAllowedError` ("the
'publickey-credentials-…' feature is not enabled in this document"); the owner's own sign-in on the owner origin
works as before.

**P2. Resource caps on the sandbox (R3).** Before: the sandbox container had no memory or CPU limit (`docker inspect`:
`Memory=0 NanoCpus=0`), `/tmp` lived in the container's layer on the host disk and `/work`/`/engine-home` on the host
root filesystem, so a build or a filler could take the supervisor, Kira and the gateway down with it. Now
(`engine-run.sh`, `engine-prestart.sh`, `engine_install.py`, `aukora-engine-disk.mount`):
- CPU and memory: `openshell sandbox create --cpu <3/4 of the CPUs> --memory <RAM less 2.5 GiB>` (OpenShell 0.1.4 sets
  docker `NanoCpus`/`Memory` on the sandbox container; its pids cap of 2048 was already there). On a 2 vCPU / 8 GiB
  node: 1.5 CPUs and about 5.2 GiB for the engine; the host keeps half a CPU and 2.5 GiB (Kira's two model servers
  about 450 MiB, the gateway 150, the supervisor 50, docker 60).
- `/tmp` is a 1 GiB tmpfs inside that memory cap (`exec`: the harness's native addons load from it; docker refuses
  `nosuid` as an option and applies nosuid/nodev itself). OpenShell refuses any mount on `/sandbox` (its reserved
  workspace), which stays in the container layer: the engine does not use it, and it is the one writable path left on
  the host disk (Landlock limits writes to the policy's `read_write` list).
- Disk: `/var/lib/aukora-engine` (the workspace and the harness home) is its own ext4 image, fallocated (two fifths
  of the root filesystem, 8..40 GiB, and only with 8 GiB left free beside it), loop-mounted nosuid,nodev; an
  existing folder is copied in and kept beside it as `.pre-disk`. The pre-start refuses without it; the engine unit
  `RequiresMountsFor` it; `check-units.sh` checks it.
- `engine-run.sh verify` now also holds the running container to the caps (memory, CPUs, pids, the /tmp tmpfs) and
  refuses unless exactly one sandbox container exists (before, a sandbox that failed to provision could still pass
  the policy check).
NODE (rehearsal, 4 vCPU / 16 GiB, so 3 CPUs / 13.1 GiB for the engine; the branch's scripts through a drop-in and
the branch's `prepare_engine_disk`, 30 GiB image), one probe a second throughout of the shell origin through Caddy
(HTTP 200 and its time), Kira's socket and a fixed host CPU slice: idle worst 34 ms / slice 41 ms; a bash fork bomb
held at 2048/2048 pids, 30/30 probes fine, worst 16 ms / slice 85 ms; a node memory hog reached 12 GiB and was
OOM-killed alone (`CONSTRAINT_MEMCG`, the sandbox's own cgroup), host used memory unchanged, worst 33 ms; 16 CPU
spinners: worst 18 ms / slice 61 ms; `/work` filled to 30G 100% (`No space left on device`), `/tmp` stopped at
1.0 GiB, the host disk stayed at 15G used, worst 13 ms. The engine stayed `running` through all of it. Then T2's
usability half: 20 real no-dep Rust projects (`cargo build --offline && cargo test --offline && ./target/debug/pN`)
inside the capped sandbox 20/20, median 281 ms, against 214 ms as auma on the host: 1.31x (bar 1.5x; the wall test
had 293/228). `wall-check.sh`: `wall ok`.

**P4. Door-level taint (R2), sticky.** After any `net` result (or a memory read carrying a `web-derived` note), the
engine's next `net` calls and memory writes ask, whatever the slider and grants say, until the owner clears it at
`https://<shell>/engine/door`; a `web-derived` write always asks. Per session, not per turn (Argon RT-1..RT-3), and
since the door cannot tell sessions apart without trusting the engine, per engine: crates/supervisor/DOOR.md, "Taint".
NODE (from inside the wall with the approved door client, starter grants approved): a `web-derived` note asked
(`ask-memory`); the first page (docs.rs) ran and wrote `taint.json` (`cause: net`); the next page (crates.io) asked
(`ask-net`), a model-generated note asked, a memory read still ran, wikipedia.org was refused `host-not-allowed`
without a card. On `/engine/door` the owner saw "Tainted … (net)" and pressed the button ("Done. Clean: your grants
apply."; journal `door: the owner cleared the engine's taint`); a note and a page (github.com) then ran without a
card, and the page after that asked again. A cross-origin POST to the clear route from an engine-origin page changed
nothing.

**P3. Starter standing grants (R5, card fatigue).** Before: `"standing": {}` and no grants, so every `net` and
memory call (bar the two own-slot reads) was a card. Now the node proposes one critical card at the ceremony,
`door/standing-grants.json` (new in the inventory), holding the starter set from the door policy: `net` to docs.rs,
crates.io, static.crates.io, registry.npmjs.org, github.com (150 a day; the door's allowlist gains those hosts, so
`engine.py install` pins them in the egress like example.com, O10; the egress policy's provider rows, model provider
plus door hosts, may now number 16, not 4, in `core.py` and `config.rs` alike; a CDN that rotates its addresses past
the pinned ones ends `resolve-failed` until `engine.py egress` is run again); memory `read` (100 a day); memory writes to Auma's
own lanes `finding`, `evidence`, `experience` (30 a day). Seven days, renewed a day before the end: one card a week.
The door reads its grants only from the bytes that card applied. Cards on a building day: none for memory reads
and Auma's own model-generated notes, none for the first page; after the first page, one per further page and per
note until the owner clears the taint on `/engine/door` (P4); one for a web-derived note. Off-allowlist hosts are
refused, and unsupported plugin, schedule or terminal crossings return `no-executor` before any owner card.
A node installed before this branch lacks the target in its inventory: the proposal is refused
(`door: starter grants not proposed`) and everything asks, as before. NODE (re-run genesis on the branch's release,
`door/standing-grants.json` added to the kept inventory by hand, the door policy re-rendered from the new template,
egress epoch 4 with the five hosts): `door: starter grants proposed` right after the bind; the card came up beside
the release, budget and plugin-set cards ("For 7 days, no card for: pages from 5 hosts (150/day), memory reads
(100/day), her own notes (30/day)." and the exact grant bytes); after the passkey, a memory read, a model-generated
note and the first docs.rs page ran with no card (`autoclear.jsonl` counted them). `engine.py egress` from the Mac
hung in `nebius compute instance list` (the CLI's own call, before anything was sent): the same epoch was built with
`egress.build` and installed with the node's `node_release.py egress`.

**P5. Contradictions.** `fs-outside` is always denied, and now in code as well as words: the door refuses a policy
that says `ask` or `allow` for it, and DOOR.md no longer lists it among what `trusted` can clear (Peter's call to
change; it would need an executor). Section 6 said `"standing": {}` "turns on the starter slider", which with no
grants cleared nothing; section 9 said the door ran "asks, grants, refusals" on the node, when only asks and refusals
ran: both corrected. Section 9's "Not built" line about `door/standing-grants.json`, superseded by P3, was dropped
when the owner-lifecycle branch landed on top of this one.

**P6. `web_search` is not mounted.** It had no executor at the door, so it sat in Auma's catalog and failed every
call (`no-executor`). `build_plugins.py` now writes `search: false` into dsh-tool-web's row in every preset that
mounts it (standard, ptc, cordis; minimal mounts none) and stops on any other shape; `web_fetch` stays. NODE: the
bundle rebuilt from the node's pinned harness differs from the staged one by exactly those three lines; approved as
the new plugin set, the composition inside the wall (`dsh --profile aukora --patch authority.patch.yml --dump-config`)
shows `search: false` in all three presets' tool-web rows, `fetch: true` kept.

**O21 (open, the next big item; design note only, no code): the model call as a named crossing (Auma R1).**
Everything the engine can read (the workspace, recalled memory, every fetched page) can leave in the next prompt to
`api.deepseek.com`, up to 8 MiB a call, with no class, no card and no line anywhere but the broker's receipt (which
holds the request's SHA-256 and size, not what was in it). The door guards every other exit; this one is guarded only
by cost. Proposed shape, smallest first:
1. **Name it.** A `model` class in the receipts and on the Aura health surface: per call the prompt bytes and the
   bytes new since the session's previous call (a model turn resends its history; the delta is what newly left), and
   per day "N calls, X MiB to <provider>". Naming changes behaviour; a card per turn would not.
2. **Budget the bytes, not only the money.** The owner-approved budget (`engine/model-budget.json`) gains
   `max_new_bytes_per_call` and `max_bytes_per_day`; past either the broker refuses (402-style, `QUOTA`) and raises
   one card ("Auma wants to send 1.4 MiB of new context to DeepSeek"), approved per call like a door ask.
3. **Canaries.** The owner can mark strings (a `.env` value, a key prefix, a Kira note id) the broker refuses to
   send, scanned like the EchoGuard scans replies (decoded, every window), so a marked secret cannot leave by prompt.
4. **Taint-aware.** After the door's taint is set (P4) a prompt carries untrusted content by definition; the broker
   could lower `max_new_bytes_per_call` while tainted, which bounds what an injected page can make Auma paste.
5. **A second provider** (Prime Intellect) is a second socket, budget, key card and byte budget, never a header on
   this one (Auma's review section 4).
Not decided: whether the delta is measured by the broker (it would have to keep the previous request per session,
which the engine names) or the cheaper per-call total only; and what the health line says when the cost is unknown.

**P2, found live after it landed.** Two holes in the disk bound, both closed in the P2 commit:
- `/sandbox`: OpenShell refuses a mount there, the engine can write it (uid 994, Landlock allows the workdir), and it
  is the container's layer on the host disk. First answered by a host-disk floor (15% of the root filesystem, at
  least 8 GiB): `engine-run.sh create` refuses to start below it, and `aukora-engine-diskguard.service` (`engine-run.sh
  watch`, one quiet loop, a check every 5 s) stops a running engine; the stop removes the sandbox and its layer. That
  floor counted blocks only and cannot reserve anything against a fast writer (Codex review): the bound is now
  containerd's own disk, below ("P2c"), and the floor is the second line. NODE: a
  `dd` into `/sandbox` from inside the wall (about 43 MB/s on this disk) took the host from 31 to 11 GB free; at the
  floor the guard said `the host disk is below its floor; stopping the engine`, the stop took 56 s (docker removing a
  20 GB layer), the disk was back at 31 GB free, and the supervisor's controller started the engine again
  (`engine: running` 4 s after the unit came up). (That run's probe log was lost with its SSH session; an earlier
  run of the same filler, stopped at 18 GB free, had the shell's worst answer at 17 ms.)
- The image was not reserved: `mkfs.ext4` discards a device by default, which on a loop file punches holes, so the
  30 GiB image held 250 MB and the host's free space was overstated by 30 GB. `mkfs.ext4 -E nodiscard`, a second
  `fallocate` after it, and the installer refuses an image whose blocks are not all held (`engine-disk-not-reserved`).
  On the node the image was re-allocated in place (`fallocate`, data kept): `du` 31G.

**Tests.** Mac: `scripts/check.sh` CONSTRUCTION GREEN (once, at 791de25's code). Linux, on the rehearsal node,
umask 002, at 791de25: `cargo test -p supervisor -p frontdoor -p laya -p broker -p gate -p floor` (sovereign 187 + 1
ignored, frontdoor 5, laya 44, broker 13, gate 17, floor 7) and `tests/deploy` (11): all pass. The two later changes
(the guard, nodiscard) are shell and installer only: `sh -n`, the deploy unit tests, and the live run above.

**P2c. containerd's root is its own disk (Codex review of node/pre-launch, HIGH).** Docker 29 here runs the containerd
image store (`docker info`: driver `overlayfs`, `io.containerd.snapshotter.v1`): the images and every container's
writable layer, the sandbox's `/sandbox` included, live in `/var/lib/containerd`. The guard above watched blocks only,
so empty files in `/sandbox` could exhaust the host's inodes (ext4) while bytes stayed above the floor, and the
supervisor, the gate and the owner services would then fail with ENOSPC. Now `/var/lib/containerd` is a fixed-size
ext4 image with its own inode table (`aukora-containerd-disk.mount`, a tenth of the root filesystem, 6..12 GiB,
fallocated without discard; `containerd.service` `RequiresMountsFor` it; the installer moves existing content in with
docker and containerd stopped), the pre-start refuses without it, `check-units.sh` checks it, and the guard's floor
gains inodes (10% of the root filesystem's, at least 100,000) as its second line. NODE (7 GiB image, 458,752 inodes,
the three images in it): from inside the wall, a node loop of empty files in `/sandbox` stopped `ENOSPC` after
421,836 files with containerd's filesystem at 0 inodes free, while the host's root filesystem kept 10,057,942 free
inodes (unchanged), a file could still be made in `/var/lib/aukora`, the shell's worst answer was 14 ms and the engine,
Kira and the supervisor stayed active; a `dd` into `/sandbox` stopped at containerd's 5.2 GB with the host's free
space unchanged (24,132 MB). Both fillers removed, the filesystem was back where it began.

**P1b. The policy on the paths P1 missed (Codex review of node/pre-launch, LOW).** The WebSocket `101` was built fresh,
without `harden()`, and what Caddy answers itself on the engine host (the `?token=` 404, the http-to-https redirect, an
upstream error) carried no `Permissions-Policy`. Neither made a document an engine page could script, but they made
"every engine-origin reply" untrue. Now the 101 is hardened before its upgrade headers (unit test), and the Caddy block
(`engine_install.ENGINE_BLOCK`) sets the same value (`ENGINE_PERMISSIONS`, a test holds it equal to the proxy's) on the
https site deferred, so it replaces the proxy's copy instead of doubling it, in `handle_errors`, and on the http site.
NODE (the block re-rendered on the rehearsal node, keeping its rehearsal-only `tls internal` line): `?token=x` 404,
`/` 401 and a bogus ticket 403 each carry exactly one `Permissions-Policy`; with the supervisor stopped, Caddy's own
502 carries it; `http://…/?token=x` 404 carries it. The 101 path is covered by the unit test, not yet by a running
release (the node's binary predates it). A node installed before this branch keeps its old block (the installer
writes the block once); re-render it by hand as above.
