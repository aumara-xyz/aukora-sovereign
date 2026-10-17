# The real node: everything on one Nebius VM

One VM runs the Rust authority (Ring 3), Kira 2, and the DeepSeek Harness 0.2.1-alpha.5 inside OpenShell (Ring 1),
with the door as the engine's only way out. This file is the design and the runbook. NORTH-STAR.md Part 1 is the plan;
the wall is the one that passed the wall test (`~/aukora-memory/review/WALL-TEST-2026-10-17.md`, OpenShell 0.1.4,
enforce, docker compute driver).

Marks: **RAN** = executed for this branch (on the Mac unless stated); **LINUX** = runs only on the node, not run yet;
**GUESS** = not verified against the real tool.

## 1. What runs where

| Process | User | Listens / holds | Reaches |
|---|---|---|---|
| Caddy | caddy | :443 for `<shell>`, `owner.<shell>`, `engine.<shell>` | 127.0.0.1:18080 (frontdoor), 127.0.0.1:18081 (engine origin) |
| `sovereign serve` (supervisor, gate, AUMLOK, Aura, frontdoor, broker, **door**, **engine controller**, **engine origin**, **model broker**) | aukora | 18080, 18081, `/run/aukora-door/door.sock`, `/run/aukora-broker/broker.sock` | Kira socket (group kira-clients), engine web socket, `systemctl start/stop aukora-engine.service` (polkit, that unit only) |
| `sovereign kira serve` | kira | `/run/aukora-kira/kira.sock` (0660, dir 2750 kira:kira-clients) | llama servers on 127.0.0.1:8771/8772 |
| llama-server ×2 (embed, rerank) | kira | 127.0.0.1:8771, :8772 (nft: only uid kira may connect) | nothing (IPAddressDeny=any) |
| openshell-gateway | root (hardened unit; only CAP_NET_BIND_SERVICE) | 127.0.0.1:690 (privileged: no other user can bind it; the fence lets only root connect) | docker |
| the engine: `node entry.mjs` → `dsh --profile aukora` | **auma** (uid ≠ root, aukora, kira), inside the sandbox | 127.0.0.1:3080 and :3081 (model bridge) *inside* the sandbox; `/run/aukora-engine-io/web.sock` (bridge) | the door socket and the broker socket; nothing else (no network, no resolver) |

Keys: the owner's passkey stays on the owner's device; the node's signing keys, Aura, the gate, the claim digest and the
Kira agent keys are in Ring 3 state (`/var/lib/aukora`, `/var/lib/aukora-kira`), never mounted into the sandbox. The
engine holds no Kira token (the door holds the non-owner one), no model key (the broker holds it, section 7) and no
owner session.

## 2. When the engine runs (the supervisor decides, outside the wall)

`crates/supervisor/src/engine/control.rs`, every 5 s, in this order (each is a stop reason in the journal):

1. `awaiting-owner-binding`: the node has no owner yet (claim + passkey not done).
2. `awaiting-release-approval`: the installed release is not the one the owner approved (the release floor).
3. `door-not-configured`: no `/etc/aukora/door-policy-v1.json`.
4. `awaiting-plugin-set-approval`: the owner has approved no plugin set. The controller raises one critical proposal for
   `engine/plugin-set.json` holding every staged package by name and fingerprint, the door marked `authority`. One card.
5. `authority-plugin-changed`: the door package on disk is not the approved bytes. The engine stops, and the changed
   door is still proposed (it keeps `authority: true`), so the owner sees it instead of a silent outage.
6. `running`: the controller writes the approved set and `admission.json` to `/run/aukora-engine-ctl` and runs
   `systemctl start aukora-engine.service`. A newly approved set restarts it. Losing any condition stops it.

New or changed non-authority packages never load (the closure copies only approved bytes); they become one proposal
(the approved set plus all of them). A refused proposal is raised again only after 10 minutes or when the bytes change.
Hot reload and creator mode are never loaded and never approvable (`floor::plugins::is_hot_reload`).

## 3. The plugin fingerprint gate, end to end

- **Staged**: `/opt/aukora-engine/plugins/<folder>` (root-owned) from `engine-plugins.tar` (`build_plugins.py`,
  byte-reproducible: two builds gave the same SHA-256, RAN). Twelve packages: `@aukora/door`, the nine faces
  (`@aukora/face-<name>`), `@aukora/dsh-plugin-foundation`, `@aukora/face-bundle` (the composition patch).
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
  appends `{set_hash, gate_sha256}` to `/var/lib/aukora/floor/engine-plugin-set.jsonl`. Storing the pin *inside* the signed
  floor (`floor::state::ProtectedState`) needs a floor schema change and an Aura migration: open item O5.

## 4. The wall (Ring 1)

The OpenShell policy is the wall test's, verbatim (`openshell-policy.yaml`), plus four NODE lines, each marked there:
`/engine-home` (the harness home), `/run/aukora-engine-io` (bridge socket + launch line), `/run/aukora-broker` (the
model broker socket, section 7) and the resolver posture.
`run_as_user` is the engine user's uid; `network_policies: {}`; Landlock `hard_requirement`.

Mounts (`engine-run.sh`): `/opt/aukora-engine` → `/engine` ro (node, pinned harness, in-wall scripts);
`/opt/rust` ro; `/var/lib/aukora-engine/work` → `/work` rw; `/var/lib/aukora-engine/home` → `/engine-home` rw;
`/run/aukora-door` rw (folder 0711 aukora, so not engine-writable); `/run/aukora-broker` rw (the same); `/run/aukora-engine/io` (1 MiB tmpfs) rw;
`/etc/aukora/engine/resolv.conf` → `/etc/resolv.conf` ro. Never: `/etc/aukora`, `/var/lib/aukora*`, the Kira socket,
the docker socket.

**The harness home.** The harness writes `.credentials.yaml`, `.anonymous-user-id`, `storages/`, `sessions/` at the top of
its home (RAN: observed on the Mac boot), so the home is writable. It is root-owned with the sticky bit (1770
root:auma): the engine can create its own files but cannot rename or delete root-owned entries, which are re-asserted by
`engine-prestart.sh` before every start: `profiles/` and `profiles/aukora/` (profile template + the closure),
`cordis.patch.yml` (`[]`), and an empty root-owned `node_modules/` guard so module resolution cannot walk up into
an engine-made package. `@deepseek-ai` resolves through one root-made link in the closure to the pinned install.
The authority overlay (`authority.patch.yml`) is passed with `--patch`, after every layer the engine can write: it
mounts the door with the node's values and disables `hmr`, `client-hmr`, the plugin manager (three rows), the web
terminal (two rows), desktop telemetry, open-in-app (two rows) and the harness-dev context. RAN: `dsh --dump-config`
composes with every row in place, and `dsh web` boots the composition (all twelve packages from the closure).

**DNS posture (the wall test's one residual, B03).** Three layers: the sandbox's `/etc/resolv.conf` names 127.0.0.1
(nothing listens there); Docker's daemon resolver forwards only to 192.0.2.53 (`docker-daemon.json`); the host fence
(`aukora-engine-fence.nft`) drops 192.0.2.53 and any port 53/853 traffic from a container network. Names the engine
needs cross through the door, which resolves them itself. `wall-check.sh` proves it from inside the sandbox:
`getent hosts example.com`, node `dns.lookup`, `dns.resolve4`, a direct query to 127.0.0.11 and to 1.1.1.1 must all
fail (LINUX).

## 5. The front door and the engine origin

The harness's web UI is served on **`engine.<shell host>`**, not on the shell origin. Reason: everything the harness
serves is engine-controlled script. On the shell origin it would run with the owner's shell session (the Memory face's
Kira reads, the approvals list, the data bridge) and could frame and overlay the owner origin's ceremony (the
clickjack seam). A sibling origin gets none of that: host-only cookies stay on their hosts and the owner origin keeps
refusing every frame ancestor but the shell. This deviates from the brief ("the shell origin serves the DSH web UI");
see decision D1.

Flow: the owner, signed in on the shell, opens `https://<shell>/engine/open`. The host (`host/engine_routes.rs`)
checks the bound shell session against the ledger's binding and the release floor, mints a one-time ticket (60 s,
single use) and redirects to `https://engine.<shell>/.aukora/enter/<ticket>`. The engine origin
(`engine/proxy.rs`, listener 18081) redeems it for `__Host-aukora-engine` (12 h, `Secure; HttpOnly; SameSite=Strict`),
and on every request re-checks that scope against the ledger and the release floor. It forwards an allowlist of
headers (never the browser's cookies) plus the harness's own cookie, which it obtained by exchanging the launch
token the harness printed inside the wall; the browser never sees the token or that cookie. Replies lose every
`Set-Cookie` and CORS header and gain `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `no-referrer` (the
single-valued ones replace the harness's own, so it cannot cancel them). Caddy and the proxy both refuse a query that
names `token`; a path segment that decodes to `.`, `..`, a separator or another escape is refused. The ticket is spent
only by a top-level navigation (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`), and no service worker can be
installed on the engine origin (its script request, `Service-Worker: script`, is refused), so no engine page can watch
the owner's next navigation for a ticket. A clock that cannot be read refuses. WebSocket upgrades are not forwarded
(the terminal is off).
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
the engine). Models: llama.cpp b10621 CPU build, the two GGUF files pinned by SHA-256 (the Mac's own, from
`~/aukora-memory/kira/models/*.sha256`), each server started with `--alias <sha256>` so Kira refuses a swapped file.

The door: the in-node door (`sovereign serve` reads `door-policy-v1.json`), so `ask` becomes a real gate proposal. The
policy is the wall test's, verbatim, except: `memory` is `allow` with the Kira socket and token (the wall test had no
Kira), `socket` is set (in-node form), `state_dir` is under the supervisor's state, and `"standing": {}` turns on the
starter slider ("only risky things", pinned). `peers.uids` is the engine uid; workspace root `/work` matches the
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
- **Key** (`KeyInbox`, memory only). The owner types it at `https://<shell>/engine/model-key` (a self-contained page
  served by the supervisor, script and style pinned by hash in its CSP); `POST /api/engine/model-key` needs the bound
  owner's shell session (frontdoor: same origin, JSON). The broker holds the key and proposes
  `engine/model-key.json` = `{key_sha256, kind, provider, v}`: the card shows the digest only; the page shows its
  first 12 hex digits (the fingerprint) to compare. A call uses the key only while its SHA-256 equals the approved
  one. Re-entering the approved key after a restart activates it without a new card; entering a different key
  pauses the engine's calls until the owner approves it. The key is never in a file, the gate, Aura, a log or a reply.
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
  429 busy, 502/503 provider unreachable or receipts unavailable. A provider error passes its status and message only
  if the message carries nothing of the key.

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

Operator machine unless marked. Nothing here was run against a host.

**A. Artifacts (once per pin set).** On the rehearsal VM that ran the wall test:
1. `npm install --save-exact --ignore-scripts @deepseek-ai/dsh@0.2.1-alpha.5` with node 24.11.1 in an empty folder;
   `tar --sort=name --owner=0 --group=0 --mtime=@0 -czf dsh-engine-0.2.1-alpha.5-linux-x64.tar.gz package.json package-lock.json node_modules`.
2. Tar the OpenShell 0.1.4 `openshell` and `openshell-gateway` binaries → `openshell-0.1.4-linux-x64.tar.gz`; `docker save`
   the sandbox image the wall test used → `openshell-sandbox-image.tar`; tar `/opt/rust` → `rust-1.99.1-x86_64-unknown-linux-gnu.tar.gz`.
3. Copy the exact `openshell sandbox create …` and `openshell-gateway …` command lines from that VM's shell history into
   `engine-run.sh` `create()` and `aukora-openshell-gateway.service` (both GUESS today; keep the mounts and the policy path).
4. Download node-v24.11.1-linux-x64.tar.xz and llama-b10621-bin-ubuntu-x64.zip; `python3 -B deploy/engine/engine.py pin FILE`
   for every artifact; fill every `sha256` in `engine-pins.json`. The installer refuses while any is null.

**B. Plugins.** Build the face (`engine/plugins/aukora-face/build-face.py --dsh <disposable DSH checkout at dsh-v0.2.1-alpha.5>`),
then `python3 -B -I deploy/engine/build_plugins.py --dsh <DSH install> --faces engine/plugins/aukora-face --node <node 24.11.1> --out OUT --tar STAGE/engine-plugins.tar`.
`sovereign engine fingerprint --from OUT` prints the set the owner will approve; keep it for step D6.

**C. Release and node.**
1. Commit (pins, plugins are not in git), `scripts/reproduce.sh build COMMIT OUT --twice`.
2. `deploy/spawn/spawn.sh create NAME --on nebius-vm --release OUT --public-ip … --spend-ok --claim-out CLAIM` with
   `AUKORA_VM_HOURLY_ESTIMATE` set. The VM needs **≥4 vCPU, ≥16 GiB, ≥80 GiB disk** (two 0.6 GB models resident, docker,
   the harness, builds): `vm.py` picks the smallest preset with 2 vCPU/8 GiB and a 40 GiB disk today. Open item O1.
3. Put the artifacts from A in `STAGE/` beside `engine-plugins.tar`;
   `python3 -B deploy/engine/engine.py install NAME --stage STAGE --dry-run`, then without `--dry-run`. It prints the
   engine host. On the node it enables the fences, docker, the gateway, the model servers, Kira, extends Caddy with the
   engine host and restarts the supervisor. The engine does not start.
4. On the node, as root: `deploy/units/check-units.sh`; `systemctl status aukora-kira aukora-openshell-gateway`;
   `journalctl -u aukora-sovereign | grep engine:` shows `awaiting-owner-binding`.

**D. The ceremony (the owner, with the passkey device).**
1. Open the claim link from `CLAIM` (`https://<shell>/#claim=…`); the operator then deletes the file.
2. Bind: create the passkey on the owner origin, as today.
3. Approve the release: the release card on the owner origin. Journal: `engine: door-not-configured` must NOT appear;
   `engine: awaiting-plugin-set-approval` appears.
4. Approve the plugin set: a critical card for `engine/plugin-set.json`. Compare its bytes with B's fingerprint output
   (twelve names, the door `authority: true`). Passkey.
5. Journal: `engine: running`. `systemctl status aukora-engine` active; on the node `deploy/engine/wall-check.sh`
   must print `wall ok` (DNS probes included).
6. Open `https://<shell>/engine/open` in the signed-in browser: the Spatial face loads on `engine.<shell>`.
7. The model key and budget (section 7): open `https://<shell>/engine/model-key` in the signed-in browser and type
   **your own** DeepSeek key (nobody else enters, prints or stores it; it is never written to a file). The page
   shows a fingerprint (12 hex digits). On the approvals, two critical cards: `engine/model-key.json` (its
   `key_sha256` must begin with that fingerprint) and `engine/model-budget.json` (the terms from
   `model-broker-v1.json`). Passkey both. Journal: `model-broker: call … completed …` on Auma's first turn; a call
   before both approvals is refused in the engine's chat with the reason. After any supervisor restart the key is
   gone (memory only): enter the same key again; it activates without a new card.
8. Crossings: ask Auma for a `web_fetch` of an allowlisted host: a door ask card appears on the owner origin (the
   starter slider asks for `net` without a grant); approve; the repeated call runs. `kira_remember` / `kira_recall` go through
   the door with the non-owner token (`kira_quarantine_source` is refused).
9. Negative checks: change one byte in `/opt/aukora-engine/plugins/aukora-door/lib/index.js` → within 5 s the engine
   stops (`authority-plugin-changed`) and a new card appears; restore the byte (or approve, deliberately not) → it
   starts again. Revoke the owner session or re-bind → `https://engine.<shell>` answers 403 at once.

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

LINUX (written, not run): the model broker's socket, peer check and in-wall bridge, `engine_install.py`, `engine.py install`, `engine-prestart.sh`, `engine-run.sh`,
`wall-check.sh`, all units, the polkit rule, tmpfiles, the nft fence, `systemctl` from the supervisor, the sticky-home
protections, the Kira units, Caddy's engine block.

GUESS: the `openshell sandbox create` mount/policy/image flags, the gateway's `--config` flag and `listen` key,
`openshell policy get` output shape in `verify`, the JWT key type (ed25519), the llama.cpp release asset name, the model
download URLs (the SHA-256 pins are what count), and that disabling the listed harness rows leaves the rest booting
on Linux as it did on the Mac.

Not built: the face's own owner-approval surfaces pointing at the owner origin;
`door/standing-grants.json` as a gate target (the slider runs on the starter, no grants); an inventory sync for nodes
installed before this branch (they refuse `engine-install: inventory-lacks-engine-target`); WebSocket forwarding.

## 10. Open items

- **O1** VM size: `vm.py` `smallest_preset` and `BOOT_DISK_GIB = "40"` are pinned deploy code; the engine node needs a
  larger preset and disk (an `AUKORA_NEBIUS_PRESET` override, reviewed).
- **O2** The exact OpenShell argv (runbook A3), and how the 0.1.4 CLI is pointed at the gateway's endpoint
  (127.0.0.1:690 since the Grok review; the wall test used another port) and verifies it: until the CLI
  authenticates the gateway itself, the privileged port and the fence are what keep an impostor out.
- **O3** Gateway auth: the wall test ran `allow_unauthenticated_users=true` on a dev gateway; this config sets false. If
  0.1.4 cannot authenticate the local CLI otherwise, choose before the first public node (loopback-only either way).
- **O4** `deploy/engine/*` is in the release (so the owner's release approval covers it) but not in `checks/run.py`'s
  `DEPLOY_PINS`; pin `engine_install.py` and `engine.py` once reviewed.
- **O5** The plugin-set pin in `ProtectedState` (floor schema change + Aura migration) instead of the audit file.
- **O6** Re-run `cargo test -p supervisor door` and `cargo test -p broker engine_link` on the node (the SO_PEERCRED
  path is Linux-only), as the wall test asked.
- **O7** The model key is memory only (the `KeyInbox`; disk persistence was reserved for later): every supervisor
  restart needs the owner to enter it again. Persisting it (a 0600 file in the broker's state, as the archive's
  keystore did) is Peter's call.
- **O8** The budget's prices in `engine_install.py` (`MODEL_BUDGET`) are placeholders above DeepSeek's published
  prices, and the model names are the harness's catalog (`deepseek-flash`, `deepseek-v4-pro`), not checked against
  the live API. Set both before the first node; the owner approves whatever terms the file holds.
