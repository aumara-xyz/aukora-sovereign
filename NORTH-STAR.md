# AUKORA Sovereign: North Star

**This is the only plan.** There is no other plan file in this repository, and `checks/` makes main red if one
appears. Every row below is one GitHub issue with the same number: row 12 is issue #12. The issues are the work
tracker. A row leaves this plan only when Peter says so, and his words are written on its issue.

It carries forward:
- Peter's Prime North Star;
- the master plan he approved on 2026-10-14 (frozen in `spec/`);
- every issue of aukora-prime and aukora-sovereign-archive;
- every Prime plugin and package, and Prime's ideas ledger;
- the NEBIUS session's two specs of 2026-10-15: Pentora at the foundation, and the rebuild guidance. They are frozen
  in `spec/` and adopted wherever Peter's direction allows.

Nothing is dropped.

## One sentence
Your own AI home base on a server you control. One link opens the Spatial app, where a personal AI organism lives,
remembers, grows and even changes itself. It can never act past the boundary without its owner's approval, and it
leaves a receipt anyone can check.

## The everything app
AUKORA is a membrane for anything its owner needs next.
- Need a website? Ask, approve, and it is live at your node's address.
- Need a tool? Install it from the AUKORA app store with one approval.

Every new capability arrives the same way: as a plugin through the gate, inside the same walls. Nothing ever widens
the cage.

## How it is built (Peter, 2026-10-15)
- **Fresh, every line.** The archive and Prime are the cheat sheet. A worker reads what worked, understands how it
  fits the whole organism, and writes it new. Nothing is copied. The archive is aumara-xyz/aukora-sovereign-archive,
  repository ID 1418448527.
- **Only data comes over as it is**, pinned by hash:
  - the AUMLOK word lists;
  - the 101-byte WASM cell;
  - the Pentora geometry table;
  - the antibody registry and the attack corpora;
  - the format vectors: canon, Aura export, WebAuthn, and the verifier's regressions;
  - the design: theme tokens, fonts, icons, copy, and screenshots of every face from Peter's running app.
- **Code goes to main, and main is tested after it lands.** It is installed on a fresh node and then attacked by every
  major AI. Nothing goes public until it survives that. Workers write no test suites.
- **A node runs only what Peter signed.** Main may be red at any moment, and that never reaches a node.
  - Spawn refuses any node already listed in `deploy/EXISTING-NODES`. S1 is pinned there from the first commit.
  - An existing node upgrades only to a commit named in a release pointer Peter signs with his passkey.
  - No worker ever writes that pointer.
- **References are pinned by repository ID and commit**, never by name or folder. This repository is ID 1420432858.

## One system: the phone is AUKORA Light, the desktop is the node (Peter, 2026-10-16)

"The phone system should only be messaging and an AI assistant eventually. If you want to build and do all the
other stuff, then you need to be on your Sovereign node on your desktop." The two are one system, not two apps.
- **Phone: AUKORA Light** (aumara-xyz/aukora-light), his installed PWA: messaging, and later Auma as his assistant.
  Its lane-corner navigation is the phone format.
- **Desktop: the Sovereign node.** Building, approvals, apps and everything else. Its shell is Peter's Spatial app
  (row 1, build 3673b98), the design source for both: Light's phone format is derived from it, never the reverse.
- **One person.** One root, one person-nostr key, on both. Peter's own node is bound to the identity he already
  has in Light ("bind with my existing words"), never to a fresh root. Test nodes stay throwaway.
- **They talk.** The phone reaches the node through Light's members-only relay with NIP-17 wraps; the node dials
  out, so no open ports. Whether the phone may approve node changes with a person-nostr signature, and for which
  risk levels, is Peter's decision (an authority question under the Golden Boundary).
- Only data crosses between the repos unless Peter says yes.

## What Peter watches, in order (only Peter says "done")
1. **M1, his fresh node.** One link opens the Spatial app, rewritten whole, in its tri-pane. He claims the node with
   his passkey and phrase. The release approval pops up inside the app.
2. **M2, Auma answers with a real model.** The receipt sits inside his spend grant, and the cage holds: she cannot
   read the server.
3. **M3, she proposes a change to herself** (the theme).
   - Laya, following his slider, decides that it pops up.
   - He approves the exact bytes with his passkey (Touch ID).
   - The change runs through the WASM core and applies once, live.
   - The same request without approval does nothing.
4. **M4, she remembers after a real reboot**, recalled by meaning. Spent approvals stay spent across a reboot of the
   same disk. A cloned disk stays unsolved until Peter chooses the clone rule (decision 4); nothing claims otherwise.
5. **M5, a stranger verifies everything** from an empty folder. Aura Coherence shows the node's health map: 110 real
   checks, with every organ watched by every other. It sits beside the fingerprint, on two labelled canvases.
6. **M6, two nodes talk.** His node and a second node exchange messages over public Nostr relays, in Messages. Neither
   machine runs a relay itself.
7. **M7, Go Sovereign.** He invites a friend.
   - The code unlocks a fresh node with one click.
   - The co-presence ceremony runs, then the passkey and phrase.
   - The friend is inside their own Spatial app.
8. **M8, home base.** He asks Auma for a website and approves it, and it is live on its own address under his node.
   He installs an app from the AUKORA app store's catalog with one approval, and it opens in the tri-pane. The app
   comes from the catalog; it is not shipped in the release.

Each milestone also passes its hostile twin on the installed node (spec v0.2 section 8), after it lands. The twin is
run by a reviewer who did not write the feature, and its evidence is the issue line:
- with no approval, nothing happens;
- a forged receipt fails;
- the other node's cookies fail;
- a truncated export fails verification.

## The shape: one organism, five organs
The Pentora is the foundation, not a picture added at the end (`spec/PENTORA-FOUNDATION.md`). Its geometry has one
exact property:
- there are five groups, and every two groups share exactly two members;
- no member serves more than two groups;
- each group also has private members.

That is the shape a system of mutual cross-checks needs, so AUKORA uses it three times:
- **Level 1, how the node checks itself.**
  - The five cubes are the five organs.
  - Each organ has 18 private cells, which are its own invariant checks.
  - Each pair of organs shares 2 corner cells (20 in all): cross-organ invariants that both organs confirm
    independently.
  - Every cell is ternary: + verified, 0 undetermined (not yet checked, unreachable, or stale), − failed.
  - A corner is + only when both organs confirm the same context. A disagreement is −, and the fault is localised to
    that pair.
  - An unwritten check counts as failed (−), never as undetermined, and it shows.
- **Level 2, how the owner's network protects them.**
  - There are five circles of people and devices, and each corner holder sits in two circles.
  - Backups repair inside a circle.
  - Any two circles' quorums meet in exactly two holders.
  - A liar fails the checks of both its circles.
- **Level 3, what people see.** The fingerprint (`pentora.display.v1`, derived from a hash), the health map (derived
  from state) and the relationship bloom. They are always labelled apart.
- **Never:** authority, human-compared security, compression or encryption. A cell may refuse, escalate or inform; it
  never grants.
- **Two types, never mixed.**
  - A health cell is a different type from a fingerprint trit.
  - `pentora.display.v1` is the only fingerprint function, and it takes a hash only. The health function takes organ
    state only. They draw on two labelled canvases.
  - Nothing in the path of an effect (the gate, the frontdoor, the launcher) reads either of them.
  - Quarantine is a passkey action.

**The twenty corners** (a draft; the wave-0 architects freeze these, the 90 private checks, and every check's owner,
source and freshness limit):

| Organ pair | Corner 1 | Corner 2 |
|---|---|---|
| AUMLOK × Gate & Aura | The owner credential epoch in AUMLOK equals the epoch Aura recorded | Every passkey AUMLOK accepts has its enrolment in Aura |
| AUMLOK × Kira | Kira's key is wrapped under AUMLOK's current root epoch | Every Kira permission change carries an owner signature AUMLOK verifies |
| AUMLOK × Network | The node and agent Nostr keys are the ones AUMLOK delegated | Every approved contact and paired device carries an approval AUMLOK verifies |
| AUMLOK × Body | The frontdoor's relying party and accepted top origin equal AUMLOK's enrolment | The frontdoor's unlock limits match AUMLOK's per-principal counters |
| Gate & Aura × Kira | Kira's verified head is anchored in Aura | Kira's demotion and quarantine counts agree with Aura |
| Gate & Aura × Network | The latest head witness on the relays equals the local head | Every contact and send has its consumed card in Aura |
| Gate & Aura × Body | The running binary's digest equals the approved release | The antibody corpus root equals the release fact |
| Kira × Network | The memory backup's commitment on the relays equals Kira's head (0 until backups exist) | Every memory disclosed in a message has a Kira permission |
| Kira × Body | The OpenViking index pin matches Kira's head | The guest's memory calls on FD 3 match Kira's recall receipts |
| Network × Body | The host's egress allowlist equals the relay set Network uses | The node's address and TLS identity match what Network publishes |

The five organs, and where each lives:
1. **AUMLOK, identity and keys** (`crates/aumlok`).
   - The acrostic seven-word phrase (ROOT, UNITE, RISE) seals a random root key.
   - A passkey (Touch ID) signs every approval.
   - The key hierarchy, with each binding recorded in Aura with an epoch.
2. **Gate and Aura, authority and the record** (`crates/canon`, `gate`, `laya`, `aura`, `floor`, `verifier`).
   - Exact bytes are shown, approved by passkey, applied once and never replayed.
   - Laya and the slider decide what pops up; they never approve.
   - One signed, append-only record, witnessed by the owner's browser and on relays.
   - No rollback.
   - A stranger verifies everything from an empty folder.
3. **Kira, memory** (`crates/kira`). Encrypted memory with cited recall, ranked by OpenViking inside the node.
   Forgetting demotes; nothing is silently deleted.
4. **Network** (`crates/nostr`, `relay`, `messaging`, `invites`, `copresence`, `portal/`).
   - The node and agent identities, the relays, and owner-approved contacts.
   - Invites: one-time, valid 48 hours, three per member, with conserved allowances.
   - **Co-presence.** Two screens face each other. Each shows a signed QR code that rotates every second, and each
     camera reads the other screen: face, seen you, handshake, bloom. Then the same Pentora blooms on both.
   - Later: guardians, watchtowers, self-healing backups, and bitchat's Bluetooth mesh. Their foundations go in now.

   A message is never authority. Receipts and relationships are private by default.
5. **Body** (`crates/supervisor`, `launcher`, `frontdoor`, `wasmcell`, `broker`, `immune`, `pentora`; `guest/`;
   `deploy/`).
   - The one trusted supervisor, the cage, the one link and the WASM core.
   - The broker: the model key is held outside the model, and spending is limited by a passkey-signed grant.
   - The immune system: every known attack is an antibody, and the MHC loop computes the Level 1 map.
   - Our own harness, spawn, and Go Sovereign.

## The Spatial app is the organism
- **One core, our own, in Cordis's paradigm.** Cordis is the plugin engine under the DeepSeek harness. In that
  paradigm:
  - everything is a plugin;
  - each plugin names the services it needs and starts only when they exist;
  - when a plugin goes away, it takes everything it made with it.

  Every organ is a service, and every face is a plugin on its organ.
  - The browser services are RPC facades over the node's organs, filtered by capability. Authority and keys stay in
    the organs on the server.
  - Each plugin declares its id, what it requires, its menu entry and its surface.
- **AUKORA APPS:** Auma Lingwa, Auma Live, Zeta Harp, Human Graph, Media, Memory (on Kira), Messages (on Network),
  Documents.
- **SYSTEM:** AUMLOK and Identity (on AUMLOK), Aura Coherence (the health map and the fingerprint), General, Models
  (on the broker), Plugins (the app store), Agent presets, Archived sessions.
- **Our own harness replaces the DeepSeek harness**, the way the cage replaced OpenShell.
  - The DeepSeek harness is about 380,000 lines of its own TypeScript, without tests, in 316 packages. It includes
    shell, file, subprocess and terminal tools: exactly what the cage takes away.
  - Ours is Auma's agent loop inside the cage. Her only operations are chat, threads, sessions, streaming replies,
    presets, compaction, proposals and memory.
  - She never executes a command or opens a socket. Seccomp denies `execve` and `execveat`, and model calls leave only
    through FD 3 to the broker.
  - **Two modes.** In Chat she talks. In Build she may also propose changes, to herself, to sites or to apps.
    Neither mode runs anything.
  - **The Laya slider** sits in the right lane, by the apps. It sets how strict approvals are: ask for everything,
    only for risky things, or within today's limits. Risky changes always ask.
  - It is one static Rust binary, so the cage needs no JavaScript engine. A rough budget is 5,000 to 10,000 fresh
    lines (Codex's estimate).
- **The tri-pane.**
  - There are three lanes, weighted 0, 1, 2 or 3 and always summing to 3. Each visible lane is one third, two thirds
    or the whole frame: the ten compositions.
  - A hidden lane keeps its state.
  - When one lane takes the whole frame, its content keeps a two-thirds measure, centred, with no full-bleed
    exception.
  - It adapts to every screen. On a phone, one lane shows at a time, full width. This rule is new: Prime has no
    narrow-screen rule.
  - Cheat sheet: Prime's layout face (`AppFrame`, `PANE_WEIGHTS`).
- **The walls stay walls inside the organism.** Three hosts, and code only from approved releases.
  1. **The one link** serves only a static shell from the approved release.
     - Its policy is `script-src 'self'`, with no inline script and no `eval`.
     - The shell holds the organism core.
     - Every face, stock or installed, is a plugin in its own sandboxed frame with an opaque origin. Faces are fed
       data over the core's RPC, and no face is ever a parent of a ceremony.
  2. **The owner origin** is a second host, framed only by the shell.
     - WebAuthn accepts the cross-origin ceremony only when `topOrigin` is exactly the shell.
     - It loads the bytes to sign from the supervisor by proposal id, never from the shell.
     - The phrase is entered and derived only here.
  3. **A site** is a third host, with no cookies, no WebAuthn and `frame-ancestors 'none'`.
  - **Auma sends the browser data, never code.**
    - FD 4 carries only bounded, validated command and event data: no guest HTML, executable assets, redirects or
      arbitrary headers.
    - Anything Auma builds stays inert until its exact bundle is approved and published on its own host.
  - **A user app** runs in its own cage: no network, no exec, no WASI. It never runs in the WASM cell, which stays the
    only proposal relay.
    - Its grants come from a closed list. The passkey, the gate, the broker, appending to Aura and the network are
      never grantable.
    - One approval cannot extend the list.

## The constitution (from the NEBIUS rebuild guidance)
Main must hold these, and is tested against them after it lands.
1. The owner root is never under anyone else's control: not guardians, the agent, a relay or a score.
2. Every authority-bearing state has an epoch and a rollback guard. That covers owner credentials, the guardian set,
   the device list, allowances, recovery requests, standing rules and the release floor.
3. Evidence never becomes authority.
   - Scores, Laya, the thymus, pictures, guardian signatures, relay agreement and model confidence may refuse,
     escalate or inform.
   - Only the owner's passkey, or a bounded policy the owner pre-signed (the slider), authorizes.
4. Fixed check floors never shrink. Adaptive layers only add checks, and a separate process hunts blind spots.
5. Budgets are conserved, not scored. Admission, invites and resources cannot be multiplied by making identities.
6. The antibody ratchet adds fresh held-out cases every release.
7. "Approved" is kept apart from "still wanted", and "published" from "delivered". A relay's silence is never consent.
8. Nothing in the inventory disappears without Peter's dated disposition.
9. Acceptance follows the whole chain on the running node: source, build, package, served assets and routes,
   signed-in browser, meaningful behaviour. A file, an HTTP 200 or a screenshot of an empty shell is not acceptance.

## Both ways: safe from her, and safe from everyone else's
**Built for stronger models.** The walls never depend on the model being weak or well-behaved. Every model is treated
as the strongest possible adversary. A smarter model can propose better things, but it cannot talk its way past the
kernel, the passkey or the record.
- Any model, from a provider or run locally, plugs into the broker's slot. Its identity is in every receipt.
- A new model starts with no grants. Before it gets any, the immune system attacks the cage with that model driving
  (row 138).
- Her power grows only through grants Peter signs. They come from a closed list, carry an epoch, and are revocable in
  one tap.
- Running code happens in a disposable sub-cage. It is built now and stays off until Peter turns it on (row 39,
  decision 9).

**Built for stronger attackers outside.** The AI in the world will keep getting better at attacking people, so no wall
relies on an attacker missing something.
- **The guarantees are mathematical or enforced by the kernel**, not cleverness: signatures over exact bytes, the cage,
  and the append-only record.
- **Almost nothing is exposed.** There is one link and passkey-only sign-in, nothing else listens, and the agent has no
  network.
- **Keys live in hardware** (Touch ID), and the root stays sealed under the phrase.
- **Every format is crypto-agile**, so post-quantum signatures arrive without a format break (row 139).
- **The immune system learns every attack**, and herd immunity spreads it.
- **Before anything is public, every major AI attacks main.**

**A life raft against other people's agents.**
- **Nothing that comes in is an instruction.** Messages, documents, memories, apps and other agents' outputs reach
  Auma as data, with their provenance, marked as not the owner.
- **Strangers cannot reach her.** Only owner-approved contacts get through. Everyone else is refused before she sees
  anything, and every refusal is counted in Aura (row 135).
- **Even a fully hijacked Auma cannot act.** She has no network and can only propose exact bytes to the owner.
- **No AI can phish the keys.** Passkeys are bound to the node's own origin, there are no passwords, and the root key
  is sealed under the phrase.
- **One node's attack becomes everyone's antibody.** Nodes share signed antibodies over Nostr. An imported antibody
  can only add checks, never remove one (row 136).
- **The people you met are marked as met.** A contact paired screen to screen is marked "met in person"; a remote or
  relayed pairing is labelled as such (row 137). Evidence, never authority.

## How it fits (spec v0.2 sections 2 to 7, with these amendments)
The amendments:
- one link;
- our own Rust harness replaces the DeepSeek harness;
- canon and Pentora run as Rust compiled to WASM, with no JavaScript twins;
- `bridge/` is retired;
- FD 4 carries data only.
- **One trusted supervisor** process holds every authority. It is wiring only: it starts the organs and routes frames.
  Policy lives in the organ crates.
- **Auma runs our harness inside the cage.** FD 3 is her only channel for proposals, model calls and memory. FD 4
  carries the app's data.
- **The supervisor is the only reader of FD 3** (row 128). It routes proposals to the gate, model calls to the broker
  and memory calls to Kira. No other crate opens those sockets.
- **One authority change is one transaction.** Verifying the passkey, persisting its counter, consuming the approval
  and appending to Aura happen in one `BEGIN IMMEDIATE` transaction. Every authority record carries
  `(epoch, sequence, previous hash)`.
- **The contracts in `spec/CONTRACTS.md` (C1 to C7) are frozen.** Additions are versioned, unknown operations refuse,
  and wave 0 freezes them before any worker starts.
- **One link.** The app and its pop-ups share one address.
  - The pop-ups come from a separate owner origin that only ever appears framed inside the app, pinned by
    `frame-ancestors`.
  - The passkey ceremony checks `topOrigin`.
- **Languages** (PROPOSAL):
  - Rust on the server and in the cage.
  - TypeScript for the faces in the browser.
  - The browser runs canon and the Pentora derivation as the same Rust compiled to WASM. There is one derivation, so
    no JavaScript twins.
  - The browser's exports are `canonicalize(raw_utf8)` and `pentora_expand(root32)`. The same WASM is pinned on both
    browser origins. If it fails to load, the page fails closed, and there is no JavaScript fallback.
- **Builds** embed by relative path and content hash. There is one source tree per build folder, and the deployed
  binary is byte-compared with a pristine rebuild.

## The repository
```
README.md        how to open the node; milestone status; claim board; IDEAS
NORTH-STAR.md    this file, the only plan
spec/            frozen inputs: SPEC v0.2, CONTRACTS, CARRY-LIST, coverage audit, PENTORA-FOUNDATION, REBUILD-GUIDANCE
crates/          canon aura gate laya aumlok kira broker wasmcell floor immune verifier pentora
                 nostr relay messaging invites copresence launcher frontdoor supervisor
app/             the Spatial app: the organism core, the tri-pane, every face as a plugin, the design data
guest/           our harness: Auma's agent loop inside the cage
ui/owner/        the trusted pop-ups (passkey, phrase, approvals, AUMLOK), shown only framed inside the app; never a page
portal/          the co-presence Point-and-Bloom page
deploy/          spawn (LXD and Nebius VM), go-sovereign, upgrade, the install units
scripts/         check.sh, antibodies.py, reproduce.sh
immune/          the antibody registry (data)
tools/           verify.py, the stranger's verifier in Python
checks/          the machine rules (run.py, scaffold.json, baseline.json) and the inventory
tests/e2e/       one acceptance run per milestone, on the installed node
```
Each crate has a README of 10 lines or fewer: what it owns, what it never owns, and which crates it may depend on.
No authored file is longer than 1,000 lines.

## Every brick (row number = issue number)
Status says how proven each brick's cheat sheet is. Every brick is written fresh either way.
- **RAN:** ran live on a node in the archive.
- **SOURCE:** built in the archive, not run live.
- **PORT:** exists in Prime or Contact.
- **BUILD:** designed, not built.
- **LATER:** kept and never dropped; Peter decides when.

### A. The Spatial app
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 1 | The Spatial app shell, rewritten as the organism: threads and chat with Auma, panels, every face a plugin on its organ; look and behaviour matched to Peter's running app | PORT | Prime plugins/aukora-face, aukora-foundation and vendor/dsh as the cheat sheet; screenshots from the pilot's build 3673b98 | app/ | M1 |
| 2 | AUKORA APPS: Auma Lingwa | PORT | Prime aukora-face apps (vendored auma-lingwa) | app/ | M1 |
| 3 | AUKORA APPS: Auma Live: the face from M1, saying plainly whether voice is installed; speaking comes after the core milestones (spec v0.2 §11) | PORT | Prime aukora-face apps, Prime voice runtime | app/ | M1 |
| 4 | AUKORA APPS: Zeta Harp | PORT | Prime aukora-face apps | app/ | M1 |
| 5 | AUKORA APPS: Human Graph (holding place for connections and media) | PORT | Prime aukora-face apps | app/ | M1 |
| 6 | AUKORA APPS: Media | PORT | Prime aukora-face apps | app/ | M1 |
| 7 | AUKORA APPS: Memory (Remembered, Signed, Proposals, Forgotten) reading Kira; a section with no backend yet says so plainly | SOURCE | archive guest memory route (2e64029) + Prime memory face | app/, guest/ | M4 |
| 8 | AUKORA APPS: Messages, the node's Nostr messages | BUILD | Prime messages face + archive messaging | app/, guest/, crates/messaging | M6 |
| 9 | AUKORA APPS: Documents (read-only, full-page rendered), served by documents.list and documents.read outside the guest from an owner document root; path and symlink escapes refused | PORT | Prime aukora-face documents | app/ | M1 |
| 10 | SYSTEM: AUMLOK (seven-word binding witness), opening the trusted panes | PORT | Prime aukora-face aumlok + archive owner panes | app/, ui/owner/ | M1 |
| 11 | SYSTEM: Identity (public contact card, contact codes, safety numbers) | PORT | Prime aukora-face aumlok (contact-qr, contact-verification) | app/, crates/nostr | M6 |
| 12 | SYSTEM: Aura Coherence: the health map (row 117) beside the fingerprint (row 55), always labelled apart | RAN | archive pentora + organs snapshot (7257d39); rendered live on S2 on 2026-10-15, 2 of 3 sources (the session record) | app/, crates/pentora | M5 |
| 13 | SYSTEM: General, Models, Plugins, Agent presets, Archived sessions | PORT | Prime aukora-face settings, threads | app/ | M1 |
| 14 | Auma theme: the first self-change target; applied through the versioned theme adapter (row 64) | PORT | Prime plugins/aukora-auma-theme | app/ | M3 |
| 15 | Every Prime plugin accounted for. Into the app: aukora-face, aukora-foundation, aukora-auma-theme, aukora-board, aukora-goal-resume, aukora-eye (its capture denied during ceremonies), aukora-organism, aukora-subscription-hands, aukora-gate-demo, aukora-action-gate (brick 30). Replaced by a crate: aukora-aumlok (aumlok), aukora-box (wasmcell; it holds the cell's source), aukora-kira (kira), aukora-nostr (nostr, relay, messaging), aukora-owner-daemon (supervisor, ui/owner), aukora-composition-gate (the supervisor's harness digest check), aukora-openshell-confinement, aukora-seatbelt, aukora-core-read-deny and aukora-caged-worker (launcher). Later: aukora-buzz-door and aukora-relay-auma (brick 87) | PORT | Prime plugins/ | app/ | M1 |
| 16 | App lock: Peter's app and System entries are registered, visible and opening, never hidden | BUILD | new | checks/ | M1 |
| 17 | App start speed: the approved assets are preloaded, so the first chat opens fast (it took 49 s on a 2-vCPU VM in the archive) | SOURCE | archive #47 (a warm-up exists in the archive frontdoor; the 49 s first load is unmeasured) | guest/ | M1 |
| 98 | Every Prime package accounted for: authority, boundary-gate, contracts, copresence, cordis-tool-provider, desktop, evolution-lab, execution, inference, invites, memory, ops, owner-key, runtime-bridge, ui; each carried into a crate, ported, or marked replaced | PORT | Prime packages/ | crates/, app/ | M1 |
| 106 | The organism core, our own: every organ a service, every face a plugin naming the services it needs; disposing a plugin removes everything it made | BUILD | Cordis's paradigm (the DeepSeek harness's plugin engine) as the cheat sheet | app/ | M1 |
| 107 | The tri-pane: three lanes weighted 0, 1, 2 or 3 and summing to 3 (ten compositions); a hidden lane keeps its state; a lane on the whole frame keeps its content at two thirds, centred, with no full-bleed exception; on a phone, one lane at a time | PORT | Prime aukora-face layout (AppFrame, PANE_WEIGHTS); the phone rule is new | app/ | M1 |
| 108 | The design as data: theme tokens, fonts, icons, copy and screenshots of every face and state from Peter's running app, pinned by hash | PORT | Prime aukora-auma-theme and aukora-face; the pilot's build 3673b98 | app/ | M1 |
| 109 | Auma sends the browser data, never code: the one link serves a static shell from the approved release (script-src 'self', no inline script, no eval); FD 4 carries only bounded, validated command and event data; anything Auma builds stays inert until its exact bundle is approved and published on its own host | BUILD | new (the one-link design) | app/, crates/frontdoor | M1 |

### B. One link
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 18 | One link: one address per node; the owner origin invisible and only ever framed | BUILD | archive frontdoor (pop-up panes RAN) | crates/frontdoor | M1 |
| 19 | Sign-in inside the app: a passkey pop-up, never a redirect | BUILD | archive frontdoor + owner panes | crates/frontdoor, ui/owner/ | M1 |
| 20 | Claiming a fresh node happens at the one link | BUILD | archive claim screen | crates/frontdoor, ui/owner/ | M1 |
| 21 | Approvals pop up by themselves, also while the agent is stopped | RAN | archive holding page (b0f148c) | crates/frontdoor | M1 |
| 22 | The app stays signed in across restarts and upgrades | RAN | archive durable sessions (a3c4988) | crates/frontdoor | M1 |
| 23 | The agent never runs unbound; an unbound session gets only the binding screens | RAN | archive frontdoor + supervisor | crates/frontdoor, crates/supervisor | M1 |
| 24 | TLS, host-only __Host- cookies, one Caddy block per node | RAN | archive frontdoor + deploy/spawn/caddy.sh | crates/frontdoor, deploy/ | M1 |

### C. The cage
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 25 | Agent runtime: our own harness inside the cage, one static Rust binary (chat, threads, sessions, streaming replies, presets, compaction, proposals, memory; no shell, file, subprocess or terminal tools); the FD 3 bridge; the app's data over FD 4; queued turns, steering and cancellation, usage receipts and proposal outcomes; presets select built-in operations and never load code; it never executes a command or opens a socket (seccomp denies execve and execveat) | BUILD | archive guest and launcher (ran with the DeepSeek harness); vendor/dsh packages core (agent, agent-loop, session, system-prompt), llm (llm, token-meter), compaction, context (session-reference, time-context), preset (agent-presets, persona) and session persistence as the cheat sheet | guest/, crates/launcher | M2 |
| 26 | The cage: namespaces, Landlock ABI 4 or higher, seccomp allowlist, cgroup limits, no network | RAN | archive launcher | crates/launcher | M2 |
| 27 | Boot record: kernel, Landlock ABI and seccomp hash written to Aura at every boot | RAN | archive launcher + aura | crates/launcher, crates/aura | M2 |
| 28 | Boot self-attack before every agent start | RAN | archive immune + launcher probe | crates/immune, crates/launcher | M2 |
| 29 | Hostile-guest attack suite, each attack with an unconfined control | RAN | archive tests + Grok | crates/immune, tests/ | M2 |
| 30 | Prime's in-guest action gate, phi-guard and path-law (tool calls judged before they run) | PORT | Prime plugins/aukora-action-gate, packages/boundary-gate | guest/, crates/laya | M2 |
| 31 | Conversation safety rails (a plugin-started turn is never the owner's words) | PORT | Prime conversation rails | guest/ | M2 |
| 128 | The supervisor is the only reader of FD 3: proposals go to the gate, model calls to the broker and memory calls to Kira; no other crate opens those sockets | BUILD | archive supervisor; Grok's review of v3 | crates/supervisor | M2 |
| 130 | Durable sessions: a session store (create, open, list, append at an expected sequence, flush), versioned events, flush before dispatch, recovery from a torn tail; Kira notes stay separate | BUILD | Codex's review of v3; vendor/dsh session packages | guest/ | M2 |

### D. Gate, approvals and Laya
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 32 | Canon: strict canonical JSON and the FD 3 codec, one Rust implementation compiled to WASM for the browser, with shared vectors (no JavaScript twins) | RAN | archive canon + bridge | crates/canon, guest/ | M1 |
| 33 | Gate: exact-bytes proposals, consumed once, recovery sweep, crash injection at every transition | RAN | archive gate | crates/gate | M3 |
| 34 | Retire and reconcile (Prime I1-I9): a declined or interrupted proposal never blocks its target | RAN | archive gate (#32), Prime #7 | crates/gate | M3 |
| 35 | Approval card: every field shown; the passkey signs the C5 authorization of exact bytes | RAN | archive gate + owner panes | crates/gate, ui/owner/ | M3 |
| 36 | Laya slider: ask for everything, only for risky things, or not within today's limits; standing permission by fingerprint; revoked in one tap; loosening it needs a passkey; tiers are routine and critical, and the default is critical; the slider sits in the right lane, by the apps | SOURCE | archive gate standing (01a2093); the card was raised and retired on S2, and no standing permission was used live yet | crates/laya, crates/gate | M3 |
| 37 | Laya triage (escalate only) with its benchmark; each Laya fine-tune ships as a pinned, reviewed model release; a separate capped process that never renders an all clear; deterministic rules ship first; evidence goes first in its input, and an overflow escalates instead of truncating | PORT | Prime lab (13.5% false alarms recorded) | crates/laya | M3 |
| 38 | Chat and Build modes: in Chat she talks; in Build she may also propose changes (to herself, sites, apps); neither runs a command or opens a socket; Yolo is gone, replaced by the slider's loosest setting | BUILD | archive #23 | crates/laya | M3 |
| 39 | The disposable sub-cage for running code (one folder, N commands, no network, under one standing signature): built now as a cage profile, off until Peter turns it on (decision 9); Auma's own runtime never executes | BUILD | Buzz shim design | crates/launcher, crates/laya | M3 |
| 40 | Three-valued decisions: Deny, Unknown, Allow; Unknown never becomes Allow | RAN | archive gate | crates/gate | M3 |
| 41 | Coverage check: every authority entry point and effect route has exactly one terminal row | BUILD | spec v0.2 section 3, archive #20 | checks/, crates/aura | M3 |
| 42 | Path 0 (A5): the caged agent proposes through the pinned cell, a passkey approves, it applies once, cold verification passes | SOURCE | archive #15 | tests/e2e/ | M3 |
| 110 | Epochs everywhere: every authority-bearing record carries epoch, sequence and previous hash; a membership change needs the old and new sets together | BUILD | NEBIUS rebuild guidance section 4 | crates/aura, crates/gate, crates/floor | M4 |
| 111 | Clone guard: an exclusive external register (operator, keys, compare-and-set, fencing tokens, bootstrap, expiry and partition behaviour specified first), built only after Peter chooses the clone rule (decision 4); until then spending and approving never consult witnesses, and unreachable witnesses change nothing | LATER | NEBIUS rebuild guidance section 4 (partly tested) | crates/floor, crates/relay | Later |
| 112 | Declined proposals are remembered and not re-proposed without new evidence; batching comes before rule proposals | BUILD | NEBIUS rebuild guidance section 5 | crates/gate | M3 |

### E. AUMLOK
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 43 | Passkey enrolment and WebAuthn (Prime semantics on RustCrypto), durable ceremonies | RAN | archive aumlok | crates/aumlok | M1 |
| 44 | Acrostic seven-word phrase (ROOT, UNITE, RISE), honest entropy, envelope over a random root; the phrase is entered and derived only on the owner origin, never in the app | RAN | archive aumlok | crates/aumlok | M1 |
| 45 | Phrase refresh screen | RAN | archive aumlok (1e8a53b); ran live on S2 with a software key; Touch ID refresh not yet | crates/aumlok, ui/owner/ | M1 |
| 46 | Passkey-bound backup (WebAuthn PRF) | SOURCE | archive aumlok (#50) | crates/aumlok | M4 |
| 47 | Add a machine; pair a device by co-presence | BUILD | archive #24, contact portal | crates/aumlok, crates/copresence | M7 |
| 48 | Delegation lineage root to device to session to agent; revocation rechecked at every use | BUILD | archive #61, kernel spec | crates/aumlok | M7 |
| 49 | Unlock limits per principal only; a stranger can never lock the owner out | RAN | archive aumlok + frontdoor (#38) | crates/aumlok, crates/frontdoor | M1 |
| 113 | The key hierarchy: owner root (hardware-held, on several devices), operational, device, node, agent, Nostr, guardian and backup keys; each binding in Aura with an epoch; no key acts beyond its scope; device mesh keys for bitchat's Bluetooth mesh are a role from day one, unused until rows 132 to 134 | BUILD | Codex's 17-role key map (NEBIUS rebuild guidance section 3) | crates/aumlok | M1 |

### F. Aura and verification
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 50 | Aura: one signed record, two arms, export with proofs (vectors at 1 to 32) | RAN | archive aura | crates/aura | M5 |
| 51 | Cold proof export: one download any stranger can verify offline | SOURCE | archive #27 | crates/aura, crates/verifier | M5 |
| 52 | The minimal verifier: aukora-verify and verify.py, from an empty folder, with Prime's regressions | SOURCE | archive verifier + tools/verify.py; the witness check ran against S2's relays; the stranger line is pending | crates/verifier | M5 |
| 53 | Owner-browser head witness: rollback and fork alarm on every visit | SOURCE | archive owner-witness | ui/owner/ | M5 |
| 54 | Aura head witnessed on Nostr relays | RAN | archive relay (b8ecb85); S2's head witnessed on relay.damus.io and nos.lol and checked by both verifiers on 2026-10-15 | crates/relay | M5 |
| 55 | Pentora fingerprint (pentora.display.v1): 110 trits from one derivation (it matched Prime on 5,360 vectors and 200 random roots); one derivation, fail-closed rendering, race guard, no digest text while moving, absent sources named with a reason; display only; a fingerprint trit is a different type from a health cell | RAN | archive pentora | crates/pentora | M5 |
| 56 | Live posture rows: the node attests its sandbox state into Aura on a schedule | BUILD | archive #26 | crates/immune, crates/aura | M5 |

### G. Kira
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 57 | Kira: encrypted notes, content-free commitments, demote never delete, cited recall (found, empty, undetermined); doctrines: usage never raises confidence, a summary is never the only copy, TTL means review-by | SOURCE | archive kira | crates/kira | M4 |
| 58 | OpenViking recall by meaning inside the node, with a local embedder | SOURCE | archive openviking; the service ran healthy under the supervisor on S2 on 2026-10-15; recall by meaning not yet shown | crates/kira, deploy/ | M4 |
| 59 | Memory permissions: disclose (done), store, dataset, export, train, activate | BUILD | carry list, Prime I-09 | crates/kira | M4 |
| 60 | Encrypted memory backup on relays and between the owner's own nodes | BUILD | archive #65, Prime records plan | crates/kira, crates/messaging | M6 |
| 61 | Member exit: export keys, memory and receipts; verify offline; restore with original ids | BUILD | archive #66, Prime #4 | crates/supervisor, crates/verifier | M7 |

### H. Broker and the model
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 62 | Broker: model key by one-time ticket, passkey spend grant, reservation, receipts; the model identity is recorded as requested, reported and verified | RAN | archive broker (real DeepSeek reply on S1) | crates/broker | M2 |
| 63 | Broker twins: a 'print your key' injection, an overspend race, and route off saying unavailable | SOURCE | archive broker tests | crates/broker, tests/ | M2 |
| 129 | Model streams: model.start, delta, end, error and cancel frames with request and reservation ids, ordered chunks, backpressure, limits and a final receipt (C4 has only a non-streaming model.call) | BUILD | Codex's review of v3; vendor/dsh packages llm | crates/broker, guest/ | M2 |

### I. WASM core, floor and immune
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 64 | WASM core: the 101-byte cell in the proposal path; a versioned theme adapter binds the cell's input and output digests, the target and the exact theme bytes into the authorization, and the supervisor reruns it before applying | SOURCE | archive wasmcell (#19) | crates/wasmcell | M3 |
| 65 | Release floor and high-water marks; a spent approval never revives | SOURCE | archive floor (#5, #54): installed once on S2 on 2026-10-15; the two bugs found there are fixed in source, not yet re-run | crates/floor | M4 |
| 66 | Immune: antibody ratchet on every release (887 registered antibodies, 885 active and 2 retired, including the fixes for archive #30 to #39 and #48); plus fresh held-out cases every release, both counts recorded as release facts; antibodies are never deleted, only retired by an owner-approved proposal | RAN | archive immune + immune/ANTIBODIES.tsv | crates/immune | M3 |
| 67 | Immune: the thymus (a shadow-clone check before a card; evidence only), the MHC loop (live self-attestation that computes the organ map, row 115) and hypermutation (seeded self-attack in its own cgroup, aimed at unmodelled hazards); a quarantine shows on the owner screen and is recovered by passkey; drift is reported apart from proven tampering; memory quarantines are visible to the owner | BUILD | archive #42, #43, #44 | crates/immune | M4 |
| 68 | Attack corpora: 815 attacks, 81 aumlok issues, 5,360 Pentora vectors (the archive holds the Pentora vectors, 4,354 and 1,006) | BUILD | archive #64 | crates/immune | M4 |

### J. Nostr
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 69 | Nostr node and agent identities, bound to Aura | RAN | archive nostr identity (#52) | crates/nostr, crates/supervisor | M6 |
| 70 | Relay client and an allowlisted egress path per relay | RAN | archive relay + spawn egress (#57) | crates/relay, deploy/ | M6 |
| 71 | Node-to-node gift-wrapped messages; contacts and sends are passkey cards; behind a transport interface: Nostr relays now, the Bluetooth mesh and a bitchat adapter later (rows 133, 134) | RAN | archive messaging; ran live S2 to S4 through public relays on 2026-10-15 (archive #60) | crates/messaging | M6 |

### K. Growth: invites, spawn, Go Sovereign, co-presence
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 72 | Invites: signed, 48 hours, three per member, provenance in the new node's first record; allowances are conserved and never multiplied by new identities | RAN | archive invites (archive #59); S2 issued the invite live and S4 was spawned from it on 2026-10-15; claiming in the browser (row 75) was never wired | crates/invites | M7 |
| 73 | One-command spawn: LXD on the host and Nebius VMs; guarded by row 131 | RAN | archive deploy/spawn | deploy/spawn | M1 |
| 74 | Go Sovereign page: paste a code, get a node | BUILD | new (Prime North Star step 11) | deploy/go-sovereign | M7 |
| 75 | Claim with the invite's secret, in the browser | BUILD | archive claim API | ui/owner/ | M7 |
| 76 | Co-presence portal (Point-and-Bloom), screen to screen; the sound, motion and intent-ack layers (built, never run) come with it; fix before reuse: sign both timestamps, keep the nonce out of the first message, bind the full context, count every attempt, and fix the method before the exchange | PORT | aukora-contact copresence-portal-v0 (ran on Mac and iPhone) | portal/ | M7 |
| 77 | Co-presence receipt verifier | SOURCE | archive copresence (ef368ee) | crates/copresence | M7 |
| 78 | Joining ceremony: co-presence with your own two devices, then phrase and passkey | BUILD | Prime North Star, Prime I-17 | portal/, crates/invites | M7 |
| 79 | A second independent node passes the core lines (A4); one node's cookies and proofs fail on the other | BUILD | S2 and S4 ran claim, binding and release; the A4 lines on two nodes never ran | tests/e2e/ | M7 |

### L. Operations and quality
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 80 | Upgrade without losing the binding; release switch with rollback; only to a commit named in Peter's passkey-signed release pointer (row 131) | BUILD | archive scratch scripts, #22 | deploy/ | M1 |
| 81 | Reproducible build and byte-compare | SOURCE | archive reproduce.sh (#63) | scripts/reproduce.sh | M1 |
| 82 | Pin-drift check on the launcher and policy | BUILD | archive #62 | checks/ | M2 |
| 83 | Repository checks: no logs, no file over 1,000 lines, no absolute or cross-repository paths, crate dependency allowlists, one plan; a commit-metadata privacy scan before any public push | BUILD | new | checks/ | M1 |
| 84 | Scaffold lock: how much of the scaffold still stands, checked on main | BUILD | new | checks/ | M1 |
| 102 | Per-unit systemd hardening, checked with systemd-analyze security | PORT | Prime hardening proposals, carry list | deploy/ | M2 |
| 103 | S1, Peter's archive-era node: keeps running untouched until the new node passes; then its record and memory move by the exit and restore path, or it retires | BUILD | archive #8 | deploy/ | M7 |
| 104 | The archive's open review findings (#46) re-checked against the new code | BUILD | archive #46 | tests/ | M1 |
| 127 | The inventory: spec/CARRY-LIST.md now, and Codex's 522-row carry list with its omission checker once Peter saves it; the checker fails closed; every row is rebuilt on main or carries Peter's own dated disposition, and nobody writes one for him; the 15 known coverage gaps are closed or dispositioned before M1 is called done, and no release is proposed while a row without a disposition fails | PORT | spec/CARRY-LIST.md; Codex's Rebuild Constitution packet (not yet saved to ~/Downloads) | checks/ | M1 |
| 131 | Deploy guard: spawn refuses any node listed in deploy/EXISTING-NODES (S1 is pinned there from the first commit); an existing node upgrades only to a commit named in a release pointer Peter signs with his passkey, which no worker writes; claim enrolment accepts only the one-time secret spawn wrote on the host | BUILD | Grok's review of v3 | deploy/, checks/ | M1 |

### M. Later: kept, never dropped
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 85 | Recursion v0: an environment-graded loop through the gate, replay first | LATER | archive #28 | later | Later |
| 86 | Ornith as Auma's mind; capped ask_model routing to other models; local models | LATER | Prime North Star (the mind), I-08 | later | Later |
| 87 | Phone approval (NIP-46), the Buzz relay under the node, Bitchat | LATER | Prime North Star, aukora-buzz | later | Later |
| 88 | Confidential VMs and the whole 'we cannot see your node' list: user-held keys, encrypted disk, the cloud control plane, abuse of free compute, KYC, the Nebius spend stop | LATER | WHIP CRACKER, 2026-10-15 | later | Later |
| 89 | Hardware keys and a trusted hash display; succession (k of n); witness committees, multi-observer heads and drand time anchors | LATER | carry list, Prime I-16 | later | Later |
| 90 | Desktop app (Electron), Windows build, phone app, AR and glasses | LATER | Prime apps/aukora-desktop, I-12, I-18 | later | Later |
| 91 | Invite chain and vouching against bots; a network of Aumas improving each other | LATER | Prime North Star, I-15 | later | Later |
| 92 | REA as a caged guest tool (static first; intake is an owner action; the supervisor reruns equivalence itself; assumptions pinned in every certificate); immune self-inspection in native Rust; herd immunity broadcasts | LATER | archive #45 | later | Later |
| 93 | Contact's System 1 and System 2 slot, the builder and breaker loop, the goal loop | LATER | aukora-contact, aukora-buzz | later | Later |
| 94 | Egress broker, mission envelopes and grant frames; the Merkle disclosure privacy note | LATER | carry list | later | Later |
| 95 | Public conformance corpus and LIMITS | LATER | coverage audit | later | Later |
| 96 | Honey Pot absorb order (73 families); about 72 unpushed commits in an old private Prime checkout; the experience schema and dataset release; anti-self-consensus; dreaming as proposals; Prime's ideas ledger I-01 to I-19, each mapped to its brick on the issue | LATER | Prime North Star, plan/IDEAS-LEDGER.md | later | Later |
| 97 | Vision R&D: tokens (AUM and AURA), PALADIN, Manifold and URHE, the Shear Engine, Trader Helm, KNVS UI, the AUMA glyph language, Gaussian memory, mesh, Bhutan NDI, the MEGA-SPEC vertical packs and economics | LATER | iCloud vision documents | later | Later |
| 99 | Licence questions for counsel: the AUMA language (CC BY-SA or AGPL), and an Apache fork loading the AGPL engine | LATER | Prime I-14, carry list | later | Later |
| 100 | Post-quantum hybrid signatures (Ed25519 with ML-DSA-65, downgrade refused) and unlinkable scoped identities | LATER | carry list, Prime labs/pq-hybrid, aumlok-id #65 | later | Later |
| 101 | First Echo: keep or drop | LATER | Prime North Star wave 1, carry list | later | Later |
| 105 | Metal: a bare-metal authority kernel (Rust no_std hosting WASM proposers), collapse to touch, trust onto metal in trust order; ternary tesseract memory; Auma the field with agents as organs | LATER | Prime I-01, I-02, I-03, I-05, I-07 | later | Later |

### N. Pentora: one shape at three levels
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 114 | The geometry as data: geometry_index_table_v1 (sha256 96b27c9b...8c61) pinned; one derivation of cubes, corners and pairs, with the every-pair-shares-two property asserted; a geometry change fails | PORT | Prime packages/ui/faces/settings/src/aura/pentora.mjs | crates/pentora, app/ | M1 |
| 115 | Level 1, the organ map: the five organs as the five cubes, 18 own checks each, 2 cross-checks for each of the 10 organ pairs confirmed by both; every cell +, 0 or -; an empty cell is an unwritten check; an unwritten check fails; wave 0 freezes all 110 check ids with their owners, sources and freshness limits | BUILD | NEBIUS Pentora foundation spec section 2 | crates/pentora, crates/immune | M5 |
| 116 | The MHC loop computes the organ map on a fixed cadence with CPU and IO caps; a - cell is evidence for quarantine or escalation, never authority; the map never changes a gate decision; the gate, the frontdoor and the launcher never read it; quarantine is a passkey action; a tampered target, desynced epochs or a drifted Kira head turns the right cell - | BUILD | NEBIUS Pentora foundation spec section 2 | crates/immune | M5 |
| 117 | The health view in Aura Coherence: solid verified, dim undetermined, red failed, shimmering repairing; undetermined is never shown as healthy | BUILD | NEBIUS Pentora foundation spec section 2 | app/ | M5 |
| 118 | The relationship bloom: the shared Pentora of a pairing, visual only | BUILD | NEBIUS Pentora foundation spec section 2; the contact portal | crates/pentora, portal/ | M7 |
| 119 | Level 2, the living network's layout: five circles, each corner holder in two; backup repair inside a circle, witness quorums that meet in exactly two holders, liars identified; a 10-slot variant for one person | LATER | NEBIUS Pentora foundation spec section 2 (partly tested) | crates/pentora, crates/relay | Later |

### O. Home base: the everything app
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 120 | The app store: a user app is a signed plugin; installing it is one approval of its exact bytes and of grants from a closed list (the passkey, the gate, the broker, appending to Aura and the network are never grantable); it runs in its own cage, never Auma's, with its own brokered services, no network, no exec and no WASI, and never in the WASM cell; its face runs in its own sandboxed frame and opens in the tri-pane | BUILD | new (Peter, 2026-10-15); Prime aukora-face apps as the cheat sheet | app/, crates/gate | M8 |
| 121 | The catalog: apps published and found over Nostr, signed by their authors; ratings are evidence, never authority | BUILD | new | crates/nostr, app/ | M8 |
| 122 | Sites: ask for a website; Auma builds it in the cage and proposes it; the card shows the exact bundle and the address; after the passkey the node serves the approved bytes on a third host with no cookies, no WebAuthn and frame-ancestors 'none'; Auma never gets the network | BUILD | new (Peter, 2026-10-15) | guest/, crates/gate, crates/frontdoor | M8 |

### P. The living network
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 123 | Marmot (MLS over Nostr) for group rooms: the guardian room, family circles, device groups; forward secrecy and healing after compromise | LATER | NEBIUS rebuild guidance section 6; github.com/marmot-protocol/marmot (MIT) | crates/nostr, crates/messaging | Later |
| 124 | Self-healing backups: encrypted and erasure-coded across devices and guardians on the Level 2 layout; local repair; current version only; shares refreshed so old thefts never combine | LATER | NEBIUS rebuild guidance section 7 (tested in simulation) | crates/kira, crates/relay | Later |
| 125 | Guardian recovery: Mode A (an operational key; the owner root stays outside the guardians) by default, Mode B (owner replacement) only if Peter chooses; 2q - n > f; vote locks protected from rollback | LATER | NEBIUS rebuild guidance section 7 | crates/aumlok, crates/gate | Later |
| 126 | Watchtowers, the veto and owner notice: one bounded pause per epoch, a separate cancellation credential, notice on several channels, 'published, unconfirmed' labelled | LATER | NEBIUS rebuild guidance section 7 | crates/relay, crates/gate | Later |
| 132 | Co-presence offline: a Bluetooth LE channel under the Noise protocol beside the screen-to-screen QR exchange, so two devices in one room pair with no internet at all; evidence only, never authority | LATER | bitchat (github.com/permissionlesstech/bitchat, public domain): its mesh, Noise sessions and BRING_THE_NOISE.md | crates/copresence, portal/ | Later |
| 133 | A bitchat adapter in Messages: its private envelopes (kind 1059 with its own v2 encryption, not NIP-17) and its geohash channels over Nostr, so an AUKORA node can talk with bitchat users | LATER | bitchat README and WHITEPAPER.md | crates/messaging | Later |
| 134 | The Bluetooth mesh as a second transport for the owner's devices: Bluetooth first, Nostr as the fallback, queued otherwise; multi-hop up to 7 (bitchat's routing) | LATER | bitchat | crates/messaging, app/ | Later |

### Q. Both ways: the life raft
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 135 | Inbound from other agents: strangers are refused before Auma sees anything; every refusal is counted in Aura and shown on the health map; an approved contact's message still reaches her only as data, marked as not the owner | SOURCE | archive messaging (its refusal counters ran live on S2 and S4); Prime conversation rails | crates/messaging, guest/ | M6 |
| 136 | Herd immunity: antibodies travel between nodes as signed Nostr events; an imported antibody can only add checks, never remove one; evidence only | BUILD | archive #45; the rebuild guidance's ratchet | crates/immune, crates/nostr | M6 |
| 137 | Met in person: a contact paired screen to screen is marked met-in-person; a remote or relayed pairing is labelled as such; evidence, never authority | BUILD | the contact portal (Point-and-Bloom); the rebuild guidance section 6 | crates/copresence, crates/messaging | M7 |
| 138 | Model intake: any model, from a provider or local, enters the broker's slot only after the immune system attacks the cage with that model driving the guest; it starts with no grants; its identity is in every receipt | BUILD | archive broker (model identity recorded); Prime I-08; Peter, 2026-10-15 | crates/broker, crates/immune | M2 |
| 139 | Crypto agility: every signature, key and record format carries an algorithm id, so post-quantum hybrids (Ed25519 with ML-DSA-65, row 100) arrive without a format break | BUILD | Prime labs/pq-hybrid; the carry list; Peter, 2026-10-15 | crates/canon, crates/aumlok, crates/aura | M1 |


## Who does what
- **Peter:** the UX, the passkey, the spend, the decisions below, and "done". He talks only with the conductor.
- **Claude, SOVEREIGN MAIN (the conductor):**
  - keeps this plan;
  - generates every worker brief from its rows;
  - launches and watches the workers;
  - tells Peter the fastest next move;
  - installs main on the fresh node and drives the milestone acceptances;
  - holds merges while main is red;
  - runs the zipper;
  - never writes feature code.

  Only two Claude chats run: the conductor and WHIP CRACKER.
- **Codex workers (gpt-6.1-sol, ultra):** 7 architects in wave 0, then 39 workers in wave 1. Each writes its section
  fresh against the frozen contracts, reading the archive and Prime as the cheat sheet. It compiles, and never commits
  or pushes.
- **Review after landing (Peter, 2026-10-15: code goes to main, then main is tested; no review gate before main):**
  two model families review every diff once it is on main, and a failed review becomes a fix worker that lands the same
  way. Grok is one family. The other is Codex for authority organs, deploy, scripts and checks, and Muse Spark
  elsewhere. Kimi held that seat until her quota ran out on 2026-10-16. A Muse pass on authority code counts as no
  verdict. Grok also sweeps main against this plan and runs the hostile twins on the installed node after each
  milestone.
- **The zipper (the conductor runs it as a script):**
  - pushes only a merged tree that compiles and passes the construction checks. Compiling is not testing;
  - runs those build steps in a sandbox that can write only inside the merge copy and has no network;
  - deletes the worker's clone and build folder the moment its diff is merged or thrown away.
  - throws away a diff that does not fit and has it re-briefed, never patched;
  - posts the evidence line on the issue, and pushes.
- **WHIP CRACKER:** the watchdog. It checks every report against what is really on main and on the node, and tells
  Peter directly.
- **NEBIUS:** the host and the Nebius VMs, read-only unless Peter says go.
- **CONTACT:** the co-presence portal.
- **Mistral (on GitHub), Gemini (Argon, from a zip) and Peter's other AIs:** attack main once it stands.

## How the work fans out
**Wave 0, the contracts, before any worker starts.** Main is reset to this plan, the frozen spec, the checks, the
inventory [127] and an empty skeleton. Seven Codex architects work in parallel: one on canon and frames, one for each of the
five organs, and one on the app's contract. The two review families check that it fits together as a whole, and the conductor zips it.

The architects freeze:
- **The contracts.** C1 to C7 as they are, plus versioned additions:
  - the FD 3 request and reply enums;
  - FD 4 `ChatCommand` and `SessionEvent`;
  - model streams;
  - the session store;
  - proposal outcomes and source provenance;
  - the atomic authority transaction: `AuthorityVersion`, `VerifiedProof`, `LedgerTxn`, the passkey counter, gate
    consumption and `Aura.append` in one transaction;
  - `HealthEvidence`, `health.snapshot`, and all 110 check ids with their owners, sources and freshness limits;
  - the browser RPC: plugin descriptors, capability-filtered calls, subscriptions and disposal;
  - the Network transport interface: Nostr relays now, the Bluetooth mesh later;
  - the WASM exports;
  - `documents.list` and `documents.read`;
  - the theme adapter;
  - crypto agility: every signature, key and record format carries an algorithm id [139].
- **The signature of every service**, where unknown operations refuse.
- **Ownership:** every path has exactly one owner per wave.
  - Faces own only `app/faces/<id>/`.
  - Wave 0 owns the entry points, manifests, schemas and the generated plugin registry.
  - Organ workers write their own health probes.
- **The pins:** a repository ID and commit for every cheat sheet, and the design data captured from Peter's running
  app.
- **The construction checks** [82, 83, 84].

**Wave 1, 39 workers**, one per section, each with exclusive paths (rows in brackets):

AUMLOK:
1. Passkey, WebAuthn, durable ceremonies, unlock limits [43, 49]
2. The phrase, the envelope, phrase refresh, PRF backup [44, 45, 46]
3. The key hierarchy, delegation lineage, devices [47, 48, 113]

Gate and Aura:
4. Canon, frames and the WASM exports [32]
5. The gate's state machine: exact bytes, consumed once, retire and reconcile, three values, declined memory, coverage
   [33, 34, 40, 41, 112]
6. Approval cards and owner actions on the owner origin, including pop-ups while the agent is stopped [21, 35]
7. Laya: the slider, triage, modes [36, 37, 38]
8. Aura: the ledger, epochs, cold export [50, 51, 110]
9. The browser head witness [53]
10. The verifiers: aukora-verify and verify.py [52]
11. The floor [65]

Kira:
12. Notes, cited recall, permissions [57, 59]
13. OpenViking recall by meaning [58]

Network:
14. Nostr identities and crypto [69]
15. The relay client and head witnesses on relays [54, 70]
16. Messaging and contacts, and refusing strangers [71, 135]
17. Invites [72]
18. The co-presence verifier and the portal's fixes [76, 77]

Body:
19. Ingress and sign-in: the one link, the owner origin, claim, sessions, TLS [18, 19, 20, 22, 23, 24]
20. Approved asset serving: the static shell, data-only FD 4, preload, the documents backend [17, 109]
21. The supervisor's FD 3 router [128]
22. The cage and its profiles, including the sub-cage that stays off [26, 39]
23. The boot record and the boot self-attack [27, 28, 29]
24. The broker and model streams [62, 63, 129]
25. The WASM cell and the theme adapter [64]
26. Immune: the release ratchet [66]
27. Immune: the thymus and hypermutation [67]
28. Immune: posture rows, the MHC loop and the organ map [56, 115, 116]
29. The harness: transport, the agent loop, operation dispatch [25, 30, 31]
30. The harness: sessions, context, compaction, presets [130]

The app:
31. The organism core [106]
32. The tri-pane and the design data [107, 108]
33. Chat and threads [1]
34. Settings: General, Models, Plugins, Agent presets, Archived sessions, the app lock [13, 16]
35. Faces: Memory and Messages [7, 8]
36. Faces: Documents, Media, Human Graph [5, 6, 9]
37. Faces: AUMLOK, Identity, Aura Coherence with the health view [10, 11, 12, 117]
38. Pentora: the pinned geometry and the fingerprint, in Rust and in WASM [55, 114]
39. Deploy: the deploy guard, spawn, upgrade, reproduce, unit hardening [73, 80, 81, 102, 131]

**Wave 2:**
- the stock apps: Auma Lingwa, Auma Live, Zeta Harp [2, 3, 4];
- the theme and the plugin and package accounting [14, 15, 98];
- Go Sovereign, claiming with an invite, the joining ceremony [74, 75, 78];
- the app store and the catalog [120, 121];
- sites [122];
- the bloom [118];
- the memory backup and the member exit [60, 61];
- the attack corpora, as data [68];
- herd immunity, met in person, and model intake [136, 137, 138].

**Wave 3:**
- Worker 21 wires the supervisor's start-up against the merged organs [128].
- Main is installed on a fresh test node, never on S1 [103].
  - The test node is a container on the existing host, so there is no new spend.
  - The conductor claims it with a disposable software passkey.
  - Peter's own node is spawned fresh for him to claim with Touch ID.
- Main is tested on the node: M1 to M8 and each milestone's hostile twin [42, 79, 104].
- Then every major AI attacks it.

If Codex throttles, a wave runs in halves. A worker that needs another section's code waits for it on main; it never
writes it itself.

## It cannot drift
1. **One plan, machine-checked.** It changes only when Peter says so, with his words on the issue.
2. **Every brief is generated by a script** from its rows. It quotes the rows verbatim and includes the frozen
   contracts, the crate READMEs and the paths the worker owns. No brief is written by hand. A brief that contradicts
   another row is refused.
3. **One writer per path per wave.** The checks refuse a diff before any reviewer reads it if it does any of these:
   - touches a path its worker does not own;
   - adds an unplanned crate, folder or codec;
   - opens a socket the contracts do not name;
   - breaks a machine rule.
4. **Each reviewer answers one question first.** Both review families ask: does this diff do exactly its rows, nothing
   more and nothing less? That includes stubs that report "verified" and tools hidden inside allowed files.
5. **The zipper never patches a diff.** It throws it away and re-briefs. It pushes only a merged tree that compiles and
   passes the construction checks, so one bad diff cannot turn main red overnight.
6. **Every session rereads this file after each compaction**, and the memory note says the same.
7. **Every hour, Grok compares main with this plan.** It lists anything unplanned or missing, and WHIP CRACKER relays
   it to Peter.
8. **The disk stays healthy.** A worker starts only while 40 GB or more is free. Its clone and build folder are deleted
   as soon as its diff is merged or thrown away.

## Rules (a machine enforces these on main; any failure means main is red)
These are construction checks. They hold on every commit, from the empty skeleton on. Milestone acceptance is
different: it runs on the installed node, is red until the milestone is built, and never stops work.
1. **One plan:** this file. There is no other plan-like file anywhere.
2. **Every row here has an open issue with the same number.** A row and its issue leave only together, with Peter's
   words on the issue.
3. **No clutter.**
   - No committed `*.log`.
   - No `*.txt` except listed data files.
   - No mutation output and no evidence folders. Evidence stays on the node, and its summary goes in the issue.
4. **No authored file over 1,000 lines.** Data files are pinned by hash: the word lists, the WASM cell, the geometry
   table, the antibody registry, the attack corpora, the format vectors and the design.
5. **The app lock.** Every app and System entry above is registered in the plugin registry. On the installed node,
   each one opens and shows what it is for. A page that merely answers is not enough.
6. **One link.** There is one public address per node, and the owner origin never answers as a page.
7. **Builds embed by relative path and content hash.** There are no absolute paths and no path into another
   repository.
8. **Each crate depends only on what its README allows.** The scaffold lock fails if a planned piece disappears, or if
   an unplanned folder or crate appears.
9. **The inventory.** Every carry-list row is rebuilt on main or carries Peter's own dated disposition. The checker
   fails closed.
10. **The deploy guard** (row 131). Spawn and upgrade refuse before any host call unless the node is new, or the commit
    is named in Peter's passkey-signed release pointer.

**Working rules:**
- Code goes to main, and main is tested after it lands, never before. Nothing is tested anywhere else without Peter's
  direct approval.
- A red construction check stops new features until it is fixed.
- No home-made crypto. Primitives come from the spec v0.2 section 11 library list, or Peter approves them.
- No global rate limit that can lock the owner out.
- Status changes only with evidence, posted on the issue in this form: `task / revision / evidence / result / blocker
  / next owner`.
- Only Peter closes a row as done.
- New ideas go on the README's IDEAS list with one question to Peter: "switch target or park it?"
- Replies to Peter are short: what's done, what's next, what needs his passkey.

## Decisions only Peter makes (never guessed)
1. Recovery: Mode A only, or Modes A and B.
2. Guardian numbers: 4 of 5, 5 of 7, or something else.
3. When the owner is unreachable: never finalize, or finalize after a long wait labelled "unconfirmed".
4. The clone rule (row 111): an exclusive external register with single-active-device leases, or something else.
   Until he chooses, M4 claims reboot safety only.
5. A failing antibody: a red break-glass card, or a hard block.
6. The stock apps not in his eight:
   - Dakini Code (a Genesis stock app);
   - Canvas (withheld in Genesis);
   - Room (its launcher status is unverified).
7. The phone layout: one lane at a time, full width.
8. What the Jack Dorsey demo must show: M1 to M8, or a cut.
9. When to turn on the sub-cage for running code (row 39). It is built now, and stays off until he says yes.

## Say plainly to anyone shown this
- A passkey approval proves that a passkey signed exact bytes after its user check, not which person pressed it.
- The record is tamper-evident to a stranger, checked against a retained or witnessed head.
- A co-presence receipt is evidence, and grants nothing.
- Whoever runs the server could read a running node until confidential VMs arrive (row 88).
- Demoted memory is kept, not erased.
- A cloned disk is not yet defended (decision 4).
- Never claim:
  - proof of unique humans;
  - solved Nostr key loss;
  - thief-proof recovery without its assumptions;
  - Pentora as security, compression or a 42-D breakthrough;
  - Laya as a judge;
  - production readiness from same-author simulations.
