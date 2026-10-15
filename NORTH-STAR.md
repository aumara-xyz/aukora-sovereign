# AUKORA Sovereign: North Star

**This is the only plan.** There is no other plan file in this repository, and `checks/` makes main red if one
appears. Every row below is one GitHub issue with the same number: row 12 is issue #12. The issues are the work
tracker. A row can only leave this plan when Peter says so, and his words are written on its issue.

It carries forward Peter's Prime North Star (aukora-prime `plan/NORTH-STAR.md`), the master plan he approved on
2026-10-14 (frozen in [spec/SPEC-v0.2.md](spec/SPEC-v0.2.md) as the technical appendix, with the contracts, carry list
and coverage audit beside it), every issue of aukora-prime and aukora-sovereign-archive, every Prime plugin, and
Prime's ideas ledger. Nothing is new invention, and nothing is dropped.

## One sentence
A personal AI organism on a Linux server you control, reached from your own app, that can grow and even change itself —
and can never act past the boundary without its owner's approval, with a receipt anyone can check.

## What Peter watches, in order (only Peter says "done")
1. **M1, his fresh node.** One link, the whole Spatial app, claimed with his passkey and phrase. The release approval
   pops up inside the app.
2. **M2, Auma answers with a real model.** The receipt sits inside his spend grant, and the cage holds: she cannot
   read the server.
3. **M3, she proposes a change to herself** (the theme). Laya, by his slider, decides it pops up. He approves the exact
   bytes with his fingerprint. It runs through the WASM core and applies once, live. The same request without
   approval does nothing.
4. **M4, she remembers after a real reboot**, recalled by meaning. Spent approvals stay spent; the floor holds.
5. **M5, a stranger verifies everything** from an empty folder, and Aura Coherence shows the same record in his app.
6. **M6, two nodes talk.** His node and a second node exchange messages over Nostr relays, in Messages.
7. **M7, Go Sovereign.** He invites a friend. The code unlocks a fresh node with one click; the co-presence ceremony
   runs, then the passkey and phrase; then the friend is inside their own Spatial app.

## The body (each organ, and where it lives)
- **The Spatial app** (`app/`): the AUKORA spatial frontend on the DeepSeek harness, brought in whole.
  - AUKORA APPS: Auma Lingwa, Auma Live, Zeta Harp, Human Graph, Media, Memory, Messages, Documents.
  - SYSTEM: AUMLOK, Identity, Aura Coherence, General, Models, Plugins, Agent presets, Archived sessions.
- **One node, one link.** Passkey, phrase and approvals are pop-ups inside the app. They are served by the node itself
  from an invisible, framed-only owner origin (`crates/frontdoor`, `owner-panes/`), never by the agent.
- **The cage** (`crates/launcher`): Auma runs as a different host user with no network, under user namespaces,
  Landlock and seccomp. She can only propose. The boot self-attack (`crates/immune`) proves the cage at every start.
- **The gate** (`crates/gate`): exact bytes are shown, approved by passkey, applied once and never replayed. Auma can
  never approve herself.
- **Laya and the slider** (`crates/laya`): the owner chooses when pop-ups appear: for everything, only for risky
  things, or not within today's limits. That is a standing permission signed once by fingerprint, scoped, counted and
  expiring. Risky changes always ask. Laya decides what pops up; she never approves.
- **AUMLOK** (`crates/aumlok`): the acrostic seven-word phrase (ROOT, UNITE, RISE) seals a random root key, and a
  passkey (Touch ID) signs every approval.
- **AURA** (`crates/aura`): one signed, append-only record of everything. It is witnessed by the owner's browser and
  on Nostr relays.
- **Pentora** (`crates/pentora`): the record's picture (Aura Coherence).
- **The minimal verifier** (`crates/verifier`): a stranger checks everything from an empty folder.
- **KIRA** (`crates/kira`): encrypted memory with cited recall, ranked by OpenViking inside the node. Forgetting
  demotes; nothing is silently deleted.
- **The WASM core** (`crates/wasmcell`): proposals run in the sealed 101-byte cell.
- **The broker** (`crates/broker`): the model key is held outside the model, and spending is limited by a
  passkey-signed grant.
- **The floor** (`crates/floor`): no rollback; a spent approval never revives.
- **The immune system** (`crates/immune`): every known attack is an antibody, and every release must pass them all.
- **NOSTR** (`crates/nostr`, `crates/relay`, `crates/messaging`): the node and agent identities, the relays, and
  node-to-node messages from owner-approved contacts. A message is never authority.
- **Invites** (`crates/invites`): "You can download the open-source software, but you can't be part of the network
  without a direct invite from me or someone I've invited." A one-time code, valid 48 hours, three per member.
- **Co-presence** (`portal/`, `crates/copresence`): two screens show each other signed light. It is evidence of being
  in the same place, never authority.
- **Go Sovereign** (`ops/go-sovereign`, `ops/spawn`): a valid invite unlocks a fresh node with one click.

## How it fits (the technical rules are in spec/SPEC-v0.2.md sections 2 to 7, unchanged, with one amendment: one link)
- **One trusted supervisor** process holds every authority. It is **wiring only**: it starts the organs and routes
  frames. Policy lives in the organ crates, never in it.
- **Auma** runs the harness inside the cage. FD 3 is her only channel for proposals, model calls and memory; FD 4
  serves the app.
- **One link.** The app and its pop-ups share one address. The pop-ups come from a separate owner origin that only
  ever appears framed inside the app, pinned by `frame-ancestors`, and the passkey ceremony checks `topOrigin`. The
  agent's code never shares an origin with a passkey ceremony or an owner session.
- **Builds embed by relative path and content hash.** There is one source tree per build folder, and the deployed
  binary is byte-compared with a pristine rebuild.

## The repository
```
README.md        how to open the node; milestone status; claim board; IDEAS
NORTH-STAR.md    this file, the only plan
spec/            frozen technical appendix: SPEC v0.2, CONTRACTS, CARRY-LIST, coverage audit (inputs, not plans)
crates/          canon aura gate laya aumlok kira broker wasmcell floor immune verifier pentora
                 nostr relay messaging invites copresence launcher frontdoor supervisor
app/             the Spatial app, whole: vendored, pinned, provenance recorded (no path into another repository)
owner-panes/     the trusted pop-ups only; never a page
guest/           the sandbox bridge (FD 3 client, model adapter, service adapters for the app)
portal/          the co-presence Point-and-Bloom page
ops/             spawn (LXD and Nebius VM), go-sovereign, upgrade, reproduce
checks/          the machine rules below
tests/e2e/       one test per milestone
```
Each crate has a README of 10 lines or fewer: what it owns, what it never owns, and which crates it may depend on.
No authored file is longer than 1,000 lines.

## Every brick (row number = issue number)
Status: **RAN** = ran live on a node in the archive (carried, then proven again here); **SOURCE** = built and tested,
not yet live; **PORT** = exists in Prime or Contact, to bring over; **BUILD** = designed, not built; **LATER** = kept,
never dropped; Peter decides when.

### A. The Spatial app
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 1 | The Spatial app shell: threads, chat with Auma, panels, spatial frontend, brought in whole and pinned to the build the Nebius pilot runs | PORT | Prime plugins/aukora-face + aukora-foundation + vendor/dsh harness (the archive ran a reduced copy with plugins hidden) | app/ | M1 |
| 2 | AUKORA APPS: Auma Lingwa | PORT | Prime aukora-face apps (vendored auma-lingwa) | app/ | M1 |
| 3 | AUKORA APPS: Auma Live: the face from M1, saying plainly whether voice is installed; speaking comes after the core milestones (spec v0.2 §11) | PORT | Prime aukora-face apps, Prime voice runtime | app/ | M1 |
| 4 | AUKORA APPS: Zeta Harp | PORT | Prime aukora-face apps | app/ | M1 |
| 5 | AUKORA APPS: Human Graph (holding place for connections and media) | PORT | Prime aukora-face apps | app/ | M1 |
| 6 | AUKORA APPS: Media | PORT | Prime aukora-face apps | app/ | M1 |
| 7 | AUKORA APPS: Memory (Remembered, Signed, Proposals, Forgotten) reading Kira | SOURCE | archive guest memory route (2e64029) + Prime memory face | app/, guest/ | M4 |
| 8 | AUKORA APPS: Messages, the node's Nostr messages | BUILD | Prime messages face + archive messaging | app/, guest/, crates/messaging | M6 |
| 9 | AUKORA APPS: Documents (read-only, full-page rendered) | PORT | Prime aukora-face documents | app/ | M1 |
| 10 | SYSTEM: AUMLOK (seven-word binding witness), opening the trusted panes | PORT | Prime aukora-face aumlok + archive owner panes | app/, owner-panes/ | M1 |
| 11 | SYSTEM: Identity (public contact card, contact codes, safety numbers) | PORT | Prime aukora-face aumlok (contact-qr, contact-verification) | app/, crates/nostr | M6 |
| 12 | SYSTEM: Aura Coherence (the Pentora picture) | RAN | archive pentora + organs snapshot (7257d39); seen rendering on S2 on 2026-10-15 | app/, crates/pentora | M5 |
| 13 | SYSTEM: General, Models, Plugins, Agent presets, Archived sessions | PORT | Prime aukora-face settings, threads | app/ | M1 |
| 14 | Auma theme: the first self-change target | PORT | Prime plugins/aukora-auma-theme | app/ | M3 |
| 15 | Every Prime plugin accounted for. Into the app: aukora-face, aukora-foundation, aukora-auma-theme, aukora-board, aukora-goal-resume, aukora-eye (its capture denied during ceremonies), aukora-organism, aukora-subscription-hands, aukora-gate-demo, aukora-action-gate (brick 30). Replaced by a crate: aukora-aumlok (aumlok), aukora-box (wasmcell; it holds the cell's source), aukora-kira (kira), aukora-nostr (nostr, relay, messaging), aukora-owner-daemon (supervisor, owner-panes), aukora-composition-gate (the supervisor's harness digest check), aukora-openshell-confinement, aukora-seatbelt, aukora-core-read-deny and aukora-caged-worker (launcher). Later: aukora-buzz-door and aukora-relay-auma (brick 87) | PORT | Prime plugins/ | app/ | M1 |
| 16 | App lock: Peter's app and System entries are registered, visible and opening, never hidden | BUILD | new | checks/ | M1 |
| 17 | App start speed: warm the plugin bundle when the agent starts (first chat took 49 s on a 2-vCPU VM) | SOURCE | archive #47 (a warm-up exists in the archive frontdoor; the 49 s first load is unmeasured) | guest/ | M1 |
| 98 | Every Prime package accounted for: authority, contracts, copresence, cordis-tool-provider, desktop, evolution-lab, execution, inference, invites, memory, ops, owner-key, runtime-bridge, ui; each carried into a crate, ported, or marked replaced | PORT | Prime packages/ | crates/, app/ | M1 |

### B. One link
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 18 | One link: one address per node; the owner origin invisible and only ever framed | BUILD | archive frontdoor (pop-up panes RAN) | crates/frontdoor | M1 |
| 19 | Sign-in inside the app: a passkey pop-up, never a redirect | BUILD | archive frontdoor + owner panes | crates/frontdoor, owner-panes/ | M1 |
| 20 | Claiming a fresh node happens at the one link | BUILD | archive claim screen | crates/frontdoor, owner-panes/ | M1 |
| 21 | Approvals pop up by themselves, also while the agent is stopped | RAN | archive holding page (b0f148c) | crates/frontdoor | M1 |
| 22 | The app stays signed in across restarts and upgrades | RAN | archive durable sessions (a3c4988) | crates/frontdoor | M1 |
| 23 | The agent never runs unbound; an unbound session gets only the binding screens | RAN | archive frontdoor + supervisor | crates/frontdoor, crates/supervisor | M1 |
| 24 | TLS, host-only __Host- cookies, one Caddy block per node | RAN | archive frontdoor + deploy/spawn/caddy.sh | crates/frontdoor, ops/ | M1 |

### C. The cage
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 25 | Agent runtime (DeepSeek harness) inside the cage; FD 3 bridge; the app over FD 4 | RAN | archive guest + launcher | crates/launcher, guest/ | M2 |
| 26 | The cage: namespaces, Landlock ABI 4 or higher, seccomp allowlist, cgroup limits, no network | RAN | archive launcher | crates/launcher | M2 |
| 27 | Boot record: kernel, Landlock ABI and seccomp hash written to Aura at every boot | RAN | archive launcher + aura | crates/launcher, crates/aura | M2 |
| 28 | Boot self-attack before every agent start | RAN | archive immune + launcher probe | crates/immune, crates/launcher | M2 |
| 29 | Hostile-guest attack suite, each attack with an unconfined control | RAN | archive tests + Grok | crates/immune, tests/ | M2 |
| 30 | Prime's in-guest action gate, phi-guard and path-law (tool calls judged before they run) | PORT | Prime plugins/aukora-action-gate, packages/boundary-gate | guest/, crates/laya | M2 |
| 31 | Conversation safety rails (a plugin-started turn is never the owner's words) | PORT | Prime conversation rails | guest/ | M2 |

### D. Gate, approvals and Laya
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 32 | Canon: strict canonical JSON, FD 3 codec, shared Rust and JS vectors | RAN | archive canon + bridge | crates/canon, guest/ | M1 |
| 33 | Gate: exact-bytes proposals, consumed once, recovery sweep, crash injection at every transition | RAN | archive gate | crates/gate | M3 |
| 34 | Retire and reconcile (Prime I1-I9): a declined or interrupted proposal never blocks its target | RAN | archive gate (#32), Prime #7 | crates/gate | M3 |
| 35 | Approval card: every field shown; the passkey signs the C5 authorization of exact bytes | RAN | archive gate + owner panes | crates/gate, owner-panes/ | M3 |
| 36 | Laya slider: ask for everything, only for risky things, or not within today's limits; standing permission by fingerprint | SOURCE | archive gate standing (01a2093); the card was raised and retired on S2, and no standing permission was used live yet | crates/laya, crates/gate | M3 |
| 37 | Laya triage (escalate only) with its benchmark; each Laya fine-tune ships as a pinned, reviewed model release | PORT | Prime lab (13.5% false alarms recorded) | crates/laya | M3 |
| 38 | Chat, Build and Yolo modes | BUILD | archive #23 | crates/laya | M3 |
| 39 | Standing bounds: one signature, one folder, N commands, enforced by the cage | BUILD | Buzz shim design | crates/laya, crates/launcher | M3 |
| 40 | Three-valued decisions: Deny, Unknown, Allow; Unknown never becomes Allow | RAN | archive gate | crates/gate | M3 |
| 41 | Coverage check: every authority entry point and effect route has exactly one terminal row | BUILD | spec v0.2 section 3, archive #20 | checks/, crates/aura | M3 |
| 42 | Path 0 (A5): the caged agent proposes through the pinned cell, a passkey approves, it applies once, cold verification passes | SOURCE | archive #15 | tests/e2e/ | M3 |

### E. AUMLOK
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 43 | Passkey enrolment and WebAuthn (Prime semantics on RustCrypto), durable ceremonies | RAN | archive aumlok | crates/aumlok | M1 |
| 44 | Acrostic seven-word phrase (ROOT, UNITE, RISE), honest entropy, envelope over a random root; decide whether the phrase is derived in a browser worker or on the node | RAN | archive aumlok | crates/aumlok | M1 |
| 45 | Phrase refresh screen | RAN | archive aumlok (1e8a53b); ran live on S2 with a software key; Touch ID refresh not yet | crates/aumlok, owner-panes/ | M1 |
| 46 | Passkey-bound backup (WebAuthn PRF) | SOURCE | archive aumlok (#50) | crates/aumlok | M4 |
| 47 | Add a machine; pair a device by co-presence | BUILD | archive #24, contact portal | crates/aumlok, crates/copresence | M7 |
| 48 | Delegation lineage root to device to session to agent; revocation rechecked at every use | BUILD | archive #61, kernel spec | crates/aumlok | M7 |
| 49 | Unlock limits per principal only; a stranger can never lock the owner out | RAN | archive aumlok + frontdoor (#38) | crates/aumlok, crates/frontdoor | M1 |

### F. Aura and verification
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 50 | Aura: one signed record, two arms, export with proofs (vectors at 1 to 32) | RAN | archive aura | crates/aura | M5 |
| 51 | Cold proof export: one download any stranger can verify offline | SOURCE | archive #27 | crates/aura, crates/verifier | M5 |
| 52 | The minimal verifier: aukora-verify and verify.py, from an empty folder, with Prime's regressions | SOURCE | archive verifier + tools/verify.py; the witness check ran against S2's relays; the stranger line is pending | crates/verifier | M5 |
| 53 | Owner-browser head witness: rollback and fork alarm on every visit | SOURCE | archive owner-witness | owner-panes/ | M5 |
| 54 | Aura head witnessed on Nostr relays | RAN | archive relay (b8ecb85); S2's head verified from the Mac against two public relays on 2026-10-15 | crates/relay | M5 |
| 55 | Pentora digest: 110 trits, identical on every device | RAN | archive pentora | crates/pentora | M5 |
| 56 | Live posture rows: the node attests its sandbox state into Aura on a schedule | BUILD | archive #26 | crates/immune, crates/aura | M5 |

### G. Kira
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 57 | Kira: encrypted notes, content-free commitments, demote never delete, cited recall (found, empty, undetermined); doctrines: usage never raises confidence, a summary is never the only copy, TTL means review-by | SOURCE | archive kira | crates/kira | M4 |
| 58 | OpenViking recall by meaning inside the node, with a local embedder | SOURCE | archive openviking; the service ran healthy under the supervisor on S2 on 2026-10-15; recall by meaning not yet shown | crates/kira, ops/ | M4 |
| 59 | Memory permissions: disclose (done), store, dataset, export, train, activate | BUILD | carry list, Prime I-09 | crates/kira | M4 |
| 60 | Encrypted memory backup on relays and between the owner's own nodes | BUILD | archive #65, Prime records plan | crates/kira, crates/messaging | M6 |
| 61 | Member exit: export keys, memory and receipts; verify offline; restore with original ids | BUILD | archive #66, Prime #4 | crates/supervisor, crates/verifier | M7 |

### H. Broker and the model
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 62 | Broker: model key by one-time ticket, passkey spend grant, reservation, receipts; the model identity is recorded as requested, reported and verified | RAN | archive broker (real DeepSeek reply on S1) | crates/broker | M2 |
| 63 | Broker twins: a 'print your key' injection, an overspend race, and route off saying unavailable | SOURCE | archive broker tests | crates/broker, tests/ | M2 |

### I. WASM core, floor and immune
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 64 | WASM core: the 101-byte cell in the proposal path | SOURCE | archive wasmcell (#19) | crates/wasmcell | M3 |
| 65 | Release floor and high-water marks; a spent approval never revives | SOURCE | archive floor (#5, #54): installed once on S2 on 2026-10-15; the two bugs found there are fixed in source, not yet re-run | crates/floor | M4 |
| 66 | Immune: antibody ratchet on every release (888 antibodies, including the fixes for archive #30 to #39 and #48) | RAN | archive immune + immune/ANTIBODIES.tsv | crates/immune | M3 |
| 67 | Immune: thymus, MHC and hypermutation | BUILD | archive #42, #43, #44 | crates/immune | M4 |
| 68 | Attack corpora: 815 attacks, 81 aumlok issues, 5,360 Pentora vectors (locate them first) | BUILD | archive #64 | crates/immune | M4 |

### J. Nostr
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 69 | Nostr node and agent identities, bound to Aura | RAN | archive nostr identity (#52) | crates/nostr, crates/supervisor | M6 |
| 70 | Relay client and an allowlisted egress path per relay | RAN | archive relay + spawn egress (#57) | crates/relay, ops/ | M6 |
| 71 | Node-to-node gift-wrapped messages; contacts and sends are passkey cards | RAN | archive messaging; ran live S2 to S4 through public relays on 2026-10-15 (archive #60) | crates/messaging | M6 |

### K. Growth: invites, spawn, Go Sovereign, co-presence
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 72 | Invites: signed, 48 hours, three per member, provenance in the new node's first record | RAN | archive invites; ran live S2 to S4 on 2026-10-15 (archive #59) | crates/invites | M7 |
| 73 | One-command spawn: LXD on the host and Nebius VMs | RAN | archive deploy/spawn | ops/spawn | M1 |
| 74 | Go Sovereign page: paste a code, get a node | BUILD | new (Prime North Star step 11) | ops/go-sovereign | M7 |
| 75 | Claim with the invite's secret, in the browser | BUILD | archive claim API | owner-panes/ | M7 |
| 76 | Co-presence portal (Point-and-Bloom), screen to screen; the sound, motion and intent-ack layers (built, never run) come with it | PORT | aukora-contact copresence-portal-v0 (ran on Mac and iPhone) | portal/ | M7 |
| 77 | Co-presence receipt verifier | SOURCE | archive copresence (ef368ee) | crates/copresence | M7 |
| 78 | Joining ceremony: co-presence with your own two devices, then phrase and passkey | BUILD | Prime North Star, Prime I-17 | portal/, crates/invites | M7 |
| 79 | A second independent node passes the core lines (A4); one node's cookies and proofs fail on the other | BUILD | S2 and S4 ran claim, binding and release; the A4 lines on two nodes never ran | tests/e2e/ | M7 |

### L. Operations and quality
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 80 | Upgrade without losing the binding; release switch with rollback | BUILD | archive scratch scripts, #22 | ops/ | M1 |
| 81 | Reproducible build and byte-compare | SOURCE | archive reproduce.sh (#63) | ops/reproduce | M1 |
| 82 | Pin-drift check on the launcher and policy | BUILD | archive #62 | checks/ | M2 |
| 83 | Repository checks: no logs, no file over 1,000 lines, no absolute or cross-repository paths, crate dependency allowlists, one plan; a commit-metadata privacy scan before any public push | BUILD | new | checks/ | M1 |
| 84 | Scaffold lock: how much of the scaffold still stands, checked on main | BUILD | new | checks/ | M1 |
| 102 | Per-unit systemd hardening, checked with systemd-analyze security | PORT | Prime hardening proposals, carry list | ops/ | M2 |
| 103 | S1, Peter's archive-era node: keeps running untouched until the new node passes; then its record and memory move by the exit and restore path, or it retires | BUILD | archive #8 | ops/ | M7 |
| 104 | The archive's open review findings (#46) re-checked against the new code | BUILD | archive #46 | tests/ | M1 |

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
| 92 | REA as a caged guest tool; immune self-inspection; herd immunity broadcasts | LATER | archive #45 | later | Later |
| 93 | Contact's System 1 and System 2 slot, the builder and breaker loop, the goal loop | LATER | aukora-contact, aukora-buzz | later | Later |
| 94 | Egress broker, mission envelopes and grant frames; the Merkle disclosure privacy note | LATER | carry list | later | Later |
| 95 | Public conformance corpus and LIMITS | LATER | coverage audit | later | Later |
| 96 | Honey Pot absorb order (73 families); about 72 unpushed commits in an old private Prime checkout; the experience schema and dataset release; anti-self-consensus; dreaming as proposals; Prime's ideas ledger I-01 to I-19, each mapped to its brick on the issue | LATER | Prime North Star, plan/IDEAS-LEDGER.md | later | Later |
| 97 | Vision R&D: tokens (AUM and AURA), PALADIN, Manifold and URHE, the Shear Engine, Trader Helm, KNVS UI, the AUMA glyph language, Gaussian memory, mesh, Bhutan NDI, the MEGA-SPEC vertical packs and economics | LATER | iCloud vision documents | later | Later |
| 99 | Licence questions for counsel: the AUMA language (CC BY-SA or AGPL), and an Apache fork loading the AGPL engine | LATER | Prime I-14, carry list | later | Later |
| 100 | Post-quantum hybrid signatures (Ed25519 with ML-DSA-65, downgrade refused) and unlinkable scoped identities | LATER | carry list, Prime labs/pq-hybrid, aumlok-id #65 | later | Later |
| 101 | First Echo: keep or drop | LATER | Prime North Star wave 1, carry list | later | Later |
| 105 | Metal: a bare-metal authority kernel (Rust no_std hosting WASM proposers), collapse to touch, trust onto metal in trust order; ternary tesseract memory; Auma the field with agents as organs | LATER | Prime I-01, I-02, I-03, I-05, I-07 | later | Later |

## Who does what
- **Claude (SOVEREIGN MAIN):**
  - writes the scaffold: the tree, crate READMEs, types and signatures, checks, and an e2e test per milestone;
  - carries the RAN and SOURCE code over and fits it into the scaffold;
  - is the only one who merges to main, tests main, and drives the live nodes;
  - writes no feature code in a crate that a worker has claimed.
- **Codex workers (gpt-6.1-sol, ultra):**
  - each fills one scaffolded crate or folder, claimed on the README's board;
  - they write and compile only, and never test;
  - a diff that does not fit the scaffold is thrown away and rerun with a better brief, never patched.
- **Kimi:** completeness auditor. After every working day, checks this file, its issues and the repository against
  each other, and reports any missing, hidden or silently changed brick to Peter. Also owns the Spatial app port map.
- **Grok:** attacks the live node after each milestone: hostile guest, a secret leaking past the one link,
  self-approval.
- **WHIP CRACKER:** the watchdog. It checks every report and rule against what is really on main and on the node,
  and tells Peter directly.
- **NEBIUS:** the host and the Nebius VMs (Caddy, egress, spawn), read-only unless Peter says go.
- **CONTACT:** the co-presence portal and its port into `portal/`.
- **Mistral, Gemini (Argon) and Dot:** outside reviews whenever Peter shares the repository.
- **Peter:** the UX, the passkey, the spend, and "done".

## Rules (a machine enforces these: `checks/run.sh` on main; any failure means main is red)
1. One plan: this file. No other plan-like file anywhere.
2. Every row here has an open issue with the same number. A row and its issue leave only together, with Peter's
   words on the issue.
3. No committed `*.log`; no `*.txt` except listed data files (the AUMLOK dictionaries); no mutation output, and no
   evidence folders. Evidence stays on the node; its summary goes in the issue.
4. No authored file over 1,000 lines. Vendored imports are pinned by hash.
5. The app lock: every app and System entry above is registered, visible and opening on the installed node, with
   no 404.
6. One link: one public address per node; the owner origin never answers as a page.
7. Builds embed by relative path and content hash, with no absolute paths and no path into another repository.
8. Each crate depends only on what its README allows. The scaffold lock fails if a scaffolded piece disappears or an
   unplanned folder or crate appears.

**Working rules:**
- Code goes to main, and only main is tested. Nothing is tested anywhere else without Peter's direct approval.
- A red main stops features until it is fixed.
- Status changes only with evidence, posted on the issue in this form: `task / revision / evidence / result /
  blocker / next owner`.
- Only Peter closes a row as done.
- New ideas go on the README's IDEAS list with one question to Peter: "switch target or park it?"
- Replies to Peter are three lines: what's done, what's next, what needs his passkey.

## Say plainly to anyone shown this
- A passkey approval proves a passkey signed exact bytes after its user check, not which person pressed it.
- The record is tamper-evident to a stranger against a retained or witnessed head.
- A co-presence receipt is evidence and grants nothing.
- Whoever runs the server could read a running node until confidential VMs (row 88).
- Demoted memory is kept, not erased.
