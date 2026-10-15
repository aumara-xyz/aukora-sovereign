# AUKORA Sovereign: master plan (restart, 2026-10-15)

**What we are building:** [NORTH-STAR.md](NORTH-STAR.md).
**The approved technical spec:** master plan v0.2 of 2026-10-14, copied into [spec/SPEC-v0.2.md](spec/SPEC-v0.2.md) with
its contracts, carry list and coverage audit. Its security invariants carry over unchanged:
- the cage;
- one signed record;
- exact-bytes passkey approval, applied once;
- the phrase sealing a random root;
- encrypted memory;
- the 101-byte cell;
- the floor.

This file says what changed, the full checklist, who does what, and the rules.

## 1. Why we restarted: five failures, and the rule that now prevents each
| What went wrong in the archive | The rule now |
|---|---|
| A second app, the "owner page", next to the real one | **One node, one link.** The trusted pieces exist only as pop-ups inside the Spatial app. A check fails if the owner address ever answers as a page. |
| Half the Spatial app's plugins were hidden or dropped, so apps 404'd | **The Spatial app comes in whole.** A lock lists Peter's 16 entries; the build fails if one is missing, hidden or 404s. |
| A build cache shipped a stale UI to the live nodes all day | **Embeds by relative path and content hash; one source tree per build folder;** releases byte-compared from a pristine checkout. |
| 157 committed logs and evidence files, 187 mutation files | **Nothing generated is committed.** Evidence stays on the node; the README carries one status line per milestone. |
| Patch-on-patch, side testing, missed estimates | **Code to main; only main is tested,** by one runner; a red main stops features; progress is counted in milestones Peter watched, never hours. |

## 2. Architecture (spec v0.2, with one amendment: one link)
- **One trusted supervisor** process holds every authority: gate, aumlok, aura, kira, broker, floor, immune, messaging,
  invites. It is **wiring only**: it starts the organs and routes frames. Policy lives in the organ crates, never in it
  (the archive's 27,000-line supervisor is split).
- **Auma** runs the Spatial app's backend (the DeepSeek harness) inside the launcher's cage, as a different host uid,
  with no network. FD 3 is her only channel for proposals, model calls and memory; FD 4 serves the app.
- **One link.**
  - The person opens one address. The app is served there.
  - The trusted pop-ups (sign-in, claim, passkey enrolment, phrase, approval cards, AUMLOK) come from a separate,
    invisible owner origin, framed only inside the app. Framing is pinned by `frame-ancestors`; the passkey ceremony
    checks `topOrigin`.
  - The agent's code never shares an origin with a passkey ceremony or an owner session.
  - A brand-new node's claim also happens at the one link.
- **Laya** decides what pops up, by the owner's slider: everything, only risky things, or not within today's limits.
  The **gate** enforces it: a standing permission is signed once by fingerprint, scoped, counted and expires within
  24 h. Risky targets always pop up.
- **Nostr:**
  - each node has its own identity, bound to its record;
  - messages between nodes are gift-wrapped through relays reached by allowlisted egress;
  - contacts and sends are owner cards;
  - the record's head is witnessed on relays.
- **Growth:** an invite (signed, 48 h, three per member) unlocks one node. The Go Sovereign page spawns it with one
  click. The joining ceremony is co-presence with your own two devices, then your passkey and phrase. The node's first
  record names who invited it.

## 3. The repository
```
README.md        the target, milestone status, claim board, IDEAS
NORTH-STAR.md    what we are building (Peter's)
MASTER-PLAN.md   this file
spec/            the approved inputs: SPEC v0.2, CONTRACTS, CARRY-LIST, the coverage audit
crates/          canon aura gate laya aumlok kira broker wasmcell floor immune verifier pentora
                 nostr relay messaging invites copresence launcher frontdoor supervisor
app/             the Spatial app, whole: vendored, pinned, provenance recorded (no path into another repository)
owner-panes/     the trusted pop-ups only; never a page
guest/           the sandbox bridge (FD 3 client, model adapter, service adapters for the app)
portal/          the co-presence Point-and-Bloom page
ops/             spawn (LXD and Nebius VM), go-sovereign, upgrade, reproduce
checks/          the machine rules (section 6)
tests/e2e/       one test per milestone
```
Each crate has a README of 10 lines or fewer: what it owns, what it never owns, and which crates it may depend on.
No authored file is longer than 1,000 lines.

## 4. The checklist: everything, nothing dropped
Status: **RAN** = ran live on a node in the archive (the code is carried, and proven again here); **SOURCE** = built
and tested, not yet run live; **PORT** = exists in Prime, Contact or Buzz, to bring over; **BUILD** = designed, not
built; **LATER** = kept for after the milestones, never dropped. `checks/spec.lock` holds this list, and a row cannot
disappear without Peter's word recorded beside it.

| # | Capability | Status | Comes from | Lives in |
|---|---|---|---|---|
| 1 | The Spatial app, all 16 entries | PORT | Prime aukora-face + DSH harness, the commit the Nebius pilot runs | app/ |
| 2 | One link; sign-in, claim and pop-ups inside the app | BUILD (pop-ups RAN) | archive frontdoor, ui/owner panes | frontdoor, owner-panes |
| 3 | Approvals pop up by themselves, also while the agent is stopped | RAN | archive frontdoor holding page | frontdoor |
| 4 | App stays signed in across restarts | RAN | archive frontdoor sessions | frontdoor |
| 5 | Cage: namespaces, Landlock ABI ≥4, seccomp, cgroup, FD 3/FD 4 | RAN | archive launcher | launcher |
| 6 | Boot self-attack before every agent start | RAN | archive launcher probe | immune, launcher |
| 7 | Hostile-guest attack suite | RAN | archive tests + Grok | immune, tests |
| 8 | Gate: exact-bytes proposals, consume once, retire, recovery | RAN | archive gate | gate |
| 9 | Passkey-signed approval card (C5) | RAN | archive gate, aumlok | gate, owner-panes |
| 10 | Laya slider: three modes, standing permission | RAN (S2, by API) | archive gate standing | laya, gate |
| 11 | Laya triage (escalate-only) and the Chat/Build/Yolo modes | PORT | Prime lab | laya |
| 12 | Standing bounds (one signature, one folder, N commands) | BUILD | Buzz shim design | laya, gate |
| 13 | AUMLOK passkey enrolment and WebAuthn | RAN | archive aumlok | aumlok |
| 14 | AUMLOK acrostic phrase sealing a random root | RAN | archive aumlok | aumlok |
| 15 | Phrase refresh; passkey-bound backup (PRF) | SOURCE | archive aumlok | aumlok |
| 16 | Add a machine; pair a device by co-presence | BUILD | contact, archive #24 | aumlok, copresence |
| 17 | Delegation lineage and a revocation store | BUILD | kernel spec | aumlok |
| 18 | AURA: one signed record, two arms, export | RAN | archive aura | aura |
| 19 | Owner-browser head witness | SOURCE | archive ui/owner | owner-panes |
| 20 | Aura head witnessed on Nostr relays | RAN | archive relay | relay |
| 21 | Minimal verifier: aukora-verify plus verify.py, from an empty folder | RAN | archive verifier, tools | verifier |
| 22 | Pentora / Aura Coherence picture from the verified root | RAN | archive pentora, organs | pentora, app |
| 23 | KIRA: encrypted notes, demote, cited recall | SOURCE | archive kira | kira |
| 24 | Memory face in the app (Remembered, Forgotten) | SOURCE | archive guest memory route | guest, app |
| 25 | OpenViking recall by meaning inside the node, local embedder | RAN (S2, no notes yet) | archive openviking, ops scripts | kira, ops |
| 26 | Memory permissions (disclose done; store, dataset, export, train, activate) | BUILD | carry list | kira |
| 27 | Encrypted memory backup on relays and between own nodes | BUILD | Prime records plan | kira, messaging |
| 28 | Member exit: export everything, verify offline, restore | BUILD | carry list | supervisor, verifier |
| 29 | Broker: model key custody, passkey spend grant, receipts | RAN (S1, real DeepSeek reply) | archive broker | broker |
| 30 | WASM core: the 101-byte cell in the proposal path | SOURCE | archive wasmcell | wasmcell |
| 31 | Release floor and high-water marks | SOURCE (S2 install bugs fixed) | archive floor | floor |
| 32 | Immune: antibody ratchet on every release | RAN | archive immune | immune |
| 33 | Immune: thymus, MHC, hypermutation | BUILD | archive #42–44 | immune |
| 34 | Attack corpora (815 attacks, 81 aumlok issues, 5,360 Pentora vectors) | BUILD (locate first) | Prime lineage | immune |
| 35 | Nostr node and agent identities bound to the record | RAN | archive nostr identity | nostr, supervisor |
| 36 | Relay egress per relay | RAN | archive spawn | ops |
| 37 | Node-to-node gift-wrapped messages; contact and send cards | RAN (S2↔S4) | archive messaging | messaging |
| 38 | Messages face in the app | BUILD | Prime messages face | app, guest |
| 39 | Identity face (public contact card); contact codes and safety numbers | PORT | Prime aumlok face | app, nostr |
| 40 | Invites: signed, 48 h, three per member, first-record provenance | RAN (S2→S4) | archive invites | invites |
| 41 | One-command spawn: LXD and Nebius VM | RAN | archive deploy/spawn | ops/spawn |
| 42 | Go Sovereign page: paste a code, get a node | BUILD | — | ops/go-sovereign |
| 43 | Claim with the invite's secret, in the browser | BUILD | — | owner-panes |
| 44 | Co-presence portal, screen to screen | PORT (ran on Mac + iPhone) | aukora-contact portal | portal |
| 45 | Co-presence receipt verifier | SOURCE | archive copresence | copresence |
| 46 | Co-presence in the joining ceremony | BUILD | North Star | portal, invites |
| 47 | A second independent node passes the core lines (A4) | RAN in part (S2, S4) | — | tests/e2e |
| 48 | Upgrade without losing the binding; release switch with rollback | BUILD | archive scratch scripts | ops |
| 49 | Reproducible build and byte-compare | SOURCE | archive reproduce.sh | ops |
| 50 | Pin-drift check on the launcher and policy | BUILD | carry list | checks |
| 51 | Live posture rows | BUILD | archive #26 | immune |
| 52 | Recursion v0 (replay first) | BUILD | archive #28 | later crate |
| 53 | Auma Live voice | PORT | Prime voice | app |
| 54 | Phone approval (NIP-46), Buzz relay under the node | LATER | Prime, Buzz | — |
| 55 | Confidential VMs ("we cannot see inside") | LATER | — | ops |
| 56 | Hardware keys, succession, witness committees | LATER | carry list | — |
| 57 | Desktop app, phone, AR | LATER (browser first, Peter 10-13) | — | — |
| 58 | Vision R&D: tokens, PALADIN, Gaussian memory, mesh | LATER | iCloud docs | IDEAS |

The archive's unfinished builder work on 2, 27, 28, 42, 43 and 50 was discarded when it froze; those rows are BUILD.

## 5. Who does what
- **Claude (SOVEREIGN MAIN):**
  - writes the scaffold today: tree, crate READMEs, workspace, checks, e2e skeleton;
  - carries the RAN and SOURCE crates over;
  - is the only one who merges to main and the only one who tests main and drives the live nodes;
  - reports to Peter in three lines: what's done, what's next, what needs his passkey.
- **Codex workers (gpt-6.1-sol, ultra):**
  - each fills one scaffolded crate or folder, claimed on the README's board;
  - they write and compile only, and never test;
  - a diff that does not fit the scaffold is thrown away and rerun with a better brief, never patched.
- **Kimi:**
  - completeness auditor: after every working day, checks NORTH-STAR and this checklist against the repository, and
    reports any missing, hidden or silently changed row to Peter;
  - owns the Spatial app port map.
- **Grok:** attacks the live node after each milestone: hostile guest, a secret leaking past one link, self-approval.
- **WHIP CRACKER:** the watchdog. It checks every report and rule against what is really on main and on the node,
  and tells Peter directly.
- **NEBIUS:** the host and the Nebius VMs (Caddy, egress, spawn), read-only unless Peter says go.
- **CONTACT:** the co-presence portal and its port into `portal/`.
- **Mistral, Gemini (Argon) and Dot:** outside reviews whenever Peter shares the repository.
- **Peter:** the UX, the passkey, the spend, and "done" on every milestone.

## 6. The rules a machine enforces (`checks/run.sh`, run on main; any failure means main is red)
1. No committed `*.log`; no `*.txt` except the listed data files (AUMLOK dictionaries); no mutation output and no
   evidence folders.
2. No authored file over 1,000 lines. Vendored imports are pinned by hash.
3. `checks/spec.lock`: every row in section 4 maps to its path. A row cannot be deleted without Peter's recorded word.
4. The app lock: Peter's 16 Spatial app entries are registered, visible and open on the installed node, with no 404.
5. One link: the deployment renders one public address per node, and the owner origin never answers as a page.
6. Builds embed by relative path and content hash: no absolute paths, and no path into another repository.
7. Each crate depends only on what its README allows.
8. Pins on the launcher and policy are re-reviewed when they change.

**Working rules:**
- Code goes to main; tests run on main only.
- A red main stops features until it is fixed.
- New ideas go on the README's IDEAS list with one question to Peter: "switch target or park it?"

## 7. Order of work
1. **Now:** Claude writes the scaffold and Peter says yes to the tree.
2. Claude carries over the RAN and SOURCE crates.
3. Codex fills supervisor, frontdoor, laya, messaging, invites, owner-panes and guest.
4. The Spatial app is imported whole.
5. **A fresh node boots with the whole app at one link: milestone 1** in [NORTH-STAR.md](NORTH-STAR.md).
6. Then milestones 2 to 7 in order. Each lands on main, is tested live, is attacked by Grok, and is watched by Peter.
