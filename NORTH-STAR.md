# AUKORA Sovereign: North Star

**This file is the one plan.** Part 1 is the current direction, approved by Peter on 2026-10-17: Plan v1 merged,
with Kira 2 as phase 1. Part 2 is the row register the checks read; where Part 2 disagrees with Part 1, Part 1 wins.
Peter's reversals (2026-10-16): the DeepSeek Harness is the engine (not our own harness), Auma executes commands and
opens sockets, and working code is copied, not rewritten.

# Part 1: the plan (2026-10-17)

## 0. What changed, in one place (Peter's decisions 2026-10-16, from PLAN-v1)
PLAN-v1 reverses main's "our own harness replaces the DeepSeek harness" and "Auma never executes". The spine of the
plan is unchanged: one human-held identity, the Golden Boundary, receipts a stranger can check, evidence ≠ authority,
the Pentora shape, the milestones M1–M8. What changes is **how the engine is built and walled**.

**[REVERSAL 1]** The engine is now the **LATEST DeepSeek Harness**, pinned and patched (≤3), with our UI/apps as DSH
plugins — NOT a fresh ~5–10k-line Rust harness. (Reverses NORTH-STAR "Our own harness replaces the DeepSeek harness".)
**[REVERSAL 2]** **Auma runs commands, opens sockets and builds.** (Reverses "She never executes a command or opens a
socket. Seccomp denies execve/execveat".)
**[REVERSAL 3]** **"Nothing is copied" is relaxed to "copy what works, rebuild the rest properly".** (Reverses "Fresh,
every line… Nothing is copied".) Code may be copied where it works; the rest is rebuilt.
The security model is unchanged and in fact strengthened: the engine is treated as one hostile process, walled by the
OS; Rust outside the wall holds the keys and re-verifies exact bytes. Capability goes up (a real IDE agent), security
stays (the wall + the door + the passkey).

---

## SECTION REWRITES

### A. "The Spatial app is the organism" → harness + Auma-executes (REWRITE)
**DELETE** the subsection "**Our own harness replaces the DeepSeek harness**" and its bullets ("about 380,000 lines…",
"Ours is Auma's agent loop inside the cage", "She never executes a command or opens a socket. Seccomp denies execve
and execveat", "It is one static Rust binary… 5,000 to 10,000 fresh lines"). *Why:* [REVERSAL 1,2] — superseded.
**CHANGE** to:
> **The engine is the DeepSeek Harness, walled.** Auma is a full IDE agent on the latest DSH (pinned by release tag,
> ≤3 patches in a ledger, a rehearsed weekly re-pin), with Cordis as its plugin kernel. Our Spatial app, faces and
> apps are DSH plugins. **Auma really executes**: files, shell, subprocess, sockets, git, compilers, tests and a
> persistent browser — all **inside the cage** (OpenShell enforce), where there are no keys, no identity and no live
> node. The whole DSH process tree is treated as one hostile process.
> **Two modes stay:** Chat (she talks) and Build (she may propose changes to herself, sites or apps). The difference
> from before: Build work *runs* in the workspace; only **crossings** (landing on the live node, spending beyond a
> grant, outbound beyond the allowlist, sending as the owner, identity/plugin changes, shared-memory writes) need the
> door and the passkey.
> **The Laya slider** stays in the right lane: ask for everything / only for risky things / within today's limits.
> Ship the starter at "only risky things".
Keep the tri-pane subsection unchanged (**KEEP**). Keep "The walls stay walls inside the organism" (one link / owner
origin / site, three hosts) unchanged (**KEEP**) — but see the FD4/FD3 change in section C.

### B. Rings and the door (REWRITE of "How it fits" + the launcher parts)
**CHANGE** the architecture to three rings + one door (PLAN-v1 Architecture):
> - **Ring 1 — the whole DSH process tree** (engine + Cordis + plugins) inside **OpenShell enforce** (a verified
>   effective policy, Landlock hard_requirement, a Linux provider), plus the launcher's netns/userns/pidns, a seccomp
>   allow-list and `close_range` to only {0,1,2, door socket}. Treated as hostile. No keys, no identity, no live node.
> - **Ring 3 — Rust**, separate processes outside the cage: supervisor, gate, AUMLOK, Aura, broker, Kira store,
>   verifier, frontdoor. The only holder of keys; the only thing that changes the live node, spends, or speaks as the
>   owner. Frontdoor stays the outer TLS proxy; the owner card stays on the owner origin.
> - **The door** — an **outermost DSH `tools/execute` wrapper** that re-digests the exact bytes and sends them to Rust
>   over a **SO_PEERCRED-checked unix socket**; Rust returns the authored result. **Rust hashes what IT executes,
>   never a digest from Ring 1.** The in-process wrapper is a classifier/UX hook, **not** a wall — SCOUT counted 11+
>   in-process bypasses and Auma found a judge-then-swap window, so the boundary is the OS wall + the Rust re-check,
>   never the guard.
> - **WASM** is a deterministic policy capsule (its hash in every receipt) and WASI plugins for small extensions; it is
>   **not a wall**.
**NEW rule (from the toy):** bulk payloads cross as a **sealed memfd** handle, fixing the 64 KiB FD3 frame cliff
(`crates/canon/src/frame.rs:19` MAX_FRAME_BYTES=65_536, RAN). Control frames stay ≤64 KiB.
**CHANGE** the "One trusted supervisor / FD3 / FD4" bullets: FD3 still carries proposals, model calls and memory, and
the supervisor is still its only reader — **but Auma also executes**, so the cage gets a second **engine profile**
that allows `execve`/`execveat` for a **pinned toolchain** (digest allow-list; idea from aukora-kernel's exec
chokepoint) and a restricted socket set (door + broker). *Why:* [REVERSAL 2].
**RAN:** `profiles.rs` has only `Auma`/`UserApp`/`Disposable` — **no engine profile exists**, so this is net-new.
The clean-room builder primitive **does** exist (`cage.rs:232 run_disposable`) but is **disabled by default** (`:239`)
and runs one inert preselected command with no shell (`:199`) — T1 widens/configures it, it is not a build container yet.
**Argon's 5 seam bugs** (frame cliff, judge-then-swap, FD3 envelope, reverse-proxy routing, UI clickjack) are tracked
in an earlier private review and must be closed as part of the door/adapter work.
**DELETE** "`bridge/` is retired" only if it conflicts (KEEP otherwise). **KEEP** "FD 4 carries data only".

### C. Plugin admission (NEW subsection — closes the SCOUT/HMR hole)
> **Plugins load only after the owner's passkey approves their fingerprint.** Rust assembles the plugin set (the set
> hash is pinned in the floor), and **HMR / Creator-mode / cordis.patch.yml are off for authority contexts**. A new or
> unmatched plugin path fail-closes to "pause for owner classification" (idea: aukora-kernel policy-rings). *Why:*
> PLAN-v1 decision 5; the toy's B12/B14 show plugin_manager install and cordis.patch.yml HMR are live bypass routes.

### D. Laya (REWRITE of rows 36–38 + the "Laya as a judge" caution)
**CHANGE** Laya to **escalate-only risk router**:
> Rust computes the floor; **Laya can only raise it, never lower it, never approve** (monotonic, like DSH's deny-only
> ToolGuard). v1 is **deterministic rules**; a local classifier is added only if it **beats the rules** on a labelled
> crossing corpus. The rules see only the crossing descriptor (effect class, target, declared capability, diff size,
> digest, whether bytes match an approved set, memory provenance). **Never-see:** raw secrets/keys, passkey material,
> secret-path file contents, private memory bodies (hashes/labels only), the never-touch list.
> **Bug (fixed):** the triage ASCII-only gate (`!text.is_ascii()` in `note_needs_review`, `crates/laya/src/triage.rs`)
> forced a card on any emoji/accented/CJK text. Commit 2659f09 narrowed it to a few direction and zero-width characters,
> which lost coverage; `crates/laya/src/screen.rs` now escalates on the Default_Ignorable code points, C1 controls,
> U+2028/2029, interlinear annotation, private use, noncharacters, tag characters and variation selectors, counts
> non-ASCII spaces in the whitespace-padding rule, and folds Cyrillic, Greek and fullwidth lookalikes (and hyphen
> variants and space runs) before the injection-phrase match. Ordinary UTF-8 (em-dash, accents, CJK) passes. (PLAN-v1
> decision 6.)
> **Bug 2 (RAN):** the risk **slider collapses** — `AskRisky` and `WithinTodayLimits` behave identically;
> `candidate()`/remaining-count only special-case `AskEverything` (`crates/laya/src/standing.rs:287`). Two of four
> slider positions are a no-op. Give each mode a distinct floor before shipping the slider.
> **Bug 3 (RAN):** standing grants only accept `kinds == ["put"]` (`standing.rs:164`); there is **no grant shape for
> read/exec/socket crossings** — the 6 crossing classes the router needs do not exist yet.
> **Do not conflate** with "Laya the navigator" (the memory experiment's retrieval approach, which LOST to plain hybrid
> retrieval + a cross-encoder). Laya here is the *risk* router only.
**KEEP** "Laya as a judge" in the "Never claim" list (it is still never a judge).

### E. Nostr (REWRITE of the Network section + rows 69, 87, 123)
**CHANGE** to PLAN-v1 decision 7:
> **Nostr is the fabric for messages and provenance, never authority** (the passkey signs approvals; a Nostr signature
> proves authorship, not authority). **Each device gets its own secp256k1 key under an owner-signed certificate**
> (reuse Aura's MembershipSet), held in a signer **outside the agents**; passkey-signed delegation records (pubkey,
> scope, expiry, nonce) and passkey-signed revocation are the control plane. **First slice:** node↔phone pairing + one
> approval. **Marmot/MLS** (NIP-EE is superseded by Marmot, adopted 2026-07-03, but experimental/unaudited — SOURCE)
> for device/group channels **later** — pin MDK, expect breaking changes. [REVERSAL: none; this refines rows 69/87/123.]
**KEEP** rows 123 (Marmot), 132–134 (bitchat) as LATER.

### F. Kira 2: one shared memory for every agent (REWRITE of rows 57–61, the Kira section, decision 8) — v3
> Full design: the Kira 2 spec v0.3 (private, not yet published). This section only says what it does to the plan.

**CHANGE [REVERSAL 4, refined]:** the shared brain is **Kira 2**, not OpenViking. Every agent (Claude, Codex, Grok,
Argon, Mistral, Dot, then Auma through the door) reads and writes **one signed, append-only memory** through one
service; Auma has **read and write in her own attributed scope** (`remember` is own-scope only) — not read-only.
**OpenViking is archived, not deleted** (do not upgrade 0.4.21 for this purpose; AGPLv3, no provenance, no read-only key,
an LLM that rewrites memory on session commit — SOURCE: a private research note, SCOUT round 2 §8).
> **What it is.** A SQLite file with FTS5 + dense embeddings + a cross-encoder, notes as Nostr events signed per agent,
> six tools (`remember`, `recall`, `get`, `list_recent`, `supersede`, `quarantine_source`), six permissions with the
> exact wire names (`store`, `disclose-to-context`, `dataset`, `export`, `train`, `activate`), all default-deny, a
> closed `capture_source` set (owner-typed | owner-signed | tool-observed | web-derived | model-generated) clamped by
> caller class and inherited by descendants, ancestry roots computed by the store, verify-on-read with a hash chain,
> fixed `self`/`resume` slots by d-tag, honest `found | empty | undetermined`, and an Aura-anchored head.
> **Two phases, one surface.** Phase M (Mac, now): standalone `kirad` service, local-root key, no Aura, owner entries
> are `channel`-attested and flagged. Phase N (node): the same events, tools and tests on the Sovereign node, backend =
> the Aura-anchored sealed store (`crates/kira/src/anchor.rs`), AUMLOK certification, the signer inside the supervisor.
> "Unchanged later" holds for the event format, tools and tests, **not for storage**.
> **Rules that stay:** memory is context, never authority (`Source::Memory`); an author signature proves who wrote it,
> not that it is true; never edit, never delete — supersede, expire, quarantine by source. A shared-memory write is a
> crossing when it is not in the caller's own scratch scope (the door sees it; tainted lineage escalates).
> **Rules that change (need Peter):** a new owner-only **erase** (physical purge / crypto-shred) against the
> 2026-10-14 "forget = demote, never delete" doctrine (SPEC-v0.2.md:259, NORTH-STAR.md:769); see decision list.
**CHANGE** the old F bullets: "Index + dedupe first" is now Kira 2 step K1/K2 (the 626 notes become epoch-1,
`model-generated`, import-attested; no imported note may sit in the commitments lane until an owner-signed manifest
promotes it); "hash-linked summary" survives only as a derived record with source hashes, never a search layer
(summaries lowered recall: 0.874 vs 0.911); "forgetting = demote + tombstone that refuses re-ingest" stays.
**CHANGE** "Kira: encrypted memory, cited recall, forgetting demotes, nothing silently deleted": **KEEP in Phase N**
(per-note wrapped keys, derived indexes only at unlock); Phase M is plaintext inside the disk boundary by design.
**DELETE** the old fix row "TLS/unix-socket + auth for OpenViking" (OpenViking leaves the path); **KEEP** "raise or
parameterize the 4096 caps (`notes.rs:22`, `recall.rs:23`)" — the largest imported field is 2,448 bytes today, so
charters and the plan need chunking.

### G. Order of work (REWRITE — adopt PLAN-v1's 0–6 over the old waves, keep the acceptance discipline)
**CHANGE** the "What Peter watches" / wave plan to PLAN-v1's order, with the toy as the decision gate:
> **0. Toy boundary** (/workspace/toy-boundary) on a Nebius test node: hostile plugin first (SCOUT's 13 + judge-then-
>   swap + hostile postinstall + B12–B14), 20 real builds, a **negative control** that must FAIL with the wall off.
>   This is the decision gate for the whole engine choice. (Ready now; RAN on the box.) **Runs in parallel with step 1;
>   neither blocks the other** (Kira 2 does not depend on the engine).
> **1. PHASE 1 — KIRA 2: memory first, every agent on one memory** (row 142, sub-items K2-01..K2-17, section J; spec
>   the private Kira 2 spec v0.3). Order: K1 inventory/snapshot/manifest (Peter approves) → K2 append/verify/tools/owner
>   channel + the **figurine test early, FTS-only** → K3 permissions + quarantine + fail-closed egress guard → K4 hybrid
>   + rerank recall, locked threshold, Test 4 (paired non-inferiority, ≥300 questions) → K5 `self`/`resume` slots + the
>   DSH client plugin + door forwarder → K6 wire every agent through the stdio bridge, atomic cutover, Pentora health +
>   `stop` gating → K7 erase (only if Peter says yes) → K8 Phase N (Aura-anchored backend, AUMLOK re-certification).
>   This absorbs PLAN-v1's old "Auma's self, early" step (memory indexing/dedupe, evidence-vs-experience split, signed
>   self file, resume brief, reserved lanes, figurine test).
> **2. Engine in walls on a node + the door + Rust rebuild + the plugin-fingerprint gate → T1, T2.** (Auma uses Kira 2
>   through the door from here on: the engine never holds the Kira token and cannot reach `kirad` directly.)
> **3. Fix the Rust blockers** (item 4: GuestPlan, engine cage profile, FD3 memfd, multi-stream, Laya triage; the Kira
>   caps now belong to step 1) + **add real tests (main now has 199 `#[test]` functions in 5 of the 20 crates — floor, gate,
>   kira, laya, supervisor; the other 15 have none — RAN, counted 2026-10-17).**
>   Note (updated): the source scan allows unit tests in `src` (`#[test]`, `#[cfg(test)]`; `checks/walls.py:126`, Peter
>   2026-10-17); cargo test and bench TARGETS (a crate `tests/` or `benches/` directory) still fail the `no-test-suites`
>   check (`checks/run.py:806-807`). "Add real tests" therefore means unit tests inside `src`, or `tests/e2e` scripts
>   (Kira 2 chooses the scripts).
> **4. The Spatial app as DSH plugins (keep what's ported), onboarding v2, Nostr devices, phone → T4, T7.**
> **5. Selective-disclosure receipts (salted commitments) before formats freeze → T5; other harnesses → T3; website → T6.**
> **6. Later:** Auma fine-tunes her own model on receipted, attributed data (GPUs + Peter's OK; held-out anti-poison tests).
**KEEP** the acceptance discipline (section "Acceptance follows the whole chain"), the hostile twin per milestone, and
"code goes to main, then main is tested". **KEEP** M1–M8 as the product-facing milestones; they map onto steps 2–6.

### H. Product tests (CHANGE — adopt PLAN-v1's crisper T1–T7 + the budget)
**CHANGE** the test definitions to PLAN-v1:
> T1 Build: Auma builds through a passkey on the **source change + build recipe**; **Rust rebuilds it in a throwaway
>   builder (two hosts, digests compared)**. T2 Wall: hostile engine + plugin + build input + injected page → zero
>   canary leaks, zero unapproved crossings, every crossing receipted; **a negative control must FAIL with the wall
>   off**. T3 any harness. T4 one mind (attributed memory, rollback by source, honest "I don't know"). T5 stranger
>   verifies offline **with selective disclosure**. T6 website→working Auma unaided. T7 phone approves.
> **Interruption budget (NEW):** ≤5 owner cards/day, ≤2/hour, **0 for workspace work**; build within the wall ≤1.5×
>   bare metal.
**KEEP** "every report starts with the product tests".

**ADD (2026-10-17): the 2026-09-29 composable runtime spec v0.2** (`spec/COMPOSABLE-RUNTIME-SPEC-v0.2.md`, frozen,
historical requirements, never a plan of its own) has 92 conformance cases: B01–B52 + O01–O40 (52 + 40; spec lines
20, 1840). Its §14.4 is a conservation constraint (phrase-only recovery needs other retained state, a party or a
higher-entropy secret), not a requirement; recovery and hardware cases (B51, O39, §14, §20.20) stay out of scope.
Mapping onto this plan (SRC source, ISO isolated/assembly test, DEP deployed on a node, OPEN, SUP superseded):

| Spec cases | Here | Status |
|---|---|---|
| B01/B02, O01–O05 | T1/T2, the rehearsal node | ISO (T2: 20/20 builds, 0 escapes) + DEP partial; **deployed B01/B02 pair OPEN — the gate before T1 is claimed** |
| B06–B08, O35/O36 | build contract (`crates/supervisor/BUILD.md` §7) | SRC + ISO; builder, orchestrator, release hook OPEN |
| B09/B10, B28/B29, O21, O25 | door call-id ledger (forgets old segments by design) + durable approval consumption, broker spend journal | SRC + ISO; B09 rests on approval consumption, not the ledger alone; broker OUTCOME_UNKNOWN (B29) OPEN |
| B24–B27 | gate card, stranger's verifier | SRC; verifier `display_sha256` check OPEN (row 52) |
| O08–O09, O34 (part) | OpenShell gateway (mTLS, root-only port), startup effective-policy verify (`engine-run.sh:46`) | SRC + DEP for the startup check only; uid 65534 reach and runtime policy drift OPEN |
| O26–O30 | approved control-plane mutation, route inventory, revision checks, activation reconciliation | OPEN |
| O15/O16/O19 | the broker (key outside the wall, approval by digest) | SRC + ISO + DEP (fake-key 401) |
| B38–B40 | Kira 2 | supersede/quarantine + recall moving corrected notes out of live candidates: SRC + ISO (`service/mod.rs:643`, `hybrid.rs:484`); OPEN: agents actually invoking supersede, the installed High→Medium case, empty sources becoming a self-root (`store.rs:386`) labelled "independent" (`recall.rs:62`), "no recorded overlap" wording (K2-18) |
| B37/O38 | private material into the inference route (the broker forwards `messages`/`system`, checks shape, model and budget only: `engine_link/request.rs:12,74`) | Peter 2026-10-16 approved provider data; OPEN: a synthetic private-memory sentinel proves owner-local/private-scope notes never reach the broker |
| O10–O12, O17/O18 | crossings go through the door, not OpenShell middleware | mechanism SUP; invariants retained: fail-closed coverage and final object binding tested at the door/executor |
| B20–B23 | Laya is a deterministic slider + standing grants, not a semantic assessor | mechanism SUP; invariants retained: no assessor authority, binding, policy denial (`door/standing.rs:384`) |

**KEEP** T2 as defined (hostile plugin, postinstall and injected page; 20 real builds in the wall ≤1.5× bare metal; a
negative control that fails with the wall off) and re-run it for every engine or OpenShell change.

### I. "How it is built" (CHANGE — the three reversals land here)
**CHANGE** the "Fresh, every line… Nothing is copied" bullet to:
> **Copy what works; rebuild the rest properly.** The archive and Prime are the source; a worker may **copy working
>   product code** (e.g. the Spatial app faces as DSH plugins) and rebuilds the rest fresh against the frozen
>   contracts. A rewrite still needs Peter's yes. [REVERSAL 3]
**CHANGE** "Only data comes over as it is" → keep the pinned-data list, but it is no longer the *only* thing that
crosses (product code may be copied). **KEEP** "Code goes to main, and main is tested after it lands" and the deploy
guard rules unchanged.

### J. Phase 1 rows: Kira 2, memory first (NEW section, v3)
Row 142 is Kira 2 in the register (row number = issue number); `K2-NN` are its sub-items, kept provisional until each gets
its own issue. Milestone column is the step in section G. Every row's acceptance is a `tests/e2e/kira2-*.sh` script on the
installed service (spec §13); none is a Rust test target. Status BUILD unless stated.

| Row | What | Depends on | Acceptance (spec §13) | Notes |
|---|---|---|---|---|
| K2-01 | **`kirad`**: standalone service, SQLite+FTS5 backend, unix socket (0600) + per-agent token + `SO_PEERCRED`, six tools, MCP/HTTP surface; new crate (scaffold, walls ALLOW net, clippy, deps pins) | K2-02 | 1, 2, 10 | `crates/kira` stays a pure library (`Store`/`Signer` traits); `embed.rs` TCP/rustix modules move behind traits or are the documented exception |
| K2-02 | **Event format + closed tag sets + vectors**: kinds 30401-30407 in the spec, but `crates/kira/src/shared/note.rs` on main uses 4500-4502 (note, supersede, quarantine), so reconcile before pinning, `capture_source`/`lane`/`privacy`/`form`/`review_state` closed sets, lane×capture rules, ancestry roots computed by the store, taint inheritance; pinned data files | — | 11, 12 | New data pinned in `checks/pins.json`; imports map to `model-generated` + `import_attestation` |
| K2-03 | **Chain, verify-on-read, signed heads** (Phase M local-root checkpoint; Phase N Aura `kira.head`) | K2-01 | 1, 16 | New Aura kind needs an issue, `schema.rs` CHECK, `coverage.rs`, re-pin (C8); batched, never one Aura row per query |
| K2-04 | **Caller identity + signing oracle limits**: per-agent keys, local-root certificates (Phase M), AUMLOK re-certification via migration manifest (Phase N), `nostr.bind` v2 (list body) + gate inventory targets | K2-01 | 10 | AUMLOK certification is not approvable today (`keys.rs:198`, `identity.rs:35,41`, empty inventory); Phase N moves the signer into the supervisor (NORTH-STAR.md:290) |
| K2-05 | **Permissions**: six exact wire names, default deny, owner-signed grant manifest (Phase M), new canon principal + v2 permission body (Phase N) | K2-02 | 7 | Dataset/Train/Activate have no call sites on main today; Kira 2 enforces all six from day one |
| K2-06 | **Recall**: FTS5 + dense + cross-encoder, reserved lanes (commitments, owner words, own experience, relevance, superseded/quarantined stubs), tie-break by id, locked calibrated no-answer threshold, embedding model hash pin + rebuild | K2-01 | 3, 4, 9, 15 | Laya NOT in the path (measured: lower recall) |
| K2-07 | **Model servers out of process** (embedder + cross-encoder as units), pinned flags, startup and RSS measured, **FTS-only degraded mode** | K2-06 | 5, 8 | No process spawn from the crate (walls.py:12) |
| K2-08 | **`self` / `resume` slots by d-tag**; deterministic resume generator in Ring 3; DSH injection as a system-prompt section (`interpolate:false`) + idempotent `agent/pre-step` re-injection | K2-01 | 17, 18 | Sizes: self 4 KB, resume 2 KB, outside the 4,800-char recall budget |
| K2-09 | **DSH Cordis client plugin + door forwarder**: native plugin over the door socket, no token in the engine, capture clamp + web-derived by tool allowlist and turn taint, `undetermined` on door outage, read-only `DSH_HOME`, session-search off | K2-01, K2-08, step 2 door | 18 | Stock MCP cannot reach a unix socket (`transport.ts:31-45`); new versioned memory frame in Phase N (`fd3_payloads.rs:365-372`) |
| K2-10 | **`kira-mcp-bridge`** (stdio↔unix socket) and onboarding of every agent: Claude Code, Codex, Grok, Argon, Mistral, Dot; atomic cutover from the old stores | K2-01 | 2, 19 | Neither Claude Code nor Codex offers a unix-socket MCP transport |
| K2-11 | **Epoch 2**: snapshot every store with hashes, archive epoch 1 (searchable, `epoch=1`), Epoch 2 manifest by rule (Peter approves), owner-signed promotion into the commitments lane, secret scan | — | 3 | 626 notes, all `AUKORA-BUILD`, no ids/signatures [RAN]; old North Star rows (139) and chatter stay in the archive |
| K2-12 | **Test 4 protocol**: ≥300 stratified questions incl. unanswerable and superseded/quarantined, pinned models and rubric, paired baseline on the same import, non-inferiority margin 3 points one-sided 95% | K2-06, K2-11 | 4 | 59 questions cannot show "within 3 points at 95%" (Grok's own CI −6.8..+1.1) |
| K2-13 | **Quarantine + supersede + source revocation** (`quarantine_source` is an owner/door action) | K2-01 | 6 | Withheld from the agent tool scope with `ctx.tools.restrict` |
| K2-14 | **Fail-closed egress guard** (`egress_check -> Exportable`) shipped before any sync code; sync = signed one-way bundle pull, later | K2-01 | 13 | `local` and unknown privacy never exported |
| K2-15 | **Memory health on Pentora + `stop` gating**: reuse INDEX_PIN / AURA_ANCHOR / RECORD_FORMATS (no free cell) or version the registry; the door consults `kira.health` before crossings that rely on memory | K2-01, step 2 door | 20 | Row 115 "freezes all 110 check ids"; cells ≠ Pentora trits |
| K2-16 | **Erase** (owner-only; Phase N crypto-shred, Phase M purge + redaction record) | Peter's decision | 14 | Contradicts "demote, never delete"; archives and exports escape; new Aura kind |
| K2-17 | **Phase N migration**: Aura-anchored sealed backend behind `Store`, derived indexes only at unlock, rows 57-61 re-issued, Laya memory-write crossing (escalate-only) once standing grants exceed `put` | K2-03, K2-04, K2-05 | all 20 re-run | Storage is NOT unchanged across phases |

**Existing rows touched by Kira 2** (mapping done against main `b79695e`, SOURCE = SCOUT integration check):
57 Kira notes/recall — CHANGE (Phase N backend; Phase M `kirad`); 58 OpenViking recall by meaning — **DELETE** (OpenViking
archived; recall is hybrid in Kira 2); 59 memory permissions — CHANGE (per-agent principal, exact wire names, manifest);
60 encrypted memory backup on relays — CHANGE (export gated by the egress guard); 61 member exit export — CHANGE
(re-check if erase lands); 7 the Memory app — KEEP; 128 supervisor is the only reader of FD 3 — KEEP via proxy
(versioned memory frame); 130 sessions/compaction — KEEP (DSH sessions stay separate from Kira); 69 Nostr identities —
CHANGE (per-agent keys under a certificate; Phase M local-root); 115 Level 1 organ map — CHANGE (memory-health cells);
116-117 health view — KEEP; 15, 98 — KEEP.

---

## ROW-BY-ROW DISPOSITION (deltas only; unlisted rows = KEEP as in main)
| Row(s) | Disposition | Note |
|---|---|---|
| Rows 1–13 (Spatial app + faces) | **KEEP** | Now shipped as DSH plugins (section A), not under our own harness. |
| Rows 15, 98 (plugin/package accounting) | **CHANGE** | Re-map: the plugins that "replaced DSH" (our-harness era) are reframed — DSH stays; our crates are the **authority ring**, not a harness replacement. |
| Row 25 (workers 29, 30) "The harness: transport, agent loop, dispatch, sessions, compaction" | **DELETE** | *Why:* [REVERSAL 1] — we don't build our own harness; these become "DSH plugin adapters + the door wrapper" instead. Re-issue as door/adapters rows. |
| Row 26 (worker 22) "the cage and its profiles" | **CHANGE** | Add the **engine profile** (execve-allowed, pinned toolchain) beside the no-exec profile. [REVERSAL 2] |
| Rows 26, 39 (worker 22) sub-cage for running code | **KEEP** | Still owner-gated (decision 9); now the *engine* runs by default, the *user-app* sub-cage stays off until Peter says. |
| Rows 32–34, 40, 41, 112 (canon, gate state machine) | **KEEP** | Add the crash-window durability test (item 3 #3). |
| Rows 36–38 (Laya) | **CHANGE** | Escalate-only risk router; the ASCII bug is fixed and its coverage restored (section D). |
| Row 141 (the door; builds on row 33) | **NEW** | Add the **door**: tools/execute wrapper + SO_PEERCRED unix socket + Rust re-digest + memfd bulk path. |
| — | **NEW** | **Plugin-fingerprint admission** row (passkey-approved set hash in the floor; HMR off). Section C. |
| Rows 57, 59 (Kira notes/recall/permissions) | **CHANGE (v3)** | Phase 1 = Kira 2 (row 142, section J, sub-items K2-01..K2-17): raise/chunk the 4096 caps; hybrid+cross-encoder recall; per-agent principal, exact wire names, default deny; attributed Auma write lane in her own scope. |
| Row 58 (OpenViking recall) | **DELETE (v3)** | OpenViking is archived, not deleted; recall is Kira 2's FTS5 + dense + cross-encoder. The v2 "TLS/unix-socket + auth for OpenViking" fix row is dropped with it. |
| Rows 60, 61 (backup on relays, member exit) | **CHANGE (v3)** | Export only through the fail-closed egress guard (row 142, K2-14); re-check member exit if erase (row 142, K2-16) is approved. |
| Row 142 (sub-items K2-01..K2-17) | **NEW (v3)** | Kira 2 shared memory; the sub-items are section J. |
| Rows 62, 63, 129 (broker, model streams) | **KEEP** | Add: the broker is an allowed-egress exfil channel → data-class labels later. |
| Row 69 (Nostr identities) | **CHANGE** | Per-device key under owner cert; delegation/revocation records (section E). |
| Row 87 (phone approval NIP-46, buzz) | **CHANGE** | First slice = node↔phone pairing + one approval; promote from LATER into step 4. |
| Row 123 (Marmot) | **KEEP (LATER)** | Device/group channels later; experimental. |
| Row 128 (supervisor FD3 router) | **CHANGE** | Add memfd bulk + multi-stream (item 4 #3,#4). |
| Row 130 (sessions/context/compaction) | **CHANGE** | Now provided by DSH, not our harness; row becomes "configure DSH sessions + our continuity (signed self file, resume brief)". |
| Row 138 (model intake) | **KEEP** | Immune attacks the cage with the new model driving before grants. |
| Row 139 (crypto agility) | **KEEP** | Add ML-DSA sandbox signer idea (item 3 #8). |
| "Decisions only Peter makes" | **KEEP + NEW** | Add: whether the phone may approve node changes and at which risk levels (already flagged in main); the DSH pin cadence. |
| "Never claim" list | **KEEP** | Still: no Laya-as-judge, no Pentora-as-security, no unique-humans, etc. |

## Open conflicts for Peter/Claude to resolve
1. ~~**Row-number mismatch**~~ **RESOLVED (v2):** Claude confirms 187/192 are **LINE numbers** in NORTH-STAR.md
   (the harness subsection, lines ~186–195), not rows. Reversals 1–2 target exactly those lines. No action needed.
2. **"One plan, no other plan-like file" construction check** (main rule 1) will go red while PLAN-v1 exists — delete
   PLAN-v1 as planned once this draft is committed.
3. **AGPL:** OpenViking is AGPLv3 and a hosted multi-tenant node touches §13 — a licensing decision before Light/hosted.
4. **DSH is MIT, our crates AGPL** — "copy what works" must respect DSH's MIT (fine) and not import AGPL into MIT-only
   surfaces; counsel row 99 already open.
5. **(v3) Erase vs "demote, never delete".** Kira 2 fix 6 asks for an owner-signed crypto-shred. It contradicts Peter's
   2026-10-14 doctrine (SPEC-v0.2.md:259, NORTH-STAR.md:769) and cannot be done in the plaintext Phase-M design; it needs
   Peter's explicit yes, a new Aura kind and a decision on backups/archives (spec §10, row 142 sub-item K2-16). Until then no erase.
6. **(v3) A new `kirad` crate, or a bin in `crates/kira`?** A crate costs scaffold, `walls.py` ALLOW net, clippy and dep-pin
   edits; "pure" is not defined by any wall (spec §1). Also: unit tests in `src` are allowed (`walls.py:126`) but cargo test
   TARGETS still fail `run.py:806-807`, so Kira 2 acceptance is `tests/e2e` scripts.
7. **(v3) Phase-M owner assurance.** Until the node passkey path exists, owner entries in the commitments lane are
   `channel`-attested (a token only Peter's user can read), flagged, then promoted by an owner-signed manifest in Phase N.
   AUMLOK cannot certify N agent keys today (nostr.bind v1 binds one node key and one agent key; the gate inventory is
   empty; `bind_key` is called from no route).
8. **(v3) Test 4 as written is unattainable.** "Within 3 points at 95% confidence" cannot be shown on 59 questions
   (Grok's paired CI there is −6.8..+1.1). The spec restates it as paired non-inferiority on ≥300 pinned questions (row 142, K2-12).

### Acceptance gaps to close (Dot's review, 2026-10-17)
1. Capability acceptance: the full edit-build-test-debug loop (generated executables, browser) runs under the installed
   OpenShell policy with ZERO workspace approval cards. Otherwise we repeat the "can't build" mistake.
2. One written OpenShell policy (filesystem, network, execution, child processes, skipped paths). Resolve "allowlisted
   egress" vs "door/broker sockets only" before T1.
3. Approve the whole build contract: an immutable input manifest (tree hash, lockfiles, toolchains, command, env); bind
   promotion to the resulting artifact digest. Two matching builds are evidence, not authorization.
4. `owner_signed` only through a passkey over the exact bytes (done in b986e7a); owner-typed until then.
5. Trust model: Phase M is same-uid trust among Mac builders; hostile-engine use needs authenticated provenance (the door).
6. Keep "Mac memory works" (true) separate from "DSH memory integration passes" (not yet).

# Part 2: the row register


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
  fits the whole organism, and writes it new. Nothing is copied (superseded by Part 1, Peter 2026-10-16). The archive is aumara-xyz/aukora-sovereign-archive,
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
   - Our own harness (superseded by Part 1, Peter 2026-10-16), spawn, and Go Sovereign.

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
- ~~**Our own harness replaces the DeepSeek harness**, the way the cage replaced OpenShell.~~ REVERSED by Peter 2026-10-16: the DeepSeek Harness is the engine (Part 1).
  - The DeepSeek harness is about 380,000 lines of its own TypeScript, without tests, in 316 packages. It includes
    shell, file, subprocess and terminal tools: exactly what the cage takes away.
  - Ours is Auma's agent loop inside the cage. Her only operations are chat, threads, sessions, streaming replies,
    presets, compaction, proposals and memory.
  - ~~She never executes a command or opens a socket.~~ REVERSED by Peter 2026-10-16: she executes and builds inside OpenShell walls (Part 1). Seccomp denies `execve` and `execveat` (superseded by Part 1, Peter 2026-10-16), and model calls leave only
    through FD 3 to the broker.
  - **Two modes.** In Chat she talks. In Build she may also propose changes, to herself, to sites or to apps.
    Neither mode runs anything (superseded by Part 1, Peter 2026-10-16).
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
  network (superseded by Part 1, Peter 2026-10-16).
- **Keys live in hardware** (Touch ID), and the root stays sealed under the phrase.
- **Every format is crypto-agile**, so post-quantum signatures arrive without a format break (row 139).
- **The immune system learns every attack**, and herd immunity spreads it.
- **Before anything is public, every major AI attacks main.**

**A life raft against other people's agents.**
- **Nothing that comes in is an instruction.** Messages, documents, memories, apps and other agents' outputs reach
  Auma as data, with their provenance, marked as not the owner.
- **Strangers cannot reach her.** Only owner-approved contacts get through. Everyone else is refused before she sees
  anything, and every refusal is counted in Aura (row 135).
- **Even a fully hijacked Auma cannot act.** She has no network and can only propose exact bytes to the owner (superseded by Part 1, Peter 2026-10-16).
- **No AI can phish the keys.** Passkeys are bound to the node's own origin, there are no passwords, and the root key
  is sealed under the phrase.
- **One node's attack becomes everyone's antibody.** Nodes share signed antibodies over Nostr. An imported antibody
  can only add checks, never remove one (row 136).
- **The people you met are marked as met.** A contact paired screen to screen is marked "met in person"; a remote or
  relayed pairing is labelled as such (row 137). Evidence, never authority.

## How it fits (spec v0.2 sections 2 to 7, with these amendments)
The amendments:
- one link;
- our own Rust harness replaces the DeepSeek harness (superseded by Part 1, Peter 2026-10-16);
- canon and Pentora run as Rust compiled to WASM, with no JavaScript twins;
- `bridge/` is retired;
- FD 4 carries data only.
- **One trusted supervisor** process holds every authority. It is wiring only: it starts the organs and routes frames.
  Policy lives in the organ crates.
- **Auma runs our harness inside the cage** (superseded by Part 1, Peter 2026-10-16). FD 3 is her only channel for proposals, model calls and memory. FD 4
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
guest/           our harness: Auma's agent loop inside the cage (superseded by Part 1, Peter 2026-10-16)
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
| 18 | One link: one address per node; the owner origin invisible and only ever framed, except `/pair`, the locked-down top-level page a phone opens to pair (portal/COPRESENCE-NODE.md) | BUILD | archive frontdoor (pop-up panes RAN) | crates/frontdoor | M1 |
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


### R. Plan v1: one system, the door, shared memory
Rows 140 to 142 carry Part 1 into the register. Part 1 wins where it differs from a row above; no earlier row is edited or removed, and Part 1's disposition table says which earlier rows these replace or change.
| # | Brick | Status | From | Lives in | Milestone |
|---|---|---|---|---|---|
| 140 | Plan v1 / one system: Auma builds, fully governed | BUILD | PLAN-v1; Peter, 2026-10-16 (issue #140); Part 1 of this file | NORTH-STAR.md Part 1, engine/, crates/supervisor, crates/gate, crates/laya | M1 |
| 141 | The door: Rust `sovereign door serve`, or inside the node when door-policy-v1.json exists; non-local tool calls arrive as one canonical line on a unix socket; peer (SO_PEERCRED) and rate checked, strict parse, digest recomputed, class re-derived, default-deny per-class policy, call id consumed durably when it would allow or ask, and only the door's own executors run crossings (allowlisted fetch, memory forwarding with its own token). An ask is a gate proposal naming the exact call digest, approved by passkey and spent once. | BUILD | engine/plugins/aukora-door/PROTOCOL.md, crates/supervisor/DOOR.md | crates/supervisor/src/door, crates/gate/src/door.rs | M2 |
| 142 | Kira 2 shared memory: one memory for every agent, with per-agent principals, cited hybrid recall and signed heads; Part 1 section J lists its sub-items K2-01 to K2-17 | BUILD | Kira 2 spec v0.3 (private); rows 57 to 61 | crates/kira/src/shared | M1 |

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
6. **One link.** There is one public address per node, and the owner origin never answers as a page, except `/pair`, the phone's locked-down co-presence pairing page.
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
