> **Frozen input to [NORTH-STAR.md](../NORTH-STAR.md), the only plan.** Kept so nothing is lost; never edited, never a plan of its own.

# Carry list: nothing left behind

Compiled 2026-10-14 from seven read-only sweeps of every older source, merged and deduplicated:
- aukora-deep: master plan @93fe05c, boundary architecture, research trilogy, whole-repo sweep
- Genesis: plan, experience-memory spec, recovered MEGA-SPEC, issue #133
- all local aukora repos
- Honey Pot's decision notes and the 81 Aumlok-ID issues
- aukora-prime's 9 issues with every comment, plus its ideas ledger, north star, organism and browser-node plans

The source documents are under `reference/`. The reference implementation is aukora-prime @de410bb.

Every item is one of:
- **[1]** in the first working system
- **[2]** joins right after, on the live system
- **[L]** later
- **[X]** dropped (the reason is given)

Sources: Prime = aukora-prime; MP = master plan; BA = boundary architecture; UC = Unownable Core; SK = Skeleton Key II; EM = experience-memory spec; V02 = `reference/AUKORA_Sovereign_Composable_Runtime_Technical_Spec_v0.2.md`; HP = Honey Pot notes; #n = an aumlok-id issue.

## First-system acceptance (each one passes on a live node, and Peter sees it on his own screen)
Only Peter accepts. Done means Peter opened it himself in a real browser. An API probe is not screen proof.
- **A1 model reply:** a real reply from the owner's model.
  - The provider call is in a receipt, and spend stays under the grant.
  - Twin: with the route off, the app says unavailable and never fakes a reply (Prime M2).
- **A2 approved change:** passkey enrolment, then one approved effect (a self-change or config change; memory itself is tracked, not approved).
  - It leaves a receipt and a retained anchor.
  - Twin: the identical effect without approval is refused with zero effects (Prime M3, adjusted for the 09-30 memory decision).
- **A3 restart:** after a node restart, a saved memory is recalled with its citation. The floor and the approvals hold.
  - [2] Export from the node alone, cold-verify, restore into an empty node with original IDs. A forgotten item stays forgotten (Prime M4).
- **A4 second node:** two nodes, each with its own VM and key, each passing A1 and A2.
  - C1's cookie or proof cannot authorize C2, and no state is copied (Prime M5). [2].
- **A5 Path 0:** the agent proposes from inside the sandbox, Peter approves with a passkey, the change is applied once, and a stranger verifies.
  - Restart or retry cannot write twice.

## Laws (apply to every organ)
- [1] Intelligence proposes; only the owner authorizes. Care, evidence, identity, repetition and Laya grant nothing (UC §2, HP 10).
- [1] One path per authority. Twin paths are a defect.
- [1] A remembered job is not a permission. One-use spend state is kept apart from job memory (HP 9).
- [1] Unknown is never shown as "no". Every result is one of found / empty / undetermined, and every action outcome is one of done / refused / failed / UNCERTAIN. An uncertain action freezes and is never blindly retried (BA §8.1, EM §3.1).
- [1] Anything the agent can disable must fail closed. Turning off the gatekeeper stops the agent. This is a live test (UC §5, SK §8).
- [1] A check that cannot fail proves nothing. An unrun check is OPEN, never green. Every hole that is found becomes a check that fails if the hole returns (BA §8.6). Build the capability, not a proof forest (HP 43).
- [1] Honest words. Present tense only for a running release, with its hash. Lead with what is not enforced. Never "proof of humanity". Aura is not a token or score. "Sovereign" names the destination. Name the key, not the person (MP §3.2.1, HP 20).
- [1] Old receipts never gain authority under a new schema. Schema changes are versioned (UC §3.7, §14).
- [1] Retire, never strand. A declined or abandoned proposal must reach a terminal state.
  - Hazard (Prime #7): a reviewed but unsent proposal was later executed with its still-valid approval, and an owner who declined was stuck.
  - Protocol I1–I9 (#7):
    - Proposed→retired only. DENIED is recorded before the journal closes, and no intent or effect is confirmed.
    - Retirement takes the owner's passkey over {operation_id, digest, "retire"}.
    - Idempotent, one receipt, resumable by retire and never by recovery.
    - The receipt survives pruning and a stranger can check it.
    - The old id and idempotency key are burned.
    - An unknown outcome is never retirable. A live reviewed proposal blocks a fresh one until it is retired.
    - Restore carries retirement records.
- [1] Authorization is three-valued: Deny / Unknown / Allow. Unknown never becomes Allow. A property test includes a twin that collapses Unknown and must fail (I-04).
- [1] Input provenance. A turn started by a plugin, relay or member is never "Peter said". Text saying "FROM PETER" is not authority (ORGANISM).
- [1] Receipts state their guarantee: reduced versus full. A gate-signed approval proves only that the gate key signed. "Used once" is not provable offline (#2).
- [1] The agent's environment is built from an allowlist. Socket modes are asserted, and file descriptors are closed in the same process that execs (SK §11, Grok).

## Gate, ledger, release floor
- [1] Exact-byte proposal → review → one-use consumption → write once → signed receipt.
  - The stale-base recheck runs before the write. After a spend comes a recovery sweep with terminal states: incomplete / failed / conflict.
  - Every transition is a CAS under BEGIN IMMEDIATE (Prime gate.mjs, Mistral).
  - A crash is injected at every transition.
- [1] Prime's gate checks and attack scenarios are the executable spec.
  - This includes the 815-attack corpus (UNVERIFIED: locate it), the Deep courts `open-findings.json` lineage families, and the aumlok-id corpus: 81 issues and 5,360 Pentora vectors (Kimi, Mistral, HP 14, deep sweep).
- [1] Bind the interpreter, not just the arguments. The WASM module digest and the tool definition are inside what is approved (BA §2, §12.2).
- [1] Signed bytes = displayed bytes. The owner card renders injectively and passes a round-trip test (SK §4.2, §11.2).
- [1] Release floor ordered by (signer_epoch, ledger_seq).
  - Boot needs the exact approval. Rollback needs fresh approval.
  - The launcher itself checks the floor. A stale lock is reconciled, not left wedged (Prime release-floor.mjs, Mistral 9).
- [1] Owner channel is never throttled by strangers. Only wrong guesses are limited, per principal (Mistral).
- [1] Named refusals that print one next step. READY is printed only after the approval channel is proven (EM, Genesis reviews).
- [1] Spend grant for model use (#2).
  - One passkey-signed grant: total cap, per-request cap, maximum requests, expiry of 24 h or less, and a nonce.
  - Reserve under lock. Refuse if expired, revoked, the epoch changed, the uuid is reused, or the remaining budget is below the estimate.
  - Settle the actual cost. A lost reply keeps its full reservation.
  - Revoke without a passkey. Per-request receipts go in the ledger.
- [1] Key custody: the model key is held only by the broker and entered through an owner-approved one-time ticket. Agent tools can never read it. A generation bump invalidates in-flight calls (#2).
- [1] Authority high-water: used keys, highest epoch and the consumed set are held outside writable state, so restore, rollback or re-rotation cannot revive a spent approval. This was Prime's "worst open defect" (I-01). The storage head is never ahead of durable bytes.
- [1] Pin-drift check: a change to the patch set or launcher fails until its pins are re-reviewed. A check that relies on source refuses to count if that source changed since review (Prime #7, NORTH-STAR).
- [2] Release switch: raise the card with the old release still up.
  - Success means a signed-in screen probe plus all plugins loaded, with automatic rollback.
  - The launcher and release come from the same commit. The app never silently falls back to an older local release.
- [2] Reproducible build: rebuild from pristine and byte-compare (41 outputs differed in Prime, #1).
- [2] Governed model emission. Every model call goes through the host broker and is metered and receipted, and model identity is recorded as requested / reported / verified ("model-visible implies logged", MP §2.2, Dot).
- [2] Six transaction controls are tested: decline, changed-after-approval, replay, restart, interrupted settlement, revocation. Each test also reports what stays unknown (HP 11).
- [2] Self-change loop: a new release that is not up within 3 minutes is rolled back automatically, and a `code.become` record is written (HP 16).
- [L] Egress broker, mission envelope, primitive registry and grant frames (deep BUILD-SPEC-ENFORCEMENT).

## Aumlok (identity, binding, approval)
- [1] Acrostic seven-word phrase.
  - Word 1 is a six-letter anchor. Words 2–7 start with its letters in order.
  - Words 2–3 are ROOT (nature), 4–5 UNITE (people, connection, celebration), 6–7 RISE (spirit, space, technology).
  - Never drop the acrostic or add words (Peter, 09-24).
  - NEW construction, not a carry. Prime has only the themed lists; Prime's live phrase is BIP-39 7×11 words. Min-entropy is computed over the real composed lists before the screen ships.
  - Make the lists as large as possible (Peter, 10-14). Prime's theme lists are about 8.7k / 19.2k / 9.3k words. RISE adds space and technology words alongside spirit.
  - The screen tells the owner to build a memory-palace story in their own head, and never to type the words into an AI. The story stays theirs, and the words never reach a model's logs or training data.
- [1] The phrase is never key material. It unlocks a random 128-bit-or-stronger root (decided 09-26, never built).
  - Unlock is online only and rate-limited.
  - Its strength is shown honestly: the weakest anchor was about 34 bits on the old lists; Prime's lists give about 68 bits.
  - Deep's recovery envelope design: a scrypt/Argon2 + AEAD envelope over a random secret, with fault tests (HP 1–2, deep).
- [1] Passkey approval on the node (webauthn-rs). A counter of 0 is valid. The page carries the v3 owner proof (Prime, Mistral).
- [1] Binding ceremony state machine EMPTY→PREPARED→CONFIRMED→COMPLETED|IN_DOUBT. A failure after the rename is never "refused" (deep spec 0049, Prime crash-safe binding).
- [2] NEW: Refresh-phrase screen (Peter). Unlock portal: one button opens bind/reset (#72).
- [2] Delegation lineage root→device→session→agent. A child is the parent intersected with the request. Revocation is rechecked at every use (HP 3, Prime delegation.mjs).
- [2] Revocation store, plus member exit: leave with keys, memory and receipts (MP §2.1, §3.1).
- [L] Observer succession: rule fixed at genesis, k-of-n with one share outside the owner, successor announced in the ledger, a contest window. `identityBound:true` is never claimed before it exists (UC §5).
- [L] Hybrid Ed25519 + ML-DSA-65 with downgrade refusal (HP 4). Unlinkable scoped identities (#65). Vouches and invites (MP §3.2).

## Aura (the one signed record)
- [1] One ledger table for every organ: gate, Aumlok, release, Kira, self-change.
  - Two arms, compatible with `vendor/append-only/verify.py`: the `aukora:aura-record:v1` hash chain plus RFC 6962 leaves, with `proofFromPrevious` emitted natively.
  - The power-of-two blind spot is closed with `nextIndex` (Aragon).
- [1] Coverage audit: each operation has named intent and settlement obligations and exactly one terminal result. A check enumerates every authority entry point and effect route; zero or duplicate terminal results fail. Any second authority entry point for the same effect fails (Kimi, Dot).
- [1] Owner-retained head. A stranger verifies from an empty folder and refuses tampered or truncated copies. `CONSISTENCY_UNCHECKED` is labelled (EM, HP 19).
- [1] The owner's browser retains the last signed head and raises a rollback or fork alarm. The owner can download the retained head.
- [2] Public external witnesses. drand gives time only, not publication. Without a witness, a receipt means nothing to a stranger (MP Gate 1, BA §11, Dot).
- [L] Merkle disclosure privacy note. Multi-observer heads for Buzz.

## Browser ingress and first claim
- [1] Backend on loopback behind TLS.
  - Exact Host, HTTPS Origin and Fetch-Metadata checks, including WS and SSE. Forwarded-header spoofing is refused.
  - `__Host-` host-only, revocable sessions with logout. This is a FIX: Prime's cookie is not revocable.
  - Separate chat and owner hostnames per node. The chat (FD 4) origin never reaches owner routes or cookies (Aragon, Grok).
  - Body, time and rate limits plus a cost cap.
  - Tokens and phrases never appear in URLs, logs or referrers (Prime BROWSER-NODE).
- [1] First claim: one-time, expiring and owner-delivered. Enrolment closes afterwards. The approval surface runs before, and independently of, the agent runtime.
- [1] Unbound sessions reach only the binding routes (403 binding-required). Prime's three open holes must not exist:
  - a readable control record lifting the guard
  - `prepare` returning the words
  - an open `/plugins/` prefix
- [1] WebAuthn: the challenge is the digest of the gate-issued canonical authorization.
  - No cookie-only or bearer-fallback approval.
  - The counter is updated inside the consumption transaction.
  - Synced passkeys do not prove device-only custody (stated).
  - The owner origin is isolated from the model apps, with no iframe approval.
- [1] Decide where the phrase is derived: in a browser worker or on the node. TLS does not make it local.
  - Node-binding envelope: node id, genesis, handle, node key, passkey and server nonce.
  - Same phrase gives the same root but a different subject per node.
  - [2] add-machine ceremony.
- [L] A web page is not a trusted display for high-impact effects (I-16). Hardware display later.

## Kira (memory)
- [1] Memory is tracked, never approved. Capture, hash into the chain, index, and recall verified against the chain (09-30 decision, HP 22).
- [1] Notes are encrypted with ChaCha20-Poly1305. The associated data is length-prefixed owner_subject, note_id and key_id. Only content-free commitments go in the ledger (Aragon).
- [1] Never delete, only demote (Peter, 2026-10-14).
  - Forget moves a note out of recall and keeps it in a lossless cold archive. Indexes are rebuilt.
  - The ledger keeps every content-free commitment.
  - Deleting a key is not proof of erasure; this is a stated non-claim (BA §13, deep Kira notes).
- [1] Recall is found / empty / undetermined with cited sources. The memory header must tell the truth (EM, MEGA B4).
- [1] Model-authored notes are tiered and never re-injected as trusted. Scope is independent of the workspace path (202 Prime notes became unreadable when it moved). Note length is bounded, and one bad index entry never blocks the queue.
- [2] Recall into a hosted model's context is disclosure. The six permissions are store, disclose-to-context, dataset, export, train and activate (EM §3.4).
- [2] Usage never raises confidence. A summary is never the only copy. TTL means "review by" (deep Kira breakthroughs).
- [L] Experience schema and dataset release, anti-self-consensus, dreaming as proposals, OpenViking-style semantic recall.

## WASM proposal cell
- [1] The pinned zero-WASI cell has one import and a 64 KiB budget. The host validates the memory `max` before instantiating. Its digests go into the proposal evidence.
- [1] Resolved: the cell is 101 bytes, sha256 34ce6cab…, measured 2026-10-14. It has one import (`aukora.propose_memory_put`) and exports `memory` and `memory_put`. Embedded with `include_bytes!`. Never auto-rewrite pins (SK §2 T8, Dot).
- [1] It is a relay, not a sandbox. Bypass tests anchor on the 64 KiB refusal (HP 26). Governed-aperture spec: `reference/recovered/genesis-issue-133.md`, comment 16.

## Sandbox and runtime
- [1] Supervisor → launcher → clone. Namespaces: user, mount, pid, net, ipc, uts, cgroup.
  - Fresh root. `/usr` is read-only. `.git` is read-only before Landlock. Network namespace is loopback only.
  - cgroups. no_new_privs. Capabilities dropped. seccomp allowlist. Landlock ABI v4 minimum or refuse to start.
  - FD 3 (SEQPACKET proposals) and FD 4 (UI listener) are placed with dup3, then close_range(5) and execve in the same child. Exact order in SPEC §2. Grok's attacks, each with an unconfined control (Grok, Kimi).
- [1] The agent runs as a separate host uid (subordinate range via newuidmap), apart from the supervisor's `aukora` user. [L] per-organ uids. The organs share one trusted process, and this is stated (Dot).
  - Socket rules: directory 0710, socket 0660, path of 103 bytes or less, no symlinked parent. Refuse to start with the same UID. Tested across real UIDs (#3).
  - Grok's attack list includes abstract sockets, /proc/pid/mem and a mount audit, which were still skipped in Prime.
- [1] systemd hardening per unit, checked with `systemd-analyze security`. Units survive a reboot.
- [1] Empty-intersection self-test at start: the guest cannot `open(2)` any key, database or socket (SK §4.3). Prove Landlock on `/dev/shm` and `/var/tmp` (HP 28).
- [1] FD 3 frames are length-prefixed, at most 64 KiB, strict canonical JSON. A shared fuzz corpus covers the Rust and harness parsers (Grok, Aragon).
- [1] The agent runtime (DeepSeek harness / Cordis) runs inside the sandbox. Model calls go through the host broker (Dot).
- [X] OpenShell / podman / sbx-exec stack (its retained verdict is FAIL; replaced). macOS Seatbelt waits for the Mac app.

## Safety slider and Laya
- [2] Laya is an extra pair of eyes: "look at this, something seems off." It never authorizes.
  - Upstream: github.com/NandhaKishorM/laya (Apache-2.0, open weights). It is fine-tuned on our cases and gets better over time.
  - Each fine-tune is a pinned, reviewed model release.
- [2] Modes Chat / Build / Yolo sit over a hard rule floor (#58).
- [2] A safety-threshold slider sits under the Pentora in 5% steps. It decides when to ask, never what is allowed. The hard floor always asks. Raising is instant; lowering needs a passkey. It is called a score until calibrated (#71).
- [2] Laya may only escalate to "ask Peter", never relax anything. Its answers are no objection / review required / block / unavailable. When unavailable, the node falls back to rules and shows offline. Lab result: it catches every attack, with 13.5% false alarms (aumlok-app advisors/laya, Prime labs/laya-screen, V02 §10).

## Pentora and UI
- [1] Pentora is derived from the single Aura root ("pentora.display.v1", 110 trits). It authenticates nothing. Stale or unavailable is shown visibly.
- [1] Reused screens: Aumlok binding, approvals, Aura coherence, memory, first run. The chat screen comes from the agent app.
- [1] No text on screens: no status strips, captions or banners. Icons and colour only, and only when Peter asks. One style everywhere: the thread-list glass panel and the app's accent colours (HP 29, Peter).
- [1] Approval card: no typed codes, forced reveal or dwell timers. One line saying what it does. ROUTINE versus CRITICAL (blue / red outline). Gate facts and from→to on top; model text fenced last (HP 30).
- [1] Never switch the live app to a face Peter hasn't seen. Screenshot first (HP 31).

## Verifier
- [1] Cold verifier built on `verify.py` plus the Rust replica.
  - It checks signatures, owner-proof binding and consistency against independently pinned keys and heads, and pins its own bytes.
  - Golden vectors from deep: `v3-fixture.json`, the owner-approval-flight evidence, transcript snapshots (SK §3.2, deep sweep).
- [1] Must pass where Prime failed: 100 sequential approvals all verify (#34). Without an independent covering checkpoint, completeness is reported UNCHECKED; a truncated export never passes as complete (#24, Dot). One junk event cannot flip a valid approval (#32). The memory chain is covered (HP 17–18).

## Spawn, ops, apps
- [1] One-click node: one command creates the Nebius VM and installs one signed release.
  - The owner approves the release with a passkey, then binds. A retry never duplicates the VM or the spend (Dot, #58).
- [1] The node-creation gate protects spend: a valid one-time invite (48 h expiry, 3 per member) unlocks a node. "Go Sovereign" hands it over to the owner (NORTH-STAR). [L] the invite chain on Aura.
- [2] Upgrade a bound node without losing the binding. Backup and restore. Export everything on leave.
- [2] Open problems to answer before promising "we cannot see your node" (HP 38–39):
  - user-held keys
  - encrypted disk
  - the cloud account holds the control plane
  - abuse of free compute
  - KYC
  - Laya licence
  - a Nebius spend stop time
- [1] Models for each node:
  - The owner brings an OpenRouter key and picks any model. The key is set through an approval, and calls go through the host broker.
  - Later, an AUKORA endpoint: compute from Nebius, serving a tuned Auma that fits the system.
  - Users' data is never trained on without their explicit, receipted consent. This is Kira's train/dataset permission (Peter, 2026-10-14).
- [1] Identity and node creation always happen in the cloud (Peter, 2026-10-14). Nodes on personal machines come later, as additional homes.
- [L] Invitation chain on Aura (anti-sybil). Buzz/Nostr as witness and transport, never authority. Messaging. The Electron Mac app (aumlok-app native biometric). The phone (optical-pairing spike, in the aukora-archive branch `spike/optical-pairing`). Local models on the owner's own machine.
- [L] Future surfaces: AR/VR glasses, neural interfaces.
  - The boundary and approval must not assume a screen, a keyboard or a mouse.
  - The card has an exact canonical form that any surface can render, so voice, glasses and others all approve the same bytes.
  - Device keys come from the delegation lineage.
- [L] MEGA-SPEC vertical packs and economics. They are a direction, not promises (Peter removed them from the plan on 09-17).

## Licence and workflow
- [1] AGPL-3.0-or-later for our own code. Vendored code keeps its MIT licence. Holders: "Aumara and Peter Viviani".
- [1] Before any public push, scan commit metadata for privacy (author emails).
- [1] Coordination rules (Prime #8):
  - Issues for work, with compact claim blocks: revision, evidence, result, next owner.
  - No ack loops. Never fake.
  - Decisions, spend, cloud and credentials come from Peter only. An agent's review is never approval.
  - Migrate IDEAS-LEDGER I-01–I-19 as idea issues.
- [1] Evidence labels: RAN / SOURCE-ONLY / UNPERFORMED. Verify prints counts and declared exclusions. Linux is the definition of done.
  - Run the full check locally before pushing, so Actions minutes are not spent on failures.
- [1] Licence question for counsel: the language licence (CC BY-SA vs AGPL), and an Apache fork loading an AGPL engine (I-14).
- [L] Goal loop and builder agent inside standing bounds. Bloom and co-presence (I-17). Phone model (I-18). Windows (I-12). Closed Nostr event-kind list (I-06). Ornith/LoRA (I-08). First Echo: decide whether to keep it.
- [X] Prime's 176-commit lane reconcile, the PG restart-hang fix, the Convex flag, and disk reclaim. These are Prime housekeeping, not system.
- [1] Code goes straight to main. One integrator. No stacked worktrees. Never `rm` a computed path (HP 41, 45).

## Decided by Peter (2026-10-14)
- Models: OpenRouter for owners now. An AUKORA endpoint (Nebius compute, tuned Auma) later. No training on user data without consent.
- Forget: never delete, only demote.
- Phrase lists: as large as possible. Memory-palace story made by the owner, never by an AI.
- Identity is created in the cloud. Plan ahead for AR/VR and neural surfaces.
- Work tracking: one GitHub issue per item in aukora-sovereign. Closed only when confirmed working on main.
