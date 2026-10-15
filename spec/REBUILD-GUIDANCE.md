> **Frozen input to NORTH-STAR.md, the only plan.** Kept so nothing is lost; never edited, never a plan of its own.

# AUKORA Sovereign: rebuild guidance spec

**From:** the NEBIUS session (Claude), for SOVEREIGN MAIN, at Peter's request. 15 October 2026.
**Status:** guidance, not gospel. Every design choice below is a proposal for the builders to test, adapt or reject with a written reason. Evidence labels: **TESTED** means measured in a simulation or CPU study (same author unless stated, not independent replication). **SOURCE** means read in code. **PROPOSAL** means not yet built or tested.

**Read with:**
- Codex's Rebuild Constitution packet (`START-HERE.md`, `CLAUDE-HANDOFF.md`, the 522-row carry list CSV). Peter needs to save it from ChatGPT to `~/Downloads`.
- `reference/PLAN-COVERAGE.md` and `reference/old-plans/` in the archived repository.
- This week's research reports.

---

## 0. Why this rebuild is the right moment

The research of the past two weeks kept arriving at the same conclusion: **the remaining failures are foundation failures.** Almost every unsolved hole in recovery, budgets and voting came from one of three things:

1. **Rollback and clones.** A restored snapshot or copied device re-spends, re-votes or re-approves.
2. **Missing epochs.** Authority-bearing state with no version, so old and new can both look "current".
3. **Things getting lost between builds.** The guardian network was in the old plans and was nearly forgotten. Auma Live's files existed, but its serving allowlist omitted needed JavaScript. Memory was built but left out of release packaging.

None of these can be bolted on afterwards. A ground-up rebuild is the one point where they can be built in as structure rather than patched in as exceptions. The previous build retrofitted. This one should not have to.

**One identity fact to pin immediately.** The original repository is now `aukora-sovereign-archive` (repository ID 1418448527). The new `aukora-sovereign` is a different repository (ID 1420432858). Pin every reference by repository ID and commit, never by name or folder. "It's in Sovereign" must not be able to mean two bodies of work.

---

## 1. The constitution: invariants that hold everywhere

These are acceptance tests from day one, not aspirations.

1. **The owner root is never under anyone else's control.** Not guardians, not the agent, not a relay, not a score.
2. **Every authority-bearing state has an epoch and a rollback guard.** That covers owner credentials, guardian set, device list, allowances, recovery requests, standing rules and release floor.
3. **Evidence never becomes authority.** Scores, Laya flags, thymus results, pictures, guardian signatures, relay agreement and model confidence may refuse, escalate or inform. Only the owner's passkey, or an owner-pre-signed bounded policy, authorizes.
4. **Fixed check floors never shrink.** Adaptive layers may only add checks. A separate process hunts blind spots, because fixed floors keep their coverage but never notice new hazard classes (TESTED: 0 of 1,832 shifted hazards caught by fixed checks).
5. **Budgets are conserved, not scored.** Admission, invites and resources are capacities that cannot be multiplied by creating identities (TESTED: 10 to 10,000 fake accounts never exceeded the shared allowance; trust scores did not give that bound).
6. **The antibody ratchet uses fresh held-out cases.** A growing regression suite is necessary but not sufficient (TESTED: a memorizing repair passed every retained regression while catching about 32% of new cases).
7. **"Approved" is separate from "still wanted."** Track stale-but-authorized outcomes separately from unauthorized ones.
8. **"Published" is separate from "delivered."** A relay's silence is never consent, and publication never proves the owner was notified.
9. **Nothing from the carry list disappears without a recorded owner disposition.**
10. **Acceptance follows the whole chain:** source → build → package → served assets and routes → authenticated browser → meaningful behaviour. A file existing, an HTTP 200, or a screenshot of an empty shell is not acceptance.

---

## 2. First commit: the carry list

- Import Codex's 522-row carry list as the repository's first artifact, with its omission checker. The checker detected removal of every registered ID.
- Every row starts **blocked**. It becomes satisfied only with acceptance evidence on the new build, or a dated owner disposition ("dropped", "deferred", "replaced by X").
- **Close the 15 explicit coverage gaps before calling the foundation ready:** full UI workflows, transitive assets, historical archives and local-only sources. The checker protects what the inventory knows; it cannot find what the inventory forgot.
- **Genesis UX comes in whole:** every face (apps, aumlok, documents, layout, memory, messages, settings, sidebar, threads), every stock app (Auma Live, Lingwa, Zeta Harp, Dakini Code, Human Graph, Media; Canvas explicitly withheld; Room's launcher status unverified) and every plugin. Each gets the full acceptance chain from invariant 10.
- **Source of the running build:** the pilot's `aukora-genesis` service ran `/opt/aukora-genesis/release-3673b98`, which is aukora-prime commit `3673b98a3e090d122ed0853386ff60913287c3a8` (5 October). That note dates from 12 October; verify the live state read-only. The faces live in Prime `plugins/aukora-face/`, with committed `lib/` bundles.
- **Wire the carry-list runner into the release gate:** a release cannot be proposed while any non-disposed row is failing.

---

## 3. Keys: the hierarchy and its blast radius (PROPOSAL, from Codex's 17-role key map)

| Role | Purpose | If compromised | If lost |
|---|---|---|---|
| Owner root / passkey | Only authority over policy, releases, guardians, devices | Full authority: the one key that must be hardware-held and multi-device | Recovery only through an explicitly chosen owner-replacement mode (section 7) |
| Operational key(s) | Day-to-day signing within scopes | Bounded by scope and epoch; revocable by owner | Re-issued by owner, or by guardian-assisted operational recovery |
| Device keys | Each paired device | That device's scopes only; revoke | Re-pair |
| Node key | The node's identity to peers | Node impersonation, bounded by peer-witnessed epochs | Re-enrol under owner approval |
| Agent key | The agent's Nostr identity | Agent actions within its delegation; never owner authority | Re-issue; delegation is owner-signed |
| Nostr keys (secp256k1) | Node and agent Nostr identities, bound to Aura | As above | As above |
| Guardian roles | Hold backup shards, vote on operational recovery, acknowledge vetoes | Bounded by threshold rules; can never act as owner | Replace through an epoch-safe guardian-set change |
| Backup encryption keys | Decrypt backups | Read access to backups | **Unrecoverable without surviving recovery material.** Reconstructing ciphertext does not restore readability |

Rules:
- No non-root key carries authority beyond its scope.
- Every key binding is recorded in Aura with an epoch.
- Two clarifications to keep explicit: non-root credentials necessarily have narrow powers, and a lost decryptor cannot be repaired from ciphertext.

---

## 4. State: epochs and rollback resistance (the foundation's hardest problem)

**Epochs.** Every authority-bearing record carries `(epoch, sequence, previous-hash)`. Membership changes (guardians, devices) use joint configurations: old and new sets both required during the switch, Raft-style. A complete reconfiguration protocol still needs to be **selected and tested**.

**Rollback guard (PROPOSAL, partially TESTED):**
- Codex's finite model shows local-state-only protection fails.
- An ideal external register prevents duplicate effects, but an identical current clone can still redeem first.
- Proposed combination:
  1. a monotonic counter, hardware-backed where available;
  2. **peer-witnessed checkpoints**: the node's latest Aura head co-signed by its circle and watchtowers, published as Nostr head witnesses;
  3. **single-active-device leases** for anything that spends, votes or approves;
  4. **fail-closed for effects when witnesses are unreachable.** Reading and preparing can continue; spending, voting and approving wait.
- Hardware counters and a real witness service are **not yet tested**. That test should finish before the state layer is frozen.

---

## 5. The gate, tiers and the immune system

**Gate.**
- Owner authorization stays bound to the exact displayed bytes.
- Tiers are `routine` and `critical`; the default is critical.
- Routine changes may flow under an owner-signed standing policy that is scoped, has a short expiry and can be revoked in one tap.
- Declined policy proposals are remembered and not re-proposed without new evidence; batching comes before proposing rules (TESTED: rule proposals created more messages than plain batching).

**Immune system:**
- **Ratchet:** the antibody corpus is replayed before every release proposal, plus fresh held-out adversarial cases each release, with both counts as release facts. Antibodies are never deleted; retiring one is an owner-approved proposal. Prefer general invariants over per-example patches.
- **Thymus:** a shadow-clone check before the owner sees a card. Evidence only: a fail may refuse or escalate, a pass never grants.
- **MHC:** live self-attestation (targets against receipts, floor, triggers' SQL hashes, binary hardening checked natively in Rust).
  - Quarantine is visible on the owner screen and recoverable by passkey.
  - Drift is reported separately from proven tampering.
  - It runs on a fixed cadence with CPU and IO caps.
- **Hypermutation:** seeded self-attack in its own cgroup, including generators aimed at **unmodelled** hazard classes.
- **Overrides:** if the owner may override a failing antibody, make it a separate red "release with a known failure" card, with the failing antibody named and the override recorded in Aura.

**Laya (escalate-only scrutiny):**
- Runs as a separate, capped process, never inside the supervisor.
- Never renders an "all clear".
- Loosening the dial needs a passkey.
- Memory quarantines are visible to the owner.
- Evidence goes first in the input, and overflow escalates rather than truncating.
- Deterministic rules ship first. Laya earns its place on a triage benchmark: 100% of seeded-critical cases caught system-wide, owner time saved, false-alarm rate, and evidence-order flip rate.

**REA (reverse engineering):**
- Guest-only, static-first.
- Intake is an owner action, with the digest recorded in Aura.
- The supervisor re-runs equivalence itself, so guest counts are display only.
- Reconstructions are at least elevated risk, with an owner rights attestation.
- Self-inspection is native Rust, not REA.
- TESTED at small scale: 576 of 576 pure C functions and 9,216 of 9,216 small state machines were reconstructed and exhaustively verified.
- Caveat: a certificate is only as good as its assumptions. A "≤4 states" test was fooled by 5- to 16-state machines, so pin the assumptions inside every certificate.

---

## 6. The Nostr layer and pairing

**Nostr (port from the archive with official vectors):**
- NIP-01 events, BIP-340 signatures, NIP-44 v2 encryption, NIP-59 wrapping.
- Node and agent secp256k1 identities held by the supervisor and bound to Aura.
- Cross-node matching by Nostr event ID.
- Redundant multi-relay delivery.
- Head witnesses published to relays.
- Backups wrapped to the owner's key.

**Marmot (MLS over Nostr; MIT; spec "adopted"; github.com/marmot-protocol/marmot):**
- Use it for group communication: the guardian room, family circles, device groups.
- It supplies what NIP-44 lacks: forward secrecy, post-compromise healing through MLS epochs on membership change, and metadata minimisation (TESTED: public relationship and recovery events expose the social graph).
- Marmot is the secure pipe; it does not decide which recovery is legitimate.

**Pairing and co-presence (`aukora-contact/copresence-portal-v0`; Mac and iPhone light handshake RAN three times):**
- Camera-to-camera signed exchange; no human comparison needed when both devices are present.
- **Fix before reuse:**
  - sign both timestamps (currently only one side's is signed, while the verifier uses both);
  - do not expose the nonce in the first message.
- Bind full context: both owner and device keys, session contributions, purpose, scopes, timestamps, expiry and method.
- Durable attempt counting, including aborted attempts.
- The method is fixed before the exchange, with no downgrade.
- Pairing never authorizes; the owner approves the device key and scopes through the gate.
- **Binding as Nostr:** two separately signed events agreeing on one exact statement (NIP-01 has one signer per event).
- **For remote people:** read emoji or a short code aloud over a channel the attacker cannot rewrite.
- **Relays and video:** a relayed exchange is labelled honestly; it is never "proved physically present".

---

## 7. The living network: self-healing data and guardian recovery

**Self-healing data (TESTED in simulation):**
- Encrypted backups are erasure-coded across devices and guardians. Holders cannot decrypt.
- 3-of-5 restore reconstructed the exact ciphertext 80 of 80 times; all 2-shard attempts were refused.
- Restore requires three reachable, authentic shards **of the current version**, plus a surviving decryptor.
- **Overlapping local repair groups** (locally repairable codes), with missing pieces as explicit erasures (the honest "unknown" state). Lost pieces are rebuilt from a small local group.
- A local repair rule (any group missing exactly one piece repairs it, repeat) recovered everything that full global decoding could.
- Repair traffic is about 4× lower than an all-in-one Reed-Solomon code at equal overhead, which is stronger per loss but must contact about 105 pieces.
- **Lying pieces fail the checks of both groups they sit in**, which identifies the liar.
- **Proactive refresh (PROPOSAL):** periodic re-randomisation of shares, so shares stolen in different epochs never combine.

**Guardian recovery: two modes, labelled honestly:**
- **Mode A, operational recovery.** Guardians help recover an operational key. The owner root stays outside their control. This is the recommended default.
- **Mode B, owner replacement after total loss.** A quorum can replace owner authority. This is delegated power, not "evidence", and needs Peter's explicit choice.
- **Safety condition (TESTED):** 2q − n > f, where n is the guardian count, q the threshold and f the tolerated dishonest guardians. 4-of-5 closes the single-equivocator fork; 5-of-7 tolerates two.
  - Costs: availability (one withholding guardian forces unanimity among the rest) and split-vote deadlock.
  - A reviewed agreement and view-change procedure with an owner tie-break is still required.
- **Vote locks** are durable per identity epoch and must be rollback-protected: restoring a pre-vote snapshot allowed a second vote.
- **Freeze-on-conflict** is scoped to recovery only, because one bad guardian can trigger it. It never disables the owner credential.
- **Veto:** the old operational key gets one bounded pause per epoch (TESTED: 20 attempts added only the 30-unit cap), plus a separately held cancellation credential.
- **Watchtowers:** with 5 watchtowers, at most 1 dishonest, and finalisation needing 4 READY statements, durable veto acknowledgements from 3 distinct watchtowers block finalisation (TESTED, under assumptions). Acknowledgements must be obtained before the commit boundary.
- **Owner notification:** multi-channel (the Marmot guardian room, Nostr DMs across relays, local mesh, devices). Any timeout-based finalisation is an explicit owner-chosen policy, labelled "published, unconfirmed".

**Anti-Sybil:**
- Invites carry conserved allowances that cannot be multiplied.
- Personal trust views are evidence only.
- Receipts and relationships are private by default.
- Admission, guardian enrolment and owner authority stay separate from any social ranking.

---

## 8. Pentora's role, built in from the foundation

What the research settled (TESTED):
- Pentora is not compression (4.77% larger on a round-trip).
- It is not encryption.
- It is not a special learning shape (it helps only when the world shares its structure).
- No 42-dimensional record is possible from 21-trit Construction A: at best 2^-10.70 centre density, below the random-lattice bound of 2^-10.21 and about 30× sparser than simple Leech + BW16 + A2 gluing.
- Its pictures are not reliable for human-to-human comparison.

What it is good for, and why that matters at the foundation:
1. **The fingerprint display.** `pentora.display.v1` stays unchanged and display-only. Port Prime's hardening:
   - one derivation with cross-implementation vectors;
   - fail-closed rendering (blank on error, no stale or resurrected picture, race-guarded);
   - no digest text while moving;
   - honest disclosures;
   - sources marked absent with a reason, never stale.
   The Stranger line never rests on a by-eye match (near-match grinding: about 2^55 work for ≤30 differing cells).
2. **The shape of the living network (PROPOSAL, partially TESTED).** The five-cube incidence (110 cells, 5 groups of 26, 20 shared cells) is a valid overlapping repair-group layout.
   - TESTED: it clearly beats non-overlapping groups (e.g. 33% against 20% recovery with 4 losses) and ties random overlap of the same shape.
   - It earns the job by being a good layout, not by magic geometry. Other shapes are valid where the network differs.
3. **The health face of the network.** Each cell maps to a real piece of the owner's safety net:
   - solid: healthy;
   - dark: missing;
   - shimmering: repairing;
   - red: failed its group checks.
   The picture is derived exactly from network state and grants nothing. Because layout and display are designed together from the start, the picture finally *means* something people can read: "whole", "two pieces missing, repairing", "one holder lying".
4. **The relationship bloom.** The shared Pentora from two paired devices' contributions is the visual of a new relationship. Visual only; the security is in the signed exchange.

---

## 9. Suggested build order, each phase with exit criteria

1. **Carry list and release-gate runner.** Exit: the checker blocks any silent removal, and all 15 gaps are closed or explicitly dispositioned.
2. **Canonical encoding, Aura ledger, epochs.** Exit: Rust↔JS parity vectors, epoch-versioned records, and the ledger read and append paths scale past the old 8 MiB failure.
3. **Key hierarchy and gate.** Exit: blast-radius tests pass, and owner authorization is bound to the exact bytes and epoch.
4. **Rollback guard.** Exit: snapshot restore, device clone and slot replay are all caught before any effect in the simulated witness setup. Hardware and witness-service tests are run or explicitly deferred.
5. **Sandbox and guest; immune ratchet, thymus and MHC; Laya rules-first.**
6. **Genesis UX whole,** through the full acceptance chain, face by face.
7. **Nostr layer, head witnesses, owner-wrapped backups.**
8. **Pairing (fixed portal protocol); Marmot groups; self-healing backups with the repair-layout health picture.**
9. **Guardian recovery Mode A, then Mode B** only if Peter chooses it.

---

## 10. Decisions Peter needs to make (do not guess these)

1. Recovery modes: A only, or A plus B.
2. Guardian numbers (4-of-5, 5-of-7, or something else), given the trade between availability and fault tolerance.
3. Timeout policy when the owner is unreachable: never finalize, or finalize after a long wait labelled "unconfirmed".
4. Clone policy: single-active-device leases for effects, or something else.
5. Override policy for failing antibodies: break-glass card, or hard block.
6. The order in which Genesis apps come over.

---

## 11. What not to claim

- Proof of unique humans.
- "Solved Nostr key loss."
- Thief-proof recovery without its stated assumptions.
- Pentora as security, compression or a 42-D breakthrough.
- Laya as a judge.
- Any production readiness from same-author simulations.

The strongest honest story is a personal agent whose data survives losing devices, whose recovery follows rules the owner set, and in which nobody, including the agent, gains hidden power.
