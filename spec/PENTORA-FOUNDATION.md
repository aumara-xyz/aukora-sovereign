> **Frozen input to NORTH-STAR.md, the only plan.** Kept so nothing is lost; never edited, never a plan of its own.

# Pentora at the foundation of AUKORA Sovereign

**From:** the NEBIUS session (Claude), for SOVEREIGN MAIN, at Peter's request. 15 October 2026.
**Status:** guidance, not gospel. The structural facts in section 1 were **COMPUTED** today from the canonical geometry table. The design mapping is a **PROPOSAL** for builders to test, adapt or reject with a written reason.
**Companion:** `AUKORA_Sovereign_Rebuild_Guidance_Spec_2026-10-15.md` (general rebuild invariants, keys, rollback, Nostr, recovery). This document covers one question only: **how Pentora becomes part of the foundation rather than a picture added at the end.**

---

## 1. The property that matters (COMPUTED from the canonical table)

Input: `geometry_index_table_v1`, sha256 `96b27c9b…8c61`, as used by Prime `packages/ui/faces/settings/src/aura/pentora.mjs`. 111 points, centre 55 fixed, 110 mutable cells, 5 cubes, 60 edges.

| Fact | Value |
|---|---|
| Cells per cube (excluding centre) | 26 = **8 corners** + 18 private cells |
| Cells shared by two cubes | **20** (the corners). Every corner belongs to exactly 2 cubes; none to 3+ |
| Cells private to one cube | 90 (18 per cube) |
| Cells shared by **every pair** of cubes | **exactly 2, for all 10 pairs** |
| Edges | all 60 run between corners; every corner has degree 6 |

**Structure in one line:** five groups; every two groups are joined by exactly two shared members; no member serves more than two groups; each group also has private members.

**Why that is special (TESTED by simulation, 100,000 trials):** wiring 20 shared members randomly among 5 groups leaves on average **1.21 pairs of groups sharing nobody**, and **78%** of random layouts have at least one blind pair. Pentora guarantees every pair is joined, twice, by construction.

This corrects an earlier finding. For pure erasure recovery, Pentora tied a random layout of the same shape (it clearly beat non-overlapping groups: 33% against 20% recovery with 4 losses). For **cross-checking and agreement**, the uniform pairwise joining is a real structural advantage that random wiring usually lacks.

---

## 2. One shape at three levels

Use the same geometry, with the same cell indices and code, for three foundational jobs.

### Level 1: the node's self-attestation map (PROPOSAL)

The node's health is a Pentora.
- **The 5 cubes are the 5 organs:**
  1. Aumlok (identity and keys)
  2. Gate + Aura (authority and the record)
  3. Kira (memory)
  4. Network (Nostr, relationships, guardians, relays)
  5. Body (code, release, sandbox, immune)
- **Private cells (18 per organ):** that organ's own invariant checks. Examples: Aura chain verifies; gate floor matches; Kira index pin matches; sandbox probe passes.
- **Corners (2 per organ pair, 20 total):** cross-organ invariants that **both organs must independently confirm**. Examples:
  - Aumlok × Aura: the owner credential epoch in Aumlok equals the epoch recorded in Aura; the Nostr key binding is present in both.
  - Kira × Aura: Kira's verified head is anchored in Aura; quarantine count agrees.
  - Body × Gate: the running binary digest equals the approved release; the antibody corpus root equals the release fact.
  - Network × Aura: the latest head witness on relays equals the local head; the guardian set epoch agrees.
  - …one pair of invariants for each of the 10 organ pairs.
- **Each cell is ternary** (the "in-between" made exact):
  - **+ verified**
  - **0 undetermined** (not yet checked, source unreachable, or stale)
  - **− failed**

  A corner is + only when both organs confirm. If they disagree it is −, and the fault is localized to that organ pair.
- **Design discipline this forces:** every pair of organs must be cross-checked by exactly two invariants. No organ can go unwatched by any other. This is a completeness rule the geometry enforces: an empty corner is visibly an unwritten check.
- **Hook into the immune system:** the MHC loop computes this map. A − cell is evidence for quarantine or escalation, never authority. A 0 cell is reported honestly as "not verified", never shown as healthy.

### Level 2: the living network's layout (PROPOSAL, partially TESTED)

The owner's safety net uses the same geometry.
- **5 circles** of people and devices (cubes).
- **Corner holders** each belong to two circles. Every two circles share exactly two holders.
- **Uses:**
  - **Backup repair groups.** Encrypted shards are placed by cell. A lost piece is rebuilt locally inside its circle.
    - TESTED: a local repair rule recovered everything that global decoding could.
    - TESTED: repair traffic is about 4× lower than all-in-one Reed-Solomon.
  - **Witness quorums against rollback.** Take a circle's full set of corner holders as the quorum. Any two circles' quorums intersect in exactly 2 holders. With at most one equivocating holder per intersection, two conflicting checkpoints (or two conflicting successor approvals) cannot both gather full circle quorums without an honest shared holder seeing both.
    - This is the same safety logic as the tested 2q − n > f bound, delivered by geometry. Tolerance is f = 1 per pair. Requiring two circles gives larger intersections; compute before relying on it.
  - **Lying detection.** A corner holder that returns bad data fails the checks of both its circles, so it is identified, not just tolerated.
- **Scale honestly.** The full structure has 20 corner slots, which suits a community, family or organisation node. For an individual, a slot can be held by a device or a watchtower rather than a person. A single-corner variant (10 slots, each pair of circles sharing 1) keeps the "every pair joined" property but tolerates no equivocator. Test both.

### Level 3: what people see

- **`pentora.display.v1` fingerprint:** unchanged and display-only. Port Prime's hardening:
  - one derivation with vectors;
  - fail-closed rendering;
  - race guard;
  - no digest text while moving;
  - sources marked absent with a reason.
- **Health view (new):** the same cells rendered from the Level 1 or Level 2 maps:
  - solid: verified
  - dim: undetermined
  - red: failed
  - shimmering: repairing

  This is the first Pentora view whose cells mean something a person can read: "whole", "two pieces repairing", "Kira and Aura disagree".
- **Relationship bloom:** the shared Pentora from a pairing session. Visual only.
- **Keep the views separate and labelled.** A fingerprint picture (hash-derived) is never shown as, or confused with, a health map (state-derived).

---

## 3. What Pentora must never be used for (settled by testing)

- **Not authority.** No cell, picture or map grants anything.
- **Not human-compared security.**
  - Near-match grinding needs about 2^55 work for a picture within 30 differing cells, and people miss small differences.
  - Pairing uses camera exchange, or emoji / short codes read aloud.
  - The Stranger line compares exact bytes.
- **Not compression.** A network round-tripped through Pentora states came out 4.77% larger.
- **Not encryption.**
- **Not a 42-D packing record.** 21-trit Construction A tops out at 2^-10.70 centre density: below the random-lattice bound of 2^-10.21, and about 30× sparser than plain Leech + BW16 + A2.
- **Not a universal learning prior.** It helps only where the world shares its structure, like any correct map.

---

## 4. Tests to run as the foundation is built

1. **Geometry conformance.** Rust and JS derive the identical cube, corner and pair table from the pinned geometry file, with the pairwise-intersection property asserted in tests. A geometry change must fail CI.
2. **Self-attestation map.**
   - Fill all 110 cells with real checks: 18 per organ, 2 per organ pair. A cell with no check is a failing test, never green.
   - Inject faults (tamper a target, desync epochs, drift Kira's head) and verify the right cell or pair turns −.
   - Strip-neutrality: the map never changes a gate decision.
3. **Witness quorums.** Simulate checkpoints and successor approvals with circle quorums over the corner holders.
   - Attacks: one equivocator per pair, then two; rollback attempts; split networks.
   - Compare against flat k-of-n with the same number of holders, on safety and availability.
4. **Repair layout** with real erasure codes, using corner holders and private-cell holders. Measure recovery, repair traffic and liar identification, against non-overlapping, random-overlap and Reed-Solomon layouts.
5. **Health view.**
   - Exact derivation from state.
   - Undetermined is never rendered as healthy.
   - Accessible labels.
   - Optionally, a consented user check that people read "whole / repairing / disagreement" correctly.
6. **Individual-scale variant.** The 10-slot single-corner design and device or watchtower holders. Report what tolerance is lost.

---

## 5. Build placement

- **Phase 1–2** (with the carry list and the Aura/epoch foundation): pinned geometry tables, Rust↔JS conformance, and the organ map with real checks (Level 1). The self-attestation map is part of the foundation, not the UI.
- **Phase 5** (immune): the MHC loop computes the Level 1 map. The owner page shows the health view next to the fingerprint.
- **Phase 7–8** (Nostr, backups, pairing): the Level 2 layout for backup repair and witness quorums, and the relationship bloom.

---

## 6. The honest summary

Pentora becomes foundational not because its geometry has hidden powers, but because its structure has one exact, useful property: **five groups, every pair joined by exactly two shared members.** That is what a system of mutual cross-checks needs. AUKORA can use the same shape for three things:
- how a node checks itself (every organ watched by every other);
- how a person's network protects them (every circle cross-checking every other);
- what the owner sees (a picture whose cells are real, verified facts).
