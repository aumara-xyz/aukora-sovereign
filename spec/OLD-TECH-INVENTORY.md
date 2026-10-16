# Old technology carry inventory

This is the capability inventory required by NORTH-STAR.md row 127, not another plan.
Its entries preserve the subjects of the 27 September audit in newly written words.
They do not declare that a capability is implemented, accepted, or running in Sovereign.
Only NORTH-STAR.md assigns work and only Peter can dispose of a carried item.

## Provenance and stable identifiers

- Primary source: `OLD-TECH-INVENTORY-20260927.md`, dated 2026-09-27.
- Primary source SHA-256: `49aba2857449271b0f95f11a182882146067e826780105a3728a9cdc70e1cf05`.
- Gap context: `GEMS-AUDIT.md`, dated 2026-10-16, audit of revision `6731164`.
- Gap context SHA-256: `dfa48651709063ed9e1d1c617acb6a4939b24c919a589967d830f8c627e57e3c`.
- `OLD001` through `OLD014` retain the primary source's numbered order. `SPEC001`
  through `SPEC010` identify its unnumbered specification and research subjects.
- An identifier belongs permanently to its capability. Deleting, renumbering, or
  rewriting it is a carry change, even if the document's total row count stays equal.
- Plan-row references locate related work; they are not coverage verdicts. `unmapped`
  means the whole capability has no explicit plan row. A nearby feature does not
  dispose of the remainder of a capability.

The primary audit examined historical revisions and reported a mixture of exercised
code, partial exercises, environment failures, and unrun designs. It explicitly did
not establish integration into the then-running app. Those historical observations
are not current runtime evidence. Its port estimates and recommendations to skip,
defer, or replace items are not Peter's dated dispositions and authorize no omission.

## Numbered capabilities

| ID | Capability | Carry requirement | Plan rows |
|---|---|---|---|
| OLD001 | Separate issuer, broker, supervisor, and guest principals | Retain the issuer's distinct operating-system identity, broker mediation, and supervisor observation of principals, jobs, and file modes against the launch manifest. Preserve checks of issuer custody and confinement. A signer in another process under the same user does not establish this boundary; the original audit's two failed harness launches established no verdict. | 26,27,29,102,128 |
| OLD002 | Signed, file-granular write law | Retain owner-signed allowlisting before every agent write or edit, refusal of every write when the law is unsigned, normalized path judgment, and a chained decision receipt. Connect the guard to the actual tool dispatch surface; a hook in a different harness is insufficient. Preserve the small dependency-free guard design as reference, without restoring agent command execution. | 30,33,41 |
| OLD003 | Pure authority decision kernel | Retain a verifier that takes policy, trusted consumed-id and receipt-head state, the SALAMA stop, and a request, then returns a decision without private keys, environmental reads, wall-clock reads, storage, networking, or effects. Preserve mandatory Ed25519 plus ML-DSA-65 checks, downgrade refusal, RFC 6962 inclusion and consistency, and refusal when trusted state is stale. Related gate and hybrid rows do not alone cover the pure kernel or SALAMA stop. | unmapped |
| OLD004 | Disposable candidate materialization | Retain path fencing and repository identity checks, a separate disposable candidate branch, and fresh verification of every draft's hybrid owner authorization at materialization. Stored interface or workflow state must not substitute for that check. Keep candidate creation separate from advancing main; owner-approved compare-and-swap promotion is a distinct operation. | 33,35,85,131 |
| OLD005 | Independent second-machine frontier acknowledgment | Retain a second machine's signed acknowledgment of the exact receipt checkpoint it retained without receiving content, initial peer comparison by the owner, monotonic sequence checks, and a hard stop on writer-epoch disagreement. Keep verified, contradicted, and unavailable outcomes distinct. The source's partial pairing exercise was not a completed verified exchange. | 101 |
| OLD006 | Governed memory recall | Retain containment, memory-envelope validation, ingest admission, and scope checks throughout recall. Retrieved content remains evidence and cannot acquire authority or escape its permitted scope. Cited retrieval by itself does not account for the full admission pipeline. | 57,58,59 |
| OLD007 | Offline grant, receipt, pairing, and settlement modules | Retain cold checking of grants, receipts, Aura records, mediation, settlement, device-pair verification, composition, roles, subjects, checkpoint continuity, retain handoff, and explicit verification ceilings. Account separately for the source's loader, simulated device, court, refusal registry, lock, and patent-license modules; a small vendored verifier subset does not cover the whole group. Historical optional cross-library checks were not completed. | unmapped |
| OLD008 | Compact complete transaction and stranger verifier | Retain the approve, grant, settle, recall, export, and independently anchored cold-verification chain, including refusal after one exported byte changes. Account for joined settlement, witness protocol, sandbox, enrolment, and succession separately from the core loop; the source did not establish all of those as integrated or nonexperimental. | 33,43,48,51,52,57,61,62 |
| OLD009 | Governed crossing from an agent intent | Retain a narrow adapter from an agent-authored pending intent to governed candidate handling. It must create no parallel approval route: an owner's independent signature remains the authority boundary. Related proposal and recursion work does not by itself account for this bridge. | unmapped |
| OLD010 | Authenticated write-route entry | Retain refusal of HTTP write routes without an authenticated session, with coverage of every write route. A replacement session mechanism must enforce that behavior at the route, even though the historical audit judged a duplicate implementation low priority. | 19,23,41,43 |
| OLD011 | Screen and vision content fence | Retain a nonce-delimited representation of captured visual content and its source provenance so a description of a screen is never treated as an instruction. Keep this requirement attached to any future vision intake; absence of vision today is not a disposition of the item. | 15,31 |
| OLD012 | Scoped memory, council, and durable workflow facade | Retain the scoped memory envelope and one staleness rule; account for multi-model deliberation with disagreement recording; account separately for the asynchronous persistent-workflow cache interface. The historical injected-I/O exercise did not establish a live workflow backend. No historical backend or council may gain authority merely by being carried. | unmapped |
| OLD013 | Memory-write epoch co-signer | Retain the function of a separate Ed25519 co-signer for bounded-lifetime memory-write epochs and a replay-resistant nonce ledger. The original tool depended on an external gate and was not exercised. Its author's replacement recommendation is not an owner disposition; any replacement must account for the bounded epoch and replay properties. | unmapped |
| OLD014 | Membrane control-plane capabilities | Account separately for proposal and approval handling, tamper-evident recording, swarm packing, and the engine boundary. The source's large control plane had an incomplete verification suite and an unperformed identity ceremony; neither importing the package nor citing its smaller descendants establishes completion. | unmapped |

## Specification and research subjects

These subjects were explicitly distinguished from implementing code in the primary
audit. Carrying them preserves a decision; it does not authorize implementing them
or substitute their historical design for the frozen Sovereign contracts.

| ID | Capability | Carry requirement | Plan rows |
|---|---|---|---|
| SPEC001 | Separated action, amendment, and attestation powers | Retain the distinction between an effect, a change to governing rules, and an observation. The historical architecture labelled these powers specified; evidence cannot be promoted into owner authority. | unmapped |
| SPEC002 | Activation statement | Retain the named activation-statement concept as an unresolved specification item. Do not infer an implemented or authorized activation mechanism from the name. | unmapped |
| SPEC003 | Boundary experiment claim | Retain the named statement for a boundary experiment separately from enforcement and approval. The historical architecture classified it as specified. | unmapped |
| SPEC004 | Hook-custody triad | Retain the named custody design as a specification item requiring an explicit decision. The source did not report implementing code for it. | unmapped |
| SPEC005 | Skeleton Key II research | Retain the architectural and measurement research as reference material, without claiming it is executable machinery or a validated security boundary. | unmapped |
| SPEC006 | Golden Boundary research | Retain the historical boundary research and measurement discussion as reference, subject to the current charter and contracts; a research document is not a component to activate. | unmapped |
| SPEC007 | Threshold guardian custody | Retain the k-of-n Shamir custody proposal as an undecided historical design. Guardian recovery work must preserve the current rule that the owner root stays outside guardians unless Peter changes that choice. | 125 |
| SPEC008 | Bhutan and Project 108 seed | Retain both the Bhutan integration idea and the Project 108 seed concept, which the audit found only in specifications. Related vision work does not prove either delivered. | 97 |
| SPEC009 | Proposed sensing extensions | Retain the sensing proposals as unresolved design subjects; the source supplied no implementing code or accepted authority route for sensed data. | unmapped |
| SPEC010 | Alternative memory architectures | Retain the historical alternative-memory proposals as research choices. Their inclusion does not replace Kira's frozen data formats or authorize a new persistence system. | 96,97 |

No owner disposition is recorded in this document. The missing 522-row packet and
the fifteen coverage gaps named by row 127 remain separate inventory obligations.
This inventory does not declare M1 complete or permit a release proposal.
