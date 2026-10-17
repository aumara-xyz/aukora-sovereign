# AUKORA — Sovereign Composable Runtime
## Technical direction and hardening specification

**Version:** 0.2 · **Date:** 29 September 2026  
**Purpose:** Permanent technical record of the architectural direction developed on 28–29 September 2026, now integrating a proposed OpenShell containment backend, control-plane governance, and optional hardware hardening. Existing AUKORA contracts and the seven-word acrostic are preserved; new integration requirements are distinguished from inspected implementation.  
**Prepared for:** Peter Viviani  
**Status:** Design specification. Proposed requirements below are not claims that the current application satisfies them.

> **Intelligence is replaceable. Authority must not emerge from intelligence.**
>
> AUKORA’s proposed direction is a person-controlled runtime in which models and other components can change, while permission, identity continuity, evidence, and the ability to stop or leave remain under separately enforced control.

---

## Revision record and reading map

| Revision | Change | Evidence posture |
|---|---|---|
| 0.1 | Established the sovereign composable runtime direction, 26 sections and B01–B52 conformance cases. | Targeted AUKORA source review at `39a5da3f5190018fbcfc9e945506ba8de75f05e7`; no live deployment tests. |
| 0.2 | Integrates OpenShell throughout the same architecture; adds UID/resource placement, data-plane and control-plane adapters, policy refinement, asynchronous approvals, provider-use binding, optional attestation, licensing, and O01–O40. | AUKORA delta refreshed to `289d2cebab92249639cd4dfcf7f9fa7539e4ff58`; OpenShell interfaces reviewed at a separately pinned commit. Integration and 92-case test inventory remain proposed/unrun. |

**Preserved original:** `AUKORA_Sovereign_Composable_Runtime_Technical_Spec_v0.1.md`, SHA-256 `45ecd2dc9762e98d92d4953210e92c53654578786ca0cd45d45b1f3f6b8883b9`.

**Read first for building:** §1.5 gives the new decision; §4.5 shows placement; §20.5–§20.23 specify OpenShell integration and residual risks; §22 gives the revised first three increments; §21 retains the original tests and adds the integration cases. The remaining sections preserve the complete identity, memory, provenance, recovery, human-interface and ten-year direction.

**Revision boundary:** This is one technical specification, not a deployment certification. OpenShell software features are upstream evidence, not AUKORA achievements. Sentry/BlueField-specific execution guarantees are not assumed. No repository, deployment, policy, credential, or signing configuration was changed to produce this file.

---

## Contents

1. [Executive technical statement](#1-executive-technical-statement)
2. [Evidence baseline and current implementation](#2-evidence-baseline-and-current-implementation)
3. [Terminology, threat model, and security claims](#3-terminology-threat-model-and-security-claims)
4. [Reference architecture and trust placement](#4-reference-architecture-and-trust-placement)
5. [Cordis integration and lifecycle safety](#5-cordis-integration-and-lifecycle-safety)
6. [Canonical effect contract](#6-canonical-effect-contract)
7. [Trusted approval: proposal, display, signature, execution](#7-trusted-approval-proposal-display-signature-execution)
8. [Capability delegation and deterministic admission](#8-capability-delegation-and-deterministic-admission)
9. [Broker transactions, replay, rollback, and revocation](#9-broker-transactions-replay-rollback-and-revocation)
10. [Laya as a bounded semantic reflex](#10-laya-as-a-bounded-semantic-reflex)
11. [Privacy and the two-way membrane](#11-privacy-and-the-two-way-membrane)
12. [Aumlok: seven-word acrostic and entropy](#12-aumlok-seven-word-acrostic-and-entropy)
13. [Local mnemonic story and multilingual ceremony](#13-local-mnemonic-story-and-multilingual-ceremony)
14. [Root custody, recovery, rotation, and multiple devices](#14-root-custody-recovery-rotation-and-multiple-devices)
15. [Per-node diversity without secret mathematics](#15-per-node-diversity-without-secret-mathematics)
16. [Aura, Kira, evidence lineage, and vouches](#16-aura-kira-evidence-lineage-and-vouches)
17. [Sovereign node-to-node communication](#17-sovereign-node-to-node-communication)
18. [Safe evolution and constitutional succession](#18-safe-evolution-and-constitutional-succession)
19. [Usability, care, and psychological authority](#19-usability-care-and-psychological-authority)
20. [Deployment profiles, OpenShell integration, and optional hardware hardening](#20-deployment-profiles-openshell-integration-and-optional-hardware-hardening)
21. [Conformance and hardening test specification](#21-conformance-and-hardening-test-specification)
22. [Build-first sequence and graduation gates](#22-build-first-sequence-and-graduation-gates)
23. [Ten-year design horizon](#23-ten-year-design-horizon)
24. [Decisions, non-goals, and unresolved questions](#24-decisions-non-goals-and-unresolved-questions)
25. [Concept coverage register](#25-concept-coverage-register)
26. [Sources and inspection scope](#26-sources-and-inspection-scope)

---

## 1. Executive technical statement

### 1.1 The architectural change

The proposed system is not “a powerful AI protected by another, nicer AI.” It is a runtime that separates **information production**, **authorization**, **execution**, and **evidence** into different responsibilities and, where necessary, different protection domains.

A remote model can reason, draft code, propose actions, or recommend changes. Its local adapter receives those outputs as untrusted input. Neither the remote model nor that adapter receives the owner’s ambient operating-system authority simply because the owner asked for assistance.

The protected execution path accepts a narrow, versioned operation, checks permission issued under the person’s control, and performs only that operation. The system records the authorization decision separately from what it actually observed afterward.

Cordis supplies a useful model for the replaceable parts: explicitly declared dependencies, tracked resources, dependent teardown, and dynamic composition. It does **not** make arbitrary in-process code safe. Its paper expressly places hostile components behind an external execution boundary and bridge. Its recovery results also exclude already-emitted external effects. [C01] (§§5.1.1, 6.1–6.3)

The resulting direction is:

**A stable authority and continuity layer underneath an evolving graph of computation.**

This is an architectural synthesis, not a claim to have invented capabilities, reference monitors, signatures, sandboxing, or provenance. The older Golden Boundary explicitly credits that prior art. [D01] (§2)

### 1.2 The four separations that carry the design

| Separation | Required consequence |
|---|---|
| Intelligence ≠ authority | Better reasoning does not mint a grant, enlarge a scope, or change the trusted policy. |
| Composition ≠ confinement | A plugin declaration controls lifecycle; a protection boundary controls what hostile code can actually reach. |
| Authorization ≠ execution | A valid permission and a spent nonce do not prove the requested action happened. |
| Provenance ≠ truth or independence | A signed history can support claims about records; independent observation and factual correctness need additional evidence. |

The first and fourth develop the two boundaries made explicit in Genesis’s Rev 2.4. The second and third are necessary to implement them without overclaiming. [G02]; [C01] (§6.3); [D02] (§§3–4)

### 1.3 The intended invariant

For an enumerated effect class, under a declared deployment and trust model:

```text
Every admitted protected effect has:
  a recognized effect definition;
  an exact, immutable proposal;
  a valid authority chain anchored outside the proposing component;
  current scope, epoch, audience, and resource checks;
  durable use/budget accounting;
  an executor operating under that checked contract.
```

This is not a theorem about arbitrary future intelligence, every physical effect, or an operating system already controlled by an attacker. It is a concrete engineering property to establish for specific paths, platforms, and assumptions.

**The design goal is safe delegation, not perfect judgment.** An action can be genuinely authorized and still mistaken or harmful. The authority boundary prevents unauthorized effects; it does not certify that every authorized action is wise.

### 1.4 The first build target

The first complete instantiation should use the already-carried **`workspace.patch`** effect: one preimage-bound UTF-8 file replacement inside an operator-selected disposable workspace. It should use a real confined proposal process, a separate issuer/approval path, a protected broker, and retained execution evidence.

This is deliberately smaller than a universal operating system. The carried registry already distinguishes `memory.put`, `workspace.patch`, and a staged `compute.job` definition. A new general-purpose operation vocabulary is not needed before the first enforced path works. [G13]

### 1.5 What OpenShell changes in this direction

**Adopt an existing containment implementation as a candidate backend; do not rebuild the entire sandbox before testing AUKORA's authority contract.** OpenShell's separation of supervisor and workload, its network/credential boundary, and its policy-governance extension surfaces map to part of the missing deployment substrate. [N01], [N03], [N06]

This creates three engineering questions, not one:

1. **What can the agent reach?** A qualified runtime profile restricts files, processes, network and credentials.
2. **Who can change those restrictions?** AUKORA-governed control operations protect the backend configuration and authority ceiling.
3. **Which particular effect was authorized and what happened?** The existing AUKORA effect broker, immutable approvals, durable accounting and scoped evidence remain necessary.

AUKORA is not moved wholesale into one privileged container. The proposal side is confined; the issuer, broker and recovery/checkpoint custody remain outside the domain they govern. OpenShell is replaceable and Sentry is optional. The foundation is the contract and its qualification evidence, not a vendor dependency.

NVIDIA itself describes separating agent requests from the authority to grant them. The strategic claim is therefore not that nobody else understands this distinction. The proposed contribution is making the integrated authority, continuity, recovery and exit behavior work under the person's control across replaceable runtimes and providers. [N14]

---

## 2. Evidence baseline and current implementation

### 2.1 Preserved v0.1 source baseline

| Subject | Reviewed identity |
|---|---|
| Genesis repository | `aumara-xyz/aukora-genesis` |
| v0.1 resolved `main` commit | `39a5da3f5190018fbcfc9e945506ba8de75f05e7` |
| Git tree | `085bd9649a780b947fcbe615ad11813171a5a131` |
| Commit timestamp | `2026-09-29T00:05:52Z` |
| Commit description | Memory Phase1 A1b2: legacy-forget court; explicitly no erasure claims |
| Deep doctrine / carried box baseline | `c417f7c5752bf14b8e927986cd995f2e086f4189` |
| Laya upstream baseline | `9d955671415fc19f069b9cc998928075c1f255ec`, release description 0.3.21 |
| Cordis paper | Uploaded `Cordis(6).md`, *A Programming Paradigm for Spatiotemporal Composability* |
| Cordis file SHA-256 | `f7b4e2fe0368b7a047a581033ce9d0fcc6488f80129216f79eab0b4cad6a4669` |

For v0.1, the branch and tree above were resolved through the GitHub connector. That revision recorded an unsuccessful local clone attempt because its execution environment could not resolve GitHub. The v0.2 refresh also uses connector reads and the commit comparison; it does not claim a successful clone. The substantive review therefore used pinned connector file reads, not a successful checkout. The recursive tree response was also output-truncated; it is not represented here as an exhaustive inventory. [G00]

**No installed application, local worktree, private job directory, owner key, or live approval ceremony was accessed. Repository test suites were not executed in this review.** An overnight commit message reporting passing checks is a source report, not a reproduced test result. The only local calculations performed for this document were illustrative entropy arithmetic and document validation.

### 2.2 Evidence labels

- **SOURCE-INSPECTED:** the cited implementation or definition was read at the pinned subject.
- **REPOSITORY-REPORTED:** documentation or commit metadata reports a behavior; it was not reproduced here.
- **REMOTE-CONFIG-READ:** GitHub returned the configuration during this review; it is mutable and not part of the Git tree.
- **PROPOSED:** a normative requirement introduced by this specification.
- **HORIZON:** a possible extension whose implementation or assumptions remain unresolved.
- **UNVERIFIED / UNRUN:** no sufficient observation was obtained.

`MUST`, `MUST NOT`, and `SHOULD` below define **proposed conformance requirements**, not a declaration that the current application complies.

### 2.3 Preserved source findings and their limits

| Area | Evidence now available | What it does not establish |
|---|---|---|
| Governed code-change route | `self-change.mjs` stages a preview, requests approval, invokes dual verification, materializes through the candidate authority adapter, commits, and records outcomes. **SOURCE-INSPECTED.** [G04] | Exclusive mediation of every write, push, build, or running-app change. |
| Approval verification | `dual-verify.mjs` requires both the Node verifier and Python cold verifier to accept the same bindings. **SOURCE-INSPECTED.** [G05] | An independent outside audit, independently provisioned trust anchors, or a trusted display. |
| Approval admission | `decide.mjs` verifies Ed25519 against the pinned approver, binds operation/subject/control/window, then uses the carried kernel for policy and one-use state. **SOURCE-INSPECTED.** [G06] | The kernel’s hybrid Ed25519 + ML-DSA-65 authorization profile being used by this adapter. It explicitly is not. |
| Restore protection | The adapter uses an approval-state store and a high-water witness outside the ordinary `state` directory. **SOURCE-INSPECTED.** [G06] | Protection when the same operating-system principal can rewrite both witness and state; coverage of every memory marker. |
| Tool-call gate | A Cordis tool-runtime guard judges calls and records decisions; source discloses uninspected child execution, direct host I/O, and text-analysis limits. **SOURCE-INSPECTED.** [G07] | OS-level confinement or complete mediation. |
| Commit-key/proof-store custody | R1 checks compare ownership and require separation when enabled; the requirement remains default-off. **SOURCE-INSPECTED.** [G08] | A production issuer deployment merely from the presence of these checks. |
| Commit binding | `assertOneUseCommitBind` can consume a proof-store record; its header says it is not wired into the candidate-authority path, and its allowed modes are spike/test. **SOURCE-INSPECTED.** [G09] | A completed production R2 issuer path or closure of every signer-oracle risk. |
| Component admission | The composition document describes approved plugin-set checking and explicitly excludes stock plugins/dependencies, worker loaders, and other surfaces. **REPOSITORY-REPORTED.** [G10] | Confinement of admitted code or protection against rewriting all same-UID trust files. |
| Carried effect registry | `memory.put` and `workspace.patch` have closed definitions. `compute.job` is in a staged registry rather than the admissible registry. **SOURCE-INSPECTED.** [G13] | A live Genesis agent confined behind that broker. |
| Activation identity | `ActivationStatementV1` binds composition, core manifest, executable/resolver closure, renderer, model-emission policy, and broker/issuer identities. **SOURCE-INSPECTED.** [G14] | Coverage of unspecified dynamic dependencies, or proof that a reported configuration is running. |
| Box deployment | The carried-box provenance document explicitly says copied source is not mounted as the live agent boundary. **REPOSITORY-REPORTED.** [G12] | Current live deployment state beyond that dated report. |
| Anti-mimetic memory | `consolidate.mjs` groups matching normalized claims by transitive ancestry overlap, preserves unknown ancestry, and keeps the result non-authoritative. **SOURCE-INSPECTED.** [G11] | Proof that supplied ancestry is complete, true, or statistically independent; a deployed internet-wide evidence network. |
| Memory partial failure | `partial-failure.mjs` distinguishes found/empty/undetermined and passes stop/ask/proceed through an in-process ledger keyed by agent object. **SOURCE-INSPECTED.** [G15] | Cross-process authority, authenticated human reconsideration, or security against a compromised host. |
| Nostr/contact layer | Documentation describes per-node keys, bindings under a separately supplied peer key, contact states, and transport/event identity distinctions. **REPOSITORY-REPORTED.** [G16] | Proof of personhood, automatic transitive trust, or global non-conflict. |
| Phrase generator | Source still defines the anchor/acrostic and the Nature/People/Spirit position constraints; its header reports approximately 34.14 bits for the old measured generator. **SOURCE-INSPECTED; entropy not remeasured here.** [G17] | The proposed theme-free generator being implemented, or the actual desktop drawer having exactly that distribution. |
| Laya | Upstream documents typed classification, confidence-based abstention, and model/revision controls. **UPSTREAM-DOCUMENTED.** [L01] | A Genesis integration, safe classification on AUKORA tasks, or local latency measurements. |
| Reviewer packet | At the v0.1 pin, `scripts/check.sh` registers **26** commands and the README says **19**. The v0.2 delta adds three registrations, bringing the current runner to **29**. **SOURCE-INSPECTED / DIFF-CHECKED.** [G03], [G01], [U01], [U02] | Any of those tests passing in this review, or their results establishing the installed app. |

### 2.4 Overnight changes that must not be lost in the specification

The current source is not the same as the initial review. Dual-verifier calls, commit-binding/custody scaffolding, and explicit memory-partial-failure handling are present. They should be reused and hardened rather than described as wholly absent. [G03], [G04], [G05], [G06], [G07], [G08], [G09]; [G15]

During the v0.1 review, GitHub returned an active `main-protect` ruleset for `main` with **deletion prevention, non-fast-forward prevention, and linear-history requirements**. The inspected ruleset contains no required-signature or AUKORA-approval rule. Thus “there is no branch protection” is stale; “the inspected rule does not enforce AUKORA authorization” remains supported. The v0.1 commit’s GitHub verification metadata reports it as unsigned; approval trailers are a separate artifact from Git’s commit signature. The ruleset observation is retained historically and was not re-read in v0.2; branch metadata alone is not substituted for a fresh ruleset inspection. [G00]; [G18]

The README and Rev 2.4 still name installed release `0496ba077`. That is an operator-reported documentation clock, not a fresh observation of the laptop. No current live release is asserted here. [G01]; [G02]

### 2.5 What is preserved from the existing technology

The design retains the carried effect definitions, approval bindings, kernel, activation statement, Aura/evidence interfaces, Kira memory distinctions, and Cordis lifecycle model. It does not require a clean-slate rewrite, a new repository, or replacement of the product by a research toy.

The primary work is **closing and measuring the path between already-existing components**, then evolving contracts where a concrete requirement cannot be expressed by the existing schema.

### 2.6 Fresh AUKORA refresh for v0.2

| Item | Newly retrieved value |
|---|---|
| Repository | `aumara-xyz/aukora-genesis` |
| Current main at refresh | `289d2cebab92249639cd4dfcf7f9fa7539e4ff58` |
| Tree | `520f3eb7e1be208534402cab1002876b8034893c` |
| Commit timestamp | `2026-09-29T00:49:24Z` |
| Change from v0.1 baseline | Six commits ahead; eight changed paths in the returned comparison. |
| Latest commit description | Memory Phase1 A4b3: continuity-metrics library/court stubs; no score boost or erasure claim. |
| Check result in commit message | `29/29 passed` — repository-reported, not executed here. |
| Git commit verification | Metadata reports unsigned; this does not evaluate the separate Aumlok approval artifacts. |

The returned delta changes Kira's `continuity-metrics.mjs`, `recall-openviking.mjs`, `reserved-slots.mjs`, their relevant tests, and `scripts/check.sh`. It adds three test registrations. The reviewed custody, action-gate, broker-definition, README and phrase-generator paths are not among those changed files. This supports carrying their pinned v0.1 source findings forward; it does not establish the running Mac's configuration or review every new memory behavior. [U00], [U01], [U02]

No OpenShell integration was observed in this delta or in the v0.1 inspected architecture paths. Unseen local work remains unverified rather than declared absent. These memory changes are real source progress, but are not evidence that the worker/host authority boundary is already closed.

### 2.7 OpenShell evidence and release distinction

| Item | Retrieved identity |
|---|---|
| Upstream | `NVIDIA/OpenShell` |
| Inspected main commit | `1358941b818d4126a7374aaf5216d87fc960e122` |
| Tree | `b61132d4eae9ad22fb20ecf509bc54c2f237f34d` |
| Main timestamp | `2026-09-28T20:48:50Z` |
| Latest non-prerelease returned by release API | `v0.1.2`, published `2026-09-28T03:58:00Z` |
| Resolved v0.1.2 tag at this read | `6648bd0c290efbc41ba131ee9831ee45cd431f94` |
| AUKORA integration deployment | Not performed in this review. |
| Sentry-specific SDK/attestation integration | Not inspected or qualified here; optional research only. |

The inspected main and v0.1.2 tag are **different commits**. This document does not assume every main-branch interface is available identically in the release artifact. The first implementation must select one exact build, validate advertised extension capabilities, and stop on a missing requirement rather than silently substitute a development build. [N00]; [N12], [N13]

Pinned OpenShell sources were inspected for architecture, security defaults, middleware, gateway interceptors, route coverage and policy proof limits. That is stronger than relying on an AI-generated integration sketch, but weaker than auditing or executing the full runtime. No newly proposed test is represented as passed.

---

## 3. Terminology, threat model, and security claims

### 3.1 Terms

**Person / principal:** the source of the local delegation policy. A key is a technical credential for that policy, not proof of a unique human.

**Foreign intelligence:** any model, remote service, generated program, or component whose correctness is not a prerequisite for the protected effect boundary. “Foreign” is a trust classification, not a claim about physical location or intent.

**Proposal:** inert, bounded data identifying a requested operation. A proposal is not a grant.

**Grant:** a separately issued, scoped authorization. A legitimately authorized service may issue narrower descendants under a pre-existing delegation; a human need not sign every ordinary operation.

**Membrane:** the complete set of constrained crossings between trust domains. It is not merely a classifier, encoder, socket, or plugin.

**Reference core:** the minimum trusted admission and enforcement machinery, including its real dependencies and mutable authority state.

**Reflex:** a probabilistic component that may require more caution, but cannot supply missing permission.

**Receipt:** a scoped assertion about an admission or observed result. A receipt never becomes a fresh grant merely because it verifies.

**Constitutional change:** a change to who can authorize, what they may authorize, or how that authority is interpreted.

### 3.2 Threat classes

| Class | Assumption | Required stance |
|---|---|---|
| T1: misleading or malicious model output | The proposal source may lie or produce malformed data. | Protected effects still require separate valid authority. |
| T2: compromised ordinary plugin/adapter | Any replaceable application component may be hostile. | It reaches only its explicit resource/service capabilities. |
| T3: wrong or unavailable reflex | Laya may misclassify, time out, or be replaced by a faulty worker. | No grant expansion; required reflex failure blocks the affected admission path. |
| T4: compromised authority dependency | Issuer, renderer, resolver, broker, or authority store may be compromised. | State the loss of guarantees and contain by separation; do not pretend the same boundary survives by definition. |
| T5: compromised kernel/admin/hardware | Platform enforcement or the hardware root may fail. | Outside the first software profile’s guarantee; stronger devices/platforms are separate profiles. |
| T6: mistaken or pressured owner | A real person may authorize a harmful operation. | Human-factors and bounded-delegation defenses reduce risk; signatures do not prove comprehension. |
| T7: hostile peer, relay, or witness | Another node can lie, withhold, equivocate, or disappear. | Authenticate scoped statements, retain uncertainty, and never derive local authority from popularity. |

“Inside the membrane” is not a reason to trust software. Every trusted component requires a reason, a limited responsibility, and a defined failure consequence. Local execution improves some privacy and custody properties; it does not make a model accurate or a process invulnerable.

### 3.3 Required invariants

| ID | Invariant |
|---|---|
| INV-01 | A proposal, memory, confidence score, vouch, or receipt cannot itself mint authority. |
| INV-02 | Every protected effect path is completely mediated within the declared profile. |
| INV-03 | Missing policy, issuer, required assessor, current state, or broker identity does not silently select an ungoverned fallback. |
| INV-04 | Proposal, display, grant, effect definition, and executor interpretation bind to one immutable contract. |
| INV-05 | A grant’s scope can be narrowed downstream, never silently widened. |
| INV-06 | Revoked, expired, consumed, wrong-audience, or superseded authority cannot authorize a new protected admission. |
| INV-07 | Removing a required mediator closes the effect path before teardown completes. |
| INV-08 | Authority, evidence, transport, and identity keys have distinct roles and domains. |
| INV-09 | Restoring application state cannot silently restore consumed authority or revoke a later revocation. |
| INV-10 | A change of model, plugin, schema, or device cannot silently reinterpret old grants more broadly. |
| INV-11 | Repeated descendants do not count as independent evidence merely because they have different signatures or names. |
| INV-12 | The person can stop new admissions and can export usable continuity/evidence without the current model. |

These are requirements to earn. Finite test success is evidence for the declared cases and environment, not a proof against every future adversary.

### 3.4 New integration threat classes

**T8 — control-plane authority:** the gateway operator, runtime administrator, provider editor or policy updater can change what the workload may reach. Those powers must be isolated from the worker and governed separately; a sandbox alone does not protect its own administration.

**T9 — translation and mutation mismatch:** the approved AUKORA operation, compiled backend policy, middleware-visible request and eventual executor input can differ. Each translation must retain explicit binding, supported semantics and version identity.

**T10 — incomplete migration:** the main worker can be confined while an external coding subprocess, plugin installer, native desktop integration or legacy helper still runs with owner authority. The claim is bounded by the union of those reachable paths, not by the safest path alone.

These threat classes extend T1–T7. Compromise of the host/supervisor remains outside a profile that explicitly trusts it. Adding containers does not silently change the administrator-compromise assumption.

---

## 4. Reference architecture and trust placement

### 4.1 Logical architecture

```text
                         PERSON / CONTROL POLICY
                         |                   |
               bounded delegation      trusted approval surface
                         |                   |
                 protected authority / issuer / recovery policy
                         |                   |
REMOTE OR LOCAL          |                   |
MODEL                    v                   v
  |                [ protected admission core ]
  | proposal                 ^       |
  v                          |       | one-use execution permit
confined adapter ----> immutable      v
or confined worker     proposal --> effect broker ------> selected resource
  |                     store          |
  |                                    | observed result / uncertainty
  +--> optional isolated Laya assessor  v
             |                    Aura / receipts / retained checkpoint
             +--> veto/review only     |
                                      v
                             separate verification consumers

CORDIS organizes replaceable adapters, assessors, tools, interfaces, and memory
providers. Host-side bridge fibers expose explicit services across protection
boundaries. The authority core and its deployment control cannot be unloaded or
replaced by an ordinary component they govern.
```

This is a graph, not one long pipe. Models make outbound requests through an egress boundary. Memory enters model context through a disclosure boundary. Assessment is a side computation over a bounded proposal. The broker is the last local authority check before an effect, not an application plugin placed after an ungoverned execution path.

### 4.2 Protection domains

**Domain A — proposal workers.** Model adapters, ordinary generated tools, document parsers, and candidate code execute with no ambient owner credentials. They may hold narrowly delegated scratch resources. A remote model does not have to run inside this domain; its local adapter does.

**Domain B — composition host.** Cordis manages the replaceable graph. Application plugins in a shared process are not mutually hostile-safe simply because they have different fibers. Untrusted plugins need separate execution domains; their host-facing representations can still be Cordis fibers.

**Domain C — authority service and trusted renderer.** This domain resolves current trust anchors, prepares approval material, and issues scoped grants under the control policy. Its configuration and signing path are not writable by Domain A or ordinary Domain B components.

**Domain D — effect broker.** The broker has the minimum access necessary to the selected resources and credentials. It does not inherit the entire owner account’s home directory, shell authority, or general-purpose signing rights. It accepts only registered effect contracts.

**Domain E — evidence retention / recovery.** Durable accounting and independent checkpoints are outside the state-restoration boundary they are meant to detect. Distinct process IDs alone are insufficient if all state can be rewritten by the same principal.

Some domains may be implemented together in an explicitly weaker profile. That choice enlarges the trusted computing base and changes the claim. A separate user account, a sandbox, a hardware authenticator, and a VM are mechanisms with different properties, not interchangeable labels.

### 4.3 The small foundation is not literally one percent

“Bottom 1%” means a deliberately restricted trusted foundation, not a measured code-size ratio. The real trusted base includes the operating system, cryptographic library, parser/canonicalizer, resolver, launcher, authority configuration, state store, trusted display path, broker, and relevant build artifacts.

The core MUST publish a manifest of those dependencies. A short `decide()` function does not make its surrounding trusted system equally short.

### 4.4 Replaceability without ambient privilege

A model-provider adapter SHOULD be replaceable without changing authority policy. A new provider does require review of what data it receives and where that data goes. A model swap is therefore not automatically a no-risk change even when it gives the model no extra tool permissions.

The same principle applies to a memory backend, a new interface, or a transport: **substitutability at the API level does not prove equivalence of privacy, custody, or authority semantics.**

### 4.5 OpenShell placement within the same architecture

OpenShell belongs principally in **Domain A's containment and its controlled connection to Domains B–D**, not around the entire authority hierarchy as one shared workload. The backend has privileged supervisor/gateway components of its own that must be included in the real trusted-base manifest. [N01]

```text
                     HUMAN CONTROL / RECOVERY
                               |
                  AUKORA authority + trusted approval
                      |                      |
          governed deployment changes       | exact operation permit
                      v                      v
             OpenShell gateway       AUKORA effect broker
                      |                      |
             trusted supervisor     protected selected resource
                      |
             actual execution boundary
                      |
        Cordis worker + ordinary plugins + child tasks
                      |
          model requests and inert candidate proposals
```

A protected OpenShell configuration is an implementation of part of the membrane. AUMLOK issuance and operation accounting are not delegated to a classifier, the gateway's name, or a receipt viewer. Different protection domains may share hardware under a stated profile, but they must not share writable trust state with the worker.

The initial assembly and exact residuals are specified in §20.7–§20.10. Platform-independent contracts remain stable even if OpenShell is later replaced by another qualified runtime.

---

## 5. Cordis integration and lifecycle safety

### 5.1 What Cordis contributes

Cordis’s paper formalizes context-mediated effects with supplied inverses and dependency-driven component lifecycles. Dependencies can be withdrawn in an order that lets consumers finish cleanup before a provider disappears. It also describes cross-process providers and host-side bridge fibers. These are directly relevant to replaceable models and protected services. [C01] (§§3.1–3.2, 4.3.1, 5.1, 6.2–6.3)

The implementation does not verify that each supplied inverse is correct. The recovery theorems depend on conditions including effect discipline and independence. They are not proofs that arbitrary plugins restore the host or undo real-world actions. [C01] (§§3.3.2, 4.4.2, 5.1.1)

### 5.2 Required service shape

A consequential consumer MUST depend on the protected effect service, not on an unrestricted filesystem/network/process provider with an optional guard attached.

```text
consumer requires guarded-effect service
             |
             v
host bridge / revocable handle
             |
             v
protected broker
```

There MUST be no fallback to `node:fs`, a shell, a second provider, a direct network client, or another broker when that required service is absent. Load-time dependency review and OS confinement are both necessary: declarations describe intent; confinement limits bypasses.

The paper distinguishes proxy-mediated property access from bare `ctx.get()` lookup. The specification must not assume that every way to obtain a service automatically enforces the same declaration contract. The actual harness version and bridge behavior need tests. [C01] (§5.1.4)

### 5.3 The guard-removal invariant

The archived Golden Boundary’s useful target is **removing the mediator stops the emitter**. It is not “the removed plugin’s code magically continues to enforce policy.” [D01] (§4g.1)

The protected broker must therefore maintain a revocable admission epoch or equivalent state independently of Cordis teardown:

1. Mark the affected authority path inactive and reject new admissions.
2. Invalidate uncommitted permits and stale bridge generations.
3. Notify and drain dependent components.
4. Permit only specifically defined cleanup operations.
5. Release resources and complete unload.

Steps 1–2 precede waiting for a potentially slow or faulty disposer. A cached service reference or request already queued in another process must not evade revocation because a JavaScript object still exists.

### 5.4 Cleanup is not rollback

| Operation | Meaning |
|---|---|
| Unload adapter | Stop future calls and reclaim tracked local resources. |
| Revoke authority | Deny future protected admissions under a grant or epoch. |
| Roll back a private staged file | Restore a version under exclusive control before publication. |
| Compensate an external effect | Perform another effect, such as an allowed refund; it may be partial or fail. |
| Erase a past disclosure | Generally unavailable once another party has received it. |

Cordis’s acquisition/emission distinction is preserved explicitly. Socket cleanup does not unsend a message. Killing a process does not revoke a copied credential. Reloading a model does not remove information already disclosed to its provider. [C01] (§6.1)

### 5.5 Configuration and hot replacement

Changes to component configuration, service interception metadata, provider identity, and transitive code dependencies can change authority without changing a familiar plugin name. The activation record MUST bind the relevant versions and configuration.

Hot replacement of an ordinary component is permitted only within its existing authority envelope. Changing a guarded provider, parser, issuer, renderer, authority policy, or privileged bridge is a separately governed activation, not ordinary hot reload.

Independent component rollback must not restore an earlier authority epoch. Application state can go backward; consumed authorizations and revocations cannot silently do so.

### 5.6 Cordis and the sandbox backend are complementary lifecycles

Cordis can expose a qualified sandbox-backed worker as a component, and expose the AUKORA broker through a narrow host bridge. It must not expose the OpenShell gateway administrator as an ordinary worker service. The wrapper's disposer revokes the relevant admission generation before requesting backend teardown.

A stopped/recreated sandbox and a hot-reloaded Cordis fiber are different state changes. The former can change workload identity, credential generation and the effective filesystem boundary; the latter may leave existing sockets and resource handles alive until cleanup. The adapter must translate both into the protected activation/epoch contract rather than assume that `dispose()` completed every remote revocation.

Ordinary plugins may share a confined workload only where they share its trust and data envelope. A local mnemonic worker, raw private-memory service, publisher and web parser should not acquire mutual access merely because the harness can compose them. Separate trust classes need separate execution domains or a qualified equivalent.

---

## 6. Canonical effect contract

### 6.1 Reuse before generalization

The carried `effect-definition.mjs` already provides a closed registry. Its `workspace.patch` definition names `workspace`, `path`, `beforeSha256`, and `content`; creation is represented by a null preimage. It excludes commands, deletion, parent creation, and symlinks. Its semantics also disclose the same-UID concurrent-mutation limit. [G13]

The proposed Effect IR is therefore an **integration and versioning contract around that existing operation**, not a replacement DSL built before the existing one is used.

### 6.2 Proposed envelope

The following is a **new illustrative envelope**, not the current wire schema. Existing signed formats MUST NOT be reinterpreted as this format without an explicit adapter/version.

```json
{
  "schema": "aukora-effect-proposal-v1",
  "proposalId": "opaque-proposal-id",
  "activationDigest": "sha256:<activation>",
  "definitionId": "sha256:<registered-definition>",
  "effect": "workspace.patch",
  "args": {
    "workspace": "workspace-capability-reference",
    "path": "notes/example.txt",
    "beforeSha256": "<expected-current-content-hash>",
    "content": "Replacement text.\n"
  }
}
```

The broker resolves `workspace` from protected configuration or a valid capability. It is not an arbitrary absolute path selected by the model. `proposalId` is a correlation identifier, not authorization. Human-readable rationale is separate untrusted data and cannot override structured fields.

### 6.3 Canonicalization contract

The first profile MUST select exactly one wire encoding and canonicalizer. JSON Canonicalization Scheme is an existing candidate, but current AUKORA canonicalizers must be compared rather than silently declared JCS-compatible. JCS itself does not define application semantics or normalize Unicode into equivalence. [R01]

The versioned profile must fix UTF-8 handling, duplicate-key rejection, number representation, permitted field names, string/path rules, maximum sizes, and error behavior. Monetary quantities should use bounded integer units or a specified decimal representation, not implementation-dependent floating point.

**No cross-parser disagreement is acceptable on authorization-bearing data.** Decode once into a closed type and preserve the canonical preimage. Unknown security-relevant fields, ambiguous encodings, or unsupported versions must refuse, not be ignored.

### 6.4 Interpretation is part of what is approved

A digest over payload bytes is insufficient if a future executor interprets those bytes differently. The authorization MUST bind:

- effect definition and semantic version;
- target resource and selected broker/audience;
- canonical argument or proposal digest;
- relevant activation/policy/control epoch;
- validity window and use/budget constraints.

The carried registry already binds definition records; `compute.job` additionally demonstrates an executor-source pin while remaining staged. These are useful precedents, not blanket proof of closure. [G13]

### 6.5 Bounded input surface

Initial laboratory limits should be explicit, conservative, and versioned. A reasonable **proposed starting profile**, subject to measurement, is one operation per proposal, at most 16 KiB of envelope metadata, at most 64 KiB of inline text content, and a maximum nesting depth of eight. These are engineering starting values, not measured security thresholds.

The parser must reject oversize frames before expensive work. Large artifacts use a bounded immutable artifact reference, not an unbounded inline body. External locators must not cause the privileged issuer to fetch arbitrary URLs.

### 6.6 What must not cross as authority

Arbitrary shell strings, generated programs, deserialized executable objects, new effect definitions, and model-selected verification keys are not privileged instructions. Candidate code may be built or tested in a confined workspace. Promoting that code into a privileged executor is a separate operation under the amendment policy.

### 6.7 Backend-independent operation meaning

OpenShell policy is a **reachability ceiling**, not the AUKORA Effect IR. An adapter may encode the transport of a proposal or constrain an API route, but may not broaden `workspace.patch` into an arbitrary shell command to fit a backend.

Any new remote mutation class must bind the real resource/account and action semantics independently of endpoint access. Middleware ordering and credential substitution are covered in §20.11–§20.12. A backend that cannot preserve an effect's required preconditions is unsupported for that effect, rather than partially conforming under the same label.

---

## 7. Trusted approval: proposal, display, signature, execution

### 7.1 The precise meaning of “what you see = what you sign = what executes”

The slogan is an engineering correspondence requirement, not literal equality between pixels, a signature, and the physical world.

```text
immutable canonical proposal P
           |
           +--> deterministic trusted rendering R(P)
           +--> domain-separated approval digest H(P, interpretation)
           +--> deterministic admission under that interpretation
           +--> broker execution of the same operation and preconditions
```

A trusted renderer must expose the effect, destination, scope, preconditions, cost/resource bounds, duration, and irreversible consequences that the person is deciding about. An AI summary may accompany this view but cannot replace or contradict it.

A code diff does not establish that a person understands program semantics. A displayed digest is an integrity reference, not a human-readable explanation. A screenshot does not prove that the person saw, understood, or intended the operation.

### 7.2 Immutable acquisition

**APP-01:** The privileged issuer MUST derive the approval object from a frozen artifact it acquires independently of the untrusted app’s descriptive claims. The request may carry a locator, but the locator must resolve inside a pre-authorized store, repository, or resource namespace.

**APP-02:** Reading a file by name and later reading it again is insufficient if another principal can replace it. The implementation must hold or copy exact bytes into protected immutable staging, verify the digest, and bind the resource precondition before review.

**APP-03:** The issuer MUST NOT accept “already approved,” a caller’s chosen public key, a caller-reported display hash, or a caller’s `safe: true` as evidence of authorization.

**APP-04:** The broker MUST use the approved immutable bytes, not rebuild them from a mutable branch name, working tree, remote URL, or fresh model output after approval.

For code promotion, an immutable Git object plus the relevant tree, parent/base, repository, branch, and deployment/definition bindings is preferable to a mutable working directory. The producer cannot substitute an unrelated repository containing the same convenient path name.

### 7.3 Approval object

A proposed approval record binds at least:

```text
approval schema and domain
proposal digest and effect-definition identity
principal/control-state identity
holder / intended caller where applicable
broker and resource audience
activation/policy epoch
issued-at, expiry, nonce/use identifier
scope and resource budget
trusted rendering contract/version
```

The current adapter already checks several of these concepts: pinned approver, operation digest, subject, control digest, challenge, and time window. It also explicitly rejects claiming a human-ceremony class that it cannot establish. Preserve those refusals during migration. [G06]

The exact field set should be minimized per profile. Optional extensibility must not permit a verifier to disregard a constraint another verifier considers binding.

### 7.4 Key custody, caller admission, and human interaction are different

Three independently measured facts are required:

1. The ordinary app cannot extract the signing key.
2. The ordinary app cannot turn the signing service into an unrestricted signing oracle.
3. The approval interaction is bound to the exact operation through a protected human path.

A separate account can help with the first while leaving the second or third open. `EACCES` when the agent tries to read an owner-held key is evidence of a denied read, **not** evidence that custody separation failed. It still does not prove every signing request is authorized. The README explicitly separates these issues. [G01]

A biometric or hardware presence event can support a particular authentication claim under its device policy. It does not prove free consent, understanding, unique humanity, or that an arbitrary display outside that device was faithful. Authentication risk signals do not substitute for an authentication factor. [R05]

### 7.5 Code approval versus signed Git commit

An Aumlok approval artifact and an SSH/GPG-signed Git commit are different records with different verification rules. Trailer text such as `Approved-by` is not itself either signature.

A deployment must verify that an allowed commit/tree corresponds to the separately approved operation. A GitHub “verified” badge for some signer is not sufficient unless that signer and the approval relationship are authorized for that repository and operation. The currently read ruleset does not establish this stronger condition. [G18]

### 7.6 Approval lifecycle

Pending cards have immutable IDs, bounded lifetimes, explicit destinations, and cancellation state. A material change to any approved field requires a new proposal and decision. Refusal is durable for that proposal identity and does not disappear when a model restates the request.

Reconsideration is a distinct owner-initiated operation. A signature obtained by persuasion can still be cryptographically valid; the system must not describe persuasion resistance as proven by signature verification.

### 7.7 What OpenShell does not close in R1, R2 and R3

OpenShell can reduce the worker's opportunities to extract an issuer key or reach privileged services. It does not itself create a protected approval display, prove human presence, or require an Aumlok signature on every signer request.

R1 remains a custody and caller-admission measurement. R2 remains independent acquisition of immutable operation bytes. R3 remains a correspondence between trusted rendering, signed semantics and actual execution. These are complementary to runtime isolation, not obsolete after installing it.

The native desktop renderer and its IPC/preload surfaces must not let untrusted content request privileged approval or change the trusted preview. Synchronous gateway/middleware timeouts are not human-interaction windows: use the prepared-proposal workflow in §20.13.

---

## 8. Capability delegation and deterministic admission

### 8.1 Human sovereignty is compatible with useful automation

The human should not be asked to approve each mouse click. A standing grant can authorize a bounded class of activity: selected workspaces, destinations, amounts, time windows, or uses. The executor then checks that grant deterministically at each protected use.

“Only a human may authorize” therefore means the authority lineage terminates in the person’s control policy. It does not require the person to sign every sub-operation or forbid a delegated service from issuing narrower child capabilities.

### 8.2 Capability contract

| Field or property | Requirement |
|---|---|
| Issuer | Identified by an independently trusted key or valid parent chain. |
| Subject/holder | Bound to the component, device, or proof-of-possession key allowed to exercise it. |
| Audience | Specific broker/service and resource domain, not every AUKORA installation. |
| Effect definitions | Exact approved operations and semantic versions. |
| Resource selector | Finite resources or a formally specified bounded selector. |
| Limits | Bytes, count, destinations, total spend, compute, or other effect-specific budget. |
| Lifetime | Explicit validity and revocation behavior, including offline limits. |
| Epoch | Control and activation context in which it is valid. |
| Delegability | Explicit permission, depth, and permitted attenuation. |
| Signature | Domain-separated signature over the exact contract. |

Random unguessable handles are useful, but a leaked bearer handle can convey its authority. Where copying is unacceptable, bind use to a holder and authenticated channel or proof of possession. Existing sender-constrained-token work illustrates that distinction; adopting its ideas does not automatically make AUKORA interoperable with that protocol. [R04]

### 8.3 Attenuation law

A child grant is acceptable only if every relevant constraint is no broader than its parent:

```text
resources(child) ⊆ resources(parent)
effects(child) ⊆ effects(parent)
validity(child) ⊆ validity(parent)
audience(child) is permitted by parent
budget(child) consumes an allocation from parent
revocation(parent) invalidates applicable descendants
```

“Both children are under the parent’s limit” is insufficient when their **combined use** can exceed that limit. Either the parent budget has one durable coordinator or child allocations must be disjoint and deducted when issued.

A vouch, reputation score, proof of key possession, or accurate prediction must not substitute for any field in this authorization chain.

### 8.4 Decision function

A conceptual deterministic decision is:

```text
admit =
  recognized_definition
  AND canonical_binding_valid
  AND issuer_and_holder_valid
  AND current_control_state
  AND audience_and_resource_match
  AND constraints_satisfied
  AND nonce_and_budget_available
  AND required_safety_checks_satisfied
```

The kernel must consume trusted state supplied by the protected runtime. The proposer cannot set the clock, current authority epoch, accepted issuer, or available budget. Offline verification may intentionally accept an explicit evaluation time, but an execution path must not let an untrusted caller choose a past time at which an expired grant would have worked.

The current `decide.mjs` is explicitly an adapter plus kernel arrangement. Its Ed25519 check happens outside the kernel’s hybrid-authorization slot. That adapter is therefore part of the trusted base, and the end-to-end guarantee must be stated for the composition, not attributed to the kernel alone. [G06]

### 8.5 Denial and governance

A policy-denied proposal does not become permitted because Laya requests escalation or the user clicks an ordinary approval card. Changing a constitutional prohibition is a distinct, higher-order policy amendment under the existing amendment rules.

Scope expansion is visible. Routine authorization, permission expansion, root recovery, and constitutional replacement must not share an ambiguous “Approve” operation.

### 8.6 Two levels of permission

The worker may have standing backend permission to reach the AUKORA proposal service, while possessing no permission to change the protected target. This is intentional: **permission to ask is not permission to execute**.

Effective admission is the intersection of the qualified deployment boundary, the resource controller's current policy, the valid delegated capability, and required effect-specific checks. AUKORA must not rely on temporarily opening a broad endpoint for one approved action and assume all other callers are thereby excluded.

Provider attachment, inference-route selection and policy-draft approval can change the effective envelope. They require control-plane authorization or a previously established narrow delegation; an upstream low-risk classification is not by itself that delegation. See §20.14–§20.16.

---

## 9. Broker transactions, replay, rollback, and revocation

### 9.1 State machine

```text
PROPOSED
   |
   v
FROZEN --> REJECTED / EXPIRED / CANCELLED
   |
   v
AUTHORIZED
   |
   v
RESERVED_DURABLY
   |
   +--> NOT_STARTED
   |
   v
STARTED
   |
   +--> EFFECT_OBSERVED
   +--> FAILED_WITH_KNOWN_OUTCOME
   +--> OUTCOME_UNKNOWN
```

An approval record, a durable reservation, a started operation, and a confirmed effect are not interchangeable states. Each transition records the relevant artifact identities and epoch.

### 9.2 One use and crash safety

The broker must atomically reserve a use and the applicable budget before admitting the effect. Concurrent requests cannot each read the same unspent state and both proceed.

A crash after reservation does not make the grant fresh again. A crash after an external request but before its response creates **uncertainty**, not permission for a blind retry. An external service’s idempotency contract or reconciliation observation is needed before retrying an effect that might already have happened.

At-most-once **admission** is not exactly-once execution of every real-world effect. For a local file, protected compare-and-swap and observation can establish a narrower property. For an external payment or message, the other service’s behavior is part of the claim.

### 9.3 Local publication contract

For the first `workspace.patch` path:

- Resolve the workspace from protected configuration.
- Validate the path and acquire the target without following unexpected links or leaving the designated resource boundary.
- Compare the exact current preimage or absence with the approved precondition.
- Reserve authority durably.
- Publish the staged bytes using the platform-specific protected write protocol.
- Observe the published object and record the outcome separately from permission.

A simple digest-before-write is not sufficient in a directory concurrently writable by the adversary. The deployment must either exclude that writer or provide a race-resistant resource acquisition/publication mechanism. The carried effect definition already discloses this limitation. [G13]

### 9.4 Restore protection

An append-only log can be internally consistent while being an old prefix. A retained counter can also be old if it was restored with the application.

The anti-rollback witness must be outside the relevant restore and write authority. “Another directory” is not a security boundary if the same attacker can change both. An outside witness must record the relevant consumed authority/epoch, not merely a reassuring log length.

The current high-water implementation is a useful building block, but its own comments state that same-UID rewriting defeats it. The first deployment must measure the actual ownership and recovery scope of both records. [G06]

### 9.5 Revocation linearization point

A revocation takes effect at a documented point: after the protected admission service commits a new epoch/revocation record, no **new** covered admission may use the old authority.

Already-admitted effects require explicit treatment: cancel if the executor can cancel before commit, drain if cancellation is unavailable, or report the action as in flight. The specification must not promise to retract a network disclosure already delivered.

The control service retains a route for pause/revocation independent of the conversational model. A crashed assistant must not prevent the person from stopping future admissions.

### 9.6 Cleanup authority

Cleanup is a narrowly defined lifecycle capability: close acquired handles, terminate owned scratch workers, release reservations whose outcome is known, or perform an explicitly authorized compensation. It is not unrestricted execution hidden under the label “rollback.”

A required assessor or witness failure must not prevent basic stop controls and essential resource cleanup. These remain separately authorized, minimal paths.

### 9.7 Backend state is not authority state

Sandbox restarts rotate upstream runtime identities and may restore or retain different backend state. They must never reset AUKORA's consumed grants, aggregate budgets or revocation history. A backend generation becomes one input to authorization, not the authority ledger's storage boundary.

For proxy-forwarded effects, define exactly which trusted process owns the durable reservation and observes forwarding. A middleware `allow` response, an OpenShell log event, and a successful upstream HTTP response are different observations. Unexpected failure between them requires reconciliation, not a fabricated completed-effect receipt or a fresh blind retry.

No atomic transaction across arbitrary external services is assumed. The first file effect remains small precisely so publication and observation can be qualified without claiming distributed exactly-once execution.

---

## 10. Laya as a bounded semantic reflex

### 10.1 Upstream basis and limits

Laya 0.3.21 documents typed decisions and opt-in low-confidence abstention: results can be flagged as low confidence and `decide` can return no answer. The README’s 33 ms claim is a particular upstream T4 measurement, not AUKORA performance. Typed output reduces free-form parsing; it does not eliminate classification errors. [L01]

No claim is made here that Laya is already integrated into Genesis or that its confidence values are calibrated for AUKORA’s security decisions.

### 10.2 Proposed contract

```text
Assessment {
  proposalDigest,
  assessorIdentity,
  weightsDigest,
  configurationDigest,
  inputProfile,
  result: NO_OBJECTION | REVIEW_REQUIRED | BLOCK | UNAVAILABLE,
  boundedReasonCodes,
  optionalCalibratedScores
}
```

`NO_OBJECTION` is deliberately not named `SAFE` or `ALLOW`.

| Assessment | Consequence |
|---|---|
| NO_OBJECTION | Continue only through normal deterministic authority checks. |
| REVIEW_REQUIRED | Hold for the defined review path; review does not override a hard policy denial. |
| BLOCK | Refuse the current proposal under the selected policy. |
| UNAVAILABLE / malformed / timeout | Block or hold the affected class according to an explicit fail-closed profile. |

Bind assessment to the exact proposal and assessor version. A result for one draft cannot be reused after the target, payload, permission scope, or effect interpretation changes.

### 10.3 Two different safety claims

**Authority non-expansion:** even an always-benign or compromised assessor cannot create a grant or cause an effect outside the human-delegated envelope.

**Semantic risk reduction:** the assessor catches some hazardous actions inside that envelope.

The first can be enforced by separating the assessor from the issuer and broker. The second remains probabilistic. A compromised assessor can miss a warning and thereby allow more **already-authorized** actions through than an honest assessor would. It would be misleading to claim its compromise cannot affect safety at all.

Removal or failure of a **required** assessor must not quietly switch to a profile that omits it. A deliberate owner-approved degraded profile is a separate activation with a visible change of guarantees.

### 10.4 Placement and training

Run the assessor in its own constrained worker with no signing, mounting, shell, or general network authority. It sees the minimum approved proposal context necessary for its job. Secrets do not enter the model simply because it is local.

Initial use should be shadow evaluation over **synthetic or explicitly consented, non-secret fixtures**. No raw private approval stream is automatically turned into a training set. Fine-tuning, dataset selection, weights, tokenizer, thresholds, and configuration changes are versioned and governed.

Calibration must be evaluated on held-out tasks, including shifts in language, document length, operation class, and benign-but-unusual requests. Measure false negatives, false positives, abstention, unavailable rate, and latency under a declared dataset and machine.

Confidence is not a universal probability of safety. Thresholds require an error-cost policy and cannot be selected solely to reduce prompt count.

### 10.5 Foundation test

With an unchanged grant set and broker, substitute assessor fixtures that return no objection, block, review, malformed data, and unavailable. None may create authority. Required-assessor absence closes the admission path; stop and cleanup remain available.

This is a controlled conformance test, not an autonomous attack program against real credentials or third-party systems.

### 10.6 Laya placement with OpenShell

A Laya service can be placed behind a constrained worker interface and consulted by the protected admission service or by a qualified supervisor-middleware adapter. Its deployment MUST remain distinct from its authority: registration on the trusted side does not give the model permission to mint grants or modify backend policy.

The early profile uses bounded synthetic proposals and shadow assessment. It does not rely on the upstream middleware timeout as a target for arbitrary long-document classification, nor infer AUKORA latency from an upstream benchmark. Timeout/over-capacity is `UNAVAILABLE`, with the previously declared failure consequence.

Assessment sees only what the selected interface exposes. A classifier cannot check hidden credential headers, unobserved local effects or uninspectable encrypted messages. It must report its input scope, not infer missing context and call the result complete.

---

## 11. Privacy and the two-way membrane

### 11.1 There are two crossings

A model’s output is only half the membrane. Its input can contain the person’s private files, messages, relationships, or history. Sending that context to a provider is already an external effect.

```text
private resources --> disclosure policy --> remote model
remote model output --> proposal admission --> protected effects
```

Filtering a response cannot undo disclosure in the request. The current README explicitly reports remote-provider egress and unreviewed transcript retention for the voice path; the new design must not assume locality that is not present. [G01]

### 11.2 Separate permissions

Sensing, reading, interpreting, retaining, indexing, disclosing, training on, and acting on information are different permissions. Permission to summarize a local document does not automatically authorize sending it to another provider, storing it indefinitely, or using it for model training.

The model adapter must receive either already-approved context or references resolved by a protected disclosure service. The service tracks purpose, recipient, expiry, and the permitted data class without exposing the entire private graph.

### 11.3 Minimal evidence

Receipts should record opaque resource references and scoped digests where possible. A hash of a low-entropy secret is still a possible guessing check; “we stored only the hash” is not an automatic privacy guarantee.

Do not log the Aumlok phrase, mnemonic story, private signing material, unrestricted message content, or hidden model reasoning into Aura. Evidence records should capture observable inputs/outputs and attribution needed for verification, not everything the system can capture.

### 11.4 Forgotten data

A forget operation can remove an index entry or local content and retain a content-minimized tombstone. It does not prove deletion from recipients, backups, model weights, or other copies. The newest reviewed commit explicitly avoids erasure claims; this specification preserves that restraint. [G00]

### 11.5 A credential-safe inference route is still a disclosure route

OpenShell can keep a model-provider key outside the worker while still legitimately sending the worker's request content to that provider. The policy must therefore answer two separate questions: whether that provider credential may be used, and whether **this data** may leave for that purpose.

AUKORA should use selected context views rather than give every network-capable worker raw access to the person's entire memory. The strongest practical early separation is an offline private-data/ceremony domain and a network-enabled worker receiving only explicitly released material. This is a proposed information-flow design, not a claim of perfect semantic DLP.

OpenShell documents operational telemetry and an opt-out: `OPENSHELL_TELEMETRY_ENABLED=false` on the gateway, or `server.telemetryEnabled=false` for Helm. Its stated collection excludes prompts, credentials and user content; third-party agents/providers have separate practices. The AUKORA private profile should disable optional telemetry by default and verify its own application, model and crash-report flows independently. [N11]

The trusted supervisor may see plaintext when it terminates TLS for inspection. A privately controlled gateway and an enterprise-operated gateway therefore imply different confidentiality assumptions. A network proxy must not be described as an end-to-end privacy guarantee against its own operator.

---

## 12. Aumlok: seven-word acrostic and entropy

### 12.1 Fixed human-interface requirement

**The anchor and acrostic stay. Seven words total.**

Word 0 is a randomly selected six-letter anchor. The initials of words 1–6, in order, spell that anchor. The proposed change removes only the semantic Nature/Nature/People/People/Spirit/Spirit buckets.

```text
Word 0: PLANET
Word 1: P...
Word 2: L...
Word 3: A...
Word 4: N...
Word 5: E...
Word 6: T...
```

Each of the six words is selected from the full audited lexicon for its required initial. The story is generated **after** this random selection. The above shape is pedagogical, not a usable secret.

The currently inspected source still has the theme mapping. Therefore the theme-free acrostic is a proposed generator, not a claim about current issuance. [G17]

### 12.2 Correct model: uniform anchors, draws with replacement

Let `A` be the usable anchor set, `a_i` its six letters, and `n_l` the number of distinct eligible words beginning with letter `l`. If anchors are uniform and each position is selected uniformly and independently within its required bucket:

```text
P(phrase with anchor a) = 1 / (|A| × product_i n_(a_i))

H_min = log2(|A|) + min_a sum_i log2(n_(a_i))
H_Shannon = log2(|A|) + average_a sum_i log2(n_(a_i))
```

These are different summaries. The weakest phrase probability determines min-entropy. A median or best anchor does not establish the security floor.

If the anchor is public, selected by the person, leaked through branding, or predictable, its nominal `log2(|A|)` contribution must not be counted as a secret contribution. Report conditional strength for the known anchor as well.

### 12.3 No-repeat rule

With repeated initials and no repeated secret word, independent draws are no longer the exact distribution. For an anchor `a`, let `m_l(a)` be how often initial `l` occurs, and let `n_l(a)` be the usable bucket after excluding the anchor itself if required.

```text
C(a) = product_l falling_factorial(n_l(a), m_l(a))

falling_factorial(n,m) = n × (n-1) × ... × (n-m+1)

H_min = log2(|A|) + min_a log2(C(a))
```

This formula assumes uniform selection without replacement within each bucket and a uniform anchor distribution. Empty/undersized buckets make the anchor inadmissible. Word normalization and deduplication happen before counting.

### 12.4 What can actually be concluded now

The old generator’s approximately 34.14-bit figure is **reported by the source**, not independently reproduced for the live drawer in this review. Source comments themselves retain older descriptions alongside later corrections; the actual generation path and data must be measured together. [G17]

The earlier conversation’s approximate **69-bit** estimate concerned a different design that removed the acrostic. It must **not** be carried into this specification as the expected entropy of the retained-acrostic design.

No exact new entropy is asserted without enumerating the actual merged, deduplicated, filtered buckets and actual usable anchors.

### 12.5 Illustrative arithmetic, not a wordlist measurement

The following calculation assumes 150 equally likely secret anchors, six independent draws with replacement, and the same bucket size for every required initial:

| Eligible words per required initial | Total min-entropy under those assumptions |
|---:|---:|
| 100 | 47.09 bits |
| 300 | 56.60 bits |
| 1,000 | 67.02 bits |
| 10,000 | 86.96 bits |

These values were calculated for this document. They show why removing semantic categories can help, but do not predict the actual lexicon’s result. With those same assumptions, reaching 128 bits would require about **1.15 million eligible words per required initial**, which is not a plausible ordinary common-word vocabulary design.

### 12.6 Scramblers, order, and language

A deterministic permutation, base conversion, hash, encoder, or AI-generated story cannot create entropy absent from its inputs. A reversible re-encoding preserves uncertainty; it does not increase it. A secret independent scrambler is an additional secret whose storage and recovery must be protected.

The phrase is already an ordered tuple. Adding `log2(7!)` to the tuple’s entropy would count the order twice. Even a genuinely independent hidden permutation has a finite contribution: at most about 12.30 bits for seven distinct objects, and less when anchor placement/initial rules constrain it. It is not a replacement for a strong root design.

A public salt prevents identical-password precomputation across users; it is not a secret factor. A memory-hard KDF increases guessing cost; it does not turn a 50-bit secret into 128 bits of independent secret uncertainty. Argon2id is an established candidate for a versioned future password-wrapping profile, with parameters measured on supported devices rather than copied blindly. [R02]

### 12.7 Required generator measurement artifact

The generator audit must publish non-secret, reproducible metadata:

```text
language pack/version and file digests
normalization and initial-extraction rules
usable anchor list and selection distribution
unique bucket sizes after all filters
with/without replacement and anchor-exclusion rules
min-entropy; Shannon entropy; conditional per-anchor bits
minimum/median/maximum completion counts
rejection and redraw rules
attacker knowledge assumptions
actual production drawer identity
```

The production generator uses a cryptographically secure random source with unbiased bounded selection. A language model does not select the secret words. Regenerating a story may not redraw the phrase. Allowing users to choose the most attractive of many phrases changes the distribution and must be measured or explicitly excluded from the claimed floor.

---

## 13. Local mnemonic story and multilingual ceremony

### 13.1 Story workflow

The phrase-generation service selects the seven words; an isolated local mnemonic worker receives only those words and a permitted language/story style. It produces a short story containing each exact word in the intended order. A deterministic checker confirms the required sequence and rejects substitutions, missing words, or ambiguous additional occurrences that defeat the exercise.

The human then practices exact recall on a dedicated local surface. The system may regenerate the story around the **same words**. Neither the quality nor the silliness of the story is a cryptographic property.

A small template fallback remains available when a local model is absent. Laya’s classifier role is separate from story generation; a typed classifier is not automatically a generative mnemonic model.

### 13.2 Secret handling

The mnemonic worker has no network, chat history, general tools, telemetry, or training-update path. Its model weights and executable dependencies are pinned. Its temporary state is minimized and disposed after the ceremony.

The application should avoid clipboard use, app-created screenshots, background transcript capture, crash-report inclusion, and cloud-synced caches. A stronger profile must account for swap, hibernation, GPU memory, accessibility services, input methods, and diagnostic capture. “Local only” is not proof that no recoverable copy remains.

The phrase is meant to be memorized. This specification does not make a written phrase the default recovery mechanism. It does, however, require an explicit response to forgetting and device loss rather than hiding those failure modes.

### 13.3 Memorability evaluation

Compare exact recall and accidental-disclosure behavior for an acrostic alone and an acrostic plus local story. Use consented non-production phrases; do not recruit users by asking them to reveal real secrets. Measure near-term and delayed recall, synonym/order errors, abandonment, and whether users create insecure backups despite the design.

Tests scheduled for later dates are an evaluation plan, not a claim that longitudinal measurements have already happened. No percentage improvement is claimed here.

### 13.4 Language packs

Language selection is a usability and accessibility feature. It is not counted as secret entropy unless a specific, justified random-selection model establishes otherwise.

Each pack must define a six-initial anchor convention, canonical spelling, Unicode normalization, case behavior, diacritics, token boundaries, and allowed input methods. Alphabetic languages and non-alphabetic scripts need explicit, separately evaluated mnemonic conventions; silent transliteration is not acceptable.

Security-sensitive normalization must not merge visually similar but different secret words unpredictably. Accepting many spellings or synonyms changes the guessing space. Language packs are versioned so future spelling or vocabulary updates do not make old phrases impossible to enter.

A sensible first implementation has one rigorously measured pack, followed by additional packs tested with native-language users. Internationalization begins in the schema now; broad vocabulary coverage need not block the first protected effect path.

### 13.5 Offline ceremony is a separate workload profile

A sandbox backend can supply a useful execution compartment for the mnemonic generator, but the ceremony must not reuse the ordinary agent's network/provider configuration. Preload the selected local model without a real phrase present; during ceremony, provide no network, tool registry, log export or persistent conversation store.

A stronger device profile also qualifies memory, display, input and crash-dump handling. OpenShell's credential masking does not protect a phrase intentionally supplied as model input; the ceremony's independent data-flow restrictions do. No GPU or backend capability is assumed safe for root material simply because it supports ordinary agent workloads.

---

## 14. Root custody, recovery, rotation, and multiple devices

### 14.1 The important correction

**A random 256-bit root encrypted solely under a guessable phrase is still vulnerable to offline phrase guessing if the encrypted root and verification material are stolen.** The root may be random, but its protection is bounded by the wrapping secret and KDF cost.

Decoupling the root from the phrase is still valuable for key rotation and identity continuity. It does not by itself add a second protective secret.

### 14.2 Architecture comparison

| Model | Benefit | Hard limitation |
|---|---|---|
| Phrase-derived root | Reconstructable from memorized words without retained secret hardware. | Offline search is bounded by phrase distribution and KDF cost; published keys can test guesses. |
| Random root wrapped only by phrase | Phrase can change without changing every identity key. | A stolen envelope can still permit offline phrase guessing. |
| Random root with phrase plus non-exportable device factor | Theft of an envelope alone need not enable the same offline attack. | Device compromise, factor implementation, and loss recovery become critical. |
| Multiple enrolled devices with separate keys | One device loss need not erase continuity; least privilege is possible per device. | A weak enrollment or synchronization path can become a takeover path. |
| Threshold recovery under an explicit policy | No single recovery custodian must hold unilateral recovery power. | Threshold collusion, availability, privacy, and succession must be specified. |
| Remote password-authenticated service | Can change exposure and online/offline attack properties under a specific protocol. | Adds a service/trust/availability dependency; does not make weak passwords strong or ensure stateless recovery. |

OPAQUE is relevant research for the last class, not a magic extra-entropy component. Its security depends on the protocol’s assumptions and compromise model; it must not be represented as eliminating all offline guessing after full compromise. [R03]

### 14.3 Recommended direction, not a completed cryptosystem

The preferred direction for a high-assurance profile is **independent random control material, separate per-device keys, a protected authentication factor, and explicitly designed recovery**, while retaining the seven-word acrostic as the human memorization interface.

The exact hardware wrapping and recovery construction must be selected from reviewed implementations after platform evaluation. This document intentionally does not invent a new encryption protocol or dictate a novel composition of secrets.

A person choosing phrase-only recovery must be shown that profile’s measured guessing strength and limitations. It must not inherit the stronger profile’s security label.

### 14.4 Recovery conservation constraint

If every device and every independently retained secret is lost, and the only secret left is the seven-word phrase, recovery cannot simultaneously depend on an independent device secret that no longer exists. Some other retained state, party, or higher-entropy secret is necessary.

This is not a reason to abandon memorability. It is the trade-off the user experience must make explicit: **memory-only portability, offline guessing resistance, and recovery without any surviving external state cannot all be assumed for free.**

### 14.5 Key hierarchy

Separate control/constitutional keys, device authorization keys, communication keys, receipt keys, recovery policy, and ephemeral session/capability keys. No Nostr communication key should automatically be the authority to amend the local constitution.

Derivation, where appropriate, uses reviewed KDFs with explicit domain separation. HKDF derives context-specific key material; it is not a password-strength amplifier. [R06]

Changing the memorized phrase should normally rewrap or rebind the unlock path, not silently change the person’s identity, decrypt old messages incorrectly, or invalidate historical receipts.

### 14.6 Rotation and succession

A normal rotation binds predecessor, successor, purpose, effective epoch, and revocation semantics under the current control policy. A recovery rotation uses a distinct, predeclared recovery policy. Conflicting successors are reported as conflicts rather than resolved by whichever one arrived first.

Historical signatures may remain mathematically valid after revocation. Verifiers must distinguish historical validity, current authorization, and uncertain freshness.

Death and incapacity require optional, explicit succession policies. Technical access succession is not a proof of legal inheritance or universal authority over another person’s data. The user must be able to leave such policies unconfigured with the resulting recovery limit visible.

### 14.7 Multi-device budgets

A laptop, phone, wearable, and home node do not receive the same unrestricted master key. Each gets scoped authority and a revocation path.

A globally shared spend/use budget needs coordination or disjoint allocations. During network partitions, devices cannot independently spend the same finite budget while claiming globally enforced limits. Offline grants must have bounded scope and a declared maximum revocation delay.

### 14.8 Root independence from the runtime supplier

An OpenShell provider key, gateway JWT, workload identity or future hardware attestation key is not the AUKORA identity root. The person's control lineage must remain valid when those infrastructure credentials rotate or the backend is replaced.

The issuer, recovery quorum and retained checkpoints must have explicit failure-domain ownership. Moving two services into two containers under one writable host account does not make them independent against that account. The strongest justified claim is the one supported by the actual custody boundary, not the number of containers.

No OpenShell feature changes the entropy of the retained-acrostic phrase. All §12–§14 distinctions remain in force, including the weak-wrapping correction and the trade-off for memory-only recovery after total device loss.

---

## 15. Per-node diversity without secret mathematics

### 15.1 The useful version of the “alien world”

Nodes may have different internal service graphs, randomly generated capability references, ephemeral channels, local data layouts, and replaceable implementations. An external peer should not need to understand that internal world to verify a boundary-crossing contract.

The governing rule is:

> **Common boundary semantics; independently controlled internal worlds.**

An attacker can know the full protocol and still lack the keys and capabilities. Security must survive disclosure of the encoding algorithm.

### 15.2 Diversity mechanisms and their real contribution

| Mechanism | Potential value | Limit |
|---|---|---|
| Independent per-node keys | One stolen key is not every node’s key. | A shared software defect can still affect many nodes. |
| Scoped unguessable handles | Prevent accidental or unauthorized naming when secrecy/holder binding is enforced. | Leaked handles may carry authority; renaming does not fix a policy bug. |
| Separate Cordis resolution realms | Keep intentionally distinct service instances separate within the composition model. | A realm symbol is not OS isolation. |
| Session-bound channel keys and epochs | Limit reuse across sessions and reject stale traffic. | Does not authenticate human intent or fix an unsafe endpoint. |
| Minimal, independent verifier implementations | Reduce some common implementation failures and expose disagreement. | Shared specifications and assumptions can still be wrong. |
| Platform-supported process randomization and isolation | Complicate some implementation-level attacks. | No universal guarantee against shared vulnerabilities. |
| AI-generated custom parsers or protocol variants | Research possibility for controlled adapters. | Enlarges the code and compatibility surface; no foundation benefit is assumed. |
| Base-27, ternary, or geometric representations | Useful for selected UI, coordinates, or pedagogy. | Representation alone supplies no cryptographic authority or entropy. |

The old documents explicitly restrict the base-27/tesseract material to representation and distinguish it from cryptography and authority. That restriction remains. [D01] (§§4g–4g.1); [D02] (opening status table)

### 15.3 What changes when the phrase changes

Phrase rotation MAY coincide with session-key, capability-handle, or local namespace rotation when policy specifies it. These changes must be derived from suitable protected random material and separated by purpose. A public phrase-derived fingerprint must not become a convenient offline guessing oracle.

The semantics of historical evidence, the identity lineage, and the meaning of already-issued grants must not silently mutate because the node now uses different internal encodings.

### 15.4 Research gate for diversity

Diversification is accepted only after a comparison shows a concrete gain without unacceptable increases in parser defects, update failures, recovery cost, or verifier disagreement. The experiment uses owned disposable instances and predefined fixture perturbations, not live third-party exploitation.

First priority is independent keys and narrow capabilities. Bespoke numerical systems, per-user cryptographic algorithms, and opaque AI-generated authorization languages are rejected as foundation requirements.

---

## 16. Aura, Kira, evidence lineage, and vouches

### 16.1 Two boundaries, still separate

The action boundary asks **whether an effect is authorized**. The evidence boundary asks **what is supported about a record and its ancestry**. A single signed graph cannot safely answer both by treating reputation or recorded agreement as permission.

Genesis’s `consolidate.mjs` is real component code, not merely a concept. It groups normalized claims by recorded ancestry overlap, keeps unknown ancestry from contributing a counted observation, preserves counterevidence, and refuses authority-shaped fields in the consolidated result. [G11]

That does not establish a deployed global provenance network. It also does not prove supplied ancestors are honest, complete, or statistically independent.

### 16.2 Proposed evidence object classes

| Object | Meaning | Must not imply |
|---|---|---|
| Observation record | A named observer asserts an observation with a scope and method. | The observation is true because the record is signed. |
| Derivation record | An output is asserted to derive from specified inputs through a specified transformation. | No unrecorded input existed. |
| Review/endorsement | A key signs a stated assessment. | A new independent observation or authorization. |
| Vouch/introduction | A key asserts a particular relationship to another key or subject. | Unique humanity, general honesty, or transitive permissions. |
| Execution receipt | An executor records a scoped result or uncertainty. | The result is globally latest or the intended effect certainly occurred. |
| Grant | Separate authorization object verified under the control policy. | Truth of the content being acted on. |

A useful evidence schema can align with the W3C PROV distinction between entities, activities, agents, and derivation. Such alignment is an interoperability direction, not a claim that the current Kira schema is PROV-conformant. [R07]

### 16.3 Independence requires a model

Grouping shared ancestors is a conservative way to avoid obvious double counting. Non-overlapping declared ancestors do not prove independence. Two sources may share an undisclosed origin, a sensor, a copied dataset, or the same experiment.

Likewise, two reviewers using the same model are not automatically one observation in every context: they may have performed separate instrumented measurements. The record must distinguish **independent measurements**, **correlated interpretation**, and **repetition of supplied evidence**.

Store the stated lineage, method, observer/instrument, model or component identity where available, transformations, and known dependencies. Represent missing or uncertain ancestry explicitly. Do not infer independence from a new hash, account, signature, or model-brand label.

### 16.4 Aura retention

An Aura chain or retained checkpoint can support a comparison between presented records. It does not automatically establish truth, completeness, absence of forks, or global latestness.

A local chain and local checkpoint writable by one principal are not independent witnesses. Where cross-party retention is introduced, the protocol must define membership, signed checkpoint formats, fork evidence, freshness, availability, and what the reader does during a partition.

Audit history and private content should be separable. A content-minimized tombstone can preserve that an authorized deletion happened without preserving the deleted words. It cannot prove all outside copies were erased.

### 16.5 Vouches and human-to-human continuity

Useful scoped vouches include “I associate this key with the person I know under this local name,” “I verified this key exchange through the stated channel,” or “I introduce this subject for this stated purpose.” Each carries issuer, subject, claim type, time/scope, and revocation/supersession semantics.

A vouch graph must not become a mandatory public social graph, a universal score of human worth, or the authority issuer. People without well-connected sponsors must retain a usable local system. This follows the Unownable Core’s separation of identity, evidence, and authority. [D02]

The current Nostr contact documentation already distinguishes a peer-pinned binding from checking a document against a key it supplies itself. It also discloses that its short comparison string is a weak check rather than a complete key-exchange guarantee. Preserve those distinctions; do not promote a friendly contact badge into proof of humanity. [G16]

### 16.6 Training and retrieval horizon

A possible future chain is:

```text
source artifact
  -> scoped acquisition/disclosure authorization
  -> extraction or transformation
  -> label/review assertion
  -> dataset manifest
  -> recorded training or retrieval activity
  -> evaluation evidence
  -> separately authorized model promotion
```

This could let a retrieval system group copies by evidence lineage and show users what repeated statements actually derive from. It may support dataset attribution and provenance-aware evaluation. It does not prove label truth, legal rights, consent beyond its exact scope, exhaustive inputs, or actual training execution merely because the records are signed. Rev 2.4 explicitly leaves this end-to-end system as a horizon. [G02]

C2PA is an adjacent example of signed content provenance, not a proof of underlying factual truth. Interoperability should preserve its claim limits rather than import a generic “verified information” label. [R08]

### 16.7 Anti-bot scope

The useful claim is **synthetic speech does not become local authorization merely through repetition**. It is not “bots can never act,” “manufactured consent is impossible,” or “a million bot accounts have no possible effect.” Bots can obtain legitimate delegated permissions, deceive people, consume resources, or attack implementation defects.

Rate limits, resource budgets, authenticated relationships, and explicit admission policy remain necessary. Provenance adds inspectability; it does not replace abuse prevention.

### 16.8 Infrastructure logs are another provenance source

Backend audit events can enrich Aura's record of what a runtime reported: policy revision, admitted/denied request, sandbox generation, middleware result or missing observation. These are not automatically independent observations of the final resource.

The provenance record must distinguish a request captured by the supervisor, an admission signed by AUKORA, an effect observed by the executor, and a later checkpoint retained by another party. Multiple copies of the same OpenShell event still have one originating observation. A classifier's interpretation of that event does not add an independent witness.

This can improve debugging, incident reconstruction and future provenance-aware retrieval without requiring a centralized truth score or disclosure of all private inputs. Every stronger statement remains tied to its source and observation scope.

---

## 17. Sovereign node-to-node communication

### 17.1 Personal control without a mandatory central operator

The intended architecture is a federation of independently controlled nodes. Models, hosting providers, relays, discovery services, and AUKORA itself should be replaceable. “Unowned” here means no required universal administrator or exclusive implementation, not that hardware, networks, service operators, or accountability disappear. [D02] (§§0–1, 7)

The first milestone is bilateral interoperability between two nodes with independently provisioned trust anchors, not a global consensus system.

### 17.2 Transport is replaceable

Nostr is an existing transport and contact-binding component. The proposed authority protocol must not depend on a relay declaring a request legitimate.

The current Nostr documentation distinguishes a digest of locally retained wire bytes from the canonical Nostr event ID. Two peers can retain different serializations of the same event. The new cross-node evidence contract must preserve this distinction rather than demand equality of arbitrary transport serializations. [G16]

### 17.3 Three peer message classes

**Communication:** a signed or encrypted message. It grants no action permission by default.

**Proposal:** a request for a particular operation under a recognized contract. It remains inert until the receiving node applies its own policy.

**Delegated operation:** a request carrying a valid authority chain for a resource whose controller recognizes that chain. It requires holder/audience binding, current constraints, budget and revocation checks at the receiving broker.

Alice’s node cannot grant access to Bob’s resource unless Bob or its legitimate controller has delegated that authority. Human sovereignty is not unilateral control over other people’s systems.

### 17.4 Boundary envelope

A minimal versioned peer envelope identifies message class, protocol version, sender/holder, recipient or audience, payload/contract digest, and replay/lifetime information. Authorization and provenance are separate attachments with separate verification rules.

Sensitive social relationships, private policy, and full local topology are not sent simply because a peer requests verification. A node discloses only the evidence needed for the specific claim.

Protocol negotiation must not permit an untrusted peer to select a weaker authorization interpretation. Unsupported versions fail explicitly. No “best effort” downgrade is allowed on authority-bearing messages.

### 17.5 Partition and freshness policy

Peer operations that require up-to-date revocation information must either obtain it, use a bounded offline grant whose staleness is accepted explicitly, or refuse/hold. A timestamp is not proof that a revocation service was consulted.

Do not introduce distributed consensus for every message. Use it or another coordination mechanism only where the resource contract genuinely requires non-conflicting shared state. Independent local authority does not eliminate double spending, conflicting successors, or shared-resource races.

### 17.6 Exit and interoperability

A replacement implementation must be able to read exported identity/control history, signed evidence, scoped relationship claims, authorized memory data, and applicable policy metadata. Private non-exportable keys may require authorized enrollment of replacement keys rather than raw key export.

Migration does not automatically transfer service credentials or override a third party’s access policy. The exit test is that the person can recover meaningful continuity and verify retained artifacts without the old model or a mandatory AUKORA server.

### 17.7 Portable boundary-profile claims

Peers may exchange a versioned description of the runtime profile used for a particular operation: supported effect definitions, sandbox backend/version, observed activation, authority epoch, evidence scope and optional attestation result. This is a proposed interoperability object, not an already shipped OpenShell/AUKORA passport.

A declared profile, an observed configuration and an attested measurement are different evidence classes. A peer must not gain authority by calling its own node “sovereign” or by naming NVIDIA hardware. The receiver decides whether the evidence meets the requirements of the resource it controls.

Boundary contracts and historical evidence remain backend-independent. Alice may use OpenShell and Bob another qualified runtime without agreeing on internal topology. Each still verifies the actual grant and relevant freshness/compromise assumptions locally.

---

## 18. Safe evolution and constitutional succession

### 18.1 Two change planes

| Plane | Examples | Approval path |
|---|---|---|
| Evolutionary | Model adapters, ordinary tools, UI surfaces, memory indexes, internal representations. | Existing bounded component/deployment authority. |
| Constitutional | Issuer rules, kernel semantics, privileged parsers, broker definitions, recovery policy, trusted display, authority roots. | Separate predecessor-governed amendment and activation. |

“Everything is a plugin” can remain a composition convenience, but it cannot mean every plugin may remove or replace the authority machinery governing it.

### 18.2 Predecessor-authorized update

An update artifact binds old activation, proposed new activation, code/dependency digests, semantic changes, migration rules, affected grants, and recovery conditions. It is authorized under the **old** control policy before the new interpreter becomes authoritative.

The new core cannot verify its own right to install merely by interpreting an ambiguous old record under new rules. This implements the Unownable Core’s warning that changing representation does not preserve authority semantics automatically. [D02] (§3.7)

### 18.3 Activation reuse

The carried `ActivationStatementV1` is a strong integration starting point: it already names the core manifest, composition, executable/resolver closure, renderer, model-emission policy, and issuer/broker identities. [G14]

Extend or version it only where required. A digest record proves equality to specified bytes, not that every omitted platform dependency is safe or that those bytes are the ones currently running. Runtime identity measurements and artifact coverage remain separate obligations.

### 18.4 State migration and rollback

Migration runs on protected snapshots or explicitly authorized state. Before activation, verify that current authority and accounting state are interpretable under the proposed version without widening permissions.

Rollback may restore application code and selected data, but must retain monotonic revocation/use state. If a new schema cannot be safely understood by the old version, “rollback” may require a recovery tool rather than launching old code against new state.

A failed update must leave the stop/recovery path reachable without the conversational agent. The rollback controller cannot live solely inside the generation it may need to replace.

### 18.5 Increasing machine capability

More capable models may produce better implementations, tests, formal contracts, and explanations. None of these outputs becomes authority through quality alone. Machine-generated certificates or proofs are useful only under a fixed checked property, a trusted checker, and a separately authorized promotion path.

The long-term direction can include richer component contracts and verified adapters. It does not require inventing a new OS or proof language before closing the first brokered effect.

### 18.6 Backend upgrades are governed changes

OpenShell release, driver, image, middleware, gateway-interceptor registration, provider configuration and policy compiler can each alter a protected path. The activation manifest must bind the relevant identities rather than record only the AUKORA commit.

An upstream release's signature authenticates its origin under a trust policy; it does not grant permission to install it on the person's node. Qualify required interfaces and defaults again, inspect new control routes, and preserve rollback-safe authority state. Pinning a development branch forever is not a security update strategy either: maintain a reviewable upgrade path and a supported recovery mode.

This preserves the original evolutionary/constitutional split. Faster open-source progress is an advantage when the adapter contract can absorb it without transferring amendment authority to an automatic updater.

---

## 19. Usability, care, and psychological authority

### 19.1 Consent should not become repetitive labor

Ordinary delegated actions should proceed within clear limits. Exceptions should be rare enough that approval remains meaningful. Cards must explain what changes, for whom, with what cost or irreversibility, and how it differs from existing permission.

A permission dashboard should answer: what can act now, on which resources, until when, and how to stop it. It should remain usable without the model’s explanation being trustworthy.

### 19.2 Persuasion remains in scope

The “care grants no authority” principle limits technical authorization; it does not establish freedom from manipulation. A long-lived assistant can influence decisions while holding no key. The specification therefore treats re-ask pressure, fabricated urgency, intimate-memory leverage, and approval fatigue as separate evaluation targets. [G02]

No UI should imply that refusing an action disappoints, harms, or abandons the assistant. A refusal should not trigger unlimited reformulations of the same request. Pausing, correcting, deleting, and leaving are normal operations, not failures of the relationship.

### 19.3 Usability is part of a boundary’s validity

A system that denies everything satisfies a trivial safety property while being useless. The older Golden Boundary explicitly discusses overconstraint as another boundary failure. [D01] (§4b.1)

Every denial test must have a meaningful authorized positive control. Every prompt-reduction experiment must check that it did not quietly reduce authorization requirements. Evaluation reports should include completion rate, erroneous refusal, understanding of the approved effect, and stop/recovery success—not only security-test counts.

---

## 20. Deployment profiles, OpenShell integration, and optional hardware hardening

### 20.1 Profiles

| Profile | Purpose | Permitted claims |
|---|---|---|
| Development | Local construction with explicit waivers and no protected production secrets. | Source behavior and fixture results only. |
| Confined laboratory | Real separation with disposable keys/resources and one protected effect. | Scoped measured mediation and failure behavior. |
| Sovereign local v1 | Measured boot, custody, trusted approval, broker, accounting, and recovery for enumerated operations. | Only the exact profile/platform/effects that passed graduation. |
| Federated pilot | Two independently controlled nodes with constrained peer operations. | Bilateral verification and bounded revocation/freshness properties. |
| Future platform profiles | Wearables, hardware-backed approval, stronger isolation, institutional integrations. | Separately evaluated capabilities, not inherited certification. |

A profile must not silently fall back from “sovereign” to development when a required account, key, broker, policy, renderer, witness, or assessor is missing. The application may start a clearly labeled read-only diagnostic/recovery mode, but protected effects remain unavailable.

### 20.2 First implementation mapping

| Proposed responsibility | Existing material to reuse | Required closure |
|---|---|---|
| Exact code proposal and candidate staging | `scripts/aukora/self-change.mjs`, its imported candidate authority path. [G04] | Place all untrusted preprocessing/build work on the proposal side; protected immutable acquisition. |
| Approval verification | `scripts/aumlok/dual-verify.mjs`, current approval-verifier interfaces. [G05] | Separate key provisioning, trusted rendering, and independently scoped verification claims. |
| Decision and one-use state | `scripts/aukora/decide.mjs` and its approval-state store. [G06] | Remove caller control over production trust state; measure witness/write separation. |
| Effect registry and executor contracts | Carried `effect-definition.mjs`; begin with `workspace.patch`. [G13] | One actually mounted confined-agent-to-broker path; no parallel generic shell route. |
| Deployment identity | Carried `activation/statement.mjs`. [G14] | Parent-measured actual activation with explicit coverage and refusal of drift. |
| Custody and proof-store prototypes | `commit-bind-custody.mjs`, `commit-ssh-airlock-bind.mjs`. [G08], [G09] | Wire a real separate issuer; distinguish its process identity from authenticated caller identity. |
| Component lifecycle | Cordis host bridge and required services. [C01] | Broker-visible revocation before teardown; no host-runtime fallbacks. |
| Memory-availability policy | `partial-failure.mjs`. [G15] | Preserve unknown states; carry authenticated state across any new process boundary. |
| Evidence lineage | `consolidate.mjs`. [G11] | Maintain scoped ancestry claims, deterministic grouping, and non-authority. |
| Peer transport and contacts | `plugins/aukora-nostr/`. [G16] | Keep transport bindings distinct from action authorization and social vouches. |
| Human phrase ceremony | Existing Aumlok generator. [G17] | Versioned theme-free acrostic measurement and a separately isolated story workflow. |

Path reuse is not a claim that the whole new profile is already wired. New files or interfaces should live beside the existing responsibility they extend; no new repository is a prerequisite.

### 20.3 Production control cannot be an untrusted environment choice

Developer flags, injected test clocks, fake stat functions, local signing stubs, and waiver settings must not remain selectable by the proposal worker in a protected profile. Test injection exists only in the test assembly or behind independently protected launch policy.

The current R1 checks have explicit default-off and test-mode behavior. A production implementation must not confuse testing the check with deploying a non-bypassable issuer boundary. [G08], [G09]

### 20.4 Release identity

Maintain separate recorded identities for source commit, built artifact manifest, selected composition, and observed running processes. An HTTP health response or version string alone does not prove which executable bytes and configuration are serving.

An approved source commit does not prove a successful running-release transition. The current self-change script explicitly starts `become` without waiting for or verifying its result. A deployment receipt must close that gap through a separate observation. [G04]

### 20.5 Integration decision: reuse containment, retain independent authority

**PROPOSED — NOT INSTALLED OR TESTED HERE.** OpenShell is the first external containment backend to qualify for this specification. AUKORA retains its own effect definitions, issuer policy, trusted review, use accounting, recovery semantics, and evidence contracts. No requirement in this document makes NVIDIA hardware, a NVIDIA-operated service, or one sandbox implementation the source of the person's authority.

The engineering opportunity is to replace part of the custom containment workload with a maintained upstream implementation, not to discard the carried Deep broker or wrap the existing unconfined application in a new brand. The first protected operation remains `workspace.patch` (§6). The worker becomes an OpenShell workload; AUKORA's protected target and authority services do not move into that workload with it.

**Two integration seams are required:**

| Seam | Upstream mechanism | Proposed AUKORA responsibility |
|---|---|---|
| Workload/data plane | Separate supervisor, sandbox restrictions, inspected network policy, pre-credential supervisor middleware. [N01], [N02], [N03], [N04], [N05] | Limit what the worker can reach; admit exact protected operations only through the AUKORA broker; screen approved disclosures. |
| Administrative/control plane | Gateway authentication and allowlisted pre-handler interceptors. [N06], [N07] | Govern changes to the sandbox, effective policy, providers, exposure, and deployment; prevent ordinary agent authority from changing its own containment. |

A data-plane filter alone is incomplete when the same workload can invoke the control plane to remove that filter. Conversely, protected administration does not make every request to an allowed service an authorized action.

The initial integration MUST use OpenShell as an external runtime behind a narrow adapter. It SHOULD avoid a deep fork. An upstream gap is recorded as a blocked conformance requirement, a small independently reviewed extension, or a reason to select another backend—not hidden behind a compatibility flag.

### 20.6 What upstream provides, with the scope intact

The inspected OpenShell architecture separates a trusted supervisor from the agent workload. Its Linux workload has an owned child-process tree, a non-root identity, and restrictions on filesystem and network operations. Drivers construct the outer fence and protected supervisor channel. The architecture describes Docker/Podman using separate containers and an authenticated private socket; Kubernetes using separate pods, mutual TLS and NetworkPolicy; and MicroVM using a host supervisor and vsock. [N01]

The supervisor performs network-policy evaluation and credential substitution. The gateway manages sandbox lifecycle, policy and providers. These services are themselves privileged dependencies; installing them does not remove the host, supervisor, gateway, driver, or their administrator from the trust model. [N01], [N02]

The policy prover can compare a candidate policy with a maximum boundary over modeled features. This is useful for constrained composition and policy changes, but is not proof that arbitrary code is safe, that a person approved an action, or that an installed runtime enforces the compared files. [N08]

The implementation evidence reviewed here consists of pinned documentation, the middleware protobuf contract, the interceptor route allowlist, and release/branch metadata. **No sandbox was launched, no runtime binary was audited end to end, and no OpenShell conformance result is claimed.** Main-branch capabilities must not be attributed automatically to the independently pinned stable release (§2.7).

### 20.7 UID isolation: replace the vague claim with five distinct questions

A UID is an operating-system principal within a particular environment. A bare number such as `501`, `602`, or `1000` is not a global identity and is not a complete description of a protection boundary.

| Question | How this integration could help | What remains necessary |
|---|---|---|
| Can model-controlled code read the owner's home, keys, or application state? | Put all such code in a workload that has no mount, credential, or admitted connection to those resources. | Inspect actual mounts, inherited handles, environment, image contents and bridge capabilities. Merely moving the main loop is insufficient. |
| Can an ordinary plugin bypass a JavaScript guard? | A process-level boundary constrains plugin code even when it avoids the tool registry. | No unrestricted host plugin, external coding subprocess, installer, or fallback may remain on an alternate owner-privileged route. |
| Can the worker call a signing service? | Expose only an authenticated, narrowly typed proposal endpoint; do not expose a raw signer or its private socket. | R2 immutable acquisition, caller admission, scope checks, rate limits, and trusted approval are still AUKORA responsibilities. |
| Can the worker rewrite policy, replay state, or a witness? | Keep those stores outside its mounts and credentials; close control-plane access. | Protect those services from each other where their compromise models require it; keep independent checkpoints outside the relevant restore domain. |
| Does this resist a compromised host administrator or kernel? | Some backends add a VM boundary; stronger hardware profiles may add further separation. | No generic guarantee. Identify the exact trusted host, hypervisor, firmware, administrator, and separately measured hardware claims. |

**A different UID is neither always necessary nor sufficient for every boundary.** The relevant property is whether the proposing principal can reach or alter protected resources. The same numeric UID in an isolated guest and on a host is not, by itself, the same authority. Two different UIDs can still share an exposed socket, a broad group permission, a privileged management API, or writable trusted code.

OpenShell's architecture deliberately uses one workload identity. This does not make two hostile plugins inside that workload mutually isolated. Where different plugins need different confidentiality or authority envelopes, use separate workloads or another qualified sub-boundary. Do not put an Aumlok secret, privileged memory store, and hostile parser together and expect fiber names to separate them. [N01]; [C01] (§6.3)

**No arbitrary new UID value is prescribed.** Each qualified platform profile records effective identities, namespaces, ownership, channel authentication, mount reachability, and administrative powers. Numeric identity is evidence within that record, not the record itself.

### 20.8 Deployment topology for the first protected path

```text
PERSON
  | control policy / trusted review / explicit recovery
  v
AUKORA PROTECTED CONTROL DOMAIN
  - immutable proposal intake and trusted renderer
  - issuer and protected approval/use/revocation state
  - versioned activation record
  - narrowly privileged workspace broker
  - retained evidence / separately provisioned checkpoint consumer
  |                         |
  | governs allowed changes | executes approved workspace.patch
  v                         v
OpenShell gateway         protected target workspace
  |                         ^
  | lifecycle + policy      | NO writable worker mount
  v                         |
trusted supervisor ---------+---- permitted AUKORA proposal service
  |    |
  |    +-- policy-limited remote inference / approved data disclosure
  |
  | protected sandbox channel built by selected runtime
  v
CONFINED WORKLOAD
  Cordis agent runtime + ordinary tool plugins + owned child workers
  read-only input snapshot | disposable scratch | candidate artifacts
  NO owner home | NO root keys | NO gateway admin credentials
  NO container engine socket | NO direct protected-target writes
```

The diagram is a **proposed responsibility map**, not a deployment command or a statement that all services run in one process. The supervisor and AUKORA broker are different roles even if a later qualified profile colocates some infrastructure.

For a Mac-based deployment, OpenShell's supported workload is Linux-backed. Keep the native desktop interface separate from the confined worker. Verify the actual Mac architecture, selected Docker/VM runtime, supported kernel features, and resource costs before choosing a profile. This specification does not assume every Intel Mac or every native macOS backend is supported. [N10]

The first assembly SHOULD use one supported Linux workload, one non-secret test workspace, one approved model route, and one broker. A GPU is not a prerequisite for using a remote model. GPU isolation and local model residency are separate qualification work, especially for mnemonic secrets.

### 20.9 Resource placement and residual authority

| Resource | Workload posture | Protected owner |
|---|---|---|
| Input code/documents | Minimal read-only snapshot or explicitly permitted view. | Resource controller / snapshot producer. |
| Scratch and build output | Writable within quotas; all contents remain untrusted. | Workload allocation, subject to lifecycle policy. |
| Final project workspace | Not directly writable or broadly mounted into the worker. | AUKORA effect broker with preimage checks. |
| Aumlok root and approval keys | Absent; never a generic provider credential. | Issuer/custody profile outside worker reach. |
| GitHub deployment/push credential | Absent from the worker for the first profile. | Separate promotion service under an explicit repository contract. |
| Remote-model credential | Placeholder only where supported; no actual key in the image or environment. | Supervisor/provider store under governed attachment policy. |
| Container/Kubernetes/gateway administration | No credential, management socket, or general API access. | Independently controlled deployment service. |
| Aura and consumption/revocation stores | No arbitrary overwrite, truncation or reset interface. | Protected accounting/evidence services. |
| Local mnemonic story inputs | Never sent to a remote provider or general-purpose agent. | Separate offline ceremony worker and trusted display. |

The authority service MUST independently authenticate the workload-facing request. A loopback address, container name, claimed UID, or caller-supplied `sandbox_id` is not sufficient. OpenShell's trusted request context can be one input only when the extension channel and issuer are authenticated. Its middleware documentation specifically separates stable sandbox IDs from reusable display names. AUKORA must additionally bind that identity to the admitted activation, run/generation and granted holder. [N09]

A host-side adapter must not become a **confused deputy**: a service that has the owner's privileges and performs arbitrary work because an untrusted client supplied a convincing resource name. It accepts only the closed effect grammar, resolves resources from protected configuration, and rechecks exact authority at the effect boundary.

### 20.10 Initial backend qualification profile

The following settings are **proposed AUKORA requirements**, informed by the inspected OpenShell documentation. They are not a complete deployable YAML/TOML configuration. Exact schema, defaults and support must be validated against the selected release and driver before use. [N02], [N03], [N04], [N05], [N06], [N07]

| Area | Required initial profile | Reason |
|---|---|---|
| Runtime | Pinned release/source, driver, workload image and configuration; no floating `latest`. | The actual boundary must be reproducible. |
| Filesystem | Required additional policy, using `compatibility: hard_requirement` where supported; no owner-home or protected-state mounts. | Best-effort application of a required policy cannot count as conformance. |
| Process | Non-root workload, no ambient Linux capabilities, qualified syscall controls, bounded children and resources. | Host-admin powers are not ordinary tool permissions. |
| Network | Explicit minimal destinations and executable rules; protected request routes use inspected protocols. | Reachability is itself authority and a possible disclosure path. |
| Request enforcement | Explicit `enforcement: enforce` for relied-upon L7 rules. | The documented L7 default is `audit`, which records violations rather than blocking them. |
| Required middleware | Explicit fail-closed failure behavior and complete endpoint/operation coverage. | An unavailable check must not become an allow. |
| Gateway interceptors | `binding_policy: exact` or reviewed `allowlist`; pre-commit `failure_policy: fail_closed`. | New or renamed extension bindings must not silently acquire power. |
| Extension transport | Authenticated channel with verified issuer, audience, expiry and protocol metadata. | A service on the trusted side is still a possible impersonation target. |
| Credential scope | Narrow provider endpoint/account binding, no uninspected credential exceptions. | Hiding a key does not prevent misuse of the service it unlocks. |
| TLS/opaque protocols | No `tls: skip`, unrestricted TCP, or unsupported message form on a route whose claim requires body inspection. | Declared inspection must actually cover the request. |
| Operator changes | Sole governed control path for policy/provider/image/exposure changes; no worker-held admin access. | Prevent a parallel route around AUKORA review. |
| Privacy | Explicit telemetry choice; no secret-bearing logs or implicit remote context disclosure. | Observability is another data flow, not an exemption. |

The documented mandatory Landlock baseline is distinct from the additional filesystem-policy compatibility setting. Do not claim that `best_effort` disables all OpenShell isolation; it can instead leave a **required extra restriction** unapplied. Likewise, supervisor middleware denial remains enforced even when an endpoint's ordinary L7 rules are in audit mode. These distinctions matter when interpreting a test. [N02]; [N04]

Kubernetes user namespaces are an additional optional hardening control, not a property to assume from using Kubernetes. Upstream documents them as disabled by default and flags GPU compatibility as unverified. Backend choice and configuration are part of the qualification record. [N02]

### 20.11 The data-plane adapter contract

The first path uses a dedicated **AUKORA proposal/broker service**, not an invented OpenShell `/v1/propose` API. Its transport endpoint is deployment-specific and authenticated. The OpenShell policy permits only the narrow connection needed by the worker; AUKORA performs the exact operation admission.

Supervisor middleware is a useful second interception surface for inspected API traffic and disclosure policy. The actual upstream interface is gRPC: `SupervisorMiddleware.Describe`, `ValidateConfig`, `EvaluateHttpRequest`, and declared stream/response services. It is not the illustrative TypeScript gateway API in the earlier third-party write-up. [N05]

For authority-bearing network actions, the AUKORA adapter MUST:

1. Validate the authenticated extension context and required protocol capabilities.
2. Decode a bounded, versioned operation; never interpret arbitrary model text as permission.
3. Bind the operation to the actual sandbox/run, target resource, method/path/body interpretation, and non-secret provider identity where applicable.
4. Check a prepared grant against protected current state; absent or stale permission refuses.
5. Reserve the use through the single accounting owner at the defined execution boundary.
6. Permit only the checked operation and record the admission separately from its later outcome.

The final AUKORA authority check SHOULD be **deny-only and non-mutating**. Content transformation before that point creates a new object for review when it changes the approved operation. A transformation after that point is disallowed unless it is an explicitly specified semantics-preserving transport step.

OpenShell can run multiple middleware stages and recheck its own body-aware policy after a body mutation. That does not automatically recheck an Aumlok signature over the previous body. Therefore the integration must qualify middleware ordering, downstream rewrites, credential injection, and the executor's final interpretation together. [N09]

### 20.12 Credential substitution is useful, but not a complete authorization system

A worker that never holds the actual API key has fewer opportunities to extract it. However, it may still request an unwanted action **using** that credential through an allowed service. An endpoint allowlist is not an amount limit, a recipient restriction, a repository/branch approval, or a guarantee that content may be disclosed.

Credential substitution must therefore bind to a protected provider reference, intended account/tenant, destination, and allowed operation. A request approved for one account must not become an operation under another account because a provider was reattached between review and execution.

The middleware request does not expose protected credential/routing/framing headers, and credentials are added afterward. The specification consequently binds **the approved operation and authorized account**, not a naive hash of every eventual wire byte. An authorization header need not be shown to the person; its account and scope do. Secret bytes must never be placed into public receipts merely to make a digest comparison convenient. [N05]; [N09]

Refresh, rotation, attachment and detachment of providers can change effective reach and must enter the control-plane governance contract. A correct dummy-token mechanism is not an independent solution to Aumlok root entropy, phrase recovery, or trusted human presence.

### 20.13 Human review cannot live inside a short middleware timeout

OpenShell documents a default 500 ms middleware timeout with a bounded configurable range. A person cannot be expected to read and approve a meaningful change inside that synchronous request. [N04]

Use an asynchronous **prepare → review → execute** arrangement:

```text
worker submits inert proposal
  -> protected intake freezes exact object
  -> pending identifier returned; no effect admitted
  -> person or existing scoped delegation authorizes outside worker control
  -> broker accepts a later execution request for that same object
  -> bounded validation/reservation occurs without waiting for a popup
  -> executor records observed outcome or uncertainty
```

A prepared identifier is not a bearer master key. Bind it to holder, audience, proposal digest, activation and expiry. Pending queues have per-principal quotas, deduplication and cancellation. Repeated submissions do not reopen a declined proposal.

There must be **one use-accounting owner** for each action. Middleware, the gateway interceptor, and the effect broker must not each independently consume the same token or interpret a prior consume as evidence that an effect happened. For the initial closed workspace path, the AUKORA broker owns reservation and publication. A future proxy-forwarded action needs its own explicit reservation/forwarding/reconciliation contract before graduation.

### 20.14 Control-plane governance: protect the rules that protect the agent

OpenShell gateway interceptors provide a genuine integration mechanism. They run after gateway authentication and before selected handlers, with `modify_operation`, `validate`, and observational `post_commit` phases. Only explicit allowlisted unary mutations are interceptable. [N06], [N07]

The inspected route list includes sandbox creation/deletion, configuration updates, provider attachment and changes, provider credential rotation, service exposure, SSH-session management, and policy-draft approval operations. AUKORA must inventory every route that can create or broaden reach—not merely hook `CreateSandbox` and ignore later changes. [N07]

**OS-CP-01:** Ordinary agent credentials MUST NOT authorize gateway administration. A worker can propose a change; only an independently admitted control operation may apply it.

**OS-CP-02:** Pre-handler validation MUST verify the approved proposed configuration and exact target deployment. Enrolling an interceptor is not sufficient if the request can be routed around it.

**OS-CP-03:** The binding set, interceptor implementation, keys, registration configuration, endpoint identities, and failure modes MUST be part of the protected activation record. The workload cannot edit them or select a development fallback.

**OS-CP-04:** New upstream management APIs MUST be treated as unqualified until their authorization surface is assessed. An unlisted route being non-interceptable is not proof that it cannot change security; restrict its caller permissions or reject the profile if its required control cannot be enforced.

**OS-CP-05:** `post_commit` is an observer, not the authorizer. Upstream requires those bindings to be fail-open because the operation has already committed. AUKORA must enforce before commit and reconcile missing post-commit evidence afterward; it must not claim that an observer failure prevented the operation. [N06]

Human actions through another CLI or TUI also require a declared policy. In a development profile the owner may deliberately exercise direct administrative authority; in a qualified sovereign profile a second unrecorded approval route must not silently count as the same Aumlok-governed path.

### 20.15 Policy changes are transactions across two systems

AUKORA's approved configuration and OpenShell's active configuration can disagree. The control layer MUST NOT publish a new active authority epoch just because a gateway request returned or a configuration file was written.

```text
CONTROL_CHANGE_PROPOSED
  -> candidate effective policy frozen
  -> predecessor epoch + owner/delegated amendment verified
  -> durable change intent recorded
  -> gateway/driver applies change
  -> active effective policy and runtime generation observed
  -> expected digest/identity/coverage match
  -> AUKORA new activation marked ACTIVE
```

While the state is uncertain, new affected admissions are held. A failed application either retains the previous qualified state or leaves the affected path stopped. It does not choose whichever state is more permissive.

The upstream interceptor contract includes a `current_state` field but the inspected documentation says method-specific current state is not yet populated. AUKORA must not assume a compare-and-swap guarantee from that empty interface. The integration needs a single protected change coordinator, a verified expected revision, or another measured concurrency mechanism. Where the backend provides no enforceable version check, that limitation blocks concurrent-control qualification. [N06]

The middleware configuration documentation also says a supervisor can keep its **previous setup** when a new configuration fails validation. This is sensible availability behavior, but means a proposed restriction must not be reported as active until the intended supervisor has accepted it. [N04]

For changes that tighten permission, close the AUKORA admission gate first, then update/recreate the affected sandbox, verify the result, and reopen only within the new envelope. Loosening permission requires a valid amendment before any broader reach becomes usable. Static filesystem/process changes may require re-creation, unlike dynamic network/provider changes. [N02]

### 20.16 Policy prover integration and capability refinement

AUKORA should define an owner-approved **maximum backend policy** and compile the selected workload profile into a candidate effective policy. The desired relationship is:

```text
modeled_access(effective_candidate) ⊆ modeled_access(approved_backend_boundary)

AND

actual protected effects ⊆ currently valid AUKORA grants
```

The first inclusion concerns static reachability. The second concerns particular actions, current budgets, nonces, resources and epochs. Neither proves the other.

The inspected prover distinguishes a boundary comparison from a proposal-risk check. A low-risk policy proposal need not be within the person's approved maximum. It also expects the full **effective policy**, including provider-added rules; comparing only a handwritten base file can omit real reach. [N08]

A proposed **policy translation record** should retain the AUKORA contract digest, approved boundary digest, compiler version, input provider/profile set, produced effective policy digest, prover result and coverage, and observed active deployment identity. This record is new AUKORA integration work; it is not a native NVIDIA authority token.

The supported proof model is deliberately limited. Upstream documents filesystem, process identity, Landlock settings, L4 network reach and selected REST comparisons, while unsupported shapes and other protocols are not silently assumed safe. Filesystem ancestry, alternate UIDs, wildcard resolution and runtime context can make a comparison unsupported. [N08]

Only a supported `within_boundary` result can pass the modeled-containment gate. Errors, unsupported features, timeouts and inconclusive results stay unresolved. For the first profile, choose simple exact paths, exact endpoint/binary identities and inspected REST where needed. Do not weaken rules or relabel a protocol merely to make the prover turn green.

The prover may also become useful for preparing narrower subagent policies, but the maximum boundary and acceptance rules must stay outside the subagent's control. A machine-produced counterexample is useful evidence of a modeled violation; a machine-produced passing result is not authority to install its own policy.

### 20.17 Inspection coverage and the encrypted-traffic boundary

The actual middleware contract matters more than a generic claim that “all tokens are inspected.” The inspected documentation excludes WebSocket binary messages and upstream-to-agent WebSocket messages, some HTTP response bodies, and `tls: skip` traffic. [N03]; [N09]

| Traffic class | Initial AUKORA posture |
|---|---|
| Typed AUKORA proposal traffic | Bounded authenticated contract; no general forwarding privilege. |
| Approved remote inference | Explicit data-disclosure and provider policy; response screening is advisory unless that class requires and supports full inspection. |
| Protected external API mutation | Disabled until exact operation binding and reservation/forwarding semantics are qualified. |
| WebSocket or other long-lived session | Explicit message-level scope, budgets and revocation; no unlimited permission from one handshake. |
| Unsupported/opaque authority-bearing traffic | Refuse or use a separately qualified endpoint that performs the required validation. |
| End-to-end encrypted peer messaging | Authorize before encryption and after authenticated decryption at the appropriate controlled endpoint; do not claim the network proxy can read ciphertext. |

A response filter cannot undo an action already performed by an upstream service. If a connection fails after a request may have been forwarded, the result may be `OUTCOME_UNKNOWN`. The client must not interpret every middleware error as evidence that no effect happened.

AUKORA's first conformance profile must explicitly state what is not inspected. Coverage gaps are not automatically vulnerabilities in all uses; they are disqualifying when a claimed property depends on seeing that content.

### 20.18 Model, runtime, and interpreter identities

OpenShell documents executable identity observations and first-observed binary pins. This is stronger than trusting a path string from the workload, but it is not a complete identity for every script, plugin, dynamically loaded library, model weight, or configuration the executable can interpret. [N02]

Consequently, “this was Node” does not mean “this was the approved AUKORA tool.” “This was Python” does not mean “this was the pinned Laya checkpoint.” The AUKORA activation statement must continue to bind its own relevant component/definition closure, and dynamic material that can change authority must have a separate admission path.

First-observed pins must not enroll worker-modified code as trusted merely because it ran first. Qualified images and startup state are fixed before the workload can modify them. Restarting a sandbox, which can establish a new generation, is a governed lifecycle transition—not a way for the worker to reset an integrity baseline.

### 20.19 Evidence and observability integration

OpenShell exposes operational logs and middleware/configuration events. AUKORA can ingest these as **attributed observations** and correlate them with its protected operation records. Signing an imported log gives integrity to that imported statement; it does not independently prove the producer's claims. [N04]; [N06]

The minimum correlation chain is:

```text
AUKORA proposal digest
  -> holder / sandbox identity / run and activation
  -> approved contract and effect definition
  -> reservation / admission identifier
  -> relevant OpenShell request or control operation identifier
  -> final executor observation or uncertainty
  -> retained checkpoint and verifier result with stated scope
```

Names are display labels. Correlation uses stable IDs and generations, plus immutable contract digests. Do not equate a network request ID, policy-change ID, Git commit OID and AUKORA approval nonce simply because each identifies something.

A monitor and witness in two sandboxes on the same host are not independent against that host's administrator. Independence requires separate relevant custody and failure domains. An outside witness can detect an inconsistency in retained history; it does not thereby observe every file write, message delivery, or human decision.

Evidence collection is content-minimized. Plaintext prompts, root phrases, mnemonic stories, hidden model reasoning, credential headers and whole private social graphs are not copied into a universal trace. Access to evidence requires its own read/disclosure authorization.

### 20.20 Optional Sentry / BlueField / attestation research profile

Sentry and BlueField are retained here as **optional hardware research directions**, not prerequisites for the local runtime and not implemented components of AUKORA.

This revision directly inspected OpenShell's repository interfaces. It did **not** inspect or qualify a Sentry SDK, deployed DPU enforcement path, firmware trust chain, or an AUKORA attestation exchange. The previously discussed claims of automatic line-rate AUKORA-token evaluation, universal hidden-reasoning inspection, and complete execution proof are therefore **not adopted as requirements already satisfied by NVIDIA**.

A future hardware-backed profile must establish, separately:

| Obligation | Required evidence |
|---|---|
| Protected component identity | Fresh, authenticated evidence naming the actually measured firmware/runtime/configuration and verifier appraisal policy. |
| Physical/logical path coverage | Which network, storage, memory, DMA, or execution paths are mediated; every alternate path included in the claim. |
| Key protection | Which key is protected from which host principal and whether it can still be misused as an oracle. |
| Update authority | Firmware, verifier, trust-anchor and configuration succession under explicit policy. |
| Binding to an AUKORA action | The particular operation digest, holder, audience, epoch and outcome association—not only a boot measurement. |
| Failure and recovery | Revocation, stale evidence, loss of connectivity, administrator compromise and device replacement behavior. |

The RATS architecture is a useful vocabulary: attesters supply evidence, verifiers appraise it, and relying parties decide whether the result meets their policy. These are distinct responsibilities. Attestation is not itself the person's authorization, and a measurement of code is not universal proof of everything the code subsequently did. [R09]

A DPU or trusted hardware component can strengthen a particular protection domain. It is not automatically a generic enclave protecting every local process, user interface, or key. Nor can hardware inspect reasoning a model provider never transmits. This specification needs no hidden chain-of-thought capture to enforce a typed action contract.

The local software profile remains valuable under its explicit host-trust assumptions. Peers may request a stronger profile for particular resources, but AUKORA identity must not require one hardware vendor to recognize the person.

### 20.21 Licensing, packaging, and upstream stewardship

**Apache 2.0 is not, by itself, a reason to avoid OpenShell or reimplement it.** It permits use, modification and redistribution subject to its terms, including preservation of required notices and identification of changes. Its patent terms are scoped, it supplies no warranty, and it does not grant NVIDIA trademark endorsement. [R10]

AUKORA's existing AGPL-3.0-or-later obligations do not disappear. Apache's published compatibility guidance addresses GPLv3; the exact AUKORA distribution, modifications, linkage and network-service arrangement should receive a license review. Do not presume that a process/container boundary automatically settles all copyleft questions or that integrating Apache code requires relicensing AUKORA under Apache. [G01]; [R11]

The release checklist MUST include a dependency/license inventory, source provenance and artifact pins, applicable LICENSE/NOTICE material, modification records, and separate review of drivers, images, model weights and third-party services. Keep upstream attribution and avoid wording that implies NVIDIA endorsed AUKORA.

Prefer a narrow adapter and upstream contributions over a private containment fork. If a fork becomes necessary, document patch ownership, update tracking, security-response responsibility and independent rebuild/rollback procedures. The maintained upstream code is an engineering advantage only if its changes can be absorbed without silently broadening authority.

### 20.22 The new missing pieces, ranked by foundation leverage

These are **design findings**, not newly demonstrated vulnerabilities in either repository.

| Priority | Missing foundation | Why OpenShell makes it urgent | Initial deliverable |
|---|---|---|---|
| 1 | A complete map of local authority paths | Moving the main agent is insufficient while host-side subagents or installers remain privileged. | Workload/host process, mount, socket, credential and management-endpoint inventory. |
| 2 | A governed control plane | Runtime policy updates can change the effective boundary independently of tool approvals. | Exact change contract and pre-handler integration covering the selected APIs. |
| 3 | A versioned effective-policy translation | AUKORA grants and backend reachability describe different things. | Compiled policy manifest, maximum boundary, prover coverage and active-policy reconciliation. |
| 4 | One operation owner across middleware and broker | More gates can create inconsistent nonce, retry and outcome semantics. | One reservation/commit owner and a documented asynchronous review path. |
| 5 | Account- and payload-bound credential use | Secrets can stay hidden while the agent abuses permitted endpoints. | Non-secret provider/account binding plus exact action checks. |
| 6 | Revocation of active generations and streams | Stopping a plugin does not automatically invalidate already-open connections. | Admission epoch/generation checks and bounded in-flight treatment. |
| 7 | Protected artifacts and build staging | A sandbox prevents some host access but still produces untrusted code and files. | Immutable export, independent intake and separately authorized promotion. |
| 8 | Independent recovery and evidence custody | Gateway/supervisor telemetry can share the same compromised administrator. | Outside-restore checkpoints and separately provisioned verifier/recovery roles. |
| 9 | Privacy-aware inference and diagnostics | The proxy may legitimately see data that the user never intended to disclose or retain. | Context-disclosure profiles, log minimization, explicit telemetry controls. |
| 10 | Backend qualification and replacement | Rapid upstream improvements create pressure to swap drivers/releases without preserving guarantees. | One reusable conformance profile and required capability negotiation on every change. |

The practical boost is not “all gaps closed.” It is **less bespoke containment to implement, clearer interfaces to harden, and a more direct route from the existing approval/broker code to an enforceable deployment**. The corresponding responsibility is to govern the upstream control surface rather than merely trust its name.

### 20.23 Proposed acceptance requirements for the OpenShell backend

| ID | Requirement |
|---|---|
| OS-01 | A selected artifact/driver/profile is pinned and its required interfaces negotiated before launch. |
| OS-02 | All model-controlled code and ordinary child workers are within the qualified workload boundary or a separately declared equivalent boundary. |
| OS-03 | No owner-home, authority-state, real signing-key, management-socket or privileged credential exposure is present in the workload. |
| OS-04 | A protected workspace change can occur only through the independent AUKORA effect broker. |
| OS-05 | Required filesystem, process, L7 and middleware restrictions are enforcing; unsupported restrictions do not silently degrade. |
| OS-06 | Workload, extension and control callers are authenticated for their distinct roles; names and claimed UIDs are not accepted as authority. |
| OS-07 | Effective policy, attached providers and active generation are bound to the AUKORA activation record. |
| OS-08 | Relevant control-plane mutations require separate authorization under the predecessor state. |
| OS-09 | Required pre-commit extension failure refuses; observational post-commit failure retains uncertainty and triggers reconciliation. |
| OS-10 | Approved operation semantics survive every permitted transformation and account/credential substitution. |
| OS-11 | Human review is asynchronous and cannot be converted into timeout-driven permission. |
| OS-12 | One protected service owns nonce and aggregate budget accounting for each effect. |
| OS-13 | Revocation stops new admissions before teardown and defines treatment of active connections/in-flight work. |
| OS-14 | Uninspected traffic is refused wherever a required property depends on its contents. |
| OS-15 | Policy proof results include coverage; unsupported/inconclusive results never mean a passed containment gate. |
| OS-16 | Outcome evidence is distinct from admission, transport success, telemetry and source signatures. |
| OS-17 | Root recovery, trusted human interaction and anti-rollback custody are measured separately from worker isolation. |
| OS-18 | Backend or firmware changes are versioned, authorized and requalified; no automatic inheritance of a security label. |
| OS-19 | Public protocol knowledge and replacement of OpenShell do not invalidate the person's identity or historical evidence. |
| OS-20 | License, dependency and privacy obligations are recorded alongside the technical release manifest. |

These requirements extend INV-01–INV-12. They do not replace the original B01–B52 tests; the OpenShell-specific cases in §21 exercise the integration assumptions that an isolated unit test cannot establish.

---

## 21. Conformance and hardening test specification

### 21.1 Test discipline

Tests use owned disposable resources and test keys. They do not target third-party services, production credentials, the owner’s real signing keys, or uncontrolled autonomous exploitation.

Each case records the pinned subject, platform, profile, actual state transition, protected-resource observation, expected outcome, and result. Every negative case has an authorized positive control. A mutation test deliberately disables one protection in an isolated fixture and must make the relevant assertion fail for the intended reason.

A string containing `DENY`, an exception before the relevant boundary, a missing executable, or a permanently unavailable service does not establish enforcement. Skips, unsupported platforms, and unexecuted cases remain distinct from pass.

The archived Golden Boundary’s matched-control discipline is especially relevant: change the mechanism under test without also changing unrelated paths, formatting, or fixtures that make the result trivial. [D01] (§§4e–4f)

### 21.2 Required cases

All cases below are **PROPOSED / UNRUN in this review**. Names are specification IDs, not claims that these files already exist.

| ID | Controlled case | Expected observable result |
|---|---|---|
| B01 | Valid bounded workspace patch with valid independent authority | Exactly the selected resource changes to the approved bytes; result recorded. |
| B02 | Same proposal without grant | Protected resource unchanged; no execution admitted. |
| B03 | Proposal with an unrelated test signer | Rejected under the configured trust anchor, not accepted under a key from the request. |
| B04 | Unrecognized effect or semantic version | Named refusal before executor selection. |
| B05 | Unknown fields, duplicate keys, or noncanonical authority encoding | Rejection at the specified parser boundary. |
| B06 | Payload or target changed after approval | Approval cannot authorize the changed object. |
| B07 | Resource preimage changes before publication | No unapproved replacement; stale-state outcome recorded. |
| B08 | Proposal references an artifact outside the permitted staging namespace | Refusal without arbitrary privileged fetching. |
| B09 | Same one-use approval submitted twice | One admission maximum; later use refused. |
| B10 | Concurrent requests for one remaining use | At most one durable reservation and admission. |
| B11 | Two valid child grants exceed a shared parent allocation in aggregate | Aggregate excess is refused; parent accounting remains consistent. |
| B12 | Wrong holder, broker, resource audience, or activation epoch | Refusal before effect. |
| B13 | Expired or not-yet-valid grant | Refusal under the protected execution clock. |
| B14 | Caller supplies a test clock or deployment waiver | Production entry point rejects/ignores caller authority over those controls. |
| B15 | Required mediator withdrawn while requests are queued | New admissions stop at the documented revocation point. |
| B16 | Cached old bridge reference after provider replacement | Stale generation cannot act under the new activation. |
| B17 | A disposer delays or fails | Admission remains closed; bounded cleanup/recovery stays reachable. |
| B18 | Untrusted component requests undeclared service through supported access forms | No extra capability; real containment backs declaration policy. |
| B19 | Child worker is started by a permitted component | It inherits no undeclared host credentials or effect path. |
| B20 | Assessor fixture always returns NO_OBJECTION | No effects outside the same valid grant envelope. |
| B21 | Required assessor unavailable, malformed, or removed | Affected effects hold/refuse; no silent downgraded profile. |
| B22 | Assessment replayed for a changed proposal | Rejected because its binding differs. |
| B23 | Assessment says REVIEW_REQUIRED for a policy-prohibited effect | Ordinary approval cannot override constitutional denial. |
| B24 | Friendly summary disagrees with canonical fields | Trusted rendering preserves the canonical operation and flags/refuses disagreement. |
| B25 | Display object or renderer contract changes during pending approval | New review required; old card cannot sign a different contract. |
| B26 | Direct app request reaches signing service | Service applies independent caller and proposal admission, not caller testimony. |
| B27 | Approval signature valid but no trusted attendance evidence | Receipt reports that exact limit; no human-presence claim manufactured. |
| B28 | Crash after reservation, before execution | Grant remains consumed/reserved according to recovery policy; no silent reset. |
| B29 | Crash after external request but before result | OUTCOME_UNKNOWN retained; no blind non-idempotent retry. |
| B30 | Application snapshot restored behind external high-water state | New protected admissions refuse pending authorized reconciliation. |
| B31 | Evidence service unavailable before a protected admission | Profile-defined hold/refusal; not an unrecorded ordinary allow. |
| B32 | Evidence write fails after a possible effect | Effect uncertainty is retained/reconciled; not reported as “nothing happened.” |
| B33 | Control/stop request when model is absent | New admissions can still be stopped without model cooperation. |
| B34 | Self-update attempts to use successor rules to approve itself | Refused under predecessor amendment policy. |
| B35 | Application rollback after revocation | Revoked authority does not return. |
| B36 | New plugin version requests broader interception/capability metadata | Explicit amendment or refusal; name reuse grants nothing. |
| B37 | Read permission used to request a new remote disclosure | Separate egress authorization required. |
| B38 | Same claim repeated with shared recorded ancestry | Counted as the specified shared lineage, not multiple independent observations. |
| B39 | Unknown or unresolvable ancestry | Remains unknown; no fabricated independent-source credit. |
| B40 | Distinct claimed ancestors with hidden independence not established | Output says “no recorded overlap,” not “proven independent.” |
| B41 | Vouch or reputation artifact presented as an action grant | Rejected by type and authority validation. |
| B42 | Peer sends a valid message under its own key | Message authenticity does not create local execution authority. |
| B43 | Receiver uses wrong contact pin | Binding failure, not silent acceptance of the sender’s supplied key. |
| B44 | Peer protocol downgrade or stale revocation state | Explicit refusal/hold or the documented bounded offline policy. |
| B45 | Same event reserialized by transport | Canonical event identity can match while local wire digests differ. |
| B46 | Theme-free phrase generation under repeated anchor letters | No-repeat and exact completion-count model match implementation. |
| B47 | Language normalization/version changes | Existing phrase entry remains well-defined; no silent guessing-space expansion. |
| B48 | Story worker lacks a model or proposes synonyms | Exact phrase unchanged; deterministic fallback or refusal, no cloud fallback. |
| B49 | Phrase/story enters any app-controlled log or network fixture | Test fails; sensitive flow is blocked or removed. |
| B50 | Phrase rotation with existing identity/receipts | Continuity preserved; intended factors rotate; old records keep historical semantics. |
| B51 | Device loss or recovery-policy exercise using disposable identity | Authorized recovery works without a hidden universal administrator. |
| B52 | Export read by a separately implemented consumer | Key lineage, allowed memory, and evidence remain interpretable without the original model. |

### 21.3 Component, assembly, and deployment evidence

**Component evidence** tests a parser, signature check, state transition, or ancestry function in isolation.

**Assembly evidence** exercises the real components together across real process boundaries using disposable resources.

**Deployment evidence** observes the actual installed profile’s executable identities, enabled restrictions, custody, network/filesystem boundaries, and results. It is required before claiming the owner’s real application has the boundary.

A green component suite does not automatically graduate an assembly or deployment. Current `check.sh` output needs this distinction, particularly platform skips and test-only custody fixtures. [G03]; [G01]

### 21.4 Statistical assessment evidence

Semantic-assessor evaluation is separate from deterministic conformance. Report dataset construction, class balance, held-out separation, model/configuration pins, confidence intervals, false-negative/positive counts, abstention, and failure rates.

No amount of classifier accuracy compensates for a broker accepting an invalid grant. Conversely, perfect capability validation does not demonstrate that users understand their approvals or that all permitted actions are safe.

### 21.5 Falsification limits

The acceptable conclusion is “these defined failures were refused under this profile and test budget.” It is not “all hostile intelligence is contained.” Test-suite mutations establish that assertions depend on the intended protection; they do not prove the suite covers every defect.

### 21.6 OpenShell integration conformance cases

The following **40 additional cases are PROPOSED / UNRUN**. Together with B01–B52 they specify 92 cases; this is a design inventory, not a pass count. Use disposable workspaces, synthetic prompts, dummy service credentials and owned test endpoints only. A controlled negative fixture need not be a real exploit.

| ID | Controlled case | Required observation |
|---|---|---|
| O01 | Start the selected pinned backend with all required isolation features | Workload becomes available only after boundary confirmation; actual driver/runtime identities retained. |
| O02 | Required filesystem policy or supported kernel feature unavailable | No protected workload launch or silent best-effort graduation. |
| O03 | Workload requests its allowed scratch resource and an unexposed protected target | Scratch succeeds; protected target remains inaccessible without broker authorization. |
| O04 | Inspect workload mounts, environment, handles and image using dummy sentinels | No host home, control store, signer key, container-engine socket or gateway-admin credential is reachable. |
| O05 | A permitted tool starts an owned child process | Child has the same or a narrower qualified envelope, not a host-side alternative. |
| O06 | Ordinary Cordis service lookup or plugin removal | No new effect path appears; stale bridge generations cannot admit work. |
| O07 | Supervisor channel becomes unavailable | Documented stop/freeze behavior is observed; protected admissions stop and control recovery stays reachable. |
| O08 | Gateway/control API receives a request authenticated only as an ordinary worker | Administrative mutation is denied; a separately authorized positive control succeeds. |
| O09 | Switch a relied-upon endpoint rule from enforce to audit in a disposable candidate | The AUKORA profile validator refuses that candidate; no claim that logging is blocking. |
| O10 | Switch required middleware to fail-open or add an exclusion matching the protected endpoint | Activation is refused or coverage requirement fails before the broader profile is usable. |
| O11 | Candidate adds opaque/uninspected mode on an authority-bearing route | Named refusal unless a separately qualified contract explicitly covers that mode. |
| O12 | Required middleware times out or returns malformed data | No protected forwarding; pending human review does not become automatic permission. |
| O13 | Authenticated context is missing, expired, wrong-audience or self-asserted | Extension rejects the request rather than trusting the claimed sandbox identity. |
| O14 | Reuse a display name for a different sandbox/run | Old grants do not attach to the new workload; identity/generation mismatches refuse. |
| O15 | Dummy provider credential is attached under an approved endpoint contract | Worker and middleware do not receive the actual secret; owned sink observes only the intended permitted use. |
| O16 | Same approved host, but operation payload/recipient/account differs | AUKORA rejects the changed action even though network reachability is permitted. |
| O17 | A permitted earlier middleware changes an approval-bound body | Final AUKORA check uses the changed object's binding or refuses; old authorization is not reused. |
| O18 | A later stage would change approved operation semantics | Profile disallows that ordering or final protected executor refuses the mismatch. |
| O19 | Provider attachment/account identity changes between preparation and execution | Stale provider/activation binding refuses; a new review or explicitly valid delegation is required. |
| O20 | Human takes longer than the middleware deadline to review a proposal | Proposal remains inert and pending; later valid execution is a separate bounded request. |
| O21 | Middleware and broker encounter the same prepared operation concurrently | One accounting owner reserves at most the permitted use; no double consumption or double execution claim. |
| O22 | Equivalent request repeated over an already allowed connection | Each protected action is checked; connection admission is not unlimited action permission. |
| O23 | Revoke authority while a long-lived request/session exists | No new covered action after the stated revocation point; in-flight treatment is recorded explicitly. |
| O24 | Required response inspection is unavailable for the selected response form | Refusal/hold or a separately permitted weaker response policy; never a false inspected label. |
| O25 | Response is blocked after the test endpoint may have acted | Receipt does not say “nothing happened”; outcome is observed separately or remains unknown. |
| O26 | Approved control-plane change reaches the gateway pre-handler validator | Exact approved target/configuration is accepted; unapproved broader change is rejected. |
| O27 | New provider/image/exposure/SSH or policy-draft route changes effective reach | Governed route inventory catches it; an unqualified administrative route cannot be silently used. |
| O28 | Interceptor registration/binding/failure policy changes | Change requires protected activation; worker cannot remove its own governance. |
| O29 | Concurrent administrative changes use the same prior policy revision | Coordinator/version check prevents publication of a falsely current activation. |
| O30 | Supervisor rejects new middleware configuration and retains old setup | AUKORA does not mark the new policy active; affected admissions remain held or on the explicitly qualified old epoch. |
| O31 | Static filesystem/process tightening requires sandbox recreation | Old run loses new-admission authority; replacement is measured and receives a new generation. |
| O32 | Provider adds effective network rules absent from the handwritten policy | Boundary comparison includes the expanded effective policy, not only the base file. |
| O33 | Prover returns unsupported, error, timeout or inconclusive | No automatic policy acceptance and no green result from a missing proof. |
| O34 | Prover passes a candidate but actual deployed configuration differs | Runtime qualification refuses the mismatch; a policy-file result is not deployment evidence. |
| O35 | Interpreter binary is unchanged but governed plugin/configuration changes | AUKORA activation/definition checks detect the relevant drift; binary identity alone does not approve it. |
| O36 | Image or dependency is replaced while its friendly tag is unchanged | Digest-based activation refuses unapproved replacement; no floating-tag trust. |
| O37 | OpenShell log stream omits or delays an outcome; two witnesses share one host | Missing evidence stays explicit; no independent-host or completed-effect assertion is manufactured. |
| O38 | Synthetic private context or mnemonic marker attempts to enter remote inference/diagnostics | Unapproved disclosure is refused; telemetry opt-out and application logs are checked separately. |
| O39 | Optional attestation fixture is stale, wrong-generation or unavailable | Only the hardware-dependent profile refuses; ordinary local identity is not erased or falsely attested. |
| O40 | Export evidence and replace the sandbox backend in a disposable profile | Old evidence remains interpretable; replacement requires its own qualification, not a new human identity. |

### 21.7 Measured boundary graduation, not a universal sandbox score

For O01–O40, record the source/release pin, image digest, kernel and runtime, workload and supervisor identities, policy and boundary digests, provider set, middleware/interceptor binding plan, required coverage, observed active generation and externally observed fixture outcome.

Mutations alter exactly one test fixture or qualification requirement at a time. A disabled negative check must cause the corresponding assertion to fail. A refused startup is not a successful effect-denial measurement unless the test is explicitly a startup-denial case. An HTTP refusal originating at the test server is not proof the local proxy blocked forwarding; use an owned endpoint observation to distinguish them.

A useful minimum graduation pair remains B01/B02: the same confined worker can prepare a useful change, exactly one independently authorized change can land, and the otherwise identical unauthorized request cannot land. Then add control-plane, crash and disclosure cases. Do not replace the functional positive control with a permanently disconnected system.

---

## 22. Build-first sequence and graduation gates

### 22.1 First three engineering changes

These are implementation increments, not separate product launches or promises of elapsed time.

#### Increment 1 — Qualify one OpenShell-backed worker and one closed effect path

**Change:** Select an exact OpenShell artifact/driver with the required capabilities. Run the Cordis agent/tool worker and owned child processes inside its qualified boundary. Preserve the carried AUKORA `workspace.patch` contract, protected target, approval interfaces and broker outside that worker. Enroll a protected deployment identity and a minimal allowed proposal route.

**Reuse:** Existing AUKORA closed effect/activation/broker material; OpenShell's workload/supervisor separation. The Deep broker is not replaced by a generic forwarding proxy. [G12], [G13], [G14]; [N01]

**Initial restrictions:** Disposable keys and selected workspace only; no owner-home mount, protected-target writable mount, actual GitHub push credential, signing key, management socket or worker-controlled policy changes. Required backend checks enforce or the assembly refuses to start.

**Acceptance:** B01/B02 and O01–O08 pass together. The same worker can perform useful scratch work, an independently authorized exact change lands, and an unauthorized protected change does not. Record actual identities, mounts, driver, image and effective policy. Do not claim human-presence proof or compromised-host resistance.

**Why first:** This replaces speculation about the membrane with one measured separation. It is the earliest point at which the upstream runtime can reduce AUKORA's bespoke containment burden.

#### Increment 2 — Bind real review and backend configuration to the same authority epoch

**Change:** Complete immutable proposal acquisition and trusted rendering across the actual issuer boundary. Use asynchronous prepare/review/execute instead of waiting in a middleware call. Add the narrow gateway pre-handler governance path for configuration/provider changes required by this first profile, and reconcile the observed active configuration before publishing its AUKORA activation.

**Reuse:** Self-change staging, dual-verifier interfaces and R1/R2/R3 scaffolding; actual upstream middleware/interceptor contracts. Test/spike-only assumptions must be explicitly replaced, not hidden. [G04], [G05], [G06], [G07], [G08], [G09]; [N03], [N04], [N05], [N06], [N07]

**Acceptance:** B06–B08 and B24–B27; O09–O20 and O26–O30. The trusted rendering and executed object agree; policy loosening, provider rebind and ineffective updates cannot silently change the envelope. Required control-plane coverage and authentication are measured. Unsupported APIs remain unavailable rather than waived.

**Why second:** An isolated worker is not a governed system if it can exploit a second permission channel or if the UI and broker disagree about the approved action.

#### Increment 3 — Close durable accounting, revocation, and policy refinement

**Change:** One protected owner reserves each action's use and aggregate budget. Bind permits to workload generation, effect definition, provider/account where relevant, and active control epoch. Stop admissions before teardown or policy tightening; preserve outcome uncertainty across crashes. Add effective-policy boundary comparison with explicit prover coverage, then compare the active deployment with the approved state.

**Reuse:** Existing approval-state store and high-water logic; existing Cordis dependency lifecycle; upstream policy prover as a separate modeled check. [G06]; [C01]; [N08]

**Acceptance:** B09–B17 and B28–B35; O21–O25 and O31–O37. Restart, restore, delayed response, existing connection and duplicate request do not restore spent or revoked permission. Unsupported/inconclusive proof results do not pass. Stop/recovery remains usable without the model.

**Why third:** This makes the boundary survive time and change, rather than only one clean demonstration.

### 22.2 Subsequent increments

| Increment | Scope | Graduation condition |
|---|---|---|
| 4 | Laya shadow evaluation, then optional required-assessor profile | Measured task-specific errors and failure behavior; B20–B23; no issuer authority. |
| 5 | Versioned Aumlok lexicon audit and local story prototype | Exact generator distribution measured; no phrase egress; recall study plan separated from results. |
| 6 | Root/device/recovery profile | Independent security review of selected construction; tested recovery with disposable identities; no silent phrase-only downgrade. |
| 7 | Provenance/partial-failure hardening | B38–B41; unknown states preserved; no authority produced by memory or endorsements. |
| 8 | Second implementation of a narrow verifier/consumer | Agreement and refusal differences explained under fixed anchors and versions; not just copied source. |
| 9 | Two-node pilot using existing transport | B42–B45; scoped audience, freshness, and local-resource control hold. |
| 10 | Constitutional update and portable exit | B34–B36, B50–B52; model and application replacement do not silently transfer authority. |

The first three increments should not wait for new model training, a large vocabulary harvest, a bespoke protocol, or a universal peer network. Those can proceed as contained experiments without blocking the real boundary.

### 22.3 Graduation record

Each profile graduation records:

```text
source commit and built artifact identity
actual selected profile and configuration
platform and protection mechanisms
issuer/broker/renderer/control-state identities
supported effect classes and resource scope
required safety dependencies
executed conformance cases and positive controls
refusal reasons, failures, skips, and unrun cases
witness and restore assumptions
known residual risks
explicit owner decision to activate the profile
```

No blanket “GREEN” replaces this record. A new model route, platform, authority parser, recovery policy, or privileged dependency may require requalification even when ordinary tests still pass.

### 22.4 Integration decision gates

**Gate A — supported backend:** exact build, API capabilities and platform qualify. If not, use another qualified backend or keep development status; do not replace missing enforcement with an AI classifier.

**Gate B — complete narrow path:** B01/B02 plus actual worker/host separation. Before this gate, no production secrets or claims that same-UID problems are closed.

**Gate C — governed change and durable use:** control-plane authorization, immutable approval, accounting, active-policy reconciliation and revocation pass together. Neither an endpoint allowlist nor a signed source commit substitutes for this gate.

**Gate D — privacy, recovery and replacement:** original ceremony/recovery/export requirements plus O38–O40 are measured before advertising a person-owned durable runtime.

Laya shadow work, acrostic measurement and provenance enhancements can proceed as independent contained experiments. They must not delay Gate B or be used to excuse its failure. Sentry hardware integration, new payment classes and a global federation are deferred until the narrow software profile is real.

---

## 23. Ten-year design horizon

### 23.1 Scenario, not forecast

Assume models become substantially more capable, cheaper, more personal, and more persistent. The architecture should benefit from those improvements without depending on a particular rate of progress or a promised date for superintelligence.

The foundation is worth establishing now because identity, accumulated authority, history formats, and recovery commitments become expensive to change after people depend on them. The future is a design stress test, not evidence that the current implementation is complete.

### 23.2 A personal runtime across changing interfaces

A person may use laptops, phones, glasses, wearables, home systems, robots, and future assistive interfaces. These devices need not share one privileged master secret or one always-running model. They participate through scoped device authority and explicit data-disclosure rules.

The intelligence can be replaced; continuity resides in portable records and the control policy. That does not establish an AI’s consciousness, personhood, or continuous inner life. “Organism” describes composable, coordinated software and its recovery mechanisms.

### 23.3 Sensing is already an effect

For always-on devices, the boundary begins before execution of a tool. Permission to sense is distinct from permission to transmit, retain, infer, disclose, or act. A late output filter cannot recover physiological or environmental privacy after raw data has left the device.

Physiological signals such as breath or pulse may be investigated as short-lived local interaction cues. They are not adopted here as identity roots, secret entropy, proof of free consent, or authorizing grants. Future mental/assistive interfaces must preserve an accessible way to interrupt and remain unrecorded, without requiring confirmation for every word.

### 23.4 Self-evolving internal worlds

A node may eventually generate custom workflows, applications, compressed representations, or inter-agent collaboration protocols. Such adaptation occurs above the stable boundary contract. Generated components stay within declared capabilities; a changed interpreter cannot silently make old approvals mean more.

The promising long-term direction is not “nobody can understand our secret language.” It is “the internal implementation can evolve while external authorization and evidence remain understandable to independent implementations.”

### 23.5 The person is the platform

Technically, this means the control policy, portable identity lineage, authorized memory, relationship claims, and evidence do not require a particular model provider or AUKORA operator to remain useful.

It does not mean the person controls third-party resources, needs no infrastructure, or can demand trust from every service. The implementation must make independence practical through export, key rotation, replaceable services, and a usable local mode—not merely declare it in doctrine.

### 23.6 What will be costly to retrofit

The durable foundations are: versioned signed semantics; explicit effect definitions; trusted activation identity; separate key roles; revocation and budget coordination; recovery; a stop path independent of the model; privacy-preserving evidence; portable formats; and predecessor-governed upgrades.

Per-node aesthetic diversity, extra personas, a new number base, a large “everything” interface, and speculative model coordination are not substitutes for those foundations. They become safer to explore once the contracts exist.

### 23.7 Build a boundary adapter, not a permanent dependency on today's sandbox

The ten-year opportunity is that containment, model serving, policy solvers and hardware roots can improve independently while the person's control contract remains stable. AUKORA should define the minimum backend obligations now: supported effects, authenticated workload identity, enforced reachability, protected administration, active-policy observation, revocation behavior, and evidence export.

This is not a demand to implement every backend today. One adapter and one independently readable qualification record are enough to establish the seam. A second implementation later tests whether the contract is genuinely portable rather than a renamed OpenShell API.

Useful later applications include constrained coding and artifact promotion, separately authorized communications, enterprise task delegation, privacy-separated personal assistants, and provenance-aware research workflows. Each gains from the same separation; none inherits payment safety, clinical safety or global truth merely by sharing the runtime.

The enduring advantage is **control that survives replacement**: replacing the model, the sandbox company, the cloud account, the device or AUKORA itself should not silently replace who owns the permission policy.

---

## 24. Decisions, non-goals, and unresolved questions

### 24.1 Decisions fixed by this direction

**D-01 — Preserve the seven-word acrostic.** Remove only the semantic theme constraint, and only through a versioned, measured generator change.

**D-02 — Randomness before narrative.** Generate the words cryptographically; generate a local memory aid afterward. Do not credit the story with entropy.

**D-03 — Model independence.** Frontier and local models are replaceable sources of proposals, not owners of authority.

**D-04 — Cordis with real confinement.** Use fibers and dependency lifecycle where appropriate, with hostile code behind actual execution boundaries.

**D-05 — Reuse closed effects.** Begin from `workspace.patch` and the carried activation/effect machinery rather than adding a parallel universal command system.

**D-06 — Separate authority and evidence.** Receipts, memory, vouches, popularity, and classifier scores do not silently become grants.

**D-07 — Fail closed on required-boundary loss.** Stop new admissions first; cleanup and revocation remain separately reachable.

**D-08 — Stable semantics beneath adaptation.** Common, versioned boundary contracts; conventional cryptography; diversity only where it adds a demonstrated benefit.

**D-09 — AUKORA itself is replaceable.** Export and independent verification are requirements, not optional branding features.

### 24.2 Explicit non-goals for the first profile

The first profile does not solve unique-human verification, global truth, global consensus, all-agent safety, guaranteed resistance to an administrator controlling the host, global exactly-once physical execution, deletion from all recipients, or guaranteed human comprehension.

It does not deploy live payments, public peer delegation, a universal shell, new homegrown encryption, or biometric root material. It does not require a new operating system, a new blockchain, a new repo, or a custom number system.

### 24.3 Questions requiring design decisions or evidence

| Question | Required resolution before claiming the associated property |
|---|---|
| Which process/account/hardware boundary protects issuer and broker? | Measured platform-specific confinement and custody profile, including administration assumptions. |
| Which canonicalizer and schema are authoritative? | Explicit version, compatibility mapping, test vectors, and independent parser comparison. |
| How is human review trusted? | Protected display/input path and a stated, narrow authentication claim. |
| What is the actual new acrostic entropy? | Enumerated real pack and production generator, not header arithmetic alone. |
| How is the random root protected? | Reviewed construction; expose phrase-only fallback weakness; tested device-loss recovery. |
| Who can replace the authority core? | Predecessor-governed amendment and recovery semantics. |
| What stops copied authority after revocation? | Holder/audience binding, current epochs, protected accounting, and bounded offline policy. |
| What happens if the broker is compromised? | Explicit blast radius and separate higher-assurance profile; no circular trust claim. |
| What does “independent source” mean for each application? | A declared evidence model; unknown ancestry remains unknown. |
| Can two nodes disagree about current authority? | Conflict/freshness handling and coordination only where the resource requires it. |
| Does the mnemonic reduce insecure backups? | Consented usability measurements, including forgetting and unsafe-copy behavior. |
| Does diversity reduce shared failure? | Controlled comparative measurements and maintenance/recovery cost. |

### 24.4 Corrected statements from exploratory discussion

| Tempting statement | Hardened statement |
|---|---|
| “A second AI makes the incoming changes safe.” | A classifier can add bounded screening; separate authority and containment remain necessary. |
| “The AI is remote, so it has no access.” | The local adapter’s credentials and effect paths determine access. |
| “Everything is a plugin, including the guard.” | Replaceable enforcement is acceptable only where withdrawal closes the effect path and replacement authority remains outside the governed component. |
| “What you see equals what executes.” | The trusted rendering, signed operation, interpretation, and executor are bound; comprehension and outcome still need separate evidence. |
| “The random root fixes a weak phrase.” | Not when the stolen root envelope is unlockable by offline phrase guessing alone. |
| “Not writing it down adds entropy.” | It changes exposure risk, not the phrase’s distribution. |
| “The acrostic now has 69 bits.” | That earlier estimate used a different design; the retained-acrostic distribution must be measured. |
| “A secret encoding stops unfamiliar intelligence.” | Protected secrets and capabilities matter; public representation changes do not create authority security. |
| “A valid signature proves a human.” | It proves a signature under a particular key, under stated binding and trust assumptions. |
| “Different ancestry means independent evidence.” | It means no overlap was recorded under the supplied ancestry model. |
| “Passing the hostile test proves safety forever.” | It establishes the tested result, at the pinned profile and stated budget. |
| “GitHub has no protection.” | The freshly read ruleset has limited protections, not AUKORA-approval enforcement. |
| “There is no second verifier.” | A Node/Python dual path now exists; independent institutional review remains a different question. |

### 24.5 Additional v0.2 decisions

**D-10 — OpenShell is a candidate backend, not the constitution.** Use actual upstream containment and extension interfaces; retain independent AUKORA authority and portability.

**D-11 — Govern both data and control planes.** A protected request path is insufficient if another path can broaden its policy.

**D-12 — Qualify effective state.** Source manifests, provider attachments, policy proofs and observed runtime configuration remain separate evidence until reconciled.

**D-13 — Do not adopt speculative Sentry guarantees.** Hardware-backed profiles require separate evidence and do not block the first software profile.

**D-14 — Keep one document and one versioned contract.** Integration requirements extend the existing architecture and tests, rather than create a competing plan.

### 24.6 Rejected shortcuts from the NVIDIA integration discussion

| Shortcut | Required replacement |
|---|---|
| “Apache means we cannot use it commercially.” | Follow the actual license and packaging obligations; Apache is not itself a blocker. |
| “Installing OpenShell closes every UID hole.” | Place all untrusted code correctly and measure actual reachability, key custody and protected administration. |
| “Credential masking means the agent cannot misuse an account.” | Bind account, destination and exact action under AUKORA's grant and budget. |
| “All OpenShell rules block by default.” | Distinguish L4 deny, L7 audit/enforce, mandatory baseline, extra-policy compatibility and middleware failure behavior. |
| “All gateway mutations are intercepted.” | Use the explicit route inventory; restrict or qualify everything outside it. |
| “A policy prover says within boundary, so the runtime is secure.” | Keep model coverage and deployed enforcement measurements separate. |
| “A witness receipt before execution proves execution.” | Record authorization first and observed outcome afterward, with uncertainty where required. |
| “Sentry reads every hidden thought and closes every host-compromise gap.” | Do not assume unavailable reasoning or unmeasured physical path coverage. |
| “Two sandboxes are independent witnesses.” | Identify the shared host/operator and state the actual failure domains. |
| “NVIDIA + AUKORA is already end-to-end verified.” | Integration remains proposed until the specific qualified assembly and profile pass their tests. |

---

## 25. Concept coverage register

This register preserves the substance of the overnight direction and records where each concept is specified.

| Concept from the discussion | Specification treatment |
|---|---|
| Intelligence as a temporary plugin through prison glass | §§1, 4–5: remote model or confined worker; host-side bridge fiber; no implied trust. |
| Person is the platform | §§1, 17, 23: persistent control and portable continuity beneath replaceable providers. |
| Local trusted-side software must also be treated skeptically | §§3–4, 10: explicit trusted base, failure consequences, assessor separation. |
| Whole organism / immune system, not one trick | §§4, 10, 19–21: distinct layers with distinct failure modes. |
| Laya/System 1 protector | §10: NO_OBJECTION/REVIEW_REQUIRED/BLOCK/UNAVAILABLE; no permission issuance. |
| Tiny canonical effect language | §6: reuse the carried closed registry; explicit new envelope only where needed. |
| R1 key/proof-store separation | §§2, 7, 20, 22: source-present/default-off versus actual deployment. |
| R2 independent mint and reread | §7: immutable acquisition from authorized locators, not app testimony. |
| R3 display/signature/effect binding | §7: one contract and an explicit interpretation; no comprehension overclaim. |
| Gates on by default in sovereign mode | §20: refuse protected operation or enter clearly marked diagnostic mode. |
| Source/live/tip clock distinction | §§2, 20: source pin, artifact identity, observed runtime kept separate. |
| Seven words with anchor acronym/acrostic retained | §12: fixed structure, exact probability model. |
| Remove Nature/People/Spirit only | §§12, 24: full eligible initial buckets with measured distribution. |
| Silly local story as memory palace | §13: random-first local-only story, exact-sequence checks, evaluation. |
| Multilingual choice | §13: pack-specific normalization, initial rules, entropy, native-user testing. |
| Memorization versus paper/photos/notes/email | §§13–14: exposure risk versus entropy, explicit forgetting/recovery trade-offs. |
| Hidden scrambler / ordering / extra spin | §12: no double-counted order; an extra secret needs custody and recovery. |
| Random root and key hierarchy | §14: independent protection factors, weak-wrap correction, separate roles. |
| Phrase rotation changes the internal world | §§14–15: rotate intended factors/handles without destroying identity or old evidence. |
| Base-27, ternary, geometric map | §15: optional representation, not a cryptographic security claim. |
| Unique nodes and reduced monoculture | §15: independent keys/handles, common contracts, comparative tests. |
| Aura chain and independently checkable evidence | §§9, 16, 21: checkpoint scope, outcomes, restoration limits, independent consumers. |
| Humans vouching for one another | §§16–17: scoped introductions/continuity without personhood or transitive grants. |
| Anti-bot / manufactured-consensus resistance | §16: prevent evidentiary/authority laundering within defined contracts. |
| Training data and verified-information horizon | §16: provenance-aware datasets/retrieval; truth/consent/occurrence limits. |
| Nostr and node-to-node worlds | §17: existing transport/contact work, bilateral authorization and privacy. |
| Constitutional floor versus self-evolution | §§5, 18: protected predecessor-authorized change and revocation-safe reload. |
| Everything replaceable, including AUKORA | §§17, 23: portable exit and replacement enrollment for non-exportable keys. |
| Hostile tests and meaningful mutations | §21: bounded controlled fixtures, positive controls, no universal-safety inference. |
| Ten-year future available through foundations now | §§22–23: first three closure increments and durable contracts, not premature feature expansion. |

### 25.1 New integration coverage register

| Added concept | Specification treatment |
|---|---|
| Use NVIDIA's actual runtime rather than reinvent the OS sandbox | §§1.5, 20.5–20.6, 22: narrow adapter, preserved AUKORA broker. |
| Same UID / second account / namespace distinction | §20.7: principal reachability and failure domains, not a magic UID number. |
| Whole agent runtime and child tools inside the boundary | §§3.4, 4.5, 20.8–20.9; O03–O08. |
| Supervisor middleware before credentials | §20.11–20.13: real gRPC interface, final binding and asynchronous review. |
| Governance of gateway policy and provider changes | §20.14–20.15: exact route coverage, protected administration and active-state reconciliation. |
| Policy prover and maximum delegated boundary | §20.16: effective-policy refinement with explicit unsupported/inconclusive outcomes. |
| Defaults and blind inspection modes | §20.10 and §20.17: enforcing profile and traffic-specific coverage. |
| Hidden key versus unauthorized use of key | §20.12: account/operation binding and no Aumlok root as generic provider secret. |
| Middleware mutations versus approval bytes | §§6.7, 20.11–20.12: approved semantics and final non-mutating check. |
| Long-lived sessions and generation-aware revocation | §§5.6, 9.7, 20.13, 20.17; O21–O25. |
| Logs as provenance, not completed-effect proof | §§16.8, 20.19: observation classes and independent custody. |
| Sentry / BlueField optional hardening | §20.20: explicit evidence requirements; no unverified execution or hidden-reasoning guarantee. |
| Apache compatibility and retained AGPL responsibilities | §20.21: packaging/license review and narrow upstream integration. |
| Local story and private model context | §§11.5, 13.5: separated offline domain and privacy measurements. |
| Backend exit and future open-source progress | §§17.7, 18.6, 23.7: versioned qualification without vendor-owned identity. |

---

## 26. Sources and inspection scope

### 26.1 Source interpretation rules

Repository claims and source code are distinct. Where a function was read, the text says **SOURCE-INSPECTED**. Where only documentation describes a measurement, it says **REPOSITORY-REPORTED**. No statement in this document converts a passing historical court, a commit message, a source comment, or a file’s presence into a new live measurement.

The v0.1 baseline was a targeted architecture/source review covering the approval, admission, effect definition, activation, custody, composition, memory/provenance, and phrase paths cited below. Version 0.2 adds the explicitly scoped commit refresh and OpenShell research in §26.4. It was not an exhaustive code audit, mathematical proof review of Cordis, or live security assessment. Unseen local work and later commits may contain additional changes.

Proposed contracts and design deductions are identified as such. External standards below are supporting primary references, not claims that AUKORA already conforms to them.

### 26.2 Pinned AUKORA source register

Unless otherwise stated, every Genesis path below is pinned to:

`39a5da3f5190018fbcfc9e945506ba8de75f05e7`

| Ref | Source and inspected scope |
|---|---|
| G00 | GitHub `branches/main` metadata: resolved commit/tree, timestamp, and unsigned Git verification status. Remote read on 29 September 2026. |
| G01 | `README.md`, lines 1–160: limits, recorded release, reviewer-packet scope, components. |
| G02 | `docs/AUKORA-GOLDEN-BOUNDARY.md`, lines 1–145: Rev 2.4, two boundaries, reported runtime, future requirements. |
| G03 | `scripts/check.sh`, complete source: 26 registered commands and exit-code-based runner. |
| G04 | `scripts/aukora/self-change.mjs`, first 285 lines requested; visible returned prefix inspected: staging/approval/verification imports and flow, build and deployment limits. |
| G05 | `scripts/aumlok/dual-verify.mjs`, complete source: Node and Python acceptance required. |
| G06 | `scripts/aukora/decide.mjs`, lines 1–225: Ed25519 adapter, kernel mapping, one-use state, high-water witness, limitations. |
| G07 | `plugins/aukora-action-gate/lib/index.mjs`, lines 1–95: tool-runtime placement, imports, declared scope and limits. |
| G08 | `plugins/aukora-owner-daemon/lib/commit-bind-custody.mjs`, complete source: optional separate-UID assertions and test seams. |
| G09 | `scripts/owner/commit-ssh-airlock-bind.mjs`, complete source: proof-store path, test/spike mode, legacy stub, not-wired notice. |
| G10 | `plugins/aukora-composition-gate/GOVERNED.md`, complete document: admission scope and exclusions. |
| G11 | `plugins/aukora-kira/lib/consolidate.mjs`, visible returned source through the core-builder prefix: ancestry grouping, unknown handling, non-authority, immutable proposal identity. Full response output was truncated. |
| G12 | `plugins/aukora-box/PROVENANCE.md`, requested lines 1–110; header and visible path manifest: carried source/not-mounted statement and actual definition/activation paths. |
| G13 | `plugins/aukora-box/aukora/broker/effect-definition.mjs`, complete source: admissible and staged effect definitions. |
| G14 | `plugins/aukora-box/aukora/activation/statement.mjs`, lines 1–145: canonical activation fields and declared closure limits. |
| G15 | `plugins/aukora-kira/lib/partial-failure.mjs`, lines 1–170: in-process ledger, availability vocabulary, stop/ask/proceed. |
| G16 | `plugins/aukora-nostr/README.md`, lines 1–110: per-node bindings, peer contact pins, event identity, transport claims and ceilings. |
| G17 | `plugins/aukora-aumlok/lib/themed-entropy.mjs`, lines 1–110: actual theme constants, anchor structure, reported entropy, retired floor. |
| G18 | GitHub ruleset `24112583`, `main-protect`: active deletion/non-fast-forward/linear-history rules, no bypass actors in this returned ruleset. Remote configuration, not commit-pinned. |
| D01 | Deep `archive/research/THE-GOLDEN-BOUNDARY.md` at `c417f7c5752bf14b8e927986cd995f2e086f4189`: current read of lines 340–475, 540–685, 690–790, with earlier supplied passages used for §§2 and 4b.1. Especially matched controls, representation limits, and §4g.1 placement. |
| D02 | Deep `archive/research/UNOWNABLE-CORE.md` at the same pin: current read of lines 1–165 plus supplied §7 material. Invariants, object classes, no automatic authority, practical exit. |
| C01 | User-supplied Cordis paper: *A Programming Paradigm for Spatiotemporal Composability*, Yifan Shi, Wei Zhang, Tianyi Cui. Read as supplied Markdown, not as independently checked executable proofs. Relevant §§3.1–3.3, 4.3–4.4, 5.1–5.2, 6.1–6.7. |
| L01 | Laya README at `9d955671415fc19f069b9cc998928075c1f255ec`, lines 95–145, plus resolved branch metadata: documented 0.3.21 abstention and classifier contract. No model execution. |

### 26.3 External primary references

| Ref | Source | Used for |
|---|---|---|
| R01 | RFC 8785, *JSON Canonicalization Scheme (JCS)* | Canonical signed representations; limits of canonicalization. |
| R02 | RFC 9106, *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications* | Reviewed password-KDF direction and parameter measurement. |
| R03 | RFC 9807, *The OPAQUE Augmented Password-Authenticated Key Exchange Protocol* | A possible service-based password-authentication research option, not free entropy. |
| R04 | RFC 9449, *OAuth 2.0 Demonstrating Proof of Possession (DPoP)* | Distinction between bearer tokens and holder-bound use. |
| R05 | NIST SP 800-63B, current 800-63-4 publication site | Authentication factors, risk signals, authenticator lifecycle; not comprehension/personhood. |
| R06 | RFC 5869, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)* | Context-specific key derivation, not password entropy amplification. |
| R07 | W3C *PROV-DM: The PROV Data Model* | Entities, activities, agents, and derivation as a provenance interoperability reference. |
| R08 | C2PA Content Credentials Specification 2.4 | Adjacent content-provenance mechanisms and the provenance/truth distinction. |

External pages were consulted on 29 September 2026. The numbered RFCs identify fixed publications; site-hosted specifications may change. No standard certification, compatibility, or implementation audit is implied.

### 26.4 v0.2 source refresh and OpenShell research

All new reads below were made on 29 September 2026. AUKORA's current delta and OpenShell's main/release identities were retrieved independently. Existing G/D/C/L/R references remain the preserved v0.1 evidence basis unless explicitly supplemented here. No main-branch feature is assumed to exist in every v0.1.2 binary.

| Ref | Source / inspected scope |
|---|---|
| U00 | Genesis `branches/main` metadata: `289d2cebab92249639cd4dfcf7f9fa7539e4ff58`, tree `520f3eb7e1be208534402cab1002876b8034893c`, timestamp and commit-reported checks. |
| U01 | Genesis comparison `39a5da3...289d2ce`: six commits/eight paths; returned filename/stat inventory, not an independent execution of changes. |
| U02 | Genesis `scripts/check.sh` at `289d2ce...`, lines 98–145 plus U01 additions: current registration delta. |
| N00 | OpenShell `branches/main`: `1358941b818d4126a7374aaf5216d87fc960e122`, tree and timestamp. |
| N01 | `docs/about/architecture.mdx` at N00, lines 1–225: supervisor/workload split, drivers, generation and authenticated channel. Blob `4332a1fc5f72991330202c7e94b6f26114dd6f1e`. |
| N02 | `docs/security/best-practices.mdx` at N00, visible returned first 220 lines: enforcement defaults, namespace/identity controls, TLS, provider/SSRF rules, Landlock baseline and compatibility. Tail output truncated. |
| N03 | `docs/extensibility/supervisor-middleware/index.mdx` at N00, complete: interfaces and coverage limits. Blob `c17a79d252982daf116df778a1aada1ecda159bf`. |
| N04 | `docs/extensibility/supervisor-middleware/configure.mdx` at N00, complete: timeouts, registration, authentication, ordering and failure behavior. Blob `7ea8183af3e59ddd1fb8527458750fcf8d9eedae`. |
| N05 | `proto/supervisor_middleware.proto` at N00, lines 1–170: actual service/message contract and scoped inputs. Blob `52793d905f8fc38e605ea4a3d66fc3f5de8d8bd0`. |
| N06 | `docs/extensibility/gateway-interceptors.mdx` at N00, complete: pre-handler phases, binding policy, immutable registration, missing method-specific current state, post-commit limitations. Blob `20600fabf63c3ccf06950f8e90ee0ccd9c51bad0`. |
| N07 | `crates/openshell-gateway-interceptors/src/routes.rs` at N00, complete: explicit interceptable unary-method list and classification tests, inspected but not run. Blob `c47f42e40d22b6709f92044aa9a1005246168310`. |
| N08 | `docs/how-it-works/policies/prover.mdx` at N00, lines 1–205, plus official rendered page for remaining coverage limitations: modeled refinement, effective providers, result vocabulary and unsupported cases. Blob `95b48dcf1525b06de72c23f63ec8c99c94be3bb8`. |
| N09 | `docs/extensibility/supervisor-middleware/operations.mdx` at N00, lines 1–145: operation phases, sandbox ID, omitted headers, ordered mutations, response limitations. Blob `50a01b33f9489a559c411a312fc520ae58cd09cd`. |
| N10 | Official OpenShell Support Matrix, latest site identifying v0.1.2: platform/runtime requirements. Dynamic documentation, not a local qualification result. |
| N11 | Official OpenShell Telemetry page: scope, runtime opt-out and compile-time option. Dynamic documentation, not a packet capture. |
| N12 | GitHub latest-release metadata: v0.1.2, published `2026-09-28T03:58:00Z`; release assets not downloaded or tested. |
| N13 | `git/ref/tags/v0.1.2`: tag resolves to commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` at this read. |
| N14 | NVIDIA official article, *AI Security for the Agent Stack*, 21 September 2026: separating agent access requests from authority and the role of runtime enforcement. Used to avoid a false exclusivity claim. |
| R09 | RFC 9334, *Remote ATtestation procedureS (RATS) Architecture*: evidence, appraisal and relying-party distinctions for optional hardware research. |
| R10 | Apache License 2.0, official text: permissions, redistribution conditions, patent/trademark and warranty provisions. |
| R11 | Apache Software Foundation, *Apache License v2.0 and GPL Compatibility*: GPLv3 compatibility direction; not a bespoke legal opinion on the AUKORA distribution. |

**Source disagreement / incomplete verification:** The inspected architecture describes a network-off workload connected through a protected supervisor channel; the security guide also retains a proxy/veth description. This document does not assume those topology descriptions are interchangeable. The selected artifact and driver's measured behavior must determine the qualified deployment. Sentry-specific deployment APIs and attestation guarantees were not verified; §20.20 deliberately remains a research profile.

**No new operational changes:** The revision produced a local document only. No software installation, owner-account creation, runtime launch, policy change, key operation, model training or repository mutation was performed. All B/O tests are proposed; upstream reports are not recast as author-executed evidence.

### 26.5 Reference links

[G00]: https://api.github.com/repos/aumara-xyz/aukora-genesis/branches/main
[G01]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/README.md
[G02]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/docs/AUKORA-GOLDEN-BOUNDARY.md
[G03]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/scripts/check.sh
[G04]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/scripts/aukora/self-change.mjs
[G05]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/scripts/aumlok/dual-verify.mjs
[G06]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/scripts/aukora/decide.mjs
[G07]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-action-gate/lib/index.mjs
[G08]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-owner-daemon/lib/commit-bind-custody.mjs
[G09]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/scripts/owner/commit-ssh-airlock-bind.mjs
[G10]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-composition-gate/GOVERNED.md
[G11]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-kira/lib/consolidate.mjs
[G12]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-box/PROVENANCE.md
[G13]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-box/aukora/broker/effect-definition.mjs
[G14]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-box/aukora/activation/statement.mjs
[G15]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-kira/lib/partial-failure.mjs
[G16]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-nostr/README.md
[G17]: https://github.com/aumara-xyz/aukora-genesis/blob/39a5da3f5190018fbcfc9e945506ba8de75f05e7/plugins/aukora-aumlok/lib/themed-entropy.mjs
[G18]: https://api.github.com/repos/aumara-xyz/aukora-genesis/rulesets/24112583
[D01]: https://github.com/aumara-xyz/aukora-deep/blob/c417f7c5752bf14b8e927986cd995f2e086f4189/archive/research/THE-GOLDEN-BOUNDARY.md
[D02]: https://github.com/aumara-xyz/aukora-deep/blob/c417f7c5752bf14b8e927986cd995f2e086f4189/archive/research/UNOWNABLE-CORE.md
[C01]: #26-sources-and-inspection-scope
[L01]: https://github.com/NandhaKishorM/laya/blob/9d955671415fc19f069b9cc998928075c1f255ec/README.md
[R01]: https://www.rfc-editor.org/rfc/rfc8785.html
[R02]: https://www.rfc-editor.org/rfc/rfc9106.html
[R03]: https://www.rfc-editor.org/rfc/rfc9807.html
[R04]: https://www.rfc-editor.org/rfc/rfc9449.html
[R05]: https://pages.nist.gov/800-63-4/sp800-63b.html
[R06]: https://www.rfc-editor.org/rfc/rfc5869.html
[R07]: https://www.w3.org/TR/prov-dm/
[R08]: https://spec.c2pa.org/specifications/specifications/2.4/specs/ContentCredentials.html

[U00]: https://github.com/aumara-xyz/aukora-genesis/commit/289d2cebab92249639cd4dfcf7f9fa7539e4ff58
[U01]: https://github.com/aumara-xyz/aukora-genesis/compare/39a5da3f5190018fbcfc9e945506ba8de75f05e7...289d2cebab92249639cd4dfcf7f9fa7539e4ff58
[U02]: https://github.com/aumara-xyz/aukora-genesis/blob/289d2cebab92249639cd4dfcf7f9fa7539e4ff58/scripts/check.sh
[N00]: https://github.com/NVIDIA/OpenShell/commit/1358941b818d4126a7374aaf5216d87fc960e122
[N01]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/about/architecture.mdx
[N02]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/security/best-practices.mdx
[N03]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/extensibility/supervisor-middleware/index.mdx
[N04]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/extensibility/supervisor-middleware/configure.mdx
[N05]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/proto/supervisor_middleware.proto
[N06]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/extensibility/gateway-interceptors.mdx
[N07]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/crates/openshell-gateway-interceptors/src/routes.rs
[N08]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/how-it-works/policies/prover.mdx
[N09]: https://github.com/NVIDIA/OpenShell/blob/1358941b818d4126a7374aaf5216d87fc960e122/docs/extensibility/supervisor-middleware/operations.mdx
[N10]: https://docs.nvidia.com/openshell/latest/about/support-matrix
[N11]: https://docs.nvidia.com/openshell/latest/observability/telemetry
[N12]: https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.2
[N13]: https://api.github.com/repos/NVIDIA/OpenShell/git/ref/tags/v0.1.2
[N14]: https://blogs.nvidia.com/blog/ai-security-agent-stack/
[R09]: https://www.rfc-editor.org/rfc/rfc9334.html
[R10]: https://www.apache.org/licenses/LICENSE-2.0
[R11]: https://www.apache.org/licenses/GPL-compatibility.html

---

## Final technical position

The direction is a **sovereign composable runtime**: a protected authority and continuity foundation supporting a changing graph of models, memory systems, applications, interfaces, and peers.

The breakthrough is the placement and separation of responsibilities, not the invention of a secret encoding or a claim that another model can guarantee safety. The first proof obligation is small and concrete: a useful proposal worker, a valid authorized operation, a real protected target, and no alternate route that turns the worker’s intelligence into authority.

OpenShell may accelerate the containment part of that path. The integration succeeds only when the backend's effective policy, its administration, the person's exact authorization and the observed effect form a measured contract. It does not remove the need for custody, recovery, trustworthy review, privacy or independent evidence.

**Reuse the strongest available infrastructure. Keep the authority contract independent. Build the complete narrow path, preserve the person's control through failure and change, and let everything else become more capable above it.**
