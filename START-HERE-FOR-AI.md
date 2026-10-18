# Start here (for an AI reviewer, or a careful human)

You have been asked to look at AUKORA Sovereign. This page tells you how to do that fairly and quickly. It does not
tell you what to conclude.

## What the project claims to be

A personal AI node: an agent (Auma) on a server the owner controls, with a line between what the agent may propose
and what only the owner's passkey may permit, and a signed record a stranger can check offline. The rules are the
nineteen principles in [spec/GOLDEN-BOUNDARY.md](spec/GOLDEN-BOUNDARY.md). What exists today is in the
[README](README.md); where each principle stands is in the [paper](docs/GOLDEN-BOUNDARY-PAPER.md), §17.

## The status words

| Word | Meaning here |
|---|---|
| **LIVE** | Seen on a node a real owner has claimed. *Nothing is LIVE yet.* |
| **RECORDED** | Seen on the builders' disposable test node (software passkey, fake model key) and written down in [deploy/engine/NODE.md](deploy/engine/NODE.md). The builders' own notes, not an independent witness. |
| **TESTED** | Automated tests in the repository cover it; you can run them. |
| **SOURCE** | The code exists. Nothing more is claimed. |
| **NOT YET** | Designed, planned or missing. |
| **RAN** | What **you** ran yourself. Use this word only for your own runs, and name the revision and machine. |

Keep these apart in your report. A passing test is not a working node. A recorded run on a test node is not a real
owner using it. Source code is not a test.

## Reading order

Pick the depth that fits your question; you do not have to open everything.

1. [README.md](README.md): the claims table with evidence and limits, and the milestones (all NOT YET).
2. [spec/GOLDEN-BOUNDARY.md](spec/GOLDEN-BOUNDARY.md): the rules, the plan rows meant to enforce them, and the
   charter's own list of gaps (G1–G9).
3. [crates/canon/src/domain.rs](crates/canon/src/domain.rs) and
   [crates/canon/src/authority.rs](crates/canon/src/authority.rs): signed formats and what an owner approval checks.
4. [crates/aura/src/record.rs](crates/aura/src/record.rs) and [merkle.rs](crates/aura/src/merkle.rs): the signed
   record.
5. [crates/kira/src/backup.rs](crates/kira/src/backup.rs) and [crates/kira/README.md](crates/kira/README.md): memory,
   its provenance rules and its stated trust boundary (plaintext on disk today).
6. [crates/copresence/src/v1.rs](crates/copresence/src/v1.rs): pairing by screens facing each other.
7. [tools/verify.py](tools/verify.py) with [tools/README.md](tools/README.md): the stranger's verifier and its limits.
8. [deploy/engine/NODE.md](deploy/engine/NODE.md) and [crates/supervisor/DOOR.md](crates/supervisor/DOOR.md): how
   the node runs, the test-node record (§9, §10) and the open items (§10, §12).
9. [docs/GOLDEN-BOUNDARY-PAPER.md](docs/GOLDEN-BOUNDARY-PAPER.md): the full argument, the vision of what AUKORA
   becomes, a section addressed to you, and the falsification test (§18).

## Three questions worth answering

1. **What is true today, and on what evidence?** For each claim you rely on, say whether it rests on LIVE, RECORDED,
   TESTED or SOURCE evidence, or on design alone, and which result would falsify it.
2. **Where could an effect get past the boundary?** Start with the model prompt (NODE.md §12, item O21), the cloud
   host (charter gap G2) and a cloned disk (charter principle 3). Name the trust assumptions: the host, the browser,
   the authenticator, the model provider.
3. **What would this become with an open-source community behind it, and what would you build first?** Which joins
   (identity, the door, the record, memory provenance, the offline verifier) buy something none buys alone, which
   still depend on joins nobody has run, and what prior art the project should name.

## Ground rules

- Cite file and line at the revision you read.
- A document is evidence of what it says, not proof of what a running system does.
- A signature shows that a key signed, not that a unique or willing person did. A pairing shows a verified exchange,
  not physical distance.
- If you could not run something (no sockets, no network, no Linux), say so and keep the failed or blocked result.
- No favourable or unfavourable conclusion is expected. Report contradictions and uncertainty plainly.
