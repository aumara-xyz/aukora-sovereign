# AUKORA Sovereign

## Imagine if Linux and Bitcoin had a baby

**From Bitcoin it gets self-custody and a record anyone can check.** Your keys stay in your hands (a passkey on your
own device and seven words you wrote down), and every decision is written into a signed, append-only ledger that a
stranger can verify offline without trusting you, us, or the server.

**From Linux it gets an open base you run yourself.** The code is AGPL-3.0, it runs on a machine you control, and
anyone can read it, change it and build on it.

**The child is a personal AI that cannot act without your provable approval.** The agent can think, remember and
propose, even changes to itself, but anything that crosses its walls waits for your passkey, over the exact bytes
you saw, once, with a receipt. There is no coin.

Like Bitcoin, almost none of the parts are new. Hashes, signatures, Merkle trees and proof of work all existed before
2009; the invention was putting them together so the whole thing worked without anyone's permission. AUKORA does the
same with passkeys, a signed ledger, a sandbox with a single door, memory that cites its sources, and Nostr for
finding each other: existing open technology, combined into the trust layer for the agentic age.

AUKORA Sovereign is a personal AI node: a server you control, an AI agent (Auma) that lives on it, and a hard line
between what that agent may **propose** and what only you may **permit**. Auma can read, write, remember and suggest
changes to herself, but a reach outside her walls, a release upgrade or a new plugin waits for a card you approve with
your passkey, and the approval leaves a signed record that a stranger can check offline. That is the design goal; this
page says plainly how much of it works today and points to the evidence for every claim.

**Short version.** The parts are built and tested in this repository. A disposable test node has run the install, the
passkey binding, the approval cards, upgrades and a refused rollback. **No owner has yet claimed a real node, and Auma
has not yet answered with a real model key.** All eight milestones below are still open.

## What it becomes, with a community

The rules are written for a future bigger than one team can build:

- **Every person holds their own AI node**, at first on a rented server, later on a box at home or hardware they can
  inspect.
- **The keys stay in their hands:** a passkey on their own device and seven words they wrote down. No company,
  founder, host or model can approve in their place or lock them out.
- **Every action leaves a receipt** that a stranger can verify offline, without trusting the operator's story.
- **Memory is theirs and cites its sources:** who said what, what contradicts it, and repetition never counted as
  evidence.
- **Agents propose and never permit**, however capable they become, and that includes changes to themselves.
- **Nodes find each other over Nostr:** people invite people, pair devices with screens facing each other, and talk
  over relays anyone can run.
- **The walls hold for any model and any harness**, local or remote, open or closed.
- **A community extends it organ by organ:** identity, record, memory, door, gate, verifier, relays and apps are
  separate pieces with written contracts, so you can improve one without being trusted with all.

None of that is a claim about today; the table further down is. The long-form paper describes the vision in full,
and its prologue lists what you could build first.

## A reading path

1. This README: what is true today, with evidence and limits.
2. [spec/GOLDEN-BOUNDARY.md](spec/GOLDEN-BOUNDARY.md): the charter. Nineteen rules, the plan rows meant to enforce
   each, and the gaps nobody has scheduled yet.
3. [crates/canon/src/domain.rs](crates/canon/src/domain.rs): every signed format has its own domain tag, so bytes
   signed for one purpose cannot be replayed as another.
4. [crates/canon/src/authority.rs](crates/canon/src/authority.rs): what an owner's passkey approval actually checks.
5. [crates/aura/src/record.rs](crates/aura/src/record.rs) and [merkle.rs](crates/aura/src/merkle.rs): the signed,
   append-only record (an RFC 6962 Merkle tree).
6. [crates/kira/src/backup.rs](crates/kira/src/backup.rs) and [crates/kira/README.md](crates/kira/README.md): memory,
   its provenance rules and its stated trust boundary.
7. [crates/copresence/src/v1.rs](crates/copresence/src/v1.rs): pairing by two screens facing each other.
8. [tools/verify.py](tools/verify.py) with [tools/README.md](tools/README.md): the stranger's verifier, one file.
9. [deploy/engine/NODE.md](deploy/engine/NODE.md) and [crates/supervisor/DOOR.md](crates/supervisor/DOOR.md): how the
   node runs, the test-node record (§9, §10) and the open items (§10, §12).
10. [docs/GOLDEN-BOUNDARY-PAPER.md](docs/GOLDEN-BOUNDARY-PAPER.md): the long-form white paper, the full argument
    and the vision, with a status line on every claim about today.
11. And back to the charter, [spec/GOLDEN-BOUNDARY.md](spec/GOLDEN-BOUNDARY.md), which is what every change answers to.

## Verify the claims yourself

From a clean checkout with Rust (the runbook pins 1.99.1), Python 3.9 or later and the locked dependencies fetched
(`cargo fetch --locked`):

```sh
bash scripts/check.sh                      # machine rules, deploy tests, verifier vectors (Rust and Python), compiler walls
cargo test --offline -p kira               # memory
cargo test --offline -p supervisor door    # the door
cargo test --offline -p supervisor pairing # co-presence pairing
bash scripts/reproduce.sh build "$(git rev-parse HEAD)" ../reproduce-out --twice   # pristine rebuild, byte-compared
```

`scripts/check.sh` is construction, not acceptance: it does not install a node. Some supervisor tests need Unix
sockets and fail in sandboxes that forbid them; keep that result rather than calling it a pass.

To check an exported record, copy only `tools/verify.py` into an empty folder (it needs PyNaCl, and coincurve and
cryptography for some evidence kinds, already installed) and run:

```sh
python3 -B verify.py --bundle export.json --key owner-key.hex --checkpoint retained-head.json
```

Add `--owner-key PIN.hex` to check owner passkey signatures. A `VERIFIED` result covers what
[tools/README.md](tools/README.md) lists and nothing more; it does not show that an effect happened in the world.

## Where it stands

Every claim carries one of these words.

| Word | Means | Does not mean |
|---|---|---|
| **LIVE** | Seen working on a node a real owner has claimed. | *Nothing is LIVE yet.* |
| **RECORDED** | Seen on the builders' disposable test node (software passkey, fake model key) and written down with commands and output in [NODE.md](deploy/engine/NODE.md) §9–§10. | An independent witness, a real owner or a real model. |
| **TESTED** | Automated tests in this repository exercise it; you can run them. | That the joined system does it on a node. |
| **SOURCE** | The code or format exists at this revision. | That it runs, or that it is wired into the node. |
| **NOT YET** | Designed, planned or missing. | — |
| **RAN** | Reserved for what *you* ran yourself while reviewing. | Anything the builders did. |

| Claim | Status | Evidence | Limit |
|---|---|---|---|
| The eight milestones | **NOT YET** | Table below | Only the project lead marks a milestone done, after a run on an installed node. |
| One cloud VM runs the authority (Rust), the memory service and the agent engine; the engine sits in an OpenShell sandbox whose only ways out are the door and the model broker | **RECORDED** | NODE.md §1, §4, §9 | Disposable test node; CPU, memory and process caps are recorded in NODE.md §12 P2. |
| The engine starts only after the owner binds a passkey, approves the running release and approves the exact plugin set | **RECORDED** | NODE.md §2 and §10, item O11 | Software passkey on the test node. |
| Fetching the web goes through the door: an allowlisted site raises a card, others are refused | **RECORDED**, **TESTED** | NODE.md §10, item O10; [DOOR.md](crates/supervisor/DOOR.md); `cargo test -p supervisor door` | Only network and memory crossings have executors. |
| Owner-approved upgrade; a decline sticks; restoring an older release floor is refused | **RECORDED** | NODE.md §10, items O17, O19, B30 | A copied whole disk is not defended yet (charter principle 3). |
| An approval covers exact bytes, once | **SOURCE**, **TESTED** | [authority.rs](crates/canon/src/authority.rs) around line 405 (challenge = SHA-256 over a domain tag and the canonical authorization); the gate's single-use nonce | A signature shows that a passkey signed, not who pressed it or that they understood. |
| A stranger can check the record from an empty folder | **TESTED** | [tools/verify.py](tools/verify.py), [tools/README.md](tools/README.md); vectors replayed by `scripts/check.sh` | Needs a key and a checkpoint kept independently. Some record kinds cannot be `VERIFIED` yet; grant scope, count and revocation are not checked. |
| The model key stays outside the agent's sandbox | **RECORDED** | NODE.md §7, §9 (a call reached the provider through the broker with a fake key, and was refused) | **What the agent reads can still leave in its prompts** (NODE.md §12, item O21: a design note, not a fix). Engine-served script can draw a lookalike key form; a key typed there is exposed to the engine (NODE.md §7). |
| Memory (Kira 2) keeps sources and corrections; repetition does not count as support | **TESTED** | [crates/kira/README.md](crates/kira/README.md); `cargo test -p kira` | Today's memory is plaintext on the node's disk; sealed memory is NOT YET. |
| Phone pairing by screens facing each other (co-presence) | **SOURCE**, **TESTED** | [crates/copresence](crates/copresence/README.md); `cargo test -p supervisor pairing` | The full phone ceremony on a node is NOT YET. Pairing is evidence, never proof of distance or permission. |
| Two nodes talk over public Nostr relays | **SOURCE**, **TESTED**; two-node run **NOT YET** | Supervisor and Messages face wiring: [MESSAGING.md](deploy/MESSAGING.md), [crates/messaging](crates/messaging/README.md), [crates/relay](crates/relay/README.md) | No node-to-node message has been recorded. |
| Recovery after losing every device; leaving with your data | **NOT YET** | Charter principles 12 and 15; gaps G3, G4 | — |
| Reproducible builds | **RECORDED** for the plugin bundle; **SOURCE** for releases | NODE.md §3 (two builds, same SHA-256); `scripts/reproduce.sh` | No independent second rebuild yet (gap G7). |

### Milestones (only the project lead says "done")

| | Milestone | State |
|---|---|---|
| M1 | A fresh node: one link, the whole Spatial app, claimed with passkey and phrase | NOT YET |
| M2 | Auma answers with a real model; the cage holds | NOT YET |
| M3 | She proposes a change to herself; Laya, passkey, WASM core; applied once | NOT YET |
| M4 | She remembers after a real reboot; spent approvals stay spent | NOT YET |
| M5 | A stranger verifies everything; Aura Coherence shows the health map | NOT YET |
| M6 | Two nodes talk over public Nostr relays | NOT YET |
| M7 | Go Sovereign: an invite, co-presence, a friend's own node | NOT YET |
| M8 | Home base: a website on request; an app from the store | NOT YET |

## Run it

**There is no one-command demo yet.** A node today needs a cloud VM, a separate Linux build machine for the engine
artifacts and an operator following the runbook in [NODE.md](deploy/engine/NODE.md) §8 step by step; spawning is
described in [deploy/README.md](deploy/README.md). After install, [tests/e2e/](tests/e2e/README.md) holds the guided
milestone runs, which need a real owner's passkey actions. A local demo is planned work. Hosting and model calls cost
money and are separate from the software licence.

## For an AI reader

Follow the question you were asked. Trace every claim here to a file, a test or a dated record in this repository,
and name the revision you read. Say what you ran yourself (RAN) and what you could not run. RECORDED entries are the
builders' own notes from a test node, not independent proof. A signature shows that a key signed, not that a unique or
willing person did. No conclusion, favourable or not, is expected. [START-HERE-FOR-AI.md](START-HERE-FOR-AI.md) has
the reading order and three questions worth answering; the [paper](docs/GOLDEN-BOUNDARY-PAPER.md) has a section
addressed to you.

## How to contribute

- **Start from the charter.** Every change answers to [spec/GOLDEN-BOUNDARY.md](spec/GOLDEN-BOUNDARY.md). Its gaps
  (G1–G9) are the best places to begin: a second verifier, a ciphertext mirror, a loss drill, a hostile test per
  principle, a self-hosting path.
- **Open an issue first** for anything larger than a fix. The plan's rows in [NORTH-STAR.md](NORTH-STAR.md) are
  numbered by issue.
- **Run `bash scripts/check.sh`** and the tests of the crates you touched before you open a pull request.
- **Keep to the machine rules** that `checks/run.py` enforces: authored files stay under 1,000 lines; pinned data in
  `checks/pins.json` is never edited without updating its pin and saying why; each crate's README says what it may
  depend on; external crates only from `checks/deps.json`; no absolute paths.
- **Headers:** new source files carry `SPDX-License-Identifier: AGPL-3.0-or-later` and the copyright line used across
  the repository.
- **Security problems:** report them privately (a GitHub security advisory on this repository, or email
  peter@aumara.xyz), not in a public issue.

Contact: peter@aumara.xyz · [aukora.xyz](https://aukora.xyz)

Contributions are made under the same licence as the project, AGPL-3.0-or-later.

## Licence

AUKORA Sovereign's own files are licensed under the GNU Affero General Public License, version 3 or (at your option)
any later version ([LICENSE](LICENSE)). You may run, study, change and share it; if you run a changed version for
other people over a network, you must offer them its source. Vendored components keep their own licences: see
[NOTICE](NOTICE). Patent applications covering parts of this work are described in [PATENTS.md](PATENTS.md).

---

## For builders of this repository

**The plan is [NORTH-STAR.md](NORTH-STAR.md), the only plan.** Row number = GitHub issue number. **The charter is
[spec/GOLDEN-BOUNDARY.md](spec/GOLDEN-BOUNDARY.md)**: the Golden Boundary and the Unownable Core, which every row
answers to. AUKORA Light carries the same file, byte for byte.

### How it is built
- **Reuse is explicit.** Stock apps are vendored verbatim from AUKORA Prime with their provenance; data comes over as
  it is, pinned by hash in `checks/pins.json`; everything else is written fresh for this repository.
- **Code goes to main, and main is tested after it lands:** on a fresh node, then attacked by independent AI
  reviewers.
- **Every change takes the same path:** it lands on main once it compiles and passes the construction checks; two
  model families review it on main; a failed review becomes a fix that lands the same way.

### Checks
`scripts/check.sh` runs the machine rules (`checks/run.py`), the deploy and wall tests, the verifier build and its
vector replay in Rust and Python, then clippy over the workspace with each crate's disallowed types and methods as
errors. `python3 -B checks/run.py --pre-push` adds the publication audit of commit metadata.

### Ideas
New ideas go here, each with one question to the project lead: "switch target or park it?"
