# AUKORA Sovereign — master plan v0.2

**Status:** approved by Peter ("time to rock", 2026-10-14). Nothing is built yet.
- v0.2 folds in the crew review (Grok, Kimi, Mistral/GLM, Aragon/Gemini, Dot) and facts measured on the Nebius host.
- The carry list (`plan/CARRY-LIST.md`) is the inventory. This document is how it fits together and the order of the build.
- aukora-prime @de410bb is the reference. Its gate scenarios, attack corpus and verifier vectors are acceptance where they apply. **A case Prime refuses and Sovereign accepts is a blocker.**

## 1. What it is
A sovereign node is an AI agent (Auma) that lives in the cloud, belongs to one person, and can never act past that person.
- The agent runs locked inside an operating-system sandbox. It can only propose.
- One trusted program, the supervisor, holds every authority:
  - It shows the owner the exact change.
  - It applies the change once after a passkey approval.
  - It writes everything to one signed record (Aura) that a stranger can verify without trusting the node.
- Memory (Kira) is encrypted and recorded. Identity (Aumlok) is an acrostic seven-word phrase plus a passkey.
- The owner uses a normal browser. Later: the Mac app, phone and glasses.
- One command creates a node on Nebius.

## 2. Processes, users, descriptors (the authoritative matrix)

| Process | Host user | Holds | Talks to |
|---|---|---|---|
| `sovereign` supervisor (Rust): front door, gate, aumlok, aura, kira, broker, floor | `aukora` (non-root, systemd unit, `Delegate=yes`) | node key, SQLite DB, envelopes, model key | browser over TLS; guest over FD 3 and FD 4 |
| launcher (code inside `sovereign`, runs in the forked child before exec) | maps guest root to a subordinate uid via `newuidmap` | nothing after exec | — |
| agent runtime (DeepSeek harness/Cordis, Node) | subordinate uid (e.g. 100000), inside a user namespace | nothing | FD 3 and FD 4 only |

**One trusted-process boundary.** Gate, aumlok, aura, kira and broker live in one supervisor process under one uid. This is accepted and stated. Per-organ uids are [L].

**The guest's uid is a different host uid** (subordinate range), so a broken mount or Landlock rule still meets file-permission denial.

**Child setup, in this order, in the same child that execs (no fork between):**
1. `clone3` with new user, mount, pid, net, ipc, uts and cgroup namespaces; `newuidmap` maps a single id; `setgroups=deny`.
2. Mounts:
   - every mount made private
   - a fresh tmpfs root
   - `/usr` bound read-only, and the workspace read-write
   - `.git` bound onto itself, then remounted `ro,nosuid,nodev,noexec`
   - a fresh `/proc` with `hidepid=2`, a minimal `/dev`, and a private `/tmp`
   - `pivot_root`, then the old root is detached
3. The network namespace has only `lo`, left down. There is no veth.
4. rlimits (NOFILE 1024, CORE 0). Node needs descriptors for sessions, tabs and sockets; 64 was too low. The cgroup is set from the delegated subtree before start: `pids.max`, `memory.max`, `memory.swap.max=0`, `cpu.max`.
5. `no_new_privs`. All capabilities dropped (bounding and ambient).
6. **Landlock.** Read-only for `/usr`, `/proc` (the guest's own) and the harness tree. Read-only for `.git`. Device access only to `/dev/null`, `/dev/zero`, `/dev/urandom`. Read-write for the workspace and `/tmp`. TCP bind and connect denied. Device ioctl denied where ABI 5 allows it.
   - Refuse to start below ABI 4.
   - **Measured on the Nebius host: kernel 6.11.0-1016-nvidia, Landlock ABI 5**, `apparmor_restrict_unprivileged_userns=0`, cgroup v2 with all controllers. Unprivileged user, net and mount namespaces work, even inside an LXD container.
   - Abstract unix sockets are per network namespace. The private network namespace is load-bearing for that, so it is tested.
7. **seccomp allowlist, installed last, just before exec.**
   - Kills x32 and foreign-architecture calls.
   - Denies ptrace, process_vm_*, mount, umount2, pivot_root, unshare, setns, bpf, perf_event_open, keyctl and add_key, userfaultfd, io_uring_*, open_by_handle_at, kexec_*, init_module and finit_module, personality.
   - `clone` with namespace flags is denied.
   - `clone3` returns ENOSYS: seccomp cannot inspect its flags, and glibc then falls back to `clone` for threads.
   - `socket()` is allowed for AF_UNIX only. Other families return EPERM, not a kill, so DNS and connect fail cleanly inside Node.
8. `dup3` the proposal socket onto **FD 3** and the UI listener onto **FD 4**, `close_range(5, ~0U, 0)` (refuse to start if it fails), stdio to `/dev/null` or a log pipe, then `execve`.

**FD 3** is an AF_UNIX `SOCK_STREAM` socketpair.
- Each frame is a 4-byte length plus one canonical JSON object of at most 64 KiB (CONTRACTS C4).
- SEQPACKET was dropped because Node cannot read it.
- The supervisor refuses anything it does not fully recognise before interpreting it.
- It carries proposals, model calls and memory calls.
- **FD 3 is the only authority channel.**

**FD 4** is an AF_UNIX `SOCK_STREAM` listening socket bound by the supervisor on the host. The guest may only `accept` on it. It carries the chat UI and nothing else.
- The front door proxies it only on the **chat hostname**.
- It never forwards owner cookies. It never proxies or serves an owner route from FD 4.
- Chat pages get CSP `default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'`.
  - The harness boots with an inline script.
  - The chat origin is untrusted by design and isolated from the owner origin. That isolation is the defence, not CSP.

**Hostnames:** `chat-<node>` (chat) and `owner-<node>` (claim, binding, approvals, Aura, memory). These are separate origins with host-only `__Host-` cookies. The approval page is never framed.

**Boot record:** the supervisor writes kernel version, Landlock ABI, sysctls and the seccomp filter hash into Aura at every boot, and refuses to start if they mismatch what it expects.

**Startup self-test:**
- The guest cannot `open(2)` any key, database or socket path, and cannot connect out.
- Killing the supervisor kills the agent within 1 s. The agent is in a cgroup the supervisor owns and is killed with it.

**Broker:** model calls leave only through the broker.
- The owner's OpenRouter key is entered through an owner-approved one-time ticket. Only the broker can read it.
- It never enters model context or logs.
- A "print your key" injection test is part of the finish line.
- A key-generation bump kills in-flight calls.

## 3. One record (Aura)
- **One SQLite table (WAL, `synchronous=FULL`) for every organ.** There is no other journal file.
  - Row kinds are named per operation: intent and settlement obligations, with **exactly one terminal result per operation**.
  - A coverage check enumerates every authority entry point and every effect route. A route with zero or two terminal rows fails.
- **Canonical JSON (one implementation, shared by Rust and the JS bridge):**
  - Sorted keys, no whitespace, UTF-8.
  - Integers only, between −(2^53−1) and 2^53−1. No floats.
  - Strings must be valid Unicode (no lone surrogates). Duplicate keys are refused.
  - Golden vectors are shared with Prime's `aukora:aura-record:v1`.
- **Two arms, compatible with `vendor/append-only/verify.py`:**
  - the `aukora:aura-record:v1` hash chain (`prev`, `sequence`, `at`, `kind`, `actor`, `body`, `domain`)
  - RFC 6962 leaves `SHA256(0x00 || entry_hash)` with nodes `SHA256(0x01 || l || r)`
  - The node key (Ed25519) signs every entry hash.
- **Export:** retained and presented heads with `proofFromPrevious`. At a power-of-two retained size it adds `nextIndex`, `nextLeafHash` and an inclusion proof. **Vectors at 1, 2, 4, 8, 16 and 32 are required tests.**
- **Completeness:** without an independent covering checkpoint, completeness is reported as UNCHECKED. A valid earlier prefix cannot reveal what is missing after it.
- **External witness [1]:** the owner's browser keeps the last signed head it saw (on the owner origin) and raises a rollback or fork alarm on every visit. The owner can download a retained head. drand gives time only, not publication. Public witnesses come later.
- **Pentora:** `SHA256("pentora.display.v1" || 0x00 || root)` gives 110 trits (integers, so identical on every device). The geometry is display only. Trits are compared, never pixels.
- **No legacy receipts.** Schema v1 carries only the owner-authorization (v3) layout. There is never an import path from Prime ledgers or Prime's v2-HMAC receipts.

## 4. Gate, floor and spend (state machines, invariants copied from Prime)
- **Proposal states:** `pending → (review challenge live) → applying → applied | incomplete | failed | conflict`, plus `refused | expired | retired`.
  - **These terminal states are final:**
    - bytes present but no receipt → `incomplete`. Never fabricated, never retried.
    - base still present → `failed`, spent, never re-applied.
    - neither → `conflict`, needs owner reconciliation.
  - **Unknown is never retried.**
- **Consume:** one `BEGIN IMMEDIATE` transaction does all of the following:
  - challenge live→spent
  - proposal pending→applying (compare-and-set on both rows)
  - ledger row appended
  - passkey counter compare-and-set, only when non-zero
  - any error inside the transaction burns the challenge
- **Before writing:** re-read the target. If it changed since the spend, refuse.
- **Recovery sweep at start:** runs under the same writer lock and is idempotent.
- **Retire (Prime #7, I1–I9):** owner passkey over `{operation_id, digest, "retire"}`. Idempotent. The old id and idempotency key are burned. An unknown outcome is never retirable.
- **Three-valued decision:** Deny / Unknown / Allow. Unknown never becomes Allow.
- **Durable ceremonies:** enrolment and sign-in states live in SQLite, with triggers that forbid rewinding or unspending.
- **Passkey counter rule (Prime's, exactly):**
  - A counter of 0 is valid while the stored counter is 0 (counterless or synced authenticators).
  - Once a non-zero counter is stored, the presented counter must be strictly greater. A presented 0 is then refused.
  - Replay protection rests on the single-use challenge, never on the counter.
- **Release floor:** copy `release-floor.mjs` semantics verbatim.
  - Ordered by `(signer_epoch, ledger_seq)`, never timestamps.
  - `equal-conflict` and `install-incomplete` refusals.
  - Root-owned path walk: no symlinks, `nlink==1`.
  - Lock with no stealing, plus an operator `reconcile-lock` command.
  - The supervisor checks the floor itself at start.
- **High-water marks:** used keys, highest epoch and the consumed set are held outside writable state. Restore or rollback cannot revive a spent approval.
- **Spend grant:**
  - A passkey-signed grant binds provider, model, price basis, total cap, per-request cap, maximum requests, expiry of 24 h or less, and a nonce.
  - Before dispatch, reserve a defensible maximum: prompt plus max-output tokens at the provider's listed price. A route without a provable price bound is refused.
  - Reserve, dispatch and revoke are decided atomically.
  - Settle the actual cost. A lost or uncertain reply keeps its reservation.
  - Revocation cannot undo spend that was already accepted.

## 5. Aumlok (bootstrap, phrase, passkey)
**Bootstrap order:**
1. The spawner creates the node and hands the owner a **one-time, expiring claim link** out of band.
2. The claim opens an owner session.
3. **Passkey enrolment** — the first and only one; enrolment then closes.
4. **Phrase binding** creates the identity.
5. The owner **approves the release** with the passkey.
6. Only then does the agent start. **The agent never runs unbound.**

An interrupted enrolment or binding resumes from durable state and never creates a second identity.

**The acrostic phrase is a new construction.**
- Word 1 is a six-letter anchor. Words 2–7 start with its letters.
- ROOT (nature), UNITE (people, connection, celebration), RISE (spirit, space, technology).
- The lists are as large as possible.
- The screen tells the owner to build a memory-palace story in their own head and never to type the words into an AI.
- **Min-entropy is computed over the real composed lists before the screen ships, and shown honestly.**

**The phrase never is the key.**
- Binding generates a random 256-bit root.
- The root is sealed in an Argon2id + XChaCha20-Poly1305 envelope under the phrase.
- The envelope is kept on the node and offered to the owner as a backup download.
- **Threat stated:** a stolen envelope permits offline guessing at Argon2id cost.
- Online unlock is rate-limited **per principal only**, never globally, so a stranger cannot lock the owner out.
- The same phrase on another node does not recreate the root. Recovery is envelope plus phrase.

**WebAuthn:**
- Our verifier ports Prime's `owner-key/webauthn.mjs` semantics onto RustCrypto (`p256`, `ed25519-dalek`, `ciborium`) and passes Prime's vectors. It does not depend on OpenSSL.
- The challenge is the digest of the gate-issued canonical authorization.
- There is no cookie-only or bearer approval.

## 6. Kira (memory)
- Memory is tracked, never approved. Capture, then encrypt, then record, then index.
- Notes are encrypted with XChaCha20-Poly1305 under a per-note key. The associated data is a length-prefixed `owner_subject`, `note_id` and `key_id`.
- **The ledger commitment carries no plaintext hash** (a plaintext hash would allow dictionary guessing). It carries `note_id`, `key_id`, `ciphertext_sha256`, category, time and the attribution tier.
- **Forget = demote** (never delete). A `memory.demote {note_id, prior_seq, reason}` row is written, the ciphertext moves to the cold table, and recall never returns it.
- **Recall is found / empty / undetermined**, with cited sources. Model-authored notes are tiered and never re-injected as trusted.
- **Disclose-to-context is a [1] permission.** It is set once by the owner with the passkey and recorded, before any recall goes into a hosted model's context.

## 7. WASM cell
- Exactly **101 bytes**, sha256 `34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438`. Measured on 2026-10-14 from Prime's `wasm-proposal-cell.mjs`. The "103" quoted elsewhere was wrong.
- **One import** (`aukora.propose_memory_put`), zero WASI. Exports `memory` and `memory_put`.
- Embedded with `include_bytes!` and checked by hash at start.
- `wasmtime`: the memory maximum is validated before instantiation, with a fuel bound.
- The cell's digests go into the approval and the evidence. Bypass tests anchor on the 64 KiB refusal.

## 8. Finish lines (each passes on a live node; Peter accepts it on his own screen)
Each line names its prerequisites, the installed revision, the observable success, the hostile twin, and the retained evidence.

| Line | Success | Twin that must fail |
|---|---|---|
| **A1** model reply | A real provider reply. A broker receipt that matches it, and a charge inside the passkey-signed grant | Route off: "unavailable", never faked. Overspend race. "Print your key" |
| **A2** approved change | Exact displayed bytes equal approved bytes, one observed effect, the receipt and the retained head | The same change without approval has zero effects. Altered bytes |
| **A3** reboot | After a real reboot: cited recall, demotion, floor, and spent approvals all hold. Distinct from restoring into an empty node, which is [2] | A spent approval revived after reboot |
| **A4** second node | An independent node (C2) passes A1 and A2 | C1's cookies and proofs fail on C2. No state is copied |
| **A5** Path 0 | The confined agent proposes through the pinned cell, a real passkey approves, the change applies once, and cold verification passes against an owner-retained head | Crash and retry at every transition: never a second write, never fabricated success |
| **Stranger** | Verify from an empty folder | A forged key, edited history or truncation passes |

**Intermediate (not acceptance):** "first chat". Peter chats with Auma through the confined runtime under an operator-set cap recorded in Aura. A1 proper requires the passkey grant.

## 9. Build order (hours of work, not dates)
- **Target node S1:** a new LXD container on the existing Nebius host. No new spend; namespaces were measured working there. Fresh VMs arrive with spawn (step 11) and need Peter's spend approval.
- **Parallel from hour 0:**
  - ledger crate with golden vectors
  - gate state machine with crash injection
  - launcher with self-test and attack harness
  - FD 3 codec plus shared fuzz corpus (Rust and JS)
  - Kira envelope and commitment format
  - verifier vectors
  - Pentora digest
  - UI rewiring against a stub supervisor API
- **Serial spine:**
  1. Skeleton and contracts frozen (2h)
  2. Ledger (6h)
  3. Gate (10h)
  4. Launcher on S1 (8h)
  5. Agent inside, FD 3/FD 4 bridge (6h) → **first chat**
  6. Front door, claim, passkey enrolment, binding (10h)
  7. Broker and grant → **A1**
  8. Approval card and apply → **A2, then A5 (Path 0)**
  9. Kira → **A3**
  10. Aura view, Pentora, cold verifier, owner-retained head → **Stranger**
  11. WASM cell joined
  12. Spawn and release switch → **C2, A4**
  13. Laya and the slider; the refresh screen; add-machine
- **Live attacks after every step:** Grok, Kimi, Mistral, Gemini and Dot. Every confirmed hole becomes one check inside the system, then a fix on main.

## 10. Crew
- **Claude:** sole writer and integrator. Owns gate, ledger and supervisor. Runs the live checks.
- **Codex workers:** build crates from issue text in parallel clones.
- **Grok:** sandbox, plus hostile-guest attacks on S1.
- **Kimi:** port maps, UI rewiring, cleanup, swarm sweeps.
- **Mistral/GLM and Gemini/Aragon (browser):** protocol and whole-repo attacks. The repo is private, so they need Peter's connector or pasted files.
- **Dot:** acceptance contract and independent attacks on each finish line.
- **Peter:** spend, credentials, binding and approvals on the live node; accepts every finish line.

## 11. Choices
**Libraries:**
- `rusqlite` (bundled)
- `ed25519-dalek` v2
- `p256`, `ciborium`, `chacha20poly1305` (XChaCha), `argon2`, `sha2`, `zeroize`
- `wasmtime` (no WASI)
- `landlock`, `nix`, `seccompiler`
- `rustls` with ACME, `axum`/`hyper`

**Runtime and UI:**
- The agent runtime stays the DeepSeek harness (Node), caged.
- Prime's in-process composition gate is dropped; the supervisor checks the harness tree's digest before mounting it read-only.
- Model calls go through a `sovereign` LlmAdapter in the guest bridge, with zero provider retries. DeepSeek, pi-ai, session-title, telemetry, session-log and package-inventory rows are disabled.
- The chat listens on FD 4 through a `webserver-listen-inherited-fd` harness patch.
- The screens are Prime's, rewired.
- Linux only for now.

**Out until after A1–A5:** Buzz, invites, voice, post-quantum, succession, AR/VR. The approval card is canonical bytes from day one, so any future surface can present it.

## 12. What this does not claim
- It does not prove a person approved, only that a passkey signed exact bytes after its user check.
- Synced passkeys do not prove device-only custody.
- The record is tamper-evident to a stranger only against a retained or witnessed head.
- Demoted memory is kept, not erased. Key deletion is not proof of erasure.
- Laya is uncalibrated until measured.
- The organs share one trusted process.
