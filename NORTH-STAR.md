# AUKORA Sovereign: North Star

Peter steers by this file. It carries forward his Prime North Star (aukora-prime `plan/NORTH-STAR.md`) and the plan he
approved on 2026-10-14 (master plan v0.2, now in aukora-sovereign-archive `plan/SPEC.md`), for a node rebuilt so the
security is real. Nothing here is new invention. Every organ below already exists in source; most have run live.

## One sentence
A personal AI organism on a Linux server you control, reached from your own app, that can grow and even change itself —
and can never act past the boundary without its owner's approval, with a receipt anyone can check.

## The body (every organ, and where it lives in this repository)
- **The Spatial app** (`app/`): the AUKORA spatial frontend on the DeepSeek harness, brought in whole: the threads, the
  chat with Auma, voice, and the panels.
  - AUKORA APPS: Auma Lingwa, Auma Live, Zeta Harp, Human Graph, Media, Memory, Messages, Documents.
  - SYSTEM: AUMLOK, Identity, Aura Coherence, General, Models, Plugins, Agent presets, Archived sessions.
  - Nothing is hidden or dropped.
- **One node, one link.** The person only ever uses one address. Passkey, phrase and approvals are pop-ups inside the
  app, served by the node itself (`crates/frontdoor`, `owner-panes/`), never by the agent.
- **The cage** (`crates/launcher`): Auma runs in an operating-system sandbox (user namespaces, Landlock, seccomp, no
  network, cgroup limits). She can only propose. A boot self-attack (`crates/immune`) proves the cage at every start.
- **The gate** (`crates/gate`): every change she proposes is shown to the owner as exact bytes. A passkey approves it,
  it applies once, and it is never replayed. Auma can never approve herself.
- **Laya and the slider** (`crates/laya`): the owner chooses how often pop-ups appear: for everything, only for risky
  things, or not within today's limits. That is a standing permission signed once by fingerprint, scoped, counted and
  expiring. Risky changes always ask. Laya decides what pops up; she never approves.
- **AUMLOK** (`crates/aumlok`): who the owner is. The acrostic seven-word phrase:
  - ROOT: nature;
  - UNITE: people and celebration;
  - RISE: spirit, space and technology.
  It seals a random root key, and a passkey (Touch ID) signs every approval.
- **AURA** (`crates/aura`): what happened. One signed, append-only record of every action, approval, memory write and
  self-change. It is witnessed by the owner's browser and on Nostr relays.
- **Pentora** (`crates/pentora`): the picture of the record (Aura Coherence). Two people or devices seeing the same
  Pentora hold the same record fingerprint.
- **The minimal verifier** (`crates/verifier`, `aukora-verify`): a stranger checks the receipts and the record from an
  empty folder, without trusting the node.
- **KIRA** (`crates/kira`): what she remembers. Encrypted notes, recorded and never approved, recalled with citations
  (found, empty or undetermined), with OpenViking ranking by meaning inside the node. Forgetting demotes; nothing is
  silently deleted.
- **The WASM core** (`crates/wasmcell`): proposals run in the sealed 101-byte WebAssembly cell before they become
  effects.
- **The broker** (`crates/broker`): the model key is held outside the model. Spending is limited by a passkey-signed
  grant, with a receipt for every call.
- **The floor** (`crates/floor`): a release can never roll back below what the owner approved, and a spent approval
  can never revive.
- **The immune system** (`crates/immune`): every known attack becomes an antibody; a release must pass them all.
- **NOSTR** (`crates/nostr`, `crates/relay`, `crates/messaging`): her voice to the world. The node and agent identities
  are bound to the record. Messages between nodes are gift-wrapped (NIP-59) through relays, from owner-approved contacts
  only. A message is never authority.
- **Invites** (`crates/invites`): "You can download the open-source software, but you can't be part of the network
  without a direct invite from me or someone I've invited." A one-time code, valid 48 hours, three per member.
- **Co-presence** (`portal/`, `crates/copresence`): two screens show each other signed light. It is evidence of being
  in the same place, never authority, and never "a verified human".
- **Go Sovereign** (`ops/go-sovereign`, `ops/spawn`): a valid invite unlocks a fresh node with one click. The joining
  ceremony is co-presence with your own two devices first, then your AUMLOK phrase and passkey, then straight into the
  Spatial app.

## What Peter watches, in order (only Peter says "done")
1. **His fresh node.** One link, the whole Spatial app, claimed with his passkey and phrase. The release approval
   pops up inside the app.
2. **Auma answers with a real model.** The receipt sits inside his spend grant, and Auma cannot read the server.
3. **She proposes a change to herself.** Laya decides it pops up, he approves the exact bytes with his fingerprint, it
   runs through the WASM core and applies once, live. The same request without approval does nothing.
4. **She remembers after a real reboot**, recalled by meaning. Spent approvals stay spent; the floor holds.
5. **A stranger verifies everything** from an empty folder, and Aura Coherence shows the same record in his app.
6. **Two nodes talk.** His node and a second node exchange messages over Nostr relays, in Messages.
7. **Go Sovereign.** He invites a friend: the code unlocks a fresh node with one click, the co-presence ceremony runs,
   then the passkey and phrase, then the friend is inside their own Spatial app.

## Say plainly to anyone shown this
- A passkey approval proves a passkey signed exact bytes after its user check. It does not prove which person pressed it.
- The record is tamper-evident to a stranger against a retained or witnessed head.
- A co-presence receipt is evidence and grants nothing.
- On a server we run, whoever controls the machine could read a running node. "We cannot see inside" needs
  confidential VMs, which come later.
- Demoted memory is kept, not erased.
