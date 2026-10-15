# crates/aumlok
- **Owns:** passkey (WebAuthn) verification and ceremonies, the acrostic phrase and its envelope, the key hierarchy, delegation, devices, unlock limits per principal.
- **Never owns:** approval decisions, the record or the network.
- **May depend on:** canon, aura.
- **Bricks:** 43, 44, 45, 46, 47, 48, 49, 113, 125, 139 (NORTH-STAR.md).

## Wave-0 contract

These modules freeze data types, function signatures and dependency choices for the
three wave-1 owners. Cryptography, browser-origin verification, codecs and durable
transitions currently return explicit `aumlok:*` refusals. They do not report a
successful ceremony or manufacture authority. Concrete code is limited to data
accessors, closed vocabulary parsing, counter/KDF bounds and failed health reports.

| Worker | Whole-file ownership | Rows |
|---|---|---|
| 1 | `webauthn.rs`, `ceremony.rs`, `unlock.rs` | 43, 49 |
| 2 | `phrase.rs`, `envelope.rs`, `refresh.rs`, `backup.rs` | 44, 45, 46 |
| 3 | `keys.rs`, `delegation.rs`, `devices.rs`, `health.rs` | 47, 48, 113, 139; organ observations |

`lib.rs` contains only the module tree, re-exports and the unsafe-code prohibition.
`Cargo.toml` supplies all three workers' dependencies, including RustCrypto,
bounded JSON/CBOR decoding, browser interfaces and durable storage. The node-side
storage dependencies are absent from wasm32 builds. AUMLOK has no transport or
process dependency and adds no routes.

## Passkeys and ceremonies

WebAuthn v1 input fields retain their pinned layout. Algorithm and epoch belong in
stored wrappers, not new wire fields. ES256 and EdDSA are the admitted passkey
algorithms. `user_handle` is required but may be null. clientDataJSON needs its own
bounded JSON reader: pinned duplicate-key and number behavior differs from C1.
The exact original bytes, not a reserialization, enter signature verification.
The `serde_json` `unbounded_depth` feature permits replacing its default recursion
limit with the WebAuthn reader's explicit `MAX_JSON_DEPTH` limit of 512 containers.
Client data and registration/assertion material also have independent byte caps.

`OriginContext.expected_top_origin = None` selects the unchanged legacy vector
behavior. Live shell ceremonies use `Some(shell_origin)` and require both
`crossOrigin: true` and an exact `topOrigin` match. No hostname rewrite infers a
shell. RP hash, UP/UV, challenge, backup eligibility and the stored counter remain
independent verification requirements. The counter permits 0/0; otherwise the
presented value must increase. Nonce consumption supplies replay protection.

`CeremonyStore` is the non-authorizing durable begin/resume interface. Nonces are
32 random bytes, lifetime is bounded to five minutes, and state must survive a
restart without rewinding. Claim reservation and resume use separate secrets.
Registration produces candidate public data, followed by possession verification;
candidate data is never an owner binding. `CeremonyReadTxn` adds locked reads to
the canon transaction without adding a counter writer or proof constructor.

**Canon dependency:** `VerifiedProof::verify` currently requires an existing
owner binding and a gate C5 proposal. `AuthorityTxn::persist_counter` accepts only
that proof. Standalone enrolment possession and sign-in use ceremony challenges;
canon exposes no proof/transaction interface for them. Their finish functions
therefore return `aumlok:canon-ceremony-contract`. No separate counter store,
fabricated C5 proposal, authorizing fact row or public proof constructor is added.
The canon owner must supply that interface before those finishes can be implemented.

C5 owner assertions retain `canon::authority::VerifiedProof` as their sole output
capability. Verification, counter persistence, consumption and record append must
share the same `AuthorityTxn`; the AUMLOK verifier never commits it itself.

## Owner-origin secrets and node inputs

Phrase entry, normalization, generation, Argon2 derivation, root unsealing, refresh
display and WebAuthn PRF output exist only in the wasm32 owner API, behind the
private `OwnerBrowser` context. Its constructor currently refuses. Merely building
WASM does not prove an origin: wave 1 must check the actual browser and shell frame.
Secret types have no public byte constructor, Debug or serialization implementation.

The node receives canonical encrypted envelope bytes and public KDF salt, nonce and
costs; a claimed root-derived public key and subject; authenticated session and
ceremony handles; owner epoch and envelope revision/digests; and raw WebAuthn
assertions. Refresh also carries replacement ciphertext and a root-encrypted
phrase capsule for resumption. It receives no phrase, identity root, wrapping key
or PRF output. A claimed subject or matching ciphertext digest grants no authority.

The phrase is an anchor followed by ROOT, ROOT, UNITE, UNITE, RISE, RISE acrostic
words. The shipped display is **41.5 bits minimum, 43.1 average**. Normalization
must follow the pinned Unicode-13 oracle; a newer ICU database alone is insufficient.
The identity root is independently random, while owner authority is the passkey.
Refreshing rewraps the same root and atomically retires the previous online envelope.
The old downloaded envelope remains decryptable offline; retirement cannot erase it.

Envelope v1 retains exactly five keys. Backup download defaults to v2 with the same
credential's PRF under its original RP; phrase-only v1 requires explicit selection.
PRF eval input is SHA-256 of its tag without NUL. The refresh key is SHA-256 of its
tag, NUL and root; its associated data is the plain ASCII ceremony id. Domain
constants preserve these exceptions.
The current implementation uses RustCrypto `hkdf` for RFC 5869 HKDF-SHA256. The
`ring` note in pinned `vectors/ENVELOPE.md` describes the archive's backend; the
frozen inputs remain `phrase_key || prf_output`, the NUL-terminated extraction
salt and expansion info, and a 32-byte output, as pinned by `backup-kdf-v2.json`.

## Keys, devices and observations

Bindings name an AlgorithmId, role, exact scope, epoch and Aura anchor. Owner action
lists describe scope but do not confer passkey authority. Descendants have no owner
actions. The lineage has three edges: root to device to session to agent. Every use
must re-read all bindings, epochs and revocations inside the current transaction.
Mesh identity/agreement roles are reserved and refuse use until their rows activate.
New binding/delegation/device formats live inside versioned record bodies; no v1
Aura row gains keys. Signature input excludes its signatures and self-identifier.

`KeyRole` has 17 roles. The grouped proposal in `spec/REBUILD-GUIDANCE.md` section 3
maps to `OwnerPasskey`, `Operational`, `Device`, `Node`, `Agent`, the separate
`NodeNostr` and `AgentNostr` roles, `GuardianShardHolder`, `GuardianRecovery`,
`GuardianVeto`, and `BackupEncryption`. The remaining six are explicit distinctions:
`IdentityRoot` is the phrase-sealed identity's commitment, separate from passkey
authority (row 44); `Session` is the intermediate delegation role (row 48);
`AuraSigning` signs records (row 50); `PersonNostr` identifies the person independently
of node and agent keys (row 113 and conductor ruling 14); `DeviceMeshIdentity` and
`DeviceMeshAgreement` reserve signing and agreement scopes (row 113). The guidance
table groups roles rather than enumerating 17 wire names; this is the implemented
mapping.

`KeyRole::wire_name()` and `KeyUse::wire_name()` expose the exact case-sensitive
spellings used by the codecs. A scope is a C1 object with exactly `subject`, `node`,
`uses`, `owner_actions`, `resources`, `not_before_ms`, and `expires_at_ms`. Scope
arrays retain their supplied order; duplicate entries and unknown uses refuse.

Device pairing carries original co-presence receipt bytes, possession signatures,
old/new device membership and a separate exact-byte owner proof. A supervisor
adapter uses co-presence's own reader; receipt decimals never pass through C1.
Evidence, remote labels and guardian statements cannot replace owner approval.

Unlock principal handles come from authenticated session resolution. There is no
global bucket or browser-chosen principal. Locked requests cannot extend a lock;
recognition does not clear failure history. Each update uses persisted principal
state and compare-and-set, with current session and epoch checks.

Only `health.rs` declares health observations. Its 18 private and eight corner
specifications reference canon's frozen registry, including ownership, source and
freshness. All observers currently report Failed/Unwritten; supervisor collection
and immune reduction remain outside AUMLOK.

The new `vectors/framed-ceremony-v1.json` contains none-attestation registration
accept/refuse data for both passkey algorithms and awaits conductor pinning/replay.
It is not assertion-possession evidence. Signed framed-assertion and full backup-v2
AEAD vectors remain with their wave-1 implementations; no acceptance is fabricated.
