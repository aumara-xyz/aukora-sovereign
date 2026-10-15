// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact owner authorization and the single authority transaction implemented by Aura.

use core::fmt;

use crate::{
    alg::{AlgorithmId, PublicKey, Signature, Signatures},
    digest::Digest32,
    ids::{CredentialId, NodeId, OperationDigest, OperationId, ProposalId, SubjectId},
    json::Value,
    Result,
};

/// Rollback context attached to each authority-bearing record.
/// Sequence is gap-free and in 1..=2^53-1. `None` is valid only at sequence 1 and
/// means C2's literal previous value `aukora:aura-record:v1`, never an all-zero hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityVersion {
    /// Current owner-state epoch, checked against the binding in the same transaction.
    pub epoch: u64,
    /// Aura's append-only sequence; clocks do not establish ordering.
    pub sequence: u64,
    /// Exact predecessor hash, or the sequence-1 domain sentinel described above.
    pub previous_hash: Option<Digest32>,
}

/// Closed C3 v1 kind registry; adding a kind requires a contract change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `boot.facts`.
    BootFacts,
    /// `gate.propose`.
    GatePropose,
    /// `gate.review`.
    GateReview,
    /// `gate.consume`.
    GateConsume,
    /// `gate.apply`.
    GateApply,
    /// `gate.retire`.
    GateRetire,
    /// `gate.refuse`.
    GateRefuse,
    /// `gate.expire`.
    GateExpire,
    /// `gate.recover`.
    GateRecover,
    /// `floor.advance`.
    FloorAdvance,
    /// `aumlok.enrol`.
    AumlokEnrol,
    /// `aumlok.bind`.
    AumlokBind,
    /// `aumlok.signin`.
    AumlokSignin,
    /// `broker.grant`.
    BrokerGrant,
    /// `broker.reserve`.
    BrokerReserve,
    /// `broker.settle`.
    BrokerSettle,
    /// `broker.revoke`.
    BrokerRevoke,
    /// `kira.save`.
    KiraSave,
    /// `kira.demote`.
    KiraDemote,
    /// `kira.permission`.
    KiraPermission,
    /// `sandbox.start`.
    SandboxStart,
    /// `sandbox.exit`.
    SandboxExit,
    /// `nostr.bind`.
    NostrBind,
}

impl Kind {
    /// Return the exact C3 v1 kind spelling.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::BootFacts => "boot.facts",
            Self::GatePropose => "gate.propose",
            Self::GateReview => "gate.review",
            Self::GateConsume => "gate.consume",
            Self::GateApply => "gate.apply",
            Self::GateRetire => "gate.retire",
            Self::GateRefuse => "gate.refuse",
            Self::GateExpire => "gate.expire",
            Self::GateRecover => "gate.recover",
            Self::FloorAdvance => "floor.advance",
            Self::AumlokEnrol => "aumlok.enrol",
            Self::AumlokBind => "aumlok.bind",
            Self::AumlokSignin => "aumlok.signin",
            Self::BrokerGrant => "broker.grant",
            Self::BrokerReserve => "broker.reserve",
            Self::BrokerSettle => "broker.settle",
            Self::BrokerRevoke => "broker.revoke",
            Self::KiraSave => "kira.save",
            Self::KiraDemote => "kira.demote",
            Self::KiraPermission => "kira.permission",
            Self::SandboxStart => "sandbox.start",
            Self::SandboxExit => "sandbox.exit",
            Self::NostrBind => "nostr.bind",
        }
    }

    /// Parse the closed C3 registry, refusing unknown operations.
    pub fn from_wire(_text: &str) -> Result<Self> {
        todo!("row 32")
    }
}

/// Closed C3 phase; every operation has exactly one terminal row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// An operation's declared intent, spelled `intent`.
    Intent,
    /// Settlement of an operation, spelled `settle`.
    Settle,
    /// The operation's unique terminal row, spelled `terminal`.
    Terminal,
    /// Informational evidence only, spelled `fact`; never an authorizing transition.
    Fact,
}

impl Phase {
    /// Return the exact C3 wire spelling.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Settle => "settle",
            Self::Terminal => "terminal",
            Self::Fact => "fact",
        }
    }

    /// Parse only the four C3 phase values.
    pub fn from_wire(_text: &str) -> Result<Self> {
        todo!("row 32")
    }
}

/// The five C5 owner actions; unknown actions refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerOperation {
    /// Approve application of the exact proposal bytes.
    Apply,
    /// Approve retirement with its own fresh challenge and displayed card digest.
    Retire,
    /// Approve a release pointer over its exact bytes.
    Release,
    /// Approve a bounded grant over its exact bytes.
    Grant,
    /// Approve an exact permission change.
    Permission,
}

impl OwnerOperation {
    /// Return the C5 `op` spelling; apply and retire cannot share a proof.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Retire => "retire",
            Self::Release => "release",
            Self::Grant => "grant",
            Self::Permission => "permission",
        }
    }
}

/// The C5 base selector; absent is the literal JSON string `absent`, never omission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseDigest {
    /// The allowed target does not exist.
    Absent,
    /// The exact existing target's SHA-256 digest.
    Present(Digest32),
}

/// C4/C5 cell commitments; the supervisor reruns the cell and compares all three.
/// A guest's supplied digests are evidence and never authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellCommitment {
    /// SHA-256 of the approved cell module bytes.
    pub module_sha256: Digest32,
    /// SHA-256 of canonical `{key,value}` input.
    pub input_sha256: Digest32,
    /// SHA-256 of the exact canonical cell effect body bytes.
    pub effect_sha256: Digest32,
}

/// A fresh gate nonce for C5: 16 random bytes encoded as exactly 32 lowercase hex digits.
/// It is distinct from the 32-byte WebAuthn challenge derived from the authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthorizationChallenge([u8; 16]);

impl AuthorizationChallenge {
    /// Retain 16 gate-supplied random bytes; this constructor supplies no randomness.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact C5 nonce bytes, without hashing them.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parse exactly 32 lowercase hexadecimal digits; all other spellings refuse.
    pub fn from_hex(_text: &str) -> Result<Self> {
        todo!("row 32")
    }
}

impl fmt::Display for AuthorizationChallenge {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(output, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The closed C6 risk vocabulary; neither value grants authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardRisk {
    /// A card whose exact `risk` value is `routine`.
    Routine,
    /// A card whose exact `risk` value is `critical`.
    Critical,
}

impl CardRisk {
    /// Return the exact C6 spelling without accepting arbitrary risk labels.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::Critical => "critical",
        }
    }
}

/// The closed C6 display object, rendered injectively by the owner surface.
/// Its exact canonical bytes are committed by `OwnerAuthorization::display_sha256`.
/// Different cards must remain visibly distinct, including escaped text; rendering
/// the card or seeing its digest never authorizes an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    /// C6 format version, exactly 1.
    pub v: u16,
    /// The closed `routine` or `critical` risk label.
    pub risk: CardRisk,
    /// One gate-written line; never supplied as an instruction by model content.
    pub says: String,
    /// Ordered facts, each encoded as exactly `[label,value]` with a C1 value.
    pub facts: Vec<(String, Value)>,
    /// Members of the C6 `from_to` object; duplicate decoded keys refuse.
    pub from_to: Vec<(String, Value)>,
    /// Untrusted model text, displayed fenced after every other card field.
    pub model_note: String,
}

impl Card {
    /// Emit exactly `{v,risk,says,facts,from_to,model_note}` as canonical C1 bytes.
    /// Refuse a version other than 1, a non-single-line `says`, duplicate `from_to`
    /// keys or a C1 depth violation. Facts retain their order and two-item shape;
    /// `from_to` is always an object. No wrapper or algorithm fields enter C6 bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        todo!("row 32")
    }
}

/// The gate's own C5 authorization, rebuilt from locked state rather than browser input.
/// `algorithm` describes this wrapper's SHA-256 commitments and is not an added C5
/// JSON field: `canonical_bytes` emits exactly the frozen C5 v1.1 field set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerAuthorization {
    /// C5 JSON version, exactly 1, with the v1.1 epoch and operation fields.
    pub v: u16,
    /// Commitment algorithm, exactly SHA-256 for C5 v1.1.
    pub algorithm: AlgorithmId,
    /// Node whose trusted state produced this authorization.
    pub node: NodeId,
    /// The owner subject bound at the current epoch.
    pub subject: SubjectId,
    /// Exact owner action being approved.
    pub op: OwnerOperation,
    /// Gate proposal selected by id, never a browser-supplied authorization object.
    pub proposal: ProposalId,
    /// Allowed target identifier selected by the gate.
    pub target: String,
    /// Existing digest or the explicit `absent` sentinel.
    pub base_sha256: BaseDigest,
    /// SHA-256 of the exact new target bytes.
    pub new_sha256: Digest32,
    /// Gate-recomputed cell commitments or JSON null.
    pub cell: Option<CellCommitment>,
    /// SHA-256 of the exact `Card::canonical_bytes` shown by the owner surface.
    pub display_sha256: Digest32,
    /// The fresh gate-generated 16-byte nonce, rendered as exactly 32 lowercase hex digits.
    pub challenge: AuthorizationChallenge,
    /// Millisecond expiry checked against gate state; time never replaces sequencing.
    pub expires_at: i64,
    /// Current credential-binding epoch.
    pub epoch: u64,
    /// C5 SHA-256 operation-content digest; distinct from the C7 random operation id.
    pub operation: OperationDigest,
}

impl OwnerAuthorization {
    /// Emit only the exact C5 v1.1 canonical object. Recompute `operation` from
    /// `aukora:operation-content:v1\0 || canon({v:1,node,target,base_sha256,new_sha256,cell})`
    /// and refuse any mismatch, unsupported wrapper algorithm or invalid field.
    /// Emit `challenge` as exactly 32 lowercase hex digits. The separate WebAuthn
    /// challenge is SHA-256(`aukora:owner-authorization:v1\0` || these bytes), 32 bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        todo!("row 32")
    }
}

/// The current stored passkey binding read inside the authority transaction.
/// A value of this type alone proves nothing and cannot construct a `VerifiedProof`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerBinding {
    /// Binding record format version, currently 1.
    pub v: u16,
    /// Signature algorithm, equal to the public key's algorithm.
    pub algorithm: AlgorithmId,
    /// Credential handle enrolled in the current owner epoch.
    pub credential_id: CredentialId,
    /// The public verification key; no secret key material enters canon.
    pub public_key: PublicKey,
    /// Owner epoch that must equal the gate authorization's epoch.
    pub epoch: u64,
    /// WebAuthn relying-party id whose SHA-256 must match authenticatorData.
    pub relying_party: String,
    /// Exact accepted ceremony origin.
    pub owner_origin: String,
    /// Exact accepted shell top origin for the cross-origin ceremony.
    pub top_origin: String,
    /// Last persisted authenticator counter, subject to AUMLOK's zero-counter policy.
    pub sign_counter: u32,
}

/// Untrusted WebAuthn input retained in full for verification inside the transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerAssertion {
    /// Assertion wrapper version, currently 1.
    pub v: u16,
    /// Signature algorithm, required to match the stored binding and signature tag.
    pub algorithm: AlgorithmId,
    /// Credential that produced the assertion; matched to the current epoch binding.
    pub credential_id: CredentialId,
    /// Exact authenticatorData bytes, including RP hash, flags and sign counter.
    pub authenticator_data: Vec<u8>,
    /// Exact clientDataJSON bytes; their original encoding is signed, not a reserialization.
    pub client_data_json: Vec<u8>,
    /// Tagged signature over authenticatorData concatenated with SHA-256(clientDataJSON).
    pub signature: Signature,
}

/// A verified owner passkey assertion over the gate's exact rebuilt C5 bytes.
/// Fields are private, there is no unchecked constructor, and this capability is not
/// cloneable. Only `verify` can create it, while the same `BEGIN IMMEDIATE` transaction
/// is active. Retained raw bytes support replay and signature verification; digests
/// alone cannot authorize. Evidence, a health cell and a fingerprint never create it.
#[derive(Debug)]
pub struct VerifiedProof {
    credential_id: CredentialId,
    algorithm: AlgorithmId,
    sign_counter: u32,
    authenticator_data_digest: Digest32,
    client_data_digest: Digest32,
    signed_bytes_digest: Digest32,
    top_origin: String,
    assertion: OwnerAssertion,
    authorization: OwnerAuthorization,
    authorization_bytes: Vec<u8>,
    signed_bytes: Vec<u8>,
    public_key: PublicKey,
    transaction_id: Digest32,
}

impl VerifiedProof {
    /// The sole constructor. Inside `txn`, load its current owner binding and rebuild
    /// C5 from the gate's locked state for this proposal and action. Refuse stale epoch,
    /// credential/key/algorithm mismatch, spent or expired challenge, changed target,
    /// operation or display bytes. Check WebAuthn type, UV and UP flags, RP-id hash,
    /// exact owner origin, cross-origin flag and exact topOrigin. A presented counter
    /// of 0 is valid while the stored counter is 0. Once the stored counter is nonzero,
    /// require a strictly greater presented counter; presented 0 then refuses.
    /// Replay protection is the single-use gate nonce, never the sign counter. Check
    /// challenge = SHA-256(`aukora:owner-authorization:v1\0` || canonical gate auth).
    /// Verify the signature with an allowlisted primitive over the exact
    /// `authenticatorData || SHA-256(clientDataJSON)` bytes. Do not canonicalize or
    /// replace clientDataJSON before hashing. Bind the result to `txn.transaction_id()`.
    /// No verification or counter update may happen outside this same transaction.
    pub fn verify<T: AuthorityTxn + ?Sized>(
        _txn: &mut T,
        _proposal: &ProposalId,
        _action: OwnerOperation,
        _assertion: OwnerAssertion,
    ) -> Result<Self> {
        todo!("row 32")
    }

    /// Credential bound and verified in the transaction's current epoch.
    pub fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    /// Algorithm actually checked against the stored public key.
    pub const fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// Authenticator counter checked by verification and persisted before consumption.
    pub const fn sign_counter(&self) -> u32 {
        self.sign_counter
    }

    /// SHA-256 of the exact retained authenticatorData bytes.
    pub const fn authenticator_data_digest(&self) -> Digest32 {
        self.authenticator_data_digest
    }

    /// SHA-256 of the exact retained clientDataJSON bytes.
    pub const fn client_data_digest(&self) -> Digest32 {
        self.client_data_digest
    }

    /// SHA-256 of the exact WebAuthn signing bytes, not merely the authorization object.
    pub const fn signed_bytes_digest(&self) -> Digest32 {
        self.signed_bytes_digest
    }

    /// The exact top origin verified against the stored binding.
    pub fn top_origin(&self) -> &str {
        &self.top_origin
    }

    /// Retained original WebAuthn assertion, including raw bytes and tagged signature.
    pub const fn assertion(&self) -> &OwnerAssertion {
        &self.assertion
    }

    /// The gate-rebuilt authorization whose bytes the challenge committed to.
    pub const fn authorization(&self) -> &OwnerAuthorization {
        &self.authorization
    }

    /// Exact canonical gate authorization bytes used to derive the WebAuthn challenge.
    pub fn authorization_bytes(&self) -> &[u8] {
        &self.authorization_bytes
    }

    /// Exact `authenticatorData || SHA-256(clientDataJSON)` bytes verified by the key.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }

    /// The bound public key used to verify the retained signature.
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Non-authorizing transaction identity; implementations compare this before every step.
    pub const fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }
}

/// An unsigned append request; having this data never authorizes its append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAuthorityRecord {
    /// Wrapper format version, currently 1; unsupported versions refuse.
    pub v: u16,
    /// Record commitment algorithm, SHA-256 for frozen C2/C3 v1.
    pub algorithm: AlgorithmId,
    /// Proposed epoch and next sequence; recomputed against locked Aura state.
    pub authority: AuthorityVersion,
    /// Informational supervisor clock in integer milliseconds.
    pub at: i64,
    /// A member of the closed C3 kind registry.
    pub kind: Kind,
    /// Recorded actor; never accepted as an owner proof.
    pub actor: String,
    /// C7 random operation id; absent only for a nonauthorizing fact.
    pub operation: Option<OperationId>,
    /// C3 phase; append enforces one terminal row per operation.
    pub phase: Phase,
    /// Canonical C1 body, treated as data.
    pub body: Value,
}

/// A versioned signed Aura record with a persistent nonempty signature-component list.
/// C3 v1 entry hashing and export remain byte-exact: its field set is unchanged and
/// `sig` exports only the Ed25519 component over the 32 raw entry-hash bytes. Hybrid
/// components remain stored in `signatures`; adding ML-DSA-65 needs no new field.
/// Neither this record nor its signatures are an owner authorization capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityRecord {
    /// Signed-record wrapper version, currently 1.
    pub v: u16,
    /// The record commitment primitive, SHA-256 under C2 v1.
    pub algorithm: AlgorithmId,
    /// Exact append-only epoch, sequence and predecessor context.
    pub authority: AuthorityVersion,
    /// C2 hash of the canonical C3 row fields and domain.
    pub hash: Digest32,
    /// All required tagged signature components; a hybrid verifies every component.
    pub signatures: Signatures,
    /// Informational supervisor clock in integer milliseconds.
    pub at: i64,
    /// Exact closed C3 kind.
    pub kind: Kind,
    /// Recorded actor string, never authority.
    pub actor: String,
    /// C7 operation id; C3 exports an empty string only when this is a fact.
    pub operation: Option<OperationId>,
    /// C3 phase; only facts may omit the operation id.
    pub phase: Phase,
    /// Canonical C1 record body.
    pub body: Value,
}

impl AuthorityRecord {
    /// Export the original C3 v1 row field set with the single standard padded-base64
    /// Ed25519 `sig`. Refuse missing/duplicate Ed25519 components or invalid C3 fields;
    /// never insert algorithm tags, epoch metadata or hybrid lists into old export bytes.
    pub fn c3_v1_export(&self) -> Result<Value> {
        todo!("row 32")
    }
}

/// Closed proposal-lifecycle observations that never authorize an effect.
/// Authorizing gate kinds (`consume`, `apply`, `retire`) are intentionally absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleKind {
    /// A guest proposal was received; its bytes remain pending owner approval.
    GatePropose,
    /// A review was observed; review does not approve or consume the proposal.
    GateReview,
    /// The operation was refused without performing its proposed effect.
    GateRefuse,
    /// The operation expired without performing its proposed effect.
    GateExpire,
}

impl LifecycleKind {
    /// Return the corresponding closed C3 kind; none grants authority.
    pub const fn kind(self) -> Kind {
        match self {
            Self::GatePropose => Kind::GatePropose,
            Self::GateReview => Kind::GateReview,
            Self::GateRefuse => Kind::GateRefuse,
            Self::GateExpire => Kind::GateExpire,
        }
    }
}

/// A nonauthorizing C3 proposal observation, retaining its random operation id.
/// Refusal and expiry use the operation's terminal phase; pending proposal and
/// review observations cannot masquerade as successful or authorizing completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleRecord {
    /// Observation wrapper version, currently 1.
    pub v: u16,
    /// Record commitment primitive, SHA-256 for frozen C2/C3 v1.
    pub algorithm: AlgorithmId,
    /// Locked epoch and expected next sequence and predecessor.
    pub authority: AuthorityVersion,
    /// Informational supervisor clock in milliseconds.
    pub at: i64,
    /// A closed lifecycle kind incapable of changing authority.
    pub kind: LifecycleKind,
    /// Informational actor label, never an owner proof.
    pub actor: String,
    /// The C7 random operation id; always retained for terminal accounting.
    pub operation: OperationId,
    /// Refusal/expiry require `Terminal`; propose/review refuse `Terminal`.
    pub phase: Phase,
    /// Canonical observation data; it cannot become an approval or instruction.
    pub body: Value,
}

/// Closed nonauthorizing fact kinds; facts report observations and cannot change authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactKind {
    /// Observed boot state; does not approve or advance a release.
    BootFacts,
    /// Observed sandbox start; never permission to start one.
    SandboxStart,
    /// Observed sandbox exit.
    SandboxExit,
    /// Observed settlement under an already authorized reservation; never a new grant.
    BrokerSettle,
}

impl FactKind {
    /// Return the associated C3 kind, always paired with `Phase::Fact`.
    pub const fn kind(self) -> Kind {
        match self {
            Self::BootFacts => Kind::BootFacts,
            Self::SandboxStart => Kind::SandboxStart,
            Self::SandboxExit => Kind::SandboxExit,
            Self::BrokerSettle => Kind::BrokerSettle,
        }
    }
}

/// An informational append request with no operation, proof, grant or mutable authority.
/// Its phase is fixed to `Fact`; it can never be promoted into an approval by a reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactRecord {
    /// Fact wrapper version, currently 1.
    pub v: u16,
    /// The record commitment primitive, SHA-256 under C2 v1.
    pub algorithm: AlgorithmId,
    /// Locked epoch and expected next sequence.
    pub authority: AuthorityVersion,
    /// Informational supervisor clock in milliseconds.
    pub at: i64,
    /// A member of the closed nonauthorizing fact registry.
    pub kind: FactKind,
    /// Informational producer identity; not an authorizing principal.
    pub actor: String,
    /// Bounded canonical fact data; not commands or executable instructions.
    pub body: Value,
}

/// One Aura-owned `BEGIN IMMEDIATE` transaction, never separate connections or nested
/// commits. For an authority change, the same transaction verifies the passkey,
/// persists its counter, consumes the exact approval and appends the signed record. Every failure rolls
/// back all four; no intermediate state commits. Its identity is unique per active
/// transaction and may not be reused after rollback or commit. Aura implements this
/// interface; cryptographic primitives come only from allowlisted crates.
pub trait AuthorityTxn {
    /// Identify this active write transaction; never an authority or a public nonce.
    fn transaction_id(&self) -> Digest32;

    /// Load the current stored credential/epoch/RP/origin binding under this transaction.
    /// Refuse missing, retired or stale credentials; never accept a caller-made binding.
    fn owner_binding(&mut self, credential: &CredentialId) -> Result<OwnerBinding>;

    /// Rebuild C5 from the gate's own locked target, proposal, card and challenge state.
    /// Nothing from clientDataJSON or the browser supplies the authorization object.
    fn rebuild_authorization(
        &mut self,
        proposal: &ProposalId,
        action: OwnerOperation,
    ) -> Result<OwnerAuthorization>;

    /// Check a tagged signature with its stored bound public key using an allowlisted
    /// implementation. Unsupported/mismatched algorithms refuse; no fallback is allowed.
    /// Success checks cryptography only and cannot mint or replace `VerifiedProof`.
    fn verify_signature(
        &mut self,
        key: &PublicKey,
        signed_bytes: &[u8],
        signature: &Signature,
    ) -> Result<()>;

    /// Persist this verified assertion's sign counter in this exact transaction only.
    /// Refuse a different transaction identity or binding epoch. Presented 0 is valid
    /// while stored is 0 and leaves it at 0. Once stored is nonzero, presented must
    /// be strictly greater; refuse presented 0 or any non-increase. Compare-and-set
    /// nonzero advances against the locked stored counter; refuse a conflict. Replay
    /// protection is the single-use challenge, never the counter. Record completion
    /// in transaction-local state required by `consume` and `append`, including 0/0.
    fn persist_counter(&mut self, proof: &VerifiedProof) -> Result<()>;

    /// After `persist_counter`, consume the exact gate approval once in this transaction.
    /// Check transaction identity, current epoch and byte-for-byte gate authorization
    /// again. Refuse reused challenges and mark consumption for `append`; do not commit.
    fn consume(&mut self, proof: &VerifiedProof) -> Result<()>;

    /// Require the private non-Clone proof by value; no proof-free authorizing append
    /// exists. Refuse unless this exact transaction verified it, persisted its counter
    /// and consumed its exact approval. Check row/action/body/operation binding, current
    /// epoch, next sequence, predecessor hash and the unique terminal rule. Persist the
    /// full required `Signatures` list and return the signed record. A fact phase refuses
    /// here. Appending or any failure never commits a partial authority transition.
    fn append(
        &mut self,
        proof: VerifiedProof,
        record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord>;

    /// Record only the four closed `LifecycleKind` observations without owner proof.
    /// Validate epoch, sequence, predecessor and operation id. Refusal and expiry must
    /// be terminal and unique; propose/review cannot be terminal. This method only
    /// appends evidence: it cannot consume an approval, persist a passkey counter,
    /// apply a target, grant capabilities or change credentials, floors, permissions
    /// or any other authority. Readers must never infer authorization from these rows.
    fn append_lifecycle(&mut self, observation: LifecycleRecord) -> Result<AuthorityRecord>;

    /// Append only a closed `FactKind` with `Phase::Fact` and no operation id. Sign and
    /// sequence the observation, but never modify credentials, release floors, grants,
    /// counters, consumption, permissions or any authorizing state. Fact readers must
    /// never treat the row as a capability or a replacement for the owner proof.
    fn append_fact(&mut self, fact: FactRecord) -> Result<AuthorityRecord>;
}

/// The NORTH-STAR name for exactly the same atomic transaction interface.
pub use AuthorityTxn as LedgerTxn;
