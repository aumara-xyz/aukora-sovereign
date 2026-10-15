// SPDX-License-Identifier: AGPL-3.0-or-later

//! Frozen C4 v1 payloads. A decoder checks the entire canonical frame byte budget.
//! These records do not authorize effects; text and tool calls remain untrusted data.

use crate::{
    digest::Digest32,
    ids::{NoteId, ProposalId},
    json::Value,
    Refusal,
};

/// C4 and C5 share one cell-commitment layout; the supervisor independently recomputes its digests.
pub use crate::authority::CellCommitment as CellCommitments;

/// C4 `propose`; acceptance only queues an owner review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Propose {
    /// Allowed target name, interpreted solely by the gate.
    pub target: String,
    /// Current target digest, encoded as 64 lowercase hexadecimal characters.
    pub base_sha256: Digest32,
    /// Replacement bytes in canonical padded RFC 4648 base64, at most 65,536 decoded bytes.
    pub new_bytes_b64: String,
    /// Untrusted model explanation, rendered as fenced text.
    pub note: String,
    /// Optional assertions that the supervisor recomputes rather than trusts.
    pub cell: Option<CellCommitments>,
}

/// C4 `read`; target authorization remains the supervisor's responsibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    /// Allowed target whose current bytes are requested.
    pub target: String,
}

/// A chat-completions message; a role string is data and never confers owner provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelMessage {
    /// Provider-facing role string; C4 v1 does not impose a role enumeration.
    pub role: String,
    /// Literal content, or JSON null.
    pub content: Option<String>,
    /// Optional ordered function calls; omission differs from an empty array.
    pub tool_calls: Option<Vec<ToolCall>>,
    /// Optional identifier correlating a tool-result message.
    pub tool_call_id: Option<String>,
}

/// A provider function declaration; its wire wrapper has exactly `type:"function"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tool {
    /// Function name passed to the model as data.
    pub name: String,
    /// Untrusted explanatory text.
    pub description: String,
    /// A JSON object, bounded by C1 and the enclosing frame; never interpreted as code.
    pub parameters: Value,
}

/// A function-call suggestion; neither the name nor arguments execute anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    /// Provider call identifier.
    pub id: String,
    /// Function name in the nested `function` object.
    pub name: String,
    /// Literal argument string in the nested `function` object.
    pub arguments: String,
}

/// C4 non-streaming `model.call`; one call consumes one broker reservation without automatic retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelCall {
    /// Frozen C4 grant string; possession is not authorization. New GrantId records
    /// use 16 random bytes in lowercase hex, without narrowing this legacy wire field.
    pub grant_id: String,
    /// Requested model identifier.
    pub model: String,
    /// Ordered messages; total serialized frame size bounds the collection.
    pub messages: Vec<ModelMessage>,
    /// Function declarations, or an empty list.
    pub tools: Vec<Tool>,
    /// Output cap in 1..=32,768.
    pub max_output_tokens: u32,
}

/// C4 `memory.put`; the caller reports pending until a matching eventual outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryPut {
    /// Mandatory independently checked proposal-cell commitments.
    pub cell: CellCommitments,
    /// Literal proposed memory statement, without instructional authority.
    pub statement: String,
    /// Optional literal source quote; absent and empty remain distinct.
    pub quote: Option<String>,
    /// Memory category supplied to Kira as data.
    pub category: String,
}

/// C4 `memory.recall`; Kira checks current-principal hosted-context permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRecall {
    /// Literal semantic query.
    pub query: String,
    /// Result cap in 1..=100.
    pub limit: u16,
}

/// The closed v1 `memory.list` tier vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryTier {
    /// Wire spelling `remembered`; active text requires recall permission.
    Remembered,
    /// Wire spelling `forgotten`; retained metadata only, never cold plaintext.
    Forgotten,
}

/// C4 paginated current-principal memory metadata request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryList {
    /// Requested closed tier.
    pub tier: MemoryTier,
    /// Last returned NoteId in that tier, 1..=128 UTF-8 bytes without control characters,
    /// or null for the first page.
    pub before: Option<NoteId>,
}

/// One C4 memory-list item; no fields contain keys or demotion reasons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryListItem {
    /// Opaque NoteId of 1..=128 UTF-8 bytes without control characters, sharing the cursor bound.
    pub note_id: NoteId,
    /// Nonempty category of at most 64 ASCII `[A-Za-z0-9_-]` bytes.
    pub category: String,
    /// Save time in milliseconds, 0..=2^53-1; never an authority clock.
    pub at: u64,
    /// Save receipt sequence in 1..=2^53-1.
    pub cite_seq: u64,
    /// Present for remembered; null for forgotten.
    pub text: Option<String>,
    /// Null for remembered; strictly greater than `cite_seq` for forgotten.
    pub demoted_seq: Option<u64>,
    /// Null for remembered; demotion milliseconds in 0..=2^53-1 for forgotten.
    pub demoted_at: Option<u64>,
}

/// C4 `memory.list.reply`; newest save sequence first, at most 100 items and one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryListReply {
    /// Tier whose item nullability rules apply.
    pub tier: MemoryTier,
    /// Bounded metadata page; no per-note signatures or pending approvals exist in v1.
    pub items: Vec<MemoryListItem>,
    /// Last returned NoteId of 1..=128 UTF-8 bytes without control characters,
    /// or null at the end.
    pub next: Option<NoteId>,
}

/// C4 `status.reply`; counts are bounded by 2^53-1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReply {
    /// Whether the supervisor is ready for its permitted operations.
    pub ready: bool,
    /// Whether the owner binding exists.
    pub bound: bool,
    /// Frozen C4 broker grant string, or null; distinct from the new 16-byte GrantId format.
    pub grant_id: Option<String>,
    /// Remaining nonnegative grant allowance, or null.
    pub grant_remaining: Option<u64>,
}

/// Non-secret AUMLOK counters in C4 `organs.reply`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AumlokStatus {
    /// Whether an owner is bound.
    pub bound: bool,
    /// Registered passkey count in 0..=2^53-1; never credential identifiers.
    pub passkeys: u64,
    /// Whether credential refresh is due.
    pub refresh_due: bool,
}

/// Non-secret Kira counts in 0..=2^53-1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KiraStatus {
    /// Retained note count, without note text.
    pub notes: u64,
    /// Demoted note count.
    pub demoted: u64,
}

/// One of the three fixed C4 Aura source names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuraSourceName {
    /// `gate-ledger`: all eight C3 `gate.*` kinds.
    GateLedger,
    /// `kira-chain`: `kira.save`, `kira.demote`, and `kira.permission`.
    KiraChain,
    /// `code-chain`: `floor.advance`.
    CodeChain,
}

/// Closed empty-source reason, required only when head is null and entries is zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAbsence {
    /// `gate-ledger-empty`, paired only with `gate-ledger`.
    GateLedgerEmpty,
    /// `kira-ledger-empty`, paired only with `kira-chain`.
    KiraLedgerEmpty,
    /// `code-record-missing`, paired only with `code-chain`.
    CodeRecordMissing,
}

/// A verified latest matching Aura row hash and matching-row count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuraSource {
    /// The fixed source name.
    pub name: AuraSourceName,
    /// Latest verified matching row hash, or null when no rows exist.
    pub head: Option<Digest32>,
    /// Zero iff head is null; otherwise 1..=2^53-1.
    pub entries: u64,
    /// Matching absence reason iff head is null; otherwise null.
    pub absence: Option<SourceAbsence>,
}

/// Read-only Aura counters and source commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuraStatus {
    /// Current sequence in 0..=2^53-1.
    pub sequence: u64,
    /// Current RFC 6962 root, encoded as lowercase SHA-256 hex.
    pub root: Digest32,
    /// Exactly `gate-ledger`, `kira-chain`, `code-chain`, in that order.
    pub sources: [AuraSource; 3],
}

/// Public Nostr identities and counters, with no private key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrStatus {
    /// Nonempty node npub of at most 128 UTF-8 bytes, or null.
    pub node_npub: Option<String>,
    /// Nonempty agent npub of at most 128 UTF-8 bytes, or null.
    pub agent_npub: Option<String>,
    /// Accepted witness count in 0..=2^53-1.
    pub witness_accepted: u64,
}

/// Public proposal-cell pin in the frozen v1 shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmStatus {
    /// Pinned module's SHA-256 digest.
    pub module_sha256: Digest32,
}

/// C4 exact `organs.reply` field set; no credential ids, session data, phrase or note text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgansReply {
    /// Required pending-approval count in 0..=2^53-1; first in UTF-16 wire key order.
    pub approvals_pending: u64,
    /// Public owner-binding counters.
    pub aumlok: AumlokStatus,
    /// Public retained-memory counters.
    pub kira: KiraStatus,
    /// Verified source commitments and counts.
    pub aura: AuraStatus,
    /// Public Nostr identities and witness count.
    pub nostr: NostrStatus,
    /// Pinned cell module digest.
    pub wasm: WasmStatus,
    /// Nonempty configured owner origin of at most 2,048 UTF-8 bytes.
    pub owner_origin: String,
}

/// C4 `accepted` means queued for the owner, never applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// Proposal whose review was queued.
    pub proposal_id: ProposalId,
}

/// The eight frozen C4 proposal outcome spellings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeState {
    /// `applied`: the gate observed completion of an authorized effect.
    Applied,
    /// `refused`: the proposal was refused.
    Refused,
    /// `expired`: the proposal expired.
    Expired,
    /// `retired`: an owner-authorized retirement completed.
    Retired,
    /// `incomplete`: completion could not be established.
    Incomplete,
    /// `failed`: applying failed.
    Failed,
    /// `conflict`: the expected state no longer matched.
    Conflict,
    /// `unknown`: no definitive outcome is available.
    Unknown,
}

/// C4 eventual proposal result; evidence of an outcome never grants another effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Proposal to which the outcome belongs.
    pub proposal_id: ProposalId,
    /// Closed outcome state.
    pub state: OutcomeState,
}

/// C4 usage counters; the broker owns spending and settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
    /// Input tokens in 0..=32,768.
    pub prompt_tokens: u32,
    /// Output tokens in 0..=32,768.
    pub completion_tokens: u32,
    /// Cost in millionths of a US dollar, 0..=2^53-1.
    pub cost_microusd: u64,
}

/// C4 non-streaming `model.reply`; nullable strings retain explicit JSON nulls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelReply {
    /// Literal model text, or null.
    pub content: Option<String>,
    /// Ordered function-call suggestions, never executions.
    pub tool_calls: Vec<ToolCall>,
    /// Provider finish reason, or null.
    pub finish_reason: Option<String>,
    /// Settled usage bounded by the C4 counter limits.
    pub usage: Usage,
    /// Final Aura receipt sequence in 1..=2^53-1.
    pub receipt_seq: u64,
}

/// C4 current allowed-target bytes and independently computed digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadReply {
    /// The same allowed target requested by `read`.
    pub target: String,
    /// SHA-256 over decoded target bytes.
    pub sha256: Digest32,
    /// Canonical padded base64, with at most 65,536 decoded bytes.
    pub bytes_b64: String,
}

/// Closed C4 recall-result vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecallResult {
    /// `found`: permitted matching text exists.
    Found,
    /// `empty`: no matching text exists.
    Empty,
    /// `undetermined`: a definitive recall result is unavailable.
    Undetermined,
}

/// A cited memory text item; its contents never become an instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallItem {
    /// Opaque note identifier preserved by the v1 codec.
    pub note_id: String,
    /// Permitted literal memory text.
    pub text: String,
    /// Save receipt sequence in 1..=2^53-1.
    pub cite_seq: u64,
}

/// C4 `recall` response; Kira owns access control and ranking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recall {
    /// Closed result state.
    pub result: RecallResult,
    /// Cited text, bounded by the containing frame.
    pub items: Vec<RecallItem>,
}

/// C4 stable refusal with literal next-step text; no payload is an executable instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusalReply {
    /// Registered `<organ>:<reason>` code; the codec refuses unregistered codes.
    pub code: Refusal,
    /// Literal human-readable next-step text.
    pub next: String,
}
