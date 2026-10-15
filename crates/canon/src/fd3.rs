// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direction-specific FD 3 contracts: v1 is exactly C4; additions require v2.
//! The supervisor alone reads this descriptor. No request executes a command or opens a socket.
//! The supervisor stamps every decoded Frame's provenance from the channel. Guest frames
//! claiming any source other than Auma refuse; Owner exists only at the signed-in session.
//! Stranger input is counted and never delivered to Auma. Session records persist on the
//! supervisor's side, separate from Kira's notes. FD 3 never transports the health map.

use crate::{fd3_payloads::*, frame::Frame, provenance::Provenance, session::*, Result};

/// Frozen C4 envelope version, retaining its exact four-field object layout.
pub const V1: u16 = 1;
/// Session and streaming additions use this envelope version.
pub const V2: u16 = 2;

/// Guest-to-supervisor operations; there is deliberately no catch-all operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// C4 v1 `propose`, available unchanged in v2.
    Propose(Propose),
    /// C4 v1 `read`, available unchanged in v2.
    Read(Read),
    /// C4 v1 non-streaming `model.call`, available unchanged in v2.
    ModelCall(ModelCall),
    /// C4 v1 `memory.put`, available unchanged in v2.
    MemoryPut(MemoryPut),
    /// C4 v1 `memory.recall`, available unchanged in v2.
    MemoryRecall(MemoryRecall),
    /// C4 v1 `memory.list`, available unchanged in v2.
    MemoryList(MemoryList),
    /// C4 v1 `status` with exactly an empty body object.
    Status,
    /// C4 v1 `organs` with exactly an empty body object.
    Organs,
    /// V2 `model.start`, admitting a single identified broker reservation.
    ModelStart(ModelStart),
    /// V2 `model.cancel`; cancellation still needs a final broker settlement receipt.
    ModelCancel(ModelCancel),
    /// V2 `session.create`.
    SessionCreate(SessionCreate),
    /// V2 `session.open`.
    SessionOpen(SessionOpen),
    /// V2 `session.list`.
    SessionList(SessionList),
    /// V2 `session.append`, requiring an exact expected sequence.
    SessionAppend(SessionAppend),
    /// V2 `session.flush`, requesting durable acknowledgement.
    SessionFlush(SessionFlush),
}

impl Request {
    /// Returns the closed wire spelling; the codec also enforces direction and version.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Propose(_) => "propose",
            Self::Read(_) => "read",
            Self::ModelCall(_) => "model.call",
            Self::MemoryPut(_) => "memory.put",
            Self::MemoryRecall(_) => "memory.recall",
            Self::MemoryList(_) => "memory.list",
            Self::Status => "status",
            Self::Organs => "organs",
            Self::ModelStart(_) => "model.start",
            Self::ModelCancel(_) => "model.cancel",
            Self::SessionCreate(_) => "session.create",
            Self::SessionOpen(_) => "session.open",
            Self::SessionList(_) => "session.list",
            Self::SessionAppend(_) => "session.append",
            Self::SessionFlush(_) => "session.flush",
        }
    }

    /// Returns 1 for frozen C4 operations and 2 for additions; unsupported versions refuse.
    pub const fn minimum_version(&self) -> u16 {
        match self {
            Self::Propose(_)
            | Self::Read(_)
            | Self::ModelCall(_)
            | Self::MemoryPut(_)
            | Self::MemoryRecall(_)
            | Self::MemoryList(_)
            | Self::Status
            | Self::Organs => V1,
            _ => V2,
        }
    }
}

/// Supervisor-to-guest operations, with the nine frozen C4 v1 replies preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// C4 `accepted`: queued for the owner, never authority to apply.
    Accepted(Accepted),
    /// C4 `outcome`: one of the eight closed proposal states.
    Outcome(Outcome),
    /// C4 `model.reply`: non-streaming completion and final receipt sequence.
    ModelReply(ModelReply),
    /// C4 `read.reply`: allowed-target bytes and digest.
    ReadReply(ReadReply),
    /// C4 `recall`: permitted cited text, never instructions.
    Recall(Recall),
    /// C4 `refusal`: registered stable code and literal next-step text.
    Refusal(RefusalReply),
    /// C4 `memory.list.reply`: bounded active text or retained demotion metadata.
    MemoryListReply(MemoryListReply),
    /// C4 `status.reply`: non-secret readiness and grant counters.
    StatusReply(StatusReply),
    /// C4 `organs.reply`: frozen non-secret field set and fixed Aura-source order.
    OrgansReply(OrgansReply),
    /// V2 `model.start`: broker-confirmed ids and bounded producer window.
    ModelStarted(ModelStarted),
    /// V2 `model.delta`: ordered text and function-call data.
    ModelDelta(ModelDelta),
    /// V2 `model.end`: one final settled receipt.
    ModelEnd(ModelEnd),
    /// V2 `model.error`: one final settled receipt for an admitted failed stream.
    ModelError(ModelError),
    /// V2 `model.cancel`: acknowledged cancellation with a final settled receipt.
    ModelCancelled(ModelEnd),
    /// V2 `session.create`: the common persisted summary.
    SessionCreated(SessionSummary),
    /// V2 `session.open`: the common summary and entry page.
    SessionOpened(SessionOpened),
    /// V2 `session.list`: the common bounded summary page.
    SessionList(SessionPage),
    /// V2 `session.append`: the exact persisted common entry.
    SessionAppended(SessionAppended),
    /// V2 `session.flush`: durable-through-sequence commitment.
    SessionFlushed(SessionFlushed),
}

impl Reply {
    /// Returns the closed wire spelling; replies correlate with the original envelope id.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Accepted(_) => "accepted",
            Self::Outcome(_) => "outcome",
            Self::ModelReply(_) => "model.reply",
            Self::ReadReply(_) => "read.reply",
            Self::Recall(_) => "recall",
            Self::Refusal(_) => "refusal",
            Self::MemoryListReply(_) => "memory.list.reply",
            Self::StatusReply(_) => "status.reply",
            Self::OrgansReply(_) => "organs.reply",
            Self::ModelStarted(_) => "model.start",
            Self::ModelDelta(_) => "model.delta",
            Self::ModelEnd(_) => "model.end",
            Self::ModelError(_) => "model.error",
            Self::ModelCancelled(_) => "model.cancel",
            Self::SessionCreated(_) => "session.create",
            Self::SessionOpened(_) => "session.open",
            Self::SessionList(_) => "session.list",
            Self::SessionAppended(_) => "session.append",
            Self::SessionFlushed(_) => "session.flush",
        }
    }

    /// Returns the oldest envelope version permitted for this reply.
    pub const fn minimum_version(&self) -> u16 {
        match self {
            Self::Accepted(_)
            | Self::Outcome(_)
            | Self::ModelReply(_)
            | Self::ReadReply(_)
            | Self::Recall(_)
            | Self::Refusal(_)
            | Self::MemoryListReply(_)
            | Self::StatusReply(_)
            | Self::OrgansReply(_) => V1,
            _ => V2,
        }
    }
}

/// Decodes canonical JSON payload bytes after the length-prefixed transport accepts a frame.
///
/// Refusal precedence is observable: check the 65,536-byte budget, C1 strict parse,
/// exact canonical bytes, envelope object shape, v's type then supported value,
/// id's type then 1..=64 ASCII `[A-Za-z0-9_-]` bytes, kind's type then known
/// operation in this direction, v2 provenance, and finally its body. Every object rejects unknown
/// fields before reporting missing fields. Unknown kinds refuse `frame:unknown-kind`;
/// unknown versions refuse `frame:unsupported-version`; neither is guessed.
///
/// V1's envelope has exactly body,id,kind,v; provenance is trusted local metadata.
/// V2's envelope has exactly body,id,kind,provenance,v. The wire provenance must
/// agree with the supervisor's channel-stamped ingress label, which supplies the returned
/// Frame's provenance. A guest claim other than Auma refuses; Owner comes only from the
/// signed-in session. Stranger input is counted, never delivered. Guest content, roles
/// and embedded labels cannot claim Owner.
/// Body scalars are checked in UTF-16 field-name order before nested values in that
/// order; arrays check type, then elements in index order. Nullable values are scalar.
///
/// V1 request order is: propose base_sha256,new_bytes_b64,note,target then cell;
/// read target; model.call grant_id,max_output_tokens,model then messages,tools;
/// memory.put category,quote,statement then cell; memory.recall limit,query;
/// memory.list before,tier; before is null or a NoteId of 1..=128 UTF-8 bytes
/// without control characters. Invalid handles refuse `frame:invalid-field`.
/// Status and organs accept only empty objects. `health.snapshot` is unknown on FD 3.
/// Message order is content,role,tool_call_id then tool_calls. A tool or tool call
/// checks its fixed `type:"function"` (and call id first), then the function object;
/// declaration fields are description,name then parameters, which must be an object;
/// call fields are arguments,name. Cell fields are effect_sha256,input_sha256,module_sha256.
///
/// C4 counts obey 2^53-1; output cap is 1..=32,768, recall limit 1..=100;
/// digests require exactly 64 lowercase hex; base64 requires canonical padded RFC 4648
/// with zero pad bits and at most 65,536 decoded bytes. The entire JSON payload remains
/// 1..=65,536 bytes and depth at most 64. Additions enforce their documented record
/// versions, algorithm ids, bounds and sequence arithmetic. Directly appended entries
/// require provenance established by their trusted originating ingress. Historical
/// entry labels in authenticated supervisor read replies come from trusted storage,
/// and never from guest assertions; mixed-source history retains its original labels.
/// Historical Owner entries remain transcript data, never new instructions or reusable
/// authorization. A direct Owner append needs live authenticated originating ingress.
pub fn decode_request(_payload: &[u8], _ingress: Provenance) -> Result<Frame<Request>> {
    todo!("row 32")
}

/// Encodes the exact schema validated by decode_request, including manually built values.
/// Refusal order, fixed field-check order and all bounds are identical to decoding.
/// Canonical object keys use C1 UTF-16 order; transport framing is handled separately.
/// Frame provenance is absent from v1 wire bytes and explicit in v2 wire bytes;
/// encoding a label never establishes that label's trust at the receiving boundary.
pub fn encode_request(_frame: &Frame<Request>) -> Result<Vec<u8>> {
    todo!("row 32")
}

/// Decodes supervisor replies with the same envelope checks and precedence as decode_request.
///
/// V1 scalar/nested validation order is accepted proposal_id; outcome proposal_id,state;
/// model.reply content,finish_reason,receipt_seq then tool_calls,usage; usage
/// completion_tokens,cost_microusd,prompt_tokens; read.reply bytes_b64,sha256,target;
/// recall result then items, with cite_seq,note_id,text per item; refusal code,next;
/// status.reply bound,grant_id,grant_remaining,ready; memory.list.reply next,tier then items,
/// whose scalars are at,category,cite_seq,demoted_at,demoted_seq,note_id,text.
/// Memory-list before, next and note_id share the NoteId bound of 1..=128 UTF-8 bytes
/// without control characters; only before and next admit null. Invalid handles
/// refuse `frame:invalid-field`.
///
/// Organs.reply has exactly approvals_pending,aumlok,aura,kira,nostr,owner_origin,wasm
/// in C1 UTF-16 key order. approvals_pending is required u64 in 0..=2^53-1, checked
/// first, followed by owner_origin before nested objects. A missing approvals_pending
/// refuses `frame:missing-field`; negative, string, boolean or null values refuse
/// `frame:invalid-field`. Nested order is aumlok,aura,kira,nostr,wasm, with
/// aumlok bound,passkeys,refresh_due; aura root,sequence then sources;
/// kira demoted,notes; nostr agent_npub,node_npub,witness_accepted; wasm module_sha256.
/// Its source array is exactly gate-ledger,kira-chain,code-chain. Each source checks
/// absence,entries,head,name and enforces matching empty code with zero count/null head,
/// or a verified digest with positive count/null absence. Empty codes are respectively
/// gate-ledger-empty,kira-ledger-empty,code-record-missing. Npubs are null or 1..=128
/// UTF-8 bytes; owner_origin is 1..=2,048 UTF-8 bytes; counts are 0..=2^53-1.
///
/// Receipt and citation sequences are 1..=2^53-1; usage tokens are 0..=32,768;
/// cost and grant remaining are 0..=2^53-1. Memory pages have at most 100 items,
/// newest save sequence first; category is 1..=64 ASCII `[A-Za-z0-9_-]` bytes.
/// Remembered requires text and null demotion fields; forgotten requires null text,
/// demoted_seq greater than cite_seq and a demotion time, never cold plaintext or keys.
/// Refusal codes must be registered, and the eight outcome states are closed.
/// These are semantic refusals; only fatal transport errors require stream closure.
pub fn decode_reply(_payload: &[u8], _ingress: Provenance) -> Result<Frame<Reply>> {
    todo!("row 32")
}

/// Serializes canonical reply bytes only after the same direction, version, schema,
/// refusal precedence, fixed body validation order and bounds as decode_reply.
/// Organs.reply emits required approvals_pending first in UTF-16 key order, before
/// aumlok, with the same u64 0..=2^53-1 bound; invalid values refuse `frame:invalid-field`.
/// V1 has no algorithm or provenance fields added to its frozen wire records.
pub fn encode_reply(_frame: &Frame<Reply>) -> Result<Vec<u8>> {
    todo!("row 32")
}
