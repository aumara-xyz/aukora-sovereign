// SPDX-License-Identifier: AGPL-3.0-or-later

//! Version 2 shared session and model-stream data used unchanged by FD 3 and FD 4.
//! Records describe observations; broker grants, passkey approval and settlement stay outside canon.
//! The supervisor persists session.* records on its side, separate from Kira's notes.
//! It stamps provenance from the channel: guest claims other than Auma refuse, Owner
//! comes only from the signed-in session, and Stranger input is counted, never delivered.

use crate::{
    alg::AlgorithmId,
    digest::Digest32,
    fd3_payloads::{ModelCall, ToolCall, Usage},
    ids::{RequestId, ReservationId, SessionId, ThreadId},
    provenance::Provenance,
    Refusal, Result,
};

/// Version of the added session and streaming record formats; old v1 bytes gain no authority.
pub const RECORD_VERSION: u16 = 2;
/// Largest number of unacknowledged model chunks permitted by the v2 codec.
pub const MAX_PENDING_CHUNKS: u16 = 16;
/// Maximum literal text bytes in one model delta.
pub const MAX_DELTA_BYTES: usize = 8_192;
/// Maximum entries or summaries in one session page, also limited by the frame byte budget.
pub const MAX_SESSION_PAGE: usize = 100;

/// UTF-8 text with a byte bound, always rendered literally rather than interpreted as markup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Text<const MAX: usize>(String);

impl<const MAX: usize> Text<MAX> {
    /// Refuses text longer than MAX bytes; empty text remains a legitimate data value.
    pub fn new(value: String) -> Result<Self> {
        if value.len() > MAX {
            return Err(Refusal::new("frame", "invalid-field"));
        }
        Ok(Self(value))
    }

    /// Returns the bounded literal UTF-8 value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A collection whose count is bounded independently of the enclosing frame's byte budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Items<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> Items<T, MAX> {
    /// Refuses more than MAX items; individual payloads still require codec validation.
    pub fn new(values: Vec<T>) -> Result<Self> {
        if values.len() > MAX {
            return Err(Refusal::new("frame", "invalid-field"));
        }
        Ok(Self(values))
    }

    /// Returns the bounded ordered collection without permitting insertion.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

/// Harness mode; neither mode executes commands, opens sockets, or authorizes an effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMode {
    /// Wire spelling `chat`; conversation only.
    Chat,
    /// Wire spelling `build`; may also propose inert changes to the gate.
    Build,
}

/// Closed session-entry role; a role never substitutes for ingress-assigned provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRole {
    /// `owner` labels a message whose provenance must independently be Owner.
    Owner,
    /// `auma` labels untrusted model output.
    Auma,
    /// `tool` labels inert tool-result data.
    Tool,
    /// `context` labels imported context without instructional authority.
    Context,
}

/// The sole session-summary record for FD 3, FD 4 and storage; v and algorithm travel together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    /// Exactly RECORD_VERSION for this layout.
    pub v: u16,
    /// Commitment algorithm; v2 requires Sha256 and refuses unknown or incompatible ids.
    pub algorithm: AlgorithmId,
    /// Stable session identifier.
    pub session_id: SessionId,
    /// Parent thread identifier.
    pub thread_id: ThreadId,
    /// Literal title of at most 256 UTF-8 bytes.
    pub title: Text<256>,
    /// Current bounded harness mode.
    pub mode: SessionMode,
    /// Whether the session is in the archived collection.
    pub archived: bool,
    /// Last persisted entry sequence, initially zero, at most 2^53-1.
    pub sequence: u64,
    /// Informational creation time in milliseconds, 0..=2^53-1.
    pub created_at_ms: u64,
    /// Informational update time in milliseconds, 0..=2^53-1.
    pub updated_at_ms: u64,
}

/// The sole stored and transported entry record, shared by both descriptors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEntry {
    /// Exactly RECORD_VERSION.
    pub v: u16,
    /// Entry-commitment algorithm; v2 requires Sha256.
    pub algorithm: AlgorithmId,
    /// Session receiving this entry.
    pub session_id: SessionId,
    /// Contiguous persisted sequence in 1..=2^53-1.
    pub sequence: u64,
    /// Display role, checked against independently assigned provenance.
    pub role: SessionRole,
    /// Literal data only, at most 32,768 UTF-8 bytes.
    pub content: Text<32_768>,
    /// At most 32 function-call suggestions; never execution requests.
    pub tool_calls: Items<ToolCall, 32>,
    /// Optional correlated tool call identifier, at most 128 UTF-8 bytes.
    pub tool_call_id: Option<Text<128>>,
    /// Trusted originating ingress label; historical Owner entries are transcript data,
    /// never a fresh instruction or replayed authorization. Wire claims cannot promote to Owner.
    pub provenance: Provenance,
    /// Informational milliseconds in 0..=2^53-1; sequence determines order.
    pub at_ms: u64,
    /// Commitment over the canonical entry data, under algorithm.
    pub commitment: Digest32,
}

/// Version 2 `session.create` input; the supervisor assigns the session id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCreate {
    /// Existing or freshly created thread to which this session belongs.
    pub thread_id: ThreadId,
    /// Literal bounded title.
    pub title: Text<256>,
    /// Requested conversation mode; no authority is conveyed.
    pub mode: SessionMode,
}

/// Version 2 `session.open`, with an optional bounded entry-page cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOpen {
    /// Session belonging to the authenticated principal.
    pub session_id: SessionId,
    /// Entries strictly after this sequence, initially zero.
    pub after_sequence: u64,
    /// Page count in 1..=100, also limited by the enclosing frame size.
    pub limit: u16,
}

/// Version 2 `session.list`, scoped by the supervisor to the current principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionList {
    /// Optional thread filter.
    pub thread_id: Option<ThreadId>,
    /// Whether archived sessions are included.
    pub include_archived: bool,
    /// Opaque last-session cursor, or none for the first page.
    pub before: Option<SessionId>,
    /// Page count in 1..=100.
    pub limit: u16,
}

/// Version 2 `session.append`; the storage owner must compare sequence atomically before writing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionAppend {
    /// Session whose current sequence must match expected_sequence.
    pub session_id: SessionId,
    /// Exact last persisted sequence; mismatch refuses without partial append.
    pub expected_sequence: u64,
    /// Entry for this session at expected_sequence + 1; provenance is validated at live
    /// authenticated originating ingress, never inferred from a retrieved transcript.
    pub entry: SessionEntry,
}

/// Version 2 `session.flush`; acknowledgement proves durable storage only through the named sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionFlush {
    /// Session whose acknowledged entries are to be flushed.
    pub session_id: SessionId,
    /// Required persisted sequence in 0..=2^53-1.
    pub through_sequence: u64,
}

/// Version 2 session-open response wrapping the same records FD 4 uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionOpened {
    /// Current shared summary.
    pub summary: SessionSummary,
    /// Ordered contiguous shared entry records, bounded in count and frame bytes.
    pub entries: Items<SessionEntry, MAX_SESSION_PAGE>,
    /// Last returned sequence if another page exists, otherwise none.
    pub next_sequence: Option<u64>,
}

/// Version 2 bounded session-list page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionPage {
    /// Shared summaries, all scoped to the authenticated principal.
    pub items: Items<SessionSummary, MAX_SESSION_PAGE>,
    /// Last returned session id when more exist.
    pub next: Option<SessionId>,
}

/// Version 2 acknowledgement of one successful compare-and-append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionAppended {
    /// Exact shared entry record retained by storage.
    pub entry: SessionEntry,
}

/// Versioned, algorithm-tagged durable-session receipt; evidence never authorizes an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionFlushed {
    /// Exactly RECORD_VERSION.
    pub v: u16,
    /// Session commitment algorithm, Sha256 in v2.
    pub algorithm: AlgorithmId,
    /// Flushed session.
    pub session_id: SessionId,
    /// Last durable entry sequence in 0..=2^53-1.
    pub sequence: u64,
    /// Commitment to those exact persisted entry bytes.
    pub commitment: Digest32,
}

/// Version 2 `model.start`; one broker-admitted reservation, with no implicit retries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelStart {
    /// Stable idempotency key for this model request.
    pub request_id: RequestId,
    /// Reservation that the broker must bind to this exact request and grant.
    pub reservation_id: ReservationId,
    /// The same model-call data schema as v1.
    pub call: ModelCall,
    /// Requested producer window in 1..=MAX_PENDING_CHUNKS; full windows stop production.
    pub max_pending_chunks: u16,
}

/// Broker-confirmed start identity and bounded producer window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelStarted {
    /// Admitted request id.
    pub request_id: RequestId,
    /// Sole broker reservation for the request.
    pub reservation_id: ReservationId,
    /// Broker-approved window in 1..=MAX_PENDING_CHUNKS.
    pub max_pending_chunks: u16,
}

/// Sole versioned delta record shared by FD 3 and FD 4, including function-call data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelDelta {
    /// Exactly RECORD_VERSION.
    pub v: u16,
    /// Stream commitment algorithm, Sha256 in v2.
    pub algorithm: AlgorithmId,
    /// Request whose stream emitted the chunk.
    pub request_id: RequestId,
    /// Broker reservation to which every stream frame is bound.
    pub reservation_id: ReservationId,
    /// Zero-based exact next chunk index; duplicates, gaps and reordering refuse.
    pub index: u64,
    /// Optional literal model text, bounded by MAX_DELTA_BYTES.
    pub content: Option<Text<MAX_DELTA_BYTES>>,
    /// At most 32 inert function-call suggestions, preserved by FD 4.
    pub tool_calls: Items<ToolCall, 32>,
}

/// Versioned final broker receipt, present on success, failure and cancellation after admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelReceipt {
    /// Exactly RECORD_VERSION.
    pub v: u16,
    /// Receipt commitment algorithm, Sha256 in v2.
    pub algorithm: AlgorithmId,
    /// Settled request identity.
    pub request_id: RequestId,
    /// Reservation settled exactly once by the broker, never by this data type.
    pub reservation_id: ReservationId,
    /// Identity of the model that actually served the call, at most 256 UTF-8 bytes.
    pub model: Text<256>,
    /// Final bounded usage counters.
    pub usage: Usage,
    /// Aura settlement sequence in 1..=2^53-1.
    pub receipt_seq: u64,
    /// Commitment to the exact broker settlement record.
    pub commitment: Digest32,
}

/// Version 2 `model.end`; a final receipt closes the stream once, without authorizing an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelEnd {
    /// Request being closed; must equal the receipt identity.
    pub request_id: RequestId,
    /// Reservation being closed; must equal the receipt identity.
    pub reservation_id: ReservationId,
    /// Number of deltas accepted, exactly the next unused index.
    pub next_index: u64,
    /// Literal provider finish reason, or null.
    pub finish_reason: Option<Text<256>>,
    /// Mandatory final settled receipt.
    pub receipt: ModelReceipt,
}

/// Version 2 `model.error` for an admitted stream; pre-admission failures use ordinary refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelError {
    /// Failed request identity.
    pub request_id: RequestId,
    /// Failed reservation identity.
    pub reservation_id: ReservationId,
    /// Exact next unused chunk index at termination.
    pub next_index: u64,
    /// Registered stable refusal code.
    pub code: Refusal,
    /// Literal next-step text, at most 2,048 UTF-8 bytes.
    pub next: Text<2_048>,
    /// Mandatory settlement receipt even when no output was emitted.
    pub receipt: ModelReceipt,
}

/// Version 2 `model.cancel`; requesting cancellation never fabricates a settlement receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelCancel {
    /// Request to cancel.
    pub request_id: RequestId,
    /// Exact reservation bound to the request.
    pub reservation_id: ReservationId,
}

/// Bounded in-memory ordering validator only; it never authorizes or settles broker spending.
#[derive(Debug)]
pub struct ModelStream {
    request_id: RequestId,
    reservation_id: ReservationId,
    next_index: u64,
    first_pending: u64,
    window: u16,
    ended: bool,
}

impl ModelStream {
    /// Returns the admitted request identity; it is a correlation key, not authority.
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the bound reservation identity; the broker alone controls its spending.
    pub const fn reservation_id(&self) -> ReservationId {
        self.reservation_id
    }

    /// Returns the exact next unused zero-based chunk index.
    pub const fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Returns the first chunk index still waiting for local forwarding acknowledgement.
    pub const fn first_pending(&self) -> u64 {
        self.first_pending
    }

    /// Returns the negotiated bound on pending chunks.
    pub const fn window(&self) -> u16 {
        self.window
    }

    /// Reports whether a final receipt-bearing terminal frame has closed this validator.
    pub const fn is_ended(&self) -> bool {
        self.ended
    }

    /// Starts at index zero after validating the negotiated producer window and admitted ids.
    pub fn new(started: &ModelStarted) -> Result<Self> {
        if !(1..=MAX_PENDING_CHUNKS).contains(&started.max_pending_chunks) {
            return Err(crate::codes::FRAME_STREAM_LIMIT);
        }
        Ok(Self {
            request_id: started.request_id,
            reservation_id: started.reservation_id,
            next_index: 0,
            first_pending: 0,
            window: started.max_pending_chunks,
            ended: false,
        })
    }

    /// Requires matching ids, exact next index, an open stream and available window capacity.
    /// A full window refuses `broker:busy`; the producer waits rather than allocating unbounded data.
    pub fn observe_delta(&mut self, delta: &ModelDelta) -> Result<()> {
        self.check_position(delta.request_id, delta.reservation_id, delta.index)?;
        check_record(delta.v, delta.algorithm)?;
        if delta.index >= crate::json::MAX_SAFE_INTEGER as u64 {
            return Err(crate::codes::FRAME_STREAM_LIMIT);
        }
        if self.next_index - self.first_pending >= u64::from(self.window) {
            return Err(crate::codes::BROKER_BUSY);
        }
        self.next_index += 1;
        Ok(())
    }

    /// Releases already forwarded chunks through the given index, refusing future or backward acks.
    /// This local flow-control acknowledgement carries no spending or approval authority.
    pub fn acknowledge_through(&mut self, index: u64) -> Result<()> {
        if index < self.first_pending || index >= self.next_index {
            return Err(crate::codes::FRAME_STREAM_ORDER);
        }
        self.first_pending = index + 1;
        Ok(())
    }

    /// Closes once at the exact next index, with matching ids and a mandatory bound final receipt.
    pub fn observe_end(&mut self, end: &ModelEnd) -> Result<()> {
        self.check_position(end.request_id, end.reservation_id, end.next_index)?;
        self.check_receipt(&end.receipt)?;
        self.ended = true;
        Ok(())
    }

    /// Applies the same one-terminal, ordered and receipt-identity checks to an error termination.
    pub fn observe_error(&mut self, error: &ModelError) -> Result<()> {
        self.check_position(error.request_id, error.reservation_id, error.next_index)?;
        self.check_receipt(&error.receipt)?;
        crate::codes::parse(&error.code.to_string())?;
        self.ended = true;
        Ok(())
    }

    fn check_position(
        &self,
        request: RequestId,
        reservation: ReservationId,
        index: u64,
    ) -> Result<()> {
        if self.ended
            || request != self.request_id
            || reservation != self.reservation_id
            || index != self.next_index
        {
            return Err(crate::codes::FRAME_STREAM_ORDER);
        }
        Ok(())
    }

    fn check_receipt(&self, receipt: &ModelReceipt) -> Result<()> {
        check_record(receipt.v, receipt.algorithm)?;
        if receipt.request_id != self.request_id || receipt.reservation_id != self.reservation_id {
            return Err(crate::codes::FRAME_STREAM_ORDER);
        }
        if receipt.receipt_seq == 0
            || receipt.receipt_seq > crate::json::MAX_SAFE_INTEGER as u64
            || receipt.usage.prompt_tokens > 32_768
            || receipt.usage.completion_tokens > 32_768
            || receipt.usage.cost_microusd > crate::json::MAX_SAFE_INTEGER as u64
        {
            return Err(crate::codes::FRAME_STREAM_LIMIT);
        }
        Ok(())
    }
}

fn check_record(version: u16, algorithm: AlgorithmId) -> Result<()> {
    if version != RECORD_VERSION {
        return Err(crate::codes::FRAME_UNSUPPORTED_VERSION);
    }
    if algorithm != AlgorithmId::Sha256 {
        return Err(crate::codes::ALG_UNSUPPORTED);
    }
    Ok(())
}

pub mod presets {
    //! Read metadata for the compiled harness presets; it selects no runtime model.

    /// Describes a compiled preset without authorizing any operation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct CompiledPreset {
        /// The harness's closed preset identifier.
        pub id: &'static str,
        /// The validator's output ceiling, not a per-request token selection.
        pub max_output_tokens: u32,
        /// Closed operation names in the harness's order and spelling.
        pub operations: &'static [&'static str],
    }

    /// The guest asserts that these values match its compiled preset implementation.
    pub const COMPILED_PRESETS: [CompiledPreset; 2] = [
        CompiledPreset {
            id: "chat",
            max_output_tokens: 32_768,
            operations: &[
                "chat",
                "threads",
                "sessions",
                "streaming",
                "compaction",
                "memory.read",
            ],
        },
        CompiledPreset {
            id: "build",
            max_output_tokens: 32_768,
            operations: &[
                "chat",
                "threads",
                "sessions",
                "streaming",
                "compaction",
                "proposals",
                "memory.read",
                "memory.propose",
            ],
        },
    ];
}
