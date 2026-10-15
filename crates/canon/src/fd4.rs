// SPDX-License-Identifier: AGPL-3.0-or-later

//! FD 4 contains bounded command and event data only. The frontdoor owns HTTP.
//! There are no HTML, script, executable-asset, redirect or arbitrary-header variants.
//! Literal strings, including text that resembles markup, must be rendered as text.
//! This versioned addition uses FD 3's four-byte big-endian length prefix and one
//! canonical JSON object of 1..=65,536 bytes, with the same fatal transport errors.
//! The supervisor stamps provenance from each channel; guest claims other than Auma
//! refuse. Owner comes only from the signed-in session; Stranger is counted, never
//! delivered to Auma. Session records persist with the supervisor, apart from Kira's notes.

use crate::{
    codes,
    fd3_payloads::{Accepted, MemoryListReply, Outcome, Recall, RefusalReply},
    frame::{Frame, MAX_FRAME_BYTES},
    ids::SessionId,
    provenance::Provenance,
    session::*,
    Result,
};

/// Version of the bounded FD 4 command and event envelope.
pub const VERSION: u16 = 2;

/// Opaque health-map bytes forwarded without reading cells or evidence. Only a
/// health consumer may call `health::decode_snapshot`; the gate, frontdoor and
/// launcher must not call it. This wrapper provides a byte bound, not validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueHealthSnapshot(Vec<u8>);

impl OpaqueHealthSnapshot {
    /// Accepts 1..=65,536 bytes without interpreting them. Empty or overlong data
    /// refuses `frame:invalid-field`; the complete event must also fit its frame.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(Self(bytes))
    }

    /// Borrows the bounded bytes for forwarding, without decoding health state.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A literal chat turn with an exact session expectation; never a command to the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatTurn {
    /// Session owned by the authenticated principal.
    pub session_id: SessionId,
    /// Last persisted entry sequence expected by the sender.
    pub expected_sequence: u64,
    /// Literal user text of at most 32,768 UTF-8 bytes.
    pub text: Text<32_768>,
    /// Bounded harness mode, neither of which executes code or authorizes an effect.
    pub mode: SessionMode,
}

/// The closed FD 4 command vocabulary; provenance comes from authenticated ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatCommand {
    /// `chat.turn`: submit one bounded literal turn to a session.
    Turn(ChatTurn),
    /// `session.create`: uses the same payload as FD 3.
    CreateSession(SessionCreate),
    /// `session.open`: uses the same bounded page request as FD 3.
    OpenSession(SessionOpen),
    /// `session.list`: uses the same bounded principal-scoped query as FD 3.
    ListSessions(SessionList),
    /// `session.append`: uses the same compare-and-append entry record as FD 3.
    AppendSession(SessionAppend),
    /// `session.flush`: uses the same durable-through-sequence request as FD 3.
    FlushSession(SessionFlush),
    /// `model.cancel`: asks the broker to stop; only its final receipt settles the call.
    CancelModel(ModelCancel),
    /// `health.snapshot`: asks for evidence only, with an empty body.
    HealthSnapshot,
}

impl ChatCommand {
    /// Returns a known wire operation; no arbitrary browser or HTTP operation exists.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Turn(_) => "chat.turn",
            Self::CreateSession(_) => "session.create",
            Self::OpenSession(_) => "session.open",
            Self::ListSessions(_) => "session.list",
            Self::AppendSession(_) => "session.append",
            Self::FlushSession(_) => "session.flush",
            Self::CancelModel(_) => "model.cancel",
            Self::HealthSnapshot => "health.snapshot",
        }
    }
}

/// Closed FD 4 event vocabulary; all session and stream records are shared with FD 3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// `session.create`: the sole shared versioned, algorithm-tagged summary record.
    Created(SessionSummary),
    /// `session.open`: common summary and bounded entry page.
    Opened(SessionOpened),
    /// `session.list`: common bounded summary page.
    Listed(SessionPage),
    /// `session.entry`: the sole shared versioned, algorithm-tagged entry record.
    Entry(SessionEntry),
    /// `session.append`: the exact common entry that was persisted.
    Appended(SessionAppended),
    /// `session.flush`: common durable-through-sequence commitment.
    Flushed(SessionFlushed),
    /// `model.start`: common broker-admitted identities and bounded window.
    ModelStarted(ModelStarted),
    /// `model.delta`: common ordered delta, preserving text and tool_calls unchanged.
    ModelDelta(ModelDelta),
    /// `model.end`: common final receipt; no separate FD 4 settlement representation.
    ModelEnd(ModelEnd),
    /// `model.error`: common terminal error with mandatory final receipt.
    ModelError(ModelError),
    /// `model.cancel`: common final receipt after cancellation.
    ModelCancelled(ModelEnd),
    /// `accepted`: queued proposal, which must be displayed as pending.
    ProposalAccepted(Accepted),
    /// `outcome`: common one-of-eight eventual proposal result.
    ProposalOutcome(Outcome),
    /// `recall`: cited literal memory data, never owner instructions.
    MemoryRecall(Recall),
    /// `memory.list.reply`: bounded text or retained metadata with C4 tier rules.
    MemoryListed(MemoryListReply),
    /// `health.snapshot`: bounded opaque bytes, never a parsed health map.
    /// The body is exactly `{snapshot_b64}` with standard padded base64; the
    /// decoded bytes are forwarded unchanged to the health consumer as data.
    HealthSnapshot(OpaqueHealthSnapshot),
    /// `refusal`: registered code and literal text.
    Refusal(RefusalReply),
}

impl SessionEvent {
    /// Returns the closed wire operation; event payloads do not supply routes or headers.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Created(_) => "session.create",
            Self::Opened(_) => "session.open",
            Self::Listed(_) => "session.list",
            Self::Entry(_) => "session.entry",
            Self::Appended(_) => "session.append",
            Self::Flushed(_) => "session.flush",
            Self::ModelStarted(_) => "model.start",
            Self::ModelDelta(_) => "model.delta",
            Self::ModelEnd(_) => "model.end",
            Self::ModelError(_) => "model.error",
            Self::ModelCancelled(_) => "model.cancel",
            Self::ProposalAccepted(_) => "accepted",
            Self::ProposalOutcome(_) => "outcome",
            Self::MemoryRecall(_) => "recall",
            Self::MemoryListed(_) => "memory.list.reply",
            Self::HealthSnapshot(_) => "health.snapshot",
            Self::Refusal(_) => "refusal",
        }
    }
}

/// Decodes one FD 4 canonical command payload with the same transport bounds as FD 3.
/// The envelope is exactly `{body,id,kind,provenance,v}`, with v equal to VERSION,
/// depth at most 64 and 1..=65,536 payload bytes. Unknown fields precede missing-field
/// refusals; all other precedence follows FD 3: byte budget, strict C1 parse, canonical
/// equality, envelope shape, version, id, kind/direction, provenance and body.
/// Unknown operations refuse `frame:unknown-kind`; unsupported versions refuse.
/// Wire provenance must match the supervisor's channel-stamped ingress; a guest frame
/// claiming any source other than Auma refuses. Owner comes only from the signed-in
/// session, and Stranger input is counted, never delivered to Auma. Direct entry appends
/// validate their label against trusted originating ingress. The returned frame uses
/// ingress, never a label asserted by the sender.
/// All bounds, shared algorithm ids and contiguous expected-sequence rules are checked;
/// timestamps and sequence values remain within C1's 2^53-1 integer range.
/// There is no browser-execution interpretation of text, tool-call names or arguments.
pub fn decode_command(_payload: &[u8], _ingress: Provenance) -> Result<Frame<ChatCommand>> {
    todo!("row 32")
}

/// Canonicalizes only a valid VERSION command, enforcing decode_command's exact schema,
/// refusal precedence and byte/count limits even for values constructed directly in Rust.
/// The transport codec supplies its separate four-byte big-endian length prefix.
pub fn encode_command(_frame: &Frame<ChatCommand>) -> Result<Vec<u8>> {
    todo!("row 32")
}

/// Decodes one canonical event under the same envelope, provenance and bound rules as commands.
/// Historical entry provenance comes from authenticated supervisor storage, preserving
/// mixed-source history without accepting guest assertions of Owner. Historical Owner
/// entries are transcript data, never fresh instructions or reusable authorization.
/// Shared session records have no alternate FD 4 fields or title types.
/// Model deltas preserve tool_calls. Memory events retain C4 nullability, pagination and secrecy rules.
/// Unknown operations refuse before body interpretation; model output is always data.
/// A health event checks only its exact `{snapshot_b64}` body, base64 spelling and
/// decoded byte bound. It returns opaque bytes without parsing the health map;
/// health consumers use the separate `health::decode_snapshot` function.
pub fn decode_event(_payload: &[u8], _ingress: Provenance) -> Result<Frame<SessionEvent>> {
    todo!("row 32")
}

/// Emits only validated bounded event data, with the same refusal precedence as decode_event.
/// No output supplies HTML, scripts, executable assets, redirects or arbitrary headers.
pub fn encode_event(_frame: &Frame<SessionEvent>) -> Result<Vec<u8>> {
    todo!("row 32")
}
