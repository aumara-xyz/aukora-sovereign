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
    fd3::{self, wire, Reply, Request},
    fd3_payloads::{Accepted, MemoryListReply, Outcome, OutcomeState, Recall, RefusalReply},
    frame::{Frame, FrameId, MAX_FRAME_BYTES},
    ids::SessionId,
    json::{Value, ValueView},
    provenance::{Provenance, Source},
    session::*,
    Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};

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
    /// `accepted`: preserves a frozen identifier outside the C7 random-id grammar.
    LegacyProposalAccepted {
        /// Exact legacy proposal identifier, with no authority attached.
        proposal_id: String,
    },
    /// `outcome`: common one-of-eight eventual proposal result.
    ProposalOutcome(Outcome),
    /// `outcome`: preserves a frozen identifier outside the C7 random-id grammar.
    LegacyProposalOutcome {
        /// Exact legacy proposal identifier.
        proposal_id: String,
        /// One of the same eight eventual proposal states.
        state: OutcomeState,
    },
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
            Self::ProposalAccepted(_) | Self::LegacyProposalAccepted { .. } => "accepted",
            Self::ProposalOutcome(_) | Self::LegacyProposalOutcome { .. } => "outcome",
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
pub fn decode_command(payload: &[u8], ingress: Provenance) -> Result<Frame<ChatCommand>> {
    let (id, kind, body) = envelope(payload, &ingress, true)?;
    let body = match kind.as_str() {
        "chat.turn" => {
            let fields = wire::Object::new(
                &body,
                &["session_id", "expected_sequence", "text", "mode"],
                &[],
            )?;
            ChatCommand::Turn(ChatTurn {
                session_id: SessionId::from_hex(wire::text(fields.get("session_id")?)?)
                    .map_err(|_| codes::FRAME_INVALID_FIELD)?,
                expected_sequence: fields.count("expected_sequence", 0, wire::MAX)?,
                text: Text::new(fields.text("text")?)?,
                mode: match wire::text(fields.get("mode")?)? {
                    "chat" => SessionMode::Chat,
                    "build" => SessionMode::Build,
                    _ => return Err(codes::FRAME_INVALID_FIELD),
                },
            })
        }
        "health.snapshot" => {
            wire::Object::new(&body, &[], &[])?;
            ChatCommand::HealthSnapshot
        }
        _ => match fd3::parse_request(&kind, &body, &ingress)? {
            Request::SessionCreate(value) => ChatCommand::CreateSession(value),
            Request::SessionOpen(value) => ChatCommand::OpenSession(value),
            Request::SessionList(value) => ChatCommand::ListSessions(value),
            Request::SessionAppend(value) => ChatCommand::AppendSession(value),
            Request::SessionFlush(value) => ChatCommand::FlushSession(value),
            Request::ModelCancel(value) => ChatCommand::CancelModel(value),
            _ => return Err(codes::FRAME_UNKNOWN_KIND),
        },
    };
    Ok(Frame {
        v: VERSION,
        id,
        provenance: ingress,
        body,
    })
}

/// Canonicalizes only a valid VERSION command, enforcing decode_command's exact schema,
/// refusal precedence and byte/count limits even for values constructed directly in Rust.
/// The transport codec supplies its separate four-byte big-endian length prefix.
pub fn encode_command(frame: &Frame<ChatCommand>) -> Result<Vec<u8>> {
    if frame.v != VERSION {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    let body = match &frame.body {
        ChatCommand::Turn(turn) => wire::object(vec![
            ("session_id", wire::s(turn.session_id)),
            ("expected_sequence", wire::n(turn.expected_sequence)?),
            ("text", wire::s(turn.text.as_str())),
            (
                "mode",
                wire::s(match turn.mode {
                    SessionMode::Chat => "chat",
                    SessionMode::Build => "build",
                }),
            ),
        ])?,
        ChatCommand::HealthSnapshot => wire::object(vec![])?,
        other => fd3::request_body(&match other {
            ChatCommand::CreateSession(value) => Request::SessionCreate(value.clone()),
            ChatCommand::OpenSession(value) => Request::SessionOpen(value.clone()),
            ChatCommand::ListSessions(value) => Request::SessionList(value.clone()),
            ChatCommand::AppendSession(value) => Request::SessionAppend(value.clone()),
            ChatCommand::FlushSession(value) => Request::SessionFlush(value.clone()),
            ChatCommand::CancelModel(value) => Request::ModelCancel(value.clone()),
            _ => return Err(codes::FRAME_UNKNOWN_KIND),
        })?,
    };
    let bytes = fd3::encode_envelope(
        frame.v,
        &frame.id,
        frame.body.kind(),
        &frame.provenance,
        body,
    )?;
    decode_command(&bytes, frame.provenance.clone())?;
    Ok(bytes)
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
pub fn decode_event(payload: &[u8], ingress: Provenance) -> Result<Frame<SessionEvent>> {
    let (id, kind, body) = envelope(payload, &ingress, false)?;
    let body = match kind.as_str() {
        "session.entry" => SessionEvent::Entry(fd3::parse_session_entry(&body, None)?),
        "health.snapshot" => {
            let fields = wire::Object::new(&body, &["snapshot_b64"], &[])?;
            let encoded = wire::text(fields.get("snapshot_b64")?)?;
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| codes::FRAME_INVALID_FIELD)?;
            if STANDARD.encode(&bytes) != encoded {
                return Err(codes::FRAME_INVALID_FIELD);
            }
            SessionEvent::HealthSnapshot(OpaqueHealthSnapshot::new(bytes)?)
        }
        _ => event_from_reply(fd3::parse_reply(&kind, &body, &ingress)?)?,
    };
    Ok(Frame {
        v: VERSION,
        id,
        provenance: ingress,
        body,
    })
}

/// Emits only validated bounded event data, with the same refusal precedence as decode_event.
/// No output supplies HTML, scripts, executable assets, redirects or arbitrary headers.
pub fn encode_event(frame: &Frame<SessionEvent>) -> Result<Vec<u8>> {
    if frame.v != VERSION {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    let body = match &frame.body {
        SessionEvent::Entry(entry) => fd3::session_entry_body(entry)?,
        SessionEvent::HealthSnapshot(snapshot) => wire::object(vec![(
            "snapshot_b64",
            wire::s(STANDARD.encode(snapshot.as_bytes())),
        )])?,
        other => fd3::reply_body(&event_as_reply(other)?)?,
    };
    let bytes = fd3::encode_envelope(
        frame.v,
        &frame.id,
        frame.body.kind(),
        &frame.provenance,
        body,
    )?;
    decode_event(&bytes, frame.provenance.clone())?;
    Ok(bytes)
}

fn envelope(
    payload: &[u8],
    ingress: &Provenance,
    command: bool,
) -> Result<(FrameId, String, Value)> {
    let value = crate::frame::decode(payload)?;
    let fields = wire::Object::new(&value, &["body", "id", "kind", "provenance", "v"], &[])?;
    match fields.get("v")?.view() {
        ValueView::Integer(version) if version.get() == i64::from(VERSION) => {}
        ValueView::Integer(_) => return Err(codes::FRAME_UNSUPPORTED_VERSION),
        _ => return Err(codes::FRAME_INVALID_FIELD),
    }
    let id = FrameId::new(fields.text("id")?)?;
    let kind = fields.text("kind")?;
    let known = if command {
        matches!(
            kind.as_str(),
            "chat.turn"
                | "session.create"
                | "session.open"
                | "session.list"
                | "session.append"
                | "session.flush"
                | "model.cancel"
                | "health.snapshot"
        )
    } else {
        matches!(
            kind.as_str(),
            "session.create"
                | "session.open"
                | "session.list"
                | "session.entry"
                | "session.append"
                | "session.flush"
                | "model.start"
                | "model.delta"
                | "model.end"
                | "model.error"
                | "model.cancel"
                | "accepted"
                | "outcome"
                | "recall"
                | "memory.list.reply"
                | "health.snapshot"
                | "refusal"
        )
    };
    if !known {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    if ingress.source == Source::Stranger
        || fd3::parse_provenance(fields.get("provenance")?)? != *ingress
    {
        return Err(codes::FRAME_PROVENANCE);
    }
    Ok((id, kind, fields.get("body")?.clone()))
}

fn event_from_reply(reply: Reply) -> Result<SessionEvent> {
    Ok(match reply {
        Reply::SessionCreated(value) => SessionEvent::Created(value),
        Reply::SessionOpened(value) => SessionEvent::Opened(value),
        Reply::SessionList(value) => SessionEvent::Listed(value),
        Reply::SessionAppended(value) => SessionEvent::Appended(value),
        Reply::SessionFlushed(value) => SessionEvent::Flushed(value),
        Reply::ModelStarted(value) => SessionEvent::ModelStarted(value),
        Reply::ModelDelta(value) => SessionEvent::ModelDelta(value),
        Reply::ModelEnd(value) => SessionEvent::ModelEnd(value),
        Reply::ModelError(value) => SessionEvent::ModelError(value),
        Reply::ModelCancelled(value) => SessionEvent::ModelCancelled(value),
        Reply::Accepted(value) => SessionEvent::ProposalAccepted(value),
        Reply::LegacyAccepted { proposal_id } => {
            SessionEvent::LegacyProposalAccepted { proposal_id }
        }
        Reply::Outcome(value) => SessionEvent::ProposalOutcome(value),
        Reply::LegacyOutcome { proposal_id, state } => {
            SessionEvent::LegacyProposalOutcome { proposal_id, state }
        }
        Reply::Recall(value) => SessionEvent::MemoryRecall(value),
        Reply::MemoryListReply(value) => SessionEvent::MemoryListed(value),
        Reply::Refusal(value) => SessionEvent::Refusal(value),
        _ => return Err(codes::FRAME_UNKNOWN_KIND),
    })
}

fn event_as_reply(event: &SessionEvent) -> Result<Reply> {
    Ok(match event {
        SessionEvent::Created(value) => Reply::SessionCreated(value.clone()),
        SessionEvent::Opened(value) => Reply::SessionOpened(value.clone()),
        SessionEvent::Listed(value) => Reply::SessionList(value.clone()),
        SessionEvent::Appended(value) => Reply::SessionAppended(value.clone()),
        SessionEvent::Flushed(value) => Reply::SessionFlushed(value.clone()),
        SessionEvent::ModelStarted(value) => Reply::ModelStarted(value.clone()),
        SessionEvent::ModelDelta(value) => Reply::ModelDelta(value.clone()),
        SessionEvent::ModelEnd(value) => Reply::ModelEnd(value.clone()),
        SessionEvent::ModelError(value) => Reply::ModelError(value.clone()),
        SessionEvent::ModelCancelled(value) => Reply::ModelCancelled(value.clone()),
        SessionEvent::ProposalAccepted(value) => Reply::Accepted(value.clone()),
        SessionEvent::LegacyProposalAccepted { proposal_id } => Reply::LegacyAccepted {
            proposal_id: proposal_id.clone(),
        },
        SessionEvent::ProposalOutcome(value) => Reply::Outcome(value.clone()),
        SessionEvent::LegacyProposalOutcome { proposal_id, state } => Reply::LegacyOutcome {
            proposal_id: proposal_id.clone(),
            state: *state,
        },
        SessionEvent::MemoryRecall(value) => Reply::Recall(value.clone()),
        SessionEvent::MemoryListed(value) => Reply::MemoryListReply(value.clone()),
        SessionEvent::Refusal(value) => Reply::Refusal(value.clone()),
        _ => return Err(codes::FRAME_UNKNOWN_KIND),
    })
}
