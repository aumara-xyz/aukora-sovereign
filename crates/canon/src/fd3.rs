// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direction-specific FD 3 contracts: v1 is exactly C4; additions require v2.
//! The supervisor alone reads this descriptor. No request executes a command or opens a socket.
//! The supervisor stamps every decoded Frame's provenance from the channel. Guest frames
//! claiming any source other than Auma refuse; Owner exists only at the signed-in session.
//! Stranger input is counted and never delivered to Auma. Session records persist on the
//! supervisor's side, separate from Kira's notes. FD 3 never transports the health map.

use crate::{
    codes,
    fd3_payloads::*,
    frame::{Frame, FrameId},
    json::{self, Value, ValueView},
    provenance::{Provenance, Source},
    session::*,
    Result,
};

mod v1;
mod v2;
pub(crate) mod wire;

/// Frozen C4 envelope version, retaining its exact four-field object layout.
pub const V1: u16 = 1;
/// Session and streaming additions use this envelope version.
pub const V2: u16 = 2;

/// Guest-to-supervisor operations; there is deliberately no catch-all operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// C4 v1 `propose`, available unchanged in v2.
    Propose(Propose),
    /// V2 static-site bundle proposal, including an explicitly absent target state.
    SitePropose(sites::SiteProposal),
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
            Self::SitePropose(_) => "sites.propose",
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
    /// Frozen v1 reply identifiers may be arbitrary strings, distinct from C7 random ids.
    LegacyAccepted {
        /// Exact legacy identifier; it conveys no authority.
        proposal_id: String,
    },
    /// C4 `outcome`: one of the eight closed proposal states.
    Outcome(Outcome),
    /// Frozen v1 outcome retaining an identifier outside the C7 hex32 grammar.
    LegacyOutcome {
        /// Exact legacy proposal identifier.
        proposal_id: String,
        /// The same closed outcome vocabulary.
        state: OutcomeState,
    },
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
            Self::Accepted(_) | Self::LegacyAccepted { .. } => "accepted",
            Self::Outcome(_) | Self::LegacyOutcome { .. } => "outcome",
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
            | Self::LegacyAccepted { .. }
            | Self::Outcome(_)
            | Self::LegacyOutcome { .. }
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
/// A required object that is null, an array or a scalar refuses `frame:not-object`;
/// this includes envelopes, bodies, cells, functions, parameters and object array
/// elements. Scalar and array type mismatches refuse `frame:invalid-field`.
/// Optional propose cell and memory quote may be omitted, but cannot be null;
/// an empty quote remains present. Nullable scalars retain explicit JSON null.
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
pub fn decode_request(payload: &[u8], ingress: Provenance) -> Result<Frame<Request>> {
    let (v, id, kind, value) = envelope(payload, &ingress, true)?;
    let body = parse_request(&kind, &value, &ingress)?;
    if v < body.minimum_version() {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    Ok(Frame {
        v,
        id,
        provenance: ingress,
        body,
    })
}

/// Encodes the exact schema validated by decode_request, including manually built values.
/// Refusal order, fixed field-check order and all bounds are identical to decoding.
/// Canonical object keys use C1 UTF-16 order; transport framing is handled separately.
/// Frame provenance is absent from v1 wire bytes and explicit in v2 wire bytes;
/// encoding a label never establishes that label's trust at the receiving boundary.
pub fn encode_request(frame: &Frame<Request>) -> Result<Vec<u8>> {
    check_outgoing(frame.v, frame.body.minimum_version())?;
    let bytes = encode_envelope(
        frame.v,
        &frame.id,
        frame.body.kind(),
        &frame.provenance,
        request_body(&frame.body)?,
    )?;
    decode_request(&bytes, frame.provenance.clone())?;
    Ok(bytes)
}

/// Decodes supervisor replies with the same envelope checks and precedence as decode_request.
///
/// V1 scalar/nested validation order is accepted proposal_id; outcome proposal_id,state;
/// model.reply content,finish_reason,receipt_seq then tool_calls,usage; usage
/// completion_tokens,cost_microusd,prompt_tokens; read.reply bytes_b64,sha256,target;
/// recall result then items, with cite_seq,note_id,text per item; refusal code,next;
/// status.reply bound,grant_id,grant_remaining,ready; memory.list.reply next,tier then items,
/// whose scalars are at,category,cite_seq,demoted_at,demoted_seq,note_id,text.
/// Required objects, including usage and object array elements, refuse
/// `frame:not-object` for every other JSON type; scalar or array type mismatches
/// refuse `frame:invalid-field`. Nullable scalar fields emit and accept JSON null.
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
pub fn decode_reply(payload: &[u8], ingress: Provenance) -> Result<Frame<Reply>> {
    let (v, id, kind, value) = envelope(payload, &ingress, false)?;
    let body = parse_reply(&kind, &value, &ingress)?;
    if v < body.minimum_version() {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    Ok(Frame {
        v,
        id,
        provenance: ingress,
        body,
    })
}

/// Serializes canonical reply bytes only after the same direction, version, schema,
/// refusal precedence, fixed body validation order and bounds as decode_reply.
/// Organs.reply emits required approvals_pending first in UTF-16 key order, before
/// aumlok, with the same u64 0..=2^53-1 bound; invalid values refuse `frame:invalid-field`.
/// V1 has no algorithm or provenance fields added to its frozen wire records.
pub fn encode_reply(frame: &Frame<Reply>) -> Result<Vec<u8>> {
    check_outgoing(frame.v, frame.body.minimum_version())?;
    let bytes = encode_envelope(
        frame.v,
        &frame.id,
        frame.body.kind(),
        &frame.provenance,
        reply_body(&frame.body)?,
    )?;
    decode_reply(&bytes, frame.provenance.clone())?;
    Ok(bytes)
}

pub(crate) fn request_body(request: &Request) -> Result<Value> {
    if request.minimum_version() == V1 {
        v1::request_body(request)
    } else {
        v2::request_body(request)
    }
}
pub(crate) fn reply_body(reply: &Reply) -> Result<Value> {
    if reply.minimum_version() == V1 {
        v1::reply_body(reply)
    } else {
        v2::reply_body(reply)
    }
}
pub(crate) fn parse_request(kind: &str, body: &Value, ingress: &Provenance) -> Result<Request> {
    if request_kind(kind) == Some(V1) {
        v1::parse_request(kind, body)
    } else {
        v2::parse_request(kind, body, ingress)
    }
}
pub(crate) fn parse_reply(kind: &str, body: &Value, ingress: &Provenance) -> Result<Reply> {
    if reply_kind(kind) == Some(V1) {
        v1::parse_reply(kind, body)
    } else {
        v2::parse_reply(kind, body, ingress)
    }
}
fn request_kind(kind: &str) -> Option<u16> {
    match kind {
        "sites.propose" => Some(V2),
        "propose" | "read" | "model.call" | "memory.put" | "memory.recall" | "memory.list"
        | "status" | "organs" => Some(V1),
        "model.start" | "model.cancel" | "session.create" | "session.open" | "session.list"
        | "session.append" | "session.flush" => Some(V2),
        _ => None,
    }
}
fn reply_kind(kind: &str) -> Option<u16> {
    match kind {
        "accepted" | "outcome" | "model.reply" | "read.reply" | "recall" | "refusal"
        | "memory.list.reply" | "status.reply" | "organs.reply" => Some(V1),
        "model.start" | "model.delta" | "model.end" | "model.error" | "model.cancel"
        | "session.create" | "session.open" | "session.list" | "session.append"
        | "session.flush" => Some(V2),
        _ => None,
    }
}
fn envelope(
    payload: &[u8],
    ingress: &Provenance,
    request: bool,
) -> Result<(u16, FrameId, String, Value)> {
    if payload.len() > crate::frame::MAX_FRAME_BYTES {
        return Err(codes::FRAME_TOO_LARGE);
    }
    let value = json::parse_strict(payload)?;
    if json::to_canonical(&value) != payload {
        return Err(codes::FRAME_NOT_CANONICAL);
    }
    let v2 = value
        .get("v")
        .is_some_and(|v| matches!(v.view(), ValueView::Integer(n) if n.get() == 2));
    let required = if v2 {
        &["body", "id", "kind", "provenance", "v"][..]
    } else {
        &["body", "id", "kind", "v"][..]
    };
    let fields = wire::Object::new(&value, required, &[])?;
    let version = match fields.get("v")?.view() {
        ValueView::Integer(n) => n.get(),
        _ => return Err(codes::FRAME_INVALID_FIELD),
    };
    if version != 1 && version != 2 {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    let id = FrameId::new(fields.text("id")?)?;
    let kind = fields.text("kind")?;
    let minimum = (if request {
        request_kind(&kind)
    } else {
        reply_kind(&kind)
    })
    .ok_or(codes::FRAME_UNKNOWN_KIND)?;
    if version < minimum as i64 {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    if (request && ingress.source != Source::Auma) || ingress.source == Source::Stranger {
        return Err(codes::FRAME_PROVENANCE);
    }
    if version == 2 {
        let claimed = parse_provenance(fields.get("provenance")?)?;
        if claimed != *ingress
            || (request && claimed.source != Source::Auma)
            || claimed.source == Source::Stranger
        {
            return Err(codes::FRAME_PROVENANCE);
        }
    }
    Ok((version as u16, id, kind, fields.get("body")?.clone()))
}
pub(crate) fn encode_envelope(
    v: u16,
    id: &FrameId,
    kind: &str,
    provenance: &Provenance,
    body: Value,
) -> Result<Vec<u8>> {
    let mut fields = vec![
        ("v", wire::n(v as u64)?),
        ("id", wire::s(id.as_str())),
        ("kind", wire::s(kind)),
        ("body", body),
    ];
    if v == 2 {
        fields.push(("provenance", provenance_body(provenance)?));
    }
    let bytes = json::to_canonical(&wire::object(fields)?);
    if bytes.len() > crate::frame::MAX_FRAME_BYTES {
        return Err(codes::FRAME_TOO_LARGE);
    }
    Ok(bytes)
}
pub(crate) fn provenance_body(provenance: &Provenance) -> Result<Value> {
    use crate::provenance::Source;
    let (source, mut fields) = match &provenance.source {
        Source::Owner => ("owner", vec![]),
        Source::Auma => ("auma", vec![]),
        Source::Document => ("document", vec![]),
        Source::Memory => ("memory", vec![]),
        Source::Stranger => ("stranger", vec![]),
        Source::App(id) => ("app", vec![("app_id", wire::s(id))]),
        Source::Contact(npub) => (
            "contact",
            vec![
                ("algorithm", wire::s(npub.algorithm().wire_name())),
                ("npub", wire::s(npub.as_str())),
            ],
        ),
    };
    fields.push(("source", wire::s(source)));
    wire::object(fields)
}
pub(crate) fn parse_provenance(value: &Value) -> Result<Provenance> {
    use crate::{alg::AlgorithmId, ids::AppId, provenance::Npub};
    let shape = wire::Object::new(value, &["source"], &["app_id", "algorithm", "npub"])?;
    let source = wire::text(shape.get("source")?)?;
    let names = match source {
        "app" => &["app_id", "source"][..],
        "contact" => &["algorithm", "npub", "source"][..],
        _ => &["source"][..],
    };
    let fields = wire::Object::new(value, names, &[])?;
    let source = match source {
        "owner" => Source::Owner,
        "auma" => Source::Auma,
        "document" => Source::Document,
        "memory" => Source::Memory,
        "stranger" => Source::Stranger,
        "app" => Source::App(
            AppId::from_hex(wire::text(fields.get("app_id")?)?)
                .map_err(|_| codes::FRAME_INVALID_FIELD)?,
        ),
        "contact" => Source::Contact(Npub::parse(
            AlgorithmId::from_wire(wire::text(fields.get("algorithm")?)?)?,
            wire::text(fields.get("npub")?)?,
        )?),
        _ => return Err(codes::FRAME_PROVENANCE),
    };
    Ok(Provenance { source })
}

pub(crate) fn session_entry_body(entry: &SessionEntry) -> Result<Value> {
    v2::entry_body(entry)
}
pub(crate) fn parse_session_entry(
    value: &Value,
    ingress: Option<&Provenance>,
) -> Result<SessionEntry> {
    v2::parse_entry(value, ingress)
}

fn check_outgoing(version: u16, minimum: u16) -> Result<()> {
    if version != V1 && version != V2 {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    if version < minimum {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    Ok(())
}
