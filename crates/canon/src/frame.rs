// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{canonical_json, codes, parse, Error, Value, MAX_SAFE_INTEGER};

pub const MAX_FRAME_BYTES: usize = 65_536;
pub const MAX_ORGAN_NPUB_BYTES: usize = 128;
pub const MAX_OWNER_ORIGIN_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Guest,
    Supervisor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub v: i64,
    pub id: String,
    pub body: FrameBody,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameBody {
    Propose(Propose),
    Read(Read),
    ModelCall(ModelCall),
    MemoryPut(MemoryPut),
    MemoryRecall(MemoryRecall),
    MemoryList(MemoryList),
    MemoryListReply(MemoryListReply),
    Status(Status),
    StatusReply(StatusReply),
    Organs(Organs),
    OrgansReply(OrgansReply),
    Accepted(Accepted),
    Outcome(Outcome),
    ModelReply(ModelReply),
    ReadReply(ReadReply),
    Recall(Recall),
    Refusal(Refusal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub module_sha256: String,
    pub input_sha256: String,
    pub effect_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Propose {
    pub target: String,
    pub base_sha256: String,
    pub new_bytes_b64: String,
    pub note: String,
    pub cell: Option<Cell>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub role: String,
    pub content: Option<String>,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub tool_call_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolFunction {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tool {
    pub function: ToolFunction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCallFunction {
    pub name: String,
    pub arguments: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub function: ToolCallFunction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelCall {
    pub grant_id: String,
    pub model: String,
    pub messages: Vec<Message>,
    pub tools: Vec<Tool>,
    pub max_output_tokens: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryPut {
    pub cell: Cell,
    pub statement: String,
    pub quote: Option<String>,
    pub category: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRecall {
    pub query: String,
    pub limit: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryTier {
    Remembered,
    Forgotten,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryList {
    pub tier: MemoryTier,
    pub before: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryListItem {
    pub note_id: String,
    pub category: String,
    pub at: i64,
    pub cite_seq: i64,
    pub text: Option<String>,
    pub demoted_seq: Option<i64>,
    pub demoted_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryListReply {
    pub tier: MemoryTier,
    pub items: Vec<MemoryListItem>,
    pub next: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReply {
    pub ready: bool,
    pub bound: bool,
    pub grant_id: Option<String>,
    pub grant_remaining: Option<i64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Organs;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AumlokOrgans {
    pub bound: bool,
    pub passkeys: i64,
    pub refresh_due: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KiraOrgans {
    pub notes: i64,
    pub demoted: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuraOrgans {
    pub sequence: i64,
    pub root: String,
    pub sources: Box<[AuraSource; 3]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuraSource {
    pub name: String,
    pub head: Option<String>,
    pub entries: i64,
    pub absence: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrOrgans {
    pub node_npub: Option<String>,
    pub agent_npub: Option<String>,
    pub witness_accepted: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmOrgans {
    pub module_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgansReply {
    pub approvals_pending: i64,
    pub aumlok: AumlokOrgans,
    pub kira: KiraOrgans,
    pub aura: AuraOrgans,
    pub nostr: NostrOrgans,
    pub wasm: WasmOrgans,
    pub owner_origin: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub proposal_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeState {
    Applied,
    Refused,
    Expired,
    Retired,
    Incomplete,
    Failed,
    Conflict,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub proposal_id: String,
    pub state: OutcomeState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cost_microusd: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelReply {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: Option<String>,
    pub usage: Usage,
    pub receipt_seq: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadReply {
    pub target: String,
    pub sha256: String,
    pub bytes_b64: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecallResult {
    Found,
    Empty,
    Undetermined,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallItem {
    pub note_id: String,
    pub text: String,
    pub cite_seq: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recall {
    pub result: RecallResult,
    pub items: Vec<RecallItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: String,
    pub next: String,
}

/// Decode a frame only in the explicitly selected authority direction.
pub fn decode_frame(input: &[u8], direction: Direction) -> Result<Frame, Error> {
    if input.len() > MAX_FRAME_BYTES {
        return Err(error(codes::FRAME_TOO_LARGE));
    }
    let value = parse(input)?;
    if canonical_json(&value)? != input {
        return Err(error(codes::FRAME_NOT_CANONICAL));
    }
    let envelope = object(
        &value,
        &["body", "id", "kind", "v"],
        &["body", "id", "kind", "v"],
    )?;
    let version = integer(field(envelope, "v")?)?;
    if version != 1 {
        return Err(error(codes::FRAME_UNSUPPORTED_VERSION));
    }
    let id = owned_string(envelope, "id")?;
    if !valid_id(&id) {
        return Err(error(codes::FRAME_INVALID_ID));
    }
    let kind = string(field(envelope, "kind")?)?;
    let body = decode_body(kind, field(envelope, "body")?, direction)?;
    Ok(Frame {
        v: version,
        id,
        body,
    })
}

pub fn decode_guest_frame(input: &[u8]) -> Result<Frame, Error> {
    decode_frame(input, Direction::Guest)
}

pub fn decode_supervisor_frame(input: &[u8]) -> Result<Frame, Error> {
    decode_frame(input, Direction::Supervisor)
}

/// Encoding checks the same schema and budgets as decoding, including typed
/// values manually constructed by a caller.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, Error> {
    let value = object_value(vec![
        ("v", Value::Integer(frame.v)),
        ("id", string_value(&frame.id)),
        ("kind", string_value(frame.body.kind())),
        ("body", frame.body.to_value()),
    ]);
    let output = canonical_json(&value)?;
    decode_frame(&output, frame.body.direction())?;
    Ok(output)
}

impl FrameBody {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Propose(_) => "propose",
            Self::Read(_) => "read",
            Self::ModelCall(_) => "model.call",
            Self::MemoryPut(_) => "memory.put",
            Self::MemoryRecall(_) => "memory.recall",
            Self::MemoryList(_) => "memory.list",
            Self::MemoryListReply(_) => "memory.list.reply",
            Self::Status(_) => "status",
            Self::StatusReply(_) => "status.reply",
            Self::Organs(_) => "organs",
            Self::OrgansReply(_) => "organs.reply",
            Self::Accepted(_) => "accepted",
            Self::Outcome(_) => "outcome",
            Self::ModelReply(_) => "model.reply",
            Self::ReadReply(_) => "read.reply",
            Self::Recall(_) => "recall",
            Self::Refusal(_) => "refusal",
        }
    }

    pub const fn direction(&self) -> Direction {
        match self {
            Self::Propose(_)
            | Self::Read(_)
            | Self::ModelCall(_)
            | Self::MemoryPut(_)
            | Self::MemoryRecall(_)
            | Self::MemoryList(_)
            | Self::Status(_)
            | Self::Organs(_) => Direction::Guest,
            _ => Direction::Supervisor,
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Propose(b) => {
                let mut fields = vec![
                    ("target", string_value(&b.target)),
                    ("base_sha256", string_value(&b.base_sha256)),
                    ("new_bytes_b64", string_value(&b.new_bytes_b64)),
                    ("note", string_value(&b.note)),
                ];
                if let Some(cell) = &b.cell {
                    fields.push(("cell", cell.to_value()));
                }
                object_value(fields)
            }
            Self::Read(b) => object_value(vec![("target", string_value(&b.target))]),
            Self::ModelCall(b) => object_value(vec![
                ("grant_id", string_value(&b.grant_id)),
                ("model", string_value(&b.model)),
                ("messages", array_value(&b.messages, Message::to_value)),
                ("tools", array_value(&b.tools, Tool::to_value)),
                ("max_output_tokens", Value::Integer(b.max_output_tokens)),
            ]),
            Self::MemoryPut(b) => {
                let mut fields = vec![
                    ("cell", b.cell.to_value()),
                    ("statement", string_value(&b.statement)),
                    ("category", string_value(&b.category)),
                ];
                if let Some(quote) = &b.quote {
                    fields.push(("quote", string_value(quote)));
                }
                object_value(fields)
            }
            Self::MemoryRecall(b) => object_value(vec![
                ("query", string_value(&b.query)),
                ("limit", Value::Integer(b.limit)),
            ]),
            Self::MemoryList(b) => object_value(vec![
                ("before", nullable_string_value(&b.before)),
                ("tier", string_value(b.tier.as_str())),
            ]),
            Self::MemoryListReply(b) => object_value(vec![
                ("items", array_value(&b.items, MemoryListItem::to_value)),
                ("next", nullable_string_value(&b.next)),
                ("tier", string_value(b.tier.as_str())),
            ]),
            Self::Status(_) | Self::Organs(_) => object_value(vec![]),
            Self::OrgansReply(b) => b.to_value(),
            Self::StatusReply(b) => object_value(vec![
                ("ready", Value::Bool(b.ready)),
                ("bound", Value::Bool(b.bound)),
                ("grant_id", nullable_string_value(&b.grant_id)),
                (
                    "grant_remaining",
                    b.grant_remaining.map_or(Value::Null, Value::Integer),
                ),
            ]),
            Self::Accepted(b) => object_value(vec![("proposal_id", string_value(&b.proposal_id))]),
            Self::Outcome(b) => object_value(vec![
                ("proposal_id", string_value(&b.proposal_id)),
                ("state", string_value(b.state.as_str())),
            ]),
            Self::ModelReply(b) => object_value(vec![
                ("content", nullable_string_value(&b.content)),
                ("tool_calls", array_value(&b.tool_calls, ToolCall::to_value)),
                ("finish_reason", nullable_string_value(&b.finish_reason)),
                ("usage", b.usage.to_value()),
                ("receipt_seq", Value::Integer(b.receipt_seq)),
            ]),
            Self::ReadReply(b) => object_value(vec![
                ("target", string_value(&b.target)),
                ("sha256", string_value(&b.sha256)),
                ("bytes_b64", string_value(&b.bytes_b64)),
            ]),
            Self::Recall(b) => object_value(vec![
                ("result", string_value(b.result.as_str())),
                ("items", array_value(&b.items, RecallItem::to_value)),
            ]),
            Self::Refusal(b) => object_value(vec![
                ("code", string_value(&b.code)),
                ("next", string_value(&b.next)),
            ]),
        }
    }
}

impl OrgansReply {
    fn to_value(&self) -> Value {
        object_value(vec![
            ("approvals_pending", Value::Integer(self.approvals_pending)),
            (
                "aumlok",
                object_value(vec![
                    ("bound", Value::Bool(self.aumlok.bound)),
                    ("passkeys", Value::Integer(self.aumlok.passkeys)),
                    ("refresh_due", Value::Bool(self.aumlok.refresh_due)),
                ]),
            ),
            (
                "kira",
                object_value(vec![
                    ("notes", Value::Integer(self.kira.notes)),
                    ("demoted", Value::Integer(self.kira.demoted)),
                ]),
            ),
            (
                "aura",
                object_value(vec![
                    ("sequence", Value::Integer(self.aura.sequence)),
                    ("root", string_value(&self.aura.root)),
                    (
                        "sources",
                        array_value(self.aura.sources.as_ref(), AuraSource::to_value),
                    ),
                ]),
            ),
            (
                "nostr",
                object_value(vec![
                    ("node_npub", nullable_string_value(&self.nostr.node_npub)),
                    ("agent_npub", nullable_string_value(&self.nostr.agent_npub)),
                    (
                        "witness_accepted",
                        Value::Integer(self.nostr.witness_accepted),
                    ),
                ]),
            ),
            (
                "wasm",
                object_value(vec![(
                    "module_sha256",
                    string_value(&self.wasm.module_sha256),
                )]),
            ),
            ("owner_origin", string_value(&self.owner_origin)),
        ])
    }
}

impl AuraSource {
    fn to_value(&self) -> Value {
        object_value(vec![
            ("name", string_value(&self.name)),
            ("head", nullable_string_value(&self.head)),
            ("entries", Value::Integer(self.entries)),
            ("absence", nullable_string_value(&self.absence)),
        ])
    }
}

impl MemoryListItem {
    fn to_value(&self) -> Value {
        object_value(vec![
            ("at", Value::Integer(self.at)),
            ("category", string_value(&self.category)),
            ("cite_seq", Value::Integer(self.cite_seq)),
            (
                "demoted_at",
                self.demoted_at.map_or(Value::Null, Value::Integer),
            ),
            (
                "demoted_seq",
                self.demoted_seq.map_or(Value::Null, Value::Integer),
            ),
            ("note_id", string_value(&self.note_id)),
            ("text", nullable_string_value(&self.text)),
        ])
    }
}

impl MemoryTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Remembered => "remembered",
            Self::Forgotten => "forgotten",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "remembered" => Ok(Self::Remembered),
            "forgotten" => Ok(Self::Forgotten),
            _ => Err(error(codes::FRAME_INVALID_FIELD)),
        }
    }
}

impl Cell {
    fn to_value(&self) -> Value {
        object_value(vec![
            ("module_sha256", string_value(&self.module_sha256)),
            ("input_sha256", string_value(&self.input_sha256)),
            ("effect_sha256", string_value(&self.effect_sha256)),
        ])
    }
}
impl Message {
    fn to_value(&self) -> Value {
        let mut fields = vec![
            ("role", string_value(&self.role)),
            ("content", nullable_string_value(&self.content)),
        ];
        if let Some(calls) = &self.tool_calls {
            fields.push(("tool_calls", array_value(calls, ToolCall::to_value)));
        }
        if let Some(id) = &self.tool_call_id {
            fields.push(("tool_call_id", string_value(id)));
        }
        object_value(fields)
    }
}
impl Tool {
    fn to_value(&self) -> Value {
        object_value(vec![
            ("type", string_value("function")),
            (
                "function",
                object_value(vec![
                    ("name", string_value(&self.function.name)),
                    ("description", string_value(&self.function.description)),
                    ("parameters", self.function.parameters.clone()),
                ]),
            ),
        ])
    }
}
impl ToolCall {
    fn to_value(&self) -> Value {
        object_value(vec![
            ("id", string_value(&self.id)),
            ("type", string_value("function")),
            (
                "function",
                object_value(vec![
                    ("name", string_value(&self.function.name)),
                    ("arguments", string_value(&self.function.arguments)),
                ]),
            ),
        ])
    }
}
impl Usage {
    fn to_value(&self) -> Value {
        object_value(vec![
            ("prompt_tokens", Value::Integer(self.prompt_tokens)),
            ("completion_tokens", Value::Integer(self.completion_tokens)),
            ("cost_microusd", Value::Integer(self.cost_microusd)),
        ])
    }
}
impl RecallItem {
    fn to_value(&self) -> Value {
        object_value(vec![
            ("note_id", string_value(&self.note_id)),
            ("text", string_value(&self.text)),
            ("cite_seq", Value::Integer(self.cite_seq)),
        ])
    }
}
impl OutcomeState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Retired => "retired",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
            Self::Conflict => "conflict",
            Self::Unknown => "unknown",
        }
    }
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "applied" => Ok(Self::Applied),
            "refused" => Ok(Self::Refused),
            "expired" => Ok(Self::Expired),
            "retired" => Ok(Self::Retired),
            "incomplete" => Ok(Self::Incomplete),
            "failed" => Ok(Self::Failed),
            "conflict" => Ok(Self::Conflict),
            "unknown" => Ok(Self::Unknown),
            _ => Err(error(codes::FRAME_INVALID_FIELD)),
        }
    }
}
impl RecallResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::Empty => "empty",
            Self::Undetermined => "undetermined",
        }
    }
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "found" => Ok(Self::Found),
            "empty" => Ok(Self::Empty),
            "undetermined" => Ok(Self::Undetermined),
            _ => Err(error(codes::FRAME_INVALID_FIELD)),
        }
    }
}

fn decode_body(kind: &str, value: &Value, direction: Direction) -> Result<FrameBody, Error> {
    match (kind, direction) {
        ("propose", Direction::Guest) => decode_propose(value).map(FrameBody::Propose),
        ("read", Direction::Guest) => {
            let b = object(value, &["target"], &["target"])?;
            Ok(FrameBody::Read(Read {
                target: owned_string(b, "target")?,
            }))
        }
        ("model.call", Direction::Guest) => decode_model_call(value).map(FrameBody::ModelCall),
        ("memory.put", Direction::Guest) => decode_memory_put(value).map(FrameBody::MemoryPut),
        ("memory.recall", Direction::Guest) => {
            let b = object(value, &["limit", "query"], &["limit", "query"])?;
            let limit = count(field(b, "limit")?, 1, 100)?;
            let query = owned_string(b, "query")?;
            Ok(FrameBody::MemoryRecall(MemoryRecall { query, limit }))
        }
        ("memory.list", Direction::Guest) => {
            let fields = &["before", "tier"];
            let b = object(value, fields, fields)?;
            let before = nullable_bounded_string(field(b, "before")?, MAX_FRAME_BYTES)?;
            let tier = MemoryTier::parse(string(field(b, "tier")?)?)?;
            Ok(FrameBody::MemoryList(MemoryList { tier, before }))
        }
        ("memory.list.reply", Direction::Supervisor) => {
            decode_memory_list_reply(value).map(FrameBody::MemoryListReply)
        }
        ("status", Direction::Guest) => {
            object(value, &[], &[])?;
            Ok(FrameBody::Status(Status))
        }
        ("organs", Direction::Guest) => {
            object(value, &[], &[])?;
            Ok(FrameBody::Organs(Organs))
        }
        ("organs.reply", Direction::Supervisor) => {
            decode_organs_reply(value).map(FrameBody::OrgansReply)
        }
        ("status.reply", Direction::Supervisor) => {
            decode_status_reply(value).map(FrameBody::StatusReply)
        }
        ("accepted", Direction::Supervisor) => {
            let b = object(value, &["proposal_id"], &["proposal_id"])?;
            Ok(FrameBody::Accepted(Accepted {
                proposal_id: owned_string(b, "proposal_id")?,
            }))
        }
        ("outcome", Direction::Supervisor) => {
            let b = object(value, &["proposal_id", "state"], &["proposal_id", "state"])?;
            let proposal_id = owned_string(b, "proposal_id")?;
            let state = OutcomeState::parse(string(field(b, "state")?)?)?;
            Ok(FrameBody::Outcome(Outcome { proposal_id, state }))
        }
        ("model.reply", Direction::Supervisor) => {
            decode_model_reply(value).map(FrameBody::ModelReply)
        }
        ("read.reply", Direction::Supervisor) => {
            let b = object(
                value,
                &["bytes_b64", "sha256", "target"],
                &["bytes_b64", "sha256", "target"],
            )?;
            let bytes_b64 = base64(field(b, "bytes_b64")?)?;
            let sha256 = digest(field(b, "sha256")?)?;
            let target = owned_string(b, "target")?;
            Ok(FrameBody::ReadReply(ReadReply {
                target,
                sha256,
                bytes_b64,
            }))
        }
        ("recall", Direction::Supervisor) => decode_recall(value).map(FrameBody::Recall),
        ("refusal", Direction::Supervisor) => {
            let b = object(value, &["code", "next"], &["code", "next"])?;
            let code = owned_string(b, "code")?;
            if !codes::ALL.contains(&code.as_str()) {
                return Err(error(codes::FRAME_INVALID_FIELD));
            }
            let next = owned_string(b, "next")?;
            Ok(FrameBody::Refusal(Refusal { code, next }))
        }
        _ => Err(error(codes::FRAME_UNKNOWN_KIND)),
    }
}

fn decode_cell(value: &Value) -> Result<Cell, Error> {
    let b = object(
        value,
        &["effect_sha256", "input_sha256", "module_sha256"],
        &["effect_sha256", "input_sha256", "module_sha256"],
    )?;
    let effect_sha256 = digest(field(b, "effect_sha256")?)?;
    let input_sha256 = digest(field(b, "input_sha256")?)?;
    let module_sha256 = digest(field(b, "module_sha256")?)?;
    Ok(Cell {
        module_sha256,
        input_sha256,
        effect_sha256,
    })
}
fn decode_propose(value: &Value) -> Result<Propose, Error> {
    let b = object(
        value,
        &["base_sha256", "cell", "new_bytes_b64", "note", "target"],
        &["base_sha256", "new_bytes_b64", "note", "target"],
    )?;
    let base_sha256 = digest(field(b, "base_sha256")?)?;
    let new_bytes_b64 = base64(field(b, "new_bytes_b64")?)?;
    let note = owned_string(b, "note")?;
    let target = owned_string(b, "target")?;
    let cell = optional(b, "cell").map(decode_cell).transpose()?;
    Ok(Propose {
        target,
        base_sha256,
        new_bytes_b64,
        note,
        cell,
    })
}
fn decode_model_call(value: &Value) -> Result<ModelCall, Error> {
    let fields = &[
        "grant_id",
        "max_output_tokens",
        "messages",
        "model",
        "tools",
    ];
    let b = object(value, fields, fields)?;
    let grant_id = owned_string(b, "grant_id")?;
    let max_output_tokens = count(field(b, "max_output_tokens")?, 1, 32768)?;
    let model = owned_string(b, "model")?;
    let messages = decode_array(field(b, "messages")?, decode_message)?;
    let tools = decode_array(field(b, "tools")?, decode_tool)?;
    Ok(ModelCall {
        grant_id,
        model,
        messages,
        tools,
        max_output_tokens,
    })
}
fn decode_message(value: &Value) -> Result<Message, Error> {
    let b = object(
        value,
        &["content", "role", "tool_call_id", "tool_calls"],
        &["content", "role"],
    )?;
    let content = nullable_string(field(b, "content")?)?;
    let role = owned_string(b, "role")?;
    let tool_call_id = optional(b, "tool_call_id")
        .map(string)
        .transpose()?
        .map(str::to_owned);
    let tool_calls = optional(b, "tool_calls")
        .map(|v| decode_array(v, decode_tool_call))
        .transpose()?;
    Ok(Message {
        role,
        content,
        tool_calls,
        tool_call_id,
    })
}
fn decode_tool(value: &Value) -> Result<Tool, Error> {
    let b = object(value, &["function", "type"], &["function", "type"])?;
    function_type(field(b, "type")?)?;
    let f = object(
        field(b, "function")?,
        &["description", "name", "parameters"],
        &["description", "name", "parameters"],
    )?;
    let description = owned_string(f, "description")?;
    let name = owned_string(f, "name")?;
    let parameters = field(f, "parameters")?;
    if !matches!(parameters, Value::Object(_)) {
        return Err(error(codes::FRAME_NOT_OBJECT));
    }
    Ok(Tool {
        function: ToolFunction {
            name,
            description,
            parameters: parameters.clone(),
        },
    })
}
fn decode_tool_call(value: &Value) -> Result<ToolCall, Error> {
    let b = object(
        value,
        &["function", "id", "type"],
        &["function", "id", "type"],
    )?;
    let id = owned_string(b, "id")?;
    function_type(field(b, "type")?)?;
    let f = object(
        field(b, "function")?,
        &["arguments", "name"],
        &["arguments", "name"],
    )?;
    let arguments = owned_string(f, "arguments")?;
    let name = owned_string(f, "name")?;
    Ok(ToolCall {
        id,
        function: ToolCallFunction { name, arguments },
    })
}
fn decode_memory_put(value: &Value) -> Result<MemoryPut, Error> {
    let b = object(
        value,
        &["category", "cell", "quote", "statement"],
        &["category", "cell", "statement"],
    )?;
    let category = owned_string(b, "category")?;
    let quote = optional(b, "quote")
        .map(string)
        .transpose()?
        .map(str::to_owned);
    let statement = owned_string(b, "statement")?;
    let cell = decode_cell(field(b, "cell")?)?;
    Ok(MemoryPut {
        cell,
        statement,
        quote,
        category,
    })
}
fn decode_organs_reply(value: &Value) -> Result<OrgansReply, Error> {
    let fields = &[
        "approvals_pending",
        "aumlok",
        "aura",
        "kira",
        "nostr",
        "owner_origin",
        "wasm",
    ];
    let b = object(value, fields, fields)?;
    let owner_origin = bounded_string(field(b, "owner_origin")?, MAX_OWNER_ORIGIN_BYTES)?;
    let fields = &["bound", "passkeys", "refresh_due"];
    let aumlok = object(field(b, "aumlok")?, fields, fields)?;
    let aumlok = AumlokOrgans {
        bound: boolean(field(aumlok, "bound")?)?,
        passkeys: count(field(aumlok, "passkeys")?, 0, MAX_SAFE_INTEGER)?,
        refresh_due: boolean(field(aumlok, "refresh_due")?)?,
    };
    let fields = &["root", "sequence", "sources"];
    let aura = object(field(b, "aura")?, fields, fields)?;
    let aura = AuraOrgans {
        root: digest(field(aura, "root")?)?,
        sequence: count(field(aura, "sequence")?, 0, MAX_SAFE_INTEGER)?,
        sources: decode_aura_sources(field(aura, "sources")?)?,
    };
    let fields = &["demoted", "notes"];
    let kira = object(field(b, "kira")?, fields, fields)?;
    let kira = KiraOrgans {
        demoted: count(field(kira, "demoted")?, 0, MAX_SAFE_INTEGER)?,
        notes: count(field(kira, "notes")?, 0, MAX_SAFE_INTEGER)?,
    };
    let fields = &["agent_npub", "node_npub", "witness_accepted"];
    let nostr = object(field(b, "nostr")?, fields, fields)?;
    let nostr = NostrOrgans {
        agent_npub: nullable_bounded_string(field(nostr, "agent_npub")?, MAX_ORGAN_NPUB_BYTES)?,
        node_npub: nullable_bounded_string(field(nostr, "node_npub")?, MAX_ORGAN_NPUB_BYTES)?,
        witness_accepted: count(field(nostr, "witness_accepted")?, 0, MAX_SAFE_INTEGER)?,
    };
    let fields = &["module_sha256"];
    let wasm = object(field(b, "wasm")?, fields, fields)?;
    let wasm = WasmOrgans {
        module_sha256: digest(field(wasm, "module_sha256")?)?,
    };
    Ok(OrgansReply {
        approvals_pending: count(field(b, "approvals_pending")?, 0, MAX_SAFE_INTEGER)?,
        aumlok,
        aura,
        kira,
        nostr,
        owner_origin,
        wasm,
    })
}

fn decode_memory_list_reply(value: &Value) -> Result<MemoryListReply, Error> {
    let fields = &["items", "next", "tier"];
    let b = object(value, fields, fields)?;
    let next = nullable_bounded_string(field(b, "next")?, MAX_FRAME_BYTES)?;
    let tier = MemoryTier::parse(string(field(b, "tier")?)?)?;
    let items = decode_array(field(b, "items")?, |item| {
        decode_memory_list_item(item, tier)
    })?;
    if items.len() > 100 {
        return Err(error(codes::FRAME_INVALID_FIELD));
    }
    Ok(MemoryListReply { tier, items, next })
}

fn decode_memory_list_item(value: &Value, tier: MemoryTier) -> Result<MemoryListItem, Error> {
    let fields = &[
        "at",
        "category",
        "cite_seq",
        "demoted_at",
        "demoted_seq",
        "note_id",
        "text",
    ];
    let b = object(value, fields, fields)?;
    let at = count(field(b, "at")?, 0, MAX_SAFE_INTEGER)?;
    let category = bounded_string(field(b, "category")?, 64)?;
    if !category
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(error(codes::FRAME_INVALID_FIELD));
    }
    let cite_seq = count(field(b, "cite_seq")?, 1, MAX_SAFE_INTEGER)?;
    let demoted_at = match field(b, "demoted_at")? {
        Value::Null => None,
        value => Some(count(value, 0, MAX_SAFE_INTEGER)?),
    };
    let demoted_seq = match field(b, "demoted_seq")? {
        Value::Null => None,
        value => Some(integer(value)?),
    };
    let note_id = bounded_string(field(b, "note_id")?, MAX_FRAME_BYTES)?;
    let text = nullable_string(field(b, "text")?)?;
    match tier {
        MemoryTier::Remembered => {
            if text.is_none() || demoted_at.is_some() || demoted_seq.is_some() {
                return Err(error(codes::FRAME_INVALID_FIELD));
            }
        }
        MemoryTier::Forgotten => {
            if text.is_some()
                || demoted_at.is_none()
                || demoted_seq.is_none_or(|seq| seq <= cite_seq)
            {
                return Err(error(codes::FRAME_INVALID_FIELD));
            }
        }
    }
    Ok(MemoryListItem {
        note_id,
        category,
        at,
        cite_seq,
        text,
        demoted_seq,
        demoted_at,
    })
}

fn decode_aura_sources(value: &Value) -> Result<Box<[AuraSource; 3]>, Error> {
    let Value::Array(items) = value else {
        return Err(error(codes::FRAME_INVALID_FIELD));
    };
    let [gate, kira, code] = items.as_slice() else {
        return Err(error(codes::FRAME_INVALID_FIELD));
    };
    Ok(Box::new([
        decode_aura_source(gate, "gate-ledger", "gate-ledger-empty")?,
        decode_aura_source(kira, "kira-chain", "kira-ledger-empty")?,
        decode_aura_source(code, "code-chain", "code-record-missing")?,
    ]))
}

fn decode_aura_source(value: &Value, name: &str, absence: &str) -> Result<AuraSource, Error> {
    let fields = &["absence", "entries", "head", "name"];
    let source = object(value, fields, fields)?;
    let actual_name = string(field(source, "name")?)?;
    if actual_name != name {
        return Err(error(codes::FRAME_INVALID_FIELD));
    }
    let entries = integer(field(source, "entries")?)?;
    let (head, actual_absence) = match field(source, "head")? {
        Value::Null => {
            let actual_absence = string(field(source, "absence")?)?;
            if entries != 0 || actual_absence != absence {
                return Err(error(codes::FRAME_INVALID_FIELD));
            }
            (None, Some(actual_absence.to_owned()))
        }
        value => {
            let head = digest(value)?;
            if entries < 1 || field(source, "absence")? != &Value::Null {
                return Err(error(codes::FRAME_INVALID_FIELD));
            }
            (Some(head), None)
        }
    };
    Ok(AuraSource {
        name: actual_name.to_owned(),
        head,
        entries,
        absence: actual_absence,
    })
}

fn decode_status_reply(value: &Value) -> Result<StatusReply, Error> {
    let fields = &["bound", "grant_id", "grant_remaining", "ready"];
    let b = object(value, fields, fields)?;
    let bound = boolean(field(b, "bound")?)?;
    let grant_id = nullable_string(field(b, "grant_id")?)?;
    let grant_remaining = match field(b, "grant_remaining")? {
        Value::Null => None,
        v => Some(count(v, 0, MAX_SAFE_INTEGER)?),
    };
    let ready = boolean(field(b, "ready")?)?;
    Ok(StatusReply {
        ready,
        bound,
        grant_id,
        grant_remaining,
    })
}
fn decode_model_reply(value: &Value) -> Result<ModelReply, Error> {
    let fields = &[
        "content",
        "finish_reason",
        "receipt_seq",
        "tool_calls",
        "usage",
    ];
    let b = object(value, fields, fields)?;
    let content = nullable_string(field(b, "content")?)?;
    let finish_reason = nullable_string(field(b, "finish_reason")?)?;
    let receipt_seq = count(field(b, "receipt_seq")?, 1, MAX_SAFE_INTEGER)?;
    let tool_calls = decode_array(field(b, "tool_calls")?, decode_tool_call)?;
    let ufields = &["completion_tokens", "cost_microusd", "prompt_tokens"];
    let u = object(field(b, "usage")?, ufields, ufields)?;
    let completion_tokens = count(field(u, "completion_tokens")?, 0, 32768)?;
    let cost_microusd = count(field(u, "cost_microusd")?, 0, MAX_SAFE_INTEGER)?;
    let prompt_tokens = count(field(u, "prompt_tokens")?, 0, 32768)?;
    Ok(ModelReply {
        content,
        tool_calls,
        finish_reason,
        usage: Usage {
            prompt_tokens,
            completion_tokens,
            cost_microusd,
        },
        receipt_seq,
    })
}
fn decode_recall(value: &Value) -> Result<Recall, Error> {
    let b = object(value, &["items", "result"], &["items", "result"])?;
    let result = RecallResult::parse(string(field(b, "result")?)?)?;
    let items = decode_array(field(b, "items")?, |value| {
        let b = object(
            value,
            &["cite_seq", "note_id", "text"],
            &["cite_seq", "note_id", "text"],
        )?;
        let cite_seq = count(field(b, "cite_seq")?, 1, MAX_SAFE_INTEGER)?;
        let note_id = owned_string(b, "note_id")?;
        let text = owned_string(b, "text")?;
        Ok(RecallItem {
            note_id,
            text,
            cite_seq,
        })
    })?;
    Ok(Recall { result, items })
}

fn object<'a>(
    value: &'a Value,
    allowed: &[&str],
    required: &[&str],
) -> Result<&'a [(String, Value)], Error> {
    let Value::Object(fields) = value else {
        return Err(error(codes::FRAME_NOT_OBJECT));
    };
    if fields
        .iter()
        .any(|(name, _)| !allowed.contains(&name.as_str()))
    {
        return Err(error(codes::FRAME_UNKNOWN_FIELD));
    }
    if required
        .iter()
        .any(|required| !fields.iter().any(|(name, _)| name == required))
    {
        return Err(error(codes::FRAME_MISSING_FIELD));
    }
    Ok(fields)
}
fn field<'a>(fields: &'a [(String, Value)], name: &str) -> Result<&'a Value, Error> {
    optional(fields, name).ok_or_else(|| error(codes::FRAME_MISSING_FIELD))
}
fn optional<'a>(fields: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    fields
        .iter()
        .find_map(|(field, value)| (field == name).then_some(value))
}
fn string(value: &Value) -> Result<&str, Error> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err(error(codes::FRAME_INVALID_FIELD)),
    }
}
fn owned_string(fields: &[(String, Value)], name: &str) -> Result<String, Error> {
    Ok(string(field(fields, name)?)?.to_owned())
}
fn bounded_string(value: &Value, maximum: usize) -> Result<String, Error> {
    let text = string(value)?;
    if text.is_empty() || text.len() > maximum {
        return Err(error(codes::FRAME_INVALID_FIELD));
    }
    Ok(text.to_owned())
}
fn nullable_bounded_string(value: &Value, maximum: usize) -> Result<Option<String>, Error> {
    match value {
        Value::Null => Ok(None),
        value => bounded_string(value, maximum).map(Some),
    }
}
fn nullable_string(value: &Value) -> Result<Option<String>, Error> {
    match value {
        Value::Null => Ok(None),
        v => Ok(Some(string(v)?.to_owned())),
    }
}
fn integer(value: &Value) -> Result<i64, Error> {
    match value {
        Value::Integer(n) => Ok(*n),
        _ => Err(error(codes::FRAME_INVALID_FIELD)),
    }
}
fn boolean(value: &Value) -> Result<bool, Error> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err(error(codes::FRAME_INVALID_FIELD)),
    }
}
fn count(value: &Value, minimum: i64, maximum: i64) -> Result<i64, Error> {
    let number = integer(value)?;
    if !(minimum..=maximum).contains(&number) {
        return Err(error(codes::FRAME_INVALID_FIELD));
    }
    Ok(number)
}
fn decode_array<T>(
    value: &Value,
    decode: impl Fn(&Value) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let Value::Array(items) = value else {
        return Err(error(codes::FRAME_INVALID_FIELD));
    };
    items.iter().map(decode).collect()
}
fn function_type(value: &Value) -> Result<(), Error> {
    if string(value)? != "function" {
        return Err(error(codes::FRAME_INVALID_FIELD));
    }
    Ok(())
}
fn digest(value: &Value) -> Result<String, Error> {
    let text = string(value)?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(error(codes::FRAME_INVALID_FIELD));
    }
    Ok(text.to_owned())
}
fn base64(value: &Value) -> Result<String, Error> {
    let text = string(value)?;
    decode_base64(text)?;
    Ok(text.to_owned())
}
/// Decode RFC 4648 standard, canonically padded base64 (zero pad bits included)
/// without allowing decoded bytes above the FD 3 frame budget.
pub fn decode_base64(text: &str) -> Result<Vec<u8>, Error> {
    if !valid_base64(text) {
        return Err(error(codes::FRAME_INVALID_FIELD));
    }
    let mut bytes = Vec::with_capacity(text.len() / 4 * 3);
    for block in text.as_bytes().chunks_exact(4) {
        let value = block.iter().fold(0_u32, |n, b| {
            (n << 6) | u32::from(b64_digit(*b).unwrap_or(0))
        });
        bytes.push((value >> 16) as u8);
        if block[2] != b'=' {
            bytes.push((value >> 8) as u8);
        }
        if block[3] != b'=' {
            bytes.push(value as u8);
        }
    }
    Ok(bytes)
}

fn valid_base64(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return false;
    }
    if bytes.is_empty() {
        return true;
    }
    let padding = if bytes.ends_with(b"==") {
        2
    } else {
        usize::from(bytes.ends_with(b"="))
    };
    let data_len = bytes.len() - padding;
    let decoded_len = bytes.len() / 4 * 3 - padding;
    if decoded_len > MAX_FRAME_BYTES || bytes[..data_len].iter().any(|b| b64_digit(*b).is_none()) {
        return false;
    }
    match padding {
        2 => b64_digit(bytes[data_len - 1]).is_some_and(|n| n & 15 == 0),
        1 => b64_digit(bytes[data_len - 1]).is_some_and(|n| n & 3 == 0),
        _ => true,
    }
}
fn b64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
fn object_value(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}
fn string_value(value: &str) -> Value {
    Value::String(value.to_owned())
}
fn nullable_string_value(value: &Option<String>) -> Value {
    value.as_deref().map_or(Value::Null, string_value)
}
fn array_value<T>(items: &[T], encode: impl Fn(&T) -> Value) -> Value {
    Value::Array(items.iter().map(encode).collect())
}
const fn error(code: &'static str) -> Error {
    Error::new(code, 0)
}
