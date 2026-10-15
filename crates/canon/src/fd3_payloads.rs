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
    /// Omitted when absent; a present value must be an object, never JSON null.
    /// The supervisor independently recomputes these assertions.
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
    /// Optional literal source quote; absent and empty remain distinct. JSON null is refused.
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

impl Propose {
    /// Decode canonical padded RFC 4648 replacement bytes within the C4 limit.
    /// This validates encoding only; target policy and authorization remain external.
    pub fn replacement_bytes(&self) -> crate::Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        if self.new_bytes_b64.len() > 87_384 {
            return Err(crate::codes::FRAME_INVALID_FIELD);
        }
        let bytes = STANDARD
            .decode(&self.new_bytes_b64)
            .map_err(|_| crate::codes::FRAME_INVALID_FIELD)?;
        if bytes.len() > 65_536 || STANDARD.encode(&bytes) != self.new_bytes_b64 {
            return Err(crate::codes::FRAME_INVALID_FIELD);
        }
        Ok(bytes)
    }
}

/// Versioned static-site data shared by the confined builder and the serving boundary.
pub mod sites {
    use crate::{codes, digest::Digest32, json, json::Value, json::ValueView, Result};
    use base64::{engine::general_purpose::STANDARD, Engine};

    /// Maximum bytes of the canonical bundle, including base64 and metadata.
    pub const MAX_BUNDLE_BYTES: usize = 32_768;
    /// Maximum number of distinct assets in one bundle.
    pub const MAX_FILES: usize = 64;
    /// The exact top-level schema discriminator.
    pub const BUNDLE_SCHEMA: &str = "aukora-site-bundle-v1";

    /// One static asset; construction of a bundle checks its path and media type.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SiteFile {
        /// Relative slash-separated asset name.
        pub path: String,
        /// Media type from the closed suffix mapping.
        pub media_type: String,
        /// Exact proposed response body.
        pub bytes: Vec<u8>,
    }

    /// Canonical site data with no authorization or publication capability.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SiteBundle {
        host: String,
        target: String,
        files: Vec<SiteFile>,
        canonical: Vec<u8>,
    }

    impl SiteBundle {
        /// Build a bounded canonical bundle, sorting the supplied files by path bytes.
        pub fn build(host: &str, files: &[SiteFile]) -> Result<Self> {
            validate_host(host)?;
            if files.is_empty() || files.len() > MAX_FILES {
                return Err(codes::CANON_SITE_BUNDLE_LIMIT);
            }
            let payload_bytes = files.iter().try_fold(0usize, |total, file| {
                total
                    .checked_add(file.bytes.len())
                    .ok_or(codes::CANON_SITE_BUNDLE_LIMIT)
            })?;
            if payload_bytes > MAX_BUNDLE_BYTES {
                return Err(codes::CANON_SITE_BUNDLE_LIMIT);
            }
            let mut retained = files.to_vec();
            retained.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            let mut encoded = Vec::with_capacity(retained.len());
            let mut previous: Option<&str> = None;
            for file in &retained {
                validate_path(&file.path)?;
                if previous == Some(file.path.as_str()) {
                    return Err(codes::CANON_SITE_PATH_INVALID);
                }
                previous = Some(&file.path);
                if media_type(&file.path)? != file.media_type {
                    return Err(codes::CANON_SITE_MEDIA_INVALID);
                }
                encoded.push(object(vec![
                    ("path", text(&file.path)?),
                    ("media_type", text(&file.media_type)?),
                    ("bytes_b64", text(&STANDARD.encode(&file.bytes))?),
                ])?);
            }
            if !retained.iter().any(|file| file.path == "index.html") {
                return Err(codes::CANON_SITE_PATH_INVALID);
            }
            let canonical = object(vec![
                ("schema", text(BUNDLE_SCHEMA)?),
                ("host", text(host)?),
                ("files", Value::checked_array(encoded)?),
            ])?
            .canonical_bytes();
            if canonical.len() > MAX_BUNDLE_BYTES {
                return Err(codes::CANON_SITE_BUNDLE_LIMIT);
            }
            Ok(Self {
                host: host.to_owned(),
                target: format!("sites/{host}.json"),
                files: retained,
                canonical,
            })
        }

        /// Decode only exact canonical bytes with the closed v1 object field sets.
        pub fn decode(bytes: &[u8]) -> Result<Self> {
            if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
                return Err(codes::CANON_SITE_BUNDLE_LIMIT);
            }
            let value = json::parse_strict(bytes).map_err(|_| codes::CANON_SITE_BUNDLE_INVALID)?;
            if value.canonical_bytes() != bytes {
                return Err(codes::CANON_SITE_BUNDLE_INVALID);
            }
            exact_fields(&value, &["files", "host", "schema"])?;
            if string(field(&value, "schema")?)? != BUNDLE_SCHEMA {
                return Err(codes::CANON_SITE_BUNDLE_INVALID);
            }
            let host = string(field(&value, "host")?)?;
            let ValueView::Array(entries) = field(&value, "files")?.view() else {
                return Err(codes::CANON_SITE_BUNDLE_INVALID);
            };
            if entries.is_empty() || entries.len() > MAX_FILES {
                return Err(codes::CANON_SITE_BUNDLE_LIMIT);
            }
            let mut files = Vec::with_capacity(entries.len());
            let mut previous: Option<&str> = None;
            for entry in entries {
                exact_fields(entry, &["bytes_b64", "media_type", "path"])?;
                let path = string(field(entry, "path")?)?;
                if previous.is_some_and(|last| last.as_bytes() >= path.as_bytes()) {
                    return Err(codes::CANON_SITE_PATH_INVALID);
                }
                previous = Some(path);
                let encoded = string(field(entry, "bytes_b64")?)?;
                let bytes = STANDARD
                    .decode(encoded)
                    .map_err(|_| codes::CANON_SITE_ENCODING_INVALID)?;
                if STANDARD.encode(&bytes) != encoded {
                    return Err(codes::CANON_SITE_ENCODING_INVALID);
                }
                files.push(SiteFile {
                    path: path.to_owned(),
                    media_type: string(field(entry, "media_type")?)?.to_owned(),
                    bytes,
                });
            }
            let bundle = Self::build(host, &files)?;
            if bundle.canonical != bytes {
                return Err(codes::CANON_SITE_BUNDLE_INVALID);
            }
            Ok(bundle)
        }

        /// Exact approved host name carried in the bundle.
        pub fn host(&self) -> &str {
            &self.host
        }

        /// Assets in strictly increasing bytewise path order.
        pub fn files(&self) -> &[SiteFile] {
            &self.files
        }

        /// Exact bytes that the gate must show and authorize.
        pub fn canonical_bytes(&self) -> &[u8] {
            &self.canonical
        }

        /// SHA-256 of the exact canonical bundle bytes.
        pub fn digest(&self) -> Digest32 {
            Digest32::sha256(&self.canonical)
        }

        /// Allowed-target name derived solely from the validated host.
        pub fn target(&self) -> &str {
            &self.target
        }
    }

    /// V2 proposal data; receipt of this value queues review without publishing bytes.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SiteProposal {
        /// Exact bundle presented for owner approval.
        pub bundle: SiteBundle,
        /// Observed target state; absence is distinct from every byte digest.
        pub base: crate::authority::BaseDigest,
        /// Untrusted explanation, rendered only as text.
        pub note: String,
    }

    impl SiteProposal {
        pub(crate) fn from_fd3_body(value: &Value) -> Result<Self> {
            use crate::authority::BaseDigest;

            exact_fields(value, &["base_sha256", "new_bytes_b64", "note", "target"])?;
            let encoded = string(field(value, "new_bytes_b64")?)?;
            if encoded.len() > MAX_BUNDLE_BYTES.div_ceil(3) * 4 {
                return Err(codes::CANON_SITE_BUNDLE_LIMIT);
            }
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| codes::CANON_SITE_ENCODING_INVALID)?;
            if STANDARD.encode(&bytes) != encoded {
                return Err(codes::CANON_SITE_ENCODING_INVALID);
            }
            let bundle = SiteBundle::decode(&bytes)?;
            if string(field(value, "target")?)? != bundle.target() {
                return Err(codes::CANON_SITE_BUNDLE_INVALID);
            }
            let base_text = string(field(value, "base_sha256")?)?;
            let base = if base_text == "absent" {
                BaseDigest::Absent
            } else {
                BaseDigest::Present(
                    Digest32::from_hex(base_text).map_err(|_| codes::CANON_SITE_BUNDLE_INVALID)?,
                )
            };
            Ok(Self {
                bundle,
                base,
                note: string(field(value, "note")?)?.to_owned(),
            })
        }

        pub(crate) fn fd3_body(&self) -> Result<Value> {
            use crate::authority::BaseDigest;

            object(vec![
                (
                    "base_sha256",
                    text(&match self.base {
                        BaseDigest::Absent => "absent".to_owned(),
                        BaseDigest::Present(digest) => digest.to_string(),
                    })?,
                ),
                (
                    "new_bytes_b64",
                    text(&STANDARD.encode(self.bundle.canonical_bytes()))?,
                ),
                ("note", text(&self.note)?),
                ("target", text(self.bundle.target())?),
            ])
        }
    }

    /// Require lowercase DNS labels, with at least two and a nonnumeric final label.
    pub fn validate_host(host: &str) -> Result<()> {
        if host.len() > 253 || !host.is_ascii() {
            return Err(codes::CANON_SITE_HOST_INVALID);
        }
        let labels: Vec<_> = host.split('.').collect();
        if labels.len() < 2
            || labels.last().is_none_or(|label| {
                !label.bytes().any(|byte| byte.is_ascii_lowercase())
                    || label.strip_prefix("0x").is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
            })
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(codes::CANON_SITE_HOST_INVALID);
        }
        Ok(())
    }

    /// Refuse unsafe paths and paths belonging to owner or API surfaces.
    pub fn validate_path(path: &str) -> Result<()> {
        if path.is_empty()
            || path.len() > 192
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte))
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || path
                .split('/')
                .next()
                .is_some_and(|part| matches!(part, "api" | "ui" | ".well-known"))
        {
            return Err(codes::CANON_SITE_PATH_INVALID);
        }
        media_type(path).map(|_| ())
    }

    /// Exact allowed media type for a lowercase suffix.
    pub fn media_type(path: &str) -> Result<&'static str> {
        match path.rsplit_once('.').map(|(_, suffix)| suffix) {
            Some("html") => Ok("text/html"),
            Some("css") => Ok("text/css"),
            Some("js") => Ok("text/javascript"),
            Some("txt") => Ok("text/plain"),
            Some("json") => Ok("application/json"),
            Some("png") => Ok("image/png"),
            Some("jpg" | "jpeg") => Ok("image/jpeg"),
            Some("webp") => Ok("image/webp"),
            Some("ico") => Ok("image/x-icon"),
            Some("woff2") => Ok("font/woff2"),
            _ => Err(codes::CANON_SITE_PATH_INVALID),
        }
    }

    fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
        Value::checked_object(
            fields
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    fn text(value: &str) -> Result<Value> {
        Value::checked_text(value.to_owned())
    }

    fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
        let ValueView::Object(fields) = value.view() else {
            return Err(codes::CANON_SITE_BUNDLE_INVALID);
        };
        fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
            .ok_or(codes::CANON_SITE_BUNDLE_INVALID)
    }

    fn string(value: &Value) -> Result<&str> {
        match value.view() {
            ValueView::Text(text) => Ok(text),
            _ => Err(codes::CANON_SITE_BUNDLE_INVALID),
        }
    }

    fn exact_fields(value: &Value, expected: &[&str]) -> Result<()> {
        let ValueView::Object(fields) = value.view() else {
            return Err(codes::CANON_SITE_BUNDLE_INVALID);
        };
        if fields.len() != expected.len()
            || fields
                .iter()
                .any(|(key, _)| !expected.contains(&key.as_str()))
        {
            return Err(codes::CANON_SITE_BUNDLE_INVALID);
        }
        Ok(())
    }
}
