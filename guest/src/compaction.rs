// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compaction describes an append-only summary; original session entries remain retained.

use std::collections::BTreeSet;

use crate::session::{
    entries_commitment, entry_commitment, validate_entry, DurablePrefix, MAX_COMPACTION_ENTRIES,
    MAX_SEQUENCE,
};
use canon::{
    alg::AlgorithmId,
    codes,
    digest::Digest32,
    ids::{RequestId, ReservationId, SessionId},
    json::{parse_strict, SafeInteger, Value, ValueView},
    provenance::{Provenance, Source},
    session::{
        Items, ModelReceipt, SessionAppend, SessionAppended, SessionEntry, SessionFlush,
        SessionRole, Text, RECORD_VERSION,
    },
    Result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionRange {
    pub session_id: SessionId,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub observed_sequence: u64,
    pub source_commitment: Digest32,
    pub retain_recent_entries: u16,
}

impl CompactionRange {
    pub fn validate(&self, durable: &DurablePrefix) -> Result<()> {
        if self.first_sequence == 0
            || self.last_sequence < self.first_sequence
            || self.observed_sequence >= MAX_SEQUENCE
            || self.last_sequence > self.observed_sequence
            || self.retain_recent_entries == 0
            || self.observed_sequence - self.last_sequence < u64::from(self.retain_recent_entries)
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        durable.require(self.session_id, self.observed_sequence)
    }
}

#[derive(Clone, Debug)]
pub struct CompactionSummary {
    pub source: CompactionRange,
    pub text: Text<16_384>,
    pub receipt: ModelReceipt,
}

/// The backend checks exact source commitments and balanced call/result pairs before summarizing.
/// Commit appends Auma-labelled context at the observed sequence and requires a flush receipt.
/// There is no destructive replace or retry operation in this interface.
pub trait Compactor {
    fn prepare(&mut self, range: CompactionRange, durable: DurablePrefix) -> Result<()>;
    fn summarized(&mut self, summary: CompactionSummary) -> Result<SessionEntry>;
    fn committed(&mut self, durable: DurablePrefix) -> Result<()>;
    fn cancel(&mut self);
}

#[derive(Debug)]
enum Stage {
    Idle,
    Prepared(CompactionRange),
    AppendIssued(SessionEntry),
    AwaitingFlush(SessionEntry),
    Committed,
    Cancelled,
}

/// One compaction attempt over an immutable, contiguous transcript snapshot.
/// Original entries are retained; the only output is a new Context entry.
#[derive(Debug)]
pub struct AppendOnlyCompactor {
    entries: Vec<SessionEntry>,
    request_id: RequestId,
    reservation_id: ReservationId,
    at_ms: u64,
    stage: Stage,
}

impl AppendOnlyCompactor {
    /// The caller supplies correlation ids and informational time.
    /// The snapshot is a bounded contiguous window ending at the observed sequence.
    /// Tool results without a matching earlier call in that window refuse preparation.
    pub fn new(
        entries: Vec<SessionEntry>,
        request_id: RequestId,
        reservation_id: ReservationId,
        at_ms: u64,
    ) -> Result<Self> {
        if entries.is_empty() || at_ms > MAX_SEQUENCE {
            return Err(codes::SESSION_SEQUENCE);
        }
        if entries.len() > MAX_COMPACTION_ENTRIES {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        let session_id = entries[0].session_id;
        let mut expected = entries[0].sequence;
        for entry in &entries {
            validate_entry(entry)?;
            if entry.session_id != session_id || entry.sequence != expected {
                return Err(codes::SESSION_SEQUENCE);
            }
            expected = expected.checked_add(1).ok_or(codes::SESSION_SEQUENCE)?;
        }
        Ok(Self {
            entries,
            request_id,
            reservation_id,
            at_ms,
            stage: Stage::Idle,
        })
    }

    /// These exact entries are summary input only after prepare has checked durability.
    pub fn source_entries(&self) -> Result<&[SessionEntry]> {
        match &self.stage {
            Stage::Prepared(range) => self.selected(range),
            _ => Err(codes::SESSION_SEQUENCE),
        }
    }

    /// A compare-and-append request; issuing it conveys no durability.
    pub fn append_request(&self) -> Result<SessionAppend> {
        match &self.stage {
            Stage::AppendIssued(entry) => Ok(SessionAppend {
                session_id: entry.session_id,
                expected_sequence: entry.sequence - 1,
                entry: entry.clone(),
            }),
            _ => Err(codes::SESSION_SEQUENCE),
        }
    }

    /// Only an exact append acknowledgement permits the flush step.
    pub fn acknowledge_append(&mut self, reply: SessionAppended) -> Result<SessionFlush> {
        let Stage::AppendIssued(entry) = &self.stage else {
            return Err(codes::SESSION_SEQUENCE);
        };
        if reply.entry != *entry {
            return Err(codes::SESSION_SEQUENCE);
        }
        let request = SessionFlush {
            session_id: entry.session_id,
            through_sequence: entry.sequence,
        };
        self.stage = Stage::AwaitingFlush(reply.entry);
        Ok(request)
    }

    pub fn is_committed(&self) -> bool {
        matches!(self.stage, Stage::Committed)
    }

    fn selected(&self, range: &CompactionRange) -> Result<&[SessionEntry]> {
        source_slice(&self.entries, range)
    }
}

impl Compactor for AppendOnlyCompactor {
    fn prepare(&mut self, range: CompactionRange, durable: DurablePrefix) -> Result<()> {
        if !matches!(self.stage, Stage::Idle) {
            return Err(codes::SESSION_SEQUENCE);
        }
        range.validate(&durable)?;
        let tail = self.entries.last().ok_or(codes::SESSION_SEQUENCE)?;
        if tail.session_id != range.session_id || tail.sequence != range.observed_sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        check_source(&self.entries, &range)?;
        self.stage = Stage::Prepared(range);
        Ok(())
    }

    fn summarized(&mut self, summary: CompactionSummary) -> Result<SessionEntry> {
        let Stage::Prepared(range) = &self.stage else {
            return Err(codes::SESSION_SEQUENCE);
        };
        if summary.source != *range || summary.text.as_str().trim().is_empty() {
            return Err(codes::SESSION_SEQUENCE);
        }
        check_receipt(&summary.receipt, self.request_id, self.reservation_id)?;
        let mut entry = SessionEntry {
            v: RECORD_VERSION,
            algorithm: AlgorithmId::Sha256,
            session_id: range.session_id,
            sequence: range.observed_sequence + 1,
            role: SessionRole::Context,
            content: summary_content(&summary)?,
            tool_calls: Items::new(Vec::new())?,
            tool_call_id: None,
            provenance: Provenance {
                source: Source::Auma,
            },
            at_ms: self.at_ms,
            commitment: Digest32::from_bytes([0; 32]),
        };
        entry.commitment = entry_commitment(&entry)?;
        validate_entry(&entry)?;
        self.stage = Stage::AppendIssued(entry.clone());
        Ok(entry)
    }

    fn committed(&mut self, durable: DurablePrefix) -> Result<()> {
        let Stage::AwaitingFlush(entry) = &self.stage else {
            return Err(codes::SESSION_SEQUENCE);
        };
        durable.require(entry.session_id, entry.sequence)?;
        self.stage = Stage::Committed;
        Ok(())
    }

    fn cancel(&mut self) {
        if !matches!(self.stage, Stage::Committed) {
            self.stage = Stage::Cancelled;
        }
    }
}

fn check_tool_boundaries(entries: &[SessionEntry], range: &CompactionRange) -> Result<()> {
    let mut pending = BTreeSet::new();
    for entry in entries {
        if entry.sequence == range.first_sequence && !pending.is_empty() {
            return Err(codes::SESSION_SEQUENCE);
        }
        for call in entry.tool_calls.as_slice() {
            if entry.role != SessionRole::Auma
                || call.id.is_empty()
                || call.id.len() > 128
                || !pending.insert(call.id.as_str())
            {
                return Err(codes::SESSION_SEQUENCE);
            }
        }
        match (&entry.tool_call_id, entry.role) {
            (Some(id), SessionRole::Tool) if pending.remove(id.as_str()) => {}
            (None, role) if role != SessionRole::Tool => {}
            _ => return Err(codes::SESSION_SEQUENCE),
        }
        if entry.sequence == range.last_sequence && !pending.is_empty() {
            return Err(codes::SESSION_SEQUENCE);
        }
    }
    Ok(())
}

fn check_receipt(
    receipt: &ModelReceipt,
    request_id: RequestId,
    reservation_id: ReservationId,
) -> Result<()> {
    if receipt.v != RECORD_VERSION {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    if receipt.algorithm != AlgorithmId::Sha256 {
        return Err(codes::ALG_UNSUPPORTED);
    }
    if receipt.request_id != request_id
        || receipt.reservation_id != reservation_id
        || receipt.receipt_seq == 0
        || receipt.receipt_seq > MAX_SEQUENCE
        || receipt.model.as_str().is_empty()
        || receipt.usage.prompt_tokens > 32_768
        || receipt.usage.completion_tokens > 32_768
        || receipt.usage.cost_microusd > MAX_SEQUENCE
    {
        return Err(codes::BROKER_INVALID_REPLY);
    }
    Ok(())
}

fn summary_content(summary: &CompactionSummary) -> Result<Text<32_768>> {
    let text = |value: String| Value::text(value);
    let number = |value: u64| {
        let value = i64::try_from(value).map_err(|_| codes::SESSION_SEQUENCE)?;
        SafeInteger::new(value).map(Value::integer)
    };
    let value = Value::object(vec![
        (
            "schema".into(),
            text("aukora-compaction-summary-v1".into())?,
        ),
        (
            "session_id".into(),
            text(summary.source.session_id.to_string())?,
        ),
        (
            "first_sequence".into(),
            number(summary.source.first_sequence)?,
        ),
        (
            "last_sequence".into(),
            number(summary.source.last_sequence)?,
        ),
        (
            "observed_sequence".into(),
            number(summary.source.observed_sequence)?,
        ),
        (
            "retain_recent_entries".into(),
            number(u64::from(summary.source.retain_recent_entries))?,
        ),
        (
            "source_commitment".into(),
            text(summary.source.source_commitment.to_string())?,
        ),
        (
            "request_id".into(),
            text(summary.receipt.request_id.to_string())?,
        ),
        (
            "reservation_id".into(),
            text(summary.receipt.reservation_id.to_string())?,
        ),
        (
            "model".into(),
            text(summary.receipt.model.as_str().to_owned())?,
        ),
        ("receipt_seq".into(), number(summary.receipt.receipt_seq)?),
        (
            "receipt_commitment".into(),
            text(summary.receipt.commitment.to_string())?,
        ),
        ("text".into(), text(summary.text.as_str().to_owned())?),
    ])?;
    let literal =
        String::from_utf8(value.canonical_bytes()).map_err(|_| codes::CANON_INVALID_UTF8)?;
    Text::new(literal)
}

/// Checks the exact source digest and call/result boundaries in a retained window.
/// It does not establish a storage receipt or confer any authority on the summary.
pub fn check_source(entries: &[SessionEntry], range: &CompactionRange) -> Result<()> {
    if entries.is_empty() || entries.len() > MAX_COMPACTION_ENTRIES {
        return Err(codes::FRAME_STREAM_LIMIT);
    }
    if range.first_sequence == 0
        || range.last_sequence < range.first_sequence
        || range.observed_sequence >= MAX_SEQUENCE
        || range.last_sequence > range.observed_sequence
        || range.retain_recent_entries == 0
        || range.observed_sequence - range.last_sequence < u64::from(range.retain_recent_entries)
    {
        return Err(codes::SESSION_SEQUENCE);
    }
    let mut expected = entries[0].sequence;
    for entry in entries {
        validate_entry(entry)?;
        if entry.session_id != range.session_id || entry.sequence != expected {
            return Err(codes::SESSION_SEQUENCE);
        }
        expected = expected.checked_add(1).ok_or(codes::SESSION_SEQUENCE)?;
    }
    if entries
        .last()
        .is_none_or(|entry| entry.sequence < range.observed_sequence)
        || entries_commitment(source_slice(entries, range)?)? != range.source_commitment
    {
        return Err(codes::SESSION_SEQUENCE);
    }
    check_tool_boundaries(entries, range)
}

fn source_slice<'a>(
    entries: &'a [SessionEntry],
    range: &CompactionRange,
) -> Result<&'a [SessionEntry]> {
    let first = entries.first().ok_or(codes::SESSION_SEQUENCE)?.sequence;
    let start = range
        .first_sequence
        .checked_sub(first)
        .ok_or(codes::SESSION_SEQUENCE)?;
    let end = range
        .last_sequence
        .checked_sub(first)
        .and_then(|value| value.checked_add(1))
        .ok_or(codes::SESSION_SEQUENCE)?;
    let start = usize::try_from(start).map_err(|_| codes::SESSION_SEQUENCE)?;
    let end = usize::try_from(end).map_err(|_| codes::SESSION_SEQUENCE)?;
    entries.get(start..end).ok_or(codes::SESSION_SEQUENCE)
}

/// Recognizes only validated Context/Auma records with the exact summary schema.
/// Returned range metadata must still be checked against retained source bytes.
pub fn covered_range(entry: &SessionEntry) -> Result<Option<CompactionRange>> {
    validate_entry(entry)?;
    if entry.role != SessionRole::Context || entry.provenance.source != Source::Auma {
        return Ok(None);
    }
    let Ok(value) = parse_strict(entry.content.as_str().as_bytes()) else {
        return Ok(None);
    };
    if value
        .get("schema")
        .map(Value::view)
        .is_none_or(|value| !matches!(value, ValueView::Text("aukora-compaction-summary-v1")))
    {
        return Ok(None);
    }
    let ValueView::Object(fields) = value.view() else {
        return Err(codes::FRAME_INVALID_FIELD);
    };
    if fields.len() != 13 || !entry.tool_calls.as_slice().is_empty() || entry.tool_call_id.is_some()
    {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    let field_text = |name: &str| match value.get(name).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(codes::FRAME_INVALID_FIELD),
    };
    let field_number = |name: &str| match value.get(name).map(Value::view) {
        Some(ValueView::Integer(number)) => {
            u64::try_from(number.get()).map_err(|_| codes::FRAME_INVALID_FIELD)
        }
        _ => Err(codes::FRAME_INVALID_FIELD),
    };
    let range = CompactionRange {
        session_id: SessionId::from_hex(field_text("session_id")?)?,
        first_sequence: field_number("first_sequence")?,
        last_sequence: field_number("last_sequence")?,
        observed_sequence: field_number("observed_sequence")?,
        source_commitment: Digest32::from_hex(field_text("source_commitment")?)?,
        retain_recent_entries: u16::try_from(field_number("retain_recent_entries")?)
            .map_err(|_| codes::FRAME_INVALID_FIELD)?,
    };
    RequestId::from_hex(field_text("request_id")?)?;
    ReservationId::from_hex(field_text("reservation_id")?)?;
    Digest32::from_hex(field_text("receipt_commitment")?)?;
    let receipt_sequence = field_number("receipt_seq")?;
    let model = field_text("model")?;
    let text = field_text("text")?;
    if range.session_id != entry.session_id
        || range.first_sequence == 0
        || range.last_sequence < range.first_sequence
        || range.observed_sequence >= MAX_SEQUENCE
        || range.last_sequence > range.observed_sequence
        || range.observed_sequence + 1 != entry.sequence
        || range.retain_recent_entries == 0
        || range.observed_sequence - range.last_sequence < u64::from(range.retain_recent_entries)
        || receipt_sequence == 0
        || receipt_sequence > MAX_SEQUENCE
        || model.is_empty()
        || model.len() > 256
        || text.trim().is_empty()
        || text.len() > 16_384
    {
        return Err(codes::SESSION_SEQUENCE);
    }
    Ok(Some(range))
}
