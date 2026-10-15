// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded context data with explicit source labels and sequence references.

use crate::session::DurablePrefix;
use canon::{
    codes,
    fd3_payloads::ModelMessage,
    ids::SessionId,
    json::{SafeInteger, Value},
    provenance::{Provenance, Source},
    session::{Items, SessionEntry, SessionRole, Text},
    Result,
};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CONTEXT_ITEMS: usize = 128;
pub const MAX_CONTEXT_BYTES: usize = 48_000;
pub const MAX_REFERENCED_SESSIONS: usize = 16;
pub const MAX_REPLAY_ENTRIES: usize = crate::session::MAX_COMPACTION_ENTRIES + 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextItem {
    pub provenance: Provenance,
    pub content: Text<32_768>,
    pub source_session: Option<SessionId>,
    pub source_sequence: Option<u64>,
}

impl ContextItem {
    /// Preserves a stored entry as labelled data; tool suggestions remain inside its text.
    pub fn from_entry(entry: &SessionEntry) -> Result<Self> {
        crate::session::validate_entry(entry)?;
        let calls = entry
            .tool_calls
            .as_slice()
            .iter()
            .map(|call| {
                Value::object(vec![
                    ("id".into(), text(&call.id)?),
                    ("name".into(), text(&call.name)?),
                    ("arguments".into(), text(&call.arguments)?),
                ])
            })
            .collect::<Result<Vec<_>>>()?;
        let data = Value::object(vec![
            ("content".into(), text(entry.content.as_str())?),
            (
                "role".into(),
                text(match entry.role {
                    SessionRole::Owner => "owner",
                    SessionRole::Auma => "auma",
                    SessionRole::Tool => "tool",
                    SessionRole::Context => "context",
                })?,
            ),
            ("tool_calls".into(), Value::array(calls)?),
            (
                "tool_call_id".into(),
                entry
                    .tool_call_id
                    .as_ref()
                    .map(|id| text(id.as_str()))
                    .transpose()?
                    .unwrap_or_else(Value::null),
            ),
        ])?;
        Ok(Self {
            provenance: entry.provenance.clone(),
            content: Text::new(canonical_text(&data)?)?,
            source_session: Some(entry.session_id),
            source_sequence: Some(entry.sequence),
        })
    }
}

/// History, memory and documents enter this collection only as literal data.
#[derive(Clone, Debug)]
pub struct Context {
    items: Items<ContextItem, MAX_CONTEXT_ITEMS>,
    bytes: usize,
}

impl Context {
    pub fn new(items: Vec<ContextItem>) -> Result<Self> {
        if items.len() > MAX_CONTEXT_ITEMS {
            return Err(codes::FRAME_TOO_LARGE);
        }
        let mut bytes = 0usize;
        let mut references = BTreeSet::new();
        for item in &items {
            if matches!(item.provenance.source, Source::Stranger) {
                return Err(codes::FRAME_PROVENANCE);
            }
            if item.source_session.is_some() != item.source_sequence.is_some()
                || item
                    .source_sequence
                    .is_some_and(|s| s == 0 || s > crate::session::MAX_SEQUENCE)
            {
                return Err(codes::SESSION_SEQUENCE);
            }
            if let (Some(session_id), Some(sequence)) = (item.source_session, item.source_sequence)
            {
                if !references.insert((session_id, sequence)) {
                    return Err(codes::SESSION_SEQUENCE);
                }
            }
            bytes = bytes
                .checked_add(item.content.as_str().len())
                .ok_or(codes::FRAME_TOO_LARGE)?;
            if bytes > MAX_CONTEXT_BYTES {
                return Err(codes::FRAME_TOO_LARGE);
            }
        }
        Ok(Self {
            items: Items::new(items)?,
            bytes,
        })
    }

    /// Projects a bounded retained transcript without recreating live owner commands.
    pub fn from_entries(entries: &[SessionEntry]) -> Result<Self> {
        if entries.len() > MAX_CONTEXT_ITEMS {
            return Err(codes::FRAME_TOO_LARGE);
        }
        Self::new(
            entries
                .iter()
                .map(ContextItem::from_entry)
                .collect::<Result<Vec<_>>>()?,
        )
    }

    /// Replaces the newest verified summary's source range only in the model view.
    /// The retained window includes the original source records and its appended summary.
    pub fn from_compacted_entries(entries: &[SessionEntry]) -> Result<Self> {
        if entries.len() > MAX_REPLAY_ENTRIES {
            return Err(codes::FRAME_TOO_LARGE);
        }
        let Some(first) = entries.first() else {
            return Self::new(Vec::new());
        };
        let mut expected = first.sequence;
        for entry in entries {
            crate::session::validate_entry(entry)?;
            if entry.session_id != first.session_id || entry.sequence != expected {
                return Err(codes::SESSION_SEQUENCE);
            }
            expected = expected.checked_add(1).ok_or(codes::SESSION_SEQUENCE)?;
        }
        let mut newest = None;
        for index in (0..entries.len()).rev() {
            if let Some(range) = crate::compaction::covered_range(&entries[index])? {
                crate::compaction::check_source(&entries[..index], &range)?;
                newest = Some((index, range));
                break;
            }
        }
        let Some((summary_index, range)) = newest else {
            return Self::from_entries(entries);
        };
        let mut items = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            if entry.sequence == range.first_sequence {
                items.push(ContextItem::from_entry(&entries[summary_index])?);
            }
            if index == summary_index
                || (range.first_sequence..=range.last_sequence).contains(&entry.sequence)
            {
                continue;
            }
            items.push(ContextItem::from_entry(entry)?);
        }
        Self::new(items)
    }

    pub fn items(&self) -> &[ContextItem] {
        self.items.as_slice()
    }
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

#[derive(Clone, Debug)]
pub struct ContextRequest {
    pub session_id: SessionId,
    pub through_sequence: u64,
    pub durable: DurablePrefix,
    pub historical_data: Context,
    pub informational_time_ms: Option<u64>,
}

impl ContextRequest {
    pub fn validate(&self) -> Result<()> {
        self.durable
            .require(self.session_id, self.through_sequence)?;
        if self
            .informational_time_ms
            .is_some_and(|value| value > crate::session::MAX_SEQUENCE)
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        for item in self.historical_data.items() {
            if item.source_session == Some(self.session_id)
                && item
                    .source_sequence
                    .is_some_and(|sequence| sequence > self.through_sequence)
            {
                return Err(codes::SESSION_SEQUENCE);
            }
        }
        Ok(())
    }
}

/// Implementations retain source labels in provider messages; no context becomes a system prompt.
pub trait ContextAssembler {
    fn assemble(
        &mut self,
        request: ContextRequest,
    ) -> Result<Vec<canon::fd3_payloads::ModelMessage>>;
}

/// Captures external durable prefixes and emits only labelled user-role data messages.
#[derive(Clone, Debug, Default)]
pub struct BoundedContextAssembler {
    references: BTreeMap<SessionId, DurablePrefix>,
}

impl BoundedContextAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// A receipt permits references only through its frozen sequence, never beyond it.
    pub fn register_reference(&mut self, durable: DurablePrefix) -> Result<()> {
        let session_id = durable.session_id();
        if let Some(previous) = self.references.get(&session_id) {
            if previous.sequence() > durable.sequence()
                || (previous.sequence() == durable.sequence()
                    && previous.commitment() != durable.commitment())
            {
                return Err(codes::SESSION_SEQUENCE);
            }
        }
        if !self.references.contains_key(&session_id)
            && self.references.len() >= MAX_REFERENCED_SESSIONS
        {
            return Err(codes::FRAME_TOO_LARGE);
        }
        self.references.insert(session_id, durable);
        Ok(())
    }

    pub fn clear_references(&mut self) {
        self.references.clear();
    }
}

impl ContextAssembler for BoundedContextAssembler {
    fn assemble(&mut self, request: ContextRequest) -> Result<Vec<ModelMessage>> {
        request.validate()?;
        let count = request.historical_data.items().len()
            + usize::from(request.informational_time_ms.is_some());
        if count > MAX_CONTEXT_ITEMS {
            return Err(codes::FRAME_TOO_LARGE);
        }
        let mut messages = Vec::with_capacity(count);
        let mut bytes = 2usize;
        for item in request.historical_data.items() {
            if let (Some(session_id), Some(sequence)) = (item.source_session, item.source_sequence)
            {
                if session_id != request.session_id {
                    let prefix = self
                        .references
                        .get(&session_id)
                        .ok_or(codes::SESSION_SEQUENCE)?;
                    if sequence > prefix.sequence() {
                        return Err(codes::SESSION_SEQUENCE);
                    }
                }
            }
            let data = Value::object(vec![
                ("type".into(), text("aukora-context-data-v1")?),
                ("authority".into(), text("historical-data")?),
                ("source".into(), source_value(&item.provenance.source)?),
                (
                    "source_session".into(),
                    item.source_session
                        .map(|session_id| text(&session_id.to_string()))
                        .transpose()?
                        .unwrap_or_else(Value::null),
                ),
                (
                    "source_sequence".into(),
                    item.source_sequence
                        .map(integer)
                        .transpose()?
                        .unwrap_or_else(Value::null),
                ),
                ("content".into(), text(item.content.as_str())?),
            ])?;
            push_message(&mut messages, &mut bytes, data)?;
        }
        if let Some(at_ms) = request.informational_time_ms {
            push_message(
                &mut messages,
                &mut bytes,
                Value::object(vec![
                    ("type".into(), text("aukora-context-time-v1")?),
                    ("authority".into(), text("informational-data")?),
                    ("at_ms".into(), integer(at_ms)?),
                ])?,
            )?;
        }
        Ok(messages)
    }
}

fn source_value(source: &Source) -> Result<Value> {
    let (label, identity) = match source {
        Source::Owner => ("owner", None),
        Source::Auma => ("auma", None),
        Source::Contact(npub) => ("contact", Some(npub.as_str().to_owned())),
        Source::App(app_id) => ("app", Some(app_id.to_string())),
        Source::Document => ("document", None),
        Source::Memory => ("memory", None),
        Source::Stranger => return Err(codes::FRAME_PROVENANCE),
    };
    Value::object(vec![
        ("kind".into(), text(label)?),
        (
            "identity".into(),
            identity
                .map(Value::text)
                .transpose()?
                .unwrap_or_else(Value::null),
        ),
    ])
}

fn push_message(messages: &mut Vec<ModelMessage>, bytes: &mut usize, data: Value) -> Result<()> {
    let content = canonical_text(&data)?;
    let serialized = Value::object(vec![
        ("role".into(), text("user")?),
        ("content".into(), text(&content)?),
    ])?;
    *bytes = bytes
        .checked_add(serialized.canonical_bytes().len())
        .and_then(|length| length.checked_add(usize::from(!messages.is_empty())))
        .ok_or(codes::FRAME_TOO_LARGE)?;
    if *bytes > MAX_CONTEXT_BYTES {
        return Err(codes::FRAME_TOO_LARGE);
    }
    messages.push(ModelMessage {
        role: "user".into(),
        content: Some(content),
        tool_calls: None,
        tool_call_id: None,
    });
    Ok(())
}

fn canonical_text(value: &Value) -> Result<String> {
    String::from_utf8(value.canonical_bytes()).map_err(|_| codes::FRAME_INVALID_FIELD)
}

fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}

fn integer(value: u64) -> Result<Value> {
    let number = i64::try_from(value).map_err(|_| codes::SESSION_SEQUENCE)?;
    Ok(Value::integer(SafeInteger::new(number)?))
}
