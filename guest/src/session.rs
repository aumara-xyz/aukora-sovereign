// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host-backed persistence contracts; this module contains no filesystem access.

use canon::{
    alg::AlgorithmId, codes, digest::Digest32, ids::SessionId, provenance::Source, session::*,
    Result,
};

pub const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;

/// All records use canon's versioned schemas. The implementation routes these calls over FD 3.
/// Only the supervisor recovers a torn tail; malformed complete entries must refuse recovery.
pub trait SessionStore {
    fn create(&mut self, request: SessionCreate) -> Result<SessionSummary>;
    fn open(&mut self, request: SessionOpen) -> Result<SessionOpened>;
    fn list(&mut self, request: SessionList) -> Result<SessionPage>;
    fn append(&mut self, request: SessionAppend) -> Result<SessionAppended>;
    fn flush(&mut self, request: SessionFlush) -> Result<SessionFlushed>;
}

/// One outstanding guest append; fresh Owner entries use the supervisor's authenticated ingress.
#[derive(Clone, Debug)]
pub struct PendingAppend {
    request: SessionAppend,
}

impl PendingAppend {
    pub fn new(request: SessionAppend) -> Result<Self> {
        if request.expected_sequence >= MAX_SEQUENCE
            || request.entry.sequence != request.expected_sequence + 1
            || request.entry.session_id != request.session_id
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        check_record(request.entry.v, request.entry.algorithm)?;
        if request.entry.provenance.source != Source::Auma
            || request.entry.role == SessionRole::Owner
        {
            return Err(codes::FRAME_PROVENANCE);
        }
        validate_entry(&request.entry)?;
        Ok(Self { request })
    }

    pub fn request(&self) -> &SessionAppend {
        &self.request
    }

    pub fn acknowledge(self, response: SessionAppended) -> Result<SessionFlush> {
        if response.entry != self.request.entry {
            return Err(codes::SESSION_SEQUENCE);
        }
        Ok(SessionFlush {
            session_id: response.entry.session_id,
            through_sequence: response.entry.sequence,
        })
    }
}

/// A storage receipt can gate model dispatch, but never supplies passkey authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePrefix {
    session_id: SessionId,
    sequence: u64,
    commitment: Digest32,
}

impl DurablePrefix {
    pub fn from_reply(request: &SessionFlush, reply: &SessionFlushed) -> Result<Self> {
        check_record(reply.v, reply.algorithm)?;
        if request.session_id != reply.session_id
            || request.through_sequence != reply.sequence
            || reply.sequence > MAX_SEQUENCE
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        Ok(Self {
            session_id: reply.session_id,
            sequence: reply.sequence,
            commitment: reply.commitment,
        })
    }

    pub fn require(&self, session_id: SessionId, sequence: u64) -> Result<()> {
        if sequence > MAX_SEQUENCE || self.session_id != session_id || self.sequence != sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        Ok(())
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
    pub const fn commitment(&self) -> Digest32 {
        self.commitment
    }
}

/// A page is validated against the requested cursor without rewriting historical provenance.
pub fn check_page(request: &SessionOpen, page: &SessionOpened) -> Result<()> {
    validate_summary(&page.summary)?;
    checked_reply(canon::fd3::Reply::SessionOpened(page.clone()))?;
    if page.summary.session_id != request.session_id
        || page.summary.sequence > MAX_SEQUENCE
        || request.after_sequence > page.summary.sequence
        || !(1..=100).contains(&request.limit)
        || page.entries.as_slice().len() > usize::from(request.limit)
    {
        return Err(codes::SESSION_SEQUENCE);
    }
    let mut sequence = request.after_sequence;
    for entry in page.entries.as_slice() {
        if sequence >= MAX_SEQUENCE
            || entry.sequence != sequence + 1
            || entry.session_id != request.session_id
            || entry.sequence > page.summary.sequence
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        check_record(entry.v, entry.algorithm)?;
        crate::rails::historical_input(entry)?;
        validate_entry(entry)?;
        sequence = entry.sequence;
    }
    if (sequence < page.summary.sequence && page.next_sequence != Some(sequence))
        || (sequence == page.summary.sequence && page.next_sequence.is_some())
        || (sequence < page.summary.sequence && sequence == request.after_sequence)
    {
        return Err(codes::SESSION_SEQUENCE);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionFacts {
    pub open_sessions: u32,
    pub pending_appends: u32,
    pub acknowledged_sequence: u64,
    pub durable_sequence: u64,
    pub sequence_conflicts: u64,
}

/// The guest retains at most this many open cursors; transcripts remain on the host.
pub const MAX_OPEN_SESSIONS: usize = 32;
/// Bounds the temporary entry collection used by compaction, independently of wire pages.
pub const MAX_COMPACTION_ENTRIES: usize = 128;

fn check_record(version: u16, algorithm: AlgorithmId) -> Result<()> {
    if version != RECORD_VERSION {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    if algorithm != AlgorithmId::Sha256 {
        return Err(codes::ALG_UNSUPPORTED);
    }
    Ok(())
}

fn auma() -> canon::provenance::Provenance {
    canon::provenance::Provenance {
        source: Source::Auma,
    }
}

fn checked_reply(body: canon::fd3::Reply) -> Result<canon::json::Value> {
    let frame = canon::frame::Frame {
        v: canon::fd3::V2,
        id: canon::frame::FrameId::new("session-record".into())?,
        provenance: auma(),
        body,
    };
    canon::json::parse_strict(&canon::fd3::encode_reply(&frame)?)
}

fn validate_summary(summary: &SessionSummary) -> Result<()> {
    check_record(summary.v, summary.algorithm)?;
    checked_reply(canon::fd3::Reply::SessionCreated(summary.clone()))?;
    Ok(())
}

fn entry_value(entry: &SessionEntry) -> Result<canon::json::Value> {
    check_record(entry.v, entry.algorithm)?;
    let envelope = checked_reply(canon::fd3::Reply::SessionAppended(SessionAppended {
        entry: entry.clone(),
    }))?;
    envelope
        .get("body")
        .and_then(|body| body.get("entry"))
        .cloned()
        .ok_or(codes::FRAME_INVALID_FIELD)
}

/// Matches the host's SHA-256 over canonical entry fields with commitment omitted.
/// The record retains its version and algorithm fields in the committed bytes.
pub fn entry_commitment(entry: &SessionEntry) -> Result<Digest32> {
    let value = entry_value(entry)?;
    let canon::json::ValueView::Object(fields) = value.view() else {
        return Err(codes::FRAME_NOT_OBJECT);
    };
    let fields = fields
        .iter()
        .filter(|(key, _)| key != "commitment")
        .cloned()
        .collect();
    let bytes = canon::json::Value::checked_object(fields)?.canonical_bytes();
    Ok(Digest32::sha256(&bytes))
}

/// Validates the frozen codec, record bounds, provenance and its exact commitment.
pub fn validate_entry(entry: &SessionEntry) -> Result<()> {
    if entry_commitment(entry)? != entry.commitment {
        return Err(codes::SESSION_SEQUENCE);
    }
    Ok(())
}

/// Compaction source commitment over a canonical array of complete, validated entries.
/// This is separate from a host flush commitment, which also covers stored log framing.
pub fn entries_commitment(entries: &[SessionEntry]) -> Result<Digest32> {
    if entries.len() > MAX_COMPACTION_ENTRIES {
        return Err(codes::FRAME_STREAM_LIMIT);
    }
    let mut values = Vec::with_capacity(entries.len());
    for entry in entries {
        validate_entry(entry)?;
        values.push(entry_value(entry)?);
    }
    let bytes = canon::json::Value::checked_array(values)?.canonical_bytes();
    Ok(Digest32::sha256(&bytes))
}

#[derive(Debug)]
struct Cursor {
    summary: SessionSummary,
    durable: Option<DurablePrefix>,
}

/// Exclusive typed FD 3 client. It acquires no descriptors and performs no local I/O.
/// One exchange is in flight; a lost or mismatched reply closes the link without retry.
/// The supplied endpoint must have no outstanding replies for other consumers.
pub struct Fd3SessionStore<L: crate::fd3::SupervisorLink> {
    link: L,
    next_id: u64,
    closed: bool,
    cursors: Vec<Cursor>,
    pending_appends: u32,
    sequence_conflicts: u64,
}

impl<L: crate::fd3::SupervisorLink> Fd3SessionStore<L> {
    pub fn new(link: L) -> Self {
        Self {
            link,
            next_id: 0,
            closed: false,
            cursors: Vec::new(),
            pending_appends: 0,
            sequence_conflicts: 0,
        }
    }

    /// Returns the exclusive endpoint for the next harness consumer without a retry or write.
    pub fn into_link(self) -> L {
        self.link
    }

    pub fn close(&mut self) {
        if !self.closed {
            self.link.close();
            self.closed = true;
        }
        for cursor in &mut self.cursors {
            cursor.durable = None;
        }
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Releases only a local cursor; the host's append-only session is retained.
    pub fn release(&mut self, session_id: SessionId) {
        self.cursors
            .retain(|cursor| cursor.summary.session_id != session_id);
    }

    pub fn summary(&self, session_id: SessionId) -> Result<&SessionSummary> {
        Ok(&self.cursors[self.position(session_id)?].summary)
    }

    /// Flushes the exact observed transcript before exposing a model-dispatch fence.
    pub fn before_dispatch(
        &mut self,
        session_id: SessionId,
        sequence: u64,
    ) -> Result<DurablePrefix> {
        if self.summary(session_id)?.sequence != sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        let request = SessionFlush {
            session_id,
            through_sequence: sequence,
        };
        let reply = self.flush(request.clone())?;
        DurablePrefix::from_reply(&request, &reply)
    }

    /// Read-only counters for the caller's health adapter; no counter grants authority.
    pub fn facts(&self, session_id: SessionId) -> Result<SessionFacts> {
        let cursor = &self.cursors[self.position(session_id)?];
        Ok(SessionFacts {
            open_sessions: self.cursors.len() as u32,
            pending_appends: self.pending_appends,
            acknowledged_sequence: cursor.summary.sequence,
            durable_sequence: cursor.durable.as_ref().map_or(0, DurablePrefix::sequence),
            sequence_conflicts: self.sequence_conflicts,
        })
    }

    fn position(&self, id: SessionId) -> Result<usize> {
        self.cursors
            .iter()
            .position(|c| c.summary.session_id == id)
            .ok_or(codes::SESSION_NOT_FOUND)
    }

    fn retain_summary(&mut self, summary: SessionSummary) -> Result<()> {
        match self.position(summary.session_id) {
            Ok(index) => {
                let cursor = &mut self.cursors[index];
                if cursor.summary.sequence > summary.sequence
                    || cursor.summary.thread_id != summary.thread_id
                    || cursor.summary.created_at_ms != summary.created_at_ms
                {
                    self.close();
                    return Err(codes::SESSION_SEQUENCE);
                }
                cursor.summary = summary;
            }
            Err(_) => {
                if self.cursors.len() == MAX_OPEN_SESSIONS {
                    return Err(codes::FRAME_STREAM_LIMIT);
                }
                self.cursors.push(Cursor {
                    summary,
                    durable: None,
                });
            }
        }
        Ok(())
    }

    fn invalid<T>(&mut self, code: canon::Refusal) -> Result<T> {
        self.close();
        Err(code)
    }

    fn exchange(&mut self, body: canon::fd3::Request) -> Result<canon::fd3::Reply> {
        use canon::fd3::Reply;
        if self.closed {
            return Err(codes::SUPERVISOR_NOT_READY);
        }
        let Some(next) = self.next_id.checked_add(1) else {
            return self.invalid(codes::FRAME_INVALID_ID);
        };
        let id = canon::frame::FrameId::new(format!("session_{next}"))?;
        let class = crate::fd3::ReplyClass::of(&body);
        let frame = crate::fd3::request(id.clone(), body);
        canon::fd3::encode_request(&frame)?;
        self.next_id = next;
        if let Err(error) = self.link.send(frame) {
            return self.invalid(error.refusal);
        }
        let response = match self.link.receive() {
            Ok(value) => value,
            Err(error) => return self.invalid(error.refusal),
        };
        if response.id != id {
            return self.invalid(codes::FRAME_INVALID_ID);
        }
        if response.v != canon::fd3::V2 {
            return self.invalid(codes::FRAME_UNSUPPORTED_VERSION);
        }
        if response.provenance != auma() {
            return self.invalid(codes::FRAME_PROVENANCE);
        }
        if let Err(code) =
            canon::fd3::encode_reply(&response).and_then(|_| class.accepts(&response.body))
        {
            return self.invalid(code);
        }
        if let Reply::Refusal(refusal) = response.body {
            return Err(refusal.code);
        }
        Ok(response.body)
    }
}

impl<L: crate::fd3::SupervisorLink> SessionStore for Fd3SessionStore<L> {
    fn create(&mut self, request: SessionCreate) -> Result<SessionSummary> {
        if self.cursors.len() == MAX_OPEN_SESSIONS {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        let canon::fd3::Reply::SessionCreated(summary) =
            self.exchange(canon::fd3::Request::SessionCreate(request.clone()))?
        else {
            return self.invalid(codes::FRAME_UNKNOWN_KIND);
        };
        if summary.thread_id != request.thread_id
            || summary.title != request.title
            || summary.mode != request.mode
            || summary.archived
            || summary.sequence != 0
            || summary.created_at_ms != summary.updated_at_ms
            || self.position(summary.session_id).is_ok()
        {
            return self.invalid(codes::SESSION_SEQUENCE);
        }
        self.retain_summary(summary.clone())?;
        Ok(summary)
    }

    fn open(&mut self, request: SessionOpen) -> Result<SessionOpened> {
        if self.position(request.session_id).is_err() && self.cursors.len() == MAX_OPEN_SESSIONS {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        let canon::fd3::Reply::SessionOpened(page) =
            self.exchange(canon::fd3::Request::SessionOpen(request.clone()))?
        else {
            return self.invalid(codes::FRAME_UNKNOWN_KIND);
        };
        if let Err(code) = check_page(&request, &page) {
            return self.invalid(code);
        }
        self.retain_summary(page.summary.clone())?;
        Ok(page)
    }

    fn list(&mut self, request: SessionList) -> Result<SessionPage> {
        let canon::fd3::Reply::SessionList(page) =
            self.exchange(canon::fd3::Request::SessionList(request.clone()))?
        else {
            return self.invalid(codes::FRAME_UNKNOWN_KIND);
        };
        if let Err(code) = check_list(&request, &page) {
            return self.invalid(code);
        }
        Ok(page)
    }

    fn append(&mut self, request: SessionAppend) -> Result<SessionAppended> {
        let pending = PendingAppend::new(request.clone())?;
        let index = self.position(request.session_id)?;
        if self.cursors[index].summary.sequence != request.expected_sequence {
            self.sequence_conflicts = self.sequence_conflicts.saturating_add(1);
            return Err(codes::SESSION_SEQUENCE);
        }
        self.cursors[index].durable = None;
        self.pending_appends = 1;
        let result = self.exchange(canon::fd3::Request::SessionAppend(request));
        self.pending_appends = 0;
        let response = match result {
            Ok(canon::fd3::Reply::SessionAppended(response)) => response,
            Ok(_) => return self.invalid(codes::FRAME_UNKNOWN_KIND),
            Err(code) => {
                if code == codes::SESSION_SEQUENCE {
                    self.sequence_conflicts = self.sequence_conflicts.saturating_add(1);
                }
                return Err(code);
            }
        };
        if let Err(code) = pending.acknowledge(response.clone()) {
            return self.invalid(code);
        }
        self.cursors[index].summary.sequence = response.entry.sequence;
        self.cursors[index].summary.updated_at_ms = response.entry.at_ms;
        Ok(response)
    }

    fn flush(&mut self, request: SessionFlush) -> Result<SessionFlushed> {
        let index = self.position(request.session_id)?;
        if request.through_sequence > self.cursors[index].summary.sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        let canon::fd3::Reply::SessionFlushed(response) =
            self.exchange(canon::fd3::Request::SessionFlush(request.clone()))?
        else {
            return self.invalid(codes::FRAME_UNKNOWN_KIND);
        };
        let durable = match DurablePrefix::from_reply(&request, &response) {
            Ok(durable) => durable,
            Err(code) => return self.invalid(code),
        };
        if let Some(previous) = &self.cursors[index].durable {
            if previous.sequence() == durable.sequence()
                && previous.commitment() != durable.commitment()
            {
                return self.invalid(codes::SESSION_SEQUENCE);
            }
        }
        if self.cursors[index]
            .durable
            .as_ref()
            .is_none_or(|old| old.sequence() <= durable.sequence())
        {
            self.cursors[index].durable = Some(durable);
        }
        Ok(response)
    }
}

/// Checks list cursor, filter, ordering and exact continuation without opening any session.
pub fn check_list(request: &SessionList, page: &SessionPage) -> Result<()> {
    checked_reply(canon::fd3::Reply::SessionList(page.clone()))?;
    if !(1..=100).contains(&request.limit) || page.items.as_slice().len() > request.limit as usize {
        return Err(codes::SESSION_SEQUENCE);
    }
    let mut before = request.before;
    for summary in page.items.as_slice() {
        validate_summary(summary)?;
        if (!request.include_archived && summary.archived)
            || request.thread_id.is_some_and(|id| id != summary.thread_id)
            || before.is_some_and(|id| summary.session_id >= id)
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        before = Some(summary.session_id);
    }
    if page.next.is_some() && (page.items.as_slice().is_empty() || page.next != before) {
        return Err(codes::SESSION_SEQUENCE);
    }
    Ok(())
}
