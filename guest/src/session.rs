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
        if request.entry.v != RECORD_VERSION || request.entry.algorithm != AlgorithmId::Sha256 {
            return Err(codes::FRAME_UNSUPPORTED_VERSION);
        }
        if request.entry.provenance.source != Source::Auma
            || request.entry.role == SessionRole::Owner
        {
            return Err(codes::FRAME_PROVENANCE);
        }
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
        if reply.v != RECORD_VERSION || reply.algorithm != AlgorithmId::Sha256 {
            return Err(codes::FRAME_UNSUPPORTED_VERSION);
        }
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
        if self.session_id != session_id || self.sequence != sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        Ok(())
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn commitment(&self) -> Digest32 {
        self.commitment
    }
}

/// A page is validated against the requested cursor without rewriting historical provenance.
pub fn check_page(request: &SessionOpen, page: &SessionOpened) -> Result<()> {
    if page.summary.v != RECORD_VERSION || page.summary.algorithm != AlgorithmId::Sha256 {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
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
        if entry.v != RECORD_VERSION || entry.algorithm != AlgorithmId::Sha256 {
            return Err(codes::FRAME_UNSUPPORTED_VERSION);
        }
        crate::rails::historical_input(entry)?;
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
