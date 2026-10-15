// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compaction describes an append-only summary; original session entries remain retained.

use crate::session::{DurablePrefix, MAX_SEQUENCE};
use canon::{
    codes,
    digest::Digest32,
    ids::SessionId,
    session::{ModelReceipt, SessionEntry, Text},
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
            || self.observed_sequence > MAX_SEQUENCE
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
