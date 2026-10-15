// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded context data with explicit source labels and sequence references.

use crate::session::DurablePrefix;
use canon::{
    codes,
    ids::SessionId,
    provenance::{Provenance, Source},
    session::{Items, Text},
    Result,
};

pub const MAX_CONTEXT_ITEMS: usize = 128;
pub const MAX_CONTEXT_BYTES: usize = 48_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextItem {
    pub provenance: Provenance,
    pub content: Text<32_768>,
    pub source_session: Option<SessionId>,
    pub source_sequence: Option<u64>,
}

/// History, memory and documents enter this collection only as literal data.
#[derive(Clone, Debug)]
pub struct Context {
    items: Items<ContextItem, MAX_CONTEXT_ITEMS>,
    bytes: usize,
}

impl Context {
    pub fn new(items: Vec<ContextItem>) -> Result<Self> {
        let mut bytes = 0usize;
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
