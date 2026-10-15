// SPDX-License-Identifier: AGPL-3.0-or-later
//! A bounded producer queue. These stream records never admit or settle spending.

use crate::receipt::{CommittedReceipt, SettlementOutcome};
use canon::{
    alg::AlgorithmId,
    codes,
    fd3_payloads::ToolCall,
    session::{
        Items, ModelCancel, ModelDelta, ModelEnd, ModelError, ModelStarted, Text, MAX_DELTA_BYTES,
        MAX_PENDING_CHUNKS, RECORD_VERSION,
    },
    Result,
};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub const MAX_STREAM_CHUNKS: u64 = 4_096;
pub const MAX_STREAM_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminal {
    End(ModelEnd),
    Error(ModelError),
    Cancel(ModelEnd),
}

pub struct StreamBuffer {
    started: ModelStarted,
    queue: VecDeque<ModelDelta>,
    next_index: u64,
    delivered: u64,
    bytes: usize,
    deadline: Instant,
    cancelling: bool,
    terminal: Option<Terminal>,
    closed: bool,
}

impl StreamBuffer {
    pub fn new(started: ModelStarted) -> Result<Self> {
        if !(1..=MAX_PENDING_CHUNKS).contains(&started.max_pending_chunks) {
            return Err(codes::BROKER_INVALID_REQUEST);
        }
        Ok(Self {
            started,
            queue: VecDeque::new(),
            next_index: 0,
            delivered: 0,
            bytes: 0,
            deadline: Instant::now() + Duration::from_millis(crate::provider::PROVIDER_DEADLINE_MS),
            cancelling: false,
            terminal: None,
            closed: false,
        })
    }

    pub fn can_poll_provider(&self) -> bool {
        self.production_refusal().is_none()
    }

    pub fn started(&self) -> &ModelStarted {
        &self.started
    }

    /// A full window is transient; elapsed time and output limits require settlement.
    pub fn production_refusal(&self) -> Option<canon::Refusal> {
        if self.closed || self.terminal.is_some() || self.cancelling {
            Some(codes::BROKER_STATE)
        } else if Instant::now() >= self.deadline {
            Some(codes::BROKER_PROVIDER_UNAVAILABLE)
        } else if self.next_index >= MAX_STREAM_CHUNKS || self.bytes >= MAX_STREAM_BYTES {
            Some(codes::BROKER_REPLY_TOO_LARGE)
        } else if self.queue.len() >= usize::from(self.started.max_pending_chunks) {
            Some(codes::BROKER_BUSY)
        } else {
            None
        }
    }

    pub fn push(
        &mut self,
        content: Option<Text<MAX_DELTA_BYTES>>,
        calls: Items<ToolCall, 32>,
    ) -> Result<()> {
        if let Some(refusal) = self.production_refusal() {
            return Err(refusal);
        }
        let content_bytes = content.as_ref().map_or(0, |value| value.as_str().len());
        let chunk_bytes = calls
            .as_slice()
            .iter()
            .try_fold(content_bytes, |total, call| {
                total
                    .checked_add(call.id.len())?
                    .checked_add(call.name.len())?
                    .checked_add(call.arguments.len())
            })
            .ok_or(codes::BROKER_REPLY_TOO_LARGE)?;
        let next_bytes = self
            .bytes
            .checked_add(chunk_bytes)
            .ok_or(codes::BROKER_REPLY_TOO_LARGE)?;
        if chunk_bytes > MAX_DELTA_BYTES
            || next_bytes > MAX_STREAM_BYTES
            || self.next_index >= MAX_STREAM_CHUNKS
        {
            return Err(codes::BROKER_REPLY_TOO_LARGE);
        }
        self.queue.push_back(ModelDelta {
            v: RECORD_VERSION,
            algorithm: AlgorithmId::Sha256,
            request_id: self.started.request_id,
            reservation_id: self.started.reservation_id,
            index: self.next_index,
            content,
            tool_calls: calls,
        });
        self.next_index += 1;
        self.bytes = next_bytes;
        Ok(())
    }

    pub fn next_delta(&self) -> Option<&ModelDelta> {
        self.queue.front()
    }

    pub fn acknowledge_delivery(&mut self, index: u64) -> Result<()> {
        let next = self.queue.front().ok_or(codes::BROKER_INVALID_REQUEST)?;
        if next.index != index || index != self.delivered {
            return Err(codes::BROKER_INVALID_REQUEST);
        }
        self.queue.pop_front();
        self.delivered += 1;
        Ok(())
    }

    pub fn request_cancel(&mut self, cancel: &ModelCancel) -> Result<()> {
        if cancel.request_id != self.started.request_id
            || cancel.reservation_id != self.started.reservation_id
            || self.closed
            || self.terminal.is_some()
        {
            return Err(codes::BROKER_INVALID_REQUEST);
        }
        self.cancelling = true;
        Ok(())
    }

    pub fn finish(
        &mut self,
        receipt: &CommittedReceipt,
        finish_reason: Option<Text<256>>,
    ) -> Result<()> {
        receipt.validate()?;
        if self.closed
            || self.terminal.is_some()
            || receipt.body.request_id != self.started.request_id
            || receipt.body.reservation_id != self.started.reservation_id
            || (self.cancelling && receipt.body.outcome == SettlementOutcome::Completed)
            || (receipt.body.outcome == SettlementOutcome::Cancelled && !self.cancelling)
        {
            return Err(codes::BROKER_STATE);
        }
        let wire_receipt = receipt.stream_receipt()?;
        self.terminal = Some(match receipt.body.outcome {
            SettlementOutcome::Completed | SettlementOutcome::Cancelled => {
                let end = ModelEnd {
                    request_id: self.started.request_id,
                    reservation_id: self.started.reservation_id,
                    next_index: self.next_index,
                    finish_reason,
                    receipt: wire_receipt,
                };
                if receipt.body.outcome == SettlementOutcome::Cancelled {
                    Terminal::Cancel(end)
                } else {
                    Terminal::End(end)
                }
            }
            SettlementOutcome::Refused | SettlementOutcome::Unknown => {
                Terminal::Error(ModelError {
                    request_id: self.started.request_id,
                    reservation_id: self.started.reservation_id,
                    next_index: self.next_index,
                    code: receipt.body.refusal.unwrap_or(codes::BROKER_UNKNOWN),
                    next: Text::new("The reservation has a final receipt.".to_owned())?,
                    receipt: wire_receipt,
                })
            }
        });
        Ok(())
    }

    pub fn take_terminal(&mut self) -> Option<Terminal> {
        if !self.queue.is_empty() || self.closed {
            return None;
        }
        let terminal = self.terminal.take()?;
        self.closed = true;
        Some(terminal)
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }
    pub fn pending_chunks(&self) -> usize {
        self.queue.len()
    }
    pub fn total_bytes(&self) -> usize {
        self.bytes
    }
    pub fn is_cancelling(&self) -> bool {
        self.cancelling
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}
