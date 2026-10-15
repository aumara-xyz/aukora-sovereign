// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded in-memory scheduling contracts; channel attachment remains outside this module.

use crate::{rails, session::DurablePrefix};
use canon::{
    codes,
    fd3::Reply,
    fd4::ChatTurn,
    frame::Frame,
    ids::{RequestId, ReservationId, SessionId},
    session::{ModelCancel, ModelReceipt, ModelStart, Text},
    Result,
};
use std::collections::VecDeque;

pub const MAX_QUEUED_TURNS: usize = 32;
pub const MAX_STEERING_ITEMS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Stopped,
    Idle,
    AwaitingDurability,
    Streaming,
    Cancelling,
    AwaitingSettlement,
}

#[derive(Clone, Debug)]
pub struct QueuedTurn {
    pub input: Frame<ChatTurn>,
}

/// Live Owner input alone can enqueue a turn. Historical entries use the context API.
#[derive(Debug, Default)]
pub struct TurnQueue {
    pending: VecDeque<QueuedTurn>,
}

impl TurnQueue {
    pub fn enqueue(&mut self, input: Frame<ChatTurn>) -> Result<()> {
        rails::require_live_owner(&input.provenance)?;
        if input.v != canon::fd4::VERSION {
            return Err(codes::FRAME_UNSUPPORTED_VERSION);
        }
        if self.pending.len() >= MAX_QUEUED_TURNS {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        if self.pending.iter().any(|turn| turn.input.id == input.id) {
            return Err(codes::FRAME_INVALID_ID);
        }
        if input.body.expected_sequence > crate::session::MAX_SEQUENCE {
            return Err(codes::SESSION_SEQUENCE);
        }
        self.pending.push_back(QueuedTurn { input });
        Ok(())
    }

    pub fn next_turn(&mut self) -> Option<QueuedTurn> {
        self.pending.pop_front()
    }
    pub fn clear(&mut self) {
        self.pending.clear();
    }
    pub fn len(&self) -> usize {
        self.pending.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct Steering {
    pub session_id: SessionId,
    pub active_request: RequestId,
    pub text: Text<32_768>,
    pub provenance: canon::provenance::Provenance,
}

impl Steering {
    pub fn validate(&self, session_id: SessionId, active_request: RequestId) -> Result<()> {
        rails::require_live_owner(&self.provenance)?;
        if self.session_id != session_id || self.active_request != active_request {
            return Err(codes::FRAME_INVALID_ID);
        }
        Ok(())
    }
}

/// A model dispatch is built only after the exact transcript prefix is durable.
#[derive(Clone, Debug)]
pub struct ReadyModel {
    session_id: SessionId,
    durable: DurablePrefix,
    request: ModelStart,
}

impl ReadyModel {
    pub fn new(
        session_id: SessionId,
        sequence: u64,
        durable: DurablePrefix,
        request: ModelStart,
    ) -> Result<Self> {
        durable.require(session_id, sequence)?;
        if !(1..=canon::session::MAX_PENDING_CHUNKS).contains(&request.max_pending_chunks) {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        Ok(Self {
            session_id,
            durable,
            request,
        })
    }
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
    pub fn durable(&self) -> &DurablePrefix {
        &self.durable
    }
    pub fn into_request(self) -> ModelStart {
        self.request
    }
}

/// Cancellation keeps the reservation outstanding until the broker's terminal receipt arrives.
#[derive(Clone, Debug)]
pub struct OutstandingModel {
    pub request_id: RequestId,
    pub reservation_id: ReservationId,
    pub next_index: u64,
    pub cancellation_requested: bool,
}

impl OutstandingModel {
    pub fn cancellation(&mut self) -> ModelCancel {
        self.cancellation_requested = true;
        ModelCancel {
            request_id: self.request_id,
            reservation_id: self.reservation_id,
        }
    }
}

/// Implementations do not retry model calls and do not infer settlement from a stopped stream.
pub trait AgentLoop {
    fn phase(&self) -> Phase;
    fn queue(&mut self, turn: Frame<ChatTurn>) -> Result<()>;
    fn steer(&mut self, input: Steering) -> Result<()>;
    fn dispatch(&mut self, ready: ReadyModel) -> Result<()>;
    fn reply(&mut self, reply: Frame<Reply>) -> Result<()>;
    fn cancel(&mut self, request: ModelCancel, keep_queue: bool) -> Result<()>;
    fn settled(&mut self, receipt: ModelReceipt) -> Result<()>;
    fn stop(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopFacts {
    pub phase: Phase,
    pub queued_turns: u16,
    pub queued_steering: u16,
    pub pending_model_reservations: u16,
    pub pending_proposals: u16,
    pub pending_deltas: u16,
}
