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

use crate::{dispatch::ProposalTracker, fd3::SupervisorLink};
use canon::{
    fd3::Request,
    fd3_payloads::ToolCall,
    fd4::SessionEvent,
    frame::FrameId,
    provenance::{Provenance, Source},
    session::ModelStream,
};
use std::collections::{BTreeMap, BTreeSet};

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
        if input.body.expected_sequence >= crate::session::MAX_SEQUENCE {
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
        canon::fd3::encode_request(&crate::fd3::request(
            FrameId::new("ready-model".into())?,
            Request::ModelStart(request.clone()),
        ))?;
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

pub const MAX_OUTPUT_EVENTS: usize = 32;
pub const MAX_USED_MODEL_IDS: usize = 1_024;
pub const MAX_PENDING_TOOLS: usize = 32;

#[derive(Debug)]
struct ActiveModel {
    frame_id: FrameId,
    cancel_id: Option<FrameId>,
    outstanding: OutstandingModel,
    requested_window: u16,
    stream: Option<ModelStream>,
    receipt: Option<ModelReceipt>,
    suggestions: BTreeMap<String, ToolCall>,
    suggestion_bytes: usize,
    declared: BTreeSet<String>,
    successful: bool,
}

#[derive(Debug)]
struct PendingTool {
    call_id: String,
    request: Request,
    accepted: Option<String>,
    event_id: FrameId,
    session_id: SessionId,
}

#[derive(Clone, Debug)]
pub struct ToolResult {
    pub call_id: String,
    pub session_id: SessionId,
    pub reply: Reply,
}

/// An externally driven scheduler over an already attached supervisor endpoint.
/// It never polls by itself, retries a request or derives an owner turn from model output.
pub struct BoundedAgentLoop<L: SupervisorLink> {
    link: L,
    phase: Phase,
    stopping: bool,
    queue: TurnQueue,
    turn: Option<QueuedTurn>,
    steering: VecDeque<Steering>,
    model: Option<ActiveModel>,
    events: VecDeque<Frame<SessionEvent>>,
    results: VecDeque<ToolResult>,
    proposals: ProposalTracker,
    tools: BTreeMap<String, PendingTool>,
    used_calls: BTreeSet<String>,
    suggestions: BTreeMap<String, ToolCall>,
    used_requests: BTreeSet<RequestId>,
    used_reservations: BTreeSet<ReservationId>,
    next_id: u64,
    required_sequence: u64,
    durable_sequence: u64,
    rails: rails::ConversationRails,
}

impl<L: SupervisorLink> BoundedAgentLoop<L> {
    pub fn new(link: L) -> Self {
        Self {
            link,
            phase: Phase::Idle,
            stopping: false,
            queue: TurnQueue::default(),
            turn: None,
            steering: VecDeque::new(),
            model: None,
            events: VecDeque::new(),
            results: VecDeque::new(),
            proposals: ProposalTracker::default(),
            tools: BTreeMap::new(),
            used_calls: BTreeSet::new(),
            used_requests: BTreeSet::new(),
            used_reservations: BTreeSet::new(),
            next_id: 0,
            suggestions: BTreeMap::new(),
            required_sequence: 0,
            durable_sequence: 0,
            rails: rails::ConversationRails::new(),
        }
    }

    /// Claims one live owner turn. Its transcript must be persisted before dispatch.
    pub fn begin_turn(&mut self) -> Result<Option<&Frame<ChatTurn>>> {
        if self.stopping || self.phase != Phase::Idle || self.turn.is_some() {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        self.turn = self.queue.next_turn();
        if self.turn.is_some() {
            self.phase = Phase::AwaitingDurability;
            self.used_calls.clear();
            self.suggestions.clear();
            let sequence = self
                .turn
                .as_ref()
                .ok_or(codes::SESSION_SEQUENCE)?
                .input
                .body
                .expected_sequence;
            self.required_sequence = sequence
                .checked_add(1)
                .filter(|s| *s <= crate::session::MAX_SEQUENCE)
                .ok_or(codes::SESSION_SEQUENCE)?;
            self.durable_sequence = sequence;
        }
        Ok(self.turn.as_ref().map(|turn| &turn.input))
    }

    /// Refuses to discard steering, unsettled spending or tool outcomes at a turn boundary.
    pub fn finish_turn(&mut self) -> Result<()> {
        if self.stopping
            || self.phase != Phase::AwaitingDurability
            || self.model.is_some()
            || self.turn.is_none()
            || !self.steering.is_empty()
            || self.waiting_tools()
            || !self.results.is_empty()
            || !self.events.is_empty()
            || self.durable_sequence < self.required_sequence
        {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        self.turn = None;
        self.suggestions.clear();
        self.phase = Phase::Idle;
        Ok(())
    }

    /// Records a new host flush fence before another step or final turn completion.
    pub fn observe_durable(&mut self, durable: &DurablePrefix) -> Result<()> {
        let turn = self.turn.as_ref().ok_or(codes::FRAME_STREAM_ORDER)?;
        if durable.session_id() != turn.input.body.session_id
            || durable.sequence() < self.required_sequence
            || durable.sequence() < self.durable_sequence
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        self.durable_sequence = durable.sequence();
        Ok(())
    }

    fn waiting_tools(&self) -> bool {
        self.tools.values().any(|tool| tool.accepted.is_none())
    }

    fn need_entry(&mut self, count: usize) -> Result<()> {
        self.required_sequence = self
            .required_sequence
            .checked_add(count as u64)
            .filter(|s| *s <= crate::session::MAX_SEQUENCE)
            .ok_or(codes::SESSION_SEQUENCE)?;
        Ok(())
    }

    /// Steering is taken only between model requests and retains its owner ingress label.
    pub fn take_steering(&mut self) -> Result<Vec<Steering>> {
        if self.phase != Phase::AwaitingDurability || self.model.is_some() || self.stopping {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        self.need_entry(self.steering.len())?;
        Ok(self.steering.drain(..).collect())
    }

    pub fn event(&self) -> Option<&Frame<SessionEvent>> {
        self.events.front()
    }

    /// A failed FD 4 write retains the event and leaves every reservation outstanding.
    pub fn forward_event(&mut self, app: &mut impl crate::fd3::AppLink) -> Result<bool> {
        let Some(event) = self.events.front().cloned() else {
            return Ok(false);
        };
        if let Err(error) = app.send(event.clone()) {
            if error.disposition == canon::frame::Disposition::Close {
                app.close();
                self.fail();
            }
            return Err(error.refusal);
        }
        self.acknowledge_event(&event)?;
        Ok(true)
    }

    /// Call only after the exact front event has been forwarded. Failed writes retain it.
    pub fn acknowledge_event(&mut self, expected: &Frame<SessionEvent>) -> Result<()> {
        if self.events.front() != Some(expected) {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        if let SessionEvent::ModelDelta(delta) = &expected.body {
            let model = self.model.as_mut().ok_or(codes::FRAME_STREAM_ORDER)?;
            let stream = model.stream.as_mut().ok_or(codes::FRAME_STREAM_ORDER)?;
            if delta.index < stream.first_pending() || delta.index >= stream.next_index() {
                return Err(codes::FRAME_STREAM_ORDER);
            }
            if let Err(error) =
                self.link
                    .acknowledge_delta(delta.request_id, delta.reservation_id, delta.index)
            {
                self.fail();
                return Err(error);
            }
            self.model
                .as_mut()
                .ok_or(codes::FRAME_STREAM_ORDER)?
                .stream
                .as_mut()
                .ok_or(codes::FRAME_STREAM_ORDER)?
                .acknowledge_through(delta.index)?;
        }
        self.events.pop_front();
        Ok(())
    }

    pub fn tool_result(&self) -> Option<&ToolResult> {
        self.results.front()
    }

    /// A consumer retains tool output as data before acknowledging it here.
    pub fn acknowledge_tool_result(&mut self, call_id: &str) -> Result<()> {
        if self.results.front().map(|result| result.call_id.as_str()) != Some(call_id) {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        if self.turn.as_ref().is_some_and(|turn| {
            self.results
                .front()
                .is_some_and(|result| result.session_id == turn.input.body.session_id)
        }) {
            self.need_entry(1)?;
        }
        match &self.results.front().ok_or(codes::FRAME_STREAM_ORDER)?.reply {
            Reply::Outcome(outcome) => {
                self.proposals.forget_terminal(outcome.proposal_id)?;
            }
            Reply::LegacyOutcome { proposal_id, .. } => {
                self.proposals.forget_legacy_terminal(proposal_id)?;
            }
            _ => {}
        }
        self.results.pop_front();
        Ok(())
    }

    pub fn proposals(&self) -> &ProposalTracker {
        &self.proposals
    }

    pub fn rails_facts(&self) -> rails::RailsFacts {
        self.rails.facts()
    }

    pub fn suggestions(&self) -> impl Iterator<Item = &ToolCall> {
        self.suggestions.values()
    }

    /// Only complete, receipt-backed model suggestions reach the closed decoder and gate.
    pub fn suggest(
        &mut self,
        suggestion: &ToolCall,
        decoder: &mut impl crate::dispatch::SuggestionDecoder,
        gate: &crate::action_gate::LocalGate,
    ) -> Result<FrameId> {
        if self.stopping
            || self.phase != Phase::AwaitingDurability
            || self.model.is_some()
            || self.tools.len() >= crate::fd3::MAX_IN_FLIGHT - 2
            || self.used_calls.len() >= MAX_PENDING_TOOLS
        {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        let turn = self.turn.as_ref().ok_or(codes::FRAME_STREAM_ORDER)?;
        if self.durable_sequence < self.required_sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        if self.used_calls.contains(&suggestion.id) {
            return Err(codes::FRAME_INVALID_ID);
        }
        if self.suggestions.get(&suggestion.id) != Some(suggestion) {
            return Err(codes::FRAME_INVALID_ID);
        }
        let event_id = turn.input.id.clone();
        let session_id = turn.input.body.session_id;
        let item = crate::dispatch::prepare(suggestion, decoder, gate, turn.input.body.mode)?;
        let id = self.fresh_id()?;
        let frame = crate::fd3::request(id.clone(), item.request.clone());
        self.write(frame)?;
        self.used_calls.insert(item.call_id.clone());
        self.suggestions.remove(&item.call_id);
        self.tools.insert(
            id.as_str().into(),
            PendingTool {
                call_id: item.call_id,
                request: item.request,
                accepted: None,
                event_id,
                session_id,
            },
        );
        Ok(id)
    }

    /// Reads at most one reply. Capacity is checked before consuming channel bytes.
    pub fn receive_one(&mut self) -> Result<()> {
        self.capacity()?;
        let reply = match self.link.receive() {
            Ok(reply) => reply,
            Err(error) => {
                self.fail();
                return Err(error.refusal);
            }
        };
        self.reply(reply)
    }

    pub fn facts(&self) -> LoopFacts {
        LoopFacts {
            phase: self.phase,
            queued_turns: self.queue.len() as u16,
            queued_steering: self.steering.len() as u16,
            pending_model_reservations: u16::from(self.model.is_some()),
            pending_proposals: self.proposals.pending_count() as u16,
            pending_deltas: self
                .model
                .as_ref()
                .and_then(|model| model.stream.as_ref())
                .map_or(0, |stream| {
                    (stream.next_index() - stream.first_pending()) as u16
                }),
        }
    }

    fn capacity(&self) -> Result<()> {
        if self.events.len() >= MAX_OUTPUT_EVENTS || self.results.len() >= MAX_PENDING_TOOLS {
            return Err(codes::BROKER_BUSY);
        }
        Ok(())
    }

    fn fresh_id(&mut self) -> Result<FrameId> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .filter(|id| *id <= crate::session::MAX_SEQUENCE)
            .ok_or(codes::FRAME_STREAM_LIMIT)?;
        FrameId::new(format!("h-{}", self.next_id))
    }

    fn write(&mut self, frame: Frame<Request>) -> Result<()> {
        canon::fd3::encode_request(&frame)?;
        if let Err(error) = self.link.send(frame) {
            self.fail();
            return Err(error.refusal);
        }
        Ok(())
    }

    fn fail(&mut self) {
        self.link.close();
        self.stopping = true;
        self.phase = Phase::Stopped;
        self.queue.clear();
        self.steering.clear();
    }

    fn emit(&mut self, id: FrameId, body: SessionEvent) -> Result<()> {
        let event = Frame {
            v: canon::fd4::VERSION,
            id,
            provenance: Provenance {
                source: Source::Auma,
            },
            body,
        };
        canon::fd4::encode_event(&event)?;
        self.events.push_back(event);
        Ok(())
    }

    fn model_reply(&mut self, frame: Frame<Reply>) -> Result<()> {
        let model = self.model.as_mut().ok_or(codes::FRAME_INVALID_ID)?;
        let cancellation_reply = model.cancel_id.as_ref() == Some(&frame.id);
        let cancelled = matches!(&frame.body, Reply::ModelCancelled(_));
        if frame.id != model.frame_id && !cancellation_reply {
            return Err(codes::FRAME_INVALID_ID);
        }
        let event = match frame.body {
            Reply::ModelStarted(start) => {
                if cancellation_reply
                    || model.stream.is_some()
                    || model.receipt.is_some()
                    || start.request_id != model.outstanding.request_id
                    || start.reservation_id != model.outstanding.reservation_id
                    || start.max_pending_chunks > model.requested_window
                {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                model.stream = Some(ModelStream::new(&start)?);
                if !self.stopping {
                    self.phase = if model.outstanding.cancellation_requested {
                        Phase::Cancelling
                    } else {
                        Phase::Streaming
                    };
                }
                SessionEvent::ModelStarted(start)
            }
            Reply::ModelDelta(delta) => {
                if cancellation_reply {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                let mut bytes = model.suggestion_bytes;
                let mut ids = BTreeSet::new();
                for call in delta.tool_calls.as_slice() {
                    if !model.declared.contains(&call.name)
                        || model.suggestions.contains_key(&call.id)
                        || !ids.insert(call.id.clone())
                    {
                        return Err(codes::FRAME_INVALID_ID);
                    }
                    bytes = bytes
                        .checked_add(call.id.len() + call.name.len() + call.arguments.len())
                        .filter(|bytes| *bytes <= 32_768)
                        .ok_or(codes::FRAME_STREAM_LIMIT)?;
                }
                if model.suggestions.len() + ids.len() > MAX_PENDING_TOOLS {
                    return Err(codes::FRAME_STREAM_LIMIT);
                }
                model
                    .stream
                    .as_mut()
                    .ok_or(codes::FRAME_STREAM_ORDER)?
                    .observe_delta(&delta)?;
                model.outstanding.next_index = delta.index + 1;
                for call in delta.tool_calls.as_slice() {
                    model.suggestions.insert(call.id.clone(), call.clone());
                }
                model.suggestion_bytes = bytes;
                SessionEvent::ModelDelta(delta)
            }
            Reply::ModelEnd(end) | Reply::ModelCancelled(end) => {
                if cancellation_reply && !cancelled {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                model
                    .stream
                    .as_mut()
                    .ok_or(codes::FRAME_STREAM_ORDER)?
                    .observe_end(&end)?;
                model.receipt = Some(end.receipt.clone());
                model.successful = !cancelled && !model.outstanding.cancellation_requested;
                if cancellation_reply {
                    model.cancel_id = None;
                }
                if !self.stopping {
                    self.phase = Phase::AwaitingSettlement;
                }
                if cancelled {
                    SessionEvent::ModelCancelled(end)
                } else {
                    SessionEvent::ModelEnd(end)
                }
            }
            Reply::ModelError(error) => {
                if cancellation_reply {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                model
                    .stream
                    .as_mut()
                    .ok_or(codes::FRAME_STREAM_ORDER)?
                    .observe_error(&error)?;
                model.receipt = Some(error.receipt.clone());
                if !self.stopping {
                    self.phase = Phase::AwaitingSettlement;
                }
                SessionEvent::ModelError(error)
            }
            Reply::Refusal(refusal) => {
                if cancellation_reply {
                    model.cancel_id = None;
                    model.outstanding.cancellation_requested = false;
                    if !self.stopping && model.receipt.is_none() {
                        self.phase = if model.stream.is_some() {
                            Phase::Streaming
                        } else {
                            Phase::AwaitingSettlement
                        };
                    }
                } else if model.stream.is_some() || model.receipt.is_some() {
                    return Err(codes::FRAME_STREAM_ORDER);
                } else {
                    self.model = None;
                    if !self.stopping {
                        self.phase = Phase::AwaitingDurability;
                    }
                }
                SessionEvent::Refusal(refusal)
            }
            _ => return Err(codes::FRAME_UNKNOWN_KIND),
        };
        let id = self
            .turn
            .as_ref()
            .ok_or(codes::FRAME_STREAM_ORDER)?
            .input
            .id
            .clone();
        self.emit(id, event)
    }

    fn tool_reply(&mut self, frame: Frame<Reply>) -> Result<()> {
        let key = frame.id.as_str();
        let tool = self.tools.get_mut(key).ok_or(codes::FRAME_INVALID_ID)?;
        crate::fd3::ReplyClass::of(&tool.request).accepts(&frame.body)?;
        let event = match &frame.body {
            Reply::Accepted(accepted) => {
                if tool.accepted.is_some() {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                self.proposals.accepted(accepted.clone())?;
                tool.accepted = Some(accepted.proposal_id.to_string());
                Some(SessionEvent::ProposalAccepted(accepted.clone()))
            }
            Reply::Outcome(outcome) => {
                if tool.accepted.as_deref() != Some(&outcome.proposal_id.to_string()) {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                self.proposals.outcome(outcome.clone())?;
                Some(SessionEvent::ProposalOutcome(outcome.clone()))
            }
            Reply::LegacyAccepted { proposal_id } => {
                if tool.accepted.is_some() {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                self.proposals.observe_reply(&frame.body)?;
                tool.accepted = Some(proposal_id.clone());
                Some(SessionEvent::LegacyProposalAccepted {
                    proposal_id: proposal_id.clone(),
                })
            }
            Reply::LegacyOutcome { proposal_id, state } => {
                if tool.accepted.as_ref() != Some(proposal_id) {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                self.proposals.observe_reply(&frame.body)?;
                Some(SessionEvent::LegacyProposalOutcome {
                    proposal_id: proposal_id.clone(),
                    state: *state,
                })
            }
            Reply::Recall(value) => Some(SessionEvent::MemoryRecall(value.clone())),
            Reply::MemoryListReply(value) => Some(SessionEvent::MemoryListed(value.clone())),
            Reply::Refusal(value) => {
                if tool.accepted.is_some() {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                Some(SessionEvent::Refusal(value.clone()))
            }
            Reply::ReadReply(value) => {
                let Request::Read(request) = &tool.request else {
                    return Err(codes::FRAME_UNKNOWN_KIND);
                };
                if value.target != request.target {
                    return Err(codes::FRAME_INVALID_FIELD);
                }
                None
            }
            _ => return Err(codes::FRAME_UNKNOWN_KIND),
        };
        let call_id = tool.call_id.clone();
        let event_id = tool.event_id.clone();
        let terminal = !matches!(
            frame.body,
            Reply::Accepted(_) | Reply::LegacyAccepted { .. }
        );
        self.results.push_back(ToolResult {
            call_id,
            session_id: tool.session_id,
            reply: frame.body,
        });
        if terminal {
            self.tools.remove(key);
        }
        if let Some(event) = event {
            self.emit(event_id, event)?;
        }
        Ok(())
    }
}

impl<L: SupervisorLink> AgentLoop for BoundedAgentLoop<L> {
    fn phase(&self) -> Phase {
        self.phase
    }

    fn queue(&mut self, turn: Frame<ChatTurn>) -> Result<()> {
        self.rails.require_turn(&turn.provenance)?;
        if self.stopping {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        if self
            .turn
            .as_ref()
            .is_some_and(|current| current.input.id == turn.id)
            || self.tools.values().any(|tool| tool.event_id == turn.id)
        {
            return Err(codes::FRAME_INVALID_ID);
        }
        canon::fd4::encode_command(&Frame {
            v: turn.v,
            id: turn.id.clone(),
            provenance: turn.provenance.clone(),
            body: canon::fd4::ChatCommand::Turn(turn.body.clone()),
        })?;
        self.queue.enqueue(turn)
    }

    fn steer(&mut self, input: Steering) -> Result<()> {
        self.rails.require_turn(&input.provenance)?;
        if self.stopping || self.steering.len() >= MAX_STEERING_ITEMS {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        let turn = self.turn.as_ref().ok_or(codes::FRAME_STREAM_ORDER)?;
        let model = self.model.as_ref().ok_or(codes::FRAME_STREAM_ORDER)?;
        input.validate(turn.input.body.session_id, model.outstanding.request_id)?;
        self.steering.push_back(input);
        Ok(())
    }

    fn dispatch(&mut self, ready: ReadyModel) -> Result<()> {
        if self.stopping
            || self.phase != Phase::AwaitingDurability
            || self.model.is_some()
            || !self.steering.is_empty()
            || self.waiting_tools()
            || !self.results.is_empty()
            || !self.events.is_empty()
        {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        let turn = self.turn.as_ref().ok_or(codes::FRAME_STREAM_ORDER)?;
        if ready.session_id != turn.input.body.session_id
            || ready.durable.sequence() < self.required_sequence
            || ready.durable.sequence() < self.durable_sequence
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        let mode = turn.input.body.mode;
        let sequence = ready.durable.sequence();
        let request = ready.into_request();
        let mut names = BTreeSet::new();
        for tool in &request.call.tools {
            let name = crate::dispatch::ToolName::parse(&tool.name)?;
            if !names.insert(tool.name.clone()) || !name.available(mode) {
                return Err(codes::FRAME_UNKNOWN_KIND);
            }
        }
        if self.used_requests.len() >= MAX_USED_MODEL_IDS
            || self.used_requests.contains(&request.request_id)
            || self.used_reservations.contains(&request.reservation_id)
        {
            return Err(codes::FRAME_INVALID_ID);
        }
        let id = self.fresh_id()?;
        let active = ActiveModel {
            frame_id: id.clone(),
            cancel_id: None,
            outstanding: OutstandingModel {
                request_id: request.request_id,
                reservation_id: request.reservation_id,
                next_index: 0,
                cancellation_requested: false,
            },
            requested_window: request.max_pending_chunks,
            stream: None,
            receipt: None,
            suggestions: BTreeMap::new(),
            suggestion_bytes: 0,
            declared: names,
            successful: false,
        };
        self.durable_sequence = sequence;
        self.required_sequence = self
            .durable_sequence
            .checked_add(1)
            .filter(|s| *s <= crate::session::MAX_SEQUENCE)
            .ok_or(codes::SESSION_SEQUENCE)?;
        self.suggestions.clear();
        self.used_requests.insert(request.request_id);
        self.used_reservations.insert(request.reservation_id);
        self.model = Some(active);
        self.phase = Phase::AwaitingSettlement;
        self.write(crate::fd3::request(id, Request::ModelStart(request)))
    }

    fn reply(&mut self, reply: Frame<Reply>) -> Result<()> {
        self.capacity()?;
        if reply.v != canon::fd3::V2 || reply.provenance.source != Source::Auma {
            self.fail();
            return Err(codes::FRAME_PROVENANCE);
        }
        if let Err(error) = canon::fd3::encode_reply(&reply) {
            self.fail();
            return Err(error);
        }
        let result = if self.tools.contains_key(reply.id.as_str()) {
            self.tool_reply(reply)
        } else {
            self.model_reply(reply)
        };
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn cancel(&mut self, request: ModelCancel, keep_queue: bool) -> Result<()> {
        let model = self.model.as_ref().ok_or(codes::FRAME_STREAM_ORDER)?;
        if request.request_id != model.outstanding.request_id
            || request.reservation_id != model.outstanding.reservation_id
            || model.outstanding.cancellation_requested
            || model.receipt.is_some()
        {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        let id = self.fresh_id()?;
        let model = self.model.as_mut().ok_or(codes::FRAME_STREAM_ORDER)?;
        model.outstanding.cancellation_requested = true;
        model.cancel_id = Some(id.clone());
        if !keep_queue {
            self.queue.clear();
        }
        self.steering.clear();
        if !self.stopping {
            self.phase = Phase::Cancelling;
        }
        self.write(crate::fd3::request(id, Request::ModelCancel(request)))
    }

    fn settled(&mut self, receipt: ModelReceipt) -> Result<()> {
        let model = self.model.as_ref().ok_or(codes::FRAME_STREAM_ORDER)?;
        if model.receipt.as_ref() != Some(&receipt)
            || model.cancel_id.is_some()
            || !self.events.is_empty()
            || model
                .stream
                .as_ref()
                .is_none_or(|stream| stream.first_pending() != stream.next_index())
        {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        let model = self.model.take().ok_or(codes::FRAME_STREAM_ORDER)?;
        if model.successful && !self.stopping {
            self.suggestions = model.suggestions;
        }
        self.phase = if self.stopping {
            Phase::Stopped
        } else {
            Phase::AwaitingDurability
        };
        Ok(())
    }

    fn stop(&mut self) {
        self.queue.clear();
        self.steering.clear();
        if let Some(model) = &self.model {
            if !model.outstanding.cancellation_requested && model.receipt.is_none() {
                let request = ModelCancel {
                    request_id: model.outstanding.request_id,
                    reservation_id: model.outstanding.reservation_id,
                };
                if self.cancel(request, false).is_err() {
                    self.fail();
                }
            }
        }
        self.stopping = true;
        self.phase = Phase::Stopped;
    }
}
