// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed FD 3 dispatch table. Authority and policy stay behind the organ ports.

use crate::{
    ingress::{self, BindingState, ConversationCursor, GuestContext},
    services::{
        BindingService, BrokerEvent, BrokerService, CellService, GateService, KiraService,
        SnapshotService, StreamHandle,
    },
    session::SessionStore,
    transport::{GuestChannel, MAX_PENDING_PROPOSALS, MAX_PENDING_REQUESTS},
};
use canon::{
    codes,
    fd3::{Reply, Request},
    fd3_payloads::RefusalReply,
    frame::{Frame, FrameId},
    ids::ProposalId,
    provenance::{Provenance, Source},
    session::{ModelStream, SessionFlushed},
    Result,
};
use std::{collections::VecDeque, time::Duration};

/// One destination for every decoded request; no string-prefix fallback exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Gate,
    Broker,
    Kira,
    Sessions,
    Snapshot,
}

pub const fn destination(request: &Request) -> Route {
    match request {
        Request::SitePropose(_) => Route::Gate,
        Request::Propose(_) | Request::Read(_) => Route::Gate,
        Request::ModelCall(_) | Request::ModelStart(_) | Request::ModelCancel(_) => Route::Broker,
        Request::MemoryPut(_) | Request::MemoryRecall(_) | Request::MemoryList(_) => Route::Kira,
        Request::SessionCreate(_)
        | Request::SessionOpen(_)
        | Request::SessionList(_)
        | Request::SessionAppend(_)
        | Request::SessionFlush(_) => Route::Sessions,
        Request::Status | Request::Organs => Route::Snapshot,
    }
}

/// References to trusted organ adapters; none is a socket or an owner capability.
pub struct OrganPorts<'a> {
    pub binding: &'a dyn BindingService,
    pub gate: &'a dyn GateService,
    pub broker: &'a dyn BrokerService,
    pub kira: &'a dyn KiraService,
    pub cell: &'a dyn CellService,
    pub sessions: &'a dyn SessionStore,
    pub snapshots: &'a dyn SnapshotService,
}

/// Stateful wiring for one guest. There is no retry-on-error entry point.
pub struct Router<'a> {
    ports: OrganPorts<'a>,
    context: GuestContext,
    proposals: VecDeque<PendingProposal>,
    streams: VecDeque<PendingStream>,
    delivery: Option<Delivery>,
    durable: Option<SessionFlushed>,
    memory_calls_forwarded: u64,
    stranger_inputs_refused: u64,
    pending_dispatch: bool,
    poisoned: bool,
}

struct Correlation {
    v: u16,
    id: FrameId,
}

impl Correlation {
    fn frame(&self, body: Reply) -> Result<Frame<Reply>> {
        let frame = Frame {
            v: self.v,
            id: self.id.clone(),
            provenance: Provenance {
                source: Source::Auma,
            },
            body,
        };
        canon::fd3::encode_reply(&frame)?;
        Ok(frame)
    }
}

struct PendingProposal {
    correlation: Correlation,
    proposal_id: ProposalId,
    memory: bool,
}

struct PendingStream {
    correlation: Correlation,
    state: ModelStream,
}

struct Delivery {
    handle: StreamHandle,
    index: u64,
}

impl<'a> Router<'a> {
    pub fn new(ports: OrganPorts<'a>, context: GuestContext) -> Self {
        Self {
            ports,
            context,
            proposals: VecDeque::new(),
            streams: VecDeque::new(),
            delivery: None,
            durable: None,
            memory_calls_forwarded: 0,
            stranger_inputs_refused: 0,
            pending_dispatch: false,
            poisoned: false,
        }
    }

    pub const fn context(&self) -> &GuestContext {
        &self.context
    }

    pub const fn ports(&self) -> &OrganPorts<'a> {
        &self.ports
    }

    /// Raw local counters for the independent Body observer.
    pub fn activity(&self) -> crate::runtime::RuntimeActivity {
        crate::runtime::RuntimeActivity {
            pending_requests: self.streams.len() + usize::from(self.pending_dispatch),
            pending_proposals: self.proposals.len(),
            session_sequence: self
                .context
                .conversation()
                .map(|c| (c.session_id, c.sequence)),
            durable_sequence: self.durable.as_ref().map(|r| (r.session_id, r.sequence)),
            memory_calls_forwarded: self.memory_calls_forwarded,
            stranger_inputs_refused: self.stranger_inputs_refused,
        }
    }

    /// Load a principal-scoped session before retaining its current sequence locally.
    /// The stored transcript is data; selecting it grants no owner authority.
    pub async fn select_conversation(
        &mut self,
        request: canon::session::SessionOpen,
    ) -> Result<canon::session::SessionOpened> {
        if self.ports.binding.current().await? != BindingState::Bound(self.context.scope()) {
            return Err(canon::codes::AUMLOK_BINDING_REQUIRED);
        }
        let requested_id = request.session_id;
        let opened = self
            .ports
            .sessions
            .open(self.context.scope(), request)
            .await?;
        if opened.summary.session_id != requested_id {
            return Err(codes::SUPERVISOR_STATE);
        }
        self.context.select(ConversationCursor {
            session_id: opened.summary.session_id,
            sequence: opened.summary.sequence,
        });
        self.durable = None;
        Ok(opened)
    }

    /// Row 128: accept only canon-decoded requests with supervisor-stamped Auma origin.
    /// Recheck binding and epoch on every call; only status/organs remain available
    /// when the guest is being stopped. Route each body to its single named port.
    /// Re-run cell evidence before propose/memory.put; no comparison grants approval.
    /// Before model.call/start, obtain the active session's store-owned durable fence.
    /// Preserve the original correlation id and version on all replies; never retry a
    /// broker call. Bound pending requests/proposals and validate output with canon.
    /// Session appends reject owner provenance from this channel. Create/open update
    /// only the host-held conversation cursor after the scoped store has acknowledged.
    /// Unknown versions/kinds are refused by canon before this typed dispatch boundary.
    pub async fn dispatch(&mut self, request: Frame<Request>) -> Result<Frame<Reply>> {
        if self.poisoned {
            return Err(codes::SUPERVISOR_STATE);
        }
        if request.provenance.source == Source::Stranger {
            self.stranger_inputs_refused = self.stranger_inputs_refused.saturating_add(1);
        }
        let request = ingress::guest_request(request)?;
        canon::fd3::encode_request(&request)?;
        let correlation = Correlation {
            v: request.v,
            id: request.id,
        };
        let scope = self.context.scope();
        let binding_required = !matches!(request.body, Request::Status | Request::Organs);
        if binding_required {
            self.require_binding().await?;
        }
        if self
            .proposals
            .iter()
            .any(|p| p.correlation.id == correlation.id)
            || self
                .streams
                .iter()
                .any(|s| s.correlation.id == correlation.id)
        {
            return Err(codes::SUPERVISOR_STATE);
        }
        let body = match request.body {
            Request::SitePropose(proposal) => {
                self.proposal_capacity()?;
                let accepted = self
                    .ports
                    .gate
                    .propose_site(scope, &correlation.id, proposal)
                    .await?;
                self.track_proposal(&correlation, accepted.proposal_id, false)?;
                Reply::Accepted(accepted)
            }
            Request::Status => Reply::StatusReply(self.ports.snapshots.status().await?),
            Request::Organs => Reply::OrgansReply(self.ports.snapshots.organs().await?),
            Request::Read(read) => Reply::ReadReply(self.ports.gate.read(scope, read).await?),
            Request::Propose(proposal) => {
                self.proposal_capacity()?;
                self.ports.cell.proposal(&proposal)?;
                let accepted = self
                    .ports
                    .gate
                    .propose(scope, &correlation.id, proposal)
                    .await?;
                self.track_proposal(&correlation, accepted.proposal_id, false)?;
                Reply::Accepted(accepted)
            }
            Request::MemoryPut(memory) => {
                self.proposal_capacity()?;
                self.ports.cell.memory(&memory)?;
                self.count_memory();
                let accepted = self.ports.kira.put(scope, &correlation.id, memory).await?;
                self.track_proposal(&correlation, accepted.proposal_id, true)?;
                Reply::Accepted(accepted)
            }
            Request::MemoryRecall(recall) => {
                self.count_memory();
                Reply::Recall(self.ports.kira.recall(scope, recall).await?)
            }
            Request::MemoryList(list) => {
                self.count_memory();
                Reply::MemoryListReply(self.ports.kira.list(scope, list).await?)
            }
            Request::ModelCall(call) => {
                if self.streams.len() >= MAX_PENDING_REQUESTS {
                    return Err(codes::BROKER_BUSY);
                }
                self.flush_conversation().await?;
                Reply::ModelReply(self.ports.broker.call(scope, &correlation.id, call).await?)
            }
            Request::ModelStart(start) => {
                self.ports.broker.streaming_ready()?;
                if self.streams.len() >= MAX_PENDING_REQUESTS - 1 {
                    return Err(codes::BROKER_BUSY);
                }
                if self.streams.iter().any(|s| {
                    s.state.request_id() == start.request_id
                        || s.state.reservation_id() == start.reservation_id
                }) {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                self.flush_conversation().await?;
                let expected = (
                    start.request_id,
                    start.reservation_id,
                    start.max_pending_chunks,
                );
                let started = self.ports.broker.start(scope, start).await?;
                if started.request_id != expected.0
                    || started.reservation_id != expected.1
                    || started.max_pending_chunks > expected.2
                {
                    self.poisoned = true;
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                let state = match ModelStream::new(&started).and_then(|state| {
                    correlation.frame(Reply::ModelStarted(started.clone()))?;
                    Ok(state)
                }) {
                    Ok(state) => state,
                    Err(error) => {
                        self.poisoned = true;
                        return Err(error);
                    }
                };
                self.streams.push_back(PendingStream {
                    correlation: Correlation {
                        v: correlation.v,
                        id: correlation.id.clone(),
                    },
                    state,
                });
                Reply::ModelStarted(started)
            }
            Request::ModelCancel(cancel) => {
                let position = self
                    .streams
                    .iter()
                    .position(|s| {
                        s.state.request_id() == cancel.request_id
                            && s.state.reservation_id() == cancel.reservation_id
                    })
                    .ok_or(codes::FRAME_STREAM_ORDER)?;
                if self
                    .delivery
                    .as_ref()
                    .is_some_and(|d| d.handle.request_id == cancel.request_id)
                {
                    return Err(codes::BROKER_BUSY);
                }
                let end = self.ports.broker.cancel(scope, cancel).await?;
                correlation.frame(Reply::ModelCancelled(end.clone()))?;
                self.streams[position].state.observe_end(&end)?;
                self.streams.remove(position);
                Reply::ModelCancelled(end)
            }
            Request::SessionCreate(create) => {
                let summary = self.ports.sessions.create(scope, create).await?;
                correlation.frame(Reply::SessionCreated(summary.clone()))?;
                self.context.select(ConversationCursor {
                    session_id: summary.session_id,
                    sequence: summary.sequence,
                });
                self.durable = None;
                Reply::SessionCreated(summary)
            }
            Request::SessionOpen(open) => {
                let requested_id = open.session_id;
                let opened = self.ports.sessions.open(scope, open).await?;
                if opened.summary.session_id != requested_id {
                    return Err(codes::SUPERVISOR_STATE);
                }
                correlation.frame(Reply::SessionOpened(opened.clone()))?;
                self.context.select(ConversationCursor {
                    session_id: opened.summary.session_id,
                    sequence: opened.summary.sequence,
                });
                self.durable = None;
                Reply::SessionOpened(opened)
            }
            Request::SessionList(list) => {
                Reply::SessionList(self.ports.sessions.list(scope, list).await?)
            }
            Request::SessionAppend(append) => {
                ingress::guest_entry(&append.entry)?;
                let expected = append.entry.clone();
                let appended = self
                    .ports
                    .sessions
                    .append(scope, request.provenance, append)
                    .await?;
                if appended.entry != expected {
                    return Err(codes::SUPERVISOR_STATE);
                }
                correlation.frame(Reply::SessionAppended(appended.clone()))?;
                if self
                    .context
                    .conversation()
                    .is_some_and(|c| c.session_id == appended.entry.session_id)
                {
                    self.context.select(ConversationCursor {
                        session_id: appended.entry.session_id,
                        sequence: appended.entry.sequence,
                    });
                }
                Reply::SessionAppended(appended)
            }
            Request::SessionFlush(flush) => {
                let expected = (flush.session_id, flush.through_sequence);
                let receipt = self.ports.sessions.flush(scope, flush).await?;
                if (receipt.session_id, receipt.sequence) != expected {
                    return Err(codes::SESSION_SEQUENCE);
                }
                correlation.frame(Reply::SessionFlushed(receipt.clone()))?;
                if self
                    .context
                    .conversation()
                    .is_some_and(|c| c.session_id == receipt.session_id)
                {
                    self.durable = Some(receipt.clone());
                }
                Reply::SessionFlushed(receipt)
            }
        };
        if binding_required {
            self.require_binding().await?;
        }
        correlation.frame(body)
    }

    /// Row 128: poll only outstanding gate/Kira ids and admitted broker streams.
    /// Forward each terminal outcome once, and require the broker's settled receipt
    /// on success, error and cancellation. Full bounded queues pause producers.
    /// Approvals themselves remain host services and do not depend on this poller.
    pub async fn next_event(&mut self) -> Result<Option<Frame<Reply>>> {
        if self.poisoned {
            return Err(codes::SUPERVISOR_STATE);
        }
        self.require_binding().await?;
        if self.delivery.is_some() {
            return Err(codes::BROKER_BUSY);
        }
        let scope = self.context.scope();
        for _ in 0..self.proposals.len() {
            let pending = self.proposals.front().ok_or(codes::SUPERVISOR_STATE)?;
            let outcome = if pending.memory {
                self.ports.kira.outcome(scope, pending.proposal_id).await?
            } else {
                self.ports.gate.outcome(scope, pending.proposal_id).await?
            };
            if let Some(outcome) = outcome {
                if outcome.proposal_id != pending.proposal_id {
                    return Err(codes::SUPERVISOR_STATE);
                }
                let frame = pending.correlation.frame(Reply::Outcome(outcome))?;
                self.proposals.pop_front();
                return Ok(Some(frame));
            }
            self.proposals.rotate_left(1);
        }
        for _ in 0..self.streams.len() {
            let pending = self.streams.front_mut().ok_or(codes::SUPERVISOR_STATE)?;
            let handle = StreamHandle {
                request_id: pending.state.request_id(),
                reservation_id: pending.state.reservation_id(),
            };
            let Some(event) = self.ports.broker.poll(scope, handle).await? else {
                self.streams.rotate_left(1);
                continue;
            };
            let body = match event {
                BrokerEvent::Delta(delta) => {
                    pending
                        .correlation
                        .frame(Reply::ModelDelta(delta.clone()))?;
                    pending.state.observe_delta(&delta)?;
                    self.delivery = Some(Delivery {
                        handle,
                        index: delta.index,
                    });
                    Reply::ModelDelta(delta)
                }
                BrokerEvent::End(end) => {
                    pending.correlation.frame(Reply::ModelEnd(end.clone()))?;
                    pending.state.observe_end(&end)?;
                    Reply::ModelEnd(end)
                }
                BrokerEvent::Error(mut error) => {
                    error.code = canon::Refusal::from_code(&error.code.to_string())
                        .unwrap_or(codes::SUPERVISOR_STATE);
                    pending
                        .correlation
                        .frame(Reply::ModelError(error.clone()))?;
                    pending.state.observe_error(&error)?;
                    Reply::ModelError(error)
                }
            };
            let frame = pending.correlation.frame(body)?;
            if pending.state.is_ended() {
                self.streams.pop_front();
            } else {
                self.streams.rotate_left(1);
            }
            return Ok(Some(frame));
        }
        Ok(None)
    }

    /// Call only after the previously returned event's complete transport write.
    pub async fn event_delivered(&mut self) -> Result<()> {
        if let Some(delivery) = &self.delivery {
            self.ports
                .broker
                .delivered(self.context.scope(), delivery.handle, delivery.index)
                .await?;
            let stream = self
                .streams
                .iter_mut()
                .find(|s| {
                    s.state.request_id() == delivery.handle.request_id
                        && s.state.reservation_id() == delivery.handle.reservation_id
                })
                .ok_or(codes::FRAME_STREAM_ORDER)?;
            stream.state.acknowledge_through(delivery.index)?;
            self.delivery = None;
        }
        Ok(())
    }

    async fn require_binding(&self) -> Result<()> {
        if self.ports.binding.current().await? != BindingState::Bound(self.context.scope()) {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        Ok(())
    }

    async fn flush_conversation(&mut self) -> Result<()> {
        let cursor = self
            .context
            .conversation()
            .ok_or(codes::SESSION_NOT_FOUND)?;
        let fence = self
            .ports
            .sessions
            .before_dispatch(self.context.scope(), cursor.session_id, cursor.sequence)
            .await?;
        if fence.scope() != self.context.scope()
            || fence.receipt().session_id != cursor.session_id
            || fence.receipt().sequence != cursor.sequence
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        self.durable = Some(fence.receipt().clone());
        self.require_binding().await?;
        Ok(())
    }

    fn proposal_capacity(&self) -> Result<()> {
        if self.proposals.len() >= MAX_PENDING_PROPOSALS {
            return Err(codes::BROKER_BUSY);
        }
        Ok(())
    }

    fn track_proposal(
        &mut self,
        correlation: &Correlation,
        proposal_id: ProposalId,
        memory: bool,
    ) -> Result<()> {
        if self.proposals.iter().any(|p| p.proposal_id == proposal_id) {
            self.poisoned = true;
            return Err(codes::SUPERVISOR_STATE);
        }
        self.proposals.push_back(PendingProposal {
            correlation: Correlation {
                v: correlation.v,
                id: correlation.id.clone(),
            },
            proposal_id,
            memory,
        });
        Ok(())
    }

    fn count_memory(&mut self) {
        self.memory_calls_forwarded = self.memory_calls_forwarded.saturating_add(1);
    }

    /// Drive one channel; event production resumes only after its complete write.
    pub async fn serve(&mut self, channel: &mut GuestChannel) -> Result<()> {
        self.serve_observed(channel, |_| {}).await
    }

    /// Publish raw activity for the host's independent observer while serving.
    pub async fn serve_observed(
        &mut self,
        channel: &mut GuestChannel,
        mut observe: impl FnMut(crate::runtime::RuntimeActivity) + Send,
    ) -> Result<()> {
        observe(self.activity());
        let result = self.serve_loop(channel, &mut observe).await;
        let close = channel.close();
        let settlement = self.cancel_outstanding().await;
        observe(self.activity());
        close?;
        settlement?;
        result
    }

    /// Ask the broker to settle each still-admitted reservation once on disconnect.
    pub async fn cancel_outstanding(&mut self) -> Result<()> {
        let mut failure = None;
        for _ in 0..self.streams.len() {
            let stream = self.streams.front_mut().ok_or(codes::SUPERVISOR_STATE)?;
            let cancel = canon::session::ModelCancel {
                request_id: stream.state.request_id(),
                reservation_id: stream.state.reservation_id(),
            };
            let result = match self.ports.broker.cancel(self.context.scope(), cancel).await {
                Ok(end) => stream
                    .correlation
                    .frame(Reply::ModelCancelled(end.clone()))
                    .and_then(|_| stream.state.observe_end(&end)),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                failure.get_or_insert(error);
                self.streams.rotate_left(1);
            } else {
                self.streams.pop_front();
            }
        }
        let disconnected = self.ports.broker.disconnect(self.context.scope()).await;
        if disconnected.is_ok() {
            self.streams.clear();
        }
        self.delivery = None;
        self.pending_dispatch = false;
        disconnected?;
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }

    async fn serve_loop(
        &mut self,
        channel: &mut GuestChannel,
        observe: &mut (impl FnMut(crate::runtime::RuntimeActivity) + Send),
    ) -> Result<()> {
        loop {
            let received =
                tokio::time::timeout(Duration::from_millis(100), channel.receive_async()).await;
            match received {
                Ok(Ok(request)) => {
                    let correlation = Correlation {
                        v: request.v,
                        id: request.id.clone(),
                    };
                    self.pending_dispatch = true;
                    observe(self.activity());
                    let dispatched = self.dispatch(request).await;
                    self.pending_dispatch = false;
                    observe(self.activity());
                    let reply = match dispatched {
                        Ok(reply) => reply,
                        Err(code) => {
                            let code = canon::Refusal::from_code(&code.to_string())
                                .unwrap_or(codes::SUPERVISOR_STATE);
                            correlation.frame(Reply::Refusal(RefusalReply {
                                code,
                                next: String::new(),
                            }))?
                        }
                    };
                    channel.send(&reply).map_err(|e| e.refusal)?;
                }
                Ok(Err(error)) => {
                    if error.disposition == canon::frame::Disposition::Close {
                        return Err(error.refusal);
                    }
                    if let Some(refusal) = channel.refusal_reply(error.refusal) {
                        channel.send(&refusal).map_err(|e| e.refusal)?;
                    } else {
                        return Err(error.refusal);
                    }
                }
                Err(_) => {}
            }
            match self.next_event().await {
                Ok(Some(event)) => {
                    self.require_binding().await?;
                    channel.send(&event).map_err(|e| e.refusal)?;
                    self.event_delivered().await?;
                }
                Ok(None) => {}
                Err(error) => {
                    channel.close()?;
                    return Err(error);
                }
            }
            observe(self.activity());
        }
    }
}
