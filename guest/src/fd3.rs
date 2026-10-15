// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed bridges over caller-owned, already attached byte handles.

use canon::{
    codes,
    fd3::{Reply, Request},
    fd4::{ChatCommand, SessionEvent},
    frame::{self, Disposition, Frame, FrameError, FrameId},
    ids::{RequestId, ReservationId},
    provenance::{Provenance, Source},
    session::{ModelEnd, ModelError, ModelStream},
    Refusal, Result,
};
use std::io::{Read, Write};

pub const DESCRIPTOR: u8 = 3;
pub const MAX_IN_FLIGHT: usize = 32;
pub const APP_DESCRIPTOR: u8 = 4;
pub const MAX_APP_IN_FLIGHT: usize = 32;
pub const MAX_APP_PENDING_PROPOSALS: usize = 128;
pub const MAX_APP_QUEUED_BYTES: usize = MAX_APP_IN_FLIGHT * frame::MAX_FRAME_BYTES;

/// The adapter owns the supplied handles and serializes each complete write.
/// A fatal framing error drops both handles without scanning for a new boundary.
pub trait SupervisorLink {
    fn send(&mut self, frame: Frame<Request>) -> core::result::Result<(), FrameError>;
    fn receive(&mut self) -> core::result::Result<Frame<Reply>, FrameError>;
    fn close(&mut self);

    /// Acknowledges a delta only after its consumer has accepted the data.
    fn acknowledge_delta(
        &mut self,
        _request_id: RequestId,
        _reservation_id: ReservationId,
        _index: u64,
    ) -> Result<()> {
        Ok(())
    }
}

/// Only bounded FD 4 command/event data crosses this link.
pub trait AppLink {
    fn receive(&mut self) -> core::result::Result<Frame<ChatCommand>, FrameError>;
    fn send(&mut self, event: Frame<SessionEvent>) -> core::result::Result<(), FrameError>;
    /// Completes chat work; correlation remains while an accepted proposal awaits its outcome.
    fn finish(&mut self, id: &FrameId) -> Result<()>;
    fn close(&mut self);
}

/// Constructs an Auma-labelled v2 request; the supervisor stamps its own ingress.
pub fn request(id: FrameId, body: Request) -> Frame<Request> {
    Frame {
        v: canon::fd3::V2,
        id,
        provenance: auma(),
        body,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyClass {
    Proposal,
    Read,
    Model,
    Stream,
    MemoryRecall,
    MemoryList,
    Status,
    Organs,
    SessionCreate,
    SessionOpen,
    SessionList,
    SessionAppend,
    SessionFlush,
}

impl ReplyClass {
    pub fn of(request: &Request) -> Self {
        match request {
            Request::Propose(_) | Request::MemoryPut(_) => Self::Proposal,
            Request::Read(_) => Self::Read,
            Request::ModelCall(_) => Self::Model,
            Request::ModelStart(_) | Request::ModelCancel(_) => Self::Stream,
            Request::MemoryRecall(_) => Self::MemoryRecall,
            Request::MemoryList(_) => Self::MemoryList,
            Request::Status => Self::Status,
            Request::Organs => Self::Organs,
            Request::SessionCreate(_) => Self::SessionCreate,
            Request::SessionOpen(_) => Self::SessionOpen,
            Request::SessionList(_) => Self::SessionList,
            Request::SessionAppend(_) => Self::SessionAppend,
            Request::SessionFlush(_) => Self::SessionFlush,
        }
    }

    pub fn accepts(self, reply: &Reply) -> Result<()> {
        if matches!(reply, Reply::Refusal(_))
            || matches!(
                (self, reply),
                (
                    Self::Proposal,
                    Reply::Accepted(_)
                        | Reply::Outcome(_)
                        | Reply::LegacyAccepted { .. }
                        | Reply::LegacyOutcome { .. }
                ) | (Self::Read, Reply::ReadReply(_))
                    | (Self::Model, Reply::ModelReply(_))
                    | (
                        Self::Stream,
                        Reply::ModelStarted(_)
                            | Reply::ModelDelta(_)
                            | Reply::ModelEnd(_)
                            | Reply::ModelError(_)
                            | Reply::ModelCancelled(_)
                    )
                    | (Self::MemoryRecall, Reply::Recall(_))
                    | (Self::MemoryList, Reply::MemoryListReply(_))
                    | (Self::Status, Reply::StatusReply(_))
                    | (Self::Organs, Reply::OrgansReply(_))
                    | (Self::SessionCreate, Reply::SessionCreated(_))
                    | (Self::SessionOpen, Reply::SessionOpened(_))
                    | (Self::SessionList, Reply::SessionList(_))
                    | (Self::SessionAppend, Reply::SessionAppended(_))
                    | (Self::SessionFlush, Reply::SessionFlushed(_))
            )
        {
            Ok(())
        } else {
            Err(codes::FRAME_UNKNOWN_KIND)
        }
    }
}

#[derive(Debug)]
enum PendingState {
    Single,
    Proposal(Option<String>),
    Starting {
        request: RequestId,
        reservation: ReservationId,
        window: u16,
    },
    Streaming(ModelStream),
    Cancel {
        request: RequestId,
        reservation: ReservationId,
    },
}

#[derive(Debug)]
struct Pending {
    id: FrameId,
    version: u16,
    class: ReplyClass,
    state: PendingState,
}

/// Correlation and stream ordering; these observations never authorize an effect.
#[derive(Default, Debug)]
pub struct PendingRequests {
    entries: Vec<Pending>,
    settled: Vec<ModelStream>,
}

impl PendingRequests {
    pub fn register(&mut self, frame: &Frame<Request>) -> Result<()> {
        canon::fd3::encode_request(frame)?;
        if frame.provenance != auma() {
            return Err(codes::FRAME_PROVENANCE);
        }
        if self.entries.len() + self.settled.len() >= MAX_IN_FLIGHT {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        if self.entries.iter().any(|entry| entry.id == frame.id) {
            return Err(codes::FRAME_INVALID_ID);
        }
        let state = match &frame.body {
            Request::Propose(_) | Request::MemoryPut(_) => PendingState::Proposal(None),
            Request::ModelStart(start) => {
                if self.entries.iter().any(|entry| {
                    matches_handle(&entry.state, start.request_id, start.reservation_id)
                }) || self.settled.iter().any(|stream| {
                    stream.request_id() == start.request_id
                        || stream.reservation_id() == start.reservation_id
                }) {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                PendingState::Starting {
                    request: start.request_id,
                    reservation: start.reservation_id,
                    window: start.max_pending_chunks,
                }
            }
            Request::ModelCancel(cancel) => {
                if self.entries.iter().any(|entry| {
                    matches!(entry.state, PendingState::Cancel { request, reservation }
                    if request == cancel.request_id && reservation == cancel.reservation_id)
                }) || !self.entries.iter().any(|entry| {
                    exact_handle(&entry.state, cancel.request_id, cancel.reservation_id)
                }) {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                PendingState::Cancel {
                    request: cancel.request_id,
                    reservation: cancel.reservation_id,
                }
            }
            _ => PendingState::Single,
        };
        self.entries.push(Pending {
            id: frame.id.clone(),
            version: frame.v,
            class: ReplyClass::of(&frame.body),
            state,
        });
        Ok(())
    }

    pub fn check(&self, frame: &Frame<Reply>) -> Result<()> {
        canon::fd3::encode_reply(frame)?;
        let pending = self.find(&frame.id)?;
        if pending.version != frame.v {
            return Err(codes::FRAME_UNSUPPORTED_VERSION);
        }
        if frame.provenance != auma() {
            return Err(codes::FRAME_PROVENANCE);
        }
        pending.class.accepts(&frame.body)?;
        if matches!(frame.body, Reply::Refusal(_)) {
            return if matches!(
                pending.state,
                PendingState::Streaming(_) | PendingState::Proposal(Some(_))
            ) {
                Err(codes::FRAME_STREAM_ORDER)
            } else {
                Ok(())
            };
        }
        match (&pending.state, &frame.body) {
            (PendingState::Single, _) => Ok(()),
            (PendingState::Proposal(None), Reply::Accepted(_) | Reply::LegacyAccepted { .. }) => {
                Ok(())
            }
            (PendingState::Proposal(Some(expected)), Reply::Outcome(outcome))
                if *expected == outcome.proposal_id.to_string() =>
            {
                Ok(())
            }
            (PendingState::Proposal(Some(expected)), Reply::LegacyOutcome { proposal_id, .. })
                if expected == proposal_id =>
            {
                Ok(())
            }
            (
                PendingState::Starting {
                    request,
                    reservation,
                    window,
                },
                Reply::ModelStarted(started),
            ) if *request == started.request_id
                && *reservation == started.reservation_id
                && started.max_pending_chunks <= *window =>
            {
                Ok(())
            }
            (PendingState::Streaming(stream), reply) => check_stream(stream, reply),
            (
                PendingState::Cancel {
                    request,
                    reservation,
                },
                Reply::ModelCancelled(end),
            ) => {
                let stream = self.stream(*request, *reservation)?;
                check_stream(stream, &Reply::ModelCancelled(end.clone()))
            }
            _ => Err(codes::FRAME_STREAM_ORDER),
        }
    }

    /// Advances state only after validation. A cancel receipt retires its original stream
    /// and the cancel alias; a refused cancel leaves the original reservation outstanding.
    pub fn observe(&mut self, frame: &Frame<Reply>) -> Result<()> {
        self.check(frame)?;
        let index = self.index(&frame.id)?;
        if let (
            PendingState::Cancel {
                request,
                reservation,
            },
            Reply::ModelCancelled(end),
        ) = (&self.entries[index].state, &frame.body)
        {
            let handle = (*request, *reservation);
            self.stream_mut(handle.0, handle.1)?.observe_end(end)?;
            let original = self
                .entries
                .iter()
                .position(|entry| {
                    exact_handle(&entry.state, handle.0, handle.1)
                        && !matches!(entry.state, PendingState::Cancel { .. })
                })
                .ok_or(codes::FRAME_STREAM_ORDER)?;
            let stream = self.entries.remove(original);
            self.retain_unacknowledged(stream);
            self.finish(&frame.id)?;
            return Ok(());
        }
        let entry = &mut self.entries[index];
        let terminal = match (&mut entry.state, &frame.body) {
            (_, Reply::Refusal(_)) => true,
            (PendingState::Proposal(proposal), Reply::Accepted(accepted)) => {
                *proposal = Some(accepted.proposal_id.to_string());
                false
            }
            (PendingState::Proposal(proposal), Reply::LegacyAccepted { proposal_id }) => {
                *proposal = Some(proposal_id.clone());
                false
            }
            (state @ PendingState::Starting { .. }, Reply::ModelStarted(started)) => {
                *state = PendingState::Streaming(ModelStream::new(started)?);
                false
            }
            (PendingState::Streaming(stream), Reply::ModelDelta(delta)) => {
                stream.observe_delta(delta)?;
                false
            }
            (
                PendingState::Streaming(stream),
                Reply::ModelEnd(end) | Reply::ModelCancelled(end),
            ) => {
                stream.observe_end(end)?;
                true
            }
            (PendingState::Streaming(stream), Reply::ModelError(error)) => {
                stream.observe_error(error)?;
                true
            }
            _ => true,
        };
        if terminal {
            let removed = self.entries.remove(index);
            self.retain_unacknowledged(removed);
        }
        Ok(())
    }

    fn retain_unacknowledged(&mut self, removed: Pending) {
        if let PendingState::Streaming(stream) = removed.state {
            if stream.first_pending() < stream.next_index() {
                self.settled.push(stream);
            }
        }
    }

    /// Discards local correlation only; it does not cancel a call or settle a reservation.
    pub fn finish(&mut self, id: &FrameId) -> Result<()> {
        let index = self.index(id)?;
        self.entries.remove(index);
        Ok(())
    }

    pub fn acknowledge_delta(
        &mut self,
        request: RequestId,
        reservation: ReservationId,
        index: u64,
    ) -> Result<()> {
        if let Some(position) = self.settled.iter().position(|stream| {
            stream.request_id() == request && stream.reservation_id() == reservation
        }) {
            let stream = &mut self.settled[position];
            stream.acknowledge_through(index)?;
            if stream.first_pending() == stream.next_index() {
                self.settled.remove(position);
            }
            Ok(())
        } else {
            self.stream_mut(request, reservation)?
                .acknowledge_through(index)
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    fn index(&self, id: &FrameId) -> Result<usize> {
        self.entries
            .iter()
            .position(|entry| entry.id == *id)
            .ok_or(codes::FRAME_INVALID_ID)
    }
    fn find(&self, id: &FrameId) -> Result<&Pending> {
        Ok(&self.entries[self.index(id)?])
    }
    fn stream(&self, request: RequestId, reservation: ReservationId) -> Result<&ModelStream> {
        self.entries
            .iter()
            .find_map(|entry| match &entry.state {
                PendingState::Streaming(stream)
                    if stream.request_id() == request && stream.reservation_id() == reservation =>
                {
                    Some(stream)
                }
                _ => None,
            })
            .ok_or(codes::FRAME_STREAM_ORDER)
    }
    fn stream_mut(
        &mut self,
        request: RequestId,
        reservation: ReservationId,
    ) -> Result<&mut ModelStream> {
        self.entries
            .iter_mut()
            .find_map(|entry| match &mut entry.state {
                PendingState::Streaming(stream)
                    if stream.request_id() == request && stream.reservation_id() == reservation =>
                {
                    Some(stream)
                }
                _ => None,
            })
            .ok_or(codes::FRAME_STREAM_ORDER)
    }
}

fn exact_handle(state: &PendingState, request: RequestId, reservation: ReservationId) -> bool {
    match state {
        PendingState::Starting {
            request: r,
            reservation: s,
            ..
        }
        | PendingState::Cancel {
            request: r,
            reservation: s,
        } => *r == request && *s == reservation,
        PendingState::Streaming(stream) => {
            stream.request_id() == request && stream.reservation_id() == reservation
        }
        _ => false,
    }
}

fn matches_handle(state: &PendingState, request: RequestId, reservation: ReservationId) -> bool {
    match state {
        PendingState::Starting {
            request: r,
            reservation: s,
            ..
        }
        | PendingState::Cancel {
            request: r,
            reservation: s,
        } => *r == request || *s == reservation,
        PendingState::Streaming(stream) => {
            stream.request_id() == request || stream.reservation_id() == reservation
        }
        _ => false,
    }
}

fn check_stream(stream: &ModelStream, reply: &Reply) -> Result<()> {
    let (request, reservation, index) = match reply {
        Reply::ModelDelta(delta) => {
            if stream.next_index() - stream.first_pending() >= u64::from(stream.window()) {
                return Err(codes::BROKER_BUSY);
            }
            (delta.request_id, delta.reservation_id, delta.index)
        }
        Reply::ModelEnd(end) | Reply::ModelCancelled(end) => {
            check_end_receipt(end)?;
            (end.request_id, end.reservation_id, end.next_index)
        }
        Reply::ModelError(error) => {
            check_error_receipt(error)?;
            (error.request_id, error.reservation_id, error.next_index)
        }
        _ => return Err(codes::FRAME_STREAM_ORDER),
    };
    if stream.is_ended()
        || stream.request_id() != request
        || stream.reservation_id() != reservation
        || stream.next_index() != index
    {
        return Err(codes::FRAME_STREAM_ORDER);
    }
    Ok(())
}

fn check_end_receipt(end: &ModelEnd) -> Result<()> {
    if end.request_id != end.receipt.request_id || end.reservation_id != end.receipt.reservation_id
    {
        Err(codes::FRAME_STREAM_ORDER)
    } else {
        Ok(())
    }
}

fn check_error_receipt(error: &ModelError) -> Result<()> {
    if error.request_id != error.receipt.request_id
        || error.reservation_id != error.receipt.reservation_id
    {
        Err(codes::FRAME_STREAM_ORDER)
    } else {
        Ok(())
    }
}

/// Handles are supplied by the cage's attachment layer; this code acquires none.
/// Dropping both owned handles is the close operation. Their owner must not retain aliases.
#[derive(Debug)]
pub struct OwnedSupervisorLink<R, W> {
    channel: DataChannel<R, W>,
    pending: PendingRequests,
}

impl<R: Read, W: Write> OwnedSupervisorLink<R, W> {
    pub fn attach(reader: R, writer: W) -> Self {
        Self {
            channel: DataChannel::new(reader, writer),
            pending: PendingRequests::default(),
        }
    }
    pub fn is_closed(&self) -> bool {
        self.channel.is_closed()
    }
    pub fn pending(&self) -> &PendingRequests {
        &self.pending
    }
}

impl<R: Read, W: Write> SupervisorLink for OwnedSupervisorLink<R, W> {
    fn send(&mut self, frame: Frame<Request>) -> core::result::Result<(), FrameError> {
        self.channel.require_open()?;
        let bytes = canon::fd3::encode_request(&frame).map_err(refuse)?;
        self.pending.register(&frame).map_err(refuse)?;
        if let Err(error) = self.channel.send_bytes(&bytes) {
            let _ = self.pending.finish(&frame.id);
            if error.disposition == Disposition::Close {
                self.close();
            }
            return Err(error);
        }
        Ok(())
    }
    fn receive(&mut self) -> core::result::Result<Frame<Reply>, FrameError> {
        let result = self.channel.receive_bytes().and_then(|bytes| {
            let reply = canon::fd3::decode_reply(&bytes, auma()).map_err(refuse)?;
            self.pending.observe(&reply).map_err(refuse)?;
            Ok(reply)
        });
        if matches!(result, Err(error) if error.disposition == Disposition::Close) {
            self.close();
        }
        result
    }
    fn close(&mut self) {
        self.channel.close();
        self.pending.entries.clear();
        self.pending.settled.clear();
    }
    fn acknowledge_delta(
        &mut self,
        request_id: RequestId,
        reservation_id: ReservationId,
        index: u64,
    ) -> Result<()> {
        self.pending
            .acknowledge_delta(request_id, reservation_id, index)
    }
}

/// FD 4 has a fixed trusted ingress set by attachment, never taken from received bytes.
/// The adapter retains at most 32 correlation ids and reads only one bounded frame at a time.
#[derive(Debug)]
pub struct OwnedAppLink<R, W> {
    channel: DataChannel<R, W>,
    ingress: Provenance,
    pending: Vec<AppPending>,
}

#[derive(Debug)]
struct AppPending {
    id: FrameId,
    kind: &'static str,
    complete: bool,
    proposals: Vec<String>,
}

enum ProposalChange {
    None,
    Accepted(String),
    Outcome(usize),
}

impl<R: Read, W: Write> OwnedAppLink<R, W> {
    pub fn attach(reader: R, writer: W, ingress: Provenance) -> Result<Self> {
        if ingress.source == Source::Stranger {
            return Err(codes::FRAME_PROVENANCE);
        }
        Ok(Self {
            channel: DataChannel::new(reader, writer),
            ingress,
            pending: Vec::new(),
        })
    }
    pub fn is_closed(&self) -> bool {
        self.channel.is_closed()
    }

    /// Completes chat work, retaining correlation until its accepted proposals have outcomes.
    /// Other command correlations retire after their sole response is written.
    pub fn finish(&mut self, id: &FrameId) -> Result<()> {
        let index = self
            .pending
            .iter()
            .position(|entry| entry.id == *id)
            .ok_or(codes::FRAME_INVALID_ID)?;
        let entry = &mut self.pending[index];
        if entry.kind != "chat.turn" || entry.complete {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        entry.complete = true;
        if entry.proposals.is_empty() {
            self.pending.remove(index);
        }
        Ok(())
    }

    fn proposal_change(&self, index: usize, event: &SessionEvent) -> Result<ProposalChange> {
        let entry = &self.pending[index];
        let accepted = match event {
            SessionEvent::ProposalAccepted(value) => Some(value.proposal_id.to_string()),
            SessionEvent::LegacyProposalAccepted { proposal_id } => Some(proposal_id.clone()),
            _ => None,
        };
        if let Some(proposal_id) = accepted {
            if entry.complete {
                return Err(codes::FRAME_STREAM_ORDER);
            }
            if self
                .pending
                .iter()
                .map(|entry| entry.proposals.len())
                .sum::<usize>()
                >= MAX_APP_PENDING_PROPOSALS
            {
                return Err(codes::FRAME_STREAM_LIMIT);
            }
            if self
                .pending
                .iter()
                .any(|entry| entry.proposals.contains(&proposal_id))
            {
                return Err(codes::FRAME_INVALID_ID);
            }
            return Ok(ProposalChange::Accepted(proposal_id));
        }
        let outcome = match event {
            SessionEvent::ProposalOutcome(value) => Some(value.proposal_id.to_string()),
            SessionEvent::LegacyProposalOutcome { proposal_id, .. } => Some(proposal_id.clone()),
            _ => None,
        };
        if let Some(proposal_id) = outcome {
            let position = entry
                .proposals
                .iter()
                .position(|pending| *pending == proposal_id)
                .ok_or(codes::FRAME_INVALID_ID)?;
            return Ok(ProposalChange::Outcome(position));
        }
        if entry.complete {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        Ok(ProposalChange::None)
    }
}

impl<R: Read, W: Write> AppLink for OwnedAppLink<R, W> {
    fn receive(&mut self) -> core::result::Result<Frame<ChatCommand>, FrameError> {
        self.channel.require_open()?;
        if self.pending.len() >= MAX_APP_IN_FLIGHT {
            return Err(refuse(codes::FRAME_STREAM_LIMIT));
        }
        let bytes = match self.channel.receive_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                if error.disposition == Disposition::Close {
                    self.close();
                }
                return Err(error);
            }
        };
        let command = canon::fd4::decode_command(&bytes, self.ingress.clone()).map_err(refuse)?;
        if self.pending.iter().any(|entry| entry.id == command.id) {
            return Err(refuse(codes::FRAME_INVALID_ID));
        }
        self.pending.push(AppPending {
            id: command.id.clone(),
            kind: command.body.kind(),
            complete: false,
            proposals: Vec::new(),
        });
        Ok(command)
    }
    fn send(&mut self, event: Frame<SessionEvent>) -> core::result::Result<(), FrameError> {
        self.channel.require_open()?;
        if event.provenance != auma() {
            return Err(refuse(codes::FRAME_PROVENANCE));
        }
        let index = self
            .pending
            .iter()
            .position(|entry| entry.id == event.id)
            .ok_or_else(|| refuse(codes::FRAME_INVALID_ID))?;
        let kind = self.pending[index].kind;
        if !app_accepts(kind, &event.body) {
            return Err(refuse(codes::FRAME_UNKNOWN_KIND));
        }
        let bytes = canon::fd4::encode_event(&event).map_err(refuse)?;
        let change = self.proposal_change(index, &event.body).map_err(refuse)?;
        match self.channel.send_bytes(&bytes) {
            Ok(()) => {
                let entry = &mut self.pending[index];
                match change {
                    ProposalChange::None => {}
                    ProposalChange::Accepted(proposal) => entry.proposals.push(proposal),
                    ProposalChange::Outcome(position) => {
                        entry.proposals.remove(position);
                    }
                }
                if kind != "chat.turn" || (entry.complete && entry.proposals.is_empty()) {
                    self.pending.remove(index);
                }
                Ok(())
            }
            Err(error) => {
                if error.disposition == Disposition::Close {
                    self.close();
                }
                Err(error)
            }
        }
    }
    fn finish(&mut self, id: &FrameId) -> Result<()> {
        OwnedAppLink::finish(self, id)
    }
    fn close(&mut self) {
        self.channel.close();
        self.pending.clear();
    }
}

fn app_accepts(kind: &str, event: &SessionEvent) -> bool {
    if matches!(event, SessionEvent::Refusal(_)) {
        return true;
    }
    match kind {
        "chat.turn" => matches!(
            event,
            SessionEvent::Entry(_)
                | SessionEvent::Appended(_)
                | SessionEvent::Flushed(_)
                | SessionEvent::ModelStarted(_)
                | SessionEvent::ModelDelta(_)
                | SessionEvent::ModelEnd(_)
                | SessionEvent::ModelError(_)
                | SessionEvent::ModelCancelled(_)
                | SessionEvent::ProposalAccepted(_)
                | SessionEvent::LegacyProposalAccepted { .. }
                | SessionEvent::ProposalOutcome(_)
                | SessionEvent::LegacyProposalOutcome { .. }
                | SessionEvent::MemoryRecall(_)
                | SessionEvent::MemoryListed(_)
        ),
        "session.create" => matches!(event, SessionEvent::Created(_)),
        "session.open" => matches!(event, SessionEvent::Opened(_)),
        "session.list" => matches!(event, SessionEvent::Listed(_)),
        "session.append" => matches!(event, SessionEvent::Appended(_)),
        "session.flush" => matches!(event, SessionEvent::Flushed(_)),
        "model.cancel" => matches!(event, SessionEvent::ModelCancelled(_)),
        "health.snapshot" => matches!(event, SessionEvent::HealthSnapshot(_)),
        _ => false,
    }
}

#[derive(Debug)]
struct DataChannel<R, W> {
    handles: Option<(R, W)>,
}

impl<R: Read, W: Write> DataChannel<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self {
            handles: Some((reader, writer)),
        }
    }
    fn is_closed(&self) -> bool {
        self.handles.is_none()
    }
    fn require_open(&self) -> core::result::Result<(), FrameError> {
        if self.is_closed() {
            Err(fatal(codes::FRAME_IO))
        } else {
            Ok(())
        }
    }
    fn close(&mut self) {
        self.handles.take();
    }
    fn receive_bytes(&mut self) -> core::result::Result<Vec<u8>, FrameError> {
        let result = match self.handles.as_mut() {
            Some((reader, _)) => frame::read(reader).map(|value| canon::json::to_canonical(&value)),
            None => Err(fatal(codes::FRAME_IO)),
        };
        if matches!(result, Err(error) if error.disposition == Disposition::Close) {
            self.close();
        }
        result
    }
    fn send_bytes(&mut self, bytes: &[u8]) -> core::result::Result<(), FrameError> {
        self.require_open()?;
        if bytes.is_empty() {
            return Err(refuse(codes::FRAME_ZERO_LENGTH));
        }
        if bytes.len() > frame::MAX_FRAME_BYTES {
            return Err(refuse(codes::FRAME_TOO_LARGE));
        }
        let (_, writer) = self
            .handles
            .as_mut()
            .ok_or_else(|| fatal(codes::FRAME_IO))?;
        let result = writer
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .and_then(|()| writer.write_all(bytes))
            .and_then(|()| writer.flush())
            .map_err(|_| fatal(codes::FRAME_IO));
        if result.is_err() {
            self.close();
        }
        result
    }
}

fn auma() -> Provenance {
    Provenance {
        source: Source::Auma,
    }
}
fn refuse(refusal: Refusal) -> FrameError {
    FrameError {
        refusal,
        disposition: Disposition::Refuse,
    }
}
fn fatal(refusal: Refusal) -> FrameError {
    FrameError {
        refusal,
        disposition: Disposition::Close,
    }
}
