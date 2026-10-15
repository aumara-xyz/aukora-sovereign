// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed bridges over caller-owned, already attached byte handles.

use canon::{
    codes,
    fd3::{Reply, Request},
    frame::{self, Disposition, Frame, FrameError, FrameId},
    ids::{RequestId, ReservationId},
    provenance::{Provenance, Source},
    session::{ModelEnd, ModelError, ModelStarted, ModelStream},
    Refusal, Result,
};
use std::io::{Read, Write};

pub const DESCRIPTOR: u8 = 3;
pub const MAX_IN_FLIGHT: usize = 32;
pub use crate::fd4::{
    AppLink, OwnedAppLink, DESCRIPTOR as APP_DESCRIPTOR, MAX_IN_FLIGHT as MAX_APP_IN_FLIGHT,
    MAX_PENDING_PROPOSALS as MAX_APP_PENDING_PROPOSALS, MAX_QUEUED_BYTES as MAX_APP_QUEUED_BYTES,
};

/// The adapter owns the supplied handles and serializes each complete write.
/// A fatal framing error drops both handles without scanning for a new boundary.
pub trait SupervisorLink {
    fn send(&mut self, frame: Frame<Request>) -> core::result::Result<(), FrameError>;
    fn receive(&mut self) -> core::result::Result<Frame<Reply>, FrameError>;
    fn close(&mut self);

    /// Acknowledges a delta only after its consumer has accepted the data.
    fn acknowledge_delta(
        &mut self,
        request_id: RequestId,
        reservation_id: ReservationId,
        index: u64,
    ) -> Result<()>;
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
            (
                state @ PendingState::Starting {
                    request,
                    reservation,
                    ..
                },
                Reply::ModelCancelled(end),
            ) if self.entries.iter().any(|entry| {
                matches!(entry.state, PendingState::Cancel { request: r, reservation: s }
                    if r == *request && s == *reservation)
            }) =>
            {
                check_cancel(state, end)
            }
            (PendingState::Streaming(stream), reply) => check_stream(stream, reply),
            (
                PendingState::Cancel {
                    request,
                    reservation,
                },
                Reply::ModelCancelled(end),
            ) => {
                let original = self.model_index(*request, *reservation)?;
                check_cancel(&self.entries[original].state, end)
            }
            _ => Err(codes::FRAME_STREAM_ORDER),
        }
    }

    /// Advances state only after validation. A cancel receipt retires its original stream
    /// and the cancel alias; a refused cancel leaves the original reservation outstanding.
    pub fn observe(&mut self, frame: &Frame<Reply>) -> Result<()> {
        self.check(frame)?;
        let index = self.index(&frame.id)?;
        if let Reply::ModelCancelled(end) = &frame.body {
            let original = self.model_index(end.request_id, end.reservation_id)?;
            if let PendingState::Streaming(stream) = &mut self.entries[original].state {
                stream.observe_end(end)?;
            }
            let stream = self.entries.remove(original);
            self.retain_unacknowledged(stream);
            self.entries.retain(|entry| {
                !matches!(entry.state, PendingState::Cancel { request, reservation }
                    if request == end.request_id && reservation == end.reservation_id)
            });
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
    fn model_index(&self, request: RequestId, reservation: ReservationId) -> Result<usize> {
        self.entries
            .iter()
            .position(|entry| {
                exact_handle(&entry.state, request, reservation)
                    && !matches!(entry.state, PendingState::Cancel { .. })
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

fn check_cancel(state: &PendingState, end: &ModelEnd) -> Result<()> {
    match state {
        PendingState::Starting {
            request,
            reservation,
            window,
        } => ModelStream::new(&ModelStarted {
            request_id: *request,
            reservation_id: *reservation,
            max_pending_chunks: *window,
        })?
        .observe_end(end),
        PendingState::Streaming(stream) => {
            check_stream(stream, &Reply::ModelCancelled(end.clone()))
        }
        _ => Err(codes::FRAME_STREAM_ORDER),
    }
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

#[derive(Debug)]
pub(crate) struct DataChannel<R, W> {
    handles: Option<(R, W)>,
}

impl<R: Read, W: Write> DataChannel<R, W> {
    pub(crate) fn new(reader: R, writer: W) -> Self {
        Self {
            handles: Some((reader, writer)),
        }
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.handles.is_none()
    }
    pub(crate) fn require_open(&self) -> core::result::Result<(), FrameError> {
        if self.is_closed() {
            Err(fatal(codes::FRAME_IO))
        } else {
            Ok(())
        }
    }
    pub(crate) fn close(&mut self) {
        self.handles.take();
    }
    pub(crate) fn receive_bytes(&mut self) -> core::result::Result<Vec<u8>, FrameError> {
        let result = match self.handles.as_mut() {
            Some((reader, _)) => frame::read(reader).map(|value| canon::json::to_canonical(&value)),
            None => Err(fatal(codes::FRAME_IO)),
        };
        if matches!(result, Err(error) if error.disposition == Disposition::Close) {
            self.close();
        }
        result
    }
    pub(crate) fn send_bytes(&mut self, bytes: &[u8]) -> core::result::Result<(), FrameError> {
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

pub(crate) fn auma() -> Provenance {
    Provenance {
        source: Source::Auma,
    }
}
pub(crate) fn refuse(refusal: Refusal) -> FrameError {
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
