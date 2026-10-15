// SPDX-License-Identifier: AGPL-3.0-or-later
//! Guest-side typed endpoint; it does not acquire or create a descriptor.

use canon::{
    codes,
    fd3::{Reply, Request},
    frame::{Frame, FrameError, FrameId},
    provenance::{Provenance, Source},
    Result,
};

pub const DESCRIPTOR: u8 = 3;
pub const MAX_IN_FLIGHT: usize = 32;

/// An adapter owns the pre-established FD 3 channel and serializes each frame write.
/// Fatal framing errors terminate the adapter; no boundary resynchronization is permitted.
pub trait SupervisorLink {
    fn send(&mut self, frame: Frame<Request>) -> core::result::Result<(), FrameError>;
    fn receive(&mut self) -> core::result::Result<Frame<Reply>, FrameError>;
    fn close(&mut self);
}

/// Constructs only Auma-labelled v2 requests; the supervisor independently stamps ingress.
pub fn request(id: FrameId, body: Request) -> Frame<Request> {
    Frame {
        v: canon::fd3::V2,
        id,
        provenance: Provenance {
            source: Source::Auma,
        },
        body,
    }
}

/// Closed correlation classes; admission acknowledgements do not count as terminal outcomes.
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
        let accepted = matches!(reply, Reply::Refusal(_))
            || matches!(
                (self, reply),
                (Self::Proposal, Reply::Accepted(_) | Reply::Outcome(_))
                    | (Self::Read, Reply::ReadReply(_))
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
            );
        if accepted {
            Ok(())
        } else {
            Err(codes::FRAME_UNKNOWN_KIND)
        }
    }
}

/// Unknown and duplicate ids refuse before a reply can reach a consumer.
#[derive(Default, Debug)]
pub struct PendingRequests(Vec<(FrameId, ReplyClass)>);

impl PendingRequests {
    pub fn register(&mut self, frame: &Frame<Request>) -> Result<()> {
        if self.0.len() >= MAX_IN_FLIGHT {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        if self.0.iter().any(|(id, _)| id == &frame.id) {
            return Err(codes::FRAME_INVALID_ID);
        }
        self.0.push((frame.id.clone(), ReplyClass::of(&frame.body)));
        Ok(())
    }

    pub fn check(&self, frame: &Frame<Reply>) -> Result<()> {
        self.0
            .iter()
            .find(|(id, _)| id == &frame.id)
            .ok_or(codes::FRAME_INVALID_ID)?
            .1
            .accepts(&frame.body)
    }

    pub fn finish(&mut self, id: &FrameId) -> Result<()> {
        let index = self
            .0
            .iter()
            .position(|(pending, _)| pending == id)
            .ok_or(codes::FRAME_INVALID_ID)?;
        self.0.remove(index);
        Ok(())
    }
}
