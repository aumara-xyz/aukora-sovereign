// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed FD 4 command/event data over already attached, caller-owned handles.
//! The four-byte length prefix bounds each canonical payload to 1..=65,536 bytes.
//! Zero length, oversized frames, truncated input and I/O failures close both handles;
//! semantic refusals leave a complete frame boundary intact. Writes are serialized.

use crate::fd3::{auma, refuse, DataChannel};
use canon::{
    codes,
    fd4::{ChatCommand, SessionEvent},
    frame::{self, Disposition, Frame, FrameError, FrameId},
    provenance::{Provenance, Source},
    Result,
};
use std::io::{Read, Write};

pub const DESCRIPTOR: u8 = 4;
pub const MAX_IN_FLIGHT: usize = 32;
pub const MAX_PENDING_PROPOSALS: usize = 128;
/// At most 32 full-size commands can remain in flight; the adapter queues no bytes.
pub const MAX_QUEUED_BYTES: usize = MAX_IN_FLIGHT * frame::MAX_FRAME_BYTES;

/// Only bounded FD 4 command/event data crosses this link.
pub trait AppLink {
    fn receive(&mut self) -> core::result::Result<Frame<ChatCommand>, FrameError>;
    fn send(&mut self, event: Frame<SessionEvent>) -> core::result::Result<(), FrameError>;
    /// Completes chat work; correlation remains while an accepted proposal awaits its outcome.
    fn finish(&mut self, id: &FrameId) -> Result<()>;
    fn close(&mut self);
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
                >= MAX_PENDING_PROPOSALS
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
        if self.pending.len() >= MAX_IN_FLIGHT {
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
