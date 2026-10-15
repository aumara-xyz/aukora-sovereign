// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed data bridge only. It creates no FD 3 or organ-service sockets.

use crate::session::BoundSession;
use canon::{
    fd4::{ChatCommand, SessionEvent},
    frame::{Frame, FrameError},
    Result,
};

pub const MAX_QUEUED_FRAMES: usize = 32;
pub const MAX_QUEUED_BYTES: usize = 256 * 1024;

/// An already-connected supervisor channel supplied at trusted startup.
/// Implementations serialize writes, preserve correlation ids and close on framing failures.
pub trait DataChannel {
    fn send(&mut self, command: Frame<ChatCommand>) -> Result<()>;
    fn receive(&mut self) -> core::result::Result<Frame<SessionEvent>, FrameError>;
    fn close(&mut self);
}

/// Owns the connection so event bytes cannot be interpreted as HTTP or executable assets.
pub struct DataBridge<C> {
    channel: C,
}

impl<C: DataChannel> DataBridge<C> {
    pub fn new(channel: C) -> Self {
        Self { channel }
    }

    /// Canon decodes exact bounded commands; ingress source comes from the live session.
    /// The supervisor rechecks session ownership, epoch and per-frame authorization.
    pub fn submit(&mut self, _session: &BoundSession<'_>, _payload: &[u8]) -> Result<()> {
        todo!("row 109")
    }

    /// All variants go through canon::fd4::encode_event without interpretation or added fields.
    /// Opaque coherence bytes are never parsed here; code-like text remains literal text.
    pub fn next_event(&mut self, _session: &BoundSession<'_>) -> Result<Vec<u8>> {
        todo!("row 109")
    }

    pub fn close(&mut self) {
        self.channel.close();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DataFacts {
    pub queued_frames: usize,
    pub queued_bytes: usize,
    pub refused_payloads: u64,
    pub fatal_closes: u64,
}
