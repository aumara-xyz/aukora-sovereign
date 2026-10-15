// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sole host reader and serialized writer of the inherited FD 3 stream.

use canon::{
    fd3::{Reply, Request},
    frame::{Frame, FrameError},
    Result,
};
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub const MAX_PENDING_REQUESTS: usize = 16;
pub const MAX_PENDING_PROPOSALS: usize = 64;
pub const SEND_DEADLINE: Duration = Duration::from_secs(5);

/// Owns the host end of the launcher-created AF_UNIX SOCK_STREAM socketpair.
/// It exposes no descriptor, clone, split reader or direct socket access to organs.
#[derive(Debug)]
pub struct GuestChannel {
    stream: UnixStream,
    closed: bool,
}

impl GuestChannel {
    /// Adopt the host endpoint from launcher. Row 128 sets deadlines before use.
    pub fn attach(_stream: UnixStream) -> Result<Self> {
        todo!("row 128")
    }

    /// Read one C4 length prefix and bounded canonical payload using canon's codec.
    /// The channel stamps Auma; a guest provenance claim other than Auma refuses.
    /// A short/zero/oversized frame or I/O failure closes the endpoint immediately.
    /// No resynchronization or scan for a later boundary is permitted.
    pub fn receive(&mut self) -> core::result::Result<Frame<Request>, FrameError> {
        todo!("row 128")
    }

    /// Encode through canon, preserving version and request id. This exclusive borrow
    /// covers the entire prefix and payload, preventing simultaneous partial writes.
    /// Bound output before writing; write failure or deadline expiry closes the channel.
    pub fn send(&mut self, _reply: &Frame<Reply>) -> core::result::Result<(), FrameError> {
        todo!("row 128")
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close both directions; no organ retains another reader or socket clone.
    pub fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.closed = true;
            self.stream
                .shutdown(std::net::Shutdown::Both)
                .map_err(|_| canon::codes::SUPERVISOR_STATE)?;
        }
        Ok(())
    }
}
