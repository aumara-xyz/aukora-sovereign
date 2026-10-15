// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sole host reader and serialized writer of the inherited FD 3 stream.

use canon::{
    codes,
    fd3::{Reply, Request},
    fd3_payloads::RefusalReply,
    frame::{self, Disposition, Frame, FrameError, FrameId},
    json::ValueView,
    provenance::{Provenance, Source},
    Result,
};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;

pub const MAX_PENDING_REQUESTS: usize = 16;
pub const MAX_PENDING_PROPOSALS: usize = 64;
pub const SEND_DEADLINE: Duration = Duration::from_secs(5);

/// Owns the host end of the launcher-created AF_UNIX SOCK_STREAM socketpair.
/// It exposes no descriptor, clone, split reader or direct socket access to organs.
#[derive(Debug)]
pub struct GuestChannel {
    stream: UnixStream,
    closed: bool,
    incoming: Vec<u8>,
    read_deadline: Option<Instant>,
    refused_correlation: Option<(u16, FrameId)>,
}

impl GuestChannel {
    /// Adopt the host endpoint from launcher. Row 128 sets deadlines before use.
    pub fn attach(stream: UnixStream) -> Result<Self> {
        stream
            .set_nonblocking(false)
            .and_then(|_| stream.set_read_timeout(None))
            .and_then(|_| stream.set_write_timeout(Some(SEND_DEADLINE)))
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        Ok(Self {
            stream,
            closed: false,
            incoming: Vec::new(),
            read_deadline: None,
            refused_correlation: None,
        })
    }

    /// Read one C4 length prefix and bounded canonical payload using canon's codec.
    /// The channel stamps Auma; a guest provenance claim other than Auma refuses.
    /// A short/zero/oversized frame or I/O failure closes the endpoint immediately.
    /// No resynchronization or scan for a later boundary is permitted.
    pub fn receive(&mut self) -> core::result::Result<Frame<Request>, FrameError> {
        self.require_open()?;
        let result = self.read_blocking().and_then(|()| self.decode_incoming());
        self.handle_error(result)
    }

    /// Wait without blocking the supervisor runtime. Cancelling this future retains
    /// every received byte and the original deadline for a partially read frame.
    /// An idle stream has no deadline; the first byte starts a bounded frame read.
    pub async fn receive_async(&mut self) -> core::result::Result<Frame<Request>, FrameError> {
        self.require_open()?;
        let result = read_async(&self.stream, &mut self.incoming, &mut self.read_deadline)
            .await
            .and_then(|()| self.decode_incoming());
        self.handle_error(result)
    }

    /// Encode through canon, preserving version and request id. This exclusive borrow
    /// covers the entire prefix and payload, preventing simultaneous partial writes.
    /// Bound output before writing; write failure or deadline expiry closes the channel.
    pub fn send(&mut self, reply: &Frame<Reply>) -> core::result::Result<(), FrameError> {
        self.require_open()?;
        let payload = canon::fd3::encode_reply(reply).map_err(refuse)?;
        let value = frame::decode(&payload).map_err(refuse)?;
        let result = self
            .stream
            .set_nonblocking(false)
            .map_err(io_failure)
            .and_then(|()| {
                frame::write(
                    &mut DeadlineWriter {
                        stream: &self.stream,
                        deadline: Instant::now() + SEND_DEADLINE,
                    },
                    &value,
                )
            });
        self.handle_error(result)
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Recover the last complete canonical envelope's checked version and id for
    /// a semantic refusal. Unsupported versions and invalid ids are never guessed.
    pub fn refusal_reply(&mut self, code: canon::Refusal) -> Option<Frame<Reply>> {
        self.refused_correlation.take().map(|(v, id)| Frame {
            v,
            id,
            provenance: Provenance {
                source: Source::Auma,
            },
            body: Reply::Refusal(RefusalReply {
                code,
                next: String::new(),
            }),
        })
    }

    /// Close both directions; no organ retains another reader or socket clone.
    pub fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.stream
                .shutdown(std::net::Shutdown::Both)
                .map_err(|_| codes::SUPERVISOR_STATE)?;
            self.closed = true;
        }
        Ok(())
    }

    fn require_open(&self) -> core::result::Result<(), FrameError> {
        if self.closed {
            Err(close_error(codes::FRAME_IO))
        } else {
            Ok(())
        }
    }

    fn handle_error<T>(
        &mut self,
        result: core::result::Result<T, FrameError>,
    ) -> core::result::Result<T, FrameError> {
        if matches!(&result, Err(error) if error.disposition == Disposition::Close) {
            let _ = self.close();
        }
        result
    }

    fn read_blocking(&mut self) -> core::result::Result<(), FrameError> {
        self.stream.set_nonblocking(false).map_err(io_failure)?;
        let mut chunk = [0u8; 4096];
        loop {
            let needed = remaining_bytes(&self.incoming)?;
            if needed == 0 {
                return Ok(());
            }
            let timeout = self
                .read_deadline
                .map(time_left)
                .transpose()
                .map_err(io_failure)?;
            self.stream.set_read_timeout(timeout).map_err(io_failure)?;
            let capacity = needed.min(chunk.len());
            match self.stream.read(&mut chunk[..capacity]) {
                Ok(0) => return Err(close_error(codes::FRAME_SHORT_READ)),
                Ok(count) => {
                    self.read_deadline
                        .get_or_insert_with(|| Instant::now() + SEND_DEADLINE);
                    self.incoming.extend_from_slice(&chunk[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_failure(error)),
            }
        }
    }

    fn decode_incoming(&mut self) -> core::result::Result<Frame<Request>, FrameError> {
        self.refused_correlation = None;
        let decoded = frame::decode_prefixed(&self.incoming);
        self.incoming.clear();
        self.read_deadline = None;
        let (value, _) = decoded?;
        let correlation = match (
            value.get("v").map(canon::json::Value::view),
            value.get("id").map(canon::json::Value::view),
        ) {
            (Some(ValueView::Integer(version)), Some(ValueView::Text(id)))
                if matches!(version.get(), 1 | 2) =>
            {
                FrameId::new(id.to_owned())
                    .ok()
                    .map(|id| (version.get() as u16, id))
            }
            _ => None,
        };
        let decoded = canon::fd3::decode_request(
            &canon::json::to_canonical(&value),
            Provenance {
                source: Source::Auma,
            },
        )
        .map_err(refuse);
        if decoded.is_err() {
            self.refused_correlation = correlation;
        }
        decoded
    }
}

async fn read_async(
    stream: &UnixStream,
    incoming: &mut Vec<u8>,
    deadline: &mut Option<Instant>,
) -> core::result::Result<(), FrameError> {
    stream.set_nonblocking(true).map_err(io_failure)?;
    // BorrowedFd keeps the endpoint alive while the reactor registration exists.
    #[allow(deprecated)]
    let registered = AsyncFd::new(stream.as_fd()).map_err(io_failure)?;
    let mut chunk = [0u8; 4096];
    loop {
        let needed = remaining_bytes(incoming)?;
        if needed == 0 {
            return Ok(());
        }
        let ready = registered.readable();
        let mut guard = match *deadline {
            Some(until) => tokio::time::timeout(time_left(until).map_err(io_failure)?, ready)
                .await
                .map_err(|_| close_error(codes::FRAME_IO))?
                .map_err(io_failure)?,
            None => ready.await.map_err(io_failure)?,
        };
        let capacity = needed.min(chunk.len());
        match guard.try_io(|_| {
            let mut reader = stream;
            reader.read(&mut chunk[..capacity])
        }) {
            Ok(Ok(0)) => return Err(close_error(codes::FRAME_SHORT_READ)),
            Ok(Ok(count)) => {
                deadline.get_or_insert_with(|| Instant::now() + SEND_DEADLINE);
                incoming.extend_from_slice(&chunk[..count]);
            }
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(io_failure(error)),
            Err(_) => continue,
        }
    }
}

fn remaining_bytes(bytes: &[u8]) -> core::result::Result<usize, FrameError> {
    if bytes.len() < frame::LENGTH_PREFIX_BYTES {
        return Ok(frame::LENGTH_PREFIX_BYTES - bytes.len());
    }
    let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if length < frame::MIN_FRAME_BYTES {
        return Err(close_error(codes::FRAME_ZERO_LENGTH));
    }
    if length > frame::MAX_FRAME_BYTES {
        return Err(close_error(codes::FRAME_TOO_LARGE));
    }
    Ok(frame::LENGTH_PREFIX_BYTES + length - bytes.len())
}

struct DeadlineWriter<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl Write for DeadlineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(time_left(self.deadline)?))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn time_left(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "frame deadline"))
}

fn io_failure(_: io::Error) -> FrameError {
    close_error(codes::FRAME_IO)
}

fn close_error(refusal: canon::Refusal) -> FrameError {
    FrameError {
        refusal,
        disposition: Disposition::Close,
    }
}

fn refuse(refusal: canon::Refusal) -> FrameError {
    FrameError {
        refusal,
        disposition: Disposition::Refuse,
    }
}
