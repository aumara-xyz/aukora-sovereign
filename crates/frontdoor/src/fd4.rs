// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed data bridge only. It creates no FD 3 or organ-service sockets.

use crate::session::BoundSession;
use canon::{
    fd4::{ChatCommand, SessionEvent},
    frame::{Disposition, Frame, FrameError, MAX_FRAME_BYTES},
    provenance::{Provenance, Source},
    Refusal, Result,
};

pub const MAX_QUEUED_FRAMES: usize = 32;
pub const MAX_QUEUED_BYTES: usize = 256 * 1024;
pub const DATA_PATH: &str = "/api/data";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataEndpoint {
    Command,
    Event,
}

impl DataEndpoint {
    pub fn resolve(
        role: crate::ingress::HostRole,
        method: crate::ingress::Method,
        path: &str,
    ) -> Result<Self> {
        use crate::ingress::{HostRole, Method};
        if role != HostRole::Shell {
            return Err(canon::codes::FRONTDOOR_HOST_REFUSED);
        }
        crate::ingress::validate_path(path)?;
        match (method, path) {
            (Method::Post, DATA_PATH) => Ok(Self::Command),
            (Method::Get, DATA_PATH) => Ok(Self::Event),
            _ => Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE),
        }
    }
}

/// A command submission acknowledges transport only; events remain canonical FD 4 data.
pub enum DataResponse {
    Submitted,
    Event(Vec<u8>),
}

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

    /// HTTP dispatch retains the shell's live-session guard through one channel operation.
    pub fn dispatch<S: crate::session::SessionStore>(
        &mut self,
        sessions: &mut S,
        admitted: &crate::ingress::AdmittedRequest,
        node: canon::ids::NodeId,
        now_ms: u64,
    ) -> Result<DataResponse> {
        let endpoint = DataEndpoint::resolve(admitted.role(), admitted.method(), admitted.path())?;
        crate::session::with_bound_session(
            sessions,
            admitted
                .cookie()
                .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?,
            node,
            admitted.origin(),
            now_ms,
            |session| match endpoint {
                DataEndpoint::Command => {
                    self.submit(&session, &canon::json::to_canonical(admitted.body()))?;
                    Ok(DataResponse::Submitted)
                }
                DataEndpoint::Event => self.next_event(&session).map(DataResponse::Event),
            },
        )
    }

    /// Canon decodes exact bounded commands; ingress source comes from the live session.
    /// The supervisor rechecks session ownership, epoch and per-frame authorization.
    pub fn submit(&mut self, session: &BoundSession<'_>, payload: &[u8]) -> Result<()> {
        self.submit_inner(session, payload, None)
    }

    /// All variants go through canon::fd4::encode_event without interpretation or added fields.
    /// Opaque coherence bytes are never parsed here; code-like text remains literal text.
    pub fn next_event(&mut self, session: &BoundSession<'_>) -> Result<Vec<u8>> {
        self.event_inner(session, None)
    }

    /// Records this synchronous bridge's refusals and closes without retaining event data.
    pub fn submit_observed(
        &mut self,
        session: &BoundSession<'_>,
        payload: &[u8],
        facts: &mut DataFacts,
    ) -> Result<()> {
        self.submit_inner(session, payload, Some(facts))
    }

    /// Queue facts are zero outside the one synchronous channel operation.
    pub fn next_event_observed(
        &mut self,
        session: &BoundSession<'_>,
        facts: &mut DataFacts,
    ) -> Result<Vec<u8>> {
        self.event_inner(session, Some(facts))
    }

    fn submit_inner(
        &mut self,
        session: &BoundSession<'_>,
        payload: &[u8],
        mut facts: Option<&mut DataFacts>,
    ) -> Result<()> {
        clear_queue(&mut facts);
        let decoded = require_data_session(session).and_then(|()| {
            if payload.is_empty() {
                return Err(canon::codes::FRAME_ZERO_LENGTH);
            }
            if payload.len() > MAX_FRAME_BYTES || payload.len() > MAX_QUEUED_BYTES {
                return Err(canon::codes::FRAME_TOO_LARGE);
            }
            canon::fd4::decode_command(
                payload,
                Provenance {
                    source: Source::Owner,
                },
            )
        });
        let command = match decoded {
            Ok(command) => command,
            Err(refusal) => {
                count_refusal(&mut facts);
                return Err(refusal);
            }
        };
        if let Some(facts) = facts.as_deref_mut() {
            facts.queued_frames = 1;
            facts.queued_bytes = payload.len();
        }
        let result = self.channel.send(command);
        clear_queue(&mut facts);
        if result.is_err() {
            count_refusal(&mut facts);
            self.channel.close();
            count_close(&mut facts);
        }
        result
    }

    fn event_inner(
        &mut self,
        session: &BoundSession<'_>,
        mut facts: Option<&mut DataFacts>,
    ) -> Result<Vec<u8>> {
        clear_queue(&mut facts);
        if let Err(refusal) = require_data_session(session) {
            count_refusal(&mut facts);
            return Err(refusal);
        }
        let event = match self.channel.receive() {
            Ok(event) => event,
            Err(error) => {
                count_refusal(&mut facts);
                if error.disposition == Disposition::Close {
                    self.channel.close();
                    count_close(&mut facts);
                }
                return Err(error.refusal);
            }
        };
        match canon::fd4::encode_event(&event) {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_FRAME_BYTES => Ok(bytes),
            result => {
                count_refusal(&mut facts);
                self.channel.close();
                count_close(&mut facts);
                Err(result.err().unwrap_or(canon::codes::FRAME_TOO_LARGE))
            }
        }
    }

    pub fn close(&mut self) {
        self.channel.close();
    }
}

pub(crate) fn require_data_session(session: &BoundSession<'_>) -> Result<()> {
    let record = session.record();
    if record.revoked
        || record.subject.is_none()
        || record.scope != crate::session::SessionScope::Shell
    {
        return Err(Refusal {
            organ: "frontdoor",
            reason: "session-required",
        });
    }
    Ok(())
}

fn clear_queue(facts: &mut Option<&mut DataFacts>) {
    if let Some(facts) = facts.as_deref_mut() {
        facts.queued_frames = 0;
        facts.queued_bytes = 0;
    }
}

fn count_refusal(facts: &mut Option<&mut DataFacts>) {
    if let Some(facts) = facts.as_deref_mut() {
        facts.refused_payloads = facts.refused_payloads.saturating_add(1);
    }
}

fn count_close(facts: &mut Option<&mut DataFacts>) {
    if let Some(facts) = facts.as_deref_mut() {
        facts.fatal_closes = facts.fatal_closes.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DataFacts {
    pub queued_frames: usize,
    pub queued_bytes: usize,
    pub refused_payloads: u64,
    pub fatal_closes: u64,
}
