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

pub const HANDOFF_PREPARE_PATH: &str = "/api/data/handoff/prepare";
pub const HANDOFF_COMPLETE_PATH: &str = "/api/data/handoff/complete";
pub const HANDOFF_PENDING_COOKIE: &str = "__Host-aukora-handoff";
pub const HANDOFF_CORRELATION_COOKIE: &str = "__Secure-aukora-handoff";
pub const HANDOFF_OWNER_COOKIE: &str = "__Host-aukora-owner-handoff";
pub const HANDOFF_LIFETIME_MS: u64 = 300_000;
const MAX_HANDOFFS: usize = 256;

struct PendingHandoff {
    pending: canon::digest::Digest32,
    reference: canon::digest::Digest32,
    owner_pending: Option<canon::digest::Digest32>,
    shell: crate::tls::Origin,
    expires_at_ms: u64,
    grant: Option<crate::ingress::ShellSessionGrant>,
}

/// The public reference locates a pending exchange; cookies and sign-in authorize it.
pub struct HandoffPrepared {
    pub cookies: [String; 2],
    pub reference: canon::digest::Digest32,
}

/// Process-local rendezvous; a restart discards pending admission, never creates it.
/// Cookies are HttpOnly. The shell notice and request body contain no bearer.
#[derive(Default)]
pub struct ShellHandoffs {
    pending: std::collections::BTreeMap<canon::digest::Digest32, PendingHandoff>,
}

impl ShellHandoffs {
    /// The domain cookie correlates the configured shell and owner; redemption also
    /// requires the shell's host-only cookie and a newly verified owner session.
    pub fn prepare(
        &mut self,
        request: &crate::ingress::AdmittedRequest,
        boundary: &crate::tls::CaddyBoundary,
        previous: Option<canon::digest::Digest32>,
        now_ms: u64,
    ) -> Result<HandoffPrepared> {
        handoff_request(request, HANDOFF_PREPARE_PATH)?;
        boundary.validate()?;
        if request.origin() != &boundary.shell
            || boundary.owner.host() != format!("owner.{}", boundary.shell.host())
        {
            return Err(canon::codes::FRONTDOOR_COOKIE_HOST_REFUSED);
        }
        let expires_at_ms = now_ms
            .checked_add(HANDOFF_LIFETIME_MS)
            .filter(|time| *time <= canon::json::MAX_SAFE_INTEGER as u64)
            .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?;
        self.pending.retain(|_, handoff| {
            handoff.expires_at_ms > now_ms && Some(handoff.pending) != previous
        });
        if self.pending.len() >= MAX_HANDOFFS {
            return Err(canon::codes::FRONTDOOR_OVERLOADED);
        }
        let pending = crate::session::SessionBearer::generate()?;
        let correlation = crate::session::SessionBearer::generate()?;
        let reference = crate::session::SessionBearer::generate()?.digest();
        let cookies = [
            handoff_cookie_header(HANDOFF_PENDING_COOKIE, &pending, None)?,
            handoff_cookie_header(
                HANDOFF_CORRELATION_COOKIE,
                &correlation,
                Some(boundary.shell.host()),
            )?,
        ];
        if self.pending.contains_key(&correlation.digest())
            || self
                .pending
                .values()
                .any(|old| old.pending == pending.digest() || old.reference == reference)
        {
            return Err(canon::codes::FRONTDOOR_SESSION_REQUIRED);
        }
        self.pending.insert(
            correlation.digest(),
            PendingHandoff {
                pending: pending.digest(),
                reference,
                owner_pending: None,
                shell: boundary.shell.clone(),
                expires_at_ms,
                grant: None,
            },
        );
        Ok(HandoffPrepared { cookies, reference })
    }

    /// Bind the shell-selected public reference to the admitted owner iframe.
    /// A domain cookie planted by a sibling cannot select a different reference.
    pub fn owner_navigation(
        &mut self,
        reference: canon::digest::Digest32,
        correlation: canon::digest::Digest32,
        navigation: &crate::owner_origin::FrameNavigation,
        now_ms: u64,
    ) -> Result<String> {
        let context = navigation.context();
        context.validate()?;
        let handoff = self
            .pending
            .get_mut(&correlation)
            .filter(|handoff| {
                handoff.reference == reference
                    && handoff.shell == context.expected_top_origin
                    && context.owner_origin.host() == format!("owner.{}", handoff.shell.host())
                    && handoff.expires_at_ms > now_ms
                    && handoff.owner_pending.is_none()
                    && handoff.grant.is_none()
            })
            .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?;
        let owner = crate::session::SessionBearer::generate()?;
        let cookie = handoff_cookie_header(HANDOFF_OWNER_COOKIE, &owner, None)?;
        handoff.owner_pending = Some(owner.digest());
        Ok(cookie)
    }

    /// Call only after successful passkey sign-in and durable owner-session insertion.
    pub fn authorize(
        &mut self,
        correlation: canon::digest::Digest32,
        owner_pending: canon::digest::Digest32,
        grant: crate::ingress::ShellSessionGrant,
        now_ms: u64,
    ) -> Result<()> {
        let handoff = self
            .pending
            .get_mut(&correlation)
            .filter(|handoff| {
                handoff.expires_at_ms > now_ms
                    && handoff.owner_pending == Some(owner_pending)
                    && handoff.grant.is_none()
            })
            .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?;
        handoff.grant = Some(grant);
        Ok(())
    }

    /// Consumes the grant before deriving the shell session. Failed writes cannot retry it.
    pub fn complete(
        &mut self,
        request: &crate::ingress::AdmittedRequest,
        pending: canon::digest::Digest32,
        correlation: canon::digest::Digest32,
        sessions: &mut impl crate::session::SessionStore,
        now_ms: u64,
    ) -> Result<[String; 3]> {
        handoff_request(request, HANDOFF_COMPLETE_PATH)?;
        let handoff = self
            .pending
            .get(&correlation)
            .filter(|handoff| {
                handoff.pending == pending
                    && handoff.shell == *request.origin()
                    && handoff.expires_at_ms > now_ms
                    && handoff.grant.is_some()
            })
            .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?;
        let domain = handoff.shell.host().to_owned();
        let grant = self
            .pending
            .remove(&correlation)
            .and_then(|handoff| handoff.grant)
            .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?;
        let session =
            grant.issue_cookie(sessions, request, now_ms, crate::session::MAX_LIFETIME_MS)?;
        Ok([
            session,
            format!(
                "{HANDOFF_PENDING_COOKIE}=; {}; Max-Age=0",
                crate::session::COOKIE_ATTRIBUTES
            ),
            format!(
                "{HANDOFF_CORRELATION_COOKIE}=; {}; Domain={domain}; Max-Age=0",
                crate::session::COOKIE_ATTRIBUTES
            ),
        ])
    }
}

fn handoff_request(request: &crate::ingress::AdmittedRequest, path: &str) -> Result<()> {
    if request.role() != crate::ingress::HostRole::Shell
        || request.method() != crate::ingress::Method::Post
        || request.path() != path
    {
        return Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE);
    }
    match request.body().view() {
        canon::json::ValueView::Object(fields) if fields.is_empty() => Ok(()),
        _ => Err(canon::codes::FRONTDOOR_BODY_INVALID),
    }
}

fn handoff_cookie_header(
    name: &str,
    bearer: &crate::session::SessionBearer,
    domain: Option<&str>,
) -> Result<String> {
    let token = std::str::from_utf8(bearer.as_bytes())
        .map_err(|_| canon::codes::FRONTDOOR_SESSION_REQUIRED)?;
    let domain = domain
        .map(|host| format!("; Domain={host}"))
        .unwrap_or_default();
    Ok(format!(
        "{name}={token}; {}{domain}; Max-Age={}",
        crate::session::COOKIE_ATTRIBUTES,
        HANDOFF_LIFETIME_MS / 1000,
    ))
}
