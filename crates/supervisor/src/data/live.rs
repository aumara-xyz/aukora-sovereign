// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated, bounded FD 4 routing to an attached guest runtime.

use super::{response, HostData};
use crate::adapters::runtime::RuntimeAdapter;
use canon::{
    codes,
    digest::Digest32,
    fd4::{ChatCommand, SessionEvent},
    frame::{Frame, FrameId, MAX_FRAME_BYTES},
    ids::{RequestId, ReservationId, SessionId},
    provenance::{Provenance, Source},
    session::ModelStream,
    Result,
};
use frontdoor::session::BoundSession;
use std::{
    collections::{BTreeMap, VecDeque},
    io::{ErrorKind, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use supervisor::{ingress::PrincipalScope, runtime::GuestState};

const MAX_PENDING: usize = 32;
const IO_DEADLINE: Duration = Duration::from_secs(5);

pub struct RuntimeData {
    host: Arc<HostData>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    connection: Option<Connection>,
    next_id: u64,
}

struct Connection {
    stream: UnixStream,
    scope: PrincipalScope,
    pending: BTreeMap<String, Pending>,
    cancelled: BTreeMap<String, canon::session::ModelEnd>,
    writes: VecDeque<Outgoing>,
    incoming: Vec<u8>,
    read_started: Option<Instant>,
}

struct Outgoing {
    bytes: Vec<u8>,
    offset: usize,
    started: Instant,
}

struct Pending {
    browser_id: FrameId,
    token: Digest32,
    expires: u64,
    kind: PendingKind,
}

enum PendingKind {
    Turn {
        session: SessionId,
        sequence: u64,
        model: Option<ModelStream>,
        proposals: Vec<String>,
    },
    Cancel {
        turn: String,
        request: RequestId,
        reservation: ReservationId,
    },
}

impl RuntimeData {
    pub fn new(host: Arc<HostData>) -> Self {
        Self {
            host,
            state: Mutex::new(State::default()),
        }
    }

    /// Called with the frontdoor's authenticated session guard held.
    pub fn submit(
        &self,
        session: &BoundSession<'_>,
        payload: &[u8],
        now: u64,
        runtime: &RuntimeAdapter,
        no_model: bool,
    ) -> Result<http::Response<Vec<u8>>> {
        let mut command = canon::fd4::decode_command(payload, owner())?;
        if !matches!(
            command.body,
            ChatCommand::Turn(_) | ChatCommand::CancelModel(_)
        ) {
            return self
                .host
                .submit_owner_command(session, payload, now, no_model);
        }
        if no_model && matches!(command.body, ChatCommand::Turn(_)) {
            return self.host.submit_owner_command(session, payload, now, true);
        }
        let scope = self.host.runtime_admit(session, now)?;
        let mut state = self.state.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
        if !state.attach(runtime, scope)? {
            return self
                .host
                .submit_owner_command(session, payload, now, no_model);
        }
        state.drive(&self.host, now, runtime)?;
        let record = session.record();
        let connection = state
            .connection
            .as_ref()
            .ok_or(codes::SUPERVISOR_NOT_READY)?;
        // One of the guest's 32 command slots remains available for cancellation.
        let admission_limit = if matches!(command.body, ChatCommand::Turn(_)) {
            MAX_PENDING - 1
        } else {
            MAX_PENDING
        };
        if connection.pending.len() >= admission_limit || connection.writes.len() >= admission_limit
        {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        if connection
            .pending
            .values()
            .any(|pending| pending.token == record.token_digest && pending.browser_id == command.id)
        {
            return Err(codes::FRAME_INVALID_ID);
        }
        let kind =
            match &command.body {
                ChatCommand::Turn(turn) => PendingKind::Turn {
                    session: turn.session_id,
                    sequence: turn
                        .expected_sequence
                        .checked_add(1)
                        .ok_or(codes::SESSION_SEQUENCE)?,
                    model: None,
                    proposals: Vec::new(),
                },
                ChatCommand::CancelModel(cancel) => {
                    if connection.cancelled.len() + 2 > MAX_PENDING * 2 {
                        return Err(codes::FRAME_STREAM_LIMIT);
                    }
                    let matching = connection
                        .pending
                        .iter()
                        .filter(|(_, pending)| {
                            pending.token == record.token_digest && pending.expires > now
                        })
                        .find_map(|(id, pending)| match &pending.kind {
                            PendingKind::Turn {
                                model: Some(model), ..
                            } => (!model.is_ended()
                                && model.request_id() == cancel.request_id
                                && model.reservation_id() == cancel.reservation_id)
                                .then(|| id.clone()),
                            _ => None,
                        });
                    let turn = matching.ok_or(codes::FRAME_STREAM_ORDER)?;
                    if connection.pending.values().any(|pending| matches!(
                    &pending.kind,
                    PendingKind::Cancel { request, reservation, .. }
                    if *request == cancel.request_id && *reservation == cancel.reservation_id
                )) {
                    return Err(codes::FRAME_STREAM_ORDER);
                }
                    PendingKind::Cancel {
                        turn,
                        request: cancel.request_id,
                        reservation: cancel.reservation_id,
                    }
                }
                _ => return Err(codes::FRAME_UNKNOWN_KIND),
            };
        let browser_id = command.id.clone();
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or(codes::FRAME_STREAM_LIMIT)?;
        command.id = FrameId::new(format!("host-{:059}", state.next_id))?;
        let payload = canon::fd4::encode_command(&command)?;
        if let ChatCommand::Turn(turn) = &command.body {
            self.host.runtime_reserve_turn(session, now)?;
            let events = tokio::runtime::Handle::try_current()
                .map_err(|_| codes::SUPERVISOR_NOT_READY)?
                .block_on(self.host.append_owner_turn(scope, turn, now))?;
            let events = events
                .into_iter()
                .map(|body| {
                    canon::fd4::encode_event(&Frame {
                        v: canon::fd4::VERSION,
                        id: browser_id.clone(),
                        provenance: owner(),
                        body,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            if !self.host.runtime_enqueue_many(
                record.token_digest,
                scope,
                now,
                events,
                || Ok(()),
            )? {
                return Err(codes::FRAME_STREAM_LIMIT);
            }
        }
        let connection = state
            .connection
            .as_mut()
            .ok_or(codes::SUPERVISOR_NOT_READY)?;
        let mut bytes = Vec::with_capacity(payload.len() + 4);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&payload);
        connection.pending.insert(
            command.id.as_str().to_owned(),
            Pending {
                browser_id,
                token: record.token_digest,
                expires: record.expires_at_ms,
                kind,
            },
        );
        connection.writes.push_back(Outgoing {
            bytes,
            offset: 0,
            started: Instant::now(),
        });
        state.drive(&self.host, now, runtime)?;
        response(b"{\"ok\":true}".to_vec())
    }

    /// Polling reads and writes only bounded data; a full browser queue stops the reader.
    pub fn pump(&self, now: u64, runtime: &RuntimeAdapter) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| codes::SUPERVISOR_STATE)?
            .drive(&self.host, now, runtime)
    }
}

impl State {
    fn attach(&mut self, runtime: &RuntimeAdapter, scope: PrincipalScope) -> Result<bool> {
        let running = running_scope(runtime)?;
        if running != Some(scope) {
            self.connection = None;
            return Ok(false);
        }
        if self
            .connection
            .as_ref()
            .is_some_and(|connection| connection.scope != scope)
        {
            self.connection = None;
        }
        if self.connection.is_none() {
            let stream = match runtime.take_app_data() {
                Ok(stream) => stream,
                Err(code) if code == codes::SUPERVISOR_NOT_READY => return Ok(false),
                Err(code) => return Err(code),
            };
            stream
                .set_nonblocking(true)
                .map_err(|_| codes::SUPERVISOR_STATE)?;
            self.connection = Some(Connection {
                stream,
                scope,
                pending: BTreeMap::new(),
                cancelled: BTreeMap::new(),
                writes: VecDeque::new(),
                incoming: Vec::new(),
                read_started: None,
            });
        }
        Ok(true)
    }

    fn drive(&mut self, host: &HostData, now: u64, runtime: &RuntimeAdapter) -> Result<()> {
        let Some(connection) = self.connection.as_mut() else {
            return Ok(());
        };
        let result = (|| {
            if running_scope(runtime)? != Some(connection.scope)
                || host.ledger.binding()?
                    != supervisor::ingress::BindingState::Bound(connection.scope)
            {
                return Err(codes::AUMLOK_BINDING_REQUIRED);
            }
            // Correlations are retained until session expiry: model.end is not a chat terminal.
            // A guest has no wire turn-finished event, so an expired active turn closes the channel.
            if connection
                .pending
                .values()
                .any(|pending| pending.expires <= now)
            {
                return Err(codes::FRONTDOOR_SESSION_REQUIRED);
            }
            connection.write_ready()?;
            for _ in 0..MAX_PENDING {
                if !connection.read_ready()? || !connection.forward(host, now)? {
                    break;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.connection = None;
        }
        result
    }
}

impl Connection {
    fn write_ready(&mut self) -> Result<()> {
        let mut budget = MAX_FRAME_BYTES * MAX_PENDING;
        while let Some(frame) = self.writes.front_mut() {
            if frame.started.elapsed() > IO_DEADLINE {
                return Err(codes::FRAME_IO);
            }
            match self.stream.write(&frame.bytes[frame.offset..]) {
                Ok(0) => return Err(codes::FRAME_IO),
                Ok(count) => {
                    frame.offset += count;
                    budget = budget.saturating_sub(count);
                    if frame.offset == frame.bytes.len() {
                        self.writes.pop_front();
                    }
                    if budget == 0 {
                        break;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(codes::FRAME_IO),
            }
        }
        Ok(())
    }

    fn read_ready(&mut self) -> Result<bool> {
        loop {
            let needed = if self.incoming.len() < 4 {
                4
            } else {
                let size = u32::from_be_bytes(
                    self.incoming[..4]
                        .try_into()
                        .map_err(|_| codes::FRAME_INVALID_FIELD)?,
                ) as usize;
                if size == 0 {
                    return Err(codes::FRAME_ZERO_LENGTH);
                }
                if size > MAX_FRAME_BYTES {
                    return Err(codes::FRAME_TOO_LARGE);
                }
                size + 4
            };
            if self.incoming.len() == needed && needed > 4 {
                self.read_started = None;
                return Ok(true);
            }
            if self
                .read_started
                .is_some_and(|started| started.elapsed() > IO_DEADLINE)
            {
                return Err(codes::FRAME_SHORT_READ);
            }
            let mut buffer = [0_u8; 8192];
            let count = (needed - self.incoming.len()).min(buffer.len());
            match self.stream.read(&mut buffer[..count]) {
                Ok(0) => return Err(codes::FRAME_SHORT_READ),
                Ok(count) => {
                    self.read_started.get_or_insert_with(Instant::now);
                    self.incoming.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(codes::FRAME_IO),
            }
        }
    }

    fn forward(&mut self, host: &HostData, now: u64) -> Result<bool> {
        let mut event = canon::fd4::decode_event(&self.incoming[4..], auma())?;
        let wire_id = event.id.as_str().to_owned();
        if let SessionEvent::ModelCancelled(end) = &event.body {
            if self.cancelled.get(&wire_id) == Some(end) {
                self.incoming.clear();
                return Ok(true);
            }
        }
        if let SessionEvent::ModelStarted(started) = &event.body {
            if self.pending.values().any(|pending| {
                matches!(
                    &pending.kind,
                    PendingKind::Turn { model: Some(model), .. }
                    if model.request_id() == started.request_id
                        || model.reservation_id() == started.reservation_id
                )
            }) {
                return Err(codes::FRAME_INVALID_ID);
            }
        }
        if matches!(
            event.body,
            SessionEvent::ProposalAccepted(_) | SessionEvent::LegacyProposalAccepted { .. }
        ) {
            let count: usize = self
                .pending
                .values()
                .map(|pending| match &pending.kind {
                    PendingKind::Turn { proposals, .. } => proposals.len(),
                    _ => 0,
                })
                .sum();
            if count >= 128 {
                return Err(codes::FRAME_STREAM_LIMIT);
            }
            let id = match &event.body {
                SessionEvent::ProposalAccepted(value) => value.proposal_id.to_string(),
                SessionEvent::LegacyProposalAccepted { proposal_id } => proposal_id.clone(),
                _ => return Err(codes::FRAME_UNKNOWN_KIND),
            };
            if self.pending.values().any(|pending| {
                matches!(&pending.kind,
                    PendingKind::Turn { proposals, .. } if proposals.contains(&id)
                )
            }) {
                return Err(codes::FRAME_INVALID_ID);
            }
        }
        let mut pending = self
            .pending
            .remove(&wire_id)
            .ok_or(codes::FRAME_INVALID_ID)?;
        event.id = pending.browser_id.clone();
        let mut events = vec![canon::fd4::encode_event(&event)?];
        let mut paired_id = None;
        if let SessionEvent::ModelCancelled(end) = &event.body {
            paired_id = match &pending.kind {
                PendingKind::Cancel { turn, .. } => Some(turn.clone()),
                PendingKind::Turn { .. } => self.pending.iter().find_map(|(id, other)| {
                    matches!(&other.kind,
                        PendingKind::Cancel { turn, request, reservation }
                        if *turn == wire_id && *request == end.request_id
                            && *reservation == end.reservation_id
                    )
                    .then(|| id.clone())
                }),
            };
            if let Some(id) = &paired_id {
                let paired = self.pending.get(id).ok_or(codes::FRAME_INVALID_ID)?;
                if paired.token != pending.token || paired.expires != pending.expires {
                    return Err(codes::FRAME_PROVENANCE);
                }
                events.push(canon::fd4::encode_event(&Frame {
                    v: event.v,
                    id: paired.browser_id.clone(),
                    provenance: auma(),
                    body: event.body.clone(),
                })?);
            }
        }
        if matches!(event.body, SessionEvent::ModelCancelled(_)) {
            let added = usize::from(!self.cancelled.contains_key(&wire_id))
                + usize::from(
                    paired_id
                        .as_ref()
                        .is_some_and(|id| !self.cancelled.contains_key(id)),
                );
            if self.cancelled.len() + added > MAX_PENDING * 2 {
                return Err(codes::FRAME_STREAM_LIMIT);
            }
        }
        let queued = host.runtime_enqueue_many(pending.token, self.scope, now, events, || {
            if let Some(id) = &paired_id {
                self.pending
                    .get_mut(id)
                    .ok_or(codes::FRAME_INVALID_ID)?
                    .observe(&event.body)?;
            }
            pending.observe(&event.body)
        })?;
        if !queued {
            self.pending.insert(wire_id, pending);
            return Ok(false);
        }
        if let SessionEvent::ModelCancelled(end) = &event.body {
            self.cancelled.insert(wire_id.clone(), end.clone());
            if let Some(id) = &paired_id {
                self.cancelled.insert(id.clone(), end.clone());
            }
        }
        if !matches!(pending.kind, PendingKind::Cancel { .. }) {
            self.pending.insert(wire_id, pending);
        }
        if let Some(id) = paired_id {
            if self
                .pending
                .get(&id)
                .is_some_and(|paired| matches!(paired.kind, PendingKind::Cancel { .. }))
            {
                self.pending.remove(&id);
            }
        }
        self.incoming.clear();
        Ok(true)
    }
}

impl Pending {
    fn observe(&mut self, event: &SessionEvent) -> Result<()> {
        if matches!(event, SessionEvent::Refusal(_)) {
            return Ok(());
        }
        match &mut self.kind {
            PendingKind::Cancel {
                request,
                reservation,
                ..
            } => match event {
                SessionEvent::ModelCancelled(end)
                    if end.request_id == *request && end.reservation_id == *reservation =>
                {
                    Ok(())
                }
                _ => Err(codes::FRAME_STREAM_ORDER),
            },
            PendingKind::Turn {
                session,
                sequence,
                model,
                proposals,
            } => {
                match event {
                    SessionEvent::Entry(entry)
                    | SessionEvent::Appended(canon::session::SessionAppended { entry }) => {
                        supervisor::ingress::guest_entry(entry)?;
                        if entry.session_id != *session || entry.sequence != *sequence + 1 {
                            return Err(codes::SESSION_SEQUENCE);
                        }
                        *sequence = entry.sequence;
                    }
                    SessionEvent::Flushed(flushed) => {
                        if flushed.session_id != *session || flushed.sequence != *sequence {
                            return Err(codes::SESSION_SEQUENCE);
                        }
                    }
                    SessionEvent::ModelStarted(started) => {
                        if model.as_ref().is_some_and(|stream| !stream.is_ended()) {
                            return Err(codes::FRAME_STREAM_ORDER);
                        }
                        *model = Some(ModelStream::new(started)?);
                    }
                    SessionEvent::ModelDelta(delta) => {
                        let stream = model.as_mut().ok_or(codes::FRAME_STREAM_ORDER)?;
                        stream.observe_delta(delta)?;
                        stream.acknowledge_through(delta.index)?;
                    }
                    SessionEvent::ModelEnd(end) | SessionEvent::ModelCancelled(end) => {
                        model
                            .as_mut()
                            .ok_or(codes::FRAME_STREAM_ORDER)?
                            .observe_end(end)?;
                    }
                    SessionEvent::ModelError(error) => {
                        model
                            .as_mut()
                            .ok_or(codes::FRAME_STREAM_ORDER)?
                            .observe_error(error)?;
                    }
                    SessionEvent::ProposalAccepted(value) => {
                        accept(proposals, value.proposal_id.to_string())?
                    }
                    SessionEvent::LegacyProposalAccepted { proposal_id } => {
                        accept(proposals, proposal_id.clone())?
                    }
                    SessionEvent::ProposalOutcome(value) => {
                        outcome(proposals, &value.proposal_id.to_string())?
                    }
                    SessionEvent::LegacyProposalOutcome { proposal_id, .. } => {
                        outcome(proposals, proposal_id)?
                    }
                    SessionEvent::MemoryRecall(_) | SessionEvent::MemoryListed(_) => {}
                    _ => return Err(codes::FRAME_UNKNOWN_KIND),
                }
                Ok(())
            }
        }
    }
}

fn accept(proposals: &mut Vec<String>, proposal: String) -> Result<()> {
    if proposals.len() >= 128 {
        return Err(codes::FRAME_STREAM_LIMIT);
    }
    if proposals.contains(&proposal) {
        return Err(codes::FRAME_INVALID_ID);
    }
    proposals.push(proposal);
    Ok(())
}

fn outcome(proposals: &mut Vec<String>, proposal: &str) -> Result<()> {
    let index = proposals
        .iter()
        .position(|pending| pending == proposal)
        .ok_or(codes::FRAME_INVALID_ID)?;
    proposals.remove(index);
    Ok(())
}

fn running_scope(runtime: &RuntimeAdapter) -> Result<Option<PrincipalScope>> {
    Ok(runtime
        .facts()?
        .filter(|facts| facts.guest_state == GuestState::Running)
        .and_then(|facts| facts.guest_bound_subject))
}

fn owner() -> Provenance {
    Provenance {
        source: Source::Owner,
    }
}
fn auma() -> Provenance {
    Provenance {
        source: Source::Auma,
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
