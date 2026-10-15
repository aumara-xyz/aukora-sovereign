// SPDX-License-Identifier: AGPL-3.0-or-later
//! Session-scoped data queues. Every output is encoded by canon before enqueueing.

use crate::{adapters::HostLedger, faces::health::HealthRead, health::HealthCollector};
use canon::{
    codes,
    digest::Digest32,
    fd4::{ChatCommand, SessionEvent},
    frame::Frame,
    ids::{AppId, NodeId},
    provenance::{Provenance, Source},
    Result,
};
use frontdoor::{
    fd4::{DataEndpoint, MAX_QUEUED_BYTES, MAX_QUEUED_FRAMES},
    session::BoundSession,
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};
use supervisor::{
    ingress::{BindingState, PrincipalScope},
    session::SessionStore,
};

struct Queue {
    scope: PrincipalScope,
    expires: u64,
    bytes: usize,
    events: VecDeque<Vec<u8>>,
}
pub struct HostData {
    sessions: Arc<supervisor::session::DurableSessions>,
    health: Arc<HealthCollector>,
    ledger: Arc<HostLedger>,
    producer: AppId,
    queues: Mutex<BTreeMap<Digest32, Queue>>,
}

impl HostData {
    pub fn new(
        sessions: Arc<supervisor::session::DurableSessions>,
        health: Arc<HealthCollector>,
        ledger: Arc<HostLedger>,
        node: NodeId,
    ) -> Result<Self> {
        Ok(Self {
            sessions,
            health,
            ledger,
            // The installed supervisor uses its persisted node identity for data replies.
            producer: AppId::from_bytes(*node.as_bytes()),
            queues: Mutex::new(BTreeMap::new()),
        })
    }

    /// Requires the host's `spawn_blocking` request task with its live-session lock held.
    /// The entered Tokio runtime drives session futures; a runtime worker must not
    /// call this synchronous method because its `Handle::block_on` would panic.
    pub fn dispatch(
        &self,
        session: &BoundSession<'_>,
        endpoint: DataEndpoint,
        payload: &[u8],
        now: u64,
    ) -> Result<http::Response<Vec<u8>>> {
        let record = session.record();
        let scope = PrincipalScope {
            subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
            epoch: record.owner_epoch,
        };
        if record.scope != frontdoor::session::SessionScope::Shell
            || self.ledger.binding()? != BindingState::Bound(scope)
        {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        let mut queues = self.queues.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
        queues.retain(|_, queue| queue.expires > now && queue.scope == scope);
        if !queues.contains_key(&record.token_digest) && queues.len() >= 64 {
            return Err(canon::Refusal {
                organ: "supervisor",
                reason: "queue-full",
            });
        }
        let queue = queues.entry(record.token_digest).or_insert_with(|| Queue {
            scope,
            expires: record.expires_at_ms,
            bytes: 0,
            events: VecDeque::new(),
        });
        if queue.scope != scope {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        match endpoint {
            DataEndpoint::Event => {
                let bytes = queue
                    .events
                    .pop_front()
                    .ok_or(codes::SUPERVISOR_NOT_READY)?;
                queue.bytes -= bytes.len();
                response(bytes)
            }
            DataEndpoint::Command => {
                // Reserve enough room for a maximum-sized reply before any transcript write.
                if queue.events.len() >= MAX_QUEUED_FRAMES
                    || queue.bytes + canon::frame::MAX_FRAME_BYTES > MAX_QUEUED_BYTES
                {
                    return Err(canon::Refusal {
                        organ: "supervisor",
                        reason: "queue-full",
                    });
                }
                let ingress = Provenance {
                    source: Source::Owner,
                };
                let command = canon::fd4::decode_command(payload, ingress.clone())?;
                let body = tokio::runtime::Handle::try_current()
                    .map_err(|_| codes::SUPERVISOR_NOT_READY)?
                    .block_on(self.command(scope, ingress, command.body))?;
                let event = Frame {
                    v: canon::fd4::VERSION,
                    id: command.id,
                    provenance: Provenance {
                        source: Source::App(self.producer),
                    },
                    body,
                };
                let bytes = canon::fd4::encode_event(&event)?;
                queue.bytes += bytes.len();
                queue.events.push_back(bytes);
                response(b"{\"ok\":true}".to_vec())
            }
        }
    }

    async fn command(
        &self,
        scope: PrincipalScope,
        ingress: Provenance,
        request: ChatCommand,
    ) -> Result<SessionEvent> {
        match request {
            ChatCommand::CreateSession(request) => Ok(SessionEvent::Created(
                self.sessions.create(scope, request).await?,
            )),
            ChatCommand::OpenSession(request) => Ok(SessionEvent::Opened(
                self.sessions.open(scope, request).await?,
            )),
            ChatCommand::ListSessions(request) => Ok(SessionEvent::Listed(
                self.sessions.list(scope, request).await?,
            )),
            ChatCommand::AppendSession(request) => Ok(SessionEvent::Appended(
                self.sessions.append(scope, ingress, request).await?,
            )),
            ChatCommand::FlushSession(request) => Ok(SessionEvent::Flushed(
                self.sessions.flush(scope, request).await?,
            )),
            ChatCommand::HealthSnapshot => Ok(SessionEvent::HealthSnapshot(
                canon::fd4::OpaqueHealthSnapshot::new(self.health.snapshot()?)?,
            )),
            ChatCommand::Turn(_) | ChatCommand::CancelModel(_) => Err(codes::SUPERVISOR_NOT_READY),
        }
    }
}

fn response(bytes: Vec<u8>) -> Result<http::Response<Vec<u8>>> {
    http::Response::builder()
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(bytes)
        .map_err(|_| codes::SUPERVISOR_STATE)
}
