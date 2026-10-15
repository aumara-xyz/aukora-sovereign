// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host-correlated presentation events around the unchanged FD 4 payload.
use super::{refuse, wire};
use canon::{
    fd4::SessionEvent,
    ids::{RequestId, ReservationId, SessionId},
    json::Value,
    session::{ModelStarted, ModelStream},
    Result,
};
use std::collections::BTreeMap;
use supervisor::{ingress::PrincipalScope, session::DispatchFence};

pub const SCHEMA: &str = "aukora-session-stream-event-v3";
const MAX_STREAMS: usize = 256;
struct BoundStream {
    scope: PrincipalScope,
    session: SessionId,
    validator: ModelStream,
}

/// Association comes from the store's flush receipt before broker dispatch.
#[derive(Default)]
pub struct StreamSessions {
    streams: BTreeMap<(RequestId, ReservationId), BoundStream>,
}

impl StreamSessions {
    pub fn started(&mut self, fence: &DispatchFence, started: ModelStarted) -> Result<Value> {
        let key = (started.request_id, started.reservation_id);
        if self.streams.len() >= MAX_STREAMS
            || self
                .streams
                .keys()
                .any(|(request, reservation)| *request == key.0 || *reservation == key.1)
        {
            return Err(refuse("stream-session-conflict"));
        }
        let validator = ModelStream::new(&started)?;
        let session = fence.receipt().session_id;
        let output = envelope(session, SessionEvent::ModelStarted(started))?;
        self.streams.insert(
            key,
            BoundStream {
                scope: fence.scope(),
                session,
                validator,
            },
        );
        Ok(output)
    }

    pub fn event(&mut self, scope: PrincipalScope, event: SessionEvent) -> Result<Value> {
        let key = match &event {
            SessionEvent::ModelDelta(delta) => (delta.request_id, delta.reservation_id),
            SessionEvent::ModelEnd(end) | SessionEvent::ModelCancelled(end) => {
                (end.request_id, end.reservation_id)
            }
            SessionEvent::ModelError(error) => (error.request_id, error.reservation_id),
            _ => return Err(refuse("stream-event-invalid")),
        };
        let bound = self
            .streams
            .get_mut(&key)
            .ok_or(refuse("stream-session-missing"))?;
        if bound.scope != scope {
            return Err(refuse("face-principal-mismatch"));
        }
        let output = envelope(bound.session, event.clone())?;
        let ended = match &event {
            SessionEvent::ModelDelta(delta) => {
                bound.validator.observe_delta(delta)?;
                false
            }
            SessionEvent::ModelEnd(end) | SessionEvent::ModelCancelled(end) => {
                bound.validator.observe_end(end)?;
                true
            }
            SessionEvent::ModelError(error) => {
                bound.validator.observe_error(error)?;
                true
            }
            _ => return Err(refuse("stream-event-invalid")),
        };
        if ended {
            self.streams.remove(&key);
        }
        Ok(output)
    }

    /// Called after the corresponding presentation event has been written.
    pub fn delivered(
        &mut self,
        scope: PrincipalScope,
        request: RequestId,
        reservation: ReservationId,
        index: u64,
    ) -> Result<()> {
        let bound = self
            .streams
            .get_mut(&(request, reservation))
            .ok_or(refuse("stream-session-missing"))?;
        if bound.scope != scope {
            return Err(refuse("face-principal-mismatch"));
        }
        bound.validator.acknowledge_through(index)
    }
}

fn envelope(session: SessionId, event: SessionEvent) -> Result<Value> {
    let kind = event.kind();
    let body = wire::event(event)?;
    wire::bounded(wire::object([
        ("schema", wire::text(SCHEMA)?),
        ("session_id", wire::text(session.to_string())?),
        (
            "event",
            wire::object([("kind", wire::text(kind)?), ("body", body)])?,
        ),
    ])?)
}
