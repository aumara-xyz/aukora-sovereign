// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed FD 3 dispatch table. Authority and policy stay behind the organ ports.

use crate::{
    ingress::{BindingState, ConversationCursor, GuestContext},
    services::{
        BindingService, BrokerService, CellService, GateService, KiraService, SnapshotService,
    },
    session::SessionStore,
};
use canon::{
    fd3::{Reply, Request},
    frame::Frame,
    Result,
};

/// One destination for every decoded request; no string-prefix fallback exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Gate,
    Broker,
    Kira,
    Sessions,
    Snapshot,
}

pub const fn destination(request: &Request) -> Route {
    match request {
        Request::Propose(_) | Request::Read(_) => Route::Gate,
        Request::ModelCall(_) | Request::ModelStart(_) | Request::ModelCancel(_) => Route::Broker,
        Request::MemoryPut(_) | Request::MemoryRecall(_) | Request::MemoryList(_) => Route::Kira,
        Request::SessionCreate(_)
        | Request::SessionOpen(_)
        | Request::SessionList(_)
        | Request::SessionAppend(_)
        | Request::SessionFlush(_) => Route::Sessions,
        Request::Status | Request::Organs => Route::Snapshot,
    }
}

/// References to trusted organ adapters; none is a socket or an owner capability.
pub struct OrganPorts<'a> {
    pub binding: &'a dyn BindingService,
    pub gate: &'a dyn GateService,
    pub broker: &'a dyn BrokerService,
    pub kira: &'a dyn KiraService,
    pub cell: &'a dyn CellService,
    pub sessions: &'a dyn SessionStore,
    pub snapshots: &'a dyn SnapshotService,
}

/// Stateful wiring for one guest. There is no retry-on-error entry point.
pub struct Router<'a> {
    ports: OrganPorts<'a>,
    context: GuestContext,
}

impl<'a> Router<'a> {
    pub fn new(ports: OrganPorts<'a>, context: GuestContext) -> Self {
        Self { ports, context }
    }

    pub const fn context(&self) -> &GuestContext {
        &self.context
    }

    pub const fn ports(&self) -> &OrganPorts<'a> {
        &self.ports
    }

    /// Load a principal-scoped session before retaining its current sequence locally.
    /// The stored transcript is data; selecting it grants no owner authority.
    pub async fn select_conversation(
        &mut self,
        request: canon::session::SessionOpen,
    ) -> Result<canon::session::SessionOpened> {
        if self.ports.binding.current().await? != BindingState::Bound(self.context.scope()) {
            return Err(canon::codes::AUMLOK_BINDING_REQUIRED);
        }
        let opened = self
            .ports
            .sessions
            .open(self.context.scope(), request)
            .await?;
        self.context.select(ConversationCursor {
            session_id: opened.summary.session_id,
            sequence: opened.summary.sequence,
        });
        Ok(opened)
    }

    /// Row 128: accept only canon-decoded requests with supervisor-stamped Auma origin.
    /// Recheck binding and epoch on every call; only status/organs remain available
    /// when the guest is being stopped. Route each body to its single named port.
    /// Re-run cell evidence before propose/memory.put; no comparison grants approval.
    /// Before model.call/start, obtain the active session's store-owned durable fence.
    /// Preserve the original correlation id and version on all replies; never retry a
    /// broker call. Bound pending requests/proposals and validate output with canon.
    /// Session appends reject owner provenance from this channel. Create/open update
    /// only the host-held conversation cursor after the scoped store has acknowledged.
    /// Unknown versions/kinds are refused by canon before this typed dispatch boundary.
    pub async fn dispatch(&mut self, _request: Frame<Request>) -> Result<Frame<Reply>> {
        todo!("row 128")
    }

    /// Row 128: poll only outstanding gate/Kira ids and admitted broker streams.
    /// Forward each terminal outcome once, and require the broker's settled receipt
    /// on success, error and cancellation. Full bounded queues pause producers.
    /// Approvals themselves remain host services and do not depend on this poller.
    pub async fn next_event(&mut self) -> Result<Option<Frame<Reply>>> {
        todo!("row 128")
    }
}
