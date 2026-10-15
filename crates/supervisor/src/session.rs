// SPDX-License-Identifier: AGPL-3.0-or-later
//! Supervisor-owned transcript persistence, separate from Kira notes.

use crate::{ingress::PrincipalScope, services::ServiceFuture};
use canon::{
    digest::Digest32,
    ids::SessionId,
    provenance::Provenance,
    session::{
        SessionAppend, SessionAppended, SessionCreate, SessionFlush, SessionFlushed, SessionList,
        SessionOpen, SessionOpened, SessionPage, SessionSummary,
    },
    Result,
};
use std::path::PathBuf;
use std::sync::Mutex;

mod codec;
mod disk;

/// Host-side storage bounds. Frames retain canon's independent 65,536-byte cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLimits {
    pub max_sessions_per_principal: u32,
    pub max_entries_per_session: u64,
    pub max_bytes_per_principal: u64,
}

/// Owner-configured store location, never supplied by a guest frame.
#[derive(Clone, Debug)]
pub struct SessionStoreConfig {
    pub root: PathBuf,
    pub limits: SessionLimits,
}

/// Result of inspecting only the append tail under the store's exclusive lock.
/// A malformed complete record or changed committed prefix refuses recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailRecovery {
    pub session_id: SessionId,
    pub last_complete_sequence: u64,
    pub discarded_tail_bytes: u64,
    pub committed_prefix: Digest32,
}

/// A local dispatch barrier, never serialized into a v1 or v2 request body.
/// It can be obtained only from the supervisor's durable store coordination.
#[derive(Debug)]
pub struct DispatchFence {
    scope: PrincipalScope,
    receipt: SessionFlushed,
}

impl DispatchFence {
    pub const fn scope(&self) -> PrincipalScope {
        self.scope
    }

    pub const fn receipt(&self) -> &SessionFlushed {
        &self.receipt
    }
}

/// Methods are scoped by authenticated host state, not by body-supplied principal ids.
/// Implementations hold the store lock across compare, append and commit; exact
/// record layouts remain canon::session's v2 types. They use no Kira note storage.
pub trait SessionStore: Send + Sync {
    /// Persist the common summary and its containing directory before acknowledging.
    /// The store supplies random ids and supervisor timestamps, never the guest.
    fn create(
        &self,
        scope: PrincipalScope,
        request: SessionCreate,
    ) -> ServiceFuture<'_, SessionSummary>;

    /// Return contiguous entries after the cursor, bounded by count and frame bytes.
    /// Historical provenance is retained as transcript data, never fresh instruction.
    fn open(&self, scope: PrincipalScope, request: SessionOpen)
        -> ServiceFuture<'_, SessionOpened>;

    /// Return only this principal's summaries with a stable, bounded page cursor.
    fn list(&self, scope: PrincipalScope, request: SessionList) -> ServiceFuture<'_, SessionPage>;

    /// Compare expected_sequence atomically; entry sequence must be exactly one higher.
    /// Origin is supplied from authenticated ingress independently of entry labels.
    /// Guest ingress supplies Auma only; Owner requires live authenticated host ingress.
    /// Refuse incorrect version, algorithm, commitment, id, sequence or role/provenance.
    /// Refuse without a partial append when a bound or expected sequence fails.
    fn append(
        &self,
        scope: PrincipalScope,
        origin: Provenance,
        request: SessionAppend,
    ) -> ServiceFuture<'_, SessionAppended>;

    /// Sync the persisted prefix before acknowledging; through_sequence may never
    /// exceed the stored sequence. The returned commitment covers exact stored bytes.
    fn flush(
        &self,
        scope: PrincipalScope,
        request: SessionFlush,
    ) -> ServiceFuture<'_, SessionFlushed>;

    /// Under exclusive access, truncate only an incomplete terminal record and sync.
    /// Never repair or discard a complete malformed record or an earlier committed row.
    fn recover(
        &self,
        scope: PrincipalScope,
        session_id: SessionId,
    ) -> ServiceFuture<'_, TailRecovery>;

    /// Consult the stored cursor and flush its exact sequence before model dispatch.
    /// Only a receipt returned by this store can become the local dispatch barrier.
    fn before_dispatch(
        &self,
        scope: PrincipalScope,
        session_id: SessionId,
        sequence: u64,
    ) -> ServiceFuture<'_, DispatchFence>;
}

/// Row 130 disk-store body. No in-memory fallback is substituted for durability.
pub struct DurableSessions {
    config: SessionStoreConfig,
    disk: Mutex<disk::Disk>,
}

impl DurableSessions {
    /// Open a private host-owned root without following symlinks; take the store lock
    /// and recover incomplete tails before publishing any successful session reply.
    pub fn open(config: SessionStoreConfig) -> Result<Self> {
        let disk = disk::Disk::open(&config)?;
        Ok(Self {
            config,
            disk: Mutex::new(disk),
        })
    }

    pub const fn config(&self) -> &SessionStoreConfig {
        &self.config
    }
}

impl SessionStore for DurableSessions {
    fn create(
        &self,
        scope: PrincipalScope,
        request: SessionCreate,
    ) -> ServiceFuture<'_, SessionSummary> {
        Box::pin(async move { self.lock()?.create(scope, request, self.config.limits) })
    }

    fn open(
        &self,
        scope: PrincipalScope,
        request: SessionOpen,
    ) -> ServiceFuture<'_, SessionOpened> {
        Box::pin(async move {
            self.lock()?
                .open_session(scope, request, self.config.limits)
        })
    }

    fn list(&self, scope: PrincipalScope, request: SessionList) -> ServiceFuture<'_, SessionPage> {
        Box::pin(async move { self.lock()?.list(scope, request, self.config.limits) })
    }

    fn append(
        &self,
        scope: PrincipalScope,
        origin: Provenance,
        request: SessionAppend,
    ) -> ServiceFuture<'_, SessionAppended> {
        Box::pin(async move {
            self.lock()?
                .append(scope, origin, request, self.config.limits)
        })
    }

    fn flush(
        &self,
        scope: PrincipalScope,
        request: SessionFlush,
    ) -> ServiceFuture<'_, SessionFlushed> {
        Box::pin(async move { self.lock()?.flush(scope, request, self.config.limits) })
    }

    fn recover(
        &self,
        scope: PrincipalScope,
        session_id: SessionId,
    ) -> ServiceFuture<'_, TailRecovery> {
        Box::pin(async move { self.lock()?.recover(scope, session_id, self.config.limits) })
    }

    fn before_dispatch(
        &self,
        scope: PrincipalScope,
        session_id: SessionId,
        sequence: u64,
    ) -> ServiceFuture<'_, DispatchFence> {
        Box::pin(async move {
            let receipt =
                self.lock()?
                    .before_dispatch(scope, session_id, sequence, self.config.limits)?;
            Ok(DispatchFence { scope, receipt })
        })
    }
}

impl DurableSessions {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, disk::Disk>> {
        self.disk.lock().map_err(|_| canon::codes::SUPERVISOR_STATE)
    }
}

/// SHA-256 of the canonical v2 entry object with only `commitment` omitted.
/// This checks the shared record schema; it does not establish ingress authority.
pub fn entry_commitment(entry: &canon::session::SessionEntry) -> Result<Digest32> {
    codec::entry_commitment(entry)
}
