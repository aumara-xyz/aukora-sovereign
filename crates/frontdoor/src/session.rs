// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable browser-session contracts. No cookie or bootstrap state authorizes an effect.

use crate::tls::Origin;
use canon::{
    digest::Digest32,
    ids::{NodeId, SubjectId},
    Result,
};

pub const OWNER_COOKIE: &str = "__Host-aukora-owner";
pub const SHELL_COOKIE: &str = "__Host-aukora-chat";
pub const COOKIE_ATTRIBUTES: &str = "Path=/; Secure; HttpOnly; SameSite=Strict";
pub const MAX_LIFETIME_MS: u64 = 86_400_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingState {
    Unclaimed,
    Claimed,
    Enrolled,
    Bound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionScope {
    BindingOnly,
    OwnerFrame,
    Shell,
}

/// Persist the digest, node, exact host, current epoch and revocation status, never the bearer.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub token_digest: Digest32,
    pub node: NodeId,
    pub origin: Origin,
    pub subject: Option<SubjectId>,
    pub owner_epoch: u64,
    pub scope: SessionScope,
    pub expires_at_ms: u64,
    pub revoked: bool,
}

/// The supervisor's durable store supplies transactions; volatile fallback is absent.
pub trait SessionStore {
    fn lookup(&mut self, digest: Digest32) -> Result<Option<SessionRecord>>;
    fn revoke(&mut self, digest: Digest32) -> Result<()>;
    /// Commit a shell session only while its durable parent remains live in the same transaction.
    fn derive_shell(&mut self, parent: Digest32, child: SessionRecord, now_ms: u64) -> Result<()>;
    /// Must hold the revocation/epoch guard through the admitted operation, not only lookup.
    fn with_live_session<T>(
        &mut self,
        digest: Digest32,
        now_ms: u64,
        operation: impl FnOnce(&SessionRecord) -> Result<T>,
    ) -> Result<T>;
}

/// A borrowed admission scope, created only while the live-session transaction is held.
pub struct BoundSession<'a> {
    record: &'a SessionRecord,
}

impl BoundSession<'_> {
    pub fn record(&self) -> &SessionRecord {
        self.record
    }
}

/// Contract: no binding-only admission, stale epoch, foreign node/host or expired bearer.
/// The callback cannot retain the admission scope beyond the live-session transaction.
pub fn with_bound_session<S: SessionStore, T>(
    _store: &mut S,
    _cookie: &[u8],
    _node: NodeId,
    _origin: &Origin,
    _now_ms: u64,
    _operation: impl for<'a> FnOnce(BoundSession<'a>) -> Result<T>,
) -> Result<T> {
    todo!("rows 22, 23")
}

#[derive(Clone, Debug)]
pub struct SessionFacts {
    pub durable_sessions: u64,
    pub binding_only_sessions: u64,
    pub revoked_sessions: u64,
    pub failed_durable_writes: u64,
}
