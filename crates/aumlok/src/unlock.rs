// SPDX-License-Identifier: AGPL-3.0-or-later
//! Principal-scoped unlock contracts. No global bucket or caller-chosen subject key.

use canon::ids::{SessionId, SubjectId};
use canon::{Refusal, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlockPolicy {
    pub failure_threshold: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

pub const DEFAULT_POLICY: UnlockPolicy = UnlockPolicy {
    failure_threshold: 5,
    base_delay_ms: 60_000,
    max_delay_ms: 3_600_000,
};

/// Only resolve_principal may create this handle, after authenticated session lookup.
#[derive(Debug)]
pub struct UnlockPrincipal {
    subject: SubjectId,
    session: SessionId,
    epoch: u64,
}

impl UnlockPrincipal {
    pub fn subject(&self) -> SubjectId {
        self.subject
    }
    pub fn session(&self) -> SessionId {
        self.session
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrincipalState {
    pub subject: SubjectId,
    pub epoch: u64,
    pub failures: u64,
    pub locked_until_ms: i64,
    pub last_observed_ms: i64,
    pub revision: u64,
}

/// A host-side adapter, not an input from the browser. Implementations must bind
/// sessions to an authenticated principal and use durable per-principal CAS updates.
pub trait UnlockStore {
    fn session_principal(&mut self, session: &SessionId, now_ms: i64) -> Result<(SubjectId, u64)>;
    fn policy(&mut self) -> Result<UnlockPolicy>;
    fn load(&mut self, principal: &UnlockPrincipal) -> Result<PrincipalState>;
    fn compare_and_set(
        &mut self,
        principal: &UnlockPrincipal,
        expected: &PrincipalState,
        next: &PrincipalState,
    ) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockOutcome {
    Rejected,
    Recognized,
}

/// Admission is not an authorization, root possession proof or owner proof.
#[derive(Debug)]
pub struct UnlockAdmission {
    principal: UnlockPrincipal,
    state_revision: u64,
}

impl UnlockAdmission {
    pub fn principal(&self) -> &UnlockPrincipal {
        &self.principal
    }
    pub fn state_revision(&self) -> u64 {
        self.state_revision
    }
}

/// Wave-1 lookup contract. Unknown/expired sessions must refuse before a limit row
/// is touched. This skeleton always refuses and therefore cannot mint a principal.
pub fn resolve_principal<S: UnlockStore + ?Sized>(
    _store: &mut S,
    _session: &SessionId,
    _now_ms: i64,
) -> Result<UnlockPrincipal> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}

/// Wave-1 admission contract: recheck session and epoch; persist last_seen using a
/// nondecreasing clock. A locked request cannot extend the lock. Currently refuses.
pub fn admit<S: UnlockStore + ?Sized>(
    _store: &mut S,
    _principal: UnlockPrincipal,
    _now_ms: i64,
) -> Result<UnlockAdmission> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}

/// Wave-1 completion contract: CAS only this principal; rejected attempts add capped
/// exponential delay after the threshold, recognition never resets failure history.
/// Caller outcomes convey observations, never an owner approval. Currently refuses.
pub fn finish<S: UnlockStore + ?Sized>(
    _store: &mut S,
    _admission: UnlockAdmission,
    _outcome: UnlockOutcome,
    _now_ms: i64,
) -> Result<PrincipalState> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}
