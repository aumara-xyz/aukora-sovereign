// SPDX-License-Identifier: AGPL-3.0-or-later
//! Principal-scoped unlock contracts. No global bucket or caller-chosen subject key.

use canon::alg::AlgorithmId;
use canon::health::{
    Cell, CheckSpec, HealthEvidence, HealthReason, OrganId, HEALTH_FORMAT_VERSION,
};
use canon::ids::{SessionId, SubjectId};
use canon::{Refusal, Result};

use crate::health::{HealthContext, UNLOCK_COUNTERS, UNLOCK_REFUSALS};

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

/// An admitted attempt must finish within five minutes of its persisted admission.
pub const ADMISSION_LEASE_MS: i64 = 300_000;

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
    /// Admission time while the revision is odd; otherwise the latest completion.
    pub last_observed_ms: i64,
    /// Initialize at zero. Even revisions are idle; odd revisions reserve one attempt.
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

/// Unknown or expired sessions refuse before any limit row is touched.
pub fn resolve_principal<S: UnlockStore + ?Sized>(
    store: &mut S,
    session: &SessionId,
    now_ms: i64,
) -> Result<UnlockPrincipal> {
    validate_time(now_ms)?;
    let (subject, epoch) = store.session_principal(session, now_ms)?;
    Ok(UnlockPrincipal {
        subject,
        session: *session,
        epoch,
    })
}

/// Reserve one attempt with an odd persisted revision and nondecreasing time.
/// Busy or locked requests perform no update. An abandoned lease counts once as
/// rejected and closes to an even revision; the caller must retry admission.
pub fn admit<S: UnlockStore + ?Sized>(
    store: &mut S,
    principal: UnlockPrincipal,
    now_ms: i64,
) -> Result<UnlockAdmission> {
    validate_time(now_ms)?;
    revalidate(store, &principal, now_ms)?;
    let policy = store.policy()?;
    validate_policy(policy)?;
    let previous = load_current(store, &principal)?;
    let observed_at = previous.last_observed_ms.max(now_ms);
    revalidate(store, &principal, observed_at)?;
    if observed_at < previous.locked_until_ms {
        return Err(refused("unlock-locked"));
    }
    if previous.revision % 2 == 1 {
        if !expired(previous, observed_at) {
            return Err(refused("unlock-busy"));
        }
        let closed = complete(previous, UnlockOutcome::Rejected, policy, observed_at)?;
        store.compare_and_set(&principal, &previous, &closed)?;
        return Err(refused("unlock-admission-expired"));
    }
    let next = advance(previous, observed_at)?;
    store.compare_and_set(&principal, &previous, &next)?;
    Ok(UnlockAdmission {
        principal,
        state_revision: next.revision,
    })
}

/// CAS only this principal; rejected attempts add capped
/// exponential delay after the threshold, recognition never resets failure history.
/// An expired lease closes as rejected even if the caller reports recognition.
/// Caller outcomes convey observations, never an owner approval.
pub fn finish<S: UnlockStore + ?Sized>(
    store: &mut S,
    admission: UnlockAdmission,
    outcome: UnlockOutcome,
    now_ms: i64,
) -> Result<PrincipalState> {
    validate_time(now_ms)?;
    let principal = &admission.principal;
    revalidate(store, principal, now_ms)?;
    let policy = store.policy()?;
    validate_policy(policy)?;
    let previous = load_current(store, principal)?;
    if previous.revision != admission.state_revision || previous.revision % 2 == 0 {
        return Err(refused("unlock-stale-admission"));
    }
    let observed_at = previous.last_observed_ms.max(now_ms);
    revalidate(store, principal, observed_at)?;
    if observed_at < previous.locked_until_ms {
        return Err(refused("unlock-locked"));
    }
    let timed_out = expired(previous, observed_at);
    let next = complete(
        previous,
        if timed_out {
            UnlockOutcome::Rejected
        } else {
            outcome
        },
        policy,
        observed_at,
    )?;
    store.compare_and_set(principal, &previous, &next)?;
    if timed_out {
        return Err(refused("unlock-admission-expired"));
    }
    Ok(next)
}

/// Read the current authenticated principal's persisted limit state without mutation.
/// The store exposes no refused-attempt history, so that check remains NotChecked.
pub fn observe_health<S: UnlockStore + ?Sized>(
    store: &mut S,
    session: &SessionId,
    context: HealthContext,
) -> [HealthEvidence; 2] {
    let observed = inspect_health(store, session, context);
    let (counter_cell, counter_reason) = match observed {
        Ok(()) => (Cell::Verified, HealthReason::Satisfied),
        Err(error) => match error.reason {
            "unlock-context" => (Cell::Failed, HealthReason::ContextMismatch),
            "unlock-observation-changed" => (Cell::Undetermined, HealthReason::NotChecked),
            "unlock-policy" | "unlock-state" | "unlock-principal" | "unlock-epoch" => {
                (Cell::Failed, HealthReason::InvariantFailed)
            }
            "unlock-time" => (Cell::Failed, HealthReason::InvalidEvidence),
            _ => (Cell::Undetermined, HealthReason::Unreachable),
        },
    };
    [
        health_report(context, UNLOCK_COUNTERS, counter_cell, counter_reason),
        health_report(
            context,
            UNLOCK_REFUSALS,
            Cell::Undetermined,
            HealthReason::NotChecked,
        ),
    ]
}

fn inspect_health<S: UnlockStore + ?Sized>(
    store: &mut S,
    session: &SessionId,
    context: HealthContext,
) -> Result<()> {
    let now_ms = i64::try_from(context.observed_at_ms).map_err(|_| refused("unlock-time"))?;
    let principal = resolve_principal(store, session, now_ms)?;
    if principal.epoch != context.epoch {
        return Err(refused("unlock-context"));
    }
    validate_policy(store.policy()?)?;
    let before = load_current(store, &principal)?;
    if before.last_observed_ms > now_ms {
        return Err(refused("unlock-context"));
    }
    revalidate(store, &principal, now_ms)?;
    let after = load_current(store, &principal)?;
    if before != after {
        return Err(refused("unlock-observation-changed"));
    }
    Ok(())
}

fn health_report(
    context: HealthContext,
    spec: CheckSpec,
    cell: Cell,
    reason: HealthReason,
) -> HealthEvidence {
    HealthEvidence {
        v: HEALTH_FORMAT_VERSION,
        algorithm: AlgorithmId::Sha256,
        check: spec.check,
        reporter: OrganId::Aumlok,
        epoch: context.epoch,
        sequence: context.sequence,
        observed_at_ms: context.observed_at_ms,
        expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
        cell,
        reason,
        commitment: context.commitment,
    }
}

fn revalidate<S: UnlockStore + ?Sized>(
    store: &mut S,
    principal: &UnlockPrincipal,
    now_ms: i64,
) -> Result<()> {
    let (subject, epoch) = store.session_principal(&principal.session, now_ms)?;
    if subject != principal.subject {
        return Err(refused("unlock-principal"));
    }
    if epoch != principal.epoch {
        return Err(refused("unlock-epoch"));
    }
    Ok(())
}

fn load_current<S: UnlockStore + ?Sized>(
    store: &mut S,
    principal: &UnlockPrincipal,
) -> Result<PrincipalState> {
    let state = store.load(principal)?;
    if state.subject != principal.subject {
        return Err(refused("unlock-principal"));
    }
    if state.epoch != principal.epoch {
        return Err(refused("unlock-epoch"));
    }
    if state.last_observed_ms < 0
        || state.locked_until_ms < 0
        || state.revision % 2 == 1 && state.locked_until_ms > state.last_observed_ms
    {
        return Err(refused("unlock-state"));
    }
    Ok(state)
}

fn validate_time(now_ms: i64) -> Result<()> {
    if now_ms < 0 {
        return Err(refused("unlock-time"));
    }
    Ok(())
}

fn validate_policy(policy: UnlockPolicy) -> Result<()> {
    if policy.failure_threshold == 0
        || policy.base_delay_ms == 0
        || policy.base_delay_ms > policy.max_delay_ms
        || policy.max_delay_ms > i64::MAX as u64
    {
        return Err(refused("unlock-policy"));
    }
    Ok(())
}

fn advance(previous: PrincipalState, observed_at: i64) -> Result<PrincipalState> {
    let revision = previous
        .revision
        .checked_add(1)
        .ok_or_else(|| refused("unlock-revision"))?;
    Ok(PrincipalState {
        last_observed_ms: observed_at,
        revision,
        ..previous
    })
}

fn expired(state: PrincipalState, observed_at: i64) -> bool {
    observed_at.saturating_sub(state.last_observed_ms) >= ADMISSION_LEASE_MS
}

fn complete(
    previous: PrincipalState,
    outcome: UnlockOutcome,
    policy: UnlockPolicy,
    observed_at: i64,
) -> Result<PrincipalState> {
    let mut next = advance(previous, observed_at)?;
    if outcome == UnlockOutcome::Rejected {
        next.failures = previous.failures.saturating_add(1);
        if next.failures >= u64::from(policy.failure_threshold) {
            let delay = delay_ms(policy, next.failures);
            next.locked_until_ms = observed_at
                .checked_add(delay as i64)
                .ok_or_else(|| refused("unlock-time"))?;
        }
    }
    Ok(next)
}

fn delay_ms(policy: UnlockPolicy, failures: u64) -> u64 {
    let exponent = failures.saturating_sub(u64::from(policy.failure_threshold));
    let multiplier = u32::try_from(exponent)
        .ok()
        .and_then(|shift| 1u64.checked_shl(shift));
    multiplier
        .and_then(|factor| policy.base_delay_ms.checked_mul(factor))
        .unwrap_or(policy.max_delay_ms)
        .min(policy.max_delay_ms)
}

fn refused(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}
