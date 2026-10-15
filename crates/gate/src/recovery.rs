// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery observes consumed work. It cannot construct an effect permit.

use crate::{proposal::ProposalState, target::TargetObservation, Result};
use canon::{
    authority::{AuthorityVersion, BaseDigest},
    digest::Digest32,
    ids::ProposalId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    BeforeProposal,
    AfterProposal,
    BeforeReview,
    AfterReview,
    AfterProof,
    AfterCounter,
    AfterConsumption,
    AfterAppend,
    BeforeCommit,
    AfterCommit,
    BeforeEffect,
    AfterEffect,
    BeforeTerminal,
    AfterTerminal,
    BeforeRetire,
    AfterRetire,
    BeforeRecovery,
    AfterRecovery,
    BeforeReconcile,
    AfterReconcile,
    BeforeExpire,
    AfterExpire,
    BeforeDecline,
    AfterDecline,
    BeforeRevoke,
    AfterRevoke,
}

pub const CRASH_POINTS: [CrashPoint; 26] = [
    CrashPoint::BeforeProposal,
    CrashPoint::AfterProposal,
    CrashPoint::BeforeReview,
    CrashPoint::AfterReview,
    CrashPoint::AfterProof,
    CrashPoint::AfterCounter,
    CrashPoint::AfterConsumption,
    CrashPoint::AfterAppend,
    CrashPoint::BeforeCommit,
    CrashPoint::AfterCommit,
    CrashPoint::BeforeEffect,
    CrashPoint::AfterEffect,
    CrashPoint::BeforeTerminal,
    CrashPoint::AfterTerminal,
    CrashPoint::BeforeRetire,
    CrashPoint::AfterRetire,
    CrashPoint::BeforeRecovery,
    CrashPoint::AfterRecovery,
    CrashPoint::BeforeReconcile,
    CrashPoint::AfterReconcile,
    CrashPoint::BeforeExpire,
    CrashPoint::AfterExpire,
    CrashPoint::BeforeDecline,
    CrashPoint::AfterDecline,
    CrashPoint::BeforeRevoke,
    CrashPoint::AfterRevoke,
];

pub trait CrashInjector {
    fn at(&mut self, point: CrashPoint) -> Result<()>;
}

#[derive(Default)]
pub struct NoInjection;

impl CrashInjector for NoInjection {
    fn at(&mut self, _point: CrashPoint) -> Result<()> {
        Ok(())
    }
}

pub struct RefuseAt(pub CrashPoint);

impl CrashInjector for RefuseAt {
    fn at(&mut self, point: CrashPoint) -> Result<()> {
        if point == self.0 {
            Err(crate::refuse("crash-injected"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryItem {
    pub proposal: ProposalId,
    pub consumed_approval: Digest32,
    pub consumption: AuthorityVersion,
    pub expected_base: BaseDigest,
    pub expected_new_digest: Digest32,
    pub observed: TargetObservation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryResult {
    pub proposal: ProposalId,
    pub state: ProposalState,
    pub terminal: AuthorityVersion,
    pub target_released: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoverySweep {
    pub settled: Vec<RecoveryResult>,
    pub blocked: Vec<(ProposalId, crate::Refusal)>,
}

pub fn classify_observation(item: &RecoveryItem) -> Result<ProposalState> {
    use sha2::{Digest, Sha256};

    if item.consumption.sequence == 0
        || item.consumption.sequence > canon::json::MAX_SAFE_INTEGER as u64
        || (item.consumption.sequence == 1) != item.consumption.previous_hash.is_none()
    {
        return Err(crate::refuse("recovery-context"));
    }
    match (&item.observed.digest, &item.observed.bytes) {
        (BaseDigest::Absent, Some(_)) => {
            return Err(crate::refuse("observation-digest"));
        }
        (BaseDigest::Present(_), None) => return Ok(ProposalState::Unknown),
        (BaseDigest::Present(expected), Some(bytes)) => {
            let actual = Digest32::from_bytes(Sha256::digest(bytes).into());
            if actual != *expected {
                return Err(crate::refuse("observation-digest"));
            }
        }
        (BaseDigest::Absent, None) => {}
    }
    if item.observed.digest == BaseDigest::Present(item.expected_new_digest) {
        Ok(ProposalState::Incomplete)
    } else if item.observed.digest == item.expected_base {
        Ok(ProposalState::Failed)
    } else {
        Ok(ProposalState::Conflict)
    }
}
