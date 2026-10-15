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

pub fn classify_observation(_item: &RecoveryItem) -> Result<ProposalState> {
    crate::unavailable()
}
