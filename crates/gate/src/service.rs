// SPDX-License-Identifier: AGPL-3.0-or-later
//! Single-ledger entry points; all pending wave-1 transitions refuse.

use crate::{
    card::DisplayedCard,
    proposal::{Proposal, ProposalRequest, ProposalState},
    recovery::{CrashInjector, RecoverySweep},
    target::{TargetSpec, TargetStore},
    Result,
};
use aura::{Ledger, TransactionServices};
use canon::{
    authority::{OwnerAssertion, OwnerOperation},
    digest::Digest32,
    ids::{NodeId, ProposalId},
};

#[derive(Clone, Debug)]
pub struct GateConfig {
    pub node: NodeId,
    pub targets: Vec<TargetSpec>,
    pub proposal_lifetime_ms: u64,
    pub ceremony_lifetime_ms: u64,
}

pub struct Gate<'a, S> {
    ledger: Ledger,
    targets: S,
    config: GateConfig,
    services: TransactionServices<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerReview {
    pub proposal: ProposalId,
    pub action: OwnerOperation,
    pub card: DisplayedCard,
    pub authorization_bytes: Vec<u8>,
    pub passkey_challenge: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub proposal: ProposalId,
    pub state: ProposalState,
    pub receipt_hash: Digest32,
}

impl<'a, S: TargetStore> Gate<'a, S> {
    pub fn open(
        _ledger: Ledger,
        _targets: S,
        _config: GateConfig,
        _services: TransactionServices<'a>,
    ) -> Result<Self> {
        crate::unavailable()
    }

    pub fn propose(
        &mut self,
        _request: ProposalRequest,
        _crash: &mut dyn CrashInjector,
    ) -> Result<Proposal> {
        crate::unavailable()
    }

    pub fn review(
        &mut self,
        _proposal: ProposalId,
        _action: OwnerOperation,
        _crash: &mut dyn CrashInjector,
    ) -> Result<OwnerReview> {
        crate::unavailable()
    }

    pub fn apply(
        &mut self,
        _proposal: ProposalId,
        _assertion: OwnerAssertion,
        _crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        crate::unavailable()
    }

    pub fn apply_standing(
        &mut self,
        _proposal: ProposalId,
        _permission: ProposalId,
        _permission_digest: Digest32,
        _crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        crate::unavailable()
    }

    pub fn retire(
        &mut self,
        _proposal: ProposalId,
        _assertion: OwnerAssertion,
        _crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        crate::unavailable()
    }

    pub fn expire(
        &mut self,
        _proposal: ProposalId,
        _crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        crate::unavailable()
    }

    pub fn decline(
        &mut self,
        _proposal: ProposalId,
        _crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        crate::unavailable()
    }

    pub fn revoke_standing(
        &mut self,
        _permission: ProposalId,
        _crash: &mut dyn CrashInjector,
    ) -> Result<()> {
        crate::unavailable()
    }

    pub fn recover(&mut self, _crash: &mut dyn CrashInjector) -> Result<RecoverySweep> {
        crate::unavailable()
    }

    pub fn reconcile(
        &mut self,
        _proposal: ProposalId,
        _crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        crate::unavailable()
    }

    pub fn config(&self) -> &GateConfig {
        &self.config
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn target_store(&self) -> &S {
        &self.targets
    }

    pub fn services(&self) -> &TransactionServices<'a> {
        &self.services
    }
}
