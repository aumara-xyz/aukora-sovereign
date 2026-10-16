// SPDX-License-Identifier: AGPL-3.0-or-later
//! The verified install supplies release proposals; only a Release proof advances its floor.

use super::*;
use canon::{alg::AlgorithmId, authority::BaseDigest, codes};
use gate::{
    proposal::ProposalState,
    recovery::NoInjection,
    service::{scoped::ScopedGate, GateConfig, Outcome},
    target::{EffectPermit, TargetId, TargetObservation, TargetStore},
};
use supervisor::ingress::PrincipalScope;

const MAX_PENDING: usize = 10_000;

#[derive(Clone)]
pub(crate) struct ReleaseApproval {
    installed: Digest32,
    floor_directory: PathBuf,
    node: NodeId,
}

impl ReleaseFiles {
    pub(crate) fn configure_owner_approval(&self, node: NodeId) -> Result<()> {
        self.ledger.configure_release_approval(ReleaseApproval {
            installed: self.release_digest,
            floor_directory: self.floor_directory.clone(),
            node,
        })?;
        Ok(())
    }
}

impl ReleaseApproval {
    pub(crate) fn ensure_proposal(&self, host: &HostLedger, scope: PrincipalScope) -> Result<()> {
        let mut floor = floor::service::FloorService::open(&self.floor_directory)?;
        host.scoped(scope, |txn| {
            floor.reconcile(txn)?;
            floor.probe_release_guard(txn)?;
            let state = floor.snapshot()?;
            if state.floor.digest != self.installed {
                return Err(refuse("release-not-approved"));
            }
            if !state.is_install_genesis() {
                return Ok(());
            }
            let mut gate = ScopedGate::new(
                NoReleaseTarget,
                GateConfig {
                    node: self.node,
                    targets: Vec::new(),
                    proposal_lifetime_ms: 300_000,
                    ceremony_lifetime_ms: 300_000,
                },
            )?;
            let pending = txn.pending_proposals(MAX_PENDING + 1)?;
            if pending.len() > MAX_PENDING {
                return Err(refuse("approval-limit"));
            }
            for stored in pending.into_iter().filter(|row| row.target == "release") {
                let proposal = gate::service::read_proposal(txn, stored.proposal)?;
                if proposal.authority.epoch != scope.epoch {
                    gate::service::scoped::validate_installed_release(txn, self.node, &proposal)?;
                    gate.reconcile(txn, proposal.id, &mut NoInjection)?;
                    continue;
                }
                self.check_proposal(txn, scope, &proposal)?;
                return Ok(());
            }
            gate.propose_release(txn, state.floor.digest, self.installed, &mut NoInjection)?;
            Ok(())
        })
    }

    pub(crate) fn approve(
        &self,
        host: &HostLedger,
        scope: PrincipalScope,
        proposal: ProposalId,
        assertion: OwnerAssertion,
    ) -> Result<Outcome> {
        let mut floor = floor::service::FloorService::open(&self.floor_directory)?;
        host.scoped(scope, |txn| floor.reconcile(txn))?;
        let receipt = host.scoped(scope, |txn| {
            floor.probe_release_guard(txn)?;
            let stored = gate::service::read_proposal(txn, proposal)?;
            self.check_proposal(txn, scope, &stored)?;
            let state = floor.snapshot()?;
            if state.floor.digest != self.installed {
                return Err(refuse("release-not-approved"));
            }
            let source = txn.record_at(stored.authority)?;
            let keys = txn.floor_signing_keys()?;
            let mut signers = keys
                .iter()
                .filter(|key| key.algorithm == AlgorithmId::Ed25519);
            let key = signers.next().ok_or(codes::SUPERVISOR_STATE)?;
            if signers.next().is_some() || key.bytes.len() != 32 {
                return Err(codes::SUPERVISOR_STATE);
            }
            let order = floor::ReleaseOrder {
                digest: self.installed,
                record: stored.new_digest,
                signer_epoch: scope.epoch,
                ledger_seq: source.authority.sequence,
                signer_key_sha256: Digest32::sha256(&key.bytes),
                ledger_hash: source.hash,
            };
            if !state.is_install_genesis() {
                return floor.retry_installed(txn, proposal, assertion, &order, self.installed);
            }
            if stored.state != ProposalState::Pending {
                return Err(codes::GATE_NOT_PENDING);
            }
            let proof = VerifiedProof::verify(txn, &proposal, OwnerOperation::Release, assertion)?;
            floor.advance_installed(txn, proof, &order, self.installed)
        })?;
        host.scoped(scope, |txn| {
            let state = floor.reconcile(txn)?;
            floor.probe_release_guard(txn)?;
            if state.authority != receipt.authority || state.floor.digest != self.installed {
                return Err(refuse("release-not-approved"));
            }
            Ok(())
        })?;
        Ok(Outcome {
            proposal,
            state: ProposalState::Applied,
            receipt_hash: receipt.hash,
        })
    }

    fn check_proposal(
        &self,
        txn: &aura::LedgerTxn<'_>,
        scope: PrincipalScope,
        proposal: &gate::Proposal,
    ) -> Result<()> {
        let pointer = Value::object(vec![
            ("digest".into(), Value::text(self.installed.to_string())?),
            ("v".into(), Value::integer(json::SafeInteger::new(1)?)),
        ])?
        .canonical_bytes();
        let origin = txn.record_at(proposal.authority)?;
        let stored = txn.proposal(&proposal.id)?;
        gate::service::scoped::validate_installed_release(txn, self.node, proposal)?;
        if proposal.authority.epoch != scope.epoch
            || proposal.request.target.as_str() != "release"
            || proposal.request.base != BaseDigest::Present(self.installed)
            || proposal.request.new_bytes != pointer
            || proposal.new_digest != Digest32::sha256(&pointer)
            || proposal.risk != gate::RiskTier::Critical
            || proposal.request.cell.is_some()
            || proposal.request.new_evidence.is_some()
            || !proposal.request.model_note.is_empty()
            || origin.actor != "supervisor"
            || stored.actor != "supervisor"
        {
            return Err(refuse("release-not-approved"));
        }
        Ok(())
    }
}

struct NoReleaseTarget;

impl TargetStore for NoReleaseTarget {
    fn observe(&self, _: &TargetId) -> Result<TargetObservation> {
        Err(codes::GATE_UNSUPPORTED_OPERATION)
    }

    fn replace_once(&mut self, _: EffectPermit) -> Result<TargetObservation> {
        Err(codes::GATE_UNSUPPORTED_OPERATION)
    }
}
