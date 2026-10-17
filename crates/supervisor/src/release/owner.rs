// SPDX-License-Identifier: AGPL-3.0-or-later
//! The verified install supplies release proposals; only a Release proof advances its floor.
//!
//! Two proposals exist (NODE.md section 8, O17). The install's own starting floor asks the owner to approve the
//! running release (genesis). Once the owner's floor names the running release, an UPGRADE is the release the operator
//! offered (`/opt/aukora/offered`, a root-made link to a staged, verified release): the running, approved release
//! raises the card from its floor to the offered one and keeps serving (UI and engine) until the owner approves it.
//! Approval advances the floor in one Aura transaction; the supervisor then exits so systemd restarts it, and the root
//! pre-start step (`node_release.py follow`) moves the current-release link to the release the floor now names. A
//! declined, withdrawn or never-answered card changes nothing: the current release keeps running.

use super::*;
use canon::{alg::AlgorithmId, authority::BaseDigest, codes};
use gate::{
    proposal::ProposalState,
    recovery::NoInjection,
    service::{scoped::ScopedGate, GateConfig, Outcome},
    target::{EffectPermit, TargetId, TargetObservation, TargetStore},
};
use std::sync::Mutex;
use supervisor::ingress::PrincipalScope;

const MAX_PENDING: usize = 10_000;
/// The supervisor's exit status after an approved upgrade: not 0, so `Restart=on-failure` starts it again on the new
/// release; distinct, so the journal says why.
pub(crate) const SWITCH_EXIT: i32 = 75;

#[derive(Clone)]
pub(crate) struct ReleaseApproval {
    installed: Digest32,
    floor_directory: PathBuf,
    node: NodeId,
    /// `/opt/aukora/offered`: beside the current-release link.
    offered: PathBuf,
    /// The last verified offer (its resolved, immutable release folder and digest): a staged release never changes, so
    /// the approvals poll does not hash it again.
    verified: Arc<Mutex<Option<(PathBuf, Digest32)>>>,
}

/// What the release card is for, once the floor names `base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Approve the running release over the install's starting floor.
    Genesis,
    /// Move from the running, approved release to the offered one.
    Upgrade(Digest32),
}

/// Which card the running release should have up (pure, NODE.md O17). `None`: no card.
pub(crate) fn wanted_step(
    floor: Digest32,
    genesis: bool,
    installed: Digest32,
    offered: Option<Digest32>,
) -> Result<Option<Step>> {
    if floor != installed {
        // This run is not the approved release: it raises nothing (it does not serve either).
        return Err(refuse("release-not-approved"));
    }
    if genesis {
        return Ok(Some(Step::Genesis));
    }
    Ok(offered
        .filter(|candidate| *candidate != installed)
        .map(Step::Upgrade))
}

impl Step {
    fn target(self, installed: Digest32) -> Digest32 {
        match self {
            Self::Genesis => installed,
            Self::Upgrade(candidate) => candidate,
        }
    }
}

impl ReleaseFiles {
    /// `current`: the current-release link; an upgrade the operator offers is the link beside it (`offered`,
    /// written by `node_release.py offer`).
    pub(crate) fn configure_owner_approval(&self, node: NodeId, current: &Path) -> Result<()> {
        let offered = current.parent().map(|root| root.join("offered")).ok_or(codes::SUPERVISOR_STATE)?;
        self.ledger.configure_release_approval(ReleaseApproval {
            installed: self.release_digest,
            floor_directory: self.floor_directory.clone(),
            node,
            offered,
            verified: Arc::new(Mutex::new(None)),
        })?;
        Ok(())
    }
}

impl ReleaseApproval {
    /// The offered release, verified once per staged folder. A broken or partial offer is no offer (logged).
    fn offered(&self) -> Option<Digest32> {
        let resolved = std::fs::canonicalize(&self.offered).ok()?;
        let mut cache = self.verified.lock().ok()?;
        if let Some((path, digest)) = cache.as_ref() {
            if *path == resolved {
                return Some(*digest);
            }
        }
        match verify_candidate(&self.offered) {
            Ok(Some((path, digest))) => {
                *cache = Some((path, digest));
                Some(digest)
            }
            Ok(None) => None,
            Err(refusal) => {
                eprintln!("release: the offered release is refused: {}:{}", refusal.organ, refusal.reason);
                None
            }
        }
    }

    pub(crate) fn ensure_proposal(&self, host: &HostLedger, scope: PrincipalScope) -> Result<()> {
        let mut floor = floor::service::FloorService::open(&self.floor_directory)?;
        let offered = self.offered();
        host.scoped(scope, |txn| {
            floor.reconcile(txn)?;
            floor.probe_release_guard(txn)?;
            let state = floor.snapshot()?;
            let step = wanted_step(state.floor.digest, state.is_install_genesis(), self.installed, offered)?;
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
                if step.is_some_and(|step| self.check_proposal(txn, scope, &proposal, step).is_ok()) {
                    return Ok(());
                }
                // An upgrade card for a release that is no longer offered (or another one now is): withdrawn, which
                // is not the owner's decline.
                if !gate.withdraw_release(txn, proposal.id)? {
                    return Ok(());
                }
            }
            let Some(step) = step else { return Ok(()) };
            let target = step.target(self.installed);
            // The owner declined exactly this step: it stays declined until the owner asks again (NODE.md O19).
            let digest = gate::service::scoped::release_operation_digest(self.node, state.floor.digest, target)?;
            if txn.last_decline(digest)?.is_some() {
                return Ok(());
            }
            gate.propose_release(txn, state.floor.digest, target, &mut NoInjection)?;
            Ok(())
        })
    }

    /// The owner asked again for a release step they declined: raised afresh when it is still the step this release
    /// would raise (the floor and the offer unchanged).
    pub(crate) fn again(&self, host: &HostLedger, scope: PrincipalScope, declined: ProposalId) -> Result<ProposalId> {
        let mut floor = floor::service::FloorService::open(&self.floor_directory)?;
        let offered = self.offered();
        host.scoped(scope, |txn| {
            floor.reconcile(txn)?;
            floor.probe_release_guard(txn)?;
            let state = floor.snapshot()?;
            let step = wanted_step(state.floor.digest, state.is_install_genesis(), self.installed, offered)?
                .ok_or(refuse("release-not-offered"))?;
            let old = gate::service::read_proposal(txn, declined)?;
            gate::service::scoped::validate_installed_release(txn, self.node, &old)?;
            let target = step.target(self.installed);
            if old.request.base != BaseDigest::Present(state.floor.digest)
                || old.request.new_bytes != pointer(target)?
            {
                return Err(refuse("release-not-offered"));
            }
            let mut gate = ScopedGate::new(
                NoReleaseTarget,
                GateConfig { node: self.node, targets: Vec::new(), proposal_lifetime_ms: 300_000, ceremony_lifetime_ms: 300_000 },
            )?;
            Ok(gate.propose_release(txn, state.floor.digest, target, &mut NoInjection)?.id)
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
        let offered = self.offered();
        host.scoped(scope, |txn| floor.reconcile(txn))?;
        let (receipt, target) = host.scoped(scope, |txn| {
            floor.probe_release_guard(txn)?;
            let stored = gate::service::read_proposal(txn, proposal)?;
            let state = floor.snapshot()?;
            let target = release_target(&stored)?;
            let step = if target == self.installed { Step::Genesis } else { Step::Upgrade(target) };
            self.check_proposal(txn, scope, &stored, step)?;
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
                digest: target,
                record: stored.new_digest,
                signer_epoch: scope.epoch,
                ledger_seq: source.authority.sequence,
                signer_key_sha256: Digest32::sha256(&key.bytes),
                ledger_hash: source.hash,
            };
            // Already advanced by this very approval (a retried request): its existing receipt.
            if state.floor.digest == target && !state.is_install_genesis() {
                return Ok((floor.retry_installed(txn, proposal, assertion, &order, target)?, target));
            }
            // The step must still be the one this running, approved release would raise.
            if wanted_step(state.floor.digest, state.is_install_genesis(), self.installed, offered)? != Some(step) {
                return Err(refuse("release-not-approved"));
            }
            if stored.state != ProposalState::Pending {
                return Err(codes::GATE_NOT_PENDING);
            }
            let proof = VerifiedProof::verify(txn, &proposal, OwnerOperation::Release, assertion)?;
            Ok((floor.advance_installed(txn, proof, &order, target)?, target))
        })?;
        host.scoped(scope, |txn| {
            let state = floor.reconcile(txn)?;
            floor.probe_release_guard(txn)?;
            if state.authority != receipt.authority || state.floor.digest != target {
                return Err(refuse("release-not-approved"));
            }
            Ok(())
        })?;
        if target != self.installed {
            switch_soon(target);
        }
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
        step: Step,
    ) -> Result<()> {
        let pointer = pointer(step.target(self.installed))?;
        let origin = txn.record_at(proposal.authority)?;
        let stored = txn.proposal(&proposal.id)?;
        gate::service::scoped::validate_installed_release(txn, self.node, proposal)?;
        // Both steps start from the running release: the genesis card from the install's floor (which names it), an
        // upgrade from the owner's floor (which names it too, or this run would not raise or approve anything).
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

fn pointer(digest: Digest32) -> Result<Vec<u8>> {
    Ok(Value::object(vec![
        ("digest".into(), Value::text(digest.to_string())?),
        ("v".into(), Value::integer(json::SafeInteger::new(1)?)),
    ])?
    .canonical_bytes())
}

/// The release a release proposal's pointer names.
fn release_target(proposal: &gate::Proposal) -> Result<Digest32> {
    let value = json::parse_strict(&proposal.request.new_bytes)?;
    Digest32::from_hex(text(&value, "digest")?).map_err(|_| refuse("release-not-approved"))
}

/// After an approved upgrade the floor names the new release, which this process is not: leave so systemd starts the
/// supervisor again and its root pre-start step switches the current-release link (`node_release.py follow`). The
/// reply to the owner's approval goes out first; the engine stops with this unit (`PartOf`, and its admission is
/// withdrawn at stop).
fn switch_soon(target: Digest32) {
    eprintln!("release: the owner approved release {target}; restarting to switch to it");
    let _ = std::thread::Builder::new()
        .name("release-switch".into())
        .spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            std::process::exit(SWITCH_EXIT);
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest32 {
        Digest32::from_bytes([n; 32])
    }

    #[test]
    fn the_running_release_raises_genesis_then_only_an_offered_different_release() {
        let (a, b) = (digest(1), digest(2));
        assert_eq!(wanted_step(a, true, a, None).unwrap(), Some(Step::Genesis));
        assert_eq!(wanted_step(a, true, a, Some(b)).unwrap(), Some(Step::Genesis), "genesis first, then upgrades");
        assert_eq!(wanted_step(a, false, a, None).unwrap(), None, "approved, nothing offered: no card");
        assert_eq!(wanted_step(a, false, a, Some(a)).unwrap(), None, "the running release offered again: no card");
        assert_eq!(wanted_step(a, false, a, Some(b)).unwrap(), Some(Step::Upgrade(b)));
        // A run that is not the floor's release raises nothing: the floor already moved on (switch pending), or this
        // binary was swapped in without the owner.
        assert!(wanted_step(b, false, a, Some(b)).is_err());
        assert!(wanted_step(b, true, a, None).is_err());
        assert_eq!(Step::Genesis.target(a), a);
        assert_eq!(Step::Upgrade(b).target(a), b);
    }

    #[test]
    fn the_pointer_is_the_gates_release_pointer() {
        let bytes = pointer(digest(9)).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!("{{\"digest\":\"{}\",\"v\":1}}", digest(9))
        );
    }
}
