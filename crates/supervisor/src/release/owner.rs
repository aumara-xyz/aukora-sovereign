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
    /// Successful immutable offers are verified once; failures are retried after a pause and logged once per path.
    verified: Arc<Mutex<Option<VerifiedOffer>>>,
    /// The pre-swap probe of each offered release: running, passed or failed (once per release; a failed release is
    /// probed again only after `PROBE_RETRY`, e.g. an approval landed while its state was copied).
    probes: Arc<Mutex<std::collections::HashMap<Digest32, (Probe, std::time::Instant)>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    Running,
    Passed,
    Failed,
}

const PROBE_RETRY: std::time::Duration = std::time::Duration::from_secs(600);

struct VerifiedOffer {
    path: PathBuf,
    digest: Option<Digest32>,
    checked: std::time::Instant,
}

impl VerifiedOffer {
    fn fresh_for(&self, path: &Path) -> bool {
        self.path == path && (self.digest.is_some() || self.checked.elapsed() < PROBE_RETRY)
    }
}

/// A probe still running is unknown, rather than evidence that root withdrew the offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Offer {
    Absent,
    Probing(Digest32),
    Ready(Digest32),
}

impl Offer {
    fn ready(self) -> Option<Digest32> {
        match self {
            Self::Ready(digest) => Some(digest),
            _ => None,
        }
    }

    fn retains(self, step: Step) -> bool {
        matches!((self, step), (Self::Probing(candidate), Step::Upgrade(target)) if candidate == target)
    }
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
            probes: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })?;
        Ok(())
    }
}

impl ReleaseApproval {
    /// The offered release, verified once per staged folder and offered to the owner only once its pre-swap probe
    /// passed (O20). A broken or partial offer, or one whose probe failed, is no offer (logged). A probe still running
    /// retains an existing card for those bytes but cannot raise or approve a card.
    fn offered(&self) -> Offer {
        let Some((path, digest)) = self.verified_offer() else {
            return Offer::Absent;
        };
        if digest == self.installed {
            return Offer::Ready(digest);
        }
        match self.probed(&path, digest) {
            Probe::Passed => Offer::Ready(digest),
            Probe::Running => Offer::Probing(digest),
            Probe::Failed => Offer::Absent,
        }
    }

    fn verified_offer(&self) -> Option<(PathBuf, Digest32)> {
        self.verified_offer_with(verify_candidate)
    }

    fn verified_offer_with(
        &self,
        verify: impl FnOnce(&Path) -> Result<Option<(PathBuf, Digest32)>>,
    ) -> Option<(PathBuf, Digest32)> {
        let resolved = std::fs::canonicalize(&self.offered).ok()?;
        let mut cache = self.verified.lock().ok()?;
        if let Some(prior) = cache.as_ref() {
            if prior.fresh_for(&resolved) {
                return prior.digest.map(|digest| (prior.path.clone(), digest));
            }
        }
        match verify(&self.offered) {
            Ok(Some((path, digest))) => {
                *cache = Some(VerifiedOffer {
                    path: path.clone(),
                    digest: Some(digest),
                    checked: std::time::Instant::now(),
                });
                Some((path, digest))
            }
            Ok(None) => None,
            Err(refusal) => {
                if !cache
                    .as_ref()
                    .is_some_and(|prior| prior.path == resolved && prior.digest.is_none())
                {
                    eprintln!(
                        "release: the offered release is refused: {}:{}",
                        refusal.organ, refusal.reason
                    );
                }
                *cache = Some(VerifiedOffer {
                    path: resolved,
                    digest: None,
                    checked: std::time::Instant::now(),
                });
                None
            }
        }
    }

    /// Whether the offered release passed its probe; starts the probe (in the background) when it has not run.
    fn probed(&self, candidate: &Path, digest: Digest32) -> Probe {
        let Ok(mut probes) = self.probes.lock() else {
            return Probe::Failed;
        };
        match probes.get(&digest) {
            Some((Probe::Passed, _)) => return Probe::Passed,
            Some((Probe::Running, _)) => return Probe::Running,
            Some((Probe::Failed, at)) if at.elapsed() < PROBE_RETRY => return Probe::Failed,
            _ => {}
        }
        probes.insert(digest, (Probe::Running, std::time::Instant::now()));
        eprintln!("release: probing the offered release {digest} in its own sandbox, on a copy of this node's state");
        let (candidate, shared) = (candidate.to_path_buf(), self.probes.clone());
        let started = std::thread::Builder::new().name("release-probe".into()).spawn(move || {
            let outcome = super::probe::run(&candidate, digest);
            let state = match &outcome {
                Ok(()) => {
                    eprintln!("release: the offered release {digest} started on a copy of the state; its card can go up");
                    Probe::Passed
                }
                Err(refusal) => {
                    eprintln!(
                        "release: the offered release {digest} did not start on a copy of the state ({}:{}); no card",
                        refusal.organ, refusal.reason
                    );
                    Probe::Failed
                }
            };
            if let Ok(mut probes) = shared.lock() {
                probes.insert(digest, (state, std::time::Instant::now()));
            }
        });
        if started.is_err() {
            probes.insert(digest, (Probe::Failed, std::time::Instant::now()));
            return Probe::Failed;
        }
        Probe::Running
    }

    pub(crate) fn ensure_proposal(&self, host: &HostLedger, scope: PrincipalScope) -> Result<()> {
        let mut floor = floor::service::FloorService::open(&self.floor_directory)?;
        let offered = self.offered();
        host.scoped(scope, |txn| {
            floor.reconcile(txn)?;
            floor.probe_release_guard(txn)?;
            let state = floor.snapshot()?;
            let step = wanted_step(state.floor.digest, state.is_install_genesis(), self.installed, offered.ready())?;
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
                if let Ok(target) = release_target(&proposal) {
                    let retained = Step::Upgrade(target);
                    if offered.retains(retained) && self.check_proposal(txn, scope, &proposal, retained).is_ok() {
                        return Ok(());
                    }
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
            let step = wanted_step(state.floor.digest, state.is_install_genesis(), self.installed, offered.ready())?
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
            if wanted_step(state.floor.digest, state.is_install_genesis(), self.installed, offered.ready())? != Some(step) {
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

    #[test]
    fn a_running_probe_retains_only_its_existing_upgrade_card_without_allowing_approval() {
        let (installed, candidate, other) = (digest(1), digest(2), digest(3));
        let offer = Offer::Probing(candidate);
        assert_eq!(
            wanted_step(installed, false, installed, offer.ready()).unwrap(),
            None,
            "no new card or approval before the probe passes"
        );
        assert!(
            offer.retains(Step::Upgrade(candidate)),
            "a restart's new probe does not withdraw the owner's card"
        );
        assert!(!offer.retains(Step::Upgrade(other)) && !offer.retains(Step::Genesis));
        assert!(
            !Offer::Absent.retains(Step::Upgrade(candidate)),
            "a withdrawn or failed offer withdraws its card"
        );
        assert_eq!(
            wanted_step(installed, false, installed, Offer::Ready(candidate).ready()).unwrap(),
            Some(Step::Upgrade(candidate))
        );
    }
    #[test]
    fn a_broken_offer_is_not_verified_on_each_approvals_poll() {
        use std::os::unix::fs::symlink;
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!("release-offer-cache-{}", hex::encode(nonce)));
        std::fs::create_dir(&root).unwrap();
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let offered = root.join("offered");
        symlink(&first, &offered).unwrap();
        let approval = ReleaseApproval {
            installed: digest(1),
            floor_directory: root.join("floor"),
            node: NodeId::from_bytes([1; 16]),
            offered,
            verified: Arc::new(Mutex::new(None)),
            probes: Arc::new(Mutex::new(std::collections::HashMap::new())),
        };
        let attempts = std::cell::Cell::new(0);
        let refused = |_: &Path| {
            attempts.set(attempts.get() + 1);
            Err(refuse("release-manifest"))
        };
        for _ in 0..4 {
            assert_eq!(approval.verified_offer_with(refused), None);
        }
        assert_eq!(
            attempts.get(),
            1,
            "a broken immutable folder is held back between retries"
        );
        approval.verified.lock().unwrap().as_mut().unwrap().checked -= PROBE_RETRY;
        assert_eq!(approval.verified_offer_with(refused), None);
        assert_eq!(
            attempts.get(),
            2,
            "a failed offer may be checked again after the pause"
        );
        std::fs::remove_file(&approval.offered).unwrap();
        symlink(&second, &approval.offered).unwrap();
        assert_eq!(approval.verified_offer_with(refused), None);
        assert_eq!(
            attempts.get(),
            3,
            "a different offered folder is checked at once"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
