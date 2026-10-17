// SPDX-License-Identifier: AGPL-3.0-or-later
//! One target writer executes gate transitions on the host's scoped ledger.

use super::HostLedger;
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    authority::{AuthorityTxn, BaseDigest, OwnerAssertion, OwnerOperation},
    codes,
    fd3_payloads::{Accepted, Outcome, OutcomeState, Propose, Read, ReadReply},
    frame::FrameId,
    ids::ProposalId,
    Result,
};
use gate::{
    proposal::{ProposalRequest, SuggestionOrder},
    recovery::NoInjection,
    service::{scoped::ScopedGate, GateConfig},
    target::{ConfinedStore, TargetId, TargetSpec, TargetStore},
};
use std::{
    fs::File,
    path::PathBuf,
    sync::{mpsc, Arc},
};
use supervisor::{
    ingress::PrincipalScope,
    services::{GateService, OwnerReview, ServiceFuture},
};

type Job = Box<dyn FnOnce(&mut Worker) + Send>;

struct Worker {
    directory: File,
    config: GateConfig,
    gate: Option<ScopedGate<ConfinedStore>>,
    ledger: Arc<HostLedger>,
}

impl Worker {
    fn configure(&mut self, targets: Vec<TargetSpec>) -> Result<()> {
        if self.gate.is_some() {
            return Err(codes::SUPERVISOR_STATE);
        }
        let mut config = self.config.clone();
        config.targets = targets;
        let directory = self
            .directory
            .try_clone()
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        let store = ConfinedStore::open(directory, config.targets.clone())?;
        let mut gate = ScopedGate::new(store, config)?;
        self.ledger.transaction(|txn| {
            let sweep = gate.recover(txn, &mut NoInjection)?;
            if !sweep.blocked.is_empty() {
                return Err(codes::GATE_RECOVERY_BLOCKED);
            }
            Ok(())
        })?;
        self.gate = Some(gate);
        Ok(())
    }

    fn gate(&mut self) -> Result<&mut ScopedGate<ConfinedStore>> {
        self.gate.as_mut().ok_or(codes::SUPERVISOR_NOT_READY)
    }
}

pub struct GateAdapter {
    sender: mpsc::SyncSender<Job>,
    ledger: Arc<HostLedger>,
}

impl GateAdapter {
    /// Uses only the supplied host ledger; the path argument retains startup compatibility.
    pub fn start(
        _: PathBuf,
        directory: File,
        config: GateConfig,
        ledger: Arc<HostLedger>,
    ) -> Result<Self> {
        let (sender, jobs) = mpsc::sync_channel::<Job>(64);
        let (ready_send, ready_recv) = mpsc::sync_channel(1);
        let host = Arc::clone(&ledger);
        std::thread::Builder::new()
            .name("sovereign-gate".into())
            .spawn(move || {
                let targets = config.targets.clone();
                let mut worker = Worker {
                    directory,
                    config,
                    gate: None,
                    ledger: host,
                };
                let ready = if targets.is_empty() {
                    Ok(())
                } else {
                    worker.configure(targets)
                };
                let failed = ready.is_err();
                if ready_send.send(ready).is_err() || failed {
                    return;
                }
                while let Ok(job) = jobs.recv() {
                    job(&mut worker);
                }
            })
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        ready_recv
            .recv()
            .map_err(|_| codes::SUPERVISOR_NOT_READY)??;
        Ok(Self { sender, ledger })
    }

    /// Empty startup configuration admits no jobs until the host supplies its targets.
    /// Configuration and the recovery sweep finish before owner or guest ingress starts.
    pub fn configure_targets(&self, targets: Vec<TargetSpec>) -> Result<()> {
        let (send, receive) = mpsc::sync_channel(1);
        self.sender
            .try_send(Box::new(move |worker| {
                let _ = send.send(worker.configure(targets));
            }))
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        receive.recv().map_err(|_| codes::SUPERVISOR_NOT_READY)?
    }

    pub fn observe_health(
        &self,
        context: gate::health::ObservationContext,
    ) -> ServiceFuture<'_, Vec<canon::health::HealthEvidence>> {
        self.submit(move |gate, host| {
            host.with_read_ledger(|ledger| {
                Ok(gate::health::health(
                    gate::health::ObservationSources {
                        ledger,
                        configuration: gate.config(),
                        targets: gate.target_store(),
                    },
                    context,
                ))
            })
        })
    }

    /// Open one owner-reviewed proposal for the door at `target` (`door/...`), against whatever the target holds now.
    /// Only the door reaches this; the guest's own `propose` refuses `door/` targets.
    pub fn propose_door(
        &self,
        scope: PrincipalScope,
        target: String,
        note: String,
        bytes: Vec<u8>,
    ) -> ServiceFuture<'_, ProposalId> {
        // Only an ask slot, and only a record the gate itself can read back (shape and call digest). The slider policy
        // and the standing grants are proposed by the owner path, not here.
        if !target.starts_with(gate::door::ASK_PREFIX) {
            return Box::pin(async { Err(codes::GATE_UNKNOWN_TARGET) });
        }
        if let Err(refusal) = gate::door::read(&bytes) {
            return Box::pin(async move { Err(refusal) });
        }
        self.propose_reserved(scope, target, note, bytes)
    }

    /// Open the owner's review of one build manifest (`gate::build`, target `build/manifest.json`). A manifest that is
    /// not exactly what `Manifest::to_bytes` writes never becomes a proposal. The guest cannot reach this either.
    pub fn propose_build(
        &self,
        scope: PrincipalScope,
        note: String,
        manifest: Vec<u8>,
    ) -> ServiceFuture<'_, ProposalId> {
        if let Err(refusal) = gate::build::Manifest::parse(&manifest) {
            return Box::pin(async move { Err(refusal) });
        }
        self.propose_reserved(scope, gate::build::TARGET.to_owned(), note, manifest)
    }

    /// The manifest the owner last approved: the bytes the gate's `build/manifest.json` target holds, which only an
    /// applied proposal can change. `None` before the first approval.
    pub fn approved_manifest(&self) -> ServiceFuture<'_, Option<Vec<u8>>> {
        self.submit(|gate, _| {
            let observed = gate.target_store().observe(&TargetId::new(gate::build::TARGET.to_owned())?)?;
            match (observed.digest, observed.bytes) {
                (BaseDigest::Absent, _) | (_, None) => Ok(None),
                (BaseDigest::Present(digest), Some(bytes)) if canon::digest::Digest32::sha256(&bytes) == digest => Ok(Some(bytes)),
                _ => Err(canon::Refusal { organ: "gate", reason: "observation-digest" }),
            }
        })
    }

    fn propose_reserved(
        &self,
        scope: PrincipalScope,
        target: String,
        note: String,
        bytes: Vec<u8>,
    ) -> ServiceFuture<'_, ProposalId> {
        self.submit(move |gate, host| {
            let target = TargetId::new(target)?;
            let base = gate.target_store().observe(&target)?.digest;
            host.scoped(scope, |txn| {
                gate.propose(
                    txn,
                    ProposalRequest {
                        target,
                        base,
                        new_bytes: bytes,
                        model_note: note,
                        cell: None,
                        new_evidence: None,
                        suggestion: SuggestionOrder::Single,
                    },
                    &mut NoInjection,
                )
                .map(|proposal| proposal.id)
            })
        })
    }

    /// Settle expired proposals now. The gate expires a pending proposal only inside `recover`, which otherwise runs
    /// once at start-up, and a target holds at most one live proposal; without this an unanswered ask keeps its
    /// target busy until the node restarts. Returns how many proposals recovery could not settle.
    pub fn sweep_expired(&self) -> ServiceFuture<'_, usize> {
        self.submit(|gate, host| {
            host.transaction(|txn| Ok(gate.recover(txn, &mut NoInjection)?.blocked.len()))
        })
    }

    fn submit<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut ScopedGate<ConfinedStore>, &HostLedger) -> Result<T>
            + Send
            + 'static,
    ) -> ServiceFuture<'_, T> {
        let host = Arc::clone(&self.ledger);
        let (send, receive) = tokio::sync::oneshot::channel();
        let queued = self
            .sender
            .try_send(Box::new(move |worker| {
                let result = worker.gate().and_then(|gate| operation(gate, &host));
                let _ = send.send(result);
            }))
            .map_err(|_| codes::SUPERVISOR_NOT_READY);
        Box::pin(async move {
            queued?;
            receive.await.map_err(|_| codes::SUPERVISOR_NOT_READY)?
        })
    }
}

impl GateService for GateAdapter {
    fn propose_site<'a>(
        &'a self,
        scope: PrincipalScope,
        _: &'a FrameId,
        request: canon::fd3_payloads::sites::SiteProposal,
    ) -> ServiceFuture<'a, Accepted> {
        self.submit(move |gate, host| {
            host.scoped(scope, |txn| {
                let proposal = gate.propose(
                    txn,
                    gate::target::sites::proposal_request(&request)?,
                    &mut NoInjection,
                )?;
                Ok(Accepted {
                    proposal_id: proposal.id,
                })
            })
        })
    }

    fn propose<'a>(
        &'a self,
        scope: PrincipalScope,
        _: &'a FrameId,
        request: Propose,
    ) -> ServiceFuture<'a, Accepted> {
        if request.target.starts_with(gate::door::TARGET_PREFIX) || request.target.starts_with(gate::build::TARGET_PREFIX) {
            return Box::pin(async { Err(codes::GATE_UNKNOWN_TARGET) });
        }
        self.submit(move |gate, host| {
            let bytes = request.replacement_bytes()?;
            host.scoped(scope, |txn| {
                let proposal = gate.propose(
                    txn,
                    ProposalRequest {
                        target: TargetId::new(request.target)?,
                        base: BaseDigest::Present(request.base_sha256),
                        new_bytes: bytes,
                        model_note: request.note,
                        cell: request.cell,
                        new_evidence: None,
                        suggestion: SuggestionOrder::Single,
                    },
                    &mut NoInjection,
                )?;
                Ok(Accepted {
                    proposal_id: proposal.id,
                })
            })
        })
    }

    fn read(&self, scope: PrincipalScope, request: Read) -> ServiceFuture<'_, ReadReply> {
        self.submit(move |gate, host| {
            host.scoped(scope, |_| {
                let observed = gate
                    .target_store()
                    .observe(&TargetId::new(request.target.clone())?)?;
                let bytes = observed.bytes.ok_or(codes::GATE_BLOB_MISSING)?;
                let digest = match observed.digest {
                    BaseDigest::Present(digest)
                        if canon::digest::Digest32::sha256(&bytes) == digest =>
                    {
                        digest
                    }
                    BaseDigest::Present(_) => {
                        return Err(canon::Refusal {
                            organ: "gate",
                            reason: "observation-digest",
                        })
                    }
                    BaseDigest::Absent => return Err(codes::GATE_BLOB_MISSING),
                };
                Ok(ReadReply {
                    target: request.target,
                    sha256: digest,
                    bytes_b64: STANDARD.encode(bytes),
                })
            })
        })
    }

    fn outcome(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
    ) -> ServiceFuture<'_, Option<Outcome>> {
        self.submit(move |_, host| {
            host.scoped(scope, |txn| {
                require_proposal_scope(txn, proposal, scope)?;
                Ok(stored_outcome(proposal, txn.proposal(&proposal)?.status))
            })
        })
    }

    fn review(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
    ) -> ServiceFuture<'_, OwnerReview> {
        self.submit(move |gate, host| {
            host.scoped(scope, |txn| {
                require_proposal_scope(txn, proposal, scope)?;
                let action = if action == OwnerOperation::Apply
                    && txn.proposal(&proposal)?.target == "release"
                {
                    OwnerOperation::Release
                } else {
                    action
                };
                let review = gate.review(txn, proposal, action, &mut NoInjection)?;
                let authorization = txn.rebuild_authorization(&proposal, action)?;
                if review.authorization_bytes != authorization.canonical_bytes()?
                    || review.card.digest() != authorization.display_sha256
                {
                    return Err(codes::SUPERVISOR_STATE);
                }
                Ok(OwnerReview {
                    proposal_id: proposal,
                    authorization,
                    authorization_bytes: review.authorization_bytes,
                    card_bytes: review.card.canonical_bytes().to_vec(),
                })
            })
        })
    }

    fn owner_assertion(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
        assertion: OwnerAssertion,
    ) -> ServiceFuture<'_, Outcome> {
        self.submit(move |gate, host| {
            let result = match action {
                OwnerOperation::Apply => {
                    let consumed = host.scoped(scope, |txn| {
                        require_proposal_scope(txn, proposal, scope)?;
                        gate.consume_apply(txn, proposal, assertion, &mut NoInjection)
                    })?;
                    host.scoped(scope, |txn| {
                        gate.effect_once(txn, consumed, &mut NoInjection)
                    })?
                }
                OwnerOperation::Retire => host.scoped(scope, |txn| {
                    require_proposal_scope(txn, proposal, scope)?;
                    gate.retire(txn, proposal, assertion, &mut NoInjection)
                })?,
                OwnerOperation::Release => {
                    host.approve_release(scope, proposal, assertion)?
                }
                _ => return Err(codes::GATE_UNSUPPORTED_OPERATION),
            };
            let state = match result.state {
                gate::proposal::ProposalState::Applied => OutcomeState::Applied,
                gate::proposal::ProposalState::Retired => OutcomeState::Retired,
                gate::proposal::ProposalState::Incomplete => OutcomeState::Incomplete,
                gate::proposal::ProposalState::Failed => OutcomeState::Failed,
                gate::proposal::ProposalState::Conflict => OutcomeState::Conflict,
                gate::proposal::ProposalState::Unknown => OutcomeState::Unknown,
                _ => return Err(codes::SUPERVISOR_STATE),
            };
            Ok(Outcome {
                proposal_id: result.proposal,
                state,
            })
        })
    }
}

fn require_proposal_scope(
    txn: &aura::LedgerTxn<'_>,
    proposal: ProposalId,
    scope: PrincipalScope,
) -> Result<()> {
    if txn.proposal(&proposal)?.authority.epoch != scope.epoch {
        return Err(codes::AUMLOK_BINDING_REQUIRED);
    }
    Ok(())
}

fn stored_outcome(
    proposal_id: ProposalId,
    status: aura::storage::ProposalStatus,
) -> Option<Outcome> {
    use aura::storage::ProposalStatus as S;
    let state = match status {
        S::Pending | S::Consumed => return None,
        S::Applied => OutcomeState::Applied,
        S::Refused => OutcomeState::Refused,
        S::Expired => OutcomeState::Expired,
        S::Retired => OutcomeState::Retired,
        S::Incomplete => OutcomeState::Incomplete,
        S::Failed => OutcomeState::Failed,
        S::Conflict => OutcomeState::Conflict,
        S::Unknown => OutcomeState::Unknown,
    };
    Some(Outcome { proposal_id, state })
}
