// SPDX-License-Identifier: AGPL-3.0-or-later
//! A single gate worker retains the target writer lock and recovery state.

use super::HostLedger;
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    authority::{BaseDigest, OwnerAssertion, OwnerOperation},
    codes,
    fd3_payloads::{Accepted, Outcome, OutcomeState, Propose, Read, ReadReply},
    frame::FrameId,
    ids::ProposalId,
    Result,
};
use gate::{
    proposal::{ProposalRequest, SuggestionOrder},
    recovery::NoInjection,
    service::{Gate, GateConfig},
    target::{ConfinedStore, TargetId, TargetStore},
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

type Job = Box<dyn for<'a> FnOnce(&mut Gate<'a, ConfinedStore>) + Send>;
pub struct GateAdapter {
    sender: mpsc::SyncSender<Job>,
    ledger: Arc<HostLedger>,
}
impl GateAdapter {
    pub fn start(
        path: PathBuf,
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
                let opened = host.serialize_gate(|| {
                    let store = ConfinedStore::open(directory, config.targets.clone())?;
                    Gate::open(aura::Ledger::open(&path)?, store, config, host.services())
                });
                let mut gate = match opened {
                    Ok(gate) => {
                        if ready_send.send(Ok(())).is_err() {
                            return;
                        }
                        gate
                    }
                    Err(error) => {
                        let _ = ready_send.send(Err(error));
                        return;
                    }
                };
                while let Ok(job) = jobs.recv() {
                    job(&mut gate);
                }
            })
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        ready_recv
            .recv()
            .map_err(|_| codes::SUPERVISOR_NOT_READY)??;
        Ok(Self { sender, ledger })
    }
    pub fn observe_health(
        &self,
        context: gate::health::ObservationContext,
    ) -> ServiceFuture<'_, Vec<canon::health::HealthEvidence>> {
        let host = Arc::clone(&self.ledger);
        let (send, receive) = tokio::sync::oneshot::channel();
        let queued = self
            .sender
            .try_send(Box::new(move |gate| {
                let evidence = host.serialize_gate(|| {
                    Ok(gate::health::health(
                        gate::health::ObservationSources {
                            ledger: gate.ledger(),
                            configuration: gate.config(),
                            targets: gate.target_store(),
                        },
                        context,
                    ))
                });
                let _ = send.send(evidence);
            }))
            .map_err(|_| codes::SUPERVISOR_NOT_READY);
        Box::pin(async move {
            queued?;
            receive.await.map_err(|_| codes::SUPERVISOR_NOT_READY)?
        })
    }
    fn submit<T: Send + 'static>(
        &self,
        scope: PrincipalScope,
        operation: impl for<'a> FnOnce(
                &mut Gate<'a, ConfinedStore>,
                &mut super::ledger::GateLedger<'_>,
            ) -> Result<T>
            + Send
            + 'static,
    ) -> ServiceFuture<'_, T> {
        let host = Arc::clone(&self.ledger);
        let (send, receive) = tokio::sync::oneshot::channel();
        let job: Job = Box::new(move |gate| {
            let result = host.gate_scoped(scope, |ledger| operation(gate, ledger));
            let _ = send.send(result);
        });
        let queued = self
            .sender
            .try_send(job)
            .map_err(|_| codes::SUPERVISOR_NOT_READY);
        Box::pin(async move {
            queued?;
            receive.await.map_err(|_| codes::SUPERVISOR_NOT_READY)?
        })
    }
    fn refuse_unscoped_authority<T>(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
    ) -> Result<T> {
        match action {
            OwnerOperation::Apply | OwnerOperation::Retire => (),
            _ => return Err(codes::GATE_UNSUPPORTED_OPERATION),
        }
        self.ledger.scoped(scope, |txn| {
            require_proposal_scope(txn, proposal, scope)?;
            // Gate starts its own transaction; it cannot join this scope check.
            Err(codes::SUPERVISOR_GATE_SCOPE_UNAVAILABLE)
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
        self.submit(scope, move |gate, _| {
            let proposal = gate.propose(
                gate::target::sites::proposal_request(&request)?,
                &mut NoInjection,
            )?;
            if proposal.authority.epoch != scope.epoch {
                return Err(codes::AUMLOK_BINDING_REQUIRED);
            }
            Ok(Accepted {
                proposal_id: proposal.id,
            })
        })
    }
    fn propose<'a>(
        &'a self,
        scope: PrincipalScope,
        _: &'a FrameId,
        request: Propose,
    ) -> ServiceFuture<'a, Accepted> {
        self.submit(scope, move |gate, _| {
            let bytes = request.replacement_bytes()?;
            let proposal = gate.propose(
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
            if proposal.authority.epoch != scope.epoch {
                return Err(codes::AUMLOK_BINDING_REQUIRED);
            }
            Ok(Accepted {
                proposal_id: proposal.id,
            })
        })
    }
    fn read(&self, scope: PrincipalScope, request: Read) -> ServiceFuture<'_, ReadReply> {
        self.submit(scope, move |gate, ledger| {
            ledger.transaction(|_| {
                let observed = gate
                    .target_store()
                    .observe(&TargetId::new(request.target.clone())?)?;
                let bytes = observed.bytes.ok_or(codes::GATE_BLOB_MISSING)?;
                let digest = match observed.digest {
                    BaseDigest::Present(digest) => digest,
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
        Box::pin(async move {
            self.ledger.scoped(scope, |txn| {
                let stored = txn.proposal(&proposal)?;
                if stored.authority.epoch != scope.epoch {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                Ok(stored_outcome(proposal, stored.status))
            })
        })
    }
    fn review(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
    ) -> ServiceFuture<'_, OwnerReview> {
        Box::pin(async move { self.refuse_unscoped_authority(scope, proposal, action) })
    }
    fn owner_assertion(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
        _assertion: OwnerAssertion,
    ) -> ServiceFuture<'_, Outcome> {
        Box::pin(async move { self.refuse_unscoped_authority(scope, proposal, action) })
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
