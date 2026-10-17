// SPDX-License-Identifier: AGPL-3.0-or-later
//! One target writer executes gate transitions on the host's scoped ledger.

use super::HostLedger;
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, BaseDigest, FactKind, FactRecord, OwnerAssertion, OwnerOperation},
    codes,
    fd3_payloads::{Accepted, Outcome, OutcomeState, Propose, Read, ReadReply},
    frame::FrameId,
    ids::ProposalId,
    Result,
};
use gate::{
    proposal::{EvidenceReference, ProposalRequest, SuggestionOrder},
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

    /// Open the owner's review of the engine's plugin set (`engine/plugin-set.json`): the exact canonical set bytes,
    /// names and digests, shown on the generic content card. Bytes `floor::plugins::PluginSet::parse` refuses never
    /// become a proposal. Only the supervisor's engine controller reaches this; the guest's `propose` refuses `engine/`.
    pub fn propose_plugin_set(&self, scope: PrincipalScope, note: String, set: Vec<u8>) -> ServiceFuture<'_, ProposalId> {
        if let Err(refusal) = floor::plugins::PluginSet::parse(&set) {
            return Box::pin(async move { Err(refusal) });
        }
        self.propose_reserved(scope, crate::engine_plugins::PLUGIN_SET_TARGET.to_owned(), note, set)
    }

    /// Open the owner's review of the engine's model key (`engine/model-key.json`, its SHA-256 only) or model budget
    /// (`engine/model-budget.json`). Bytes the broker would not read never become a proposal. Only the supervisor's
    /// model broker reaches this; the guest's `propose` refuses `engine/`.
    pub fn propose_model_target(
        &self,
        scope: PrincipalScope,
        target: &'static str,
        note: String,
        bytes: Vec<u8>,
    ) -> ServiceFuture<'_, ProposalId> {
        let valid = match target {
            crate::model_broker::KEY_TARGET => broker::engine_link::budget::KeyApproval::parse(&bytes).is_some(),
            crate::model_broker::BUDGET_TARGET => broker::engine_link::budget::Budget::parse(&bytes).is_ok(),
            _ => false,
        };
        if !valid {
            return Box::pin(async { Err(codes::GATE_UNKNOWN_TARGET) });
        }
        self.propose_reserved(scope, target.to_owned(), note, bytes)
    }

    /// The bytes an owner-approved target holds now, checked against the digest the gate observes for it. `None`
    /// before the first applied proposal (or when the target is not in this node's inventory).
    pub fn approved_target(&self, target: &'static str) -> ServiceFuture<'_, Option<Vec<u8>>> {
        self.submit(move |gate, _| {
            let id = TargetId::new(target.to_owned())?;
            let Ok(observed) = gate.target_store().observe(&id) else { return Ok(None) };
            match (observed.digest, observed.bytes) {
                (BaseDigest::Absent, _) | (_, None) => Ok(None),
                (BaseDigest::Present(digest), Some(bytes)) if canon::digest::Digest32::sha256(&bytes) == digest => Ok(Some(bytes)),
                _ => Err(canon::Refusal { organ: "gate", reason: "observation-digest" }),
            }
        })
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

    /// The owner's Decline of one card (NODE.md O19): a deliberate no, no passkey (it only narrows). Closing a card is
    /// not this; an unanswered card only expires, and an expiry is never a decline.
    pub fn decline(&self, scope: PrincipalScope, proposal: ProposalId) -> ServiceFuture<'_, Outcome> {
        self.submit(move |gate, host| {
            let outcome = host.scoped(scope, |txn| {
                require_proposal_scope(txn, proposal, scope)?;
                gate.decline(txn, proposal)
            })?;
            Ok(Outcome { proposal_id: outcome.proposal, state: OutcomeState::Refused })
        })
    }

    /// The owner asks again for something they declined (NODE.md O19): a fresh proposal of the same bytes, raised
    /// because the owner asked. Only the node's own requests (`engine/` targets and the release) can be asked for
    /// again, and only while the owner's Decline is the latest word on those bytes. Returns the new proposal.
    pub fn again(&self, scope: PrincipalScope, declined: ProposalId) -> ServiceFuture<'_, ProposalId> {
        self.submit(move |gate, host| {
            let target = host.scoped(scope, |txn| {
                let stored = txn.proposal(&declined)?;
                let digest = stored.operation_digest;
                // Declined, or ran out of time (held back for a day): either way the owner's latest word on the bytes.
                if txn.last_decline(digest)?.map(|row| row.proposal) != Some(declined)
                    && txn.last_expiry(digest)?.map(|(id, _)| id) != Some(declined)
                {
                    return Err(refuse("not-declined"));
                }
                Ok(stored.target)
            })?;
            if target == "release" {
                return host.release_again(scope, declined);
            }
            if !target.starts_with(crate::engine::TARGET_PREFIX) {
                return Err(codes::GATE_UNSUPPORTED_OPERATION);
            }
            let bytes = host.scoped(scope, |txn| Ok(txn.proposal(&declined)?.new_bytes))?;
            propose_again(gate, host, scope, declined, target, String::new(), bytes)
        })
    }

    /// A request the owner made themselves (the model key typed on the owner's page): proposed like any other, and if
    /// the owner declined these exact bytes before, typing them again is the owner asking again. A card already up for
    /// the same bytes is that card; a card up for other bytes is refused `awaiting-other-approval` (nothing replaced).
    pub fn propose_owner_requested(
        &self,
        scope: PrincipalScope,
        target: &'static str,
        note: String,
        bytes: Vec<u8>,
    ) -> ServiceFuture<'_, ProposalId> {
        self.submit(move |gate, host| {
            let pending = host.scoped(scope, |txn| {
                Ok(txn
                    .pending_proposals(10_001)?
                    .into_iter()
                    .find(|row| row.target == target)
                    .map(|row| (row.proposal, row.new_bytes)))
            })?;
            match pending {
                Some((id, held)) if held == bytes => return Ok(id),
                Some(_) => return Err(refuse("awaiting-other-approval")),
                None => {}
            }
            let first = propose_once(gate, host, scope, target.to_owned(), note.clone(), bytes.clone(), None);
            match first {
                Err(refusal)
                    if matches!(refusal.reason, "declined-unchanged" | "unchanged-decline" | "recently-expired") =>
                {
                    let declined = host.scoped(scope, |txn| {
                        let base = gate.target_store().observe(&TargetId::new(target.to_owned())?)?.digest;
                        let digest = proposal_digest(gate, target, base, &bytes)?;
                        match txn.last_decline(digest)? {
                            Some(row) => Ok(row.proposal),
                            None => txn.last_expiry(digest)?.map(|(id, _)| id).ok_or(refusal),
                        }
                    })?;
                    propose_again(gate, host, scope, declined, target.to_owned(), note, bytes)
                }
                other => other,
            }
        })
    }

    /// The owner's latest Declines among the node's own requests, for the "ask again" list.
    pub fn owner_declines(&self, scope: PrincipalScope) -> ServiceFuture<'_, Vec<(ProposalId, String)>> {
        self.submit(move |_, host| host.scoped(scope, |txn| txn.owner_declines(16)))
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

// `door/standing-grants.json`, proposed by the door's starter keeper (gate/standing.rs).
mod standing;

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
        if request.target.starts_with(gate::door::TARGET_PREFIX)
            || request.target.starts_with(gate::build::TARGET_PREFIX)
            || request.target.starts_with(crate::engine::TARGET_PREFIX)
        {
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

fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal { organ: "gate", reason }
}

fn request(target: TargetId, base: BaseDigest, note: String, bytes: Vec<u8>, evidence: Option<EvidenceReference>) -> ProposalRequest {
    ProposalRequest {
        target,
        base,
        new_bytes: bytes,
        model_note: note,
        cell: None,
        new_evidence: evidence,
        suggestion: SuggestionOrder::Single,
    }
}

fn proposal_digest(
    gate: &ScopedGate<ConfinedStore>,
    target: &str,
    base: BaseDigest,
    bytes: &[u8],
) -> Result<canon::ids::OperationDigest> {
    let probe = request(TargetId::new(target.to_owned())?, base, String::new(), bytes.to_vec(), None);
    gate::proposal::request_digest(gate.config().node, &probe)
}

/// One proposal against whatever the target holds now, in its own transaction (a refusal rolls it back).
fn propose_once(
    gate: &mut ScopedGate<ConfinedStore>,
    host: &HostLedger,
    scope: PrincipalScope,
    target: String,
    note: String,
    bytes: Vec<u8>,
    evidence: Option<EvidenceReference>,
) -> Result<ProposalId> {
    let target = TargetId::new(target)?;
    let base = gate.target_store().observe(&target)?.digest;
    host.scoped(scope, |txn| {
        gate.propose(txn, request(target, base, note, bytes, evidence), &mut NoInjection)
            .map(|proposal| proposal.id)
    })
}

/// The owner asked again for bytes they declined: an Aura fact records the request (`aukora-owner-again-v1`, naming
/// the declined proposal), and the fresh proposal carries that fact as its new evidence, which is what lets the gate
/// raise bytes the owner declined. Both commit together or not at all.
fn propose_again(
    gate: &mut ScopedGate<ConfinedStore>,
    host: &HostLedger,
    scope: PrincipalScope,
    declined: ProposalId,
    target: String,
    note: String,
    bytes: Vec<u8>,
) -> Result<ProposalId> {
    let target = TargetId::new(target)?;
    let base = gate.target_store().observe(&target)?.digest;
    host.scoped(scope, |txn| propose_again_in(txn, gate, declined, target, base, note, bytes))
}

pub(crate) fn propose_again_in<S: TargetStore>(
    txn: &mut aura::LedgerTxn<'_>,
    gate: &mut ScopedGate<S>,
    declined: ProposalId,
    target: TargetId,
    base: BaseDigest,
    note: String,
    bytes: Vec<u8>,
) -> Result<ProposalId> {
    let stored = txn.proposal(&declined)?;
    let context = txn.observation_context()?;
    let fact = txn.append_fact(FactRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: context.authority,
        at: context.at,
        kind: FactKind::BootFacts,
        actor: "supervisor".into(),
        body: canon::json::Value::object(vec![
            ("schema".into(), canon::json::Value::text(AGAIN_SCHEMA.to_owned())?),
            ("declined".into(), canon::json::Value::text(declined.to_string())?),
            ("operation".into(), canon::json::Value::text(stored.operation_digest.to_string())?),
            ("target".into(), canon::json::Value::text(target.as_str().to_owned())?),
        ])?,
    })?;
    let evidence = EvidenceReference { digest: fact.hash, source_record: fact.authority };
    gate.propose(txn, request(target, base, note, bytes, Some(evidence)), &mut NoInjection)
        .map(|proposal| proposal.id)
}

/// The Aura fact that records the owner asking again for something they declined.
pub const AGAIN_SCHEMA: &str = "aukora-owner-again-v1";

#[cfg(test)]
mod tests {
    //! NODE.md O19 against a real Aura ledger and the gate: closing a card (it expires) is not a decline; the owner's
    //! Decline is, until the owner asks again.
    use super::*;
    use canon::alg::{PublicKey, Signature, Signatures};
    use ed25519_dalek::{Signer, SigningKey};
    use gate::target::TargetClass;

    struct TestSigner(SigningKey);
    impl aura::RecordSigner for TestSigner {
        fn public_keys(&self) -> Result<Vec<PublicKey>> {
            Ok(vec![PublicKey { v: 1, algorithm: AlgorithmId::Ed25519, bytes: self.0.verifying_key().to_bytes().to_vec() }])
        }
        fn sign_entry_hash(&self, hash: canon::digest::Digest32) -> Result<Signatures> {
            Signatures::new(vec![Signature { v: 1, algorithm: AlgorithmId::Ed25519, bytes: self.0.sign(hash.as_bytes()).to_bytes().to_vec() }])
        }
    }

    const PLUGIN: &str = "engine/plugin-set.json";
    const ASK: &str = "door/ask-00.json";

    struct Rig {
        directory: std::path::PathBuf,
        ledger: HostLedger,
        gate: ScopedGate<ConfinedStore>,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn rig(name: &str, lifetime_ms: u64) -> Rig {
        let directory = std::env::temp_dir().join(format!("o19-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(directory.join("targets")).unwrap();
        let directory = std::fs::canonicalize(directory).unwrap();
        let ledger = HostLedger::open(
            &directory.join("aura.sqlite3"),
            Arc::new(TestSigner(SigningKey::from_bytes(&[5; 32]))),
            Arc::new(crate::adapters::HostClock),
        )
        .unwrap();
        let targets: Vec<TargetSpec> = [PLUGIN, ASK]
            .into_iter()
            .map(|id| TargetSpec {
                id: TargetId::new(id.to_owned()).unwrap(),
                class: TargetClass::Content,
                risk: gate::RiskTier::Critical,
                max_bytes: 65_536,
            })
            .collect();
        let store = ConfinedStore::open(File::open(directory.join("targets")).unwrap(), targets.clone()).unwrap();
        let gate = ScopedGate::new(
            store,
            GateConfig {
                node: canon::ids::NodeId::from_bytes([7; 16]),
                targets,
                proposal_lifetime_ms: lifetime_ms,
                ceremony_lifetime_ms: 300_000,
            },
        )
        .unwrap();
        Rig { directory, ledger, gate }
    }

    impl Rig {
        fn propose(&mut self, target: &str, bytes: &[u8]) -> Result<ProposalId> {
            let target = TargetId::new(target.to_owned())?;
            let base = self.gate.target_store().observe(&target)?.digest;
            let gate = &mut self.gate;
            self.ledger.transaction(|txn| {
                gate.propose(txn, request(target, base, String::new(), bytes.to_vec(), None), &mut NoInjection)
                    .map(|proposal| proposal.id)
            })
        }

        fn decline(&mut self, id: ProposalId) -> Result<gate::proposal::ProposalState> {
            let gate = &mut self.gate;
            self.ledger.transaction(|txn| gate.decline(txn, id).map(|outcome| outcome.state))
        }

        fn expire_all(&mut self) {
            std::thread::sleep(std::time::Duration::from_millis(self.gate.config().proposal_lifetime_ms + 20));
            let gate = &mut self.gate;
            let blocked = self.ledger.transaction(|txn| Ok(gate.recover(txn, &mut NoInjection)?.blocked.len())).unwrap();
            assert_eq!(blocked, 0);
        }

        fn status(&self, id: ProposalId) -> aura::storage::ProposalStatus {
            self.ledger.transaction(|txn| Ok(txn.proposal(&id)?.status)).unwrap()
        }

        fn declines(&self) -> Vec<(ProposalId, String)> {
            self.ledger.transaction(|txn| txn.owner_declines(16)).unwrap()
        }

        fn again(&mut self, declined: ProposalId, target: &str, bytes: &[u8]) -> Result<ProposalId> {
            let target = TargetId::new(target.to_owned())?;
            let base = self.gate.target_store().observe(&target)?.digest;
            let gate = &mut self.gate;
            self.ledger
                .transaction(|txn| propose_again_in(txn, gate, declined, target, base, String::new(), bytes.to_vec()))
        }
    }

    fn declined_refusal(result: Result<ProposalId>) -> bool {
        matches!(result, Err(refusal) if matches!(refusal.reason, "declined-unchanged" | "unchanged-decline"))
    }

    #[test]
    fn a_closed_card_that_ran_out_of_time_is_held_back_a_day_unless_the_owner_asks_again() {
        let mut rig = rig("expiry", 1);
        let set = br#"{"set":"a"}"#;
        let first = rig.propose(PLUGIN, set).unwrap();
        rig.expire_all();
        assert_eq!(rig.status(first), aura::storage::ProposalStatus::Expired);
        // Before O19 this was gate:declined-unchanged for ever. Now it is held back for a day (no nagging) and the
        // owner may ask again at once: it is listed with the declines.
        assert!(matches!(rig.propose(PLUGIN, set), Err(refusal) if refusal.reason == "recently-expired"));
        assert_eq!(rig.declines(), vec![(first, PLUGIN.to_owned())]);
        let second = rig.again(first, PLUGIN, set).unwrap();
        assert_ne!(first, second);
        assert_eq!(rig.status(second), aura::storage::ProposalStatus::Pending);
        assert!(rig.declines().is_empty());
        // Other bytes are not held back.
        rig.expire_all();
        rig.propose(PLUGIN, br#"{"set":"b"}"#).unwrap();
    }

    #[test]
    fn the_owners_decline_holds_until_the_owner_asks_again() {
        let mut rig = rig("decline", 600_000);
        let set = br#"{"set":"a"}"#;
        let first = rig.propose(PLUGIN, set).unwrap();
        assert_eq!(rig.decline(first).unwrap(), gate::proposal::ProposalState::Refused);
        assert_eq!(rig.status(first), aura::storage::ProposalStatus::Refused);
        // A second Decline answers the settled outcome; nothing new is written.
        assert_eq!(rig.decline(first).unwrap(), gate::proposal::ProposalState::Refused);
        // The node's own re-proposal of the same bytes is refused: the owner said no.
        assert!(declined_refusal(rig.propose(PLUGIN, set)));
        // Other bytes are another request.
        let other = rig.propose(PLUGIN, br#"{"set":"b"}"#).unwrap();
        rig.decline(other).unwrap();
        assert_eq!(rig.declines(), vec![(other, PLUGIN.to_owned())], "the newest request per target is listed");
        // Ask again for the first set: a fresh card for the same bytes, carrying the owner's request as evidence.
        let again = rig.again(first, PLUGIN, set).unwrap();
        assert_eq!(rig.status(again), aura::storage::ProposalStatus::Pending);
        let stored = rig.ledger.transaction(|txn| txn.proposal(&again)).unwrap();
        assert!(stored.evidence_source.is_some() && stored.new_bytes == set);
        assert!(rig.declines().is_empty(), "the request raised since hides the older no");
        // Declining the fresh card is a no again; asking again once more works again.
        rig.decline(again).unwrap();
        assert!(declined_refusal(rig.propose(PLUGIN, set)));
        assert_eq!(rig.declines(), vec![(again, PLUGIN.to_owned())]);
        let third = rig.again(again, PLUGIN, set).unwrap();
        assert_eq!(rig.status(third), aura::storage::ProposalStatus::Pending);
    }

    #[test]
    fn a_card_asked_for_again_that_then_runs_out_of_time_is_held_back_not_declined() {
        let mut rig = rig("again-expiry", 400);
        let set = br#"{"set":"a"}"#;
        let first = rig.propose(PLUGIN, set).unwrap();
        rig.decline(first).unwrap();
        rig.again(first, PLUGIN, set).unwrap();
        rig.expire_all();
        // The owner's latest word on these bytes is "ask again", then the card lapsed: not a decline, held back for a
        // day like any lapsed card.
        assert!(matches!(rig.propose(PLUGIN, set), Err(refusal) if refusal.reason == "recently-expired"));
    }

    #[test]
    fn a_declined_door_ask_refuses_that_call_and_the_next_call_gets_its_own_card() {
        let mut rig = rig("door", 600_000);
        let ask = |call: &str| {
            let args = canon::json::Value::object(vec![("url".into(), canon::json::Value::text("https://example.com/".into()).unwrap())]).unwrap();
            let digest = gate::door::call_digest("web_fetch", &canon::json::to_canonical(&args));
            gate::door::record(&gate::door::Ask { call_id: call, class: "ask-net", tool: "web_fetch", digest_sha256: &digest, args: &args }).unwrap()
        };
        let first = rig.propose(ASK, &ask("call-1")).unwrap();
        rig.decline(first).unwrap();
        assert!(declined_refusal(rig.propose(ASK, &ask("call-1"))), "the same call stays declined");
        let next = rig.propose(ASK, &ask("call-2")).unwrap();
        assert_eq!(rig.status(next), aura::storage::ProposalStatus::Pending);
        assert!(rig.declines().is_empty(), "door asks are not offered for asking again: the call itself is gone");
    }

    #[test]
    fn the_owners_decline_is_found_by_its_bytes() {
        // Only a gate.refuse terminal with reason owner-declined counts (aura::storage::OWNER_DECLINED).
        let mut rig = rig("reason", 600_000);
        let set = br#"{"set":"a"}"#;
        let first = rig.propose(PLUGIN, set).unwrap();
        let digest = rig.ledger.transaction(|txn| Ok(txn.proposal(&first)?.operation_digest)).unwrap();
        rig.decline(first).unwrap();
        let declined = rig.ledger.transaction(|txn| txn.last_decline(digest)).unwrap();
        assert_eq!(declined.map(|row| row.proposal), Some(first));
    }
}
