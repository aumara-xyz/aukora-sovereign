// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact proposals and one-use transitions through the single Aura writer.

use crate::{
    card::{self, CeremonyContext, DisplayedCard, ReviewFacts},
    coverage::{self, EffectRoute, EntryPoint},
    proposal::{
        self, DeclinedProposal, EvidenceChange, Proposal, ProposalRequest, ProposalState,
        SuggestionOrder,
    },
    recovery::{
        self, CrashInjector, CrashPoint, NoInjection, RecoveryItem, RecoveryResult, RecoverySweep,
    },
    standing::{self, StandingPermissionRef},
    target::{EffectPermit, TargetClass, TargetObservation, TargetSpec, TargetStore},
    Result,
};
use aura::{Ledger, LedgerTxn, TransactionServices};
use canon::{
    alg::AlgorithmId,
    authority::{
        AuthorityTxn, AuthorizationChallenge, BaseDigest, Kind, LifecycleKind, LifecycleRecord,
        OwnerAssertion, OwnerOperation, PendingAuthorityRecord, Phase,
    },
    digest::Digest32,
    ids::{NodeId, OperationId, ProposalId},
    json::{Value, ValueView, MAX_SAFE_INTEGER},
};
use sha2::{Digest, Sha256};

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
        ledger: Ledger,
        targets: S,
        config: GateConfig,
        services: TransactionServices<'a>,
    ) -> Result<Self> {
        let mut names = std::collections::BTreeSet::new();
        if config.proposal_lifetime_ms == 0
            || config.proposal_lifetime_ms > MAX_SAFE_INTEGER as u64
            || config.ceremony_lifetime_ms == 0
            || config.ceremony_lifetime_ms > 300_000
            || config
                .targets
                .iter()
                .any(|target| target.max_bytes == 0 || !names.insert(target.id.clone()))
        {
            return Err(crate::refuse("configuration"));
        }
        let mut gate = Self {
            ledger,
            targets,
            config,
            services,
        };
        let sweep = gate.recover(&mut NoInjection)?;
        if !sweep.blocked.is_empty() {
            return Err(crate::refuse("recovery-blocked"));
        }
        Ok(gate)
    }

    pub fn propose(
        &mut self,
        request: ProposalRequest,
        crash: &mut dyn CrashInjector,
    ) -> Result<Proposal> {
        crash.at(CrashPoint::BeforeProposal)?;
        let spec = self
            .config
            .targets
            .iter()
            .find(|target| target.id == request.target)
            .ok_or(crate::refuse("unknown-target"))?;
        if request.new_bytes.len() > spec.max_bytes
            || request.new_bytes.len() > 65_536
            || request.model_note.len() > 8_192
        {
            return Err(crate::refuse("proposal-too-large"));
        }
        let now = clock(self.services)?;
        let expires = deadline(now, self.config.proposal_lifetime_ms)?;
        let observed = self.targets.observe(&request.target)?;
        check_observation(&observed)?;
        if observed.digest != request.base {
            return Err(crate::refuse("stale-base"));
        }
        if observed.bytes.as_ref() == Some(&request.new_bytes) {
            return Err(crate::refuse("unchanged"));
        }
        let digest = proposal::content_digest(self.config.node, &request)?;
        let mut transaction = self.ledger.begin(self.services)?;
        if let Some(declined) = transaction.last_decline(digest)? {
            let evidence = request
                .new_evidence
                .as_ref()
                .ok_or(crate::refuse("declined-unchanged"))?;
            proposal::validate_new_evidence(
                &mut transaction,
                &DeclinedProposal {
                    proposal: declined.proposal,
                    operation: declined.operation_digest,
                    target: crate::target::TargetId::new(declined.target)?,
                    evidence: Some(declined.evidence_digest),
                    terminal: declined.authority,
                },
                &EvidenceChange {
                    previous: Some(declined.evidence_digest),
                    current: evidence.digest,
                    source_record: evidence.source_record,
                },
            )?;
        } else if let Some(evidence) = &request.new_evidence {
            let source = transaction.record_at(evidence.source_record)?;
            if source.authority != evidence.source_record || source.hash != evidence.digest {
                return Err(crate::refuse("evidence-source"));
            }
        }
        if let SuggestionOrder::RuleAfterReviewedBatch { batch } = request.suggestion {
            if !transaction.gate_reviewed_batch(&batch, request.target.as_str())? {
                return Err(crate::refuse("batch-review-required"));
            }
        }
        let proposal = Proposal {
            id: ProposalId::from_bytes(random()?),
            operation_id: OperationId::from_bytes(random()?),
            operation_digest: digest,
            authority: transaction.current_version()?,
            new_digest: hash(&request.new_bytes),
            risk: if spec.class == TargetClass::Content {
                spec.risk
            } else {
                crate::DEFAULT_RISK
            },
            request,
            state: ProposalState::Pending,
            created_at_ms: now,
            expires_at_ms: expires,
        };
        transaction.stage_proposal(proposal::to_stored(&proposal))?;
        transaction.append_lifecycle(lifecycle(
            &transaction,
            &proposal,
            LifecycleKind::GatePropose,
            Phase::Intent,
            now,
            proposal::lifecycle_body(&proposal)?,
        )?)?;
        commit(transaction, crash)?;
        crash.at(CrashPoint::AfterProposal)?;
        Ok(proposal)
    }

    pub fn review(
        &mut self,
        id: ProposalId,
        action: OwnerOperation,
        crash: &mut dyn CrashInjector,
    ) -> Result<OwnerReview> {
        crash.at(CrashPoint::BeforeReview)?;
        let now = clock(self.services)?;
        let mut transaction = self.ledger.begin(self.services)?;
        let proposal = load(&transaction, id)?;
        validate_content(self.config.node, &proposal)?;
        if action == OwnerOperation::Retire {
            proposal.state.require_retirable()?;
        }
        if proposal.state != ProposalState::Pending {
            return Err(crate::refuse("not-pending"));
        }
        if now >= proposal.expires_at_ms {
            return Err(crate::refuse("expired"));
        }
        let spec = self
            .config
            .targets
            .iter()
            .find(|target| target.id == proposal.request.target)
            .ok_or(crate::refuse("unknown-target"))?;
        match action {
            OwnerOperation::Apply if spec.class == TargetClass::Content => (),
            OwnerOperation::Retire => (),
            _ => return Err(crate::refuse("unsupported-operation")),
        }
        let observed = self.targets.observe(&proposal.request.target)?;
        check_observation(&observed)?;
        if action == OwnerOperation::Apply && observed.digest != proposal.request.base {
            return Err(crate::refuse("stale-base"));
        }
        let facts = ReviewFacts {
            says: match action {
                OwnerOperation::Apply => "Replace the target with the displayed bytes.",
                OwnerOperation::Retire => "Retire this proposal without applying its bytes.",
                _ => return Err(crate::refuse("unsupported-operation")),
            }
            .into(),
            facts: vec![
                ("target".into(), text(proposal.request.target.as_str())?),
                ("base_sha256".into(), base_value(proposal.request.base)?),
                ("new_sha256".into(), text(proposal.new_digest)?),
            ],
            from_to: vec![
                ("base_sha256".into(), base_value(proposal.request.base)?),
                (
                    "new_bytes_b64".into(),
                    text(encode_bytes(&proposal.request.new_bytes))?,
                ),
            ],
        };
        let displayed = card::build_card(&proposal, action, facts)?;
        let authorization = card::authorization(
            &proposal,
            action,
            &displayed,
            CeremonyContext {
                node: self.config.node,
                subject: transaction.gate_owner_subject()?,
                epoch: transaction.current_version()?.epoch,
                challenge: AuthorizationChallenge::from_bytes(random()?),
                expires_at_ms: deadline(now, self.config.ceremony_lifetime_ms)?
                    .min(proposal.expires_at_ms),
            },
        )?;
        let authorization_bytes = authorization.canonical_bytes()?;
        let passkey_challenge = card::passkey_challenge(&authorization)?;
        transaction.stage_authorization(aura::storage::StagedAuthorization {
            authorization,
            card: displayed.card().clone(),
        })?;
        let body = object(vec![
            ("proposal", text(id)?),
            ("action", text(action.wire_name())?),
            ("display_sha256", text(displayed.digest())?),
            ("authorization_sha256", text(hash(&authorization_bytes))?),
        ])?;
        transaction.append_lifecycle(lifecycle(
            &transaction,
            &proposal,
            LifecycleKind::GateReview,
            Phase::Settle,
            now,
            body,
        )?)?;
        commit(transaction, crash)?;
        crash.at(CrashPoint::AfterReview)?;
        Ok(OwnerReview {
            proposal: id,
            action,
            card: displayed,
            authorization_bytes,
            passkey_challenge,
        })
    }

    pub fn apply(
        &mut self,
        id: ProposalId,
        assertion: OwnerAssertion,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        coverage::lookup(EntryPoint::Apply, EffectRoute::TargetReplace)?;
        let now = clock(self.services)?;
        let mut transaction = self.ledger.begin(self.services)?;
        let proposal = load(&transaction, id)?;
        if proposal.state != ProposalState::Pending {
            return Err(crate::refuse("not-pending"));
        }
        if now >= proposal.expires_at_ms {
            return Err(crate::refuse("expired"));
        }
        let spec = self
            .config
            .targets
            .iter()
            .find(|target| target.id == proposal.request.target)
            .ok_or(crate::refuse("unknown-target"))?;
        if spec.class != TargetClass::Content {
            return Err(crate::refuse("unsupported-operation"));
        }
        if proposal::content_digest(self.config.node, &proposal.request)?
            != proposal.operation_digest
        {
            return Err(crate::refuse("operation-mismatch"));
        }
        let observation = self.targets.observe(&proposal.request.target)?;
        check_observation(&observation)?;
        if observation.digest != proposal.request.base {
            return Err(crate::refuse("stale-base"));
        }
        let proof = aumlok::webauthn::verify_owner_assertion(
            &mut transaction,
            &id,
            OwnerOperation::Apply,
            assertion,
        )?;
        crash.at(CrashPoint::AfterProof)?;
        let approval = hash(proof.authorization_bytes());
        transaction.persist_counter(&proof)?;
        crash.at(CrashPoint::AfterCounter)?;
        transaction.consume(&proof)?;
        crash.at(CrashPoint::AfterConsumption)?;
        let row = authority_row(
            &transaction,
            &proposal,
            Kind::GateConsume,
            Phase::Settle,
            now,
            outcome_body(&proposal, ProposalState::Consumed, Some(approval), None)?,
        )?;
        transaction.append(proof, row)?;
        crash.at(CrashPoint::AfterAppend)?;
        commit(transaction, crash)?;
        self.effect_once(id, approval, crash)
    }

    /// A standing use names the exact signed permission by its fingerprint.
    /// Locked verification checks that fingerprint and only permits routine Apply.
    /// It cannot grant, renew or widen a permission; changes require
    /// `standing::StandingChange`, including a fresh owner assertion.
    /// This path refuses without effects while standing consumption is unavailable.
    pub fn apply_standing(
        &mut self,
        proposal: ProposalId,
        permission: StandingPermissionRef,
        _crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        coverage::lookup(EntryPoint::Apply, EffectRoute::TargetReplace)?;
        let mut transaction = self.ledger.begin(self.services)?;
        let _usage = standing::check_use(&mut transaction, &proposal, permission)?;
        crate::unavailable()
    }

    /// Retire pending work with its exact C5 owner assertion, or return its
    /// existing retirement receipt. Unknown outcomes refuse `gate:unknown-outcome`.
    pub fn retire(
        &mut self,
        id: ProposalId,
        assertion: OwnerAssertion,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        coverage::lookup(EntryPoint::Retire, EffectRoute::ProposalRetire)?;
        crash.at(CrashPoint::BeforeRetire)?;
        let now = clock(self.services)?;
        let mut transaction = self.ledger.begin(self.services)?;
        let proposal = load(&transaction, id)?;
        proposal.state.require_retirable()?;
        if proposal.state == ProposalState::Retired {
            return terminal_outcome(&transaction, &proposal);
        }
        let proof = aumlok::webauthn::verify_owner_assertion(
            &mut transaction,
            &id,
            OwnerOperation::Retire,
            assertion,
        )?;
        crash.at(CrashPoint::AfterProof)?;
        let approval = hash(proof.authorization_bytes());
        transaction.persist_counter(&proof)?;
        crash.at(CrashPoint::AfterCounter)?;
        transaction.consume(&proof)?;
        crash.at(CrashPoint::AfterConsumption)?;
        let row = authority_row(
            &transaction,
            &proposal,
            Kind::GateRetire,
            Phase::Terminal,
            now,
            outcome_body(&proposal, ProposalState::Retired, Some(approval), None)?,
        )?;
        let receipt = transaction.append(proof, row)?;
        crash.at(CrashPoint::AfterAppend)?;
        transaction.release_reservation(&id)?;
        let outcome = outcome(&proposal, ProposalState::Retired, receipt.hash);
        commit(transaction, crash)?;
        crash.at(CrashPoint::AfterRetire)?;
        Ok(outcome)
    }

    pub fn expire(&mut self, id: ProposalId, crash: &mut dyn CrashInjector) -> Result<Outcome> {
        crash.at(CrashPoint::BeforeExpire)?;
        let result = self.finish_unconsumed(id, true, crash)?;
        crash.at(CrashPoint::AfterExpire)?;
        Ok(result)
    }

    pub fn decline(&mut self, id: ProposalId, crash: &mut dyn CrashInjector) -> Result<Outcome> {
        crash.at(CrashPoint::BeforeDecline)?;
        let result = self.finish_unconsumed(id, false, crash)?;
        crash.at(CrashPoint::AfterDecline)?;
        Ok(result)
    }

    /// One-tap narrowing requires no new passkey assertion. The transaction
    /// matches the exact grant fingerprint and current owner epoch; a matching
    /// prior revocation is idempotent. An unavailable adapter refuses.
    pub fn revoke_standing(
        &mut self,
        permission: StandingPermissionRef,
        crash: &mut dyn CrashInjector,
    ) -> Result<()> {
        crash.at(CrashPoint::BeforeRevoke)?;
        let mut transaction = self.ledger.begin(self.services)?;
        standing::revoke(&mut transaction, permission)?;
        commit(transaction, crash)?;
        crash.at(CrashPoint::AfterRevoke)?;
        Ok(())
    }

    pub fn recover(&mut self, crash: &mut dyn CrashInjector) -> Result<RecoverySweep> {
        crash.at(CrashPoint::BeforeRecovery)?;
        clock(self.services)?;
        let transaction = self.ledger.begin(self.services)?;
        let pending = transaction.pending_proposals(10_001)?;
        let consumed = transaction.recovery_work(10_001)?;
        if pending.len() > 10_000 || consumed.len() > 10_000 {
            return Err(crate::refuse("recovery-limit"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for stored in pending {
            let record = transaction.record_at(stored.authority)?;
            let proposal = proposal::from_stored(stored, &record)?;
            if proposal.state == ProposalState::Pending {
                ids.insert(proposal.id);
            }
        }
        ids.extend(consumed.iter().map(|work| work.proposal));
        transaction.rollback()?;
        let mut sweep = RecoverySweep::default();
        for id in ids {
            match self.reconcile(id, crash) {
                Ok(outcome) => {
                    let transaction = self.ledger.begin(self.services)?;
                    let stored = transaction.proposal(&id)?;
                    let terminal = transaction
                        .gate_terminal(&stored.operation)?
                        .ok_or(crate::refuse("missing-terminal"))?;
                    sweep.settled.push(RecoveryResult {
                        proposal: id,
                        state: outcome.state,
                        terminal: terminal.authority,
                        target_released: true,
                    });
                    transaction.rollback()?;
                }
                Err(error) => sweep.blocked.push((id, error)),
            }
        }
        crash.at(CrashPoint::AfterRecovery)?;
        Ok(sweep)
    }

    pub fn reconcile(&mut self, id: ProposalId, crash: &mut dyn CrashInjector) -> Result<Outcome> {
        crash.at(CrashPoint::BeforeReconcile)?;
        let now = clock(self.services)?;
        let mut transaction = self.ledger.begin(self.services)?;
        let proposal = load(&transaction, id)?;
        if proposal.state.is_terminal() {
            let result = terminal_outcome(&transaction, &proposal)?;
            transaction.release_reservation(&id)?;
            commit(transaction, crash)?;
            crash.at(CrashPoint::AfterReconcile)?;
            return Ok(result);
        }
        if proposal.state == ProposalState::Pending {
            if now >= proposal.expires_at_ms {
                transaction.rollback()?;
                let result = self.finish_unconsumed(id, true, crash)?;
                crash.at(CrashPoint::AfterReconcile)?;
                return Ok(result);
            }
            crash.at(CrashPoint::BeforeTerminal)?;
            let row = lifecycle(
                &transaction,
                &proposal,
                LifecycleKind::GateRefuse,
                Phase::Terminal,
                now,
                outcome_body(&proposal, ProposalState::Failed, None, None)?,
            )?;
            let receipt = transaction.append_lifecycle(row)?;
            transaction.release_reservation(&id)?;
            crash.at(CrashPoint::AfterTerminal)?;
            let result = outcome(&proposal, ProposalState::Failed, receipt.hash);
            commit(transaction, crash)?;
            crash.at(CrashPoint::AfterReconcile)?;
            return Ok(result);
        }
        let work = recovery_work(&transaction, &proposal)?;
        let observed = self.targets.observe(&proposal.request.target).ok();
        let state = match &observed {
            Some(observed) => recovery::classify_observation(&RecoveryItem {
                proposal: id,
                consumed_approval: work.consumed_approval,
                consumption: work.consumed_at,
                expected_base: work.base_sha256,
                expected_new_digest: work.new_sha256,
                observed: observed.clone(),
            })?,
            None => ProposalState::Unknown,
        };
        let result = settle(
            &mut transaction,
            &proposal,
            state,
            work.consumed_approval,
            observed.as_ref(),
            now,
            crash,
        )?;
        commit(transaction, crash)?;
        crash.at(CrashPoint::AfterReconcile)?;
        Ok(result)
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

    fn effect_once(
        &mut self,
        id: ProposalId,
        approval: Digest32,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        let mut transaction = self.ledger.begin(self.services)?;
        let proposal = load(&transaction, id)?;
        validate_content(self.config.node, &proposal)?;
        if proposal.state != ProposalState::Consumed {
            return Err(crate::refuse("not-consumed"));
        }
        let work = recovery_work(&transaction, &proposal)?;
        if work.consumed_approval != approval {
            return Err(crate::refuse("consumption-mismatch"));
        }
        let before = self
            .targets
            .observe(&proposal.request.target)
            .and_then(|observed| {
                check_observation(&observed)?;
                Ok(observed)
            });
        let mut applied = false;
        if matches!(before, Ok(ref observed) if observed.digest == proposal.request.base) {
            crash.at(CrashPoint::BeforeEffect)?;
            let permit = EffectPermit::new(
                proposal.operation_id,
                proposal.request.target.clone(),
                proposal.request.base,
                proposal.new_digest,
                proposal.request.new_bytes.clone(),
            );
            let replacement = self.targets.replace_once(permit);
            crash.at(CrashPoint::AfterEffect)?;
            if let Ok(observed) = replacement {
                applied = check_observation(&observed).is_ok()
                    && observed.digest == BaseDigest::Present(proposal.new_digest)
                    && observed.bytes.as_ref() == Some(&proposal.request.new_bytes);
            }
        }
        let observed = self.targets.observe(&proposal.request.target).ok();
        let state = match &observed {
            Some(observed)
                if applied
                    && observed.digest == BaseDigest::Present(proposal.new_digest)
                    && observed.bytes.as_ref() == Some(&proposal.request.new_bytes) =>
            {
                ProposalState::Applied
            }
            Some(observed) => recovery::classify_observation(&RecoveryItem {
                proposal: id,
                consumed_approval: approval,
                consumption: work.consumed_at,
                expected_base: work.base_sha256,
                expected_new_digest: work.new_sha256,
                observed: observed.clone(),
            })?,
            None => ProposalState::Unknown,
        };
        let result = settle(
            &mut transaction,
            &proposal,
            state,
            approval,
            observed.as_ref(),
            clock(self.services)?,
            crash,
        )?;
        commit(transaction, crash)?;
        Ok(result)
    }

    fn finish_unconsumed(
        &mut self,
        id: ProposalId,
        expired: bool,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        let now = clock(self.services)?;
        let mut transaction = self.ledger.begin(self.services)?;
        let proposal = load(&transaction, id)?;
        if proposal.state.is_terminal() {
            return terminal_outcome(&transaction, &proposal);
        }
        if proposal.state != ProposalState::Pending {
            return Err(crate::refuse("consumed-reconcile-required"));
        }
        if expired && now < proposal.expires_at_ms {
            return Err(crate::refuse("not-expired"));
        }
        let state = if expired {
            ProposalState::Expired
        } else {
            ProposalState::Refused
        };
        crash.at(CrashPoint::BeforeTerminal)?;
        let row = lifecycle(
            &transaction,
            &proposal,
            if expired {
                LifecycleKind::GateExpire
            } else {
                LifecycleKind::GateRefuse
            },
            Phase::Terminal,
            now,
            outcome_body(&proposal, state, None, None)?,
        )?;
        let receipt = if expired {
            transaction.append_lifecycle(row)?
        } else {
            transaction.decline(&id, row)?
        };
        transaction.release_reservation(&id)?;
        crash.at(CrashPoint::AfterTerminal)?;
        let result = outcome(&proposal, state, receipt.hash);
        commit(transaction, crash)?;
        Ok(result)
    }
}

fn load(transaction: &LedgerTxn<'_>, id: ProposalId) -> Result<Proposal> {
    let stored = transaction.proposal(&id)?;
    let record = transaction.record_at(stored.authority)?;
    proposal::from_stored(stored, &record)
}

fn recovery_work(
    transaction: &LedgerTxn<'_>,
    proposal: &Proposal,
) -> Result<aura::storage::RecoveryWork> {
    let rows = transaction.recovery_work(10_001)?;
    if rows.len() > 10_000 {
        return Err(crate::refuse("recovery-limit"));
    }
    let mut rows = rows.into_iter().filter(|work| work.proposal == proposal.id);
    let work = rows.next().ok_or(crate::refuse("missing-consumption"))?;
    if rows.next().is_some()
        || work.operation != proposal.operation_id
        || work.target != proposal.request.target.as_str()
        || work.base_sha256 != proposal.request.base
        || work.new_sha256 != proposal.new_digest
    {
        return Err(crate::refuse("consumption-mismatch"));
    }
    let record = transaction.record_at(work.consumed_at)?;
    if record.authority != work.consumed_at
        || record.kind != Kind::GateConsume
        || record.phase != Phase::Settle
        || record.operation != Some(proposal.operation_id)
        || !matches_proposal(payload(&record.body), proposal)?
        || field_text(payload(&record.body), "state") != Some("consumed")
        || field_text(payload(&record.body), "consumed_approval")
            != Some(work.consumed_approval.to_string().as_str())
    {
        return Err(crate::refuse("consumption-mismatch"));
    }
    Ok(work)
}

fn settle(
    transaction: &mut LedgerTxn<'_>,
    proposal: &Proposal,
    state: ProposalState,
    approval: Digest32,
    observed: Option<&TargetObservation>,
    now: i64,
    crash: &mut dyn CrashInjector,
) -> Result<Outcome> {
    if !matches!(
        state,
        ProposalState::Applied
            | ProposalState::Incomplete
            | ProposalState::Failed
            | ProposalState::Conflict
            | ProposalState::Unknown
    ) {
        return Err(crate::refuse("settlement-state"));
    }
    crash.at(CrashPoint::BeforeTerminal)?;
    let row = lifecycle(
        transaction,
        proposal,
        LifecycleKind::GateRecover {
            consumed_approval: approval,
        },
        Phase::Terminal,
        now,
        outcome_body(proposal, state, Some(approval), observed)?,
    )?;
    let receipt = transaction.append_lifecycle(row)?;
    transaction.release_reservation(&proposal.id)?;
    crash.at(CrashPoint::AfterTerminal)?;
    Ok(outcome(proposal, state, receipt.hash))
}

fn authority_row(
    transaction: &LedgerTxn<'_>,
    proposal: &Proposal,
    kind: Kind,
    phase: Phase,
    at: i64,
    body: Value,
) -> Result<PendingAuthorityRecord> {
    Ok(PendingAuthorityRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: transaction.current_version()?,
        at,
        kind,
        actor: "owner".into(),
        operation: Some(proposal.operation_id),
        phase,
        body,
    })
}

fn lifecycle(
    transaction: &LedgerTxn<'_>,
    proposal: &Proposal,
    kind: LifecycleKind,
    phase: Phase,
    at: i64,
    body: Value,
) -> Result<LifecycleRecord> {
    Ok(LifecycleRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: transaction.current_version()?,
        at,
        kind,
        actor: if kind == LifecycleKind::GatePropose {
            "auma"
        } else {
            "gate"
        }
        .into(),
        operation: proposal.operation_id,
        phase,
        body,
    })
}

fn outcome_body(
    proposal: &Proposal,
    state: ProposalState,
    approval: Option<Digest32>,
    observed: Option<&TargetObservation>,
) -> Result<Value> {
    let mut fields = vec![
        ("proposal", text(proposal.id)?),
        ("target", text(proposal.request.target.as_str())?),
        ("operation", text(proposal.operation_digest)?),
        ("base_sha256", base_value(proposal.request.base)?),
        ("new_sha256", text(proposal.new_digest)?),
        ("state", text(state_name(state))?),
        ("retry", Value::boolean(false)),
    ];
    if let Some(approval) = approval {
        fields.push(("consumed_approval", text(approval)?));
    }
    if let Some(observed) = observed {
        fields.push(("observed_sha256", base_value(observed.digest)?));
    } else if state == ProposalState::Unknown {
        fields.push(("observed_sha256", Value::null()));
        fields.push(("observation", text("unavailable")?));
    }
    object(fields)
}

fn terminal_outcome(transaction: &LedgerTxn<'_>, proposal: &Proposal) -> Result<Outcome> {
    let terminal = transaction
        .gate_terminal(&proposal.operation_id)?
        .ok_or(crate::refuse("missing-terminal"))?;
    let body = payload(&terminal.body);
    if !matches_proposal(body, proposal)?
        || field_text(body, "state") != Some(state_name(proposal.state))
    {
        return Err(crate::refuse("terminal-mismatch"));
    }
    Ok(outcome(proposal, proposal.state, terminal.hash))
}

fn validate_content(node: NodeId, proposal: &Proposal) -> Result<()> {
    if hash(&proposal.request.new_bytes) != proposal.new_digest
        || proposal::content_digest(node, &proposal.request)? != proposal.operation_digest
    {
        return Err(crate::refuse("operation-mismatch"));
    }
    Ok(())
}

fn matches_proposal(body: &Value, proposal: &Proposal) -> Result<bool> {
    Ok(
        field_text(body, "proposal") == Some(proposal.id.to_string().as_str())
            && field_text(body, "target") == Some(proposal.request.target.as_str())
            && field_text(body, "operation")
                == Some(proposal.operation_digest.to_string().as_str())
            && field_text(body, "new_sha256") == Some(proposal.new_digest.to_string().as_str())
            && body.get("base_sha256") == Some(&base_value(proposal.request.base)?),
    )
}

fn outcome(proposal: &Proposal, state: ProposalState, receipt_hash: Digest32) -> Outcome {
    Outcome {
        proposal: proposal.id,
        state,
        receipt_hash,
    }
}

fn commit(transaction: LedgerTxn<'_>, crash: &mut dyn CrashInjector) -> Result<()> {
    crash.at(CrashPoint::BeforeCommit)?;
    transaction.commit()?;
    crash.at(CrashPoint::AfterCommit)
}

fn check_observation(observed: &TargetObservation) -> Result<()> {
    match (&observed.digest, &observed.bytes) {
        (BaseDigest::Absent, None) => Ok(()),
        (BaseDigest::Present(expected), Some(bytes)) if *expected == hash(bytes) => Ok(()),
        _ => Err(crate::refuse("target-observation")),
    }
}

fn clock(services: TransactionServices<'_>) -> Result<i64> {
    let now = services.clock.now_ms()?;
    if !(0..=MAX_SAFE_INTEGER).contains(&now) {
        return Err(crate::refuse("clock"));
    }
    Ok(now)
}

fn deadline(now: i64, lifetime: u64) -> Result<i64> {
    let expires = now
        .checked_add(i64::try_from(lifetime).map_err(|_| crate::refuse("clock"))?)
        .ok_or(crate::refuse("clock"))?;
    if expires > MAX_SAFE_INTEGER {
        return Err(crate::refuse("clock"));
    }
    Ok(expires)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| crate::refuse("randomness"))?;
    Ok(bytes)
}

fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}
fn text(value: impl ToString) -> Result<Value> {
    Value::text(value.to_string())
}
fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn base_value(base: BaseDigest) -> Result<Value> {
    text(match base {
        BaseDigest::Absent => "absent".into(),
        BaseDigest::Present(hash) => hash.to_string(),
    })
}
fn payload(body: &Value) -> &Value {
    if field_text(body, "schema") == Some(aura::record::AUTHORITY_BODY_SCHEMA) {
        body.get("payload").unwrap_or(body)
    } else {
        body
    }
}
fn field_text<'a>(body: &'a Value, field: &str) -> Option<&'a str> {
    match body.get(field)?.view() {
        ValueView::Text(text) => Some(text),
        _ => None,
    }
}
fn encode_bytes(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn state_name(state: ProposalState) -> &'static str {
    match state {
        ProposalState::Pending => "pending",
        ProposalState::Consumed => "consumed",
        ProposalState::Applied => "applied",
        ProposalState::Refused => "refused",
        ProposalState::Expired => "expired",
        ProposalState::Retired => "retired",
        ProposalState::Incomplete => "incomplete",
        ProposalState::Failed => "failed",
        ProposalState::Conflict => "conflict",
        ProposalState::Unknown => "unknown",
    }
}

impl<'a, S: TargetStore> Gate<'a, S> {
    pub(crate) fn install_parts(
        &mut self,
    ) -> (&mut Ledger, &mut S, &GateConfig, TransactionServices<'a>) {
        (&mut self.ledger, &mut self.targets, &self.config, self.services)
    }

    pub(crate) fn install_construct(
        ledger: Ledger,
        targets: S,
        config: GateConfig,
        services: TransactionServices<'a>,
    ) -> Self {
        Self { ledger, targets, config, services }
    }
}
