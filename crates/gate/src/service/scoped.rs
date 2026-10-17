// SPDX-License-Identifier: AGPL-3.0-or-later
//! Gate transitions on the supervisor's already scoped Aura transaction.

use super::*;

mod recovery;
mod release;
mod review;

pub use release::release_operation_digest;

/// The caller commits each transition and supplies a new transaction for effects.
pub struct ScopedGate<S> {
    targets: S,
    config: GateConfig,
}

/// A consumed assertion can attempt its effect only in a later transaction.
pub struct ConsumedApply {
    proposal: ProposalId,
    approval: Digest32,
    transaction: Digest32,
}

/// Commit a staged transition with both durable-boundary crash points.
/// Consumption and its effect must be committed in separate transactions.
pub fn commit_transition(txn: LedgerTxn<'_>, crash: &mut dyn CrashInjector) -> Result<()> {
    super::commit(txn, crash)
}

pub fn validate_installed_release(
    txn: &LedgerTxn<'_>,
    node: NodeId,
    proposal: &Proposal,
) -> Result<()> {
    validate_content(node, proposal)?;
    release::validate_origin(txn, proposal)
}

impl<S: TargetStore> ScopedGate<S> {
    pub fn new(targets: S, config: GateConfig) -> Result<Self> {
        let mut names = std::collections::BTreeSet::new();
        if !(1..=MAX_SAFE_INTEGER as u64).contains(&config.proposal_lifetime_ms)
            || !(1..=300_000).contains(&config.ceremony_lifetime_ms)
            || config
                .targets
                .iter()
                .any(|spec| spec.max_bytes == 0 || !names.insert(spec.id.clone()))
        {
            return Err(crate::refuse("configuration"));
        }
        Ok(Self { targets, config })
    }

    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    pub fn target_store(&self) -> &S {
        &self.targets
    }

    pub fn propose(
        &mut self,
        txn: &mut LedgerTxn<'_>,
        request: ProposalRequest,
        crash: &mut dyn CrashInjector,
    ) -> Result<Proposal> {
        crash.at(CrashPoint::BeforeProposal)?;
        let spec = self.spec(&request.target)?;
        if spec.class == TargetClass::Release || request.target.as_str() == "release" {
            return Err(crate::refuse("unsupported-operation"));
        }
        if request.new_bytes.len() > spec.max_bytes
            || request.new_bytes.len() > 65_536
            || request.model_note.len() > 8_192
        {
            return Err(crate::refuse("proposal-too-large"));
        }
        if request.target.as_str().starts_with("sites/") {
            crate::target::sites::validate_request(&self.config, &request)?;
        }
        let before = self.observe(&request.target)?;
        if before.digest != request.base {
            return Err(crate::refuse("stale-base"));
        }
        if before.bytes.as_deref() == Some(request.new_bytes.as_slice()) {
            return Err(crate::refuse("unchanged"));
        }
        let digest = proposal::content_digest(self.config.node, &request)?;
        self.check_evidence(txn, &request, digest)?;
        if let SuggestionOrder::RuleAfterReviewedBatch { batch } = request.suggestion {
            if !txn.gate_reviewed_batch(&batch, request.target.as_str())? {
                return Err(crate::refuse("batch-review-required"));
            }
        }
        let now = now(txn)?;
        let proposal = Proposal {
            id: ProposalId::from_bytes(random()?),
            operation_id: OperationId::from_bytes(random()?),
            operation_digest: digest,
            authority: txn.current_version()?,
            new_digest: hash(&request.new_bytes),
            risk: match spec.class {
                TargetClass::Content => spec.risk,
                _ => crate::DEFAULT_RISK,
            },
            request,
            state: ProposalState::Pending,
            created_at_ms: now,
            expires_at_ms: deadline(now, self.config.proposal_lifetime_ms)?,
        };
        txn.stage_proposal(proposal::to_stored(&proposal)?)?;
        let row = lifecycle(
            txn,
            &proposal,
            LifecycleKind::GatePropose,
            Phase::Intent,
            now,
            proposal::lifecycle_body(&proposal)?,
        )?;
        txn.append_lifecycle(row)?;
        crash.at(CrashPoint::AfterProposal)?;
        Ok(proposal)
    }

    pub fn consume_apply(
        &mut self,
        txn: &mut LedgerTxn<'_>,
        id: ProposalId,
        assertion: OwnerAssertion,
        crash: &mut dyn CrashInjector,
    ) -> Result<ConsumedApply> {
        coverage::lookup(EntryPoint::Apply, EffectRoute::TargetReplace)?;
        let proposal = load(txn, id)?;
        self.validate(&proposal, true)?;
        pending(txn, &proposal)?;
        if self.observe(&proposal.request.target)?.digest != proposal.request.base {
            return Err(crate::refuse("stale-base"));
        }
        txn.read_live_review(id, OwnerOperation::Apply)?
            .ok_or(crate::refuse("authorization-mismatch"))?;
        let proof = VerifiedProof::verify(txn, &id, OwnerOperation::Apply, assertion)?;
        crash.at(CrashPoint::AfterProof)?;
        let approval = hash(proof.authorization_bytes());
        txn.persist_counter(&proof)?;
        crash.at(CrashPoint::AfterCounter)?;
        txn.consume(&proof)?;
        crash.at(CrashPoint::AfterConsumption)?;
        let at = now(txn)?;
        let row = authority_row(
            txn,
            &proposal,
            Kind::GateConsume,
            Phase::Settle,
            at,
            outcome_body(&proposal, ProposalState::Consumed, Some(approval), None)?,
        )?;
        txn.append(proof, row)?;
        crash.at(CrashPoint::AfterAppend)?;
        Ok(ConsumedApply {
            proposal: id,
            approval,
            transaction: txn.transaction_id(),
        })
    }

    pub fn effect_once(
        &mut self,
        txn: &mut LedgerTxn<'_>,
        consumed: ConsumedApply,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        if consumed.transaction == txn.transaction_id() {
            return Err(crate::refuse("consumption-uncommitted"));
        }
        let proposal = load(txn, consumed.proposal)?;
        self.validate(&proposal, true)?;
        if proposal.state != ProposalState::Consumed {
            return Err(crate::refuse("not-consumed"));
        }
        if proposal.authority.epoch != txn.current_version()?.epoch {
            return Err(crate::refuse("owner-epoch-changed"));
        }
        if recovery_work(txn, &proposal)?.consumed_approval != consumed.approval {
            return Err(crate::refuse("consumption-mismatch"));
        }
        txn.check_target_consumption(proposal.id, consumed.approval)?;
        let before = self.targets.observe(&proposal.request.target);
        let mut acknowledged = false;
        if before.as_ref().is_ok_and(|seen| {
            crate::observation::validate(seen).is_ok() && seen.digest == proposal.request.base
        }) {
            crash.at(CrashPoint::BeforeEffect)?;
            let result = self.targets.replace_once(EffectPermit::new(
                proposal.operation_id,
                proposal.request.target.clone(),
                proposal.request.base,
                proposal.new_digest,
                proposal.request.new_bytes.clone(),
            ));
            crash.at(CrashPoint::AfterEffect)?;
            if let Ok(seen) = result {
                acknowledged = crate::observation::validate(&seen).is_ok()
                    && seen.digest == BaseDigest::Present(proposal.new_digest)
                    && seen.bytes.as_deref() == Some(proposal.request.new_bytes.as_slice());
            }
        }
        settle(
            txn,
            &self.targets,
            &proposal,
            consumed.approval,
            acknowledged,
            crash,
        )
    }

    pub fn retire(
        &mut self,
        txn: &mut LedgerTxn<'_>,
        id: ProposalId,
        assertion: OwnerAssertion,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        coverage::lookup(EntryPoint::Retire, EffectRoute::ProposalRetire)?;
        crash.at(CrashPoint::BeforeRetire)?;
        let proposal = load(txn, id)?;
        validate_content(self.config.node, &proposal)?;
        proposal.state.require_retirable()?;
        if proposal.state == ProposalState::Retired {
            return terminal_outcome(txn, &proposal);
        }
        pending(txn, &proposal)?;
        txn.read_live_review(id, OwnerOperation::Retire)?
            .ok_or(crate::refuse("authorization-mismatch"))?;
        let proof = VerifiedProof::verify(txn, &id, OwnerOperation::Retire, assertion)?;
        crash.at(CrashPoint::AfterProof)?;
        let approval = hash(proof.authorization_bytes());
        txn.persist_counter(&proof)?;
        crash.at(CrashPoint::AfterCounter)?;
        txn.consume(&proof)?;
        crash.at(CrashPoint::AfterConsumption)?;
        let at = now(txn)?;
        let row = authority_row(
            txn,
            &proposal,
            Kind::GateRetire,
            Phase::Terminal,
            at,
            outcome_body(&proposal, ProposalState::Retired, Some(approval), None)?,
        )?;
        let receipt = txn.append(proof, row)?;
        crash.at(CrashPoint::AfterAppend)?;
        txn.release_reservation(&id)?;
        crash.at(CrashPoint::AfterRetire)?;
        Ok(outcome(&proposal, ProposalState::Retired, receipt.hash))
    }

    /// The owner's Decline (NODE.md O19): a deliberate no, recorded as a `gate.refuse` terminal whose reason is
    /// `aura::storage::OWNER_DECLINED`. No passkey: it only narrows (nothing is applied), like revoking a standing
    /// grant. It ends any review the owner opened for the card. Until the owner asks again (`Rerequest`, new
    /// evidence), the same bytes are refused `declined-unchanged`. Closing a card is not this: an unanswered card only
    /// expires, and an expiry is not a decline. A settled proposal answers its existing outcome.
    pub fn decline(&mut self, txn: &mut LedgerTxn<'_>, id: ProposalId) -> Result<Outcome> {
        let proposal = load(txn, id)?;
        validate_content(self.config.node, &proposal)?;
        if proposal.state.is_terminal() {
            return terminal_outcome(txn, &proposal);
        }
        pending(txn, &proposal)?;
        let at = now(txn)?;
        let row = lifecycle(
            txn,
            &proposal,
            LifecycleKind::GateRefuse,
            Phase::Terminal,
            at,
            declined_body(&proposal)?,
        )?;
        let receipt = txn.decline(&id, row)?;
        txn.release_reservation(&id)?;
        Ok(outcome(&proposal, ProposalState::Refused, receipt.hash))
    }

    fn spec(&self, target: &crate::target::TargetId) -> Result<&TargetSpec> {
        self.config
            .targets
            .iter()
            .find(|spec| &spec.id == target)
            .ok_or(crate::refuse("unknown-target"))
    }

    fn observe(&self, target: &crate::target::TargetId) -> Result<TargetObservation> {
        let observation = self.targets.observe(target)?;
        crate::observation::validate(&observation)?;
        Ok(observation)
    }

    fn validate(&self, proposal: &Proposal, applying: bool) -> Result<()> {
        validate_content(self.config.node, proposal)?;
        let spec = self.spec(&proposal.request.target)?;
        if proposal.request.new_bytes.len() > spec.max_bytes
            || (applying && (spec.class != TargetClass::Content || spec.risk != proposal.risk))
        {
            return Err(crate::refuse("unsupported-operation"));
        }
        if proposal.request.target.as_str().starts_with("sites/") {
            crate::target::sites::validate(&self.config, proposal)?;
        }
        Ok(())
    }

    fn check_evidence(
        &self,
        txn: &mut LedgerTxn<'_>,
        request: &ProposalRequest,
        digest: canon::ids::OperationDigest,
    ) -> Result<()> {
        if let Some(previous) = txn.last_decline(digest)? {
            let evidence = request
                .new_evidence
                .as_ref()
                .ok_or(crate::refuse("declined-unchanged"))?;
            proposal::validate_new_evidence(
                txn,
                &DeclinedProposal {
                    proposal: previous.proposal,
                    operation: previous.operation_digest,
                    target: crate::target::TargetId::new(previous.target)?,
                    evidence: Some(previous.evidence_digest),
                    terminal: previous.authority,
                },
                &EvidenceChange {
                    previous: Some(previous.evidence_digest),
                    current: evidence.digest,
                    source_record: evidence.source_record,
                },
            )?;
        } else if let Some(evidence) = &request.new_evidence {
            let row = txn.record_at(evidence.source_record)?;
            if row.authority != evidence.source_record || row.hash != evidence.digest {
                return Err(crate::refuse("evidence-source"));
            }
        } else if let Some((_, at)) = txn.last_expiry(digest)? {
            // The same bytes whose card simply ran out of time: at most once a day, unless the owner asks again
            // (which carries new evidence). Peter, 2026-10-17: no nagging, and no permanent no either.
            if now(txn)?.saturating_sub(at) < aura::ledger::DAY_MS {
                return Err(crate::refuse("recently-expired"));
            }
        }
        Ok(())
    }
}

fn declined_body(proposal: &Proposal) -> Result<Value> {
    let body = outcome_body(proposal, ProposalState::Refused, None, None)?;
    let ValueView::Object(fields) = body.view() else {
        return Err(crate::refuse("terminal-body"));
    };
    let mut fields = fields.to_vec();
    fields.push((
        "reason".into(),
        Value::text(aura::storage::OWNER_DECLINED.to_owned())?,
    ));
    Value::object(fields)
}

fn now(txn: &mut LedgerTxn<'_>) -> Result<i64> {
    let at = txn.observation_context()?.at;
    if !(0..=MAX_SAFE_INTEGER).contains(&at) {
        return Err(crate::refuse("clock"));
    }
    Ok(at)
}

fn pending(txn: &mut LedgerTxn<'_>, proposal: &Proposal) -> Result<()> {
    if proposal.state != ProposalState::Pending {
        return Err(crate::refuse("not-pending"));
    }
    if proposal.authority.epoch != txn.current_version()?.epoch {
        return Err(crate::refuse("owner-epoch-changed"));
    }
    if now(txn)? >= proposal.expires_at_ms {
        return Err(crate::refuse("expired"));
    }
    Ok(())
}
