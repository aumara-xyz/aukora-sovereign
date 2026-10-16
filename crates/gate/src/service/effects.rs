// SPDX-License-Identifier: AGPL-3.0-or-later
//! Consumption and target effects remain separate durable transitions.

use super::*;

impl<S: TargetStore> Gate<'_, S> {
    /// Consume a checked routine permission before attempting its exact target effect.
    pub fn apply_standing(
        &mut self,
        id: ProposalId,
        permission: StandingPermissionRef,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        coverage::lookup(EntryPoint::Apply, EffectRoute::TargetReplace)?;
        let now = clock(self.services)?;
        let mut transaction = self.ledger.begin(self.services)?;
        let proposal = load(&transaction, id)?;
        validate_content(self.config.node, &proposal)?;
        if proposal.state != ProposalState::Pending {
            return Err(crate::refuse("not-pending"));
        }
        if now >= proposal.expires_at_ms {
            return Err(crate::refuse("expired"));
        }
        let target = self
            .config
            .targets
            .iter()
            .find(|target| target.id == proposal.request.target)
            .ok_or(crate::refuse("unknown-target"))?;
        if target.class != TargetClass::Content
            || proposal.request.new_bytes.len() > target.max_bytes
        {
            return Err(crate::refuse("unsupported-operation"));
        }
        if proposal.risk != crate::RiskTier::Routine || target.risk != crate::RiskTier::Routine {
            return Err(crate::refuse("standing-critical"));
        }
        let observed = self.targets.observe(&proposal.request.target)?;
        check_observation(&observed)?;
        if observed.digest != proposal.request.base {
            return Err(crate::refuse("stale-base"));
        }
        let usage = standing::verify_use(&mut transaction, &id, permission)?;
        if usage.context().epoch != proposal.authority.epoch
            || usage.context().epoch != transaction.current_version()?.epoch
            || usage.context().operation != proposal.operation_digest
            || usage.proposal() != &id
        {
            return Err(crate::refuse("consumption-mismatch"));
        }
        crash.at(CrashPoint::AfterProof)?;
        let grant = load(&transaction, *usage.permission_id())?;
        let standing = object(vec![
            ("permission", text(grant.operation_id)?),
            ("permission_proposal", text(usage.permission_id())?),
            ("permission_digest", text(usage.permission_digest())?),
            ("proposal", text(id)?),
            ("operation", text(proposal.operation_digest)?),
            (
                "use_number",
                Value::integer(canon::json::SafeInteger::new(
                    i64::try_from(usage.context().use_number)
                        .map_err(|_| crate::refuse("consumption-mismatch"))?,
                )?),
            ),
        ])?;
        let approval = hash(&standing.canonical_bytes());
        let body = outcome_body(&proposal, ProposalState::Consumed, Some(approval), None)?;
        let ValueView::Object(fields) = body.view() else {
            return Err(crate::refuse("consumption-mismatch"));
        };
        let mut fields = fields.to_vec();
        fields.push(("standing".into(), standing));
        let row = authority_row(
            &transaction,
            &proposal,
            Kind::GateConsume,
            Phase::Settle,
            now,
            Value::object(fields)?,
        )?;
        transaction.append_standing(usage, row)?;
        crash.at(CrashPoint::AfterConsumption)?;
        crash.at(CrashPoint::AfterAppend)?;
        let consumed = load(&transaction, id)?;
        if consumed.state != ProposalState::Consumed
            || recovery_work(&transaction, &consumed)?.consumed_approval != approval
        {
            return Err(crate::refuse("consumption-mismatch"));
        }
        commit(transaction, crash)?;
        self.effect_once(id, approval, crash)
    }

    pub(super) fn effect_once(
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
        if proposal.authority.epoch != transaction.current_version()?.epoch {
            return Err(crate::refuse("owner-epoch-changed"));
        }
        let target = self
            .config
            .targets
            .iter()
            .find(|target| target.id == proposal.request.target)
            .ok_or(crate::refuse("unknown-target"))?;
        if target.class != TargetClass::Content
            || proposal.request.new_bytes.len() > target.max_bytes
        {
            return Err(crate::refuse("unsupported-operation"));
        }
        let work = recovery_work(&transaction, &proposal)?;
        if work.consumed_approval != approval {
            return Err(crate::refuse("consumption-mismatch"));
        }
        transaction.check_target_consumption(id, approval)?;
        let before = self.targets.observe(&proposal.request.target);
        if let Ok(observed) = &before {
            check_observation(observed)?;
        }
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
                check_observation(&observed)?;
                applied = observed.digest == BaseDigest::Present(proposal.new_digest)
                    && observed.bytes.as_ref() == Some(&proposal.request.new_bytes);
            }
        }
        let result = settle(
            &mut transaction,
            &self.targets,
            &proposal,
            approval,
            applied,
            crash,
        )?;
        commit(transaction, crash)?;
        Ok(result)
    }
}
