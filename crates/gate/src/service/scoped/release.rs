// SPDX-License-Identifier: AGPL-3.0-or-later
//! Installed release proposals bind a floor digest and the exact pointer bytes.

use super::*;

impl<S: TargetStore> ScopedGate<S> {
    pub fn propose_release(
        &mut self,
        txn: &mut LedgerTxn<'_>,
        base: Digest32,
        installed: Digest32,
        crash: &mut dyn CrashInjector,
    ) -> Result<Proposal> {
        coverage::lookup(EntryPoint::Release, EffectRoute::FloorAdvance)?;
        crash.at(CrashPoint::BeforeProposal)?;
        txn.gate_owner_subject()?;
        let request = release_request(base, installed)?;
        let pending_rows = txn.pending_proposals(10_001)?;
        if pending_rows.len() > 10_000 {
            return Err(crate::refuse("recovery-limit"));
        }
        let mut retained = None;
        for stored in pending_rows {
            if stored.target != "release" {
                continue;
            }
            let existing = load(txn, stored.proposal)?;
            validate_content(self.config.node, &existing)?;
            validate_origin(txn, &existing)?;
            pending(txn, &existing)?;
            if retained.is_some() || existing.request != request {
                return Err(crate::refuse("release-proposal-conflict"));
            }
            retained = Some(existing);
        }
        if let Some(existing) = retained {
            crash.at(CrashPoint::AfterProposal)?;
            return Ok(existing);
        }
        let at = now(txn)?;
        if at == MAX_SAFE_INTEGER {
            return Err(crate::refuse("clock"));
        }
        let proposal = Proposal {
            id: ProposalId::from_bytes(random()?),
            operation_id: OperationId::from_bytes(random()?),
            operation_digest: proposal::content_digest(self.config.node, &request)?,
            authority: txn.current_version()?,
            new_digest: hash(&request.new_bytes),
            risk: crate::RiskTier::Critical,
            request,
            state: ProposalState::Pending,
            created_at_ms: at,
            expires_at_ms: MAX_SAFE_INTEGER,
        };
        validate_release(&proposal)?;
        let mut stored = proposal::to_stored(&proposal)?;
        stored.actor = "supervisor".into();
        txn.stage_proposal(stored)?;
        let mut record = lifecycle(
            txn,
            &proposal,
            LifecycleKind::GatePropose,
            Phase::Intent,
            at,
            proposal::lifecycle_body(&proposal)?,
        )?;
        record.actor = "supervisor".into();
        txn.append_lifecycle(record)?;
        crash.at(CrashPoint::AfterProposal)?;
        Ok(proposal)
    }
}

impl<S: TargetStore> ScopedGate<S> {
    /// Withdraw a pending release card the supervisor no longer offers (the operator took the offer back or offered
    /// another release). Recorded as an expiry with reason `withdrawn`: not the owner's decline, so the same step can
    /// be raised again if it is offered again (NODE.md O17, O19). A card the owner is reviewing right now is left
    /// until that review lapses (`false`): the decision is the owner's to finish or drop. Once it has lapsed, the
    /// card is withdrawn on the next call.
    pub fn withdraw_release(&mut self, txn: &mut LedgerTxn<'_>, id: ProposalId) -> Result<bool> {
        let proposal = load(txn, id)?;
        validate_content(self.config.node, &proposal)?;
        validate_origin(txn, &proposal)?;
        if proposal.state != ProposalState::Pending {
            return Ok(true);
        }
        // A live review keeps the card; a review whose ceremony lapsed is removed (as Review does) and the card is
        // withdrawn. An unreadable or spent review still refuses, so withdrawal never hides a broken record.
        if txn.read_or_expire_release_review(id)?.is_some() {
            return Ok(false);
        }
        let at = now(txn)?;
        let body = outcome_body(&proposal, ProposalState::Expired, None, None)?;
        let ValueView::Object(fields) = body.view() else {
            return Err(crate::refuse("terminal-body"));
        };
        let mut fields = fields.to_vec();
        fields.push(("reason".into(), text("withdrawn")?));
        let row = lifecycle(
            txn,
            &proposal,
            LifecycleKind::GateExpire,
            Phase::Terminal,
            at,
            Value::object(fields)?,
        )?;
        txn.append_lifecycle(row)?;
        txn.release_reservation(&id)?;
        Ok(true)
    }
}

fn release_request(base: Digest32, installed: Digest32) -> Result<ProposalRequest> {
    Ok(ProposalRequest {
        target: crate::target::TargetId::new("release".into())?,
        base: BaseDigest::Present(base),
        new_bytes: object(vec![
            ("v", Value::integer(canon::json::SafeInteger::new(1)?)),
            ("digest", text(installed)?),
        ])?
        .canonical_bytes(),
        model_note: String::new(),
        cell: None,
        new_evidence: None,
        suggestion: SuggestionOrder::Single,
    })
}

/// The operation digest of the release proposal from the floor at `base` to `installed`: the same bytes always give
/// the same digest, so the supervisor can ask whether the owner declined exactly this step (NODE.md O19).
pub fn release_operation_digest(
    node: NodeId,
    base: Digest32,
    installed: Digest32,
) -> Result<canon::ids::OperationDigest> {
    proposal::content_digest(node, &release_request(base, installed)?)
}

pub(super) fn validate_origin(txn: &LedgerTxn<'_>, proposal: &Proposal) -> Result<()> {
    validate_release(proposal)?;
    let stored = txn.proposal(&proposal.id)?;
    let source = txn.record_at(stored.authority)?;
    if stored.actor != "supervisor"
        || source.actor != "supervisor"
        || proposal::from_stored(stored, &source)? != *proposal
    {
        return Err(crate::refuse("unsupported-operation"));
    }
    Ok(())
}

pub(super) fn validate_release(proposal: &Proposal) -> Result<Digest32> {
    if proposal.request.target.as_str() != "release"
        || !matches!(proposal.request.base, BaseDigest::Present(_))
        || proposal.risk != crate::RiskTier::Critical
        || proposal.request.cell.is_some()
        || proposal.request.new_evidence.is_some()
        || !proposal.request.model_note.is_empty()
        || proposal.request.suggestion != SuggestionOrder::Single
    {
        return Err(crate::refuse("unsupported-operation"));
    }
    let pointer = canon::json::parse_strict(&proposal.request.new_bytes)?;
    let ValueView::Object(fields) = pointer.view() else {
        return Err(crate::refuse("release-pointer"));
    };
    if pointer.canonical_bytes() != proposal.request.new_bytes
        || fields.len() != 2
        || !matches!(pointer.get("v").map(Value::view), Some(ValueView::Integer(v)) if v.get() == 1)
    {
        return Err(crate::refuse("release-pointer"));
    }
    let Some(ValueView::Text(digest)) = pointer.get("digest").map(Value::view) else {
        return Err(crate::refuse("release-pointer"));
    };
    Digest32::from_hex(digest).map_err(|_| crate::refuse("release-pointer"))
}

pub(super) fn release_facts(proposal: &Proposal) -> Result<ReviewFacts> {
    let installed = validate_release(proposal)?;
    // From the install's floor to the release it recorded (genesis), or from the owner's floor to another release
    // (an upgrade the operator offered: the node keeps running the current one until this is approved).
    let says = if proposal.request.base == BaseDigest::Present(installed) {
        "Approve the installed release as the owner's release floor."
    } else {
        "Upgrade this node to a new release: it becomes the owner's release floor and the node switches to it."
    };
    Ok(ReviewFacts {
        says: says.into(),
        facts: vec![
            ("target".into(), text("release")?),
            ("base_sha256".into(), base_value(proposal.request.base)?),
            ("release_sha256".into(), text(installed)?),
            ("new_sha256".into(), text(proposal.new_digest)?),
        ],
        from_to: vec![
            ("base_sha256".into(), base_value(proposal.request.base)?),
            ("release_sha256".into(), text(installed)?),
            (
                "new_bytes_b64".into(),
                text(encode_bytes(&proposal.request.new_bytes))?,
            ),
        ],
    })
}
