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
        let request = ProposalRequest {
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
        };
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
    Ok(ReviewFacts {
        says: "Approve the installed release as the owner's release floor.".into(),
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
