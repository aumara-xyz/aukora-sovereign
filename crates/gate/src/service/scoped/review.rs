// SPDX-License-Identifier: AGPL-3.0-or-later
//! Review cards are committed with the exact rebuilt C5 authorization.

use super::*;

impl<S: TargetStore> ScopedGate<S> {
    pub fn review(
        &mut self,
        txn: &mut LedgerTxn<'_>,
        id: ProposalId,
        action: OwnerOperation,
        crash: &mut dyn CrashInjector,
    ) -> Result<OwnerReview> {
        crash.at(CrashPoint::BeforeReview)?;
        if !matches!(
            action,
            OwnerOperation::Apply | OwnerOperation::Retire | OwnerOperation::Release
        ) {
            return Err(crate::refuse("unsupported-operation"));
        }
        let proposal = load(txn, id)?;
        let release = proposal.request.target.as_str() == "release";
        if release {
            validate_content(self.config.node, &proposal)?;
            release::validate_origin(txn, &proposal)?;
            if action == OwnerOperation::Apply {
                return Err(crate::refuse("unsupported-operation"));
            }
        } else {
            if action == OwnerOperation::Release {
                return Err(crate::refuse("unsupported-operation"));
            }
            self.validate(&proposal, action == OwnerOperation::Apply)?;
        }
        if action == OwnerOperation::Retire {
            proposal.state.require_retirable()?;
        }
        pending(txn, &proposal)?;
        let before = if release {
            TargetObservation {
                digest: proposal.request.base,
                bytes: None,
            }
        } else {
            self.observe(&proposal.request.target)?
        };
        if action == OwnerOperation::Apply && before.digest != proposal.request.base {
            return Err(crate::refuse("stale-base"));
        }
        let stored_review = if action == OwnerOperation::Release {
            txn.read_or_expire_release_review(id)?
        } else {
            txn.read_live_review(id, action)?
        };
        if let Some(stored) = stored_review {
            let card = if action == OwnerOperation::Release {
                card::restore_release_card(&proposal, stored.card)?
            } else {
                DisplayedCard::from_stored_review(&proposal, action, stored.card)?
            };
            let authorization = review_authorization(
                &proposal,
                action,
                &card,
                CeremonyContext {
                    node: self.config.node,
                    subject: txn.gate_owner_subject()?,
                    epoch: txn.current_version()?.epoch,
                    challenge: stored.authorization.challenge,
                    expires_at_ms: stored.authorization.expires_at,
                },
            )?;
            if authorization != stored.authorization {
                return Err(crate::refuse("authorization-mismatch"));
            }
            crash.at(CrashPoint::AfterReview)?;
            return Ok(OwnerReview {
                proposal: id,
                action,
                authorization_bytes: authorization.canonical_bytes()?,
                passkey_challenge: card::passkey_challenge(&authorization)?,
                card,
            });
        }
        let facts = if action == OwnerOperation::Release {
            release::release_facts(&proposal)?
        } else if action == OwnerOperation::Apply
            && proposal.request.target.as_str().starts_with("sites/")
        {
            site_facts(&self.config, &proposal)?
        } else if action == OwnerOperation::Apply
            && proposal.request.target.as_str().starts_with(crate::door::TARGET_PREFIX)
        {
            door_facts(&proposal)?
        } else {
            content_facts(&proposal, action, &before)?
        };
        let card = if action == OwnerOperation::Release {
            card::build_release_card(&proposal, facts)?
        } else {
            card::build_card(&proposal, action, facts)?
        };
        let at = now(txn)?;
        let auth = review_authorization(
            &proposal,
            action,
            &card,
            CeremonyContext {
                node: self.config.node,
                subject: txn.gate_owner_subject()?,
                epoch: txn.current_version()?.epoch,
                challenge: AuthorizationChallenge::from_bytes(random()?),
                expires_at_ms: deadline(at, self.config.ceremony_lifetime_ms)?
                    .min(proposal.expires_at_ms),
            },
        )?;
        let authorization_bytes = auth.canonical_bytes()?;
        let passkey_challenge = card::passkey_challenge(&auth)?;
        txn.stage_authorization(aura::storage::StagedAuthorization {
            authorization: auth,
            card: card.card().clone(),
        })?;
        let row = lifecycle(
            txn,
            &proposal,
            LifecycleKind::GateReview,
            Phase::Settle,
            at,
            object(vec![
                ("proposal", text(id)?),
                ("action", text(action.wire_name())?),
                ("display_sha256", text(card.digest())?),
                ("authorization_sha256", text(hash(&authorization_bytes))?),
            ])?,
        )?;
        if action == OwnerOperation::Release {
            txn.append_release_review(row)?;
        } else {
            txn.append_lifecycle(row)?;
        }
        crash.at(CrashPoint::AfterReview)?;
        Ok(OwnerReview {
            proposal: id,
            action,
            card,
            authorization_bytes,
            passkey_challenge,
        })
    }
}

fn review_authorization(
    proposal: &Proposal,
    action: OwnerOperation,
    card: &DisplayedCard,
    context: CeremonyContext,
) -> Result<canon::authority::OwnerAuthorization> {
    if action == OwnerOperation::Release {
        card::release_authorization(proposal, card, context)
    } else {
        card::authorization(proposal, action, card, context)
    }
}

fn content_facts(
    proposal: &Proposal,
    action: OwnerOperation,
    before: &TargetObservation,
) -> Result<ReviewFacts> {
    let mut facts = ReviewFacts {
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
    if let Some(cell) = proposal.request.cell {
        facts.facts.push((
            "cell".into(),
            object(vec![
                ("module_sha256", text(cell.module_sha256)?),
                ("input_sha256", text(cell.input_sha256)?),
                ("effect_sha256", text(cell.effect_sha256)?),
            ])?,
        ));
    }
    if let Some(bytes) = &before.bytes {
        if let Ok(value) = std::str::from_utf8(bytes) {
            facts.from_to.push(("before".into(), text(value)?));
        }
    }
    if let Ok(value) = std::str::from_utf8(&proposal.request.new_bytes) {
        facts.from_to.push(("after".into(), text(value)?));
    }
    Ok(facts)
}

/// The card for a door ask. Every fact is read back from the bytes the owner's passkey covers.
fn door_facts(proposal: &Proposal) -> Result<ReviewFacts> {
    let record = crate::door::read(&proposal.request.new_bytes)?;
    let mut from_to = vec![
        ("base_sha256".into(), base_value(proposal.request.base)?),
        ("new_bytes_b64".into(), text(encode_bytes(&proposal.request.new_bytes))?),
    ];
    if let Ok(after) = std::str::from_utf8(&proposal.request.new_bytes) {
        from_to.push(("after".into(), text(after)?));
    }
    Ok(ReviewFacts {
        says: "Let the engine run this one call, exactly as displayed.".into(),
        facts: vec![
            ("target".into(), text(proposal.request.target.as_str())?),
            ("tool".into(), text(&record.tool)?),
            ("class".into(), text(&record.class)?),
            ("call_sha256".into(), text(&record.digest_sha256)?),
            ("new_sha256".into(), text(proposal.new_digest)?),
        ],
        from_to,
    })
}

fn site_facts(config: &GateConfig, proposal: &Proposal) -> Result<ReviewFacts> {
    let bundle = crate::target::sites::validate(config, proposal)?;
    Ok(ReviewFacts {
        says: "Publish this exact website bundle at the displayed address.".into(),
        facts: vec![
            (
                "address".into(),
                text(format!("https://{}/", bundle.host()))?,
            ),
            ("target".into(), text(proposal.request.target.as_str())?),
            ("bundle_sha256".into(), text(bundle.digest())?),
            (
                "isolation".into(),
                text("Separate host; no cookies or WebAuthn; framing refused.")?,
            ),
        ],
        from_to: vec![
            ("base_sha256".into(), base_value(proposal.request.base)?),
            (
                "new_bytes_b64".into(),
                text(encode_bytes(&proposal.request.new_bytes))?,
            ),
        ],
    })
}
