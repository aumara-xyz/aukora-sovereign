// SPDX-License-Identifier: AGPL-3.0-or-later
//! The owner's slider changes share the gate worker with passkey consumption.
use super::*;
use canon::digest::Digest32;
use laya::{SliderPolicy, SliderSetting};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SliderChange {
    Applied(SliderSetting),
    Pending {
        setting: SliderSetting,
        proposal: ProposalId,
    },
}

impl GateAdapter {
    /// The same durable policy used by owner actions, with applied target bytes
    /// authenticated against the gate's observation. A failed read is never a default.
    pub fn slider_policy(&self) -> ServiceFuture<'_, SliderPolicy> {
        self.submit(move |gate, host| {
            host.transaction(|txn| checked_state(txn, gate).map(|state| state.policy))
        })
    }

    pub fn set_slider(
        &self,
        scope: PrincipalScope,
        setting: SliderSetting,
    ) -> ServiceFuture<'_, SliderChange> {
        self.submit(move |gate, host| {
            host.scoped(scope, |txn| {
                let state = checked_state(txn, gate)?;
                let previous = state.policy.setting;
                if setting == previous {
                    return Ok(SliderChange::Applied(setting));
                }
                // Expire a lapsed slider card before deciding whether to reuse
                // it. A stale pending row must not block tightening or retry.
                for pending in txn
                    .pending_proposals(10_001)?
                    .into_iter()
                    .filter(|row| row.target == laya::slider::POLICY_TARGET)
                {
                    gate.reconcile(txn, pending.proposal, &mut NoInjection)?;
                }
                let mut policy = state.policy.clone();
                policy.setting = setting;
                if !policy.loosens(previous) {
                    // A queued assertion sees these proposals already declined. The
                    // worker never interleaves tightening between consume and effect.
                    for pending in txn
                        .pending_proposals(10_001)?
                        .into_iter()
                        .filter(|row| row.target == laya::slider::POLICY_TARGET)
                    {
                        gate.decline(txn, pending.proposal)?;
                    }
                    super::super::slider::tighten(txn, &state, setting)?;
                    return Ok(SliderChange::Applied(setting));
                }
                let bytes = policy.canonical_bytes()?;
                if let Some(pending) = txn
                    .pending_proposals(10_001)?
                    .into_iter()
                    .find(|row| row.target == laya::slider::POLICY_TARGET)
                {
                    if pending.new_bytes == bytes {
                        return Ok(SliderChange::Pending {
                            setting: previous,
                            proposal: pending.proposal,
                        });
                    }
                    return Err(refuse("awaiting-other-approval"));
                }
                let base = gate
                    .target_store()
                    .observe(&TargetId::new(laya::slider::POLICY_TARGET.into())?)?
                    .digest;
                let mut request = policy.proposal(base)?;
                request.model_note = format!(
                    "Change the slider from {} to {}.",
                    previous.wire_name(),
                    setting.wire_name()
                );
                request.new_evidence = state.tightening.clone();
                let proposed = match gate.propose(txn, request.clone(), &mut NoInjection) {
                    Ok(proposal) => proposal.id,
                    Err(refusal)
                        if matches!(
                            refusal.reason,
                            "declined-unchanged"
                                | "unchanged-decline"
                                | "evidence-unchanged"
                                | "recently-expired"
                        ) =>
                    {
                        let digest = gate::proposal::request_digest(gate.config().node, &request)?;
                        let declined = match txn.last_decline(digest)? {
                            Some(declined) => declined.proposal,
                            None => txn.last_expiry(digest)?.map(|(id, _)| id).ok_or(refusal)?,
                        };
                        // The retry inherits that card's evidence. If the slider was tightened since, it no longer
                        // names the current tightening, and approving it would leave the policy unreadable: keep the
                        // original refusal (the same bytes can be asked for once the hold ends).
                        let linked = txn.proposal(&declined)?;
                        if !super::super::slider::policy_evidence_matches(txn, &linked, state.tightening.as_ref())? {
                            return Err(refusal);
                        }
                        propose_again_in(
                            txn,
                            gate,
                            declined,
                            request.target,
                            base,
                            request.model_note,
                            request.new_bytes,
                        )?
                    }
                    Err(refusal) => return Err(refusal),
                };
                Ok(SliderChange::Pending {
                    setting: previous,
                    proposal: proposed,
                })
            })
        })
    }
}

fn checked_state(
    txn: &mut aura::LedgerTxn<'_>,
    gate: &ScopedGate<ConfinedStore>,
) -> Result<super::super::slider::PolicyState> {
    let state = super::super::slider::current_state(txn)?;
    let observed = gate
        .target_store()
        .observe(&TargetId::new(laya::slider::POLICY_TARGET.into())?)?;
    match (
        observed.digest,
        observed.bytes.as_deref(),
        state.applied.as_deref(),
    ) {
        (BaseDigest::Absent, None, None) => {}
        (BaseDigest::Present(digest), Some(bytes), Some(applied))
            if bytes == applied && Digest32::sha256(bytes) == digest => {}
        _ => return Err(refuse("slider-observation-mismatch")),
    }
    Ok(state)
}

#[cfg(test)]
mod tests;
