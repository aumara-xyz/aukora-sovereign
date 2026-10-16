// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery observes retained consumption without issuing an effect permit.

use super::*;

impl<S: TargetStore> ScopedGate<S> {
    pub fn recover(
        &mut self,
        txn: &mut LedgerTxn<'_>,
        crash: &mut dyn CrashInjector,
    ) -> Result<RecoverySweep> {
        crash.at(CrashPoint::BeforeRecovery)?;
        let pending_rows = txn.pending_proposals(10_001)?;
        let interrupted = txn.recovery_work(10_001)?;
        if pending_rows.len() > 10_000 || interrupted.len() > 10_000 {
            return Err(crate::refuse("recovery-limit"));
        }
        let at = now(txn)?;
        let epoch = txn.current_version()?.epoch;
        let mut ids = std::collections::BTreeSet::new();
        for stored in pending_rows {
            let row = txn.record_at(stored.authority)?;
            let proposal = proposal::from_stored(stored, &row)?;
            if proposal.state == ProposalState::Pending
                && (proposal.expires_at_ms <= at || proposal.authority.epoch != epoch)
            {
                ids.insert(proposal.id);
            }
        }
        ids.extend(interrupted.into_iter().map(|work| work.proposal));
        let mut sweep = RecoverySweep::default();
        for id in ids {
            let result = self.reconcile(txn, id, crash)?;
            if result.state == ProposalState::Pending {
                continue;
            }
            let proposal = load(txn, id)?;
            let terminal = txn
                .gate_terminal(&proposal.operation_id)?
                .ok_or(crate::refuse("missing-terminal"))?;
            sweep.settled.push(RecoveryResult {
                proposal: id,
                state: result.state,
                terminal: terminal.authority,
                target_released: true,
            });
        }
        crash.at(CrashPoint::AfterRecovery)?;
        Ok(sweep)
    }

    pub fn reconcile(
        &mut self,
        txn: &mut LedgerTxn<'_>,
        id: ProposalId,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        crash.at(CrashPoint::BeforeReconcile)?;
        let proposal = load(txn, id)?;
        validate_content(self.config.node, &proposal)?;
        let result = match proposal.state {
            state if state.is_terminal() => {
                let result = terminal_outcome(txn, &proposal)?;
                txn.release_reservation(&id)?;
                result
            }
            ProposalState::Pending => {
                if proposal.authority.epoch != txn.current_version()?.epoch {
                    crash.at(CrashPoint::BeforeTerminal)?;
                    let receipt = txn.refuse_stale_pending(id)?;
                    txn.release_reservation(&id)?;
                    crash.at(CrashPoint::AfterTerminal)?;
                    outcome(&proposal, ProposalState::Refused, receipt.hash)
                } else if now(txn)? >= proposal.expires_at_ms {
                    self.expire_pending(txn, &proposal, crash)?
                } else {
                    outcome(
                        &proposal,
                        ProposalState::Pending,
                        txn.record_at(proposal.authority)?.hash,
                    )
                }
            }
            ProposalState::Consumed => {
                let consumed = recovery_work(txn, &proposal)?;
                settle(
                    txn,
                    &self.targets,
                    &proposal,
                    consumed.consumed_approval,
                    false,
                    crash,
                )?
            }
            _ => return Err(crate::refuse("settlement-state")),
        };
        crash.at(CrashPoint::AfterReconcile)?;
        Ok(result)
    }

    fn expire_pending(
        &self,
        txn: &mut LedgerTxn<'_>,
        proposal: &Proposal,
        crash: &mut dyn CrashInjector,
    ) -> Result<Outcome> {
        crash.at(CrashPoint::BeforeExpire)?;
        crash.at(CrashPoint::BeforeTerminal)?;
        let at = now(txn)?;
        let row = lifecycle(
            txn,
            proposal,
            LifecycleKind::GateExpire,
            Phase::Terminal,
            at,
            outcome_body(proposal, ProposalState::Expired, None, None)?,
        )?;
        let receipt = txn.append_lifecycle(row)?;
        txn.release_reservation(&proposal.id)?;
        crash.at(CrashPoint::AfterTerminal)?;
        crash.at(CrashPoint::AfterExpire)?;
        Ok(outcome(proposal, ProposalState::Expired, receipt.hash))
    }
}
