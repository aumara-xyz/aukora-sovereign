// SPDX-License-Identifier: AGPL-3.0-or-later
//! Only the latest retriable terminal may offer the owner's Ask again action.

use canon::{ids::ProposalId, Result};

pub(super) fn review_state(txn: &aura::LedgerTxn<'_>, id: ProposalId) -> Result<()> {
    let stored = txn.proposal(&id)?;
    if stored.target != "release" && !stored.target.starts_with(crate::engine::TARGET_PREFIX) {
        return Ok(());
    }
    if txn.last_decline(stored.operation_digest)?.is_some_and(|row| row.proposal == id) {
        return Err(canon::Refusal { organ: "gate", reason: "declined-retryable" });
    }
    if txn.last_expiry(stored.operation_digest)?.is_some_and(|(proposal, _)| proposal == id) {
        return Err(canon::Refusal { organ: "gate", reason: "expired-retryable" });
    }
    Ok(())
}
