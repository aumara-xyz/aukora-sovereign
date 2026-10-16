// SPDX-License-Identifier: AGPL-3.0-or-later
//! An install floor may use its release proposal as ordering evidence.

use super::*;

pub(super) fn release_proposal_source(
    current: Option<&ProtectedState>,
    proposed: &ReleaseOrder,
    source: &AuthorityRecord,
    proposal: &aura::storage::ProposalState,
) -> Result<bool> {
    let Some(install) = current.filter(|state| state.is_install_genesis()) else {
        return Ok(false);
    };
    if source.kind != Kind::GatePropose {
        return Ok(false);
    }
    install.validate()?;
    let body = payload(&source.body)?;
    if install.floor.digest != proposed.digest
        || proposed.ledger_seq <= install.floor.ledger_seq
        || source.authority != proposal.authority
        || source.authority.epoch != proposed.signer_epoch
        || source.authority.sequence != proposed.ledger_seq
        || source.hash != proposed.ledger_hash
        || source.phase != Phase::Intent
        || source.operation != Some(proposal.operation)
        || source.actor != "supervisor"
        || proposal.actor != "supervisor"
        || proposal.target != "release"
        || proposal.base_sha256 != canon::authority::BaseDigest::Present(install.floor.digest)
        || proposal.risk != canon::authority::CardRisk::Critical
        || proposal.cell.is_some()
        || proposal.evidence_source.is_some()
        || proposal.evidence_digest != Digest32::from_bytes([0; 32])
        || proposal.prior_reviewed_batch.is_some()
        || !proposal.model_note.is_empty()
        || Digest32::sha256(&proposal.new_bytes) != proposed.record
        || field_text(body, "proposal") != Some(proposal.proposal.to_string().as_str())
        || field_text(body, "target") != Some("release")
        || field_text(body, "operation") != Some(proposal.operation_digest.to_string().as_str())
    {
        return Err(refuse("ordering-evidence"));
    }
    release_pointer(&proposal.new_bytes, install.floor.digest)?;
    Ok(true)
}
