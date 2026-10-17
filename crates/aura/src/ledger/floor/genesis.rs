// SPDX-License-Identifier: AGPL-3.0-or-later
//! A release proposal from the supervisor is ordering data for the floor it starts from: the install's floor for the
//! installed release (genesis), an owner's floor for the next release (an upgrade, NODE.md O17).

use super::*;

pub(super) fn release_proposal_source(
    current: Option<&Value>,
    next: &Value,
    source: &AuthorityRecord,
    proposal: &crate::storage::ProposalState,
) -> Result<bool> {
    let Some(current) = current else {
        return Ok(false);
    };
    if source.kind != Kind::GatePropose {
        return Ok(false);
    }
    let genesis = field_text(current, "schema")? == INSTALL_STATE;
    let installed = member(current, "floor")?;
    let floor = member(next, "floor")?;
    let payload = super::super::gate_payload(&source.body);
    // Genesis approves the installed release itself; an upgrade names another one.
    let same = hash(installed, "digest")? == hash(floor, "digest")?;
    if same != genesis
        || source.authority != proposal.authority
        || source.authority.epoch != positive(floor, "signer_epoch")?
        || source.authority.sequence != positive(floor, "ledger_seq")?
        || source.authority.sequence <= positive(installed, "ledger_seq")?
        || source.authority.sequence >= authority(member(next, "authority")?)?.sequence
        || source.hash != hash(floor, "ledger_hash")?
        || source.phase != Phase::Intent
        || source.operation != Some(proposal.operation)
        || source.actor != "supervisor"
        || proposal.actor != "supervisor"
        || proposal.target != "release"
        || proposal.base_sha256 != canon::authority::BaseDigest::Present(hash(installed, "digest")?)
        || proposal.risk != canon::authority::CardRisk::Critical
        || proposal.cell.is_some()
        || proposal.evidence_source.is_some()
        || proposal.evidence_digest != Digest32::from_bytes([0; 32])
        || proposal.prior_reviewed_batch.is_some()
        || !proposal.model_note.is_empty()
        || Digest32::sha256(&proposal.new_bytes) != hash(floor, "record")?
        || field_text(payload, "proposal")? != proposal.proposal.to_string()
        || field_text(payload, "target")? != "release"
        || field_text(payload, "operation")? != proposal.operation_digest.to_string()
    {
        return Err(refusal("floor-ordering"));
    }
    release_pointer(&proposal.new_bytes, hash(floor, "digest")?)?;
    Ok(true)
}
