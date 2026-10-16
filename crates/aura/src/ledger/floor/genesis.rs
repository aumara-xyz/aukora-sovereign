// SPDX-License-Identifier: AGPL-3.0-or-later
//! The first owner release uses a signed proposal only as ordering data.

use super::*;

pub(super) fn release_proposal_source(
    current: Option<&Value>,
    next: &Value,
    source: &AuthorityRecord,
    proposal: &crate::storage::ProposalState,
) -> Result<bool> {
    let Some(install) = current else {
        return Ok(false);
    };
    if field_text(install, "schema")? != INSTALL_STATE || source.kind != Kind::GatePropose {
        return Ok(false);
    }
    let installed = member(install, "floor")?;
    let floor = member(next, "floor")?;
    let payload = super::super::gate_payload(&source.body);
    if hash(installed, "digest")? != hash(floor, "digest")?
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
    release_pointer(&proposal.new_bytes, hash(installed, "digest")?)?;
    Ok(true)
}
