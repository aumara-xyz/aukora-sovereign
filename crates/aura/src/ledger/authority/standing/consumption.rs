// SPDX-License-Identifier: AGPL-3.0-or-later
//! Standing consumption binds the retained grant to one recoverable target effect.

use super::*;

const PROOF_SCHEMA: &str = "aukora-aura-standing-consumption-v1";

pub(super) fn descriptor(
    grant: &Grant,
    proposal: &storage::ProposalState,
    count: u64,
) -> Result<Value> {
    object(vec![
        ("permission", text(grant.proposal.operation)?),
        ("permission_proposal", text(grant.stored.permission)?),
        ("permission_digest", text(grant.stored.digest)?),
        ("proposal", text(proposal.proposal)?),
        ("operation", text(proposal.operation_digest)?),
        ("use_number", number(count)?),
    ])
}

pub(super) fn body(
    proposal: &storage::ProposalState,
    standing: Value,
    approval: Digest32,
) -> Result<Value> {
    let base = match proposal.base_sha256 {
        canon::authority::BaseDigest::Absent => "absent".to_owned(),
        canon::authority::BaseDigest::Present(hash) => hash.to_string(),
    };
    object(vec![
        ("proposal", text(proposal.proposal)?),
        ("target", text(&proposal.target)?),
        ("operation", text(proposal.operation_digest)?),
        ("base_sha256", text(base)?),
        ("new_sha256", text(Digest32::sha256(&proposal.new_bytes))?),
        ("state", text("consumed")?),
        ("retry", Value::boolean(false)),
        ("consumed_approval", text(approval)?),
        ("standing", standing),
    ])
}

pub(super) fn proof(standing: Value) -> Result<Value> {
    object(vec![
        ("schema", text(PROOF_SCHEMA)?),
        ("standing", standing),
    ])
}

impl LedgerTxn<'_> {
    pub(in super::super) fn verify_standing_target_consumption(
        &self,
        proposal: &storage::ProposalState,
        approval: Digest32,
        record: &AuthorityRecord,
    ) -> Result<AuthorityRecord> {
        let standing = member(gate_payload(&record.body), "standing")?;
        let permission = ProposalId::from_hex(text_field(standing, "permission_proposal")?)?;
        let digest = Digest32::from_hex(text_field(standing, "permission_digest")?)?;
        let grant = self.standing_grant(&permission, digest)?;
        let use_number = unsigned_field(standing, "use_number")?;
        if use_number == 0 || !grant.permission.enabled {
            return Err(refusal("standing-consumption"));
        }
        self.check_standing_consumption(&grant, proposal, record, use_number)?;
        if field(gate_payload(&record.body), "consumed_approval")
            != Some(approval.to_string().as_str())
        {
            return Err(refusal("standing-consumption"));
        }
        let (count, _) = self.standing_history(&grant, self.services.clock.now_ms()?)?;
        if count < use_number {
            return Err(refusal("standing-consumption"));
        }
        Ok(record.clone())
    }

    pub(super) fn check_standing_consumption(
        &self,
        grant: &Grant,
        proposal: &storage::ProposalState,
        record: &AuthorityRecord,
        count: u64,
    ) -> Result<()> {
        let standing = descriptor(grant, proposal, count)?;
        let approval = Digest32::sha256(&standing.canonical_bytes());
        if record.kind != Kind::GateConsume
            || record.phase != Phase::Settle
            || record.actor != "owner"
            || record.operation != Some(proposal.operation)
            || record.authority.epoch != proposal.authority.epoch
            || gate_payload(&record.body) != &body(proposal, standing.clone(), approval)?
        {
            return Err(refusal("standing-consumption"));
        }
        let retained: i64 = self.transaction.query_row(
            "SELECT count(*) FROM authority_consumptions WHERE approval=?1 AND proposal=?2 AND operation=?3 AND epoch=?4 AND sequence=?5 AND previous_hash IS ?6 AND proof=?7 AND credential='' AND counter=0 AND action='apply' AND appended=1",
            params![approval.to_string(), proposal.proposal.to_string(), proposal.operation.to_string(),
                sql_number(record.authority.epoch)?, sql_number(record.authority.sequence)?,
                record.authority.previous_hash.map(|hash| hash.to_string()), proof(standing)?.canonical_bytes()],
            |row| row.get(0),
        ).map_err(sql)?;
        if retained != 1 {
            return Err(refusal("standing-consumption"));
        }
        let terminal = self.gate_terminal(&proposal.operation)?;
        match proposal.status {
            ProposalStatus::Consumed if terminal.is_none() => Ok(()),
            ProposalStatus::Applied | ProposalStatus::Incomplete | ProposalStatus::Failed
            | ProposalStatus::Conflict | ProposalStatus::Unknown => {
                let terminal = terminal.ok_or(refusal("standing-consumption"))?;
                let expected_kind = if proposal.status == ProposalStatus::Applied {
                    Kind::GateApply
                } else {
                    Kind::GateRecover
                };
                if terminal.kind != expected_kind || terminal.phase != Phase::Terminal
                    || terminal.actor != "gate" || terminal.authority.epoch != record.authority.epoch
                    || terminal.authority.sequence <= record.authority.sequence
                    || terminal.at < record.at
                {
                    return Err(refusal("standing-consumption"));
                }
                bind_gate_body(gate_payload(&terminal.body), proposal, approval, proposal.status.wire_name())
            }
            _ => Err(refusal("standing-consumption")),
        }
    }
}
