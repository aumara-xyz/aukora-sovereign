// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stored proposal bytes, reservations and exact owner challenge material.
use super::*;
use crate::storage::{
    self, DeclinedProposal, OperationCoverage, ProposalState, ProposalStatus, RecoveryWork,
    StagedAuthorization,
};
use canon::{
    authority::{LifecycleRecord, OwnerAuthorization, OwnerOperation},
    ids::{OperationDigest, ProposalId},
    json::{Value, ValueView},
};
use rusqlite::{params, OptionalExtension};

impl LedgerTxn<'_> {
    pub fn stage_proposal(&mut self, proposal: ProposalState) -> Result<()> {
        self.mutate(|this| {
            if proposal.status != ProposalStatus::Pending || proposal.authority != this.current_version()?
                || proposal.target.is_empty() || proposal.actor.is_empty() { return Err(refusal("proposal-context")); }
            if let Some(version) = proposal.evidence_source { this.record_at(version)?; }
            if let Some(prior) = this.last_decline(proposal.operation_digest)? {
                if prior.evidence_digest == proposal.evidence_digest { return Err(refusal("unchanged-decline")); }
            }
            this.transaction.execute("INSERT INTO authority_proposals(id,operation,target,status,body) VALUES (?1,?2,?3,'pending',?4)",
                params![proposal.proposal.to_string(),proposal.operation.to_string(),proposal.target,storage::encode_proposal(&proposal)?]).map_err(sql)?;
            Ok(())
        })
    }

    pub fn proposal(&self, proposal: &ProposalId) -> Result<ProposalState> {
        self.active()?;
        let (body, operation, target, status): (Vec<u8>, String, String, String) = self
            .transaction
            .query_row(
                "SELECT body,operation,target,status FROM authority_proposals WHERE id=?1",
                [proposal.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(sql)?;
        let mut stored = storage::decode_proposal(&body)?;
        if stored.proposal != *proposal
            || stored.operation.to_string() != operation
            || stored.target != target
        {
            return Err(refusal("proposal-mismatch"));
        }
        stored.status = ProposalStatus::from_wire(&status)?;
        Ok(stored)
    }

    pub fn pending_proposals(&self, limit: usize) -> Result<Vec<ProposalState>> {
        self.active()?;
        let mut statement = self
            .transaction
            .prepare(
                "SELECT id FROM authority_proposals WHERE status='pending' ORDER BY rowid LIMIT ?1",
            )
            .map_err(sql)?;
        let mut cursor = statement
            .query([i64::try_from(limit).map_err(|_| refusal("limit"))?])
            .map_err(sql)?;
        let mut result = Vec::new();
        while let Some(row) = cursor.next().map_err(sql)? {
            result.push(self.proposal(&ProposalId::from_hex(
                &row.get::<_, String>(0).map_err(sql)?,
            )?)?);
        }
        Ok(result)
    }

    pub fn stage_authorization(&mut self, staged: StagedAuthorization) -> Result<()> {
        self.mutate(|this| {
            let auth = &staged.authorization;
            let proposal = this.proposal(&auth.proposal)?;
            this.match_authorization(auth, &proposal)?;
            let body = storage::encode_authorization(auth)?;
            let card = storage::encode_card(&staged.card)?;
            if Digest32::sha256(&card) != auth.display_sha256 || staged.card.risk != proposal.risk
                || staged.card.model_note != proposal.model_note || this.services.clock.now_ms()? >= auth.expires_at {
                return Err(refusal("authorization-card"));
            }
            this.transaction.execute("INSERT INTO authority_challenges(proposal,action,challenge,body,card,spent) VALUES (?1,?2,?3,?4,?5,0)",
                params![auth.proposal.to_string(),auth.op.wire_name(),auth.challenge.to_string(),body,card]).map_err(sql)?;
            Ok(())
        })
    }

    pub(super) fn match_authorization(
        &self,
        auth: &OwnerAuthorization,
        proposal: &ProposalState,
    ) -> Result<()> {
        auth.canonical_bytes()?;
        if proposal.status != ProposalStatus::Pending
            || auth.epoch != self.state.epoch
            || auth.epoch != proposal.authority.epoch
            || auth.proposal != proposal.proposal
            || auth.target != proposal.target
            || auth.operation != proposal.operation_digest
            || auth.base_sha256 != proposal.base_sha256
            || auth.new_sha256 != Digest32::sha256(&proposal.new_bytes)
            || auth.cell != proposal.cell
        {
            return Err(refusal("authorization-mismatch"));
        }
        Ok(())
    }

    pub(super) fn authorization(
        &self,
        id: &ProposalId,
        action: OwnerOperation,
    ) -> Result<OwnerAuthorization> {
        let (bytes,card,challenge,spent): (Vec<u8>,Vec<u8>,String,i64) = self.transaction.query_row(
            "SELECT body,card,challenge,spent FROM authority_challenges WHERE proposal=?1 AND action=?2",
            params![id.to_string(),action.wire_name()], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(sql)?;
        let auth = storage::decode_authorization(&bytes)?;
        let decoded_card = storage::decode_card(&card)?;
        let proposal = self.proposal(id)?;
        self.match_authorization(&auth, &proposal)?;
        if auth.proposal != *id
            || auth.op != action
            || auth.challenge.to_string() != challenge
            || spent != 0
            || auth.display_sha256 != Digest32::sha256(&card)
            || decoded_card.risk != proposal.risk
            || decoded_card.model_note != proposal.model_note
            || self.services.clock.now_ms()? >= auth.expires_at
        {
            return Err(refusal("authorization-not-live"));
        }
        Ok(auth)
    }

    pub fn last_decline(&self, operation: OperationDigest) -> Result<Option<DeclinedProposal>> {
        self.active()?;
        type DeclineRow = (String, String, String, i64, i64, Option<String>);
        let row: Option<DeclineRow> = self.transaction.query_row("SELECT proposal,evidence_digest,target,epoch,sequence,previous_hash FROM authority_declines WHERE operation_digest=?1 ORDER BY sequence DESC LIMIT 1",[operation.to_string()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(sql)?;
        row.map(|(proposal, evidence, target, epoch, sequence, previous)| {
            Ok(DeclinedProposal {
                proposal: ProposalId::from_hex(&proposal)?,
                operation_digest: operation,
                evidence_digest: Digest32::from_hex(&evidence)?,
                target,
                authority: AuthorityVersion {
                    epoch: unsigned(epoch)?,
                    sequence: unsigned(sequence)?,
                    previous_hash: previous.map(|v| Digest32::from_hex(&v)).transpose()?,
                },
            })
        })
        .transpose()
    }

    pub fn decline(
        &mut self,
        proposal: &ProposalId,
        row: LifecycleRecord,
    ) -> Result<AuthorityRecord> {
        self.mutate(|this| {
            let stored = this.proposal(proposal)?;
            if row.operation != stored.operation
                || !matches!(
                    row.kind,
                    canon::authority::LifecycleKind::GateRefuse
                        | canon::authority::LifecycleKind::GateExpire
                )
            {
                return Err(refusal("decline-context"));
            }
            this.append_lifecycle(row)
        })
    }

    pub fn recovery_work(&self, limit: usize) -> Result<Vec<RecoveryWork>> {
        self.active()?;
        let mut statement = self.transaction.prepare("SELECT p.id,c.approval,c.epoch,c.sequence,c.previous_hash FROM authority_proposals p JOIN authority_consumptions c ON c.proposal=p.id WHERE p.status='consumed' AND c.appended=1 ORDER BY c.sequence LIMIT ?1").map_err(sql)?;
        let mut cursor = statement
            .query([i64::try_from(limit).map_err(|_| refusal("limit"))?])
            .map_err(sql)?;
        let mut result = Vec::new();
        while let Some(row) = cursor.next().map_err(sql)? {
            let id = ProposalId::from_hex(&row.get::<_, String>(0).map_err(sql)?)?;
            let proposal = self.proposal(&id)?;
            let previous: Option<String> = row.get(4).map_err(sql)?;
            result.push(RecoveryWork {
                proposal: id,
                operation: proposal.operation,
                target: proposal.target,
                consumed_approval: Digest32::from_hex(&row.get::<_, String>(1).map_err(sql)?)?,
                consumed_at: AuthorityVersion {
                    epoch: unsigned(row.get(2).map_err(sql)?)?,
                    sequence: unsigned(row.get(3).map_err(sql)?)?,
                    previous_hash: previous.map(|v| Digest32::from_hex(&v)).transpose()?,
                },
                base_sha256: proposal.base_sha256,
                new_sha256: Digest32::sha256(&proposal.new_bytes),
            });
        }
        Ok(result)
    }

    pub fn release_reservation(&mut self, proposal: &ProposalId) -> Result<()> {
        self.mutate(|this| {
            let stored = this.proposal(proposal)?;
            let terminal = this
                .gate_terminal(&stored.operation)?
                .ok_or(refusal("terminal-missing"))?;
            if stored.status.holds_reservation()
                || field(gate_payload(&terminal.body), "proposal")
                    != Some(proposal.to_string().as_str())
            {
                return Err(refusal("reservation-live"));
            }
            Ok(())
        })
    }

    pub fn operation_coverage(&self, operation: &OperationId) -> Result<OperationCoverage> {
        self.active()?;
        let (intents,settlements,terminals):(i64,i64,i64) = self.transaction.query_row("SELECT count(CASE WHEN phase='intent' THEN 1 END),count(CASE WHEN phase='settle' THEN 1 END),count(CASE WHEN phase='terminal' THEN 1 END) FROM aura WHERE op=?1",[operation.to_string()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(sql)?;
        Ok(OperationCoverage {
            intents: unsigned(intents)?,
            settlements: unsigned(settlements)?,
            terminals: unsigned(terminals)?,
        })
    }

    pub(super) fn set_status(&self, id: ProposalId, status: ProposalStatus) -> Result<()> {
        if self
            .transaction
            .execute(
                "UPDATE authority_proposals SET status=?2 WHERE id=?1",
                params![id.to_string(), status.wire_name()],
            )
            .map_err(sql)?
            != 1
        {
            return Err(refusal("proposal-missing"));
        }
        Ok(())
    }
}

pub(super) fn field<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    match value.get(name)?.view() {
        ValueView::Text(v) => Some(v),
        _ => None,
    }
}

fn unsigned(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| refusal("integer-range"))
}
