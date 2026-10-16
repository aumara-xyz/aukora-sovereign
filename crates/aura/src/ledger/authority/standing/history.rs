// SPDX-License-Identifier: AGPL-3.0-or-later
//! Standing counters and revocation are checked against signed retained records.

use super::*;
use std::collections::VecDeque;

impl LedgerTxn<'_> {
    pub(super) fn standing_proposal_intent(
        &self,
        proposal: &storage::ProposalState,
        at: i64,
    ) -> Result<()> {
        let record = self.record_at(proposal.authority)?;
        let payload = gate_payload(&record.body);
        if record.kind != Kind::GatePropose
            || record.phase != Phase::Intent
            || record.operation != Some(proposal.operation)
            || record.actor != proposal.actor
            || field(payload, "proposal") != Some(proposal.proposal.to_string().as_str())
            || field(payload, "target") != Some(proposal.target.as_str())
            || field(payload, "operation") != Some(proposal.operation_digest.to_string().as_str())
            || integer(payload, "created_at_ms")? != record.at
            || record.at < 0
            || at < record.at
            || at >= integer(payload, "expires_at_ms")?
        {
            return Err(refusal("standing-proposal-context"));
        }
        Ok(())
    }

    fn standing_sequences(&self, grant: &Grant, schema: &str) -> Result<Vec<u64>> {
        let mut statement = self.transaction.prepare(
            "SELECT seq FROM aura WHERE kind='gate.apply' AND phase='terminal' AND json_extract(body,'$.payload.schema')=?1 AND json_extract(body,'$.payload.permission')=?2 ORDER BY seq",
        ).map_err(sql)?;
        let mut rows = statement
            .query(params![schema, grant.stored.permission.to_string()])
            .map_err(sql)?;
        let mut sequences = Vec::new();
        while let Some(row) = rows.next().map_err(sql)? {
            if sequences.len() >= 1_000_001 {
                return Err(refusal("standing-history-bounds"));
            }
            let sequence: i64 = row.get(0).map_err(sql)?;
            sequences.push(u64::try_from(sequence).map_err(|_| refusal("standing-history"))?);
        }
        Ok(sequences)
    }

    pub(super) fn verify_standing_revocation(&self, grant: &Grant) -> Result<()> {
        let sequences = self.standing_sequences(grant, REVOKE_SCHEMA)?;
        if sequences.len() > 1 || grant.stored.revoked != !sequences.is_empty() {
            return Err(refusal("standing-revocation-mismatch"));
        }
        if let Some(sequence) = sequences.first() {
            let record = self
                .floor_record_at_sequence(*sequence)?
                .ok_or(refusal("standing-revocation-missing"))?;
            if record.kind != Kind::GateApply
                || record.phase != Phase::Terminal
                || record.actor != "gate"
                || record.operation.is_none()
                || record.authority.epoch != grant.record.authority.epoch
                || record.authority.sequence <= grant.stored.sequence
                || record.at < grant.record.at
                || record.at > self.services.clock.now_ms()?
                || gate_payload(&record.body) != &revocation_body(grant)?
            {
                return Err(refusal("standing-revocation-mismatch"));
            }
        }
        Ok(())
    }

    pub(super) fn standing_history(&self, grant: &Grant, now: i64) -> Result<(u64, u64)> {
        if now < grant.record.at || now > json::MAX_SAFE_INTEGER {
            return Err(refusal("standing-clock"));
        }
        let mut count = 0_u64;
        let mut last = grant.record.at;
        let mut window = VecDeque::new();
        let revoked_at = self
            .standing_sequences(grant, REVOKE_SCHEMA)?
            .first()
            .copied();
        let superseded_at: Option<i64> = self.transaction.query_row(
            "SELECT min(seq) FROM aura WHERE seq>?1 AND kind='gate.apply' AND phase='terminal' AND json_extract(body,'$.payload.target')='gate/permission'",
            [sql_number(grant.stored.sequence)?], |row| row.get(0),
        ).map_err(sql)?;
        for sequence in self.standing_sequences(grant, USE_SCHEMA)? {
            count = count.checked_add(1).ok_or(refusal("standing-count"))?;
            let record = self
                .floor_record_at_sequence(sequence)?
                .ok_or(refusal("standing-history"))?;
            let payload = gate_payload(&record.body);
            let proposal =
                self.proposal(&ProposalId::from_hex(text_field(payload, "proposal")?)?)?;
            if record.kind != Kind::GateApply
                || record.phase != Phase::Terminal
                || record.actor != "gate"
                || record.operation != Some(proposal.operation)
                || record.authority.epoch != grant.record.authority.epoch
                || sequence <= grant.stored.sequence
                || record.at < last
                || record.at > now
                || revoked_at.is_some_and(|revoked| sequence >= revoked)
                || superseded_at.is_some_and(|superseded| {
                    i64::try_from(sequence).map_or(true, |use_at| use_at >= superseded)
                })
                || record.at < grant.permission.starts
                || record.at >= grant.permission.expires
                || proposal.status != ProposalStatus::Applied
                || proposal.risk != CardRisk::Routine
                || proposal.authority.epoch != grant.record.authority.epoch
                || !grant.permission.allows(&proposal.target)
                || count > grant.permission.maximum
                || payload != &use_body(grant, &proposal, count)?
            {
                return Err(refusal("standing-history"));
            }
            self.standing_proposal_intent(&proposal, record.at)?;
            verify_operation(&grant.authorization, &proposal)?;
            while window
                .front()
                .is_some_and(|time| record.at - time >= grant.permission.window_ms)
            {
                window.pop_front();
            }
            window.push_back(record.at);
            if window.len() as u64 > grant.permission.rate_count {
                return Err(refusal("standing-history-rate"));
            }
            last = record.at;
        }
        if count != grant.stored.count {
            return Err(refusal("standing-count-mismatch"));
        }
        while window
            .front()
            .is_some_and(|time| now - time >= grant.permission.window_ms)
        {
            window.pop_front();
        }
        Ok((count, window.len() as u64))
    }
}
