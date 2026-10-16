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
            "SELECT seq FROM aura WHERE (kind='gate.apply' AND phase='terminal' AND json_extract(body,'$.payload.schema')=?1 AND json_extract(body,'$.payload.permission')=?2) OR (?1='aukora-aura-standing-use-v1' AND kind='gate.consume' AND phase='settle' AND json_extract(body,'$.payload.standing.permission_proposal')=?2) ORDER BY seq",
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
            if record.operation != Some(proposal.operation)
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
                || !grant.permission.enabled
                || proposal.risk != CardRisk::Routine
                || proposal.authority.epoch != grant.record.authority.epoch
                || !grant.permission.allows(&proposal.target)
                || count > grant.permission.maximum
            {
                return Err(refusal("standing-history"));
            }
            if record.kind == Kind::GateConsume {
                self.check_standing_consumption(grant, &proposal, &record, count)?;
            } else if record.kind != Kind::GateApply || record.phase != Phase::Terminal
                || record.actor != "gate" || proposal.status != ProposalStatus::Applied
                || payload != &use_body(grant, &proposal, count)? {
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

impl LedgerTxn<'_> {
    /// Verify a consumed standing use for observation, without restoring its authority.
    pub(in crate::ledger) fn verify_historical_standing_consumption(
        &self,
        proposal: &storage::ProposalState,
        approval: Digest32,
        record: &AuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.active()?;
        if self.proposal(&proposal.proposal)? != *proposal
            || self.record_at(record.authority)? != *record
            || proposal.authority.epoch > self.current_version()?.epoch
        {
            return Err(refusal("standing-consumption"));
        }
        let descriptor = member(gate_payload(&record.body), "standing")?;
        let permission_id = ProposalId::from_hex(text_field(descriptor, "permission_proposal")?)?;
        let permission_digest = Digest32::from_hex(text_field(descriptor, "permission_digest")?)?;
        let bytes: Vec<u8> = self.transaction.query_row(
            "SELECT body FROM authority_permissions WHERE permission=?1",
            [permission_id.to_string()], |row| row.get(0),
        ).map_err(sql)?;
        let stored = Stored::parse(&bytes)?;
        let permission_proposal = self.proposal(&permission_id)?;
        let grant_record = self.floor_record_at_sequence(stored.sequence)?
            .ok_or(refusal("standing-grant-missing"))?;
        if stored.permission != permission_id || stored.digest != permission_digest
            || Digest32::sha256(&permission_proposal.new_bytes) != permission_digest
            || permission_proposal.target != "gate/permission"
            || permission_proposal.status != ProposalStatus::Applied
            || permission_proposal.risk != CardRisk::Critical
            || permission_proposal.cell.is_some()
            || permission_proposal.authority.epoch != proposal.authority.epoch
            || grant_record.authority.epoch != proposal.authority.epoch
            || grant_record.kind != Kind::GateApply || grant_record.phase != Phase::Terminal
            || grant_record.actor != "owner"
            || grant_record.operation != Some(permission_proposal.operation)
        {
            return Err(refusal("standing-grant-context"));
        }
        bind_gate_body(gate_payload(&grant_record.body), &permission_proposal, stored.approval, "applied")?;
        let permission = StandingPermission::parse(&permission_proposal.new_bytes, grant_record.at)?;
        let authorization = self.historical_standing_proof(&stored, &permission_proposal, &grant_record)?;
        self.standing_proposal_intent(&permission_proposal, grant_record.at)?;
        let grant = Grant { stored, permission, proposal: permission_proposal, authorization, record: grant_record };
        self.verify_standing_revocation(&grant)?;
        let use_number = unsigned_field(descriptor, "use_number")?;
        if use_number == 0 || use_number > grant.stored.count
            || Digest32::sha256(&descriptor.canonical_bytes()) != approval
        {
            return Err(refusal("standing-consumption"));
        }
        self.historical_standing_use(&grant, proposal, record, use_number)?;
        self.historical_standing_history(&grant)?;
        Ok(record.clone())
    }

    fn historical_standing_history(&self, grant: &Grant) -> Result<()> {
        let now = self.services.clock.now_ms()?;
        if now < grant.record.at || now > json::MAX_SAFE_INTEGER {
            return Err(refusal("standing-clock"));
        }
        let revoked = self.standing_sequences(grant, REVOKE_SCHEMA)?.first().copied();
        let superseded: Option<i64> = self.transaction.query_row(
            "SELECT min(seq) FROM aura WHERE seq>?1 AND kind='gate.apply' AND phase='terminal' AND json_extract(body,'$.payload.target')='gate/permission'",
            [sql_number(grant.stored.sequence)?], |row| row.get(0),
        ).map_err(sql)?;
        let mut count = 0_u64;
        let mut last = grant.record.at;
        let mut window = VecDeque::new();
        for sequence in self.standing_sequences(grant, USE_SCHEMA)? {
            count = count.checked_add(1).ok_or(refusal("standing-count"))?;
            let record = self.floor_record_at_sequence(sequence)?
                .ok_or(refusal("standing-history"))?;
            let payload = gate_payload(&record.body);
            let proposal = self.proposal(&ProposalId::from_hex(text_field(payload, "proposal")?)?)?;
            if record.operation != Some(proposal.operation)
                || record.authority.epoch != grant.record.authority.epoch
                || sequence <= grant.stored.sequence || record.at < last || record.at > now
                || revoked.is_some_and(|at| sequence >= at)
                || superseded.is_some_and(|at| i64::try_from(sequence).map_or(true, |seq| seq >= at))
                || !grant.permission.enabled || record.at < grant.permission.starts
                || record.at >= grant.permission.expires || count > grant.permission.maximum
                || proposal.risk != CardRisk::Routine
                || proposal.authority.epoch != grant.record.authority.epoch
                || !grant.permission.allows(&proposal.target)
            {
                return Err(refusal("standing-history"));
            }
            if record.kind == Kind::GateConsume {
                self.historical_standing_use(grant, &proposal, &record, count)?;
            } else if record.kind != Kind::GateApply || record.phase != Phase::Terminal
                || record.actor != "gate" || proposal.status != ProposalStatus::Applied
                || payload != &use_body(grant, &proposal, count)?
            {
                return Err(refusal("standing-history"));
            }
            self.standing_proposal_intent(&proposal, record.at)?;
            verify_operation(&grant.authorization, &proposal)?;
            while window.front().is_some_and(|time| record.at - time >= grant.permission.window_ms) {
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
        Ok(())
    }

    fn historical_standing_use(
        &self,
        grant: &Grant,
        proposal: &storage::ProposalState,
        record: &AuthorityRecord,
        use_number: u64,
    ) -> Result<()> {
        let descriptor = consumption::descriptor(grant, proposal, use_number)?;
        let approval = Digest32::sha256(&descriptor.canonical_bytes());
        if record.kind != Kind::GateConsume || record.phase != Phase::Settle
            || record.actor != "owner" || record.operation != Some(proposal.operation)
            || record.authority.epoch != proposal.authority.epoch
            || gate_payload(&record.body) != &consumption::body(proposal, descriptor.clone(), approval)?
        {
            return Err(refusal("standing-consumption"));
        }
        let count: i64 = self.transaction.query_row(
            "SELECT count(*) FROM authority_consumptions WHERE approval=?1 AND proposal=?2 AND operation=?3 AND epoch=?4 AND sequence=?5 AND previous_hash IS ?6 AND proof=?7 AND credential='' AND counter=0 AND action='apply' AND appended=1",
            params![approval.to_string(), proposal.proposal.to_string(), proposal.operation.to_string(),
                sql_number(record.authority.epoch)?, sql_number(record.authority.sequence)?,
                record.authority.previous_hash.map(|hash| hash.to_string()),
                consumption::proof(descriptor)?.canonical_bytes()], |row| row.get(0),
        ).map_err(sql)?;
        if count != 1 {
            return Err(refusal("standing-consumption"));
        }
        let terminal = self.gate_terminal(&proposal.operation)?;
        if proposal.status == ProposalStatus::Consumed && terminal.is_none() {
            return Ok(());
        }
        let terminal = terminal.ok_or(refusal("standing-consumption"))?;
        let recovered = matches!(proposal.status, ProposalStatus::Incomplete | ProposalStatus::Failed
            | ProposalStatus::Conflict | ProposalStatus::Unknown);
        let same_epoch = terminal.authority.epoch == record.authority.epoch;
        if terminal.phase != Phase::Terminal || terminal.actor != "gate"
            || terminal.operation != Some(proposal.operation)
            || terminal.authority.sequence <= record.authority.sequence || terminal.at < record.at
            || terminal.authority.epoch < record.authority.epoch
            || terminal.authority.epoch > self.current_version()?.epoch
            || !(recovered && terminal.kind == Kind::GateRecover
                || proposal.status == ProposalStatus::Applied && terminal.kind == Kind::GateApply && same_epoch)
        {
            return Err(refusal("standing-consumption"));
        }
        bind_gate_body(gate_payload(&terminal.body), proposal, approval, proposal.status.wire_name())?;
        if recovered {
            historical_recovery_observation(proposal, gate_payload(&terminal.body))?;
        }
        Ok(())
    }
}

fn historical_recovery_observation(proposal: &storage::ProposalState, body: &Value) -> Result<()> {
    use canon::authority::BaseDigest;
    let mut fields = vec!["proposal", "target", "operation", "base_sha256", "new_sha256",
        "state", "retry", "consumed_approval", "observed_sha256"];
    if proposal.status == ProposalStatus::Unknown {
        fields.push("observation");
    }
    exact(body, &fields)?;
    let digest = |value: &Value| -> Result<BaseDigest> {
        match value.view() {
            json::ValueView::Text("absent") => Ok(BaseDigest::Absent),
            json::ValueView::Text(value) => Ok(BaseDigest::Present(Digest32::from_hex(value)?)),
            _ => Err(refusal("standing-consumption")),
        }
    };
    if digest(member(body, "base_sha256")?)? != proposal.base_sha256
        || !matches!(member(body, "retry")?.view(), json::ValueView::Boolean(false))
    {
        return Err(refusal("standing-consumption"));
    }
    let observed = member(body, "observed_sha256")?;
    let valid = if proposal.status == ProposalStatus::Unknown {
        matches!(observed.view(), json::ValueView::Null)
            && field(body, "observation") == Some("unavailable")
    } else {
        let observed = digest(observed)?;
        let new = BaseDigest::Present(Digest32::sha256(&proposal.new_bytes));
        match proposal.status {
            ProposalStatus::Incomplete => observed == new,
            ProposalStatus::Failed => observed == proposal.base_sha256,
            ProposalStatus::Conflict => observed != new && observed != proposal.base_sha256,
            _ => false,
        }
    };
    if valid { Ok(()) } else { Err(refusal("standing-consumption")) }
}
