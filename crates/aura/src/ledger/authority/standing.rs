// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retained owner grants and bounded uses share the active authority transaction.

use super::*;
use canon::authority::CardRisk;
use canon::ids::OperationId;
use format::*;

mod consumption;
mod format;
mod history;
mod proof;

struct Grant {
    stored: Stored,
    permission: StandingPermission,
    proposal: storage::ProposalState,
    authorization: OwnerAuthorization,
    record: AuthorityRecord,
}

impl LedgerTxn<'_> {
    pub(super) fn validate_standing_grant(
        &self,
        proof: &VerifiedProof,
        pending: &PendingAuthorityRecord,
        proposal: &storage::ProposalState,
    ) -> Result<()> {
        let auth = proof.authorization();
        let now = self.services.clock.now_ms()?;
        if auth.op != OwnerOperation::Permission
            || auth.target != "gate/permission"
            || proposal.target != auth.target
            || proposal.risk != CardRisk::Critical
            || proposal.cell.is_some()
            || pending.actor != "owner"
            || pending.at < 0
            || pending.at > now
            || now >= auth.expires_at
        {
            return Err(refusal("standing-grant-context"));
        }
        bind_gate_body(
            gate_payload(&pending.body),
            proposal,
            Digest32::sha256(proof.authorization_bytes()),
            "applied",
        )?;
        StandingPermission::parse(&proposal.new_bytes, pending.at)?;
        self.standing_proposal_intent(proposal, pending.at)?;
        Ok(())
    }

    pub(super) fn store_standing_grant(
        &mut self,
        proposal: &storage::ProposalState,
        approval: Digest32,
        record: &AuthorityRecord,
    ) -> Result<()> {
        let stored = Stored {
            permission: proposal.proposal,
            digest: Digest32::sha256(&proposal.new_bytes),
            approval,
            sequence: record.authority.sequence,
            count: 0,
            revoked: false,
        };
        self.transaction
            .execute(
                "INSERT INTO authority_permissions(permission,body) VALUES (?1,?2)",
                params![proposal.proposal.to_string(), stored.bytes()?],
            )
            .map_err(sql)?;
        Ok(())
    }

    fn standing_grant(&self, id: &ProposalId, digest: Digest32) -> Result<Grant> {
        self.active()?;
        let bytes: Vec<u8> = self
            .transaction
            .query_row(
                "SELECT body FROM authority_permissions WHERE permission=?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .map_err(sql)?;
        let stored = Stored::parse(&bytes)?;
        let proposal = self.proposal(id)?;
        if stored.permission != *id
            || stored.digest != digest
            || digest != Digest32::sha256(&proposal.new_bytes)
            || proposal.target != "gate/permission"
            || proposal.risk != CardRisk::Critical
            || proposal.status != ProposalStatus::Applied
            || proposal.cell.is_some()
            || proposal.authority.epoch != self.state.epoch
        {
            return Err(refusal("standing-grant-context"));
        }
        let record = self
            .floor_record_at_sequence(stored.sequence)?
            .ok_or(refusal("standing-grant-missing"))?;
        if record.kind != Kind::GateApply
            || record.phase != Phase::Terminal
            || record.actor != "owner"
            || record.operation != Some(proposal.operation)
            || record.authority.epoch != self.state.epoch
        {
            return Err(refusal("standing-grant-context"));
        }
        bind_gate_body(
            gate_payload(&record.body),
            &proposal,
            stored.approval,
            "applied",
        )?;
        let permission = StandingPermission::parse(&proposal.new_bytes, record.at)?;
        let authorization = self.verify_standing_proof(&stored, &proposal, &record)?;
        self.standing_proposal_intent(&proposal, record.at)?;
        let grant = Grant {
            stored,
            permission,
            proposal,
            authorization,
            record,
        };
        self.verify_standing_revocation(&grant)?;
        Ok(grant)
    }

    pub(super) fn check_standing(
        &mut self,
        permission_id: &ProposalId,
        digest: Digest32,
        proposal_id: &ProposalId,
        action: OwnerOperation,
    ) -> Result<StandingUseContext> {
        if action != OwnerOperation::Apply || proposal_id == permission_id {
            return Err(refusal("standing-action"));
        }
        let grant = self.standing_grant(permission_id, digest)?;
        let now = self.services.clock.now_ms()?;
        if grant.stored.revoked
            || !grant.permission.enabled
            || now < grant.permission.starts
            || now >= grant.permission.expires
            || now > json::MAX_SAFE_INTEGER
        {
            return Err(refusal("standing-inactive"));
        }
        let latest: Option<i64> = self.transaction.query_row(
            "SELECT max(seq) FROM aura WHERE kind='gate.apply' AND phase='terminal' AND json_extract(body,'$.payload.target')='gate/permission'",
            [], |row| row.get(0),
        ).map_err(sql)?;
        if latest != Some(sql_number(grant.stored.sequence)?) {
            return Err(refusal("standing-superseded"));
        }
        let proposal = self.proposal(proposal_id)?;
        if proposal.status != ProposalStatus::Pending
            || proposal.authority.epoch != self.state.epoch
            || proposal.risk != CardRisk::Routine
            || !grant.permission.allows(&proposal.target)
        {
            return Err(refusal("standing-scope"));
        }
        self.standing_proposal_intent(&proposal, now)?;
        verify_operation(&grant.authorization, &proposal)?;
        let prior: i64 = self.transaction.query_row(
            "SELECT (SELECT count(*) FROM authority_consumptions WHERE proposal=?1) + (SELECT count(*) FROM aura WHERE op=?2 AND (phase='terminal' OR kind='gate.consume'))",
            params![proposal_id.to_string(), proposal.operation.to_string()], |row| row.get(0),
        ).map_err(sql)?;
        if prior != 0 {
            return Err(refusal("standing-already-consumed"));
        }
        let (count, recent) = self.standing_history(&grant, now)?;
        let next = count.checked_add(1).ok_or(refusal("standing-count"))?;
        if next > grant.permission.maximum || recent >= grant.permission.rate_count {
            return Err(refusal("standing-exhausted"));
        }
        Ok(StandingUseContext {
            epoch: self.state.epoch,
            operation: proposal.operation_digest,
            use_number: next,
            risk: proposal.risk,
        })
    }

    pub(super) fn append_standing_use(
        &mut self,
        usage: VerifiedStandingUse,
        mut pending: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        if usage.transaction_id() != self.identity {
            return Err(refusal("standing-transaction"));
        }
        let checked = self.check_standing(
            usage.permission_id(),
            usage.permission_digest(),
            usage.proposal(),
            usage.action(),
        )?;
        if checked != *usage.context() {
            return Err(refusal("standing-changed"));
        }
        let proposal = self.proposal(usage.proposal())?;
        let grant = self.standing_grant(usage.permission_id(), usage.permission_digest())?;
        let now = self.services.clock.now_ms()?;
        self.standing_proposal_intent(&proposal, now)?;
        let (count, recent) = self.standing_history(&grant, now)?;
        if count.checked_add(1) != Some(checked.use_number)
            || checked.use_number > grant.permission.maximum
            || recent >= grant.permission.rate_count
        {
            return Err(refusal("standing-changed"));
        }
        if now < grant.permission.starts
            || now >= grant.permission.expires
            || pending.kind != Kind::GateConsume
            || pending.phase != Phase::Settle
            || pending.authority != self.current_version()?
            || pending.operation != Some(proposal.operation)
            || pending.actor != "owner"
            || pending.at < 0
            || pending.at > now
        {
            return Err(refusal("standing-append-context"));
        }
        if field(&pending.body, "schema") == Some(crate::record::AUTHORITY_BODY_SCHEMA) {
            let wrapper = crate::record::AuthorityBodyV1::parse(&pending.body)?;
            if wrapper.authority != pending.authority || wrapper.algorithm != pending.algorithm {
                return Err(refusal("standing-append-context"));
            }
        }
        let descriptor = consumption::descriptor(&grant, &proposal, checked.use_number)?;
        let approval = Digest32::sha256(&descriptor.canonical_bytes());
        let expected = consumption::body(&proposal, descriptor.clone(), approval)?;
        if gate_payload(&pending.body) != &expected {
            return Err(refusal("standing-record-mismatch"));
        }
        pending.at = now;
        let version = pending.authority;
        let proof = consumption::proof(descriptor)?.canonical_bytes();
        self.transaction.execute(
            "INSERT INTO authority_consumptions(approval,proposal,operation,epoch,sequence,proof,credential,counter,action,appended,previous_hash) VALUES (?1,?2,?3,?4,?5,?6,'',0,'apply',1,?7)",
            params![approval.to_string(), proposal.proposal.to_string(), proposal.operation.to_string(),
                sql_number(version.epoch)?, sql_number(version.sequence)?, proof,
                version.previous_hash.map(|hash| hash.to_string())],
        ).map_err(sql)?;
        self.set_status(proposal.proposal, ProposalStatus::Consumed)?;
        let record = self.write_record(pending)?;
        let mut stored = grant.stored;
        stored.count = checked.use_number;
        self.replace_standing(&stored)?;
        Ok(record)
    }

    pub(super) fn revoke_standing_permission(
        &mut self,
        id: &ProposalId,
        digest: Digest32,
    ) -> Result<()> {
        let grant = self.standing_grant(id, digest)?;
        let now = self.services.clock.now_ms()?;
        self.standing_history(&grant, now)?;
        if grant.stored.revoked {
            return Ok(());
        }
        let mut operation = [0; 16];
        getrandom::fill(&mut operation).map_err(|_| refusal("standing-randomness"))?;
        let body = revocation_body(&grant)?;
        self.write_record(PendingAuthorityRecord {
            v: 1,
            algorithm: canon::alg::AlgorithmId::Sha256,
            authority: self.current_version()?,
            at: now,
            kind: Kind::GateApply,
            actor: "gate".to_owned(),
            operation: Some(OperationId::from_bytes(operation)),
            phase: Phase::Terminal,
            body,
        })?;
        let mut stored = grant.stored;
        stored.revoked = true;
        self.replace_standing(&stored)
    }

    fn replace_standing(&self, stored: &Stored) -> Result<()> {
        if self
            .transaction
            .execute(
                "UPDATE authority_permissions SET body=?2 WHERE permission=?1",
                params![stored.permission.to_string(), stored.bytes()?],
            )
            .map_err(sql)?
            != 1
        {
            return Err(refusal("standing-storage"));
        }
        Ok(())
    }
}

fn verify_operation(auth: &OwnerAuthorization, proposal: &storage::ProposalState) -> Result<()> {
    let mut rebuilt = auth.clone();
    rebuilt.op = OwnerOperation::Apply;
    rebuilt.proposal = proposal.proposal;
    rebuilt.target = proposal.target.clone();
    rebuilt.base_sha256 = proposal.base_sha256;
    rebuilt.new_sha256 = Digest32::sha256(&proposal.new_bytes);
    rebuilt.cell = proposal.cell;
    rebuilt.operation = proposal.operation_digest;
    rebuilt.canonical_bytes()?;
    Ok(())
}

fn use_body(grant: &Grant, proposal: &storage::ProposalState, count: u64) -> Result<Value> {
    let base = match proposal.base_sha256 {
        canon::authority::BaseDigest::Absent => "absent".to_owned(),
        canon::authority::BaseDigest::Present(digest) => digest.to_string(),
    };
    object(vec![
        ("schema", text(USE_SCHEMA)?),
        ("permission", text(grant.stored.permission)?),
        ("permission_sha256", text(grant.stored.digest)?),
        ("standing_operation", text(grant.proposal.operation)?),
        ("use_number", number(count)?),
        ("proposal", text(proposal.proposal)?),
        ("target", text(&proposal.target)?),
        ("operation", text(proposal.operation_digest)?),
        ("base_sha256", text(base)?),
        ("new_sha256", text(Digest32::sha256(&proposal.new_bytes))?),
        ("state", text("applied")?),
        ("action", text("apply")?),
    ])
}

fn revocation_body(grant: &Grant) -> Result<Value> {
    object(vec![
        ("schema", text(REVOKE_SCHEMA)?),
        ("permission", text(grant.stored.permission)?),
        ("permission_sha256", text(grant.stored.digest)?),
        ("standing_operation", text(grant.proposal.operation)?),
        ("grant_sequence", number(grant.stored.sequence)?),
        ("state", text("revoked")?),
    ])
}
