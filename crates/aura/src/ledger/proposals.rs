// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stored proposal bytes, reservations and exact owner challenge material.
use super::*;
use crate::storage::{
    self, DeclinedProposal, OperationCoverage, ProposalState, ProposalStatus, RecoveryWork,
    StagedAuthorization, OWNER_DECLINED,
};
use canon::{
    authority::{LifecycleRecord, OwnerAuthorization, OwnerOperation},
    ids::{OperationDigest, ProposalId},
    json::{Value, ValueView},
};
use rusqlite::{params, OptionalExtension};

/// How long the gate holds back the same bytes after their card ran out of time.
pub const DAY_MS: i64 = 86_400_000;

impl LedgerTxn<'_> {
    pub fn stage_proposal(&mut self, proposal: ProposalState) -> Result<()> {
        self.mutate(|this| {
            if proposal.status != ProposalStatus::Pending || proposal.authority != this.current_version()?
                || proposal.target.is_empty() || proposal.actor.is_empty() { return Err(refusal("proposal-context")); }
            if let Some(version) = proposal.evidence_source { this.record_at(version)?; }
            // The supervisor's installed-release proposal is re-raised after an epoch change with the same digest;
            // its stale decline must not block it for good (SCOUT ad03d28 #4).
            if !(proposal.actor == "supervisor" && proposal.target == "release") {
                if let Some(prior) = this.last_decline(proposal.operation_digest)? {
                    if prior.evidence_digest == proposal.evidence_digest { return Err(refusal("unchanged-decline")); }
                }
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

    /// The most recently raised card for a target, including its terminal state. A supervisor keeper uses this to
    /// respect the owner's answer when a request's clock-derived expiry changes but its terms do not.
    pub fn latest_proposal(&self, target: &str) -> Result<Option<ProposalState>> {
        self.active()?;
        let id: Option<String> = self.transaction.query_row(
            "SELECT id FROM authority_proposals WHERE target=?1 ORDER BY rowid DESC LIMIT 1",
            [target], |row| row.get(0),
        ).optional().map_err(sql)?;
        id.map(|id| self.proposal(&ProposalId::from_hex(&id)?)).transpose()
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
        let Some((proposal, evidence, target, epoch, sequence, previous)) = row else {
            return Ok(None);
        };
        let declined = DeclinedProposal {
            proposal: ProposalId::from_hex(&proposal)?,
            operation_digest: operation,
            evidence_digest: Digest32::from_hex(&evidence)?,
            target,
            authority: AuthorityVersion {
                epoch: unsigned(epoch)?,
                sequence: unsigned(sequence)?,
                previous_hash: previous.map(|v| Digest32::from_hex(&v)).transpose()?,
            },
        };
        // NODE.md O19: only the owner's explicit Decline is a decline. The latest terminal for these exact bytes
        // decides: a card that ran out of time (closed, never answered) or was refused for another reason (an owner
        // epoch change) leaves the same bytes free to be raised again.
        let terminal = self.record_at(declined.authority)?;
        if field(gate_payload(&terminal.body), "reason") != Some(OWNER_DECLINED) {
            return Ok(None);
        }
        Ok(Some(declined))
    }

    /// The latest card for these exact bytes that simply ran out of time, when that is the latest word on them (no
    /// decline, refusal or withdrawal since): its proposal and when it expired. The gate raises the same bytes again
    /// at most once a day unless the owner asks again (NODE.md O19).
    pub fn last_expiry(&self, operation: OperationDigest) -> Result<Option<(ProposalId, i64)>> {
        self.active()?;
        type Row = (String, i64, i64, Option<String>);
        let row: Option<Row> = self.transaction.query_row("SELECT d.proposal,d.epoch,d.sequence,d.previous_hash FROM authority_declines d JOIN authority_proposals p ON p.id=d.proposal WHERE d.operation_digest=?1 AND p.status='expired' AND d.sequence=(SELECT max(sequence) FROM authority_declines WHERE operation_digest=?1)",[operation.to_string()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(sql)?;
        let Some((proposal, epoch, sequence, previous)) = row else { return Ok(None) };
        let terminal = self.record_at(AuthorityVersion {
            epoch: unsigned(epoch)?,
            sequence: unsigned(sequence)?,
            previous_hash: previous.map(|v| Digest32::from_hex(&v)).transpose()?,
        })?;
        if field(gate_payload(&terminal.body), "reason").is_some() {
            return Ok(None);
        }
        Ok(Some((ProposalId::from_hex(&proposal)?, terminal.at)))
    }

    /// The owner's standing Declines among the node's own requests (targets under `engine/` and the release): for each
    /// target, its newest proposal when that proposal is one the owner declined, newest first. These are what the
    /// owner may ask for again (NODE.md O19); a request raised since (pending, applied, expired) hides the older no.
    pub fn owner_declines(&self, limit: usize) -> Result<Vec<(ProposalId, String)>> {
        self.active()?;
        let mut statement = self.transaction.prepare("SELECT d.proposal,d.target,d.operation_digest FROM authority_declines d JOIN authority_proposals p ON p.id=d.proposal \
            WHERE p.status IN ('refused','expired') AND (d.target LIKE 'engine/%' OR d.target='release') \
            AND p.rowid=(SELECT max(q.rowid) FROM authority_proposals q WHERE q.target=d.target) ORDER BY d.sequence DESC LIMIT ?1").map_err(sql)?;
        let mut cursor = statement
            .query([i64::try_from(limit).map_err(|_| refusal("limit"))?])
            .map_err(sql)?;
        let mut rows = Vec::new();
        while let Some(row) = cursor.next().map_err(sql)? {
            rows.push((
                ProposalId::from_hex(&row.get::<_, String>(0).map_err(sql)?)?,
                row.get::<_, String>(1).map_err(sql)?,
                OperationDigest::from_hex(&row.get::<_, String>(2).map_err(sql)?)?,
            ));
        }
        let now = self.services.clock.now_ms()?;
        let mut result = Vec::new();
        for (proposal, target, operation) in rows {
            let declined = self.last_decline(operation)?.is_some_and(|row| row.proposal == proposal);
            // A card that ran out of time is listed while the day it holds its bytes back lasts.
            let lapsed = self.last_expiry(operation)?.is_some_and(|(id, at)| id == proposal && now.saturating_sub(at) < DAY_MS);
            if declined || lapsed {
                result.push((proposal, target));
            }
        }
        Ok(result)
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
            // The owner's own Decline ends any review the owner opened for it: a card shown and then declined must
            // not wait for its review to run out (the live-review check below would refuse the decline).
            if row.kind == canon::authority::LifecycleKind::GateRefuse
                && field(gate_payload(&row.body), "reason") == Some(OWNER_DECLINED)
            {
                this.transaction
                    .execute(
                        "UPDATE authority_challenges SET spent=1 WHERE proposal=?1 AND spent=0",
                        [proposal.to_string()],
                    )
                    .map_err(sql)?;
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

impl LedgerTxn<'_> {
    /// Return the exact retained card only while its stored challenge remains live.
    pub fn read_live_review(
        &self,
        id: ProposalId,
        action: OwnerOperation,
    ) -> Result<Option<StagedAuthorization>> {
        self.active()?;
        let card: Option<Vec<u8>> = self.transaction.query_row(
            "SELECT card FROM authority_challenges WHERE proposal=?1 AND action=?2",
            params![id.to_string(), action.wire_name()],
            |row| row.get(0),
        ).optional().map_err(sql)?;
        let Some(bytes) = card else {
            return Ok(None);
        };
        let authorization = self.authorization(&id, action)?;
        self.check_review_commitment(&authorization)?;
        Ok(Some(StagedAuthorization {
            authorization,
            card: storage::decode_card(&bytes)?,
        }))
    }

    /// Commit a Release review without consuming its passkey challenge.
    pub fn append_release_review(
        &mut self,
        review: LifecycleRecord,
    ) -> Result<canon::authority::AuthorityRecord> {
        self.mutate(|ledger| {
            use canon::authority::{Kind, LifecycleKind, PendingAuthorityRecord, Phase};

            if review.kind != LifecycleKind::GateReview
                || review.phase != Phase::Settle
                || review.actor != "gate"
            {
                return Err(refusal("lifecycle-phase"));
            }
            let body = gate_payload(&review.body);
            let ValueView::Object(fields) = body.view() else {
                return Err(refusal("review-commitment"));
            };
            if fields.len() != 4 || field(body, "action") != Some("release") {
                return Err(refusal("review-action"));
            }
            let proposal_id = ProposalId::from_hex(
                field(body, "proposal").ok_or(refusal("lifecycle-proposal"))?,
            )?;
            let proposal = ledger.proposal(&proposal_id)?;
            let source = ledger.record_at(proposal.authority)?;
            if proposal.status != ProposalStatus::Pending
                || proposal.operation != review.operation
                || proposal.target != "release"
                || proposal.actor != "supervisor"
                || proposal.cell.is_some()
                || proposal.risk != canon::authority::CardRisk::Critical
                || source.kind != Kind::GatePropose
                || source.phase != Phase::Intent
                || source.actor != "supervisor"
                || source.operation != Some(proposal.operation)
                || ledger.gate_terminal(&proposal.operation)?.is_some()
            {
                return Err(refusal("lifecycle-proposal"));
            }
            let auth = ledger.authorization(&proposal_id, OwnerOperation::Release)?;
            if field(body, "display_sha256") != Some(auth.display_sha256.to_string().as_str())
                || field(body, "authorization_sha256")
                    != Some(Digest32::sha256(&auth.canonical_bytes()?).to_string().as_str())
            {
                return Err(refusal("review-commitment"));
            }
            ledger.write_record(PendingAuthorityRecord {
                v: review.v,
                algorithm: review.algorithm,
                authority: review.authority,
                at: review.at,
                kind: Kind::GateReview,
                actor: review.actor,
                operation: Some(review.operation),
                phase: Phase::Settle,
                body: review.body,
            })
        })
    }

    fn check_review_commitment(&self, auth: &OwnerAuthorization) -> Result<()> {
        let proposal = self.proposal(&auth.proposal)?;
        let mut statement = self.transaction.prepare(
            "SELECT seq FROM aura WHERE op=?1 AND kind='gate.review' ORDER BY seq DESC",
        ).map_err(sql)?;
        let mut cursor = statement.query([proposal.operation.to_string()]).map_err(sql)?;
        while let Some(row) = cursor.next().map_err(sql)? {
            let sequence = unsigned(row.get(0).map_err(sql)?)?;
            let record = self.floor_record_at_sequence(sequence)?
                .ok_or(refusal("authorization-mismatch"))?;
            let body = gate_payload(&record.body);
            if field(body, "action") != Some(auth.op.wire_name()) {
                continue;
            }
            if record.kind != canon::authority::Kind::GateReview
                || record.phase != canon::authority::Phase::Settle
                || record.actor != "gate"
                || record.operation != Some(proposal.operation)
                || record.authority.epoch != auth.epoch
                || record.authority.sequence <= proposal.authority.sequence
                || field(body, "proposal") != Some(auth.proposal.to_string().as_str())
                || field(body, "display_sha256") != Some(auth.display_sha256.to_string().as_str())
                || field(body, "authorization_sha256")
                    != Some(Digest32::sha256(&auth.canonical_bytes()?).to_string().as_str())
            {
                return Err(refusal("authorization-mismatch"));
            }
            return Ok(());
        }
        Err(refusal("authorization-mismatch"))
    }
}

impl LedgerTxn<'_> {
    /// Keep a live release review, or remove only its expired, unspent challenge.
    pub fn read_or_expire_release_review(
        &mut self,
        id: ProposalId,
    ) -> Result<Option<StagedAuthorization>> {
        self.mutate(|this| {
            let proposal = this.proposal(&id)?;
            if proposal.target != "release"
                || proposal.status != ProposalStatus::Pending
                || proposal.authority.epoch != this.current_version()?.epoch
                || this.gate_terminal(&proposal.operation)?.is_some()
            {
                return Err(refusal("authorization-mismatch"));
            }
            let consumed: i64 = this.transaction.query_row(
                "SELECT count(*) FROM authority_consumptions WHERE proposal=?1 OR operation=?2",
                params![id.to_string(), proposal.operation.to_string()],
                |row| row.get(0),
            ).map_err(sql)?;
            if consumed != 0 {
                return Err(refusal("challenge-spent"));
            }
            let row: Option<(Vec<u8>, Vec<u8>, String, i64)> = this.transaction.query_row(
                "SELECT body,card,challenge,spent FROM authority_challenges WHERE proposal=?1 AND action='release'",
                [id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).optional().map_err(sql)?;
            let Some((bytes, card_bytes, challenge, spent)) = row else {
                return Ok(None);
            };
            let authorization = storage::decode_authorization(&bytes)?;
            let card = storage::decode_card(&card_bytes)?;
            this.match_authorization(&authorization, &proposal)?;
            if authorization.proposal != id
                || authorization.op != OwnerOperation::Release
                || authorization.subject != this.gate_owner_subject()?
                || authorization.challenge.to_string() != challenge
                || authorization.display_sha256 != Digest32::sha256(&card_bytes)
                || card.risk != proposal.risk
                || card.model_note != proposal.model_note
            {
                return Err(refusal("authorization-mismatch"));
            }
            let approval = Digest32::sha256(&bytes).to_string();
            if spent != 0
                || this.counters.contains_key(&approval)
                || this.consumptions.contains(&approval)
            {
                return Err(refusal("challenge-spent"));
            }
            this.check_review_commitment(&authorization)?;
            if this.services.clock.now_ms()? < authorization.expires_at {
                return Ok(Some(StagedAuthorization { authorization, card }));
            }
            let removed = this.transaction.execute(
                "DELETE FROM authority_challenges WHERE proposal=?1 AND action='release' AND challenge=?2 AND body=?3 AND card=?4 AND spent=0",
                params![id.to_string(), challenge, bytes, card_bytes],
            ).map_err(sql)?;
            if removed != 1 {
                return Err(refusal("authorization-mismatch"));
            }
            Ok(None)
        })
    }
}
