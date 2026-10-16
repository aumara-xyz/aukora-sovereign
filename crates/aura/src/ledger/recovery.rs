// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery observations cannot issue a permit or execute an effect.

use super::{gate_payload, proposals::field, refusal, sql, LedgerTxn};
use crate::storage::{self, ProposalStatus};
use canon::{
    alg::AlgorithmId,
    authority::{
        AuthorityRecord, AuthorityTxn, BaseDigest, Kind, LifecycleKind, LifecycleRecord, Phase,
    },
    digest::Digest32,
    ids::ProposalId,
    json::Value,
    Result,
};
use rusqlite::params;

impl LedgerTxn<'_> {
    /// Close only pending work whose recorded owner epoch has been superseded.
    pub fn refuse_stale_pending(&mut self, proposal: ProposalId) -> Result<AuthorityRecord> {
        self.mutate(|this| {
            let stored = this.proposal(&proposal)?;
            let current = this.current_version()?;
            if stored.status != ProposalStatus::Pending || stored.authority.epoch >= current.epoch {
                return Err(refusal("pending-epoch"));
            }
            if this.gate_terminal(&stored.operation)?.is_some() {
                return Err(refusal("pending-terminal"));
            }
            let consumed: i64 = this.transaction.query_row(
                "SELECT count(*) FROM authority_consumptions WHERE proposal=?1 OR operation=?2",
                params![proposal.to_string(), stored.operation.to_string()],
                |row| row.get(0),
            ).map_err(sql)?;
            if consumed != 0 {
                return Err(refusal("pending-consumed"));
            }
            let proposed = this.record_at(stored.authority)?;
            let payload = gate_payload(&proposed.body);
            if proposed.kind != Kind::GatePropose
                || proposed.phase != Phase::Intent
                || proposed.operation != Some(stored.operation)
                || field(payload, "proposal") != Some(proposal.to_string().as_str())
                || field(payload, "target") != Some(stored.target.as_str())
                || field(payload, "operation") != Some(stored.operation_digest.to_string().as_str())
            {
                return Err(refusal("pending-proposal"));
            }
            {
                let mut statement = this.transaction.prepare(
                    "SELECT action,challenge,body,card FROM authority_challenges WHERE proposal=?1 AND spent=0",
                ).map_err(sql)?;
                let mut rows = statement.query([proposal.to_string()]).map_err(sql)?;
                while let Some(row) = rows.next().map_err(sql)? {
                    let action: String = row.get(0).map_err(sql)?;
                    let challenge: String = row.get(1).map_err(sql)?;
                    let bytes: Vec<u8> = row.get(2).map_err(sql)?;
                    let card_bytes: Vec<u8> = row.get(3).map_err(sql)?;
                    let authorization = storage::decode_authorization(&bytes)?;
                    let card = storage::decode_card(&card_bytes)?;
                    if authorization.epoch != stored.authority.epoch
                        || authorization.proposal != proposal
                        || authorization.op.wire_name() != action
                        || authorization.challenge.to_string() != challenge
                        || authorization.target != stored.target
                        || authorization.operation != stored.operation_digest
                        || authorization.base_sha256 != stored.base_sha256
                        || authorization.new_sha256 != Digest32::sha256(&stored.new_bytes)
                        || authorization.cell != stored.cell
                        || authorization.display_sha256 != Digest32::sha256(&card_bytes)
                        || card.risk != stored.risk
                        || card.model_note != stored.model_note
                    {
                        return Err(refusal("pending-authorization"));
                    }
                }
            }
            this.transaction.execute(
                "UPDATE authority_challenges SET spent=1 WHERE proposal=?1 AND spent=0",
                [proposal.to_string()],
            ).map_err(sql)?;
            let base = match stored.base_sha256 {
                BaseDigest::Absent => "absent".to_owned(),
                BaseDigest::Present(digest) => digest.to_string(),
            };
            let body = Value::object(vec![
                ("proposal".into(), Value::text(proposal.to_string())?),
                ("target".into(), Value::text(stored.target)?),
                ("operation".into(), Value::text(stored.operation_digest.to_string())?),
                ("base_sha256".into(), Value::text(base)?),
                ("new_sha256".into(), Value::text(Digest32::sha256(&stored.new_bytes).to_string())?),
                ("state".into(), Value::text("refused".into())?),
                ("retry".into(), Value::boolean(false)),
                ("reason".into(), Value::text("gate:owner-epoch-changed".into())?),
            ])?;
            let record = this.append_lifecycle(LifecycleRecord {
                v: 1,
                algorithm: AlgorithmId::Sha256,
                authority: current,
                at: this.services.clock.now_ms()?,
                kind: LifecycleKind::GateRefuse,
                actor: "gate".into(),
                operation: stored.operation,
                phase: Phase::Terminal,
                body,
            })?;
            this.release_reservation(&proposal)?;
            Ok(record)
        })
    }

    /// Observe interrupted work without interpreting present bytes as an acknowledged apply.
    pub fn observe_interrupted_target(
        &mut self,
        proposal: ProposalId,
        approval: Digest32,
        reader: impl FnOnce(&str) -> Result<Option<Vec<u8>>>,
    ) -> Result<(ProposalStatus, Option<BaseDigest>)> {
        self.mutate(|this| {
            let (status, observed) = this.observe_consumed_target(proposal, approval, reader)?;
            if status != ProposalStatus::Applied {
                return Ok((status, observed));
            }
            let observation = this
                .target_observation
                .as_mut()
                .ok_or(refusal("target-observation-required"))?;
            observation.status = ProposalStatus::Incomplete;
            Ok((ProposalStatus::Incomplete, observed))
        })
    }
}
