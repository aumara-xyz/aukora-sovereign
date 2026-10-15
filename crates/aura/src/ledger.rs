// SPDX-License-Identifier: AGPL-3.0-or-later
//! Locked, signed append-only storage. Read snapshots never grant authority.

use crate::export::{ColdProofV1, ExportLimits};
use canon::{
    alg::{PublicKey, Signatures},
    authority::{AuthorityRecord, AuthorityTxn, AuthorityVersion, VerifiedProof},
    digest::Digest32,
    ids::OperationId,
    Result,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

mod authority;
mod broker_reads;
mod epochs;
mod floor;
mod io;
mod observations;
mod proposals;

/// Signing keys remain with the supervisor's signing service.
pub trait RecordSigner {
    fn public_keys(&self) -> Result<Vec<PublicKey>>;
    fn sign_entry_hash(&self, hash: Digest32) -> Result<Signatures>;
}

/// Time is supplied by the supervisor and does not determine record ordering.
pub trait TrustedClock {
    fn now_ms(&self) -> Result<i64>;
}

#[derive(Clone, Copy)]
pub struct TransactionServices<'a> {
    pub signer: &'a dyn RecordSigner,
    pub clock: &'a dyn TrustedClock,
}

pub struct Ledger {
    connection: rusqlite::Connection,
    verified: io::Snapshot,
    data_version: i64,
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Self> {
        let mut connection = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(sql)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sql)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL;",
            )
            .map_err(sql)?;
        crate::schema::migrate(&mut connection)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql)?;
        let verified = io::verify(&transaction)?;
        let data_version = transaction
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .map_err(sql)?;
        transaction.commit().map_err(sql)?;
        Ok(Self {
            connection,
            verified,
            data_version,
        })
    }

    pub fn begin<'a>(&'a mut self, services: TransactionServices<'a>) -> Result<LedgerTxn<'a>> {
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(|_| refusal("randomness"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql)?;
        let version: i64 = transaction
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .map_err(sql)?;
        if version != self.data_version {
            crate::schema::validate(&transaction)?;
            let observed = io::verify(&transaction)?;
            if observed.frontier.size() < self.verified.frontier.size()
                || observed.epoch < self.verified.epoch
            {
                return Err(refusal("retained-state-rollback"));
            }
            if let Some(hash) = self.verified.hash {
                let retained = io::record_at(&transaction, self.verified.frontier.size())?;
                if retained.hash != hash {
                    return Err(refusal("retained-prefix-rewritten"));
                }
            }
            self.verified = observed;
            self.data_version = version;
        }
        let keys = services.signer.public_keys()?;
        if !self.verified.keys.is_empty() && keys != self.verified.keys {
            return Err(refusal("signer-changed"));
        }
        let state = self.verified.clone();
        let observation_start_changes = transaction.total_changes();
        Ok(LedgerTxn {
            observation_start_changes,
            transaction,
            services,
            identity: Digest32::from_bytes(random),
            state,
            retained: &mut self.verified,
            poisoned: false,
            counters: BTreeMap::new(),
            consumptions: BTreeSet::new(),
            floor_obligation: None,
            target_observation: None,
        })
    }

    pub fn export_cold_proof(&self, limits: ExportLimits) -> Result<ColdProofV1> {
        let transaction = self.connection.unchecked_transaction().map_err(sql)?;
        crate::schema::validate(&transaction)?;
        let (count, stored_bytes):(i64,i64) = transaction.query_row(
            "SELECT count(*),coalesce(sum(length(CAST(body AS BLOB))+length(CAST(actor AS BLOB))+length(sig)+length(hash)+length(prev)+length(op)+length(kind)+length(phase)),0) FROM aura",
            [],|row|Ok((row.get(0)?,row.get(1)?))).map_err(sql)?;
        if count < 0
            || count as u128 > limits.max_rows as u128
            || stored_bytes < 0
            || stored_bytes as u128 > limits.max_bytes as u128
        {
            return Err(refusal("export-limit"));
        }
        let state = io::verify(&transaction)?;
        self.check_snapshot(&transaction, &state)?;
        let head = state.head()?;
        if head.sequence > limits.max_rows as u64 {
            return Err(refusal("export-limit"));
        }
        let key = state
            .keys
            .iter()
            .find(|key| key.algorithm == canon::alg::AlgorithmId::Ed25519)
            .ok_or(refusal("signer-missing"))?;
        let public_key = key
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| refusal("signer-invalid"))?;
        let mut statement = transaction.prepare(io::ROW_QUERY).map_err(sql)?;
        let mut cursor = statement.query([]).map_err(sql)?;
        let mut rows = Vec::new();
        let mut bytes = b"{\"head\":".len()
            + head.canonical_bytes()?.len()
            + b",\"publicKey\":\"".len()
            + 64
            + b"\",\"rows\":[".len()
            + b"],\"schema\":\"aukora-aura-cold-proof-v1\"}".len();
        if bytes > limits.max_bytes {
            return Err(refusal("export-limit"));
        }
        while let Some(raw) = cursor.next().map_err(sql)? {
            let row = io::read_row(raw)?;
            bytes = bytes
                .checked_add(
                    crate::export::row_value(&row)?.canonical_bytes().len()
                        + usize::from(!rows.is_empty()),
                )
                .ok_or(refusal("export-limit"))?;
            if bytes > limits.max_bytes {
                return Err(refusal("export-limit"));
            }
            rows.push(row);
        }
        let result = ColdProofV1 {
            head,
            public_key,
            rows,
        };
        result.canonical_bytes(limits)?;
        Ok(result)
    }
}

impl LedgerTxn<'_> {
    /// Recheck the retained owner proof and its signed consumption without issuing a permit.
    pub fn check_target_consumption(
        &self,
        proposal: canon::ids::ProposalId,
        approval: Digest32,
    ) -> Result<AuthorityRecord> {
        self.active()?;
        let stored = self.proposal(&proposal)?;
        authority::verify_target_consumption(self, &stored, approval)
            .map_err(|_| refusal("target-consumption"))
    }

    /// Read consumed target bytes under this transaction and retain their settlement.
    pub fn observe_consumed_target(
        &mut self,
        proposal: canon::ids::ProposalId,
        approval: Digest32,
        reader: impl FnOnce(&str) -> Result<Option<Vec<u8>>>,
    ) -> Result<(crate::storage::ProposalStatus, Option<canon::authority::BaseDigest>)> {
        self.mutate(|this| {
            use crate::storage::ProposalStatus;
            use canon::authority::BaseDigest;

            if this.target_observation.is_some() {
                return Err(refusal("target-observation-pending"));
            }
            let stored = this.proposal(&proposal)?;
            if stored.status != ProposalStatus::Consumed
                || stored.authority.epoch != this.current_version()?.epoch
                || this.gate_terminal(&stored.operation)?.is_some()
            {
                return Err(refusal("target-settlement"));
            }
            this.check_target_consumption(proposal, approval)?;
            let (status, observed) = match reader(&stored.target) {
                Ok(Some(bytes)) => {
                    let digest = BaseDigest::Present(Digest32::sha256(&bytes));
                    let status = if bytes == stored.new_bytes {
                        ProposalStatus::Applied
                    } else if digest == stored.base_sha256 {
                        ProposalStatus::Failed
                    } else {
                        ProposalStatus::Conflict
                    };
                    (status, Some(digest))
                }
                Ok(None) => (
                    if stored.base_sha256 == BaseDigest::Absent {
                        ProposalStatus::Failed
                    } else {
                        ProposalStatus::Conflict
                    },
                    Some(BaseDigest::Absent),
                ),
                Err(_) => (ProposalStatus::Unknown, None),
            };
            this.target_observation = Some(TargetSettlementObservation {
                proposal,
                approval,
                status,
                observed,
            });
            Ok((status, observed))
        })
    }

    /// Record an already-consumed effect observation; this method cannot execute or retry it.
    pub fn settle_consumed_target(
        &mut self,
        proposal: canon::ids::ProposalId,
        approval: Digest32,
        status: crate::storage::ProposalStatus,
        observed: Option<canon::authority::BaseDigest>,
    ) -> Result<AuthorityRecord> {
        self.mutate(|this| {
            use crate::storage::ProposalStatus;
            use canon::{authority::{BaseDigest, Kind, PendingAuthorityRecord, Phase}, json::Value};
            let observation = this.target_observation.take()
                .ok_or(refusal("target-observation-required"))?;
            if observation.proposal != proposal || observation.approval != approval
                || observation.status != status || observation.observed != observed
            {
                return Err(refusal("target-observation-mismatch"));
            }
            let stored = this.proposal(&proposal)?;
            if stored.authority.epoch != this.current_version()?.epoch {
                return Err(refusal("target-settlement"));
            }
            if stored.status != ProposalStatus::Consumed || this.gate_terminal(&stored.operation)?.is_some() {
                return Err(refusal("target-settlement"));
            }
            this.check_target_consumption(proposal, approval)?;
            let new = BaseDigest::Present(Digest32::sha256(&stored.new_bytes));
            let valid = match status {
                ProposalStatus::Applied | ProposalStatus::Incomplete => observed == Some(new),
                ProposalStatus::Failed => observed == Some(stored.base_sha256),
                ProposalStatus::Conflict => observed.is_some_and(|value| value != new && value != stored.base_sha256),
                ProposalStatus::Unknown => observed.is_none(),
                _ => false,
            };
            if !valid { return Err(refusal("target-settlement")); }
            let base = |digest| match digest { BaseDigest::Absent => "absent".into(), BaseDigest::Present(hash) => hash.to_string() };
            let text = |value: String| Value::text(value);
            let mut fields = vec![
                ("proposal".into(), text(proposal.to_string())?),
                ("target".into(), text(stored.target.clone())?),
                ("operation".into(), text(stored.operation_digest.to_string())?),
                ("base_sha256".into(), text(base(stored.base_sha256))?),
                ("new_sha256".into(), text(Digest32::sha256(&stored.new_bytes).to_string())?),
                ("state".into(), text(status.wire_name().into())?),
                ("retry".into(), Value::boolean(false)),
                ("consumed_approval".into(), text(approval.to_string())?),
                ("observed_sha256".into(), match observed { Some(value) => text(base(value))?, None => Value::null() }),
            ];
            if observed.is_none() { fields.push(("observation".into(), text("unavailable".into())?)); }
            let record = this.write_record(PendingAuthorityRecord {
                v: 1, algorithm: canon::alg::AlgorithmId::Sha256, authority: this.current_version()?,
                at: this.services.clock.now_ms()?,
                kind: if status == ProposalStatus::Applied { Kind::GateApply } else { Kind::GateRecover },
                actor: "gate".into(), operation: Some(stored.operation), phase: Phase::Terminal,
                body: Value::object(fields)?,
            })?;
            this.set_status(proposal, status)?;
            Ok(record)
        })
    }
}

struct TargetSettlementObservation {
    proposal: canon::ids::ProposalId,
    approval: Digest32,
    status: crate::storage::ProposalStatus,
    observed: Option<canon::authority::BaseDigest>,
}

pub struct LedgerTxn<'a> {
    observation_start_changes: u64,
    transaction: rusqlite::Transaction<'a>,
    services: TransactionServices<'a>,
    identity: Digest32,
    state: io::Snapshot,
    retained: &'a mut io::Snapshot,
    poisoned: bool,
    counters: BTreeMap<String, Digest32>,
    consumptions: BTreeSet<String>,
    floor_obligation: Option<Digest32>,
    target_observation: Option<TargetSettlementObservation>,
}

impl LedgerTxn<'_> {
    pub fn current_version(&self) -> Result<AuthorityVersion> {
        self.active()?;
        self.state.next()
    }

    pub fn record_at(&self, version: AuthorityVersion) -> Result<AuthorityRecord> {
        self.active()?;
        let record = io::record_at(&self.transaction, version.sequence)?;
        if record.authority != version {
            return Err(refusal("record-context"));
        }
        crate::record::verify_record(&record, &self.state.keys)?;
        Ok(record)
    }

    pub fn commit(self) -> Result<()> {
        self.active()?;
        if !self.counters.is_empty()
            || !self.consumptions.is_empty()
            || self.floor_obligation.is_some()
            || self.target_observation.is_some()
        {
            return Err(refusal("unfinished-transition"));
        }
        self.transaction.commit().map_err(sql)?;
        *self.retained = self.state;
        Ok(())
    }

    pub fn rollback(self) -> Result<()> {
        self.transaction.rollback().map_err(sql)
    }

    fn active(&self) -> Result<()> {
        if self.poisoned || self.transaction.is_autocommit() {
            Err(refusal("transaction"))
        } else {
            Ok(())
        }
    }

    fn mutate<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.active()?;
        let outcome = action(self);
        if outcome.is_err() {
            self.poisoned = true;
        }
        outcome
    }
}

fn refusal(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "aura",
        reason,
    }
}

impl LedgerTxn<'_> {
    /// Observe retained Kira-table absence under the active transaction.
    /// This cannot prove empty memory without also verifying the complete Aura history.
    pub fn kira_retention_empty(&self) -> Result<bool> {
        use rusqlite::OptionalExtension;
        self.active()?;
        for (table, query) in [
            ("kira_notes_v1", "SELECT EXISTS(SELECT 1 FROM kira_notes_v1)"),
            (
                "kira_demotions_v1",
                "SELECT EXISTS(SELECT 1 FROM kira_demotions_v1)",
            ),
        ] {
            let kind: Option<String> = self
                .transaction
                .query_row(
                    "SELECT type FROM sqlite_master WHERE name=?1",
                    [table],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql)?;
            match kind.as_deref() {
                None => continue,
                Some("table") => {}
                _ => return Err(canon::codes::KIRA_STORE_CORRUPT),
            }
            let present: bool = self
                .transaction
                .query_row(query, [], |row| row.get(0))
                .map_err(sql)?;
            if present {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
fn sql(_: rusqlite::Error) -> canon::Refusal {
    refusal("storage")
}

impl LedgerTxn<'_> {
    /// Read the latest recorded owner subject without creating an authority proof.
    pub fn gate_owner_subject(&self) -> Result<canon::ids::SubjectId> {
        let operation: String = self.transaction.query_row(
            "SELECT op FROM aura WHERE kind IN ('aumlok.enrol','aumlok.bind') AND phase='terminal' ORDER BY seq DESC LIMIT 1",
            [], |row| row.get(0),
        ).map_err(|_| canon::Refusal { organ: "aura", reason: "owner-subject" })?;
        let operation = OperationId::from_hex(&operation)?;
        let record = self
            .gate_terminal(&operation)?
            .ok_or(canon::codes::AURA_UNVERIFIED)?;
        if !matches!(
            record.kind,
            canon::authority::Kind::AumlokEnrol | canon::authority::Kind::AumlokBind
        ) || record.authority.epoch != self.current_version()?.epoch
        {
            return Err(canon::codes::AURA_UNVERIFIED);
        }
        let body = gate_payload(&record.body);
        match body.get("subject").map(canon::json::Value::view) {
            Some(canon::json::ValueView::Text(subject)) => canon::ids::SubjectId::parse(subject),
            _ => Err(canon::Refusal {
                organ: "aura",
                reason: "owner-subject",
            }),
        }
    }

    /// Read the operation's unique terminal for an idempotent lifecycle reply.
    pub fn gate_terminal(&self, operation: &OperationId) -> Result<Option<AuthorityRecord>> {
        use rusqlite::OptionalExtension;
        let row: Option<(String, String)> = self
            .transaction
            .query_row(
                "SELECT hash,body FROM aura WHERE op=?1 AND phase='terminal'",
                [operation.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| canon::codes::AURA_TRANSACTION)?;
        row.map(|(hash, body)| {
            let body = canon::json::parse_strict(body.as_bytes())?;
            let wrapper = crate::record::AuthorityBodyV1::parse(&body)?;
            let record = self.record_at(wrapper.authority)?;
            if record.hash != Digest32::from_hex(&hash)?
                || record.operation != Some(*operation)
                || record.phase != canon::authority::Phase::Terminal
            {
                return Err(canon::codes::AURA_UNVERIFIED);
            }
            Ok(record)
        })
        .transpose()
    }

    /// A rule suggestion may cite only an actual batch with a later recorded review.
    pub fn gate_reviewed_batch(&self, operation: &OperationId, target: &str) -> Result<bool> {
        use rusqlite::OptionalExtension;
        let rows: Option<(String, String)> = self.transaction.query_row(
            "SELECT p.body,r.body FROM aura p JOIN aura r ON r.op=p.op WHERE p.op=?1 AND p.kind='gate.propose' AND p.phase='intent' AND r.kind='gate.review' AND r.seq>p.seq ORDER BY r.seq DESC LIMIT 1",
            [operation.to_string()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|_| canon::codes::AURA_TRANSACTION)?;
        let Some((proposed, reviewed)) = rows else {
            return Ok(false);
        };
        let proposed = canon::json::parse_strict(proposed.as_bytes())?;
        let reviewed = canon::json::parse_strict(reviewed.as_bytes())?;
        let proposed =
            self.record_at(crate::record::AuthorityBodyV1::parse(&proposed)?.authority)?;
        let reviewed =
            self.record_at(crate::record::AuthorityBodyV1::parse(&reviewed)?.authority)?;
        if proposed.kind != canon::authority::Kind::GatePropose
            || proposed.phase != canon::authority::Phase::Intent
            || reviewed.kind != canon::authority::Kind::GateReview
            || reviewed.phase == canon::authority::Phase::Terminal
            || proposed.operation != Some(*operation)
            || reviewed.operation != Some(*operation)
            || reviewed.authority.sequence <= proposed.authority.sequence
        {
            return Err(canon::codes::AURA_UNVERIFIED);
        }
        Ok(matches!(
            gate_payload(&proposed.body)
                .get("suggestion")
                .map(canon::json::Value::view),
            Some(canon::json::ValueView::Text("batch"))
        ) && matches!(gate_payload(&proposed.body).get("target").map(canon::json::Value::view),
                Some(canon::json::ValueView::Text(value)) if value == target)
            && matches!(
                gate_payload(&reviewed.body)
                    .get("action")
                    .map(canon::json::Value::view),
                Some(canon::json::ValueView::Text("apply"))
            ))
    }
}

impl LedgerTxn<'_> {
    /// Read the transaction's signer public keys; this grants no append capability.
    pub fn floor_signing_keys(&self) -> Result<Vec<PublicKey>> {
        self.services.signer.public_keys()
    }

    /// Locate a retained row by sequence, then authenticate its full stored context.
    pub fn floor_record_at_sequence(&self, sequence: u64) -> Result<Option<AuthorityRecord>> {
        use rusqlite::OptionalExtension;
        if sequence == 0 || sequence > canon::json::MAX_SAFE_INTEGER as u64 {
            return Err(canon::codes::AURA_UNVERIFIED);
        }
        let stored: Option<(String, String)> = self
            .transaction
            .query_row(
                "SELECT hash,body FROM aura WHERE seq=?1",
                [sequence as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| canon::codes::AURA_TRANSACTION)?;
        let Some((claimed_hash, body)) = stored else {
            return Ok(None);
        };
        let body = canon::json::parse_strict(body.as_bytes())?;
        let context = crate::record::AuthorityBodyV1::parse(&body)?.authority;
        let record = self.record_at(context)?;
        if record.authority.sequence != sequence
            || record.hash != Digest32::from_hex(&claimed_hash)?
        {
            return Err(canon::codes::AURA_UNVERIFIED);
        }
        Ok(Some(record))
    }

    /// Read locked release append coordinates without consuming the owner proof.
    pub fn floor_append_context(
        &self,
        proof: &VerifiedProof,
    ) -> Result<canon::authority::AuthorityAppendContext> {
        if proof.transaction_id() != self.identity {
            return Err(canon::Refusal {
                organ: "aura",
                reason: "proof-transaction",
            });
        }
        let proposal = self.proposal(&proof.authorization().proposal)?;
        Ok(canon::authority::AuthorityAppendContext {
            authority: self.current_version()?,
            at: self.services.clock.now_ms()?,
            operation_id: proposal.operation,
        })
    }
}

fn gate_payload(value: &canon::json::Value) -> &canon::json::Value {
    if matches!(
        value.get("schema").map(canon::json::Value::view),
        Some(canon::json::ValueView::Text(
            crate::record::AUTHORITY_BODY_SCHEMA
        ))
    ) {
        value.get("payload").unwrap_or(value)
    } else {
        value
    }
}

impl LedgerTxn<'_> {
    fn immune_committed_records(&self) -> Result<Vec<AuthorityRecord>> {
        if self.poisoned {
            return Err(refusal("transaction"));
        }
        if self.transaction.is_autocommit() {
            let snapshot = self.transaction.unchecked_transaction().map_err(sql)?;
            let records = immune_prefix(&snapshot, self.retained)?;
            snapshot.commit().map_err(sql)?;
            Ok(records)
        } else {
            immune_prefix(&self.transaction, self.retained)
        }
    }
}

fn immune_prefix(
    connection: &rusqlite::Connection,
    retained: &io::Snapshot,
) -> Result<Vec<AuthorityRecord>> {
    use canon::authority::{Kind, Phase};
    let mut previous = None;
    let mut epoch = 0;
    let mut frontier = crate::merkle::Frontier::default();
    let mut records = Vec::new();
    let mut selected_bytes = 0_usize;
    for sequence in 1..=retained.frontier.size() {
        let record = io::record_at(connection, sequence)?;
        crate::record::verify_record(&record, &retained.keys)?;
        if record.authority.sequence != sequence
            || record.authority.previous_hash != previous
            || record.authority.epoch < epoch
            || record.authority.epoch > epoch + 1
        {
            return Err(refusal("immune-history-context"));
        }
        if record.authority.epoch != epoch {
            authority::verify_epoch_body(&record, epoch, connection)?;
        }
        previous = Some(record.hash);
        epoch = record.authority.epoch;
        frontier.push(record.hash)?;
        let body = gate_payload(&record.body);
        let selected = if record.kind == Kind::GateRetire
            && (record.actor == "immune"
                || matches!(
                    body.get("target").map(canon::json::Value::view),
                    Some(canon::json::ValueView::Text("immune.antibodies"))
                )) {
            authority::verify_immune_retirement(connection, &record, &retained.keys)?;
            true
        } else if record.kind == Kind::BootFacts
            && record.actor == "immune"
            && record.phase == Phase::Fact
            && record.operation.is_none()
        {
            matches!(body.get("schema").map(canon::json::Value::view), Some(canon::json::ValueView::Text(schema))
                if schema.starts_with("aukora-immune-heldout-") || schema.starts_with("aukora-immune-release-"))
        } else {
            false
        };
        if selected {
            selected_bytes = selected_bytes
                .checked_add(record.body.canonical_bytes().len())
                .ok_or(refusal("immune-history-limit"))?;
            if records.len() >= 16_384 || selected_bytes > 16 * 1024 * 1024 {
                return Err(refusal("immune-history-limit"));
            }
            records.push(record);
        }
    }
    if previous != retained.hash
        || epoch != retained.epoch
        || frontier.root() != retained.frontier.root()
    {
        return Err(refusal("immune-history-context"));
    }
    Ok(records)
}

impl Ledger {
    /// Authenticate a retained checkpoint from one read snapshot.
    pub fn retained_head(&self) -> Result<crate::export::RetainedHeadV1> {
        let transaction = self.connection.unchecked_transaction().map_err(sql)?;
        crate::schema::validate(&transaction)?;
        let state = io::verify(&transaction)?;
        self.check_snapshot(&transaction, &state)?;
        state.head()
    }

    /// Prove extension of the caller's independent checkpoint after checking its chain hash.
    pub fn present_from(
        &self,
        retained: &crate::export::RetainedHeadV1,
    ) -> Result<crate::export::PresentedHeadV1> {
        retained.canonical_bytes()?;
        let transaction = self.connection.unchecked_transaction().map_err(sql)?;
        crate::schema::validate(&transaction)?;
        let verified = io::verify(&transaction)?;
        self.check_snapshot(&transaction, &verified)?;
        let head = verified.head()?;
        if retained.sequence > head.sequence {
            return Err(refusal("retained-head-ahead"));
        }
        let (hash, root):(String,String) = transaction.query_row(
            "SELECT a.hash,w.root FROM aura a JOIN aura_record_wrappers w ON w.seq=a.seq WHERE a.seq=?1",
            [i64::try_from(retained.sequence).map_err(|_|refusal("sequence-range"))?],|row|Ok((row.get(0)?,row.get(1)?))).map_err(sql)?;
        if Digest32::from_hex(&hash)? != retained.hash
            || Digest32::from_hex(&root)? != retained.root
        {
            return Err(refusal("retained-prefix-rewritten"));
        }
        let mut hashes = Vec::new();
        let mut statement = transaction
            .prepare("SELECT hash FROM aura ORDER BY seq")
            .map_err(sql)?;
        let mut cursor = statement.query([]).map_err(sql)?;
        while let Some(row) = cursor.next().map_err(sql)? {
            hashes.push(Digest32::from_hex(&row.get::<_, String>(0).map_err(sql)?)?);
        }
        let proof = crate::merkle::consistency(
            &hashes,
            usize::try_from(retained.sequence).map_err(|_| refusal("sequence-range"))?,
        )?;
        crate::merkle::verify_consistency(
            retained.tree_size,
            head.tree_size,
            retained.root,
            head.root,
            &proof,
        )?;
        Ok(crate::export::PresentedHeadV1 {
            tree_size: head.tree_size,
            root: head.root,
            retained_tree_size: retained.tree_size,
            proof_from_previous: proof,
        })
    }
}

impl Ledger {
    fn check_snapshot(
        &self,
        connection: &rusqlite::Connection,
        observed: &io::Snapshot,
    ) -> Result<()> {
        if observed.frontier.size() < self.verified.frontier.size()
            || observed.epoch < self.verified.epoch
            || (!self.verified.keys.is_empty() && observed.keys != self.verified.keys)
        {
            return Err(refusal("retained-state-rollback"));
        }
        if let Some(hash) = self.verified.hash {
            if io::record_at(connection, self.verified.frontier.size())?.hash != hash {
                return Err(refusal("retained-prefix-rewritten"));
            }
        }
        Ok(())
    }
}
