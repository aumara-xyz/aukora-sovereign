// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private SQLite ownership; all authority service bodies remain closed in wave 0.

use std::path::Path;

use canon::{
    alg::{PublicKey, Signature, Signatures},
    authority::{
        AuthorityRecord, AuthorityTxn, AuthorityVersion, FactRecord, LifecycleRecord,
        OwnerAuthorization, OwnerBinding, OwnerOperation, PendingAuthorityRecord,
        StandingUseContext, VerifiedProof, VerifiedStandingUse,
    },
    digest::Digest32,
    ids::{CredentialId, OperationDigest, OperationId, ProposalId},
    Result,
};

use crate::{
    export::{ColdProofV1, ExportLimits},
    storage::{
        DeclinedProposal, OperationCoverage, ProposalState, RecoveryWork, StagedAuthorization,
    },
};

/// A signing service holds the key; Aura receives only public keys and signatures.
pub trait RecordSigner {
    fn public_keys(&self) -> Result<Vec<PublicKey>>;
    fn sign_entry_hash(&self, hash: Digest32) -> Result<Signatures>;
}

/// The supervisor supplies clock observations. Time never substitutes for sequence.
pub trait TrustedClock {
    fn now_ms(&self) -> Result<i64>;
}

#[derive(Clone, Copy)]
pub struct TransactionServices<'a> {
    pub signer: &'a dyn RecordSigner,
    pub clock: &'a dyn TrustedClock,
}

/// No public connection, unchecked constructor, generic SQL, or mutable raw handle.
pub struct Ledger {
    connection: rusqlite::Connection,
}

impl Ledger {
    /// Wave-1 contract: open the owner-selected file, verify schema and both arms,
    /// apply only admitted migrations, reject unknown schemas or damaged history.
    pub fn open(_path: &Path) -> Result<Self> {
        crate::unavailable()
    }

    /// Wave-1 contract: fresh unpredictable transaction identity and BEGIN IMMEDIATE.
    /// The signer is borrowed; Aura never takes custody of its secret key.
    pub fn begin<'a>(&'a mut self, _services: TransactionServices<'a>) -> Result<LedgerTxn<'a>> {
        let _ = &self.connection;
        crate::unavailable()
    }

    /// Read one authenticated snapshot, including full rows and their covering head.
    pub fn export_cold_proof(&self, _limits: ExportLimits) -> Result<ColdProofV1> {
        crate::unavailable()
    }
}

/// Drop rolls SQLite back. There is no public constructor or connection accessor.
/// A transaction can commit only after its counter/consumption/append obligations close.
pub struct LedgerTxn<'a> {
    transaction: rusqlite::Transaction<'a>,
    services: TransactionServices<'a>,
    identity: Digest32,
}

impl LedgerTxn<'_> {
    pub fn current_version(&self) -> Result<AuthorityVersion> {
        crate::unavailable()
    }

    /// Return only a retained row matching this exact epoch, sequence and predecessor.
    pub fn record_at(&self, _version: AuthorityVersion) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    /// Stage only Pending exact proposal bytes; reject occupied targets and declines
    /// with the same operation/evidence commitments. No approval is created here.
    pub fn stage_proposal(&mut self, _proposal: ProposalState) -> Result<()> {
        crate::unavailable()
    }

    pub fn proposal(&self, _proposal: &ProposalId) -> Result<ProposalState> {
        crate::unavailable()
    }

    /// Include interrupted unconsumed proposals so reconciliation can expire/refuse them.
    pub fn pending_proposals(&self, _limit: usize) -> Result<Vec<ProposalState>> {
        crate::unavailable()
    }

    /// Store exact card/auth bytes only after recomputing all commitments from storage.
    pub fn stage_authorization(&mut self, _authorization: StagedAuthorization) -> Result<()> {
        crate::unavailable()
    }

    pub fn last_decline(&self, _operation: OperationDigest) -> Result<Option<DeclinedProposal>> {
        crate::unavailable()
    }

    /// Store a nonauthorizing refusal terminal, release its target, retain its decline.
    /// A consumed approval cannot take this path; it must be reconciled.
    pub fn decline(
        &mut self,
        _proposal: &ProposalId,
        _row: LifecycleRecord,
    ) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    pub fn recovery_work(&self, _limit: usize) -> Result<Vec<RecoveryWork>> {
        crate::unavailable()
    }

    /// Release only after the recorded terminal is verified for this exact operation.
    /// Pending or consumed state without that terminal cannot release a reservation.
    pub fn release_reservation(&mut self, _proposal: &ProposalId) -> Result<()> {
        crate::unavailable()
    }

    pub fn operation_coverage(&self, _operation: &OperationId) -> Result<OperationCoverage> {
        crate::unavailable()
    }

    /// Floor owns the versioned protected-state format; Aura keeps its exact bytes.
    pub fn floor_state(&self) -> Result<Option<Vec<u8>>> {
        crate::unavailable()
    }

    /// Stage only under the same transaction's persisted, consumed Release proof.
    /// Compare the previous commitment; the next state's seven-key floor member
    /// must match C5's exact approved bytes. Derive high-water metadata from locked
    /// state, preserving spent approvals and rejecting any counter/epoch rollback.
    /// The corresponding signed floor.advance append must close this obligation.
    pub fn stage_floor(
        &mut self,
        _proof: &VerifiedProof,
        _expected_state_digest: Option<Digest32>,
        _next_state_bytes: &[u8],
    ) -> Result<()> {
        crate::unavailable()
    }

    /// All staged authority obligations must be satisfied; partial transitions refuse.
    pub fn commit(self) -> Result<()> {
        let _ = (&self.transaction, &self.services);
        crate::unavailable()
    }

    pub fn rollback(self) -> Result<()> {
        self.transaction
            .rollback()
            .map_err(|_| canon::codes::AURA_TRANSACTION)
    }
}

impl AuthorityTxn for LedgerTxn<'_> {
    fn transaction_id(&self) -> Digest32 {
        self.identity
    }

    fn owner_binding(&mut self, _credential: &CredentialId) -> Result<OwnerBinding> {
        crate::unavailable()
    }

    fn rebuild_authorization(
        &mut self,
        _proposal: &ProposalId,
        _action: OwnerOperation,
    ) -> Result<OwnerAuthorization> {
        crate::unavailable()
    }

    fn verify_signature(
        &mut self,
        _key: &PublicKey,
        _signed_bytes: &[u8],
        _signature: &Signature,
    ) -> Result<()> {
        crate::unavailable()
    }

    fn persist_counter(&mut self, _proof: &VerifiedProof) -> Result<()> {
        crate::unavailable()
    }

    fn consume(&mut self, _proof: &VerifiedProof) -> Result<()> {
        crate::unavailable()
    }

    fn append(
        &mut self,
        _proof: VerifiedProof,
        _record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    fn check_standing_use(
        &mut self,
        _permission_id: &ProposalId,
        _permission_digest: Digest32,
        _proposal: &ProposalId,
        _action: OwnerOperation,
    ) -> Result<StandingUseContext> {
        crate::unavailable()
    }

    fn append_standing(
        &mut self,
        _usage: VerifiedStandingUse,
        _record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    fn append_lifecycle(&mut self, _observation: LifecycleRecord) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    fn append_fact(&mut self, _fact: FactRecord) -> Result<AuthorityRecord> {
        crate::unavailable()
    }
}

impl LedgerTxn<'_> {
    /// Read the latest recorded owner subject without creating an authority proof.
    pub fn gate_owner_subject(&self) -> Result<canon::ids::SubjectId> {
        let operation: String = self.transaction.query_row(
            "SELECT op FROM aura WHERE kind IN ('aumlok.enrol','aumlok.bind') AND phase='terminal' ORDER BY seq DESC LIMIT 1",
            [], |row| row.get(0),
        ).map_err(|_| canon::Refusal { organ: "aura", reason: "owner-subject" })?;
        let operation = OperationId::from_hex(&operation)?;
        let record = self.gate_terminal(&operation)?.ok_or(canon::codes::AURA_UNVERIFIED)?;
        if !matches!(record.kind, canon::authority::Kind::AumlokEnrol | canon::authority::Kind::AumlokBind)
            || record.authority.epoch != self.current_version()?.epoch {
            return Err(canon::codes::AURA_UNVERIFIED);
        }
        let body = gate_payload(&record.body);
        match body.get("subject").map(canon::json::Value::view) {
            Some(canon::json::ValueView::Text(subject)) => canon::ids::SubjectId::parse(subject),
            _ => Err(canon::Refusal { organ: "aura", reason: "owner-subject" }),
        }
    }

    /// Read the operation's unique terminal for an idempotent lifecycle reply.
    pub fn gate_terminal(&self, operation: &OperationId) -> Result<Option<AuthorityRecord>> {
        use rusqlite::OptionalExtension;
        let row: Option<(String, String)> = self.transaction.query_row(
            "SELECT hash,body FROM aura WHERE op=?1 AND phase='terminal'",
            [operation.to_string()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|_| canon::codes::AURA_TRANSACTION)?;
        row.map(|(hash, body)| {
            let body = canon::json::parse_strict(body.as_bytes())?;
            let wrapper = crate::record::AuthorityBodyV1::parse(&body)?;
            let record = self.record_at(wrapper.authority)?;
            if record.hash != Digest32::from_hex(&hash)? || record.operation != Some(*operation)
                || record.phase != canon::authority::Phase::Terminal {
                return Err(canon::codes::AURA_UNVERIFIED);
            }
            Ok(record)
        }).transpose()
    }

    /// A rule suggestion may cite only an actual batch with a later recorded review.
    pub fn gate_reviewed_batch(&self, operation: &OperationId, target: &str) -> Result<bool> {
        use rusqlite::OptionalExtension;
        let rows: Option<(String, String)> = self.transaction.query_row(
            "SELECT p.body,r.body FROM aura p JOIN aura r ON r.op=p.op WHERE p.op=?1 AND p.kind='gate.propose' AND p.phase='intent' AND r.kind='gate.review' AND r.seq>p.seq ORDER BY r.seq DESC LIMIT 1",
            [operation.to_string()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|_| canon::codes::AURA_TRANSACTION)?;
        let Some((proposed, reviewed)) = rows else { return Ok(false); };
        let proposed = canon::json::parse_strict(proposed.as_bytes())?;
        let reviewed = canon::json::parse_strict(reviewed.as_bytes())?;
        let proposed = self.record_at(crate::record::AuthorityBodyV1::parse(&proposed)?.authority)?;
        let reviewed = self.record_at(crate::record::AuthorityBodyV1::parse(&reviewed)?.authority)?;
        if proposed.kind != canon::authority::Kind::GatePropose || proposed.phase != canon::authority::Phase::Intent
            || reviewed.kind != canon::authority::Kind::GateReview || reviewed.phase == canon::authority::Phase::Terminal
            || proposed.operation != Some(*operation) || reviewed.operation != Some(*operation)
            || reviewed.authority.sequence <= proposed.authority.sequence {
            return Err(canon::codes::AURA_UNVERIFIED);
        }
        Ok(matches!(gate_payload(&proposed.body).get("suggestion").map(canon::json::Value::view),
            Some(canon::json::ValueView::Text("batch")))
            && matches!(gate_payload(&proposed.body).get("target").map(canon::json::Value::view),
                Some(canon::json::ValueView::Text(value)) if value == target)
            && matches!(gate_payload(&reviewed.body).get("action").map(canon::json::Value::view),
                Some(canon::json::ValueView::Text("apply"))))
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
        let stored: Option<(String, String)> = self.transaction.query_row(
            "SELECT hash,body FROM aura WHERE seq=?1",
            [sequence as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|_| canon::codes::AURA_TRANSACTION)?;
        let Some((claimed_hash, body)) = stored else { return Ok(None); };
        let body = canon::json::parse_strict(body.as_bytes())?;
        let context = crate::record::AuthorityBodyV1::parse(&body)?.authority;
        let record = self.record_at(context)?;
        if record.authority.sequence != sequence || record.hash != Digest32::from_hex(&claimed_hash)? {
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
            return Err(canon::Refusal { organ: "aura", reason: "proof-transaction" });
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
    if matches!(value.get("schema").map(canon::json::Value::view),
        Some(canon::json::ValueView::Text(crate::record::AUTHORITY_BODY_SCHEMA))) {
        value.get("payload").unwrap_or(value)
    } else { value }
}
