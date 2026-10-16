// SPDX-License-Identifier: AGPL-3.0-or-later
//! Proof-bound mutations share the active SQLite write transaction.
use super::proposals::field;
use super::*;
use crate::storage::{self, ProposalStatus};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use canon::{
    alg::Signature,
    authority::{
        FactRecord, Kind, LifecycleKind, LifecycleRecord, OwnerAuthorization, OwnerBinding,
        OwnerOperation, PendingAuthorityRecord, Phase, StandingUseContext, VerifiedStandingUse,
    },
    ids::{CredentialId, ProposalId},
    json::{self, Value},
};
use rusqlite::params;

pub(super) use super::epochs::verify_epoch_body;
mod standing;

impl AuthorityTxn for LedgerTxn<'_> {
    fn finish_ceremony(
        &mut self,
        request: canon::authority::ceremony::CeremonyFinish<'_>,
    ) -> Result<()> {
        self.mutate(|this| this.enrol_owner(request))
    }

    fn authority_state(&mut self, namespace: &str, key: &str) -> Result<Option<Value>> {
        self.read_broker_absence(namespace, key)
    }

    fn committed_authority_state(&mut self, namespace: &str, key: &str) -> Result<Option<Value>> {
        self.read_broker_absence(namespace, key)
    }

    fn pending_broker_reservations(&mut self) -> Result<Vec<Value>> {
        self.read_empty_broker_pending()
    }

    fn committed_immune_records(&mut self) -> Result<Vec<AuthorityRecord>> {
        self.immune_committed_records()
    }

    fn commit_antibody_retirement(
        &mut self,
        proof: VerifiedProof,
        record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.mutate(|this| {
            let writes = this
                .transaction
                .total_changes()
                .checked_sub(this.observation_start_changes)
                .ok_or(refusal("immune-retirement-context"))?;
            if this.state.next()? != this.retained.next()?
                || writes != 4
                || !this.counters.is_empty()
                || this.consumptions.len() != 1
                || this.floor_obligation.is_some()
            {
                return Err(refusal("immune-retirement-staged"));
            }
            this.check_proof(&proof, true)?;
            let auth = proof.authorization();
            let proposal = this.proposal(&auth.proposal)?;
            let payload = gate_payload(&record.body);
            let retirement = immune_retirement_payload(payload)?;
            if auth.op != OwnerOperation::Retire
                || auth.target != "immune.antibodies"
                || auth.cell.is_some()
                || proposal.target != auth.target
                || retirement.canonical_bytes() != proposal.new_bytes
                || auth.base_sha256
                    != canon::authority::BaseDigest::Present(Digest32::from_hex(immune_text(
                        retirement,
                        "registry_sha256",
                    )?)?)
                || record.kind != Kind::GateRetire
                || record.phase != Phase::Terminal
                || record.actor != "immune"
            {
                return Err(refusal("immune-retirement-context"));
            }
            let appended = this.append_proven(proof, record, false)?;
            if !this.counters.is_empty()
                || !this.consumptions.is_empty()
                || this.floor_obligation.is_some()
                || this
                    .transaction
                    .total_changes()
                    .checked_sub(this.observation_start_changes)
                    != Some(8)
            {
                return Err(refusal("immune-retirement-staged"));
            }
            verify_immune_retirement(&this.transaction, &appended, &this.state.keys)?;
            this.transaction.execute_batch("COMMIT").map_err(sql)?;
            *this.retained = this.state.clone();
            Ok(appended)
        })
    }

    fn transaction_id(&self) -> Digest32 {
        self.identity
    }

    fn owner_binding(&mut self, credential: &CredentialId) -> Result<OwnerBinding> {
        self.active()?;
        let (bytes, counter): (Vec<u8>, u32) = self
            .transaction
            .query_row(
                "SELECT body,counter FROM authority_bindings WHERE credential=?1",
                [URL_SAFE_NO_PAD.encode(credential.as_bytes())],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(sql)?;
        let mut binding = storage::decode_binding(&bytes)?;
        if binding.credential_id != *credential
            || binding.epoch != self.state.epoch
            || counter < binding.sign_counter
        {
            return Err(refusal("binding-context"));
        }
        binding.sign_counter = counter;
        super::epochs::binding_anchor(&self.transaction, &binding, &self.state.keys)?;
        let maximum: Option<u32> = self
            .transaction
            .query_row(
                "SELECT max(counter) FROM authority_consumptions WHERE credential=?1",
                [URL_SAFE_NO_PAD.encode(credential.as_bytes())],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if maximum.is_some_and(|previous| previous > counter) {
            return Err(refusal("counter-rollback"));
        }
        binding.sign_counter = counter;
        Ok(binding)
    }

    fn rebuild_authorization(
        &mut self,
        proposal: &ProposalId,
        action: OwnerOperation,
    ) -> Result<OwnerAuthorization> {
        self.active()?;
        self.authorization(proposal, action)
    }

    fn check_authorization_live(&mut self, authorization: &OwnerAuthorization) -> Result<()> {
        self.active()?;
        if self.authorization(&authorization.proposal, authorization.op)? != *authorization {
            return Err(refusal("authorization-changed"));
        }
        Ok(())
    }

    fn verify_signature(
        &mut self,
        key: &PublicKey,
        bytes: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        self.active()?;
        crate::record::verify_signature(key, bytes, signature)
    }

    fn persist_counter(&mut self, proof: &VerifiedProof) -> Result<()> {
        self.mutate(|this| {
            this.check_proof(proof, false)?;
            let approval = Digest32::sha256(proof.authorization_bytes()).to_string();
            if this.counters.contains_key(&approval) || this.consumptions.contains(&approval) {
                return Err(refusal("counter-already-persisted"));
            }
            let binding = this.owner_binding(proof.credential_id())?;
            if binding.sign_counter != 0 && proof.sign_counter() <= binding.sign_counter {
                return Err(refusal("counter-replay"));
            }
            let changed = this
                .transaction
                .execute(
                    "UPDATE authority_bindings SET counter=?2 WHERE credential=?1 AND counter=?3",
                    params![
                        URL_SAFE_NO_PAD.encode(proof.credential_id().as_bytes()),
                        proof.sign_counter(),
                        binding.sign_counter
                    ],
                )
                .map_err(sql)?;
            if changed != 1 {
                return Err(refusal("counter-conflict"));
            }
            this.counters
                .insert(approval, Digest32::sha256(&proof_bytes(proof)?));
            Ok(())
        })
    }

    fn consume(&mut self, proof: &VerifiedProof) -> Result<()> {
        self.mutate(|this| {
            this.check_proof(proof, false)?;
            let digest = Digest32::sha256(proof.authorization_bytes());
            let approval = digest.to_string();
            if this.counters.get(&approval) != Some(&Digest32::sha256(&proof_bytes(proof)?)) { return Err(refusal("counter-not-persisted")); }
            let auth = proof.authorization();
            let proposal = this.proposal(&auth.proposal)?;
            let version = this.current_version()?;
            let prior:i64 = this.transaction.query_row("SELECT count(*) FROM aura WHERE op=?1 AND kind IN ('gate.consume','gate.apply','gate.retire','floor.advance','aumlok.bind','broker.grant','broker.revoke','kira.permission')",[proposal.operation.to_string()],|r|r.get(0)).map_err(sql)?;
            if prior != 0 { return Err(refusal("operation-already-authorized")); }
            let proof_bytes = proof_bytes(proof)?;
            if this.transaction.execute("UPDATE authority_challenges SET spent=1 WHERE proposal=?1 AND action=?2 AND challenge=?3 AND spent=0",
                params![auth.proposal.to_string(),auth.op.wire_name(),auth.challenge.to_string()]).map_err(sql)? != 1 { return Err(refusal("challenge-spent")); }
            this.transaction.execute("INSERT INTO authority_consumptions(approval,proposal,operation,epoch,sequence,proof,credential,counter,action,appended,previous_hash) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10)",
                params![approval,auth.proposal.to_string(),proposal.operation.to_string(),sql_number(auth.epoch)?,sql_number(version.sequence)?,proof_bytes,URL_SAFE_NO_PAD.encode(proof.credential_id().as_bytes()),proof.sign_counter(),auth.op.wire_name(),version.previous_hash.map(|v|v.to_string())]).map_err(sql)?;
            this.set_status(auth.proposal,ProposalStatus::Consumed)?;
            this.counters.remove(&approval);
            this.consumptions.insert(approval);
            Ok(())
        })
    }

    fn append(
        &mut self,
        proof: VerifiedProof,
        record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.mutate(|this| this.append_proven(proof, record, false))
    }

    fn append_epoch_change(
        &mut self,
        proof: VerifiedProof,
        record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.mutate(|this| this.append_proven(proof, record, true))
    }

    fn authority_append_context(
        &mut self,
        proof: &VerifiedProof,
    ) -> Result<canon::authority::AuthorityAppendContext> {
        self.floor_append_context(proof)
    }

    fn observation_context(&mut self) -> Result<canon::authority::ObservationContext> {
        Ok(canon::authority::ObservationContext {
            authority: self.current_version()?,
            at: self.services.clock.now_ms()?,
        })
    }

    fn committed_observation_state(
        &mut self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<Value>> {
        self.read_committed_observation(namespace, key)
    }

    fn commit_observations(&mut self) -> Result<()> {
        self.commit_fact_observations()
    }

    fn check_standing_use(
        &mut self,
        permission_id: &ProposalId,
        permission_digest: Digest32,
        proposal: &ProposalId,
        action: OwnerOperation,
    ) -> Result<StandingUseContext> {
        self.check_standing(permission_id, permission_digest, proposal, action)
    }
    fn append_standing(
        &mut self,
        usage: VerifiedStandingUse,
        record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.mutate(|this| this.append_standing_use(usage, record))
    }

    fn revoke_standing(&mut self, permission: &ProposalId, digest: Digest32) -> Result<()> {
        self.mutate(|this| this.revoke_standing_permission(permission, digest))
    }

    fn append_lifecycle(&mut self, row: LifecycleRecord) -> Result<AuthorityRecord> {
        self.mutate(|this| {
            let id: String = this.transaction.query_row("SELECT id FROM authority_proposals WHERE operation=?1",[row.operation.to_string()],|r|r.get(0)).map_err(sql)?;
            let id = ProposalId::from_hex(&id)?;
            let proposal = this.proposal(&id)?;
            let body = gate_payload(&row.body);
            if field(body,"proposal") != Some(id.to_string().as_str()) { return Err(refusal("lifecycle-proposal")); }
            let status = match row.kind {
                LifecycleKind::GatePropose => {
                    if proposal.status != ProposalStatus::Pending || row.phase != Phase::Intent || this.operation_coverage(&row.operation)?.intents != 0 { return Err(refusal("lifecycle-phase")); }
                    None
                }
                LifecycleKind::GateReview => {
                    if proposal.status != ProposalStatus::Pending || row.phase != Phase::Settle { return Err(refusal("lifecycle-phase")); }
                    let action = match field(body,"action") { Some("apply")=>OwnerOperation::Apply,Some("retire")=>OwnerOperation::Retire,_=>return Err(refusal("review-action")) };
                    let auth = this.authorization(&id,action)?;
                    if field(body,"display_sha256") != Some(auth.display_sha256.to_string().as_str())
                        || field(body,"authorization_sha256") != Some(Digest32::sha256(&auth.canonical_bytes()?).to_string().as_str()) { return Err(refusal("review-commitment")); }
                    None
                }
                LifecycleKind::GateRefuse | LifecycleKind::GateExpire => {
                    if proposal.status != ProposalStatus::Pending || row.phase != Phase::Terminal { return Err(refusal("lifecycle-phase")); }
                    let live:i64 = this.transaction.query_row("SELECT count(*) FROM authority_challenges WHERE proposal=?1 AND spent=0",[id.to_string()],|r|r.get(0)).map_err(sql)?;
                    if live != 0 {
                        let mut statement = this.transaction.prepare("SELECT body FROM authority_challenges WHERE proposal=?1 AND spent=0").map_err(sql)?;
                        let mut cursor = statement.query([id.to_string()]).map_err(sql)?;
                        while let Some(raw) = cursor.next().map_err(sql)? {
                            let auth = storage::decode_authorization(&raw.get::<_,Vec<u8>>(0).map_err(sql)?)?;
                            if this.services.clock.now_ms()? < auth.expires_at { return Err(refusal("review-still-live")); }
                        }
                    }
                    Some(if row.kind == LifecycleKind::GateExpire { ProposalStatus::Expired } else { ProposalStatus::Refused })
                }
                LifecycleKind::GateRecover { consumed_approval } => {
                    if proposal.status != ProposalStatus::Consumed || !matches!(row.phase,Phase::Settle|Phase::Terminal)
                        || field(body,"consumed_approval") != Some(consumed_approval.to_string().as_str()) { return Err(refusal("recovery-context")); }
                    let (operation,epoch,appended):(String,i64,i64) = this.transaction.query_row("SELECT operation,epoch,appended FROM authority_consumptions WHERE approval=?1 AND proposal=?2",params![consumed_approval.to_string(),id.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(sql)?;
                    if operation != row.operation.to_string() || epoch != sql_number(row.authority.epoch)? || appended != 1 { return Err(refusal("recovery-context")); }
                    let state = match field(body,"state") { Some("incomplete")=>ProposalStatus::Incomplete,Some("failed")=>ProposalStatus::Failed,Some("conflict")=>ProposalStatus::Conflict,Some("unknown")=>ProposalStatus::Unknown,_=>return Err(refusal("recovery-state")) };
                    bind_gate_body(body,&proposal,consumed_approval,state.wire_name())?;
                    if row.phase == Phase::Terminal { Some(state) } else { None }
                }
            };
            if let Some(status) = status {
                if field(body,"state") != Some(status.wire_name()) { return Err(refusal("lifecycle-state")); }
            }
            let record = this.write_record(PendingAuthorityRecord { v:row.v,algorithm:row.algorithm,authority:row.authority,at:row.at,kind:row.kind.kind(),actor:row.actor,operation:Some(row.operation),phase:row.phase,body:row.body })?;
            if let Some(status) = status {
                this.set_status(id,status)?;
                if matches!(status,ProposalStatus::Expired|ProposalStatus::Refused) {
                    this.transaction.execute("INSERT INTO authority_declines(proposal,operation_digest,evidence_digest,target,epoch,sequence,previous_hash) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                        params![id.to_string(),proposal.operation_digest.to_string(),proposal.evidence_digest.to_string(),proposal.target,sql_number(record.authority.epoch)?,sql_number(record.authority.sequence)?,record.authority.previous_hash.map(|v|v.to_string())]).map_err(sql)?;
                }
            }
            Ok(record)
        })
    }

    fn append_fact(&mut self, fact: FactRecord) -> Result<AuthorityRecord> {
        self.mutate(|this| {
            this.write_record(PendingAuthorityRecord {
                v: fact.v,
                algorithm: fact.algorithm,
                authority: fact.authority,
                at: fact.at,
                kind: fact.kind.kind(),
                actor: fact.actor,
                operation: None,
                phase: Phase::Fact,
                body: fact.body,
            })
        })
    }
}

impl LedgerTxn<'_> {
    fn check_proof(&mut self, proof: &VerifiedProof, consumed: bool) -> Result<()> {
        self.active()?;
        if proof.transaction_id() != self.identity
            || proof.authorization().epoch != self.state.epoch
        {
            return Err(refusal("proof-transaction"));
        }
        let binding = self.owner_binding(proof.credential_id())?;
        if binding.public_key != *proof.public_key()
            || binding.algorithm != proof.algorithm()
            || binding.top_origin != proof.top_origin()
        {
            return Err(refusal("proof-binding"));
        }
        crate::record::verify_signature(
            proof.public_key(),
            proof.signed_bytes(),
            &proof.assertion().signature,
        )?;
        if !consumed
            && self
                .authorization(&proof.authorization().proposal, proof.authorization().op)?
                .canonical_bytes()?
                != proof.authorization_bytes()
        {
            return Err(refusal("proof-authorization"));
        }
        Ok(())
    }

    fn append_proven(
        &mut self,
        proof: VerifiedProof,
        pending: PendingAuthorityRecord,
        epoch_change: bool,
    ) -> Result<AuthorityRecord> {
        self.check_proof(&proof, true)?;
        let approval = Digest32::sha256(proof.authorization_bytes());
        if !self.consumptions.contains(&approval.to_string()) {
            return Err(refusal("approval-not-consumed"));
        }
        let auth = proof.authorization();
        let proposal = self.proposal(&auth.proposal)?;
        if proposal.status != ProposalStatus::Consumed
            || pending.operation != Some(proposal.operation)
            || pending.phase == Phase::Fact
            || pending.authority.sequence != self.current_version()?.sequence
            || pending.authority.previous_hash != self.state.hash
        {
            return Err(refusal("append-authorization"));
        }
        let (stored_proof,epoch,sequence,previous):(Vec<u8>,i64,i64,Option<String>) = self.transaction.query_row(
            "SELECT proof,epoch,sequence,previous_hash FROM authority_consumptions WHERE approval=?1 AND appended=0",[approval.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(sql)?;
        if stored_proof != proof_bytes(&proof)?
            || epoch != sql_number(auth.epoch)?
            || sequence != sql_number(pending.authority.sequence)?
            || previous
                != pending
                    .authority
                    .previous_hash
                    .map(|value| value.to_string())
        {
            return Err(refusal("consumption-context"));
        }
        let body = gate_payload(&pending.body);
        let status = match (auth.op, pending.kind, pending.phase) {
            (OwnerOperation::Apply, Kind::GateConsume, Phase::Settle) => {
                bind_gate_body(body, &proposal, approval, "consumed")?;
                ProposalStatus::Consumed
            }
            (OwnerOperation::Retire, Kind::GateRetire, Phase::Terminal) => {
                bind_gate_body(body, &proposal, approval, "retired")?;
                ProposalStatus::Retired
            }
            (OwnerOperation::Release, Kind::FloorAdvance, Phase::Terminal) => {
                self.check_floor_append(&proof, body)?;
                ProposalStatus::Applied
            }
            (OwnerOperation::Permission, Kind::AumlokBind, Phase::Terminal) => {
                let canonical = body.canonical_bytes();
                let approved = approved_payload(&proposal.new_bytes)?;
                if approved != canonical {
                    return Err(refusal("approved-body-mismatch"));
                }
                ProposalStatus::Applied
            }
            (OwnerOperation::Permission, Kind::GateApply, Phase::Terminal) => {
                self.validate_standing_grant(&proof, &pending, &proposal)?;
                ProposalStatus::Applied
            }
            _ => return Err(refusal("unsupported-authority-operation")),
        };
        if epoch_change {
            let transition = super::epochs::verify_epoch_transition(
                body,
                pending.authority,
                self.state.epoch,
                &self.transaction,
            )?;
            if !transition.old.members.contains(proof.public_key()) {
                return Err(refusal("membership-owner"));
            }
            let mut statement = self
                .transaction
                .prepare("SELECT credential,body FROM authority_bindings")
                .map_err(sql)?;
            let mut cursor = statement.query([]).map_err(sql)?;
            let mut retained = Vec::new();
            while let Some(row) = cursor.next().map_err(sql)? {
                let mut binding = storage::decode_binding(&row.get::<_, Vec<u8>>(1).map_err(sql)?)?;
                if binding.epoch == self.state.epoch
                    && transition.new.members.contains(&binding.public_key)
                {
                    binding.epoch = transition.new.epoch;
                    retained.push((
                        row.get::<_, String>(0).map_err(sql)?,
                        storage::encode_binding(&binding)?,
                    ));
                }
            }
            drop(cursor);
            drop(statement);
            if retained.is_empty() {
                return Err(refusal("membership-binding-missing"));
            }
            for (credential, body) in retained {
                self.transaction
                    .execute(
                        "UPDATE authority_bindings SET body=?2 WHERE credential=?1",
                        params![credential, body],
                    )
                    .map_err(sql)?;
            }
            if auth.op != OwnerOperation::Permission
                || pending.kind != Kind::AumlokBind
                || pending.authority.epoch
                    != self
                        .state
                        .epoch
                        .checked_add(1)
                        .ok_or(refusal("epoch-overflow"))?
            {
                return Err(refusal("epoch-context"));
            }
            self.state.epoch = pending.authority.epoch;
        } else if pending.authority.epoch != self.state.epoch {
            return Err(refusal("epoch-context"));
        }
        let record = self.write_record(pending)?;
        if self
            .transaction
            .execute(
                "UPDATE authority_consumptions SET appended=1 WHERE approval=?1 AND appended=0",
                [approval.to_string()],
            )
            .map_err(sql)?
            != 1
        {
            return Err(refusal("approval-already-appended"));
        }
        self.set_status(auth.proposal, status)?;
        self.consumptions.remove(&approval.to_string());
        if auth.op == OwnerOperation::Permission && record.kind == Kind::GateApply {
            self.store_standing_grant(&proposal, approval, &record)?;
        }
        if record.kind == Kind::FloorAdvance {
            self.check_floor_record(&record)?;
            self.floor_obligation = None;
        }
        Ok(record)
    }
}

fn bind_gate_body(
    body: &Value,
    proposal: &storage::ProposalState,
    approval: Digest32,
    state: &str,
) -> Result<()> {
    if field(body, "proposal") != Some(proposal.proposal.to_string().as_str())
        || field(body, "target") != Some(proposal.target.as_str())
        || field(body, "operation") != Some(proposal.operation_digest.to_string().as_str())
        || field(body, "new_sha256")
            != Some(Digest32::sha256(&proposal.new_bytes).to_string().as_str())
        || field(body, "consumed_approval") != Some(approval.to_string().as_str())
        || field(body, "state") != Some(state)
    {
        return Err(refusal("record-approval-mismatch"));
    }
    Ok(())
}

fn immune_exact(value: &Value, names: &[&str]) -> Result<()> {
    match value.view() {
        json::ValueView::Object(fields)
            if fields.len() == names.len()
                && names.iter().all(|name| value.get(name).is_some()) =>
        {
            Ok(())
        }
        _ => Err(refusal("immune-retirement-format")),
    }
}

fn immune_text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name).ok_or(refusal("immune-retirement-format"))
}

fn immune_retirement_payload(payload: &Value) -> Result<&Value> {
    immune_exact(
        payload,
        &[
            "schema",
            "proposal",
            "target",
            "operation",
            "new_sha256",
            "consumed_approval",
            "state",
            "retirement",
        ],
    )?;
    if immune_text(payload, "schema")? != "aukora-immune-antibody-retirement-record-v1"
        || immune_text(payload, "target")? != "immune.antibodies"
        || immune_text(payload, "state")? != "retired"
    {
        return Err(refusal("immune-retirement-format"));
    }
    let retirement = payload
        .get("retirement")
        .ok_or(refusal("immune-retirement-format"))?;
    immune_exact(
        retirement,
        &[
            "schema",
            "registry_sha256",
            "name",
            "area",
            "source",
            "disposition",
        ],
    )?;
    if immune_text(retirement, "schema")? != "aukora-immune-antibody-retirement-v1"
        || ["name", "area", "source", "disposition"]
            .iter()
            .any(|name| {
                immune_text(retirement, name).map_or(true, |text| {
                    text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control)
                })
            })
    {
        return Err(refusal("immune-retirement-format"));
    }
    Digest32::from_hex(immune_text(retirement, "registry_sha256")?)?;
    Ok(retirement)
}

fn immune_standard_bytes(value: &Value, name: &str) -> Result<Vec<u8>> {
    let encoded = immune_text(value, name)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| refusal("immune-proof-format"))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(refusal("immune-proof-format"));
    }
    Ok(bytes)
}

pub(super) fn verify_immune_retirement(
    connection: &rusqlite::Connection,
    record: &AuthorityRecord,
    keys: &[PublicKey],
) -> Result<()> {
    use canon::authority::{BaseDigest, OwnerAssertion};
    if record.kind != Kind::GateRetire
        || record.phase != Phase::Terminal
        || record.actor != "immune"
    {
        return Err(refusal("immune-history-context"));
    }
    let payload = gate_payload(&record.body);
    let retirement = immune_retirement_payload(payload)?;
    let approval = Digest32::from_hex(immune_text(payload, "consumed_approval")?)?;
    let proposal_id = ProposalId::from_hex(immune_text(payload, "proposal")?)?;
    let (proof_bytes, credential, counter, epoch, sequence, previous, operation, proposal, action, appended):
        (Vec<u8>, String, u32, i64, i64, Option<String>, String, String, String, i64) = connection.query_row(
        "SELECT proof,credential,counter,epoch,sequence,previous_hash,operation,proposal,action,appended FROM authority_consumptions WHERE approval=?1",
        [approval.to_string()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
    ).map_err(sql)?;
    let epoch = u64::try_from(epoch).map_err(|_| refusal("immune-history-context"))?;
    let sequence = u64::try_from(sequence).map_err(|_| refusal("immune-history-context"))?;
    if action != "retire"
        || appended != 1
        || proposal != proposal_id.to_string()
        || record.authority
            != (AuthorityVersion {
                epoch,
                sequence,
                previous_hash: previous.as_deref().map(Digest32::from_hex).transpose()?,
            })
        || record.operation != Some(OperationId::from_hex(&operation)?)
    {
        return Err(refusal("immune-history-context"));
    }
    let proof = json::parse_strict(&proof_bytes)?;
    immune_exact(
        &proof,
        &[
            "authorization",
            "credential",
            "authenticator_data",
            "client_data_json",
            "signed_bytes",
            "public_keys",
            "signatures",
        ],
    )?;
    let authorization_bytes = proof
        .get("authorization")
        .ok_or(refusal("immune-proof-format"))?
        .canonical_bytes();
    let authorization = storage::decode_authorization(&authorization_bytes)?;
    let (stored_body, stored_target, stored_operation, stored_status): (
        Vec<u8>,
        String,
        String,
        String,
    ) = connection
        .query_row(
            "SELECT body,target,operation,status FROM authority_proposals WHERE id=?1",
            [proposal_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(sql)?;
    let stored = storage::decode_proposal(&stored_body)?;
    if proof.canonical_bytes() != proof_bytes
        || immune_text(&proof, "credential")? != credential
        || Digest32::sha256(&authorization_bytes) != approval
        || authorization.proposal != proposal_id
        || authorization.epoch != epoch
        || authorization.op != OwnerOperation::Retire
        || authorization.target != "immune.antibodies"
        || authorization.cell.is_some()
        || authorization.expires_at <= record.at
        || stored.proposal != proposal_id
        || stored.target != stored_target
        || stored_target != authorization.target
        || stored.operation.to_string() != stored_operation
        || stored_operation != operation
        || stored_status != "retired"
        || stored.operation_digest != authorization.operation
        || stored.base_sha256 != authorization.base_sha256
        || stored.cell != authorization.cell
        || Digest32::sha256(&stored.new_bytes) != authorization.new_sha256
        || stored.new_bytes != retirement.canonical_bytes()
        || authorization.base_sha256
            != BaseDigest::Present(Digest32::from_hex(immune_text(
                retirement,
                "registry_sha256",
            )?)?)
    {
        return Err(refusal("immune-history-context"));
    }
    bind_gate_body(payload, &stored, approval, "retired")?;
    let (challenge_body, card, challenge, spent): (Vec<u8>,Vec<u8>,String,i64) = connection.query_row(
        "SELECT body,card,challenge,spent FROM authority_challenges WHERE proposal=?1 AND action='retire'",
        [proposal_id.to_string()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).map_err(sql)?;
    let decoded_card = storage::decode_card(&card)?;
    if challenge_body != authorization_bytes
        || challenge != authorization.challenge.to_string()
        || spent != 1
        || Digest32::sha256(&card) != authorization.display_sha256
        || decoded_card.risk != stored.risk
        || decoded_card.model_note != stored.model_note
    {
        return Err(refusal("immune-history-context"));
    }
    let credential_bytes = URL_SAFE_NO_PAD
        .decode(&credential)
        .map_err(|_| refusal("immune-proof-format"))?;
    if URL_SAFE_NO_PAD.encode(&credential_bytes) != credential {
        return Err(refusal("immune-proof-format"));
    }
    let credential_id = CredentialId::new(credential_bytes)?;
    let binding =
        super::epochs::immune_binding_before(connection, &credential_id, epoch, sequence, keys)?;
    let proof_keys = storage::decode_keys(
        &proof
            .get("public_keys")
            .ok_or(refusal("immune-proof-format"))?
            .canonical_bytes(),
    )?;
    let signatures = storage::decode_signatures(
        &proof
            .get("signatures")
            .ok_or(refusal("immune-proof-format"))?
            .canonical_bytes(),
    )?;
    if proof_keys != [binding.public_key.clone()] || signatures.components().len() != 1 {
        return Err(refusal("immune-proof-format"));
    }
    let signature = signatures.components()[0].clone();
    let authenticator_data = immune_standard_bytes(&proof, "authenticator_data")?;
    let client_data_json = immune_standard_bytes(&proof, "client_data_json")?;
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(Digest32::sha256(&client_data_json).as_bytes());
    if authenticator_data.len() != 37
        || authenticator_data[33..37] != counter.to_be_bytes()
        || signed != immune_standard_bytes(&proof, "signed_bytes")?
    {
        return Err(refusal("immune-proof-format"));
    }
    canon::authority::verify_retained_owner_assertion(
        binding,
        authorization,
        OwnerAssertion {
            v: 1,
            algorithm: signature.algorithm,
            credential_id,
            authenticator_data,
            client_data_json,
            signature,
        },
        crate::record::verify_signature,
    )
}

fn proof_bytes(proof: &VerifiedProof) -> Result<Vec<u8>> {
    let assertion = proof.assertion();
    let fields = vec![
        (
            "authorization",
            json::parse_strict(proof.authorization_bytes())?,
        ),
        (
            "credential",
            Value::text(URL_SAFE_NO_PAD.encode(proof.credential_id().as_bytes()))?,
        ),
        (
            "authenticator_data",
            Value::text(STANDARD.encode(&assertion.authenticator_data))?,
        ),
        (
            "client_data_json",
            Value::text(STANDARD.encode(&assertion.client_data_json))?,
        ),
        (
            "signed_bytes",
            Value::text(STANDARD.encode(proof.signed_bytes()))?,
        ),
        (
            "public_keys",
            json::parse_strict(&storage::encode_keys(std::slice::from_ref(
                proof.public_key(),
            ))?)?,
        ),
        (
            "signatures",
            json::parse_strict(&storage::encode_signatures(&Signatures::new(vec![
                assertion.signature.clone(),
            ])?)?)?,
        ),
    ];
    Ok(Value::object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())?.canonical_bytes())
}

pub(super) fn sql_number(value: u64) -> Result<i64> {
    if value > json::MAX_SAFE_INTEGER as u64 {
        return Err(refusal("integer-range"));
    }
    Ok(value as i64)
}

fn approved_payload(bytes: &[u8]) -> Result<&[u8]> {
    let Some(separator) = bytes.iter().position(|byte| *byte == 0) else {
        return Ok(bytes);
    };
    let domain = &bytes[..separator];
    let admitted = [
        crate::record::MEMBERSHIP_DOMAIN,
        "aukora:aumlok-key-binding:v1",
        "aukora:aumlok-person-nostr-binding:v1",
        "aukora:aumlok-delegation:v1",
        "aukora:aumlok-device-binding:v1",
        "aukora:aumlok-device-revocation:v1",
        "aukora:aumlok-device-approval:v1",
    ];
    if !admitted.iter().any(|tag| tag.as_bytes() == domain) {
        return Err(refusal("unsupported-approval-domain"));
    }
    Ok(&bytes[separator + 1..])
}

pub(super) fn verify_target_consumption(
    transaction: &LedgerTxn<'_>,
    stored: &storage::ProposalState,
    approval: Digest32,
) -> Result<AuthorityRecord> {
    use canon::authority::OwnerAssertion;
    let (proof_bytes, credential, counter, epoch, sequence, previous, operation, proposal, action, appended):
        (Vec<u8>, String, u32, i64, i64, Option<String>, String, String, String, i64) = transaction.transaction.query_row(
        "SELECT proof,credential,counter,epoch,sequence,previous_hash,operation,proposal,action,appended FROM authority_consumptions WHERE approval=?1",
        [approval.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)),
    ).map_err(sql)?;
    let epoch = u64::try_from(epoch).map_err(|_| refusal("target-consumption"))?;
    let sequence = u64::try_from(sequence).map_err(|_| refusal("target-consumption"))?;
    let consumed = transaction.record_at(AuthorityVersion {
        epoch, sequence, previous_hash: previous.as_deref().map(Digest32::from_hex).transpose()?,
    })?;
    if proposal != stored.proposal.to_string() || operation != stored.operation.to_string()
        || action != "apply" || appended != 1 || epoch != stored.authority.epoch
        || consumed.operation != Some(stored.operation) || consumed.kind != Kind::GateConsume
        || consumed.phase != Phase::Settle || consumed.actor != "owner" {
        return Err(refusal("target-consumption"));
    }
    bind_gate_body(gate_payload(&consumed.body), stored, approval, "consumed")?;
    let proof = json::parse_strict(&proof_bytes)?;
    immune_exact(&proof, &["authorization", "credential", "authenticator_data", "client_data_json",
        "signed_bytes", "public_keys", "signatures"])?;
    let authorization_bytes = proof.get("authorization").ok_or(refusal("target-proof"))?.canonical_bytes();
    let authorization = storage::decode_authorization(&authorization_bytes)?;
    if proof.canonical_bytes() != proof_bytes || field(&proof, "credential") != Some(credential.as_str())
        || Digest32::sha256(&authorization_bytes) != approval || authorization.proposal != stored.proposal
        || authorization.epoch != epoch || authorization.op != OwnerOperation::Apply
        || authorization.target != stored.target || authorization.base_sha256 != stored.base_sha256
        || authorization.new_sha256 != Digest32::sha256(&stored.new_bytes)
        || authorization.cell != stored.cell || authorization.operation != stored.operation_digest
        || authorization.expires_at <= consumed.at {
        return Err(refusal("target-proof"));
    }
    let (challenge_body, card, challenge, spent): (Vec<u8>, Vec<u8>, String, i64) = transaction.transaction.query_row(
        "SELECT body,card,challenge,spent FROM authority_challenges WHERE proposal=?1 AND action='apply'",
        [stored.proposal.to_string()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).map_err(sql)?;
    let decoded_card = storage::decode_card(&card)?;
    if challenge_body != authorization_bytes || challenge != authorization.challenge.to_string()
        || spent != 1 || Digest32::sha256(&card) != authorization.display_sha256
        || decoded_card.risk != stored.risk || decoded_card.model_note != stored.model_note {
        return Err(refusal("target-proof"));
    }
    let credential_bytes = URL_SAFE_NO_PAD.decode(&credential).map_err(|_| refusal("target-proof"))?;
    if URL_SAFE_NO_PAD.encode(&credential_bytes) != credential { return Err(refusal("target-proof")); }
    let credential_id = CredentialId::new(credential_bytes)?;
    let binding = super::epochs::immune_binding_before(&transaction.transaction, &credential_id,
        epoch, sequence, &transaction.state.keys)?;
    let proof_keys = storage::decode_keys(&proof.get("public_keys").ok_or(refusal("target-proof"))?.canonical_bytes())?;
    let signatures = storage::decode_signatures(&proof.get("signatures").ok_or(refusal("target-proof"))?.canonical_bytes())?;
    if proof_keys != [binding.public_key.clone()] || signatures.components().len() != 1 {
        return Err(refusal("target-proof"));
    }
    let signature = signatures.components()[0].clone();
    let authenticator_data = immune_standard_bytes(&proof, "authenticator_data")?;
    let client_data_json = immune_standard_bytes(&proof, "client_data_json")?;
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(Digest32::sha256(&client_data_json).as_bytes());
    if authenticator_data.len() != 37 || authenticator_data[33..37] != counter.to_be_bytes()
        || signed != immune_standard_bytes(&proof, "signed_bytes")? {
        return Err(refusal("target-proof"));
    }
    canon::authority::verify_retained_owner_assertion(binding, authorization, OwnerAssertion {
        v: 1, algorithm: signature.algorithm, credential_id, authenticator_data, client_data_json, signature,
    }, crate::record::verify_signature)?;
    Ok(consumed)
}
