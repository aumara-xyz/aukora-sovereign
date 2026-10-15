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

impl AuthorityTxn for LedgerTxn<'_> {
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
        _permission_id: &ProposalId,
        _permission_digest: Digest32,
        _proposal: &ProposalId,
        _action: OwnerOperation,
    ) -> Result<StandingUseContext> {
        Err(refusal("standing-permission-unavailable"))
    }
    fn append_standing(
        &mut self,
        _usage: VerifiedStandingUse,
        _record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.mutate(|_| Err(refusal("standing-permission-unavailable")))
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
                    let state = match field(body,"state") { Some("incomplete")=>ProposalStatus::Incomplete,Some("failed")=>ProposalStatus::Failed,Some("conflict")=>ProposalStatus::Conflict,_=>return Err(refusal("recovery-state")) };
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
