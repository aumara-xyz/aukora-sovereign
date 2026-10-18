// SPDX-License-Identifier: AGPL-3.0-or-later
//! Messaging projections authenticate Aura's retained gate proof under its writer lock.
use super::HostLedger;
use canon::{
    alg::{AlgorithmId, PublicKey as SigningKey, Signature},
    authority::{
        AuthorityAppendContext, AuthorityRecord, AuthorityTxn, FactRecord, Kind, LifecycleRecord,
        ObservationContext, OwnerAuthorization, OwnerBinding, OwnerOperation,
        PendingAuthorityRecord, Phase, StandingUseContext, VerifiedProof, VerifiedStandingUse,
    },
    digest::Digest32,
    ids::{CredentialId, ProposalId},
    json::{SafeInteger, Value, ValueView},
    Result,
};
use messaging::{
    ApprovedContact, ContactChange, Disclosure, MessagingTxn, OwnerAction, PairingEvidence,
};
use std::collections::BTreeMap;
use supervisor::ingress::PrincipalScope;

#[cfg(test)]
mod tests;

pub struct NetworkTxn<'a, 'db> {
    inner: &'a mut aura::LedgerTxn<'db>,
    scope: PrincipalScope,
    owner_session: bool,
    contacts: BTreeMap<String, Value>,
    messages: BTreeMap<String, Value>,
    pending_messages: BTreeMap<String, Value>,
}

impl HostLedger {
    pub fn messaging<T>(
        &self,
        scope: PrincipalScope,
        owner_session: bool,
        operation: impl FnOnce(&mut NetworkTxn<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        self.transition(|txn| {
            let mut network = NetworkTxn::new(txn, scope, owner_session)?;
            let result = operation(&mut network)?;
            // Messaging's observation methods may already have durably committed.
            // A plain read has no changes; dropping its transaction rolls it back.
            Ok(result)
        })
    }
}

impl<'a, 'db> NetworkTxn<'a, 'db> {
    fn new(
        inner: &'a mut aura::LedgerTxn<'db>,
        scope: PrincipalScope,
        owner_session: bool,
    ) -> Result<Self> {
        HostLedger::require_scope(inner, scope)?;
        let end = inner.current_version()?.sequence;
        let mut result = Self {
            inner,
            scope,
            owner_session,
            contacts: BTreeMap::new(),
            messages: BTreeMap::new(),
            pending_messages: BTreeMap::new(),
        };
        for sequence in 1..end {
            let row = result
                .inner
                .floor_record_at_sequence(sequence)?
                .ok_or(refuse("history-gap"))?;
            if row.authority.epoch != scope.epoch {
                continue;
            }
            let body = aura::record::AuthorityBodyV1::parse(&row.body)?.payload;
            if row.kind == Kind::GateApply
                && row.phase == Phase::Terminal
                && string(&body, "target").ok() == Some(messaging::CONTACT_TARGET)
                && string(&body, "state").ok() == Some("applied")
            {
                result.project_contact(&row, &body)?;
            } else if row.kind == Kind::BootFacts
                && row.phase == Phase::Fact
                && row.operation.is_none()
                && row.actor == "messaging"
                && string(&body, "schema").ok() == Some("aukora:messaging-event:v1")
            {
                let id = string(&body, "id")?;
                Digest32::from_hex(id)?;
                if result
                    .messages
                    .insert(id.into(), observation(&row, body.clone())?)
                    .is_some()
                {
                    return Err(refuse("message-observation-duplicate"));
                }
            }
        }
        Ok(result)
    }

    fn project_contact(&mut self, row: &AuthorityRecord, body: &Value) -> Result<()> {
        let proposal = ProposalId::from_hex(string(body, "proposal")?)?;
        let receipt = Digest32::from_hex(string(body, "consumed_approval")?)?;
        let stored = self.inner.proposal(&proposal)?;
        let consumed = self.inner.check_target_consumption(proposal, receipt)?;
        if stored.status != aura::storage::ProposalStatus::Applied
            || stored.target != messaging::CONTACT_TARGET
            || row.operation != Some(stored.operation)
            || row.authority.epoch != stored.authority.epoch
            || row.authority.sequence <= consumed.authority.sequence
            || string(body, "new_sha256")? != Digest32::sha256(&stored.new_bytes).to_string()
        {
            return Err(refuse("contact-projection-invalid"));
        }
        match OwnerAction::decode(&stored.new_bytes)? {
            OwnerAction::Contact(ContactChange::Add(draft)) => {
                let key = hex::encode(draft.key.as_bytes());
                let state = Value::object(vec![
                    ("schema".into(), text("aukora:messaging-contact-state:v1")?),
                    ("action".into(), text(hex::encode(stored.new_bytes))?),
                    ("epoch".into(), number(row.authority.epoch)?),
                    ("sequence".into(), number(row.authority.sequence)?),
                    (
                        "previous_hash".into(),
                        row.authority
                            .previous_hash
                            .map(|hash| text(hash.to_string()))
                            .transpose()?
                            .unwrap_or_else(Value::null),
                    ),
                    ("proposal".into(), text(proposal.to_string())?),
                    ("receipt".into(), text(receipt.to_string())?),
                    (
                        "record".into(),
                        Value::object(vec![
                            ("terminal".into(), row.body.clone()),
                            ("terminal_hash".into(), text(row.hash.to_string())?),
                            ("consumed".into(), consumed.body),
                            ("consumed_hash".into(), text(consumed.hash.to_string())?),
                        ])?,
                    ),
                ])?;
                messaging::contact_from_state(&state, draft.key)?;
                self.contacts.insert(key, state);
            }
            OwnerAction::Contact(ContactChange::Remove { key }) => {
                self.contacts.remove(&hex::encode(key.as_bytes()));
            }
            OwnerAction::Send(_) => return Err(refuse("contact-projection-invalid")),
        }
        Ok(())
    }

    pub fn contact_keys(&self) -> Result<Vec<nostr::PublicKey>> {
        self.contacts
            .keys()
            .map(|key| nostr::PublicKey::from_hex(key))
            .collect()
    }
}

impl AuthorityTxn for NetworkTxn<'_, '_> {
    fn transaction_id(&self) -> Digest32 {
        self.inner.transaction_id()
    }
    fn owner_binding(&mut self, credential: &CredentialId) -> Result<OwnerBinding> {
        self.inner.owner_binding(credential)
    }
    fn rebuild_authorization(
        &mut self,
        proposal: &ProposalId,
        action: OwnerOperation,
    ) -> Result<OwnerAuthorization> {
        self.inner.rebuild_authorization(proposal, action)
    }
    fn check_authorization_live(&mut self, authorization: &OwnerAuthorization) -> Result<()> {
        self.inner.check_authorization_live(authorization)
    }
    fn verify_signature(
        &mut self,
        key: &SigningKey,
        bytes: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        self.inner.verify_signature(key, bytes, signature)
    }
    fn persist_counter(&mut self, proof: &VerifiedProof) -> Result<()> {
        self.inner.persist_counter(proof)
    }
    fn consume(&mut self, proof: &VerifiedProof) -> Result<()> {
        self.inner.consume(proof)
    }
    fn append(
        &mut self,
        proof: VerifiedProof,
        record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.inner.append(proof, record)
    }
    fn check_standing_use(
        &mut self,
        permission: &ProposalId,
        digest: Digest32,
        proposal: &ProposalId,
        action: OwnerOperation,
    ) -> Result<StandingUseContext> {
        self.inner
            .check_standing_use(permission, digest, proposal, action)
    }
    fn append_standing(
        &mut self,
        usage: VerifiedStandingUse,
        record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.inner.append_standing(usage, record)
    }
    fn append_lifecycle(&mut self, record: LifecycleRecord) -> Result<AuthorityRecord> {
        self.inner.append_lifecycle(record)
    }
    fn observation_context(&mut self) -> Result<ObservationContext> {
        self.inner.observation_context()
    }
    fn authority_append_context(
        &mut self,
        proof: &VerifiedProof,
    ) -> Result<AuthorityAppendContext> {
        self.inner.authority_append_context(proof)
    }
    fn authority_state(&mut self, namespace: &str, key: &str) -> Result<Option<Value>> {
        self.committed_authority_state(namespace, key)
    }
    fn committed_authority_state(&mut self, namespace: &str, key: &str) -> Result<Option<Value>> {
        match namespace {
            "messaging.contact" => {
                nostr::PublicKey::from_hex(key)?;
                Ok(self.contacts.get(key).cloned())
            }
            _ => self.inner.committed_authority_state(namespace, key),
        }
    }
    fn committed_observation_state(&mut self, namespace: &str, key: &str) -> Result<Option<Value>> {
        if namespace == "messaging.message" {
            Digest32::from_hex(key)?;
            Ok(self.messages.get(key).cloned())
        } else {
            self.inner.committed_observation_state(namespace, key)
        }
    }
    fn append_fact(&mut self, fact: FactRecord) -> Result<AuthorityRecord> {
        let message = fact.actor == "messaging"
            && string(&fact.body, "schema").ok() == Some("aukora:messaging-event:v1");
        let row = self.inner.append_fact(fact)?;
        if message {
            let body = aura::record::AuthorityBodyV1::parse(&row.body)?.payload;
            let id = string(&body, "id")?;
            if self.messages.contains_key(id)
                || self
                    .pending_messages
                    .insert(id.into(), observation(&row, body.clone())?)
                    .is_some()
            {
                return Err(refuse("message-observation-duplicate"));
            }
        }
        Ok(row)
    }
    fn commit_observations(&mut self) -> Result<()> {
        self.inner.commit_observations()?;
        self.messages.append(&mut self.pending_messages);
        Ok(())
    }
}

impl MessagingTxn for NetworkTxn<'_, '_> {
    fn load_contact(&mut self, key: nostr::PublicKey) -> Result<Option<ApprovedContact>> {
        self.contacts
            .get(&hex::encode(key.as_bytes()))
            .map(|state| messaging::contact_from_state(state, key))
            .transpose()
    }
    fn proposed_action(&mut self, proposal: ProposalId) -> Result<OwnerAction> {
        let stored = self.inner.proposal(&proposal)?;
        if stored.authority.epoch != self.scope.epoch || stored.target != messaging::CONTACT_TARGET
        {
            return Err(refuse("owner-contact-proposal-required"));
        }
        OwnerAction::decode(&stored.new_bytes)
    }
    fn stage_owner_action(
        &mut self,
        proof: &VerifiedProof,
        action: &OwnerAction,
    ) -> Result<PendingAuthorityRecord> {
        let authorization = proof.authorization();
        if proof.transaction_id() != self.transaction_id()
            || authorization.epoch != self.scope.epoch
            || self.proposed_action(authorization.proposal)? != *action
            || authorization.new_sha256 != Digest32::sha256(&action.canonical_bytes()?)
            || authorization.display_sha256 != Digest32::sha256(&action.card()?.canonical_bytes()?)
        {
            return Err(refuse("approval-mismatch"));
        }
        let context = self.inner.authority_append_context(proof)?;
        let stored = self.inner.proposal(&authorization.proposal)?;
        Ok(PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: Kind::GateApply,
            phase: Phase::Terminal,
            actor: "owner".into(),
            operation: Some(stored.operation),
            body: Value::object(vec![
                ("proposal".into(), text(authorization.proposal.to_string())?),
                ("target".into(), text(messaging::CONTACT_TARGET)?),
                (
                    "operation".into(),
                    text(stored.operation_digest.to_string())?,
                ),
                (
                    "new_sha256".into(),
                    text(authorization.new_sha256.to_string())?,
                ),
                (
                    "consumed_approval".into(),
                    text(Digest32::sha256(proof.authorization_bytes()).to_string())?,
                ),
                ("state".into(), text("applied")?),
            ])?,
        })
    }
    fn check_disclosures(&mut self, _: nostr::PublicKey, items: &[Disclosure]) -> Result<()> {
        if items.is_empty() {
            Ok(())
        } else {
            Err(refuse("disclosures-unavailable"))
        }
    }
    fn check_pairing(&mut self, _: &PairingEvidence) -> Result<()> {
        Err(refuse("pairing-unavailable"))
    }
}

impl messaging::OwnerSessionTxn for NetworkTxn<'_, '_> {
    fn check_owner_session(&mut self) -> Result<()> {
        if !self.owner_session {
            return Err(refuse("owner-shell-session-required"));
        }
        HostLedger::require_scope(self.inner, self.scope)
    }
}

fn observation(row: &AuthorityRecord, body: Value) -> Result<Value> {
    Value::object(vec![
        ("body".into(), body),
        ("sequence".into(), number(row.authority.sequence)?),
    ])
}
fn number(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(
        i64::try_from(value).map_err(|_| refuse("number-invalid"))?,
    )?))
}
fn text(value: impl Into<String>) -> Result<Value> {
    Value::text(value.into())
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refuse("record-invalid")),
    }
}
fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "messaging",
        reason,
    }
}
