// SPDX-License-Identifier: AGPL-3.0-or-later
//! Messaging projections authenticate independent reads, then recheck the live writer.
use super::HostLedger;
use canon::{
    alg::{AlgorithmId, PublicKey as SigningKey, Signature},
    authority::{
        AuthorityAppendContext, AuthorityRecord, AuthorityTxn, AuthorityVersion, FactKind, FactRecord,
        Kind,
        LifecycleRecord, ObservationContext, OwnerAuthorization, OwnerBinding, OwnerOperation,
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
mod owner_contact_tests;
#[cfg(test)]
pub(crate) mod tests;

pub struct NetworkTxn<'a, 'db> {
    inner: &'a mut aura::LedgerTxn<'db>,
    scope: PrincipalScope,
    owner_session: bool,
    contacts: BTreeMap<String, Value>,
    messages: BTreeMap<String, Value>,
    pending_messages: BTreeMap<String, Value>,
    observations: aura::ledger::ObservationProjection,
    pending_refusals: Vec<AuthorityRecord>,
}

impl HostLedger {
    /// Polling only needs an authenticated read; scope is checked again against
    /// the detached projection before each effect is admitted by the writer.
    pub fn messaging_binding(&self) -> Result<supervisor::ingress::BindingState> {
        aura::Ledger::read_snapshot(&self.path, self.services(), |snapshot| {
            let version = snapshot.current_version()?;
            Ok(if version.epoch == 0 {
                supervisor::ingress::BindingState::Unbound
            } else {
                supervisor::ingress::BindingState::Bound(PrincipalScope {
                    subject: snapshot.owner_subject()?, epoch: version.epoch,
                })
            })
        })
    }

    pub fn messaging<T>(
        &self,
        scope: PrincipalScope,
        owner_session: bool,
        operation: impl FnOnce(&mut NetworkTxn<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        // Full verification and projection use a separate SQLite read snapshot.
        // A concurrent approval can advance the head; retry before invoking the
        // operation, so stale contacts and epochs never authorize an effect.
        let mut operation = Some(operation);
        for _ in 0..3 {
            let generation = self.with_read_ledger(|ledger| ledger.read_generation())?;
            let (projection, verified) =
                aura::Ledger::read_snapshot(&self.path, self.services(), |snapshot| {
                    Ok((NetworkProjection::read(snapshot, scope)?, snapshot.verified()))
                })?;
            if let Some(result) = self.transition_verified(generation, verified, |txn| {
                let mut network = projection.enter(txn, scope, owner_session)?;
                operation.take().expect("operation runs once")(&mut network)
            })? {
                return Ok(result);
            }
        }
        // Under sustained writes, serialize one verified projection instead of
        // refusing an owner call indefinitely. BEGIN IMMEDIATE holds both the
        // process writer and SQLite writer while the snapshot is copied.
        self.transition(|txn| {
            let projection =
                aura::Ledger::read_snapshot(&self.path, self.services(), |snapshot| {
                    NetworkProjection::read(snapshot, scope)
                })?;
            let mut network = projection.enter(txn, scope, owner_session)?;
            operation.take().expect("operation runs once")(&mut network)
        })
    }
}

struct NetworkProjection {
    version: AuthorityVersion,
    contacts: BTreeMap<String, Value>,
    messages: BTreeMap<String, Value>,
    observations: aura::ledger::ObservationProjection,
}
impl NetworkProjection {
    fn enter<'a, 'db>(
        self,
        txn: &'a mut aura::LedgerTxn<'db>,
        scope: PrincipalScope,
        owner_session: bool,
    ) -> Result<NetworkTxn<'a, 'db>> {
        if txn.current_version()? != self.version {
            return Err(refuse("snapshot-head"));
        }
        Ok(NetworkTxn {
            inner: txn,
            scope,
            owner_session,
            contacts: self.contacts,
            messages: self.messages,
            pending_messages: BTreeMap::new(),
            observations: self.observations,
            pending_refusals: Vec::new(),
        })
    }

    fn read(snapshot: &aura::ledger::ReadSnapshot<'_>, scope: PrincipalScope) -> Result<Self> {
        let version = snapshot.current_version()?;
        if version.epoch != scope.epoch || snapshot.owner_subject()? != scope.subject {
            return Err(canon::codes::AUMLOK_BINDING_REQUIRED);
        }
        let mut result = Self {
            version,
            contacts: BTreeMap::new(),
            messages: BTreeMap::new(),
            observations: snapshot.observations()?,
        };
        for sequence in 1..version.sequence {
            let row = snapshot
                .record_at_sequence(sequence)?
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
                result.project_contact(snapshot, &row, &body)?;
            } else if row.kind == Kind::BootFacts
                && row.phase == Phase::Fact
                && row.operation.is_none()
                && row.actor == "owner"
                && string(&body, "schema").ok() == Some(messaging::OWNER_CONTACT_SCHEMA)
            {
                project_owner_contact(&mut result.contacts, scope, &row, &body)?;
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

    fn project_contact(
        &mut self,
        snapshot: &aura::ledger::ReadSnapshot<'_>,
        row: &AuthorityRecord,
        body: &Value,
    ) -> Result<()> {
        let proposal = ProposalId::from_hex(string(body, "proposal")?)?;
        let receipt = Digest32::from_hex(string(body, "consumed_approval")?)?;
        let stored = snapshot.proposal(&proposal)?;
        let consumed = snapshot.check_target_consumption(proposal, receipt)?;
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
}

impl NetworkTxn<'_, '_> {
    /// Returns false only when the current slider requires the existing owner card.
    /// Scope, selected setting and append share the host's Aura writer lock.
    pub fn apply_owner_contact(&mut self, action: &OwnerAction) -> Result<bool> {
        use messaging::OwnerSessionTxn;
        self.check_owner_session()?;
        let OwnerAction::Contact(change) = action else {
            return Err(refuse("owner-contact-action-required"));
        };
        let bytes = action.canonical_bytes()?;
        match change {
            ContactChange::Add(draft) if draft.pairing.is_some() => {
                return Err(refuse("pairing-unavailable"))
            }
            ContactChange::Remove { key } if self.load_contact(*key)?.is_none() => {
                return Err(refuse("contact-missing"))
            }
            _ => {}
        }
        let setting = super::slider::current_policy(self.inner)?.setting;
        if setting == laya::SliderSetting::AskEverything {
            return Ok(false);
        }
        let context = self.inner.observation_context()?;
        let body = Value::object(vec![
            ("schema".into(), text(messaging::OWNER_CONTACT_SCHEMA)?),
            ("subject".into(), text(self.scope.subject.to_string())?),
            ("setting".into(), text(setting.wire_name())?),
            ("action".into(), text(hex::encode(bytes))?),
        ])?;
        let row = self.inner.append_fact(FactRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: FactKind::BootFacts,
            actor: "owner".into(),
            body: body.clone(),
        })?;
        self.inner.commit_observations()?;
        project_owner_contact(&mut self.contacts, self.scope, &row, &body)?;
        Ok(true)
    }

    pub fn contact_keys(&self) -> Result<Vec<nostr::PublicKey>> {
        self.contacts
            .keys()
            .map(|key| nostr::PublicKey::from_hex(key))
            .collect()
    }
}

/// An owner-session contact change recorded in Aura while the slider allowed it (no card); shared by the detached
/// projection and the live writer so both derive the same contact state.
fn project_owner_contact(
    contacts: &mut BTreeMap<String, Value>,
    scope: PrincipalScope,
    row: &AuthorityRecord,
    body: &Value,
) -> Result<()> {
    let ValueView::Object(fields) = body.view() else {
        return Err(refuse("owner-contact-record"));
    };
    if fields.len() != 4
        || row.kind != Kind::BootFacts
        || row.phase != Phase::Fact
        || row.operation.is_some()
        || row.actor != "owner"
        || string(body, "schema")? != messaging::OWNER_CONTACT_SCHEMA
        || string(body, "subject")? != scope.subject.to_string()
        || !matches!(string(body, "setting")?, "risky" | "limits" | "trusted")
        || row.authority.epoch != scope.epoch
    {
        return Err(refuse("owner-contact-record"));
    }
    let encoded = string(body, "action")?;
    if encoded.len() > 16_384 {
        return Err(refuse("owner-contact-record"));
    }
    let bytes = hex::decode(encoded).map_err(|_| refuse("owner-contact-record"))?;
    if hex::encode(&bytes) != encoded {
        return Err(refuse("owner-contact-record"));
    }
    match OwnerAction::decode(&bytes)? {
        OwnerAction::Contact(ContactChange::Add(draft)) => {
            let state = Value::object(vec![
                (
                    "schema".into(),
                    text("aukora:messaging-owner-contact-state:v1")?,
                ),
                ("action".into(), text(encoded)?),
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
                ("receipt".into(), text(row.hash.to_string())?),
                ("record".into(), row.body.clone()),
            ])?;
            messaging::contact_from_state(&state, draft.key)?;
            contacts
                .insert(hex::encode(draft.key.as_bytes()), state);
        }
        OwnerAction::Contact(ContactChange::Remove { key }) => {
            contacts.remove(&hex::encode(key.as_bytes()));
        }
        OwnerAction::Send(_) => return Err(refuse("owner-contact-record")),
    }
    Ok(())
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
            self.observations.get(namespace, key)
        }
    }
    fn append_fact(&mut self, fact: FactRecord) -> Result<AuthorityRecord> {
        let message = fact.actor == "messaging"
            && string(&fact.body, "schema").ok() == Some("aukora:messaging-event:v1");
        let refusal = fact.actor == "messaging"
            && string(&fact.body, "schema").ok() == Some("aukora:messaging-refusal:v1");
        let row = self.inner.append_fact(fact)?;
        if refusal {
            self.pending_refusals.push(row.clone());
        }
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
        for row in self.pending_refusals.drain(..) {
            self.observations.append_committed(&row)?;
        }
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
        if self.inner.current_version()?.epoch != self.scope.epoch {
            return Err(canon::codes::AUMLOK_BINDING_REQUIRED);
        }
        Ok(())
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
