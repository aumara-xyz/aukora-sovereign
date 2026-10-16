// SPDX-License-Identifier: AGPL-3.0-or-later
//! Epoch-zero possession receipts and epoch-one binding share the Aura write lock.

use super::super::{io, refusal, sql, LedgerTxn};
use crate::{
    record::{AuthorityBodyV1, MembershipSet},
    storage,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use canon::{
    alg::{AlgorithmId, PublicKey, Signature},
    authority::{
        pending::{
            BindingFinish, BoundCeremonyFinish, BoundOwnerIdentity, PendingEnrolmentFinish,
            PendingOwnerCredential,
        },
        AuthorityRecord, AuthorityVersion, Kind, OwnerBinding, PendingAuthorityRecord, Phase,
    },
    digest::Digest32,
    ids::{CredentialId, OperationId, RequestId, SessionId, SubjectId},
    json::{self, Value, ValueView},
    Result,
};
use rusqlite::{params, Connection, OptionalExtension};

mod bound;
mod codec;
use codec::*;

const ENROL: &str = "aukora-aumlok-pending-enrolment-v2";
const PENDING_SIGNIN: &str = "aukora-aumlok-pending-signin-v2";
const BIND: &str = "aukora-aumlok-initial-binding-v2";
const SIGNIN: &str = "aukora-aumlok-bound-signin-v2";
const REFRESH: &str = "aukora-aumlok-envelope-refresh-v2";

struct Ceremony {
    id: RequestId,
    purpose: String,
    state: String,
    context: Value,
    nonce: [u8; 32],
    issued: u64,
    deadline: u64,
    candidate: Value,
    candidate_digest: Option<Digest32>,
    payload: Value,
}

impl Ceremony {
    fn load(
        connection: &Connection,
        id: RequestId,
        session: SessionId,
        now: i64,
        observed: i64,
        version: AuthorityVersion,
    ) -> Result<Self> {
        if now < 0 || observed < 0 || observed > now {
            return Err(refusal("identity-clock"));
        }
        let mut statement = connection.prepare(
            "SELECT purpose,state,context,nonce,issued,deadline,candidate,candidate_digest,payload FROM aumlok_ceremonies_v2 WHERE id=?1 AND issued<=?2 AND last_seen<=?2 AND last_seen>=issued AND deadline>?3 AND deadline-issued BETWEEN 1 AND 300000"
        ).map_err(sql)?;
        let row = statement
            .query_row(params![id.as_bytes().as_slice(), observed, now], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            })
            .optional()
            .map_err(sql)?
            .ok_or(refusal("identity-ceremony"))?;
        let ceremony = Self {
            id,
            purpose: row.0,
            state: row.1,
            context: canonical(&row.2, 8192)?,
            nonce: row.3.try_into().map_err(|_| refusal("identity-ceremony"))?,
            issued: u64::try_from(row.4).map_err(|_| refusal("identity-clock"))?,
            deadline: u64::try_from(row.5).map_err(|_| refusal("identity-clock"))?,
            candidate: row
                .6
                .as_deref()
                .map(|value| canonical(value, 16384))
                .transpose()?
                .unwrap_or_else(Value::null),
            candidate_digest: row
                .7
                .map(|bytes| {
                    bytes
                        .try_into()
                        .map(Digest32::from_bytes)
                        .map_err(|_| refusal("identity-candidate"))
                })
                .transpose()?,
            payload: row
                .8
                .as_deref()
                .map(|value| canonical(value, 16384))
                .transpose()?
                .unwrap_or_else(Value::null),
        };
        check_context(connection, &ceremony.context, version, session)?;
        Ok(ceremony)
    }
    fn transition(&self, connection: &Connection, old: &str, new: &str, now: i64) -> Result<()> {
        let changed = connection.execute(
            "UPDATE aumlok_ceremonies_v2 SET state=?1,last_seen=?2 WHERE id=?3 AND state=?4 AND nonce=?5 AND context=?6 AND issued<=?2 AND last_seen<=?2 AND deadline>?2",
            params![new, now, self.id.as_bytes().as_slice(), old, self.nonce.as_slice(), String::from_utf8(self.context.canonical_bytes()).map_err(|_| refusal("identity-encoding"))?],
        ).map_err(sql)?;
        if changed != 1 {
            return Err(refusal("identity-ceremony"));
        }
        Ok(())
    }
    fn receipt(
        &self,
        schema: &str,
        assertion: Value,
        binding: &OwnerBinding,
        enrolment: Option<&PendingOwnerCredential>,
    ) -> Result<Value> {
        object(vec![
            ("schema", string(schema)?),
            ("ceremony", string(self.id.to_string())?),
            (
                "subject",
                self.payload
                    .get("subject")
                    .or_else(|| self.context.get("subject"))
                    .ok_or(refusal("identity-subject"))?
                    .clone(),
            ),
            ("context", self.context.clone()),
            ("nonce", string(STANDARD.encode(self.nonce))?),
            ("issued", integer(self.issued)?),
            ("deadline", integer(self.deadline)?),
            ("candidate", self.candidate.clone()),
            (
                "candidate_digest",
                self.candidate_digest
                    .map(|digest| string(digest.to_string()))
                    .transpose()?
                    .unwrap_or_else(Value::null),
            ),
            ("payload", self.payload.clone()),
            ("assertion", assertion),
            ("binding", storage::owner_binding_value(binding)?),
            (
                "enrolment_sequence",
                enrolment
                    .map(|value| integer(value.enrolment.sequence))
                    .transpose()?
                    .unwrap_or_else(Value::null),
            ),
            (
                "enrolment_hash",
                enrolment
                    .map(|value| string(value.enrolment_hash.to_string()))
                    .transpose()?
                    .unwrap_or_else(Value::null),
            ),
        ])
    }
    fn retained(record: &AuthorityRecord, payload: &Value, purpose: &str) -> Result<Self> {
        exact(
            payload,
            &[
                "schema",
                "ceremony",
                "subject",
                "context",
                "nonce",
                "issued",
                "deadline",
                "candidate",
                "candidate_digest",
                "payload",
                "assertion",
                "binding",
                "enrolment_sequence",
                "enrolment_hash",
            ],
        )?;
        let id = RequestId::from_hex(text(payload, "ceremony")?)?;
        let issued = number(payload, "issued")?;
        let deadline = number(payload, "deadline")?;
        if record.phase != Phase::Terminal
            || record.operation != Some(OperationId::from_bytes(*id.as_bytes()))
            || record.at < 0
            || issued > record.at as u64
            || deadline <= record.at as u64
            || deadline
                .checked_sub(issued)
                .is_none_or(|duration| !(1..=300000).contains(&duration))
        {
            return Err(refusal("identity-anchor"));
        }
        let context = field(payload, "context")?.clone();
        if text(&context, "owner_id")? != record.actor {
            return Err(refusal("identity-anchor"));
        }
        Ok(Self {
            id,
            purpose: purpose.to_owned(),
            state: "finished".to_owned(),
            context,
            nonce: decode_standard(text(payload, "nonce")?, 32)?
                .try_into()
                .map_err(|_| refusal("identity-anchor"))?,
            issued,
            deadline,
            candidate: field(payload, "candidate")?.clone(),
            candidate_digest: match field(payload, "candidate_digest")?.view() {
                ValueView::Null => None,
                ValueView::Text(value) => Some(Digest32::from_hex(value)?),
                _ => return Err(refusal("identity-anchor")),
            },
            payload: field(payload, "payload")?.clone(),
        })
    }
}

fn payload(record: &AuthorityRecord) -> Result<Value> {
    let wrapper = AuthorityBodyV1::parse(&record.body)?;
    if wrapper.authority != record.authority || wrapper.algorithm != record.algorithm {
        return Err(refusal("identity-anchor"));
    }
    Ok(wrapper.payload)
}

fn enrolment_challenge(ceremony: &Ceremony) -> Result<[u8; 32]> {
    let digest = ceremony
        .candidate_digest
        .ok_or(refusal("enrolment-candidate"))?;
    if Digest32::sha256(&ceremony.candidate.canonical_bytes()) != digest {
        return Err(refusal("enrolment-candidate"));
    }
    let mut message = b"aukora:enrol-possession:v1\0".to_vec();
    message.extend_from_slice(ceremony.id.to_string().as_bytes());
    message.extend_from_slice(digest.as_bytes());
    Ok(*Digest32::sha256(&message).as_bytes())
}

fn verify_enrolment(
    connection: &Connection,
    record: &AuthorityRecord,
) -> Result<PendingOwnerCredential> {
    let body = payload(record)?;
    if text(&body, "schema")? != ENROL
        || record.kind != Kind::AumlokEnrol
        || record.authority.epoch != 0
    {
        return Err(refusal("enrolment-anchor"));
    }
    let row = Ceremony::retained(record, &body, "enrolment")?;
    let session = SessionId::from_hex(text(&row.context, "session")?)?;
    check_context(connection, &row.context, record.authority, session)?;
    if !matches!(field(&row.context, "subject")?.view(), ValueView::Null)
        || !matches!(field(&row.context, "credential")?.view(), ValueView::Null)
        || !matches!(field(&body, "subject")?.view(), ValueView::Null)
        || !matches!(field(&body, "enrolment_sequence")?.view(), ValueView::Null)
        || !matches!(field(&body, "enrolment_hash")?.view(), ValueView::Null)
        || !matches!(row.payload.view(), ValueView::Null)
    {
        return Err(refusal("enrolment-anchor"));
    }
    let (mut binding, backup_eligible) = candidate_binding(&row.context, &row.candidate)?;
    let user_handle = decode_url(text(&row.context, "user_handle")?, 64)?;
    let (_, counter) = assert_possession(
        &field(&body, "assertion")?.canonical_bytes(),
        &binding,
        &user_handle,
        backup_eligible,
        &enrolment_challenge(&row)?,
    )?;
    binding.sign_counter = counter;
    if storage::owner_binding_from_value(field(&body, "binding")?)? != binding {
        return Err(refusal("enrolment-anchor"));
    }
    Ok(PendingOwnerCredential {
        binding,
        owner_id: record.actor.clone(),
        user_handle,
        backup_eligible,
        enrolment: record.authority,
        enrolment_hash: record.hash,
        session,
    })
}

pub(in crate::ledger) fn read_pending(
    connection: &Connection,
    keys: &[PublicKey],
    before: u64,
) -> Result<Option<PendingOwnerCredential>> {
    let mut statement = connection.prepare("SELECT a.seq FROM aura a JOIN aura_record_wrappers w ON w.seq=a.seq WHERE a.seq<?1 AND w.epoch=0 AND a.kind IN ('aumlok.enrol','aumlok.signin') AND a.phase='terminal' ORDER BY a.seq").map_err(sql)?;
    let mut rows = statement
        .query([i64::try_from(before).map_err(|_| refusal("identity-range"))?])
        .map_err(sql)?;
    let mut pending = None;
    while let Some(row) = rows.next().map_err(sql)? {
        let sequence = u64::try_from(row.get::<_, i64>(0).map_err(sql)?)
            .map_err(|_| refusal("identity-range"))?;
        let record = io::record_at(connection, sequence)?;
        crate::record::verify_record(&record, keys)?;
        let body = payload(&record)?;
        match text(&body, "schema")? {
            ENROL if pending.is_none() => pending = Some(verify_enrolment(connection, &record)?),
            PENDING_SIGNIN => {
                let credential = pending.as_mut().ok_or(refusal("enrolment-anchor"))?;
                let ceremony = Ceremony::retained(&record, &body, "signin")?;
                verify_pending_signin(connection, &record, &body, &ceremony, credential)?;
            }
            _ => return Err(refusal("enrolment-anchor")),
        }
    }
    Ok(pending)
}

fn check_credential_context(context: &Value, credential: &PendingOwnerCredential) -> Result<()> {
    if decode_url(text(context, "credential")?, 1024)?
        != credential.binding.credential_id.as_bytes()
        || text(context, "rp")? != credential.binding.relying_party
        || text(context, "owner_origin")? != credential.binding.owner_origin
        || text(context, "top_origin")? != credential.binding.top_origin
        || text(context, "owner_id")? != credential.owner_id
        || decode_url(text(context, "user_handle")?, 64)? != credential.user_handle
    {
        return Err(refusal("identity-context"));
    }
    Ok(())
}
fn check_enrolment_reference(body: &Value, credential: &PendingOwnerCredential) -> Result<()> {
    if number(body, "enrolment_sequence")? != credential.enrolment.sequence
        || text(body, "enrolment_hash")? != credential.enrolment_hash.to_string()
    {
        return Err(refusal("enrolment-anchor"));
    }
    Ok(())
}
fn verify_pending_signin(
    connection: &Connection,
    record: &AuthorityRecord,
    body: &Value,
    ceremony: &Ceremony,
    credential: &mut PendingOwnerCredential,
) -> Result<()> {
    if record.kind != Kind::AumlokSignin || record.authority.epoch != 0 {
        return Err(refusal("identity-anchor"));
    }
    let session = SessionId::from_hex(text(&ceremony.context, "session")?)?;
    check_context(connection, &ceremony.context, record.authority, session)?;
    check_credential_context(&ceremony.context, credential)?;
    check_enrolment_reference(body, credential)?;
    if !matches!(field(&ceremony.context, "subject")?.view(), ValueView::Null)
        || !matches!(field(body, "subject")?.view(), ValueView::Null)
        || !matches!(ceremony.payload.view(), ValueView::Null)
    {
        return Err(refusal("identity-context"));
    }
    let (_, counter) = assert_possession(
        &field(body, "assertion")?.canonical_bytes(),
        &credential.binding,
        &credential.user_handle,
        credential.backup_eligible,
        &ceremony.nonce,
    )?;
    credential.binding.sign_counter = counter;
    if storage::owner_binding_from_value(field(body, "binding")?)? != credential.binding {
        return Err(refusal("identity-anchor"));
    }
    credential.session = session;
    Ok(())
}

impl LedgerTxn<'_> {
    fn identity_ready(&self, transaction: Digest32) -> Result<()> {
        self.active()?;
        if transaction != self.identity
            || !self.counters.is_empty()
            || !self.consumptions.is_empty()
            || self.floor_obligation.is_some()
            || self.target_observation.is_some()
        {
            return Err(refusal("identity-transaction"));
        }
        Ok(())
    }
    fn identity_record(
        &mut self,
        row: &Ceremony,
        kind: Kind,
        body: Value,
        now: i64,
    ) -> Result<AuthorityRecord> {
        self.write_record(PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: self.state.next()?,
            at: now,
            kind,
            actor: text(&row.context, "owner_id")?.to_owned(),
            operation: Some(OperationId::from_bytes(*row.id.as_bytes())),
            phase: Phase::Terminal,
            body,
        })
    }
    pub(in crate::ledger) fn pending_credential(&self) -> Result<Option<PendingOwnerCredential>> {
        self.active()?;
        if self.state.epoch != 0 {
            return Ok(None);
        }
        read_pending(
            &self.transaction,
            &self.state.keys,
            self.state.next()?.sequence,
        )
    }
    pub(in crate::ledger) fn enrol_pending(
        &mut self,
        request: PendingEnrolmentFinish<'_>,
    ) -> Result<PendingOwnerCredential> {
        self.identity_ready(request.transaction_id)?;
        let occupied: bool = self.transaction.query_row("SELECT EXISTS(SELECT 1 FROM authority_bindings) OR EXISTS(SELECT 1 FROM aura WHERE kind IN ('aumlok.enrol','aumlok.bind'))", [], |row| row.get(0)).map_err(sql)?;
        if self.state.epoch != 0 || occupied {
            return Err(refusal("enrolment-closed"));
        }
        let now = self.services.clock.now_ms()?;
        let row = Ceremony::load(
            &self.transaction,
            request.id,
            request.session,
            now,
            request.now_ms,
            self.state.next()?,
        )?;
        if row.purpose != "enrolment"
            || row.state != "registered"
            || !matches!(field(&row.context, "subject")?.view(), ValueView::Null)
            || !matches!(field(&row.context, "credential")?.view(), ValueView::Null)
        {
            return Err(refusal("enrolment-context"));
        }
        let (mut binding, backup) = candidate_binding(&row.context, &row.candidate)?;
        let user_handle = decode_url(text(&row.context, "user_handle")?, 64)?;
        let (assertion, counter) = assert_possession(
            request.assertion_json,
            &binding,
            &user_handle,
            backup,
            &enrolment_challenge(&row)?,
        )?;
        binding.sign_counter = counter;
        let receipt = row.receipt(ENROL, assertion, &binding, None)?;
        row.transition(&self.transaction, "registered", "spent", now)?;
        let record = self.identity_record(&row, Kind::AumlokEnrol, receipt, now)?;
        let credential = verify_enrolment(&self.transaction, &record)?;
        row.transition(&self.transaction, "spent", "finished", now)?;
        Ok(credential)
    }
    pub(in crate::ledger) fn signin_pending(
        &mut self,
        request: BoundCeremonyFinish<'_>,
    ) -> Result<PendingOwnerCredential> {
        self.identity_ready(request.transaction_id)?;
        let mut credential = self
            .pending_credential()?
            .ok_or(refusal("enrolment-required"))?;
        let now = self.services.clock.now_ms()?;
        let row = Ceremony::load(
            &self.transaction,
            request.id,
            request.session,
            now,
            request.now_ms,
            self.state.next()?,
        )?;
        if row.purpose != "signin"
            || row.state != "fresh"
            || !matches!(field(&row.context, "subject")?.view(), ValueView::Null)
        {
            return Err(refusal("identity-context"));
        }
        check_credential_context(&row.context, &credential)?;
        let (assertion, counter) = assert_possession(
            request.assertion_json,
            &credential.binding,
            &credential.user_handle,
            credential.backup_eligible,
            &row.nonce,
        )?;
        credential.binding.sign_counter = counter;
        let body = row.receipt(
            PENDING_SIGNIN,
            assertion,
            &credential.binding,
            Some(&credential),
        )?;
        row.transition(&self.transaction, "fresh", "spent", now)?;
        self.identity_record(&row, Kind::AumlokSignin, body, now)?;
        row.transition(&self.transaction, "spent", "finished", now)?;
        credential.session = request.session;
        Ok(credential)
    }
}

/// Verify the initial epoch-one membership without treating enrolment as a subject.
pub(super) fn initial_binding(
    connection: &Connection,
    record: &AuthorityRecord,
) -> Result<OwnerBinding> {
    let keys: Vec<u8> = connection
        .query_row(
            "SELECT public_keys FROM aura_record_wrappers WHERE seq=?1",
            [i64::try_from(record.authority.sequence).map_err(|_| refusal("identity-range"))?],
            |row| row.get(0),
        )
        .map_err(sql)?;
    Ok(
        bound::verify_initial(connection, record, &storage::decode_keys(&keys)?)?
            .credential
            .binding,
    )
}

pub(super) fn initial_membership(
    connection: &Connection,
    before: u64,
) -> Result<Option<MembershipSet>> {
    let mut statement = connection.prepare("SELECT a.seq FROM aura a JOIN aura_record_wrappers w ON w.seq=a.seq WHERE a.seq<?1 AND a.kind='aumlok.bind' AND a.phase='terminal' AND w.epoch=1 ORDER BY a.seq").map_err(sql)?;
    let mut rows = statement
        .query([i64::try_from(before).map_err(|_| refusal("identity-range"))?])
        .map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let record = io::record_at(
            connection,
            u64::try_from(row.get::<_, i64>(0).map_err(sql)?)
                .map_err(|_| refusal("identity-range"))?,
        )?;
        let body = payload(&record)?;
        if body
            .get("schema")
            .is_some_and(|value| matches!(value.view(), ValueView::Text(BIND)))
        {
            let binding = initial_binding(connection, &record)?;
            return Ok(Some(MembershipSet {
                epoch: 1,
                members: vec![binding.public_key],
                required_signers: 1,
            }));
        }
    }
    Ok(None)
}
