// SPDX-License-Identifier: AGPL-3.0-or-later
//! Subjectless bootstrap ceremonies and exact-ciphertext binding preparation.

use super::{
    candidate_digest, candidate_value, refusal, validate_identity, CeremonyId, CeremonyPurpose,
    EnrolmentIdentity, MAX_CEREMONY_MS,
};
use crate::webauthn::{
    verify_registration, ExtensionPolicy, OriginContext, RegistrationCandidate,
    RegistrationContext, RegistrationMaterial,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    authority::AuthorityVersion,
    digest::Digest32,
    ids::{CredentialId, SessionId, SubjectId},
    json::Value,
    Result,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

mod codec;
mod options;
use codec::{canonical, context_json, parse_candidate, parse_context};
pub use options::{assertion_material, registration_material};

#[derive(Clone, Debug)]
pub struct Context {
    pub origins: OriginContext,
    pub identity: EnrolmentIdentity,
    pub session: SessionId,
    pub subject: Option<SubjectId>,
    pub credential: Option<CredentialId>,
    pub authority: AuthorityVersion,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub id: CeremonyId,
    pub purpose: CeremonyPurpose,
    pub state: String,
    pub context: Context,
    pub nonce: [u8; 32],
    pub issued: i64,
    pub deadline: i64,
    pub candidate: Option<RegistrationCandidate>,
    pub candidate_digest: Option<Digest32>,
    pub payload: Option<Value>,
    last_seen: i64,
}

impl Snapshot {
    /// Registration and sign-in use their nonce; possession and binding commit to public data.
    pub fn challenge(&self) -> Result<[u8; 32]> {
        match (self.purpose, self.state.as_str()) {
            (CeremonyPurpose::Enrolment, "fresh") | (CeremonyPurpose::SignIn, "fresh") => {
                Ok(self.nonce)
            }
            (CeremonyPurpose::Enrolment, "registered") => {
                let mut hash = Sha256::new();
                hash.update(b"aukora:enrol-possession:v1\0");
                hash.update(self.id.to_string().as_bytes());
                hash.update(
                    self.candidate_digest
                        .ok_or_else(|| refusal("registration-required"))?
                        .as_bytes(),
                );
                Ok(hash.finalize().into())
            }
            (CeremonyPurpose::Binding | CeremonyPurpose::Refresh, "prepared") => {
                let mut hash = Sha256::new();
                hash.update(if self.purpose == CeremonyPurpose::Binding {
                    b"aukora:aumlok-binding:v2\0".as_slice()
                } else {
                    b"aukora:aumlok-refresh:v2\0".as_slice()
                });
                hash.update(self.nonce);
                hash.update(
                    self.payload
                        .as_ref()
                        .ok_or_else(|| refusal("ceremony-data-invalid"))?
                        .canonical_bytes(),
                );
                Ok(hash.finalize().into())
            }
            _ => Err(refusal("ceremony-state")),
        }
    }
}

/// All authority writes remain in Aura's transaction; this store writes preparations only.
pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(sql)?;
        if connection.path().is_none_or(str::is_empty) || !connection.is_autocommit() {
            return Err(refusal("store-not-durable"));
        }
        connection
            .busy_timeout(std::time::Duration::from_secs(2))
            .map_err(sql)?;
        connection
            .execute_batch("PRAGMA synchronous=FULL;")
            .map_err(sql)?;
        let journal: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .map_err(sql)?;
        if journal != "wal" {
            return Err(refusal("store-not-durable"));
        }
        connection.execute_batch(codec::SCHEMA).map_err(sql)?;
        Ok(Self { connection })
    }

    /// The host supplies the authenticated claimed/enrolled/bound session context.
    pub fn begin(
        &mut self,
        context: &Context,
        purpose: CeremonyPurpose,
        now: i64,
    ) -> Result<Snapshot> {
        crate::webauthn::validate_origins(&context.origins)?;
        validate_identity(&context.identity)?;
        if context.origins.expected_top_origin.is_none()
            || !(0..=9_007_199_254_740_991 - MAX_CEREMONY_MS).contains(&now)
            || context.authority.sequence == 0
            || context.authority.sequence > 9_007_199_254_740_991
            || context.authority.epoch > 9_007_199_254_740_991
            || (context.authority.sequence == 1) != context.authority.previous_hash.is_none()
        {
            return Err(refusal("ceremony-data-invalid"));
        }
        match purpose {
            CeremonyPurpose::Enrolment
                if context.subject.is_none()
                    && context.credential.is_none()
                    && context.authority.epoch == 0 => {}
            CeremonyPurpose::Binding
                if context.subject.is_none()
                    && context.credential.is_some()
                    && context.authority.epoch == 0 => {}
            CeremonyPurpose::SignIn
                if context.subject.is_none()
                    && context.credential.is_some()
                    && context.authority.epoch == 0 => {}
            CeremonyPurpose::SignIn | CeremonyPurpose::Refresh
                if context.subject.is_some()
                    && context.credential.is_some()
                    && context.authority.epoch > 0 => {}
            _ => return Err(refusal("ceremony-state")),
        }
        let encoded = context_json(context)?;
        let mut id = [0; 16];
        let mut nonce = [0; 32];
        getrandom::fill(&mut id).map_err(|_| refusal("random-unavailable"))?;
        getrandom::fill(&mut nonce).map_err(|_| refusal("random-unavailable"))?;
        let id = CeremonyId::from_bytes(id);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        tx.execute("UPDATE aumlok_ceremonies_v2 SET state='expired',last_seen=?1 WHERE deadline<=?1 AND last_seen<=?1 AND state IN ('fresh','registered','prepared')", [now]).map_err(sql)?;
        if purpose == CeremonyPurpose::SignIn {
            let shared: Option<Vec<u8>> = tx.query_row(
                "SELECT id FROM aumlok_ceremonies_v2 WHERE purpose='signin' AND state='fresh' AND json_extract(context,'$.credential')=?1 AND json_extract(context,'$.epoch')=?2 ORDER BY issued DESC LIMIT 1",
                params![context.credential.as_ref().map(|id| URL_SAFE_NO_PAD.encode(id.as_bytes())), i64::try_from(context.authority.epoch).map_err(|_| refusal("ceremony-data-invalid"))?], |row| row.get(0)).optional().map_err(sql)?;
            if let Some(shared) = shared {
                let found = read(
                    &tx,
                    &CeremonyId::from_bytes(
                        shared.try_into().map_err(|_| refusal("store-corrupt"))?,
                    ),
                )?;
                live(&found, found.context.session, now)?;
                if found.context.origins != context.origins
                    || found.context.subject != context.subject
                    || found.context.identity.owner_id != context.identity.owner_id
                    || found.context.identity.user_handle != context.identity.user_handle
                {
                    return Err(refusal("ceremony-context-changed"));
                }
                tx.commit().map_err(sql)?;
                return Ok(found);
            }
        }
        let existing: Option<Vec<u8>> = tx.query_row(
            "SELECT id FROM aumlok_ceremonies_v2 WHERE purpose=?1 AND json_extract(context,'$.session')=?2 AND state IN ('fresh','registered','prepared')",
            params![purpose.wire_name(), context.session.to_string()], |row| row.get(0)).optional().map_err(sql)?;
        if let Some(existing) = existing {
            let found = read(
                &tx,
                &CeremonyId::from_bytes(existing.try_into().map_err(|_| refusal("store-corrupt"))?),
            )?;
            live(&found, context.session, now)?;
            if found.context.origins != context.origins
                || found.context.identity.owner_id != context.identity.owner_id
                || found.context.identity.user_handle != context.identity.user_handle
                || found.context.session != context.session
                || found.context.subject != context.subject
                || found.context.credential != context.credential
                || found.context.authority.epoch != context.authority.epoch
            {
                return Err(refusal("ceremony-context-changed"));
            }
            tx.commit().map_err(sql)?;
            return Ok(found);
        }
        if purpose == CeremonyPurpose::Enrolment {
            let occupied: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM aura WHERE kind IN ('aumlok.enrol','aumlok.bind'))", [], |row| row.get(0)).map_err(sql)?;
            if occupied {
                return Err(refusal("enrolment-closed"));
            }
        }
        tx.execute("INSERT INTO aumlok_ceremonies_v2(id,purpose,state,context,nonce,issued,deadline,last_seen) VALUES(?1,?2,'fresh',?3,?4,?5,?6,?5)",
            params![id.as_bytes().as_slice(), purpose.wire_name(), encoded, nonce.as_slice(), now, now + MAX_CEREMONY_MS]).map_err(sql)?;
        let row = read(&tx, &id)?;
        tx.commit().map_err(sql)?;
        Ok(row)
    }

    pub fn load(&mut self, id: &CeremonyId, session: SessionId, now: i64) -> Result<Snapshot> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let row = read(&tx, id)?;
        live(&row, session, now)?;
        tx.execute(
            "UPDATE aumlok_ceremonies_v2 SET last_seen=?1 WHERE id=?2",
            params![now, id.as_bytes().as_slice()],
        )
        .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(row)
    }

    /// Sign-in handles disclose public challenge data; possession is required to finish.
    pub fn load_signin(&mut self, id: &CeremonyId, now: i64) -> Result<Snapshot> {
        let row = read(&self.connection, id)?;
        if row.purpose != CeremonyPurpose::SignIn {
            return Err(refusal("ceremony-kind"));
        }
        self.load(id, row.context.session, now)
    }

    pub fn register(
        &mut self,
        id: &CeremonyId,
        session: SessionId,
        registration: &RegistrationMaterial,
        now: i64,
    ) -> Result<Snapshot> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let row = read(&tx, id)?;
        live(&row, session, now)?;
        if row.purpose != CeremonyPurpose::Enrolment
            || !matches!(row.state.as_str(), "fresh" | "registered")
        {
            return Err(refusal("ceremony-state"));
        }
        let candidate = verify_registration(
            registration,
            &RegistrationContext {
                origins: row.context.origins.clone(),
                owner_id: row.context.identity.owner_id.clone(),
                user_handle: row.context.identity.user_handle.clone(),
                existing_credentials: Vec::new(),
                challenge: row.nonce,
                extensions: ExtensionPolicy::RegistrationPrf,
            },
        )?;
        let digest = candidate_digest(&candidate)?;
        let encoded = canonical(&candidate_value(&candidate))?;
        if row.state == "registered" {
            if row.candidate_digest != Some(digest) {
                return Err(refusal("ceremony-candidate"));
            }
            tx.execute(
                "UPDATE aumlok_ceremonies_v2 SET last_seen=?1 WHERE id=?2",
                params![now, id.as_bytes().as_slice()],
            )
            .map_err(sql)?;
            tx.commit().map_err(sql)?;
            return Ok(row);
        }
        let changed = tx.execute("UPDATE aumlok_ceremonies_v2 SET state='registered',candidate=?1,candidate_digest=?2,last_seen=?3 WHERE id=?4 AND state='fresh'",
            params![encoded, digest.as_bytes().as_slice(), now, id.as_bytes().as_slice()]).map_err(sql)?;
        if changed != 1 {
            return Err(refusal("ceremony-state"));
        }
        let row = read(&tx, id)?;
        tx.commit().map_err(sql)?;
        Ok(row)
    }

    pub fn register_json(
        &mut self,
        id: &CeremonyId,
        session: SessionId,
        registration: &Value,
        now: i64,
    ) -> Result<Snapshot> {
        self.register(id, session, &registration_material(registration)?, now)
    }

    pub fn prepare(
        &mut self,
        id: &CeremonyId,
        session: SessionId,
        payload: &Value,
        now: i64,
    ) -> Result<Snapshot> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let row = read(&tx, id)?;
        live(&row, session, now)?;
        if !matches!(
            row.purpose,
            CeremonyPurpose::Binding | CeremonyPurpose::Refresh
        ) || !matches!(row.state.as_str(), "fresh" | "prepared")
        {
            return Err(refusal("ceremony-state"));
        }
        codec::validate_payload(payload, row.purpose, row.context.subject)?;
        if row.state == "prepared" {
            if row.payload.as_ref() != Some(payload) {
                return Err(refusal("ceremony-context-changed"));
            }
            tx.execute(
                "UPDATE aumlok_ceremonies_v2 SET last_seen=?1 WHERE id=?2",
                params![now, id.as_bytes().as_slice()],
            )
            .map_err(sql)?;
            tx.commit().map_err(sql)?;
            return Ok(row);
        }
        let encoded = String::from_utf8(payload.canonical_bytes())
            .map_err(|_| refusal("ceremony-data-invalid"))?;
        let changed = tx.execute("UPDATE aumlok_ceremonies_v2 SET state='prepared',payload=?1,last_seen=?2 WHERE id=?3 AND state='fresh'",
            params![encoded, now, id.as_bytes().as_slice()]).map_err(sql)?;
        if changed != 1 {
            return Err(refusal("ceremony-state"));
        }
        let row = read(&tx, id)?;
        tx.commit().map_err(sql)?;
        Ok(row)
    }
}

fn live(row: &Snapshot, session: SessionId, now: i64) -> Result<()> {
    if row.context.session != session {
        return Err(refusal("session-invalid"));
    }
    if now < row.issued || now < row.last_seen || now >= row.deadline {
        return Err(refusal("ceremony-expired"));
    }
    if !matches!(row.state.as_str(), "fresh" | "registered" | "prepared") {
        return Err(refusal("ceremony-state"));
    }
    Ok(())
}

fn read(connection: &Connection, id: &CeremonyId) -> Result<Snapshot> {
    let row = connection.query_row("SELECT purpose,state,context,nonce,issued,deadline,last_seen,candidate,candidate_digest,payload FROM aumlok_ceremonies_v2 WHERE id=?1",
        [id.as_bytes().as_slice()], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?,r.get::<_,i64>(6)?,r.get::<_,Option<String>>(7)?,r.get::<_,Option<Vec<u8>>>(8)?,r.get::<_,Option<String>>(9)?)))
        .optional().map_err(sql)?.ok_or_else(|| refusal("ceremony-not-found"))?;
    if row.2.len() > 8192
        || row.7.as_ref().is_some_and(|s| s.len() > 16384)
        || row.9.as_ref().is_some_and(|s| s.len() > 8192)
    {
        return Err(refusal("store-corrupt"));
    }
    let candidate = row.7.as_deref().map(parse_candidate).transpose()?;
    let digest = row
        .8
        .map(|b| {
            b.try_into()
                .map(Digest32::from_bytes)
                .map_err(|_| refusal("store-corrupt"))
        })
        .transpose()?;
    if candidate.as_ref().map(candidate_digest).transpose()? != digest {
        return Err(refusal("store-corrupt"));
    }
    Ok(Snapshot {
        id: *id,
        purpose: CeremonyPurpose::parse(&row.0)?,
        state: row.1,
        context: parse_context(&row.2)?,
        nonce: row.3.try_into().map_err(|_| refusal("store-corrupt"))?,
        issued: row.4,
        deadline: row.5,
        last_seen: row.6,
        candidate,
        candidate_digest: digest,
        payload: row
            .9
            .as_deref()
            .map(|s| canon::json::parse_strict(s.as_bytes()))
            .transpose()?,
    })
}

fn sql(_: rusqlite::Error) -> canon::Refusal {
    refusal("store-error")
}

pub(crate) fn receipt_candidate(value: &Value) -> Result<RegistrationCandidate> {
    let encoded =
        String::from_utf8(value.canonical_bytes()).map_err(|_| refusal("store-corrupt"))?;
    parse_candidate(&encoded)
}

impl Store {
    /// Observe prepared or unfinished refreshes without advancing their state or clock.
    pub fn refresh_pending(
        &self,
        owner: &canon::authority::pending::BoundOwnerIdentity,
        now: i64,
    ) -> Result<bool> {
        if !(0..=canon::json::MAX_SAFE_INTEGER).contains(&now) {
            return Err(refusal("ceremony-data-invalid"));
        }
        let mut statement = self.connection.prepare(
            "SELECT id FROM aumlok_ceremonies_v2 WHERE purpose='refresh' AND state IN ('prepared','spent') AND json_extract(context,'$.subject')=?1 AND json_extract(context,'$.epoch')=?2 LIMIT 1025",
        ).map_err(sql)?;
        let epoch = i64::try_from(owner.credential.binding.epoch)
            .map_err(|_| refusal("ceremony-data-invalid"))?;
        let mut rows = statement
            .query(params![owner.subject.to_string(), epoch])
            .map_err(sql)?;
        let mut pending = false;
        let mut count = 0;
        while let Some(row) = rows.next().map_err(sql)? {
            count += 1;
            if count > 1024 {
                return Err(refusal("ceremony-capacity"));
            }
            let bytes: Vec<u8> = row.get(0).map_err(sql)?;
            let id = CeremonyId::from_bytes(
                bytes.try_into().map_err(|_| refusal("store-corrupt"))?,
            );
            let refresh = read(&self.connection, &id)?;
            if refresh.context.subject != Some(owner.subject)
                || refresh.context.credential.as_ref()
                    != Some(&owner.credential.binding.credential_id)
                || refresh.context.authority.epoch != owner.credential.binding.epoch
                || refresh.issued < 0
                || refresh.last_seen < refresh.issued
                || refresh.last_seen > now
                || refresh.deadline <= refresh.issued
                || refresh.deadline - refresh.issued > MAX_CEREMONY_MS
            {
                return Err(refusal("store-corrupt"));
            }
            let payload = refresh
                .payload
                .as_ref()
                .ok_or_else(|| refusal("store-corrupt"))?;
            codec::validate_payload(payload, CeremonyPurpose::Refresh, Some(owner.subject))?;
            pending |= refresh.state == "spent"
                || (refresh.state == "prepared" && refresh.deadline > now);
        }
        Ok(pending)
    }
}
