// SPDX-License-Identifier: AGPL-3.0-or-later
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use aumlok::{
    binding::BindingStore,
    envelope,
    phrase::Phrase,
    refresh::{self, RefreshError, RefreshPreparation, VerifiedRefreshApproval},
    webauthn,
};
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use frontdoor::{ApiError, BootstrapState, Operation, OwnerState};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod invitation;

const CEREMONY_MS: i64 = 300_000;
/// The WebAuthn timeout the owner page asks for.
const SIGNIN_SHARE_MIN_MS: i64 = 60_000;
const CHAT_SESSION_LIMIT: i64 = 1024;
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS supervisor_owner (
 id INTEGER PRIMARY KEY CHECK(id=1), credential TEXT, counter INTEGER NOT NULL DEFAULT 0,
 subject TEXT, root BLOB, envelope TEXT,
 CHECK(counter BETWEEN 0 AND 4294967295),
 CHECK((subject IS NULL)=(root IS NULL)), CHECK((root IS NULL)=(envelope IS NULL))
);
INSERT OR IGNORE INTO supervisor_owner(id) VALUES(1);
CREATE TRIGGER IF NOT EXISTS supervisor_owner_pin BEFORE UPDATE ON supervisor_owner
WHEN (OLD.credential IS NOT NULL AND NEW.credential IS NOT OLD.credential)
 OR NEW.counter<OLD.counter
 OR (OLD.subject IS NOT NULL AND (NEW.subject IS NOT OLD.subject OR NEW.root IS NOT OLD.root OR NEW.envelope IS NOT OLD.envelope))
BEGIN SELECT RAISE(ABORT,'aumlok:owner-rewind'); END;
CREATE TRIGGER IF NOT EXISTS supervisor_owner_retained BEFORE DELETE ON supervisor_owner
BEGIN SELECT RAISE(ABORT,'aumlok:owner-retained'); END;
CREATE TABLE IF NOT EXISTS supervisor_claim (
 digest BLOB PRIMARY KEY CHECK(length(digest)=32), expires_at INTEGER NOT NULL, spent INTEGER NOT NULL DEFAULT 0 CHECK(spent IN(0,1))
);
CREATE TRIGGER IF NOT EXISTS supervisor_claim_pin BEFORE UPDATE ON supervisor_claim
WHEN NEW.digest IS NOT OLD.digest OR NEW.expires_at IS NOT OLD.expires_at OR NEW.spent<OLD.spent
BEGIN SELECT RAISE(ABORT,'aumlok:claim-rewind'); END;
CREATE TRIGGER IF NOT EXISTS supervisor_claim_retained BEFORE DELETE ON supervisor_claim
BEGIN SELECT RAISE(ABORT,'aumlok:claim-retained'); END;
CREATE TABLE IF NOT EXISTS supervisor_session (
 digest BLOB PRIMARY KEY CHECK(length(digest)=32), expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1))
);
CREATE TRIGGER IF NOT EXISTS supervisor_session_pin BEFORE UPDATE ON supervisor_session
WHEN NEW.digest IS NOT OLD.digest OR NEW.expires_at IS NOT OLD.expires_at OR NEW.revoked<OLD.revoked
BEGIN SELECT RAISE(ABORT,'aumlok:session-rewind'); END;
CREATE TABLE IF NOT EXISTS supervisor_chat_session (
 digest BLOB PRIMARY KEY CHECK(length(digest)=32), owner_digest BLOB NOT NULL CHECK(length(owner_digest)=32),
 expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1))
);
CREATE TRIGGER IF NOT EXISTS supervisor_chat_session_pin BEFORE UPDATE ON supervisor_chat_session
WHEN NEW.digest IS NOT OLD.digest OR NEW.owner_digest IS NOT OLD.owner_digest
 OR NEW.expires_at IS NOT OLD.expires_at OR NEW.revoked<OLD.revoked
BEGIN SELECT RAISE(ABORT,'aumlok:chat-session-rewind'); END;
CREATE TABLE IF NOT EXISTS supervisor_ceremony (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN('enrol','signin','binding')),
 principal TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN('live','candidate','spent','cancelled')),
 candidate TEXT, possession TEXT, prepared BLOB,
 CHECK((candidate IS NULL)=(possession IS NULL))
);
CREATE TRIGGER IF NOT EXISTS supervisor_ceremony_pin BEFORE UPDATE ON supervisor_ceremony
WHEN NEW.id IS NOT OLD.id OR NEW.kind IS NOT OLD.kind OR NEW.principal IS NOT OLD.principal
 OR NEW.challenge IS NOT OLD.challenge OR NEW.expires_at IS NOT OLD.expires_at
 OR (OLD.candidate IS NOT NULL AND (NEW.candidate IS NOT OLD.candidate OR NEW.possession IS NOT OLD.possession))
 OR NEW.prepared IS NOT OLD.prepared
 OR NOT (NEW.state=OLD.state OR (OLD.state='live' AND NEW.state IN('candidate','spent','cancelled')) OR (OLD.state='candidate' AND NEW.state IN('spent','cancelled')))
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-rewind'); END;
DROP TRIGGER IF EXISTS supervisor_ceremony_retained;
CREATE TRIGGER supervisor_ceremony_retained BEFORE DELETE ON supervisor_ceremony
WHEN OLD.kind<>'signin'
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-retained'); END;
CREATE TABLE IF NOT EXISTS supervisor_refresh_approval (
 id TEXT PRIMARY KEY, principal TEXT NOT NULL, auth TEXT NOT NULL,
 expires_at INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN('live','spent'))
);
CREATE TRIGGER IF NOT EXISTS supervisor_refresh_approval_pin BEFORE UPDATE ON supervisor_refresh_approval
WHEN NEW.id IS NOT OLD.id OR NEW.principal IS NOT OLD.principal OR NEW.auth IS NOT OLD.auth
 OR NEW.expires_at IS NOT OLD.expires_at OR OLD.state<>'live' OR NEW.state<>'spent'
BEGIN SELECT RAISE(ABORT,'aumlok:refresh-proof-spent'); END;
DROP TRIGGER IF EXISTS supervisor_refresh_approval_retained;
CREATE TRIGGER supervisor_refresh_approval_retained BEFORE DELETE ON supervisor_refresh_approval
WHEN OLD.state='live'
BEGIN SELECT RAISE(ABORT,'aumlok:refresh-proof-retained'); END;
CREATE TABLE IF NOT EXISTS supervisor_logout_approval (
 id TEXT PRIMARY KEY, principal TEXT NOT NULL UNIQUE, auth TEXT NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS supervisor_logout_approval_pin BEFORE UPDATE ON supervisor_logout_approval
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-rewind'); END;
CREATE TABLE IF NOT EXISTS supervisor_backup (
 id TEXT PRIMARY KEY, principal TEXT NOT NULL UNIQUE, challenge TEXT NOT NULL,
 envelope_sha256 TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS supervisor_backup_pin BEFORE UPDATE ON supervisor_backup
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-rewind'); END;
"#;

#[derive(Clone, Copy)]
pub(crate) enum KdfMode {
    Production,
    DisposableTwin,
}

impl KdfMode {
    fn params(self) -> envelope::KdfParams {
        match self {
            Self::Production => envelope::KdfParams::default(),
            Self::DisposableTwin => envelope::KdfParams {
                memory_kib: 8,
                time_cost: 1,
                parallelism: 1,
            },
        }
    }
}

pub struct Owner {
    binding: BindingStore,
    node: String,
    rp: String,
    origin: String,
    signer: Arc<SigningKey>,
    wrap_key: Zeroizing<[u8; 32]>,
    kdf: KdfMode,
}

impl Owner {
    pub fn open(
        connection: Connection,
        node: String,
        rp: String,
        origin: String,
        signer: Arc<SigningKey>,
    ) -> Result<Self, ApiError> {
        Self::open_with_kdf(connection, node, rp, origin, signer, KdfMode::Production)
    }

    pub(crate) fn open_with_kdf(
        connection: Connection,
        node: String,
        rp: String,
        origin: String,
        signer: Arc<SigningKey>,
        kdf: KdfMode,
    ) -> Result<Self, ApiError> {
        webauthn::validate_origin(&rp, &origin).map_err(|e| refusal(e.0))?;
        let mut binding = BindingStore::from_connection(connection).map_err(|_| storage())?;
        let connection = binding.connection_mut();
        aura::initialize(connection).map_err(|_| storage())?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        tx.execute_batch(SCHEMA).map_err(|_| storage())?;
        let owner_id = credential(&tx)?.map(|c| c.owner_id).unwrap_or_default();
        prune_signin(&tx, &owner_id, now()?)?;
        prune_refresh_approvals(&tx, now()?)?;
        tx.commit().map_err(|_| storage())?;
        let wrap_key = stored_wrap_key(&signer);
        let mut owner = Self {
            binding,
            node,
            rp,
            origin,
            signer,
            wrap_key,
            kdf,
        };
        owner.adopt_initial_binding()?;
        Ok(owner)
    }

    pub fn state(&self) -> Result<OwnerState, ApiError> {
        let subject: Option<String> = self
            .binding
            .connection()
            .query_row("SELECT subject FROM supervisor_owner WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(|_| storage())?;
        let state = if subject.is_some() {
            BootstrapState::Bound
        } else if self.credential()?.is_some() {
            BootstrapState::Enrolled
        } else {
            BootstrapState::ClaimOpen
        };
        Ok(OwnerState { state, subject })
    }

    fn adopt_initial_binding(&mut self) -> Result<(), ApiError> {
        let Some(root) = self.root()? else {
            return Ok(());
        };
        let json: String = self
            .binding
            .connection()
            .query_row(
                "SELECT envelope FROM supervisor_owner WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| storage())?;
        let envelope = envelope::Envelope::from_canonical_json(&json).map_err(|_| storage())?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        BindingStore::adopt_completed(&tx, &root, &envelope).map_err(|_| storage())?;
        tx.commit().map_err(|_| storage())
    }

    fn refresh_start(&mut self, principal: &str) -> Result<Value, ApiError> {
        let at = now()?;
        self.refresh_start_at(principal, at)
    }

    fn backup_start(&mut self, principal: &str) -> Result<Value, ApiError> {
        self.backup_start_at(principal, now()?)
    }

    fn backup_start_at(&mut self, principal: &str, at: i64) -> Result<Value, ApiError> {
        refresh_session(self.binding.connection(), principal, at)?;
        let binding = self
            .binding
            .binding()
            .map_err(|_| storage())?
            .ok_or_else(|| refusal("aumlok:binding-required"))?;
        let digest = refresh::envelope_sha256(&binding.envelope);
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        refresh_session(&tx, principal, at)?;
        let credential = credential(&tx)?.ok_or_else(|| refusal("aumlok:enrolment-required"))?;
        tx.execute("DELETE FROM supervisor_backup WHERE expires_at<=?1 OR NOT EXISTS(SELECT 1 FROM supervisor_session s WHERE supervisor_backup.principal='session:'||lower(hex(s.digest)) AND s.revoked=0 AND s.expires_at>?1)", [at]).map_err(|_| storage())?;
        let live: Option<(String, String)> = tx.query_row(
            "SELECT id,challenge FROM supervisor_backup WHERE principal=?1 AND envelope_sha256=?2 AND expires_at>=?3",
            params![principal, digest, at + SIGNIN_SHARE_MIN_MS], |r| Ok((r.get(0)?,r.get(1)?))
        ).optional().map_err(|_| storage())?;
        let (id, challenge) = if let Some(live) = live {
            live
        } else {
            tx.execute(
                "DELETE FROM supervisor_backup WHERE principal=?1",
                [principal],
            )
            .map_err(|_| storage())?;
            let id = hex::encode(random::<16>()?);
            let challenge = URL_SAFE_NO_PAD.encode(random::<32>()?);
            tx.execute(
                "INSERT INTO supervisor_backup VALUES(?1,?2,?3,?4,?5)",
                params![id, principal, challenge, digest, at + CEREMONY_MS],
            )
            .map_err(|_| storage())?;
            (id, challenge)
        };
        tx.commit().map_err(|_| storage())?;
        let mut public_key = assertion_options(&self.rp, &credential, &challenge);
        public_key["extensions"] =
            json!({"prf":{"eval":{"first":URL_SAFE_NO_PAD.encode(envelope::BACKUP_PRF_SALT)}}});
        Ok(json!({"backup_id":id,"public_key":public_key}))
    }

    fn backup_finish(&mut self, principal: &str, body: Value) -> Result<Value, ApiError> {
        self.backup_finish_at(principal, body, now()?)
    }

    fn backup_finish_at(
        &mut self,
        principal: &str,
        body: Value,
        at: i64,
    ) -> Result<Value, ApiError> {
        let prf = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(text(&body, "prf_output")?)
                .map_err(|_| refusal("aumlok:backup-prf-required"))?,
        );
        if prf.len() != 32 {
            return Err(refusal("aumlok:backup-prf-required"));
        }
        let id = text(&body, "backup_id")?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        refresh_session(&tx, principal, at)?;
        let row: Option<(String,String,String,i64)> = tx.query_row(
            "SELECT principal,challenge,envelope_sha256,expires_at FROM supervisor_backup WHERE id=?1", [id],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))
        ).optional().map_err(|_| storage())?;
        let (owner, challenge, digest, expires) =
            row.ok_or_else(|| refusal("aumlok:backup-unknown"))?;
        if owner != principal {
            return Err(refusal("aumlok:ceremony-principal"));
        }
        if expires <= at {
            return Err(refusal("aumlok:ceremony-expired"));
        }
        let credential = credential(&tx)?.ok_or_else(|| refusal("aumlok:enrolment-required"))?;
        let config = webauthn::Config {
            rp_id: self.rp.clone(),
            origin: self.origin.clone(),
            credential: credential.clone(),
        };
        let verified = webauthn::verify_backup_assertion(
            &assertion(&body["assertion"])?,
            &config,
            &credential.owner_id,
            &challenge,
            None,
        )
        .map_err(|_| refusal("aumlok:assertion-refused"))?;
        // Each phrase attempt spends its own fresh owner assertion.
        if tx
            .execute(
                "DELETE FROM supervisor_backup WHERE id=?1 AND principal=?2",
                params![id, principal],
            )
            .map_err(|_| storage())?
            != 1
        {
            return Err(refusal("aumlok:backup-unknown"));
        }
        persist_assertion_counter(&tx, &verified)?;
        tx.commit().map_err(|_| storage())?;
        let phrase = self
            .binding
            .parse_refresh_phrase(principal, text(&body, "current_phrase")?, at)
            .map_err(refresh_error)?;
        let root = self
            .binding
            .open_current(&digest, principal, &phrase, at)
            .map_err(refresh_error)?;
        let backup = envelope::seal_backup(
            &root,
            &phrase,
            &prf,
            &credential.credential_id,
            &self.rp,
            self.kdf.params(),
        )
        .map_err(|e| refusal(e.code()))?;
        serde_json::from_str(&backup.to_canonical_json()).map_err(|_| storage())
    }

    fn refresh_start_at(&mut self, principal: &str, at: i64) -> Result<Value, ApiError> {
        refresh_session(self.binding.connection(), principal, at)?;
        if let Some(ceremony) = self
            .binding
            .live_refresh(principal, at)
            .map_err(refresh_error)?
        {
            return Ok(refresh_live(ceremony));
        }
        if let Some(expires_at) = self
            .binding
            .other_live_refresh_expiry(principal, at)
            .map_err(refresh_error)?
        {
            return Err(ApiError::with_expires_at(
                StatusCode::CONFLICT,
                "aumlok:refresh-live",
                expires_at,
            ));
        }
        let binding = self
            .binding
            .binding()
            .map_err(|_| storage())?
            .ok_or_else(|| refusal("aumlok:binding-required"))?;
        let credential = self
            .credential()?
            .ok_or_else(|| refusal("aumlok:enrolment-required"))?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        refresh_session(&tx, principal, at)?;
        let live: Option<(String, String)> = tx.query_row("SELECT id,auth FROM supervisor_refresh_approval WHERE principal=?1 AND state='live' AND expires_at>=?2 AND json_extract(auth,'$.base_sha256')=?3 ORDER BY rowid DESC LIMIT 1", params![principal, at + SIGNIN_SHARE_MIN_MS, refresh::envelope_sha256(&binding.envelope)], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_| storage())?;
        let kept = live.as_ref().map(|(id, _)| id.as_str()).unwrap_or("");
        tx.execute("UPDATE supervisor_refresh_approval SET state='spent' WHERE principal=?1 AND state='live' AND id<>?2", params![principal, kept]).map_err(|_| storage())?;
        tx.execute(
            "DELETE FROM supervisor_refresh_approval WHERE principal=?1 AND state='spent'",
            [principal],
        )
        .map_err(|_| storage())?;
        let (id, auth, card) = if let Some((id, stored)) = live {
            let auth: Value = serde_json::from_str(&stored).map_err(|_| storage())?;
            let (rebuilt, card) = refresh_authorization(
                &self.node,
                &binding,
                &id,
                text(&auth, "challenge")?,
                auth["expires_at"].as_i64().ok_or_else(storage)?,
            )?;
            if auth != rebuilt {
                return Err(conflict("aumlok:refresh-stale"));
            }
            (id, auth, card)
        } else {
            let id = hex::encode(random::<16>()?);
            let (auth, card) = refresh_authorization(
                &self.node,
                &binding,
                &id,
                &hex::encode(random::<32>()?),
                at + CEREMONY_MS,
            )?;
            tx.execute(
                "INSERT INTO supervisor_refresh_approval VALUES(?1,?2,?3,?4,'live')",
                params![
                    id,
                    principal,
                    String::from_utf8(canonical(&auth)?).map_err(|_| storage())?,
                    at + CEREMONY_MS
                ],
            )
            .map_err(|_| storage())?;
            (id, auth, card)
        };
        tx.commit().map_err(|_| storage())?;
        let challenge =
            webauthn::owner_authorization_challenge(&canonical(&auth)?).map_err(|_| storage())?;
        Ok(
            json!({"ceremony_id":id,"card":card,"display_sha256":auth["display_sha256"],"auth":auth,"public_key":assertion_options(&self.rp,&credential,&challenge)}),
        )
    }

    fn refresh_prepare(&mut self, principal: &str, body: Value) -> Result<Value, ApiError> {
        self.refresh_prepare_at(principal, body, now()?)
    }

    fn refresh_prepare_at(
        &mut self,
        principal: &str,
        body: Value,
        at: i64,
    ) -> Result<Value, ApiError> {
        refresh_session(self.binding.connection(), principal, at)?;
        if let Some(ceremony) = self
            .binding
            .live_refresh(principal, at)
            .map_err(refresh_error)?
        {
            return Ok(refresh_live(ceremony));
        }
        if let Some(expires_at) = self
            .binding
            .other_live_refresh_expiry(principal, at)
            .map_err(refresh_error)?
        {
            return Err(ApiError::with_expires_at(
                StatusCode::CONFLICT,
                "aumlok:refresh-live",
                expires_at,
            ));
        }
        let id = text(&body, "ceremony_id")?;
        let stored: Option<(String, String, i64, String)> = self.binding.connection().query_row("SELECT principal,auth,expires_at,state FROM supervisor_refresh_approval WHERE id=?1", [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|_| storage())?;
        let (owner, auth, expires, state) =
            stored.ok_or_else(|| refusal("aumlok:ceremony-unknown"))?;
        if owner != principal {
            return Err(refusal("aumlok:ceremony-unknown"));
        }
        if state != "live" {
            return Err(refusal("aumlok:refresh-proof-spent"));
        }
        if expires <= at {
            return Err(ApiError::new(StatusCode::GONE, "aumlok:ceremony-expired"));
        }
        let binding = self
            .binding
            .binding()
            .map_err(|_| storage())?
            .ok_or_else(|| refusal("aumlok:binding-required"))?;
        let authorization: Value = serde_json::from_str(&auth).map_err(|_| storage())?;
        let (rebuilt, _) = refresh_authorization(
            &self.node,
            &binding,
            id,
            text(&authorization, "challenge")?,
            expires,
        )?;
        if canonical(&rebuilt)? != auth.as_bytes() {
            return Err(conflict("aumlok:refresh-stale"));
        }
        let proof = VerifiedRefreshApproval::new(
            principal.into(),
            binding.subject,
            refresh::envelope_sha256(&binding.envelope),
            id.into(),
        );
        let signer = self.signer.clone();
        let rp = self.rp.clone();
        let origin = self.origin.clone();
        let preparation = self
            .binding
            .prepare_refresh_authorized(
                principal,
                text(&body, "current_phrase")?,
                Some(proof),
                at,
                at + CEREMONY_MS,
                self.kdf.params(),
                |tx| {
                    spend_refresh_assertion(
                        tx,
                        principal,
                        id,
                        at,
                        &rp,
                        &origin,
                        auth.as_bytes(),
                        &body["assertion"],
                    )
                    .map_err(|e| RefreshError::refused(e.code))
                },
                |tx, record| {
                    let run = || -> Result<(), ApiError> {
                        refresh_session(tx, principal, at)?;
                        append_phase(
                            tx,
                            &signer,
                            at,
                            "aumlok.bind",
                            &record.ceremony_id,
                            "fact",
                            json!({"refresh":true,"stage":"start","subject":record.subject}),
                        )
                    };
                    run().map_err(|e| RefreshError::refused(e.code))
                },
            )
            .map_err(refresh_error)?;
        Ok(refresh_words(preparation))
    }

    fn refresh_resume(&mut self, principal: &str, body: Value) -> Result<Value, ApiError> {
        let at = now()?;
        refresh_session(self.binding.connection(), principal, at)?;
        let id = text(&body, "ceremony_id")?;
        if let Some(subject) = self
            .binding
            .committed_refresh_subject(id, principal, at)
            .map_err(refresh_error)?
        {
            return Ok(refresh_committed(subject));
        }
        let phrase = self
            .binding
            .parse_refresh_phrase(principal, text(&body, "current_phrase")?, at)
            .map_err(refresh_error)?;
        let preparation = self
            .binding
            .resume_refresh(id, principal, &phrase, at)
            .map_err(refresh_error)?;
        Ok(refresh_words(preparation))
    }

    fn refresh_confirm(&mut self, principal: &str, body: Value) -> Result<Value, ApiError> {
        let at = now()?;
        refresh_session(self.binding.connection(), principal, at)?;
        let id = text(&body, "ceremony_id")?;
        if let Some(subject) = self
            .binding
            .committed_refresh_subject(id, principal, at)
            .map_err(refresh_error)?
        {
            return Ok(refresh_committed(subject));
        }
        let phrase = self
            .binding
            .parse_refresh_phrase(principal, text(&body, "current_phrase")?, at)
            .map_err(refresh_error)?;
        let words = body["words"]
            .as_array()
            .ok_or_else(ApiError::invalid_body)?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(ApiError::invalid_body)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signer = self.signer.clone();
        let record = self
            .binding
            .confirm_refresh(id, principal, &phrase, &words, at, |tx, record| {
                let run = || -> Result<(), ApiError> {
                    refresh_session(tx, principal, at)?;
                    append_phase(
                        tx,
                        &signer,
                        at,
                        "aumlok.bind",
                        &record.ceremony_id,
                        "fact",
                        json!({"refresh":true,"stage":"finish","subject":record.subject}),
                    )?;
                    append(
                        tx,
                        &signer,
                        at,
                        record.kind(),
                        &record.ceremony_id,
                        serde_json::from_str(&record.body()).map_err(|_| storage())?,
                    )
                };
                run().map_err(|e| RefreshError::refused(e.code))
            })
            .map_err(refresh_error)?;
        Ok(refresh_committed(record.subject))
    }

    fn refresh_cancel(&mut self, principal: &str, body: Value) -> Result<Value, ApiError> {
        let at = now()?;
        refresh_session(self.binding.connection(), principal, at)?;
        match self
            .binding
            .cancel_refresh(text(&body, "ceremony_id")?, principal, at)
            .map_err(refresh_error)?
        {
            Some(subject) => Ok(refresh_committed(subject)),
            None => Ok(json!({"ok":true})),
        }
    }

    fn logout_everywhere_start(&mut self, principal: &str) -> Result<Value, ApiError> {
        self.logout_everywhere_start_at(principal, now()?)
    }

    fn logout_everywhere_start_at(&mut self, principal: &str, at: i64) -> Result<Value, ApiError> {
        refresh_session(self.binding.connection(), principal, at)?;
        let binding = self
            .binding
            .binding()
            .map_err(|_| storage())?
            .ok_or_else(|| refusal("aumlok:binding-required"))?;
        let credential = self
            .credential()?
            .ok_or_else(|| refusal("aumlok:enrolment-required"))?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        refresh_session(&tx, principal, at)?;
        let existing: Option<(String,String)> = tx.query_row("SELECT id,auth FROM supervisor_logout_approval WHERE principal=?1 AND expires_at>=?2", params![principal, at + SIGNIN_SHARE_MIN_MS], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(|_| storage())?;
        let (id, auth, card) = if let Some((id, stored)) = existing {
            let auth: Value = serde_json::from_str(&stored).map_err(|_| storage())?;
            let (rebuilt, card) = logout_authorization(
                &self.node,
                &binding.subject,
                &id,
                text(&auth, "challenge")?,
                auth["expires_at"].as_i64().ok_or_else(storage)?,
            )?;
            if auth != rebuilt {
                return Err(conflict("aumlok:refresh-stale"));
            }
            (id, auth, card)
        } else {
            let id = hex::encode(random::<16>()?);
            let (auth, card) = logout_authorization(
                &self.node,
                &binding.subject,
                &id,
                &hex::encode(random::<32>()?),
                at + CEREMONY_MS,
            )?;
            tx.execute(
                "DELETE FROM supervisor_logout_approval WHERE principal=?1",
                [principal],
            )
            .map_err(|_| storage())?;
            tx.execute(
                "INSERT INTO supervisor_logout_approval VALUES(?1,?2,?3,?4)",
                params![
                    id,
                    principal,
                    String::from_utf8(canonical(&auth)?).map_err(|_| storage())?,
                    at + CEREMONY_MS
                ],
            )
            .map_err(|_| storage())?;
            (id, auth, card)
        };
        tx.commit().map_err(|_| storage())?;
        let challenge =
            webauthn::owner_authorization_challenge(&canonical(&auth)?).map_err(|_| storage())?;
        Ok(
            json!({"ceremony_id":id,"card":card,"display_sha256":auth["display_sha256"],"auth":auth,"public_key":assertion_options(&self.rp,&credential,&challenge)}),
        )
    }

    fn logout_everywhere_finish(
        &mut self,
        principal: &str,
        body: Value,
    ) -> Result<Value, ApiError> {
        let at = now()?;
        let id = text(&body, "ceremony_id")?;
        let subject = self
            .state()?
            .subject
            .ok_or_else(|| refusal("aumlok:binding-required"))?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        refresh_session(&tx, principal, at)?;
        let stored: Option<(String, String, i64)> = tx
            .query_row(
                "SELECT principal,auth,expires_at FROM supervisor_logout_approval WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| storage())?;
        let (owner, stored, expires) = stored.ok_or_else(|| refusal("aumlok:ceremony-unknown"))?;
        if owner != principal {
            return Err(refusal("aumlok:ceremony-principal"));
        }
        if expires <= at {
            return Err(ApiError::new(StatusCode::GONE, "aumlok:ceremony-expired"));
        }
        let auth: Value = serde_json::from_str(&stored).map_err(|_| storage())?;
        let (rebuilt, _) =
            logout_authorization(&self.node, &subject, id, text(&auth, "challenge")?, expires)?;
        if canonical(&rebuilt)? != stored.as_bytes() {
            return Err(refusal("aumlok:assertion-refused"));
        }
        let verified = verify_refresh_assertion(
            &tx,
            &self.rp,
            &self.origin,
            stored.as_bytes(),
            &body["assertion"],
        )?;
        if tx
            .execute(
                "DELETE FROM supervisor_logout_approval WHERE id=?1 AND principal=?2",
                params![id, principal],
            )
            .map_err(|_| storage())?
            != 1
        {
            return Err(refusal("aumlok:ceremony-spent"));
        }
        persist_assertion_counter(&tx, &verified)?;
        tx.execute(
            "UPDATE supervisor_session SET revoked=1 WHERE revoked=0",
            [],
        )
        .map_err(|_| storage())?;
        tx.execute(
            "UPDATE aumlok_refresh SET state='CANCELLED' WHERE state='LIVE'",
            [],
        )
        .map_err(|_| storage())?;
        tx.execute(
            "UPDATE supervisor_refresh_approval SET state='spent' WHERE state='live'",
            [],
        )
        .map_err(|_| storage())?;
        tx.execute(
            "DELETE FROM supervisor_refresh_approval WHERE state='spent'",
            [],
        )
        .map_err(|_| storage())?;
        tx.execute("DELETE FROM supervisor_logout_approval", [])
            .map_err(|_| storage())?;
        append(
            &tx,
            &self.signer,
            at,
            "aumlok.signin",
            id,
            json!({"action":"signout-everywhere","subject":subject,"credential_id":verified.credential_id,"assertion_sha256":verified.signed_bytes_digest}),
        )?;
        tx.commit().map_err(|_| storage())?;
        Ok(json!({"ok":true}))
    }

    pub fn credential(&self) -> Result<Option<webauthn::Credential>, ApiError> {
        credential(self.binding.connection())
    }

    pub fn root(&self) -> Result<Option<Zeroizing<[u8; 32]>>, ApiError> {
        let bytes: Option<Vec<u8>> = self
            .binding
            .connection()
            .query_row("SELECT root FROM supervisor_owner WHERE id=1", [], |r| {
                r.get(0)
            })
            .map_err(|_| storage())?;
        bytes
            .map(|bytes| {
                let plain = decrypt(&self.wrap_key, &bytes, b"root")?;
                let root: [u8; 32] = plain.as_slice().try_into().map_err(|_| storage())?;
                Ok(Zeroizing::new(root))
            })
            .transpose()
    }

    pub fn create_claim(&mut self) -> Result<String, ApiError> {
        if self.credential()?.is_some() {
            return Err(conflict("aumlok:enrolment-closed"));
        }
        let token = URL_SAFE_NO_PAD.encode(random::<32>()?);
        self.binding
            .connection()
            .execute(
                "INSERT INTO supervisor_claim(digest,expires_at) VALUES(?1,?2)",
                params![
                    Sha256::digest(token.as_bytes()).as_slice(),
                    now()? + 15 * 60 * 1000
                ],
            )
            .map_err(|_| storage())?;
        Ok(token)
    }

    pub fn consume_claim(&mut self, digest: [u8; 32]) -> Result<(), ApiError> {
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        spend_claim(&tx, digest, now()?)?;
        tx.commit().map_err(|_| storage())
    }

    pub fn consume_claim_session(
        &mut self,
        digest: [u8; 32],
        session: [u8; 32],
        expires_at: i64,
    ) -> Result<(), ApiError> {
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let at = now()?;
        spend_claim(&tx, digest, at)?;
        if expires_at <= at || expires_at - at > 86_400_000 {
            return Err(storage());
        }
        tx.execute(
            "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
            params![session, expires_at],
        )
        .map_err(|_| storage())?;
        tx.commit().map_err(|_| storage())
    }

    pub fn session_valid(&self, digest: [u8; 32], at: i64) -> Result<bool, ApiError> {
        self.binding.connection().query_row("SELECT EXISTS(SELECT 1 FROM supervisor_session WHERE digest=?1 AND revoked=0 AND expires_at>?2)", params![digest, at], |r| r.get(0)).map_err(|_| storage())
    }

    pub fn revoke_session(&mut self, digest: [u8; 32]) -> Result<(), ApiError> {
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        tx.execute(
            "UPDATE supervisor_session SET revoked=1 WHERE digest=?1",
            [digest],
        )
        .map_err(|_| storage())?;
        tx.execute(
            "UPDATE aumlok_refresh SET state='CANCELLED' WHERE principal=?1 AND state='LIVE'",
            [format!("session:{}", hex::encode(digest))],
        )
        .map_err(|_| storage())?;
        tx.commit().map_err(|_| storage())
    }

    pub fn create_chat_session(
        &mut self,
        owner: [u8; 32],
        session: [u8; 32],
        expires_at: i64,
    ) -> Result<(), ApiError> {
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let at = now()?;
        if expires_at <= at || expires_at - at > 86_400_000 {
            return Err(storage());
        }
        let parent_expiry: Option<i64> = tx
            .query_row(
                "SELECT expires_at FROM supervisor_session WHERE digest=?1 AND revoked=0 AND expires_at>?2",
                params![owner, at],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| storage())?;
        let Some(parent_expiry) = parent_expiry else {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "frontdoor:session-required",
            ));
        };
        tx.execute(
            "DELETE FROM supervisor_chat_session WHERE revoked=1 OR expires_at<=?1 OR NOT EXISTS(SELECT 1 FROM supervisor_session p WHERE p.digest=owner_digest AND p.revoked=0 AND p.expires_at>?1)",
            [at],
        )
        .map_err(|_| storage())?;
        let count: i64 = tx
            .query_row("SELECT count(*) FROM supervisor_chat_session", [], |row| {
                row.get(0)
            })
            .map_err(|_| storage())?;
        if count >= CHAT_SESSION_LIMIT {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "frontdoor:chat-session-limit",
            ));
        }
        tx.execute(
            "INSERT INTO supervisor_chat_session(digest,owner_digest,expires_at) VALUES(?1,?2,?3)",
            params![session, owner, expires_at.min(parent_expiry)],
        )
        .map_err(|_| storage())?;
        tx.commit().map_err(|_| storage())
    }

    pub fn chat_session_valid(&self, digest: [u8; 32], at: i64) -> Result<bool, ApiError> {
        self.binding.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM supervisor_chat_session c JOIN supervisor_session p ON p.digest=c.owner_digest WHERE c.digest=?1 AND c.revoked=0 AND c.expires_at>?2 AND p.revoked=0 AND p.expires_at>?2)",
            params![digest, at],
            |row| row.get(0),
        ).map_err(|_| storage())
    }

    pub fn revoke_chat_session(&mut self, digest: [u8; 32]) -> Result<(), ApiError> {
        self.binding
            .connection()
            .execute(
                "UPDATE supervisor_chat_session SET revoked=1 WHERE digest=?1",
                [digest],
            )
            .map_err(|_| storage())?;
        Ok(())
    }

    pub fn call(
        &mut self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> Result<Value, ApiError> {
        frontdoor::validate_operation(operation, &body)?;
        match operation {
            Operation::EnrolStart => self.enrol_start(principal),
            Operation::EnrolFinish => self.enrol_finish(principal, body),
            Operation::SigninStart => self.signin_start(),
            Operation::SigninFinish => self.signin_finish(body),
            Operation::LogoutEverywhereStart => self.logout_everywhere_start(principal),
            Operation::LogoutEverywhereFinish => self.logout_everywhere_finish(principal, body),
            Operation::BindingPrepare => self.binding_prepare(principal),
            Operation::BindingConfirm => self.binding_confirm(principal, body),
            Operation::BindingCancel => self.binding_cancel(principal, body),
            Operation::BindingRefresh => self.refresh_start(principal),
            Operation::BindingRefreshPrepare => self.refresh_prepare(principal, body),
            Operation::BindingRefreshResume => self.refresh_resume(principal, body),
            Operation::BindingRefreshConfirm => self.refresh_confirm(principal, body),
            Operation::BindingRefreshCancel => self.refresh_cancel(principal, body),
            Operation::BindingBackupStart => self.backup_start(principal),
            Operation::BindingBackupFinish => self.backup_finish(principal, body),
            Operation::BindingEnvelope => {
                let binding = self
                    .binding
                    .binding()
                    .map_err(|_| storage())?
                    .ok_or_else(|| refusal("aumlok:binding-required"))?;
                serde_json::from_str(&binding.envelope.to_canonical_json()).map_err(|_| storage())
            }
            _ => Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "frontdoor:unknown-route",
            )),
        }
    }

    fn enrol_start(&mut self, principal: &str) -> Result<Value, ApiError> {
        if self.credential()?.is_some() {
            return Err(conflict("aumlok:enrolment-closed"));
        }
        let at = now()?;
        let live = self.binding.connection().query_row("SELECT id,challenge FROM supervisor_ceremony WHERE kind='enrol' AND principal=?1 AND state IN('live','candidate') AND expires_at>?2 ORDER BY rowid DESC LIMIT 1", params![principal, at], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional().map_err(|_| storage())?;
        if let Some((id, _)) = live.as_ref() {
            let candidate: Option<(String,String)> = self.binding.connection().query_row("SELECT candidate,possession FROM supervisor_ceremony WHERE id=?1 AND state='candidate'",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|storage())?;
            if let Some((candidate, challenge)) = candidate {
                let candidate: webauthn::RegistrationCandidate =
                    serde_json::from_str(&candidate).map_err(|_| storage())?;
                return Ok(
                    json!({"enrolment_id":id,"state":"possession-required","public_key":assertion_options(&self.rp,&candidate.credential,&challenge)}),
                );
            }
        }
        let (id, challenge) = if let Some(row) = live {
            row
        } else {
            let id = hex::encode(random::<16>()?);
            let challenge = URL_SAFE_NO_PAD.encode(random::<32>()?);
            self.binding.connection().execute("INSERT INTO supervisor_ceremony(id,kind,principal,challenge,expires_at,state) VALUES(?1,'enrol',?2,?3,?4,'live')",params![id,principal,challenge,at+CEREMONY_MS]).map_err(|_| storage())?;
            (id, challenge)
        };
        Ok(json!({"enrolment_id":id,"public_key":{
            "challenge":challenge,"rp":{"name":"Aukora Sovereign","id":self.rp},
            "user":{"id":URL_SAFE_NO_PAD.encode(self.node.as_bytes()),"name":"owner","displayName":"Owner"},
            "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8}],
            "authenticatorSelection":{"residentKey":"required","userVerification":"required"},
            "attestation":"none","timeout":60000,"extensions":{"prf":{}}
        }}))
    }

    fn enrol_finish(&mut self, principal: &str, body: Value) -> Result<Value, ApiError> {
        if self.credential()?.is_some() {
            return Err(conflict("aumlok:enrolment-closed"));
        }
        let at = now()?;
        let id = text(&body, "enrolment_id")?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let row = ceremony(&tx, id, "enrol", principal, at)?;
        if let Some(registration) = body.get("attestation") {
            if row.state != "live" {
                return Err(conflict("aumlok:enrolment-closed"));
            }
            let mut material = registration.clone();
            material["type"] = json!("public-key");
            let material = serde_json::from_value(material)
                .map_err(|_| refusal("aumlok:attestation-refused"))?;
            let context = webauthn::RegistrationContext {
                rp_id: self.rp.clone(),
                origin: self.origin.clone(),
                owner_id: format!("owner:{}", self.node),
                user_handle: URL_SAFE_NO_PAD.encode(self.node.as_bytes()),
                existing_credential_ids: vec![],
            };
            let candidate = webauthn::verify_prf_registration(&material, &context, &row.challenge)
                .map_err(|_| refusal("aumlok:attestation-refused"))?;
            let candidate_bytes =
                canonical(&serde_json::to_value(&candidate).map_err(|_| storage())?)?;
            let mut digest = Sha256::new();
            digest.update(b"aukora:enrol-possession:v1\0");
            digest.update(id.as_bytes());
            digest.update(Sha256::digest(candidate_bytes));
            let challenge = URL_SAFE_NO_PAD.encode(digest.finalize());
            tx.execute("UPDATE supervisor_ceremony SET state='candidate',candidate=?2,possession=?3 WHERE id=?1 AND state='live'",params![id,serde_json::to_string(&candidate).map_err(|_| storage())?,challenge]).map_err(|_| storage())?;
            tx.commit().map_err(|_| storage())?;
            return Ok(
                json!({"enrolment_id":id,"state":"possession-required","public_key":assertion_options(&self.rp,&candidate.credential,&challenge)}),
            );
        }
        if row.state != "candidate" {
            return Err(refusal("aumlok:registration-required"));
        }
        let candidate: webauthn::RegistrationCandidate =
            serde_json::from_str(row.candidate.as_deref().ok_or_else(storage)?)
                .map_err(|_| storage())?;
        let assertion = assertion(&body["assertion"])?;
        let config = webauthn::Config {
            rp_id: self.rp.clone(),
            origin: self.origin.clone(),
            credential: candidate.credential.clone(),
        };
        let verified = webauthn::verify_assertion(
            &assertion,
            &config,
            &candidate.credential.owner_id,
            row.possession.as_deref().ok_or_else(storage)?,
            None,
        )
        .map_err(|_| refusal("aumlok:assertion-refused"))?;
        let changed=tx.execute("UPDATE supervisor_owner SET credential=?1,counter=?2 WHERE id=1 AND credential IS NULL",params![serde_json::to_string(&candidate.credential).map_err(|_| storage())?,verified.sign_count]).map_err(|_| storage())?;
        if changed != 1 {
            return Err(conflict("aumlok:enrolment-closed"));
        }
        tx.execute(
            "UPDATE supervisor_ceremony SET state='spent' WHERE id=?1 AND state='candidate'",
            [id],
        )
        .map_err(|_| storage())?;
        append(
            &tx,
            &self.signer,
            at,
            "aumlok.enrol",
            id,
            json!({"credential_id":candidate.credential.credential_id,"rp_id":self.rp,"registration_sha256":candidate.registration_client_data_sha256,"possession_sha256":verified.signed_bytes_digest}),
        )?;
        tx.commit().map_err(|_| storage())?;
        Ok(json!({"ok":true,"state":"enrolled"}))
    }

    fn signin_start(&mut self) -> Result<Value, ApiError> {
        self.signin_start_at(now()?)
    }

    fn signin_start_at(&mut self, at: i64) -> Result<Value, ApiError> {
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let credential = credential(&tx)?.ok_or_else(|| conflict("aumlok:not-enrolled"))?;
        prune_signin(&tx, &credential.owner_id, at)?;
        // Starts share a live challenge; strangers cannot reset or evict the owner's ceremony.
        // It is shared only while a whole WebAuthn timeout remains, so nobody can hand the
        // owner a challenge about to expire (then at most two live rows exist).
        let live = tx.query_row(
            "SELECT id,challenge FROM supervisor_ceremony WHERE kind='signin' AND principal=?1 AND state='live' AND expires_at>?2 ORDER BY expires_at DESC LIMIT 1",
            params![credential.owner_id, at + SIGNIN_SHARE_MIN_MS],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        ).optional().map_err(|_| storage())?;
        let (id, challenge) = if let Some(live) = live {
            live
        } else {
            let id = hex::encode(random::<16>()?);
            let challenge = URL_SAFE_NO_PAD.encode(random::<32>()?);
            tx.execute("INSERT INTO supervisor_ceremony(id,kind,principal,challenge,expires_at,state) VALUES(?1,'signin',?2,?3,?4,'live')",params![id,credential.owner_id,challenge,at+CEREMONY_MS]).map_err(|_| storage())?;
            (id, challenge)
        };
        tx.commit().map_err(|_| storage())?;
        Ok(
            json!({"ceremony_id":id,"public_key":assertion_options(&self.rp,&credential,&challenge)}),
        )
    }

    fn signin_finish(&mut self, body: Value) -> Result<Value, ApiError> {
        self.signin_finish_session(body, None)
    }

    pub fn signin_session(
        &mut self,
        body: Value,
        session: [u8; 32],
        expires_at: i64,
    ) -> Result<Value, ApiError> {
        frontdoor::validate_operation(Operation::SigninFinish, &body)?;
        self.signin_finish_session(body, Some((session, expires_at)))
    }

    fn signin_finish_session(
        &mut self,
        body: Value,
        session: Option<([u8; 32], i64)>,
    ) -> Result<Value, ApiError> {
        let at = now()?;
        if session.is_some_and(|(_, expires_at)| expires_at <= at || expires_at - at > 86_400_000) {
            return Err(storage());
        }
        let id = text(&body, "ceremony_id")?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let credential = credential(&tx)?.ok_or_else(|| conflict("aumlok:not-enrolled"))?;
        let row = ceremony(&tx, id, "signin", &credential.owner_id, at)?;
        if row.state != "live" {
            return Err(refusal("aumlok:ceremony-unknown"));
        }
        let config = webauthn::Config {
            rp_id: self.rp.clone(),
            origin: self.origin.clone(),
            credential: credential.clone(),
        };
        let verified = webauthn::verify_assertion(
            &assertion(&body["assertion"])?,
            &config,
            &credential.owner_id,
            &row.challenge,
            None,
        )
        .map_err(|_| refusal("aumlok:assertion-refused"))?;
        tx.execute(
            "UPDATE supervisor_owner SET counter=?1 WHERE id=1",
            [verified.sign_count],
        )
        .map_err(|_| storage())?;
        let gate_exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='gate_owner')",[],|r|r.get(0)).map_err(|_|storage())?;
        if gate_exists {
            tx.execute("UPDATE gate_owner SET sign_count=max(sign_count,?1) WHERE singleton=1 AND credential_id=?2",params![verified.sign_count,gate::sha256(verified.credential_id.as_bytes())]).map_err(|_|storage())?;
        }

        tx.execute(
            "UPDATE supervisor_ceremony SET state='spent' WHERE id=?1 AND state='live'",
            [id],
        )
        .map_err(|_| storage())?;
        append(
            &tx,
            &self.signer,
            at,
            "aumlok.signin",
            id,
            json!({"credential_id":verified.credential_id,"assertion_sha256":verified.signed_bytes_digest}),
        )?;
        if let Some((digest, expires_at)) = session {
            tx.execute(
                "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
                params![digest, expires_at],
            )
            .map_err(|_| storage())?;
            tx.execute(
                "UPDATE aumlok_refresh SET state='CANCELLED' WHERE state='LIVE' AND EXISTS(SELECT 1 FROM supervisor_session s WHERE aumlok_refresh.principal='session:'||lower(hex(s.digest)) AND (s.revoked=1 OR s.expires_at<=?1))",
                [at],
            )
            .map_err(|_| storage())?;
        }
        tx.commit().map_err(|_| storage())?;
        Ok(json!({"ok":true,"state":self.state()?.state.as_str()}))
    }

    fn binding_prepare(&mut self, principal: &str) -> Result<Value, ApiError> {
        if self.state()?.state.is_bound() {
            return Err(conflict("aumlok:already-bound"));
        }
        if self.credential()?.is_none() {
            return Err(refusal("aumlok:enrolment-required"));
        }
        let at = now()?;
        let prepared: Option<(String,i64,Vec<u8>)>=self.binding.connection().query_row("SELECT id,expires_at,prepared FROM supervisor_ceremony WHERE kind='binding' AND principal=?1 AND state='live' AND expires_at>?2 ORDER BY rowid DESC LIMIT 1",params![principal,at],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_| storage())?;
        let (id, expires, plain) = if let Some((id, expires, prepared)) = prepared {
            (id, expires, decrypt(&self.wrap_key, &prepared, b"binding")?)
        } else {
            let phrase = Phrase::draw().map_err(|e| refusal(e.code()))?;
            let sealed =
                envelope::seal(&phrase, self.kdf.params()).map_err(|e| refusal(e.code()))?;
            let id = hex::encode(random::<16>()?);
            let expires = at + CEREMONY_MS;
            let plain=Zeroizing::new(serde_json::to_vec(&json!({"words":phrase.as_str().split_whitespace().collect::<Vec<_>>(),"root":hex::encode(*sealed.root),"envelope":sealed.envelope.to_canonical_json()})).map_err(|_|storage())?);
            let encrypted = encrypt(&self.wrap_key, &plain, b"binding")?;
            self.binding.connection().execute("INSERT INTO supervisor_ceremony(id,kind,principal,challenge,expires_at,state,prepared) VALUES(?1,'binding',?2,'',?3,'live',?4)",params![id,principal,expires,encrypted]).map_err(|_|storage())?;
            (id, expires, plain)
        };
        let prepared: Value = serde_json::from_slice(&plain).map_err(|_| storage())?;
        let bits = aumlok::phrase::entropy().minimum_bits;
        Ok(
            json!({"ceremony_id":id,"words":prepared["words"],"entropy_bits":bits.floor() as u64,"expires_at":expires}),
        )
    }

    fn binding_confirm(&mut self, principal: &str, body: Value) -> Result<Value, ApiError> {
        if self.state()?.state.is_bound() {
            return Err(conflict("aumlok:already-bound"));
        }
        if self.credential()?.is_none() {
            return Err(refusal("aumlok:enrolment-required"));
        }
        let at = now()?;
        let id = text(&body, "ceremony_id")?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let row = ceremony(&tx, id, "binding", principal, at)?;
        if row.state != "live" {
            return Err(refusal("aumlok:ceremony-unknown"));
        }
        let plain = decrypt(
            &self.wrap_key,
            row.prepared.as_deref().ok_or_else(storage)?,
            b"binding",
        )?;
        let prepared: Value = serde_json::from_slice(&plain).map_err(|_| storage())?;
        for position in 0..7 {
            if body["words"][position] != prepared["words"][position] {
                return Err(ApiError::with_position(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "aumlok:word-mismatch",
                    (position + 1) as u8,
                ));
            }
        }
        let root: [u8; 32] = hex::decode(text(&prepared, "root")?)
            .map_err(|_| storage())?
            .try_into()
            .map_err(|_| storage())?;
        let subject = aumlok::binding::subject_from_root(&root);
        let wrapped = encrypt(&self.wrap_key, &root, b"root")?;
        let changed=tx.execute("UPDATE supervisor_owner SET subject=?1,root=?2,envelope=?3 WHERE id=1 AND subject IS NULL",params![subject,wrapped,text(&prepared,"envelope")?]).map_err(|_|storage())?;
        if changed != 1 {
            return Err(conflict("aumlok:already-bound"));
        }
        let envelope = envelope::Envelope::from_canonical_json(text(&prepared, "envelope")?)
            .map_err(|_| storage())?;
        BindingStore::adopt_completed(&tx, &root, &envelope).map_err(|_| storage())?;
        tx.execute(
            "UPDATE supervisor_ceremony SET state='spent' WHERE id=?1 AND state='live'",
            [id],
        )
        .map_err(|_| storage())?;
        append(
            &tx,
            &self.signer,
            at,
            "aumlok.bind",
            id,
            json!({"subject":subject,"envelope_version":1}),
        )?;
        tx.commit().map_err(|_| storage())?;
        Ok(json!({"ok":true,"state":"bound","subject":subject}))
    }

    fn binding_cancel(&mut self, principal: &str, body: Value) -> Result<Value, ApiError> {
        let id = text(&body, "ceremony_id")?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        let row = ceremony(&tx, id, "binding", principal, now()?)?;
        if row.state != "live" {
            return Err(refusal("aumlok:ceremony-unknown"));
        }
        tx.execute(
            "UPDATE supervisor_ceremony SET state='cancelled' WHERE id=?1 AND state='live'",
            [id],
        )
        .map_err(|_| storage())?;
        tx.commit().map_err(|_| storage())?;
        Ok(json!({"ok":true}))
    }
}

fn prune_signin(tx: &Transaction<'_>, owner_id: &str, at: i64) -> Result<(), ApiError> {
    tx.execute(
        "DELETE FROM supervisor_ceremony WHERE kind='signin' AND (principal<>?1 OR state<>'live' OR expires_at<=?2 OR rowid NOT IN (SELECT rowid FROM supervisor_ceremony WHERE kind='signin' AND principal=?1 AND state='live' AND expires_at>?2 ORDER BY rowid DESC LIMIT 1))",
        params![owner_id, at],
    ).map_err(|_| storage())?;
    Ok(())
}

pub struct PasskeyProof {
    pub rp: String,
    pub origin: String,
    pub credential: Arc<Mutex<Option<webauthn::Credential>>>,
}
impl gate::OwnerProof for PasskeyProof {
    fn verify(&self, auth_bytes: &[u8], proof: &[u8]) -> gate::Result<gate::VerifiedProof> {
        let credential = self
            .credential
            .lock()
            .map_err(|_| gate::Error::Refused("aumlok:assertion-refused"))?
            .clone()
            .ok_or(gate::Error::Refused("aumlok:not-enrolled"))?;
        self.verify_credential(credential, auth_bytes, proof)
    }

    fn verify_in_transaction(
        &self,
        tx: &Transaction<'_>,
        auth_bytes: &[u8],
        proof: &[u8],
        retained: bool,
    ) -> gate::Result<gate::VerifiedProof> {
        let mut credential = credential(tx)
            .map_err(|_| gate::Error::Refused("aumlok:storage"))?
            .ok_or(gate::Error::Refused("aumlok:not-enrolled"))?;
        // Retained proofs return an existing receipt without another spend.
        if retained {
            credential.sign_count = 0;
        }
        self.verify_credential(credential, auth_bytes, proof)
    }

    fn persist_counter(
        &self,
        tx: &Transaction<'_>,
        verified: &gate::VerifiedProof,
    ) -> gate::Result<()> {
        let (json, prior): (String, u32) = tx.query_row(
            "SELECT credential,counter FROM supervisor_owner WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let pinned: webauthn::Credential = serde_json::from_str(&json)?;
        if verified.credential_id != gate::sha256(pinned.credential_id.as_bytes()) {
            return Err(gate::Error::Refused("gate:credential-mismatch"));
        }
        if (verified.counter != 0 || prior != 0) && verified.counter <= prior {
            return Err(gate::Error::Refused("gate:counter-replay"));
        }
        if verified.counter == 0 {
            return Ok(());
        }
        if tx.execute(
            "UPDATE supervisor_owner SET counter=?1 WHERE id=1 AND counter=?2 AND credential=?3",
            params![verified.counter, prior, json],
        )? != 1
        {
            return Err(gate::Error::Refused("gate:counter-conflict"));
        }
        Ok(())
    }
}

impl PasskeyProof {
    fn verify_credential(
        &self,
        credential: webauthn::Credential,
        auth_bytes: &[u8],
        proof: &[u8],
    ) -> gate::Result<gate::VerifiedProof> {
        let material: webauthn::AssertionMaterial = serde_json::from_slice(proof)
            .map_err(|_| gate::Error::Refused("aumlok:assertion-refused"))?;
        let challenge = webauthn::owner_authorization_challenge(auth_bytes)
            .map_err(|e| gate::Error::Refused(e.0))?;
        let config = webauthn::Config {
            rp_id: self.rp.clone(),
            origin: self.origin.clone(),
            credential: credential.clone(),
        };
        let checked =
            webauthn::verify_assertion(&material, &config, &credential.owner_id, &challenge, None)
                .map_err(|e| gate::Error::Refused(e.0))?;
        Ok(gate::VerifiedProof {
            credential_id: gate::sha256(checked.credential_id.as_bytes()),
            counter: checked.sign_count,
        })
    }
}

type StoredCeremony = (
    String,
    String,
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
);

struct CeremonyRow {
    challenge: String,
    state: String,
    candidate: Option<String>,
    possession: Option<String>,
    prepared: Option<Vec<u8>>,
}
fn ceremony(
    tx: &Transaction<'_>,
    id: &str,
    kind: &str,
    principal: &str,
    at: i64,
) -> Result<CeremonyRow, ApiError> {
    let row:Option<StoredCeremony>=tx.query_row("SELECT principal,challenge,state,expires_at,candidate,possession,prepared FROM supervisor_ceremony WHERE id=?1 AND kind=?2",params![id,kind],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(|_|storage())?;
    let (owner, challenge, state, expires, candidate, possession, prepared) =
        row.ok_or_else(|| refusal("aumlok:ceremony-unknown"))?;
    if owner != principal {
        return Err(refusal("aumlok:ceremony-unknown"));
    }
    if at >= expires {
        return Err(ApiError::new(StatusCode::GONE, "aumlok:ceremony-expired"));
    }
    Ok(CeremonyRow {
        challenge,
        state,
        candidate,
        possession,
        prepared,
    })
}
fn credential(connection: &Connection) -> Result<Option<webauthn::Credential>, ApiError> {
    let (json, counter): (Option<String>, u32) = connection
        .query_row(
            "SELECT credential,counter FROM supervisor_owner WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| storage())?;
    let Some(json) = json else { return Ok(None) };
    let mut credential: webauthn::Credential =
        serde_json::from_str(&json).map_err(|_| storage())?;
    let gate_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='gate_owner')",
            [],
            |r| r.get(0),
        )
        .map_err(|_| storage())?;
    let counter = if gate_exists {
        let gate_counter: Option<u32> = connection
            .query_row(
                "SELECT sign_count FROM gate_owner WHERE singleton=1 AND credential_id=?1",
                [gate::sha256(credential.credential_id.as_bytes())],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| storage())?;
        counter.max(gate_counter.unwrap_or(0))
    } else {
        counter
    };
    credential.sign_count = counter;
    Ok(Some(credential))
}
fn spend_claim(tx: &Transaction<'_>, digest: [u8; 32], at: i64) -> Result<(), ApiError> {
    if credential(tx)?.is_some() {
        return Err(refusal("aumlok:claim-spent"));
    }
    let row: Option<(i64, bool)> = tx
        .query_row(
            "SELECT expires_at,spent FROM supervisor_claim WHERE digest=?1",
            [digest],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| storage())?;
    let (expiry, spent) = row.ok_or_else(|| refusal("aumlok:claim-unknown"))?;
    if spent {
        return Err(refusal("aumlok:claim-spent"));
    }
    if at >= expiry {
        return Err(ApiError::new(StatusCode::GONE, "aumlok:claim-expired"));
    }
    if tx
        .execute(
            "UPDATE supervisor_claim SET spent=1 WHERE digest=?1 AND spent=0",
            [digest],
        )
        .map_err(|_| storage())?
        != 1
    {
        return Err(refusal("aumlok:claim-spent"));
    }
    Ok(())
}
fn assertion(value: &Value) -> Result<webauthn::AssertionMaterial, ApiError> {
    let mut value = value.clone();
    if value.get("user_handle").is_none() {
        value["user_handle"] = Value::Null;
    }
    serde_json::from_value(value).map_err(|_| refusal("aumlok:assertion-refused"))
}
fn assertion_options(rp: &str, credential: &webauthn::Credential, challenge: &str) -> Value {
    json!({"challenge":challenge,"rpId":rp,"allowCredentials":[{"type":"public-key","id":credential.credential_id}],"userVerification":"required","timeout":60000})
}
fn append(
    tx: &Transaction<'_>,
    signer: &SigningKey,
    at: i64,
    kind: &str,
    op: &str,
    body: Value,
) -> Result<(), ApiError> {
    append_phase(tx, signer, at, kind, op, "terminal", body)
}
#[allow(clippy::too_many_arguments)]
fn append_phase(
    tx: &Transaction<'_>,
    signer: &SigningKey,
    at: i64,
    kind: &str,
    op: &str,
    phase: &str,
    body: Value,
) -> Result<(), ApiError> {
    let body = canon::parse(&canonical(&body)?).map_err(|_| storage())?;
    aura::append(
        &aura::WriteLocked::new(tx).map_err(|_| storage())?,
        signer,
        &signer.verifying_key(),
        &aura::NewEntry {
            at,
            kind: kind.into(),
            actor: "owner".into(),
            op: op.into(),
            phase: phase.into(),
            body,
        },
    )
    .map_err(|_| storage())?;
    Ok(())
}

fn refresh_session(connection: &Connection, principal: &str, at: i64) -> Result<(), ApiError> {
    let digest = principal
        .strip_prefix("session:")
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "frontdoor:session-required"))?;
    let valid: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM supervisor_session WHERE digest=?1 AND revoked=0 AND expires_at>?2)", params![digest, at], |r| r.get(0)).map_err(|_| storage())?;
    if !valid {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "frontdoor:session-required",
        ));
    }
    Ok(())
}
fn prune_refresh_approvals(tx: &Transaction<'_>, at: i64) -> Result<(), ApiError> {
    tx.execute("UPDATE supervisor_refresh_approval SET state='spent' WHERE state='live' AND (expires_at<=?1 OR rowid NOT IN (SELECT max(rowid) FROM supervisor_refresh_approval WHERE state='live' AND expires_at>?1 GROUP BY principal))", [at]).map_err(|_| storage())?;
    tx.execute(
        "DELETE FROM supervisor_refresh_approval WHERE state='spent'",
        [],
    )
    .map_err(|_| storage())?;
    Ok(())
}
fn logout_authorization(
    node: &str,
    subject: &str,
    id: &str,
    nonce: &str,
    expires: i64,
) -> Result<(Value, Value), ApiError> {
    let target = "aumlok/session/revoke-all";
    let card = json!({"v":1,"risk":"critical","says":"Sign out everywhere and cancel every unfinished phrase replacement","facts":[["subject",subject],["sessions","every owner session, including this one"]],"from_to":{},"model_note":""});
    let new = gate::sha256(&canonical(
        &json!({"v":1,"action":"signout-everywhere","subject":subject}),
    )?);
    let content = json!({"v":1,"node":node,"target":target,"base_sha256":"absent","new_sha256":new,"cell":null});
    let mut operation = b"aukora:operation-content:v1\0".to_vec();
    operation.extend(canonical(&content)?);
    Ok((
        json!({"v":1,"node":node,"subject":subject,"op":"permission","proposal":id,"target":target,"base_sha256":"absent","new_sha256":new,"cell":null,"display_sha256":gate::sha256(&canonical(&card)?),"challenge":nonce,"expires_at":expires,"epoch":1,"operation":gate::sha256(&operation)}),
        card,
    ))
}
fn refresh_authorization(
    node: &str,
    binding: &aumlok::binding::BindingRecord,
    id: &str,
    nonce: &str,
    expires: i64,
) -> Result<(Value, Value), ApiError> {
    let old = refresh::envelope_sha256(&binding.envelope);
    let card = json!({"v":1,"risk":"critical","says":"Replace the current binding phrase","facts":[["subject",binding.subject],["current envelope",old]],"from_to":{},"model_note":""});
    let new = gate::sha256(&canonical(
        &json!({"v":1,"action":"refresh","subject":binding.subject,"envelope_sha256":old}),
    )?);
    let content = json!({"v":1,"node":node,"target":"aumlok/binding/refresh","base_sha256":old,"new_sha256":new,"cell":null});
    let mut operation = b"aukora:operation-content:v1\0".to_vec();
    operation.extend(canonical(&content)?);
    Ok((
        json!({"v":1,"node":node,"subject":binding.subject,"op":"permission","proposal":id,"target":"aumlok/binding/refresh","base_sha256":old,"new_sha256":new,"cell":null,"display_sha256":gate::sha256(&canonical(&card)?),"challenge":nonce,"expires_at":expires,"epoch":1,"operation":gate::sha256(&operation)}),
        card,
    ))
}
fn verify_refresh_assertion(
    connection: &Connection,
    rp: &str,
    origin: &str,
    auth: &[u8],
    material: &Value,
) -> Result<webauthn::VerifiedAssertion, ApiError> {
    let credential = credential(connection)?.ok_or_else(|| refusal("aumlok:enrolment-required"))?;
    let challenge = webauthn::owner_authorization_challenge(auth).map_err(|_| storage())?;
    let config = webauthn::Config {
        rp_id: rp.into(),
        origin: origin.into(),
        credential: credential.clone(),
    };
    webauthn::verify_assertion(
        &assertion(material)?,
        &config,
        &credential.owner_id,
        &challenge,
        None,
    )
    .map_err(|_| refusal("aumlok:assertion-refused"))
}
#[allow(clippy::too_many_arguments)]
fn spend_refresh_assertion(
    tx: &Transaction<'_>,
    principal: &str,
    id: &str,
    at: i64,
    rp: &str,
    origin: &str,
    auth: &[u8],
    material: &Value,
) -> Result<(), ApiError> {
    refresh_session(tx, principal, at)?;
    let verified = verify_refresh_assertion(tx, rp, origin, auth, material)?;
    if tx.execute("UPDATE supervisor_refresh_approval SET state='spent' WHERE id=?1 AND principal=?2 AND state='live' AND expires_at>?3", params![id, principal, at]).map_err(|_| storage())? != 1 { return Err(refusal("aumlok:refresh-proof-spent")); }
    persist_assertion_counter(tx, &verified)
}
fn persist_assertion_counter(
    tx: &Transaction<'_>,
    verified: &webauthn::VerifiedAssertion,
) -> Result<(), ApiError> {
    tx.execute(
        "UPDATE supervisor_owner SET counter=?1 WHERE id=1",
        [verified.sign_count],
    )
    .map_err(|_| storage())?;
    let gate_exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='gate_owner')",
            [],
            |r| r.get(0),
        )
        .map_err(|_| storage())?;
    if gate_exists {
        tx.execute("UPDATE gate_owner SET sign_count=max(sign_count,?1) WHERE singleton=1 AND credential_id=?2", params![verified.sign_count,gate::sha256(verified.credential_id.as_bytes())]).map_err(|_| storage())?;
    }
    Ok(())
}
fn refresh_words(preparation: RefreshPreparation) -> Value {
    json!({"ceremony_id":preparation.ceremony_id,"words":preparation.phrase.as_str().split(' ').collect::<Vec<_>>(),"entropy_bits":preparation.entropy_bits.floor() as u64,"expires_at":preparation.expires_at})
}
fn refresh_live(ceremony: refresh::LiveRefresh) -> Value {
    json!({"ceremony_id":ceremony.ceremony_id,"state":"live","expires_at":ceremony.expires_at})
}
fn refresh_committed(subject: String) -> Value {
    json!({"ok":true,"state":"committed","subject":subject})
}
fn refresh_error(error: RefreshError) -> ApiError {
    if let Some(position) = error.position() {
        return ApiError::with_position(
            StatusCode::UNPROCESSABLE_ENTITY,
            error.code(),
            position as u8,
        );
    }
    let status = match error.code() {
        "frontdoor:session-required" => StatusCode::UNAUTHORIZED,
        "aumlok:phrase-rate-limited" => StatusCode::TOO_MANY_REQUESTS,
        "aumlok:ceremony-expired" => StatusCode::GONE,
        "aumlok:refresh-storage" | "aumlok:storage" => StatusCode::SERVICE_UNAVAILABLE,
        _ => refusal(error.code()).status,
    };
    ApiError::new(status, error.code())
}
fn canonical(value: &Value) -> Result<Vec<u8>, ApiError> {
    canon::parse(value.to_string().as_bytes())
        .and_then(|v| canon::canonical_json(&v))
        .map_err(|_| storage())
}
pub(crate) fn stored_wrap_key(signer: &SigningKey) -> Zeroizing<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"aukora:supervisor-root-wrap:v1\0");
    digest.update(signer.to_bytes());
    Zeroizing::new(digest.finalize().into())
}
pub(crate) fn encrypt(key: &[u8; 32], plain: &[u8], purpose: &[u8]) -> Result<Vec<u8>, ApiError> {
    let nonce = random::<24>()?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut result = nonce.to_vec();
    result.extend(
        cipher
            .encrypt(
                &XNonce::from(nonce),
                chacha20poly1305::aead::Payload {
                    msg: plain,
                    aad: purpose,
                },
            )
            .map_err(|_| storage())?,
    );
    Ok(result)
}
pub(crate) fn decrypt(
    key: &[u8; 32],
    bytes: &[u8],
    purpose: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    if bytes.len() < 40 {
        return Err(storage());
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &XNonce::from(<[u8; 24]>::try_from(&bytes[..24]).map_err(|_| storage())?),
            chacha20poly1305::aead::Payload {
                msg: &bytes[24..],
                aad: purpose,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| storage())
}
fn random<const N: usize>() -> Result<[u8; N], ApiError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "aumlok:random-unavailable"))?;
    Ok(bytes)
}
fn text<'a>(body: &'a Value, key: &str) -> Result<&'a str, ApiError> {
    body.get(key)
        .and_then(Value::as_str)
        .ok_or_else(ApiError::invalid_body)
}
fn now() -> Result<i64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .ok_or_else(storage)
}
fn storage() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "aumlok:storage")
}
fn refusal(code: &'static str) -> ApiError {
    let status = if matches!(
        code,
        "aumlok:claim-unknown"
            | "aumlok:claim-spent"
            | "aumlok:ceremony-unknown"
            | "aumlok:binding-required"
            | "aumlok:enrolment-required"
            | "aumlok:registration-required"
    ) {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    ApiError::new(status, code)
}
fn conflict(code: &'static str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    const NODE: &str = "00000000000000000000000000000001";
    const RP: &str = "owner-test.example";
    const PRINCIPAL: &str = "owner:00000000000000000000000000000001";
    const CREDENTIAL: &[u8] = b"owner-credential";

    fn open(path: &std::path::Path) -> Owner {
        Owner::open(
            Connection::open(path).unwrap(),
            NODE.into(),
            RP.into(),
            format!("https://{RP}"),
            Arc::new(SigningKey::from_bytes(&[7; 32])),
        )
        .unwrap()
    }
    fn bytes_cbor(bytes: &[u8]) -> Vec<u8> {
        let mut encoded = if bytes.len() < 24 {
            vec![0x40 + bytes.len() as u8]
        } else if bytes.len() < 256 {
            vec![0x58, bytes.len() as u8]
        } else {
            vec![0x59, (bytes.len() >> 8) as u8, bytes.len() as u8]
        };
        encoded.extend(bytes);
        encoded
    }
    pub(crate) fn registration(challenge: &str) -> Value {
        registration_prf(challenge, false)
    }
    fn registration_prf(challenge: &str, enabled: bool) -> Value {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
        cose.extend(bytes_cbor(key.verifying_key().as_bytes()));
        let mut auth = Sha256::digest(RP).to_vec();
        auth.push(if enabled { 0xc5 } else { 0x45 });
        auth.extend(0_u32.to_be_bytes());
        auth.extend([0; 16]);
        auth.extend((CREDENTIAL.len() as u16).to_be_bytes());
        auth.extend(CREDENTIAL);
        auth.extend(cose);
        if enabled {
            auth.extend(b"\xa1\x6bhmac-secret\xf5");
        }
        let mut attestation = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData".to_vec();
        attestation.extend(bytes_cbor(&auth));
        json!({"kind":"passkey-registration","id":URL_SAFE_NO_PAD.encode(CREDENTIAL),"raw_id":URL_SAFE_NO_PAD.encode(CREDENTIAL),"client_data_json":URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.create","challenge":challenge,"origin":format!("https://{RP}"),"crossOrigin":false}).to_string()),"attestation_object":URL_SAFE_NO_PAD.encode(attestation),"client_extension_results":if enabled {json!({"prf":{"enabled":true}})}else{json!({})}})
    }
    pub(crate) fn assertion(challenge: &str, count: u32) -> Value {
        assertion_extensions(challenge, count, &[])
    }
    fn assertion_extensions(challenge: &str, count: u32, extensions: &[u8]) -> Value {
        let client=json!({"type":"webauthn.get","challenge":challenge,"origin":format!("https://{RP}"),"crossOrigin":false}).to_string();
        let mut auth = Sha256::digest(RP).to_vec();
        auth.push(if extensions.is_empty() { 5 } else { 0x85 });
        auth.extend(count.to_be_bytes());
        auth.extend(extensions);
        let signed = [
            auth.as_slice(),
            Sha256::digest(client.as_bytes()).as_slice(),
        ]
        .concat();
        let signature = SigningKey::from_bytes(&[9; 32]).sign(&signed);
        json!({"kind":"passkey","credential_id":URL_SAFE_NO_PAD.encode(CREDENTIAL),"client_data_json":URL_SAFE_NO_PAD.encode(client),"authenticator_data":URL_SAFE_NO_PAD.encode(auth),"signature":URL_SAFE_NO_PAD.encode(signature.to_bytes()),"user_handle":URL_SAFE_NO_PAD.encode(NODE.as_bytes())})
    }
    fn enrol(owner: &mut Owner) {
        let start = owner
            .call(PRINCIPAL, Operation::EnrolStart, json!({}))
            .unwrap();
        let staged=owner.call(PRINCIPAL,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],"attestation":registration(start["public_key"]["challenge"].as_str().unwrap())})).unwrap();
        owner.call(PRINCIPAL,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],"assertion":assertion(staged["public_key"]["challenge"].as_str().unwrap(),1)})).unwrap();
    }

    #[test]
    fn antibody_signin_session_lifetime_matches_claim_limits_without_spending() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let mut owner = open(&directory.path().join("signin-session.sqlite"));
        enrol(&mut owner);
        let start = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        let proof = assertion(start["public_key"]["challenge"].as_str().unwrap(), 2);
        let body = json!({"ceremony_id":start["ceremony_id"],"assertion":proof});
        for expires_at in [-1, now().unwrap() + 87_400_000] {
            assert_eq!(
                owner
                    .signin_session(body.clone(), [72; 32], expires_at)
                    .unwrap_err()
                    .code,
                "aumlok:storage"
            );
            assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
            assert_eq!(
                owner
                    .binding
                    .connection()
                    .query_row("SELECT count(*) FROM supervisor_session", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        let expires_at = now().unwrap() + 60_000;
        assert_eq!(
            owner.signin_session(body, [72; 32], expires_at).unwrap()["ok"],
            true
        );
        assert!(owner.session_valid([72; 32], expires_at - 1).unwrap());
        assert!(!owner.session_valid([72; 32], expires_at).unwrap());
    }

    fn chat_parent(owner: &Owner, digest: [u8; 32], expires_at: i64, revoked: bool) {
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_session(digest,expires_at,revoked) VALUES(?1,?2,?3)",
                params![digest, expires_at, revoked],
            )
            .unwrap();
    }

    #[test]
    fn antibody_chat_sessions_reopen_with_only_linked_digests() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("chat.sqlite");
        let mut owner = open(&path);
        let owner_token = "disposable-owner-token-5467656573f5fc058e0d7796867150c758ed27";
        let chat_token = "disposable-chat-token-d2fed1a839bc2fdf905c35a958a1a091c695fed";
        let parent: [u8; 32] = Sha256::digest(owner_token).into();
        let session: [u8; 32] = Sha256::digest(chat_token).into();
        let at = now().unwrap();
        chat_parent(&owner, parent, at + 60_000, false);
        owner
            .create_chat_session(parent, session, at + 60_000)
            .unwrap();
        assert!(owner.chat_session_valid(session, at).unwrap());
        drop(owner);
        let owner = open(&path);
        assert!(owner.chat_session_valid(session, at).unwrap());
        let stored: (Vec<u8>, Vec<u8>) = owner
            .binding
            .connection()
            .query_row(
                "SELECT digest,owner_digest FROM supervisor_chat_session",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, (session.to_vec(), parent.to_vec()));
        let mut columns = owner
            .binding
            .connection()
            .prepare("PRAGMA table_info(supervisor_chat_session)")
            .unwrap();
        let names = columns
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(names, ["digest", "owner_digest", "expires_at", "revoked"]);
        let stored = std::fs::read(&path).unwrap();
        for token in [owner_token, chat_token] {
            assert!(!stored
                .windows(token.len())
                .any(|bytes| bytes == token.as_bytes()));
        }
    }

    #[test]
    fn antibody_chat_session_expiry_and_lifetime_are_pinned() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("chat.sqlite");
        let mut owner = open(&path);
        let at = now().unwrap();
        let expiry = at + 60_000;
        chat_parent(&owner, [80; 32], expiry, false);
        for expires_at in [-1, i64::MAX] {
            assert_eq!(
                owner
                    .create_chat_session([80; 32], [81; 32], expires_at)
                    .unwrap_err()
                    .code,
                "aumlok:storage"
            );
        }
        owner
            .create_chat_session([80; 32], [81; 32], at + 120_000)
            .unwrap();
        owner
            .create_chat_session([80; 32], [82; 32], at + 30_000)
            .unwrap();
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT expires_at FROM supervisor_chat_session WHERE digest=?1",
                    [[81_u8; 32]],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            expiry
        );
        assert!(owner.chat_session_valid([81; 32], expiry - 1).unwrap());
        assert!(!owner.chat_session_valid([81; 32], expiry).unwrap());
        assert!(owner.chat_session_valid([82; 32], at + 29_999).unwrap());
        assert!(!owner.chat_session_valid([82; 32], at + 30_000).unwrap());
        drop(owner);
        let owner = open(&path);
        assert!(!owner.chat_session_valid([81; 32], expiry).unwrap());
        assert!(!owner.chat_session_valid([82; 32], at + 30_000).unwrap());
    }

    #[test]
    fn antibody_chat_session_revoke_survives_reopen_and_cannot_rewind() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("chat.sqlite");
        let mut owner = open(&path);
        let at = now().unwrap();
        chat_parent(&owner, [80; 32], at + 60_000, false);
        owner
            .create_chat_session([80; 32], [81; 32], at + 60_000)
            .unwrap();
        for sql in [
            "UPDATE supervisor_chat_session SET digest=randomblob(32)",
            "UPDATE supervisor_chat_session SET owner_digest=randomblob(32)",
            "UPDATE supervisor_chat_session SET expires_at=expires_at+1",
        ] {
            assert!(
                owner.binding.connection().execute(sql, []).is_err(),
                "{sql}"
            );
        }
        owner.revoke_chat_session([81; 32]).unwrap();
        assert!(!owner.chat_session_valid([81; 32], at).unwrap());
        assert!(owner
            .binding
            .connection()
            .execute("UPDATE supervisor_chat_session SET revoked=0", [])
            .is_err());
        drop(owner);
        let owner = open(&path);
        assert!(!owner.chat_session_valid([81; 32], at).unwrap());
    }

    #[test]
    fn antibody_chat_session_parent_is_live_at_create_and_every_validation() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("chat.sqlite");
        let mut owner = open(&path);
        let at = now().unwrap();
        chat_parent(&owner, [80; 32], at + 60_000, false);
        chat_parent(&owner, [82; 32], at, false);
        chat_parent(&owner, [83; 32], at + 60_000, true);
        for parent in [[82; 32], [83; 32], [84; 32]] {
            assert_eq!(
                owner
                    .create_chat_session(parent, [81; 32], at + 60_000)
                    .unwrap_err()
                    .code,
                "frontdoor:session-required"
            );
        }
        owner
            .create_chat_session([80; 32], [81; 32], at + 60_000)
            .unwrap();
        owner.binding.connection().execute(
            "INSERT INTO supervisor_chat_session(digest,owner_digest,expires_at) VALUES(?1,?2,?3)",
            params![[85_u8; 32], [82_u8; 32], at + 60_000],
        ).unwrap();
        assert!(!owner.chat_session_valid([85; 32], at).unwrap());
        owner.revoke_session([80; 32]).unwrap();
        assert!(!owner.chat_session_valid([81; 32], at).unwrap());
        drop(owner);
        let owner = open(&path);
        assert!(!owner.chat_session_valid([81; 32], at).unwrap());
    }

    #[test]
    fn antibody_chat_sessions_are_bounded_and_prune_inactive_rows() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let mut owner = open(&directory.path().join("chat.sqlite"));
        let at = now().unwrap();
        chat_parent(&owner, [80; 32], at + 60_000, false);
        owner.binding.connection().execute(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO supervisor_chat_session(digest,owner_digest,expires_at) SELECT randomblob(32),?2,?3 FROM n",
            params![CHAT_SESSION_LIMIT, [80_u8; 32], at + 60_000],
        ).unwrap();
        let refusal = owner
            .create_chat_session([80; 32], [81; 32], at + 60_000)
            .unwrap_err();
        assert_eq!(refusal.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(refusal.code, "frontdoor:chat-session-limit");
        owner
            .binding
            .connection()
            .execute("UPDATE supervisor_chat_session SET revoked=1", [])
            .unwrap();
        owner
            .create_chat_session([80; 32], [81; 32], at + 60_000)
            .unwrap();
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row("SELECT count(*) FROM supervisor_chat_session", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
    }
    pub(crate) fn prepare_fast(owner: &mut Owner) -> Value {
        let phrase = Phrase::draw().unwrap();
        let sealed = envelope::seal(
            &phrase,
            envelope::KdfParams {
                memory_kib: 8,
                time_cost: 1,
                parallelism: 1,
            },
        )
        .unwrap();
        let id = hex::encode(random::<16>().unwrap());
        let expires = now().unwrap() + CEREMONY_MS;
        let words = phrase.as_str().split_whitespace().collect::<Vec<_>>();
        let plain=serde_json::to_vec(&json!({"words":words,"root":hex::encode(*sealed.root),"envelope":sealed.envelope.to_canonical_json()})).unwrap();
        owner.binding.connection().execute("INSERT INTO supervisor_ceremony(id,kind,principal,challenge,expires_at,state,prepared) VALUES(?1,'binding',?2,'',?3,'live',?4)",params![id,PRINCIPAL,expires,encrypt(&owner.wrap_key,&plain,b"binding").unwrap()]).unwrap();
        json!({"ceremony_id":id,"words":words})
    }

    #[test]
    fn claims_sessions_restart_replay_expiry_and_sql_rewind_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.db");
        let mut owner = open(&path);
        let token = owner.create_claim().unwrap();
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let session = [4; 32];
        let at = now().unwrap();
        assert_eq!(
            owner.consume_claim([0; 32]).unwrap_err().code,
            "aumlok:claim-unknown"
        );
        owner
            .consume_claim_session(digest, session, at + 60000)
            .unwrap();
        assert!(owner.session_valid(session, at).unwrap());
        assert!(!owner.session_valid(session, at + 60000).unwrap());
        assert_eq!(
            owner.consume_claim(digest).unwrap_err().code,
            "aumlok:claim-spent"
        );
        assert!(owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_claim SET spent=0 WHERE digest=?1",
                [digest]
            )
            .is_err());
        drop(owner);
        let mut owner = open(&path);
        assert!(owner.session_valid(session, at).unwrap());
        assert_eq!(
            owner.consume_claim(digest).unwrap_err().code,
            "aumlok:claim-spent"
        );
        owner.revoke_session(session).unwrap();
        assert!(!owner.session_valid(session, at).unwrap());
        assert!(owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_session SET revoked=0 WHERE digest=?1",
                [session]
            )
            .is_err());
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_claim(digest,expires_at) VALUES(?1,?2)",
                params![[5u8; 32], at - 1],
            )
            .unwrap();
        assert_eq!(
            owner.consume_claim([5; 32]).unwrap_err().code,
            "aumlok:claim-expired"
        );
    }

    #[test]
    fn registration_needs_possession_and_resumes_without_second_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.db");
        let mut owner = open(&path);
        let start = owner
            .call(PRINCIPAL, Operation::EnrolStart, json!({}))
            .unwrap();
        let staged=owner.call(PRINCIPAL,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],"attestation":registration(start["public_key"]["challenge"].as_str().unwrap())})).unwrap();
        assert_eq!(staged["state"], "possession-required");
        assert!(owner.credential().unwrap().is_none());
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::BindingPrepare, json!({}))
                .unwrap_err()
                .code,
            "aumlok:enrolment-required"
        );
        assert_eq!(owner.call(PRINCIPAL,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),1)})).unwrap_err().code,"aumlok:assertion-refused");
        drop(owner);
        let mut owner = open(&path);
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::EnrolStart, json!({}))
                .unwrap(),
            staged
        );
        assert!(owner.call("foreign",Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],"assertion":assertion(staged["public_key"]["challenge"].as_str().unwrap(),1)})).is_err());
        owner.call(PRINCIPAL,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],"assertion":assertion(staged["public_key"]["challenge"].as_str().unwrap(),1)})).unwrap();
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::EnrolStart, json!({}))
                .unwrap_err()
                .code,
            "aumlok:enrolment-closed"
        );
        assert!(owner
            .binding
            .connection()
            .execute("UPDATE supervisor_owner SET credential=NULL", [])
            .is_err());
        let entries = aura::read_entries(owner.binding.connection()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "aumlok.enrol");
        aura::walk(&entries, &owner.signer.verifying_key(), None).unwrap();
    }

    #[test]
    fn binding_words_cancel_root_wrapping_and_terminal_rows_hold() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.db");
        let mut owner = open(&path);
        enrol(&mut owner);
        let prepared = prepare_fast(&mut owner);
        let resumed = owner
            .call(PRINCIPAL, Operation::BindingPrepare, json!({}))
            .unwrap();
        assert_eq!(prepared["words"], resumed["words"]);
        let mut bad = prepared.clone();
        bad["words"][3] = json!("wrong");
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::BindingConfirm, bad)
                .unwrap_err()
                .position,
            Some(4)
        );
        assert!(owner.root().unwrap().is_none());
        assert!(owner
            .call(
                "foreign",
                Operation::BindingCancel,
                json!({"ceremony_id":prepared["ceremony_id"]})
            )
            .is_err());
        owner
            .call(
                PRINCIPAL,
                Operation::BindingCancel,
                json!({"ceremony_id":prepared["ceremony_id"]}),
            )
            .unwrap();
        assert!(owner
            .call(PRINCIPAL, Operation::BindingConfirm, prepared)
            .is_err());
        let prepared = prepare_fast(&mut owner);
        owner
            .call(PRINCIPAL, Operation::BindingConfirm, prepared)
            .unwrap();
        let root = owner.root().unwrap().unwrap();
        let envelope = owner
            .call(PRINCIPAL, Operation::BindingEnvelope, json!({}))
            .unwrap();
        let envelope = envelope::Envelope::from_canonical_json(
            std::str::from_utf8(&canonical(&envelope).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(envelope.version(), 1);
        let stored: Vec<u8> = owner
            .binding
            .connection()
            .query_row("SELECT root FROM supervisor_owner", [], |r| r.get(0))
            .unwrap();
        assert_ne!(stored.as_slice(), root.as_slice());
        assert!(decrypt(&owner.wrap_key, &stored, b"binding").is_err());
        assert!(decrypt(&[8; 32], &stored, b"root").is_err());
        let mut edited = stored.clone();
        edited[30] ^= 1;
        assert!(decrypt(&owner.wrap_key, &edited, b"root").is_err());
        assert!(owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_owner SET subject=NULL,root=NULL,envelope=NULL",
                []
            )
            .is_err());
        drop(owner);
        let owner = open(&path);
        assert_eq!(*owner.root().unwrap().unwrap(), *root);
        assert!(owner.state().unwrap().state.is_bound());
        let entries = aura::read_entries(owner.binding.connection()).unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.kind == "aumlok.bind" && e.phase == "terminal")
                .count(),
            1
        );
        aura::walk(&entries, &owner.signer.verifying_key(), None).unwrap();
    }

    #[test]
    fn antibody_signin_10000_starts_are_bounded_and_owner_finishes_during_flood() {
        // Invalid proofs and replay expect aumlok:assertion-refused / aumlok:ceremony-unknown.
        let directory = tempfile::tempdir().unwrap();
        let mut owner = open(&directory.path().join("node.db"));
        enrol(&mut owner);
        let mut owner_start = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        let mut finished = None;
        for index in 0..10_000 {
            let stranger_start = owner
                .call("stranger", Operation::SigninStart, json!({}))
                .unwrap();
            let live: i64 = owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM supervisor_ceremony WHERE kind='signin'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(live, 1, "start {index} grew ceremony storage");
            assert_eq!(
                stranger_start, owner_start,
                "start {index} evicted the owner"
            );
            if index == 4_999 {
                let challenge = owner_start["public_key"]["challenge"].as_str().unwrap();
                assert_eq!(owner.call(PRINCIPAL, Operation::SigninFinish,
                    json!({"ceremony_id":owner_start["ceremony_id"],"assertion":assertion("wrong",2)})
                ).unwrap_err().code, "aumlok:assertion-refused");
                let finish = json!({"ceremony_id":owner_start["ceremony_id"],"assertion":assertion(challenge,2)});
                owner
                    .call(PRINCIPAL, Operation::SigninFinish, finish.clone())
                    .unwrap();
                finished = Some(finish);
                owner_start = owner
                    .call(PRINCIPAL, Operation::SigninStart, json!({}))
                    .unwrap();
            }
        }
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::SigninFinish, finished.unwrap())
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        owner.call(PRINCIPAL, Operation::SigninFinish,
            json!({"ceremony_id":owner_start["ceremony_id"],"assertion":assertion(owner_start["public_key"]["challenge"].as_str().unwrap(),3)})
        ).unwrap();
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 3);
    }

    #[test]
    fn antibody_signin_never_shares_a_challenge_about_to_expire() {
        // Independent review: a stranger starting sign-in at each expiry could hand the owner
        // a shared challenge with seconds left. It is shared only with a whole timeout left.
        let directory = tempfile::tempdir().unwrap();
        let mut owner = open(&directory.path().join("node.db"));
        enrol(&mut owner);
        let at = now().unwrap();
        let first = owner.signin_start_at(at).unwrap();
        let shared = owner.signin_start_at(at + 1_000).unwrap();
        assert_eq!(first["ceremony_id"], shared["ceremony_id"]);
        let late = owner
            .signin_start_at(at + CEREMONY_MS - SIGNIN_SHARE_MIN_MS + 1)
            .unwrap();
        assert_ne!(first["ceremony_id"], late["ceremony_id"]);
        let live: i64 = owner
            .binding
            .connection()
            .query_row(
                "SELECT count(*) FROM supervisor_ceremony WHERE kind='signin' AND state='live'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(live <= 2, "{live}");
    }

    #[test]
    fn antibody_signin_expired_and_spent_rows_are_pruned_without_reviving_replay() {
        // Before pruning: aumlok:ceremony-expired; after pruning: aumlok:ceremony-unknown.
        let directory = tempfile::tempdir().unwrap();
        let mut owner = open(&directory.path().join("node.db"));
        enrol(&mut owner);
        let at = now().unwrap();
        let expired = owner.signin_start_at(at - CEREMONY_MS).unwrap();
        let expired_finish = json!({"ceremony_id":expired["ceremony_id"],"assertion":assertion(expired["public_key"]["challenge"].as_str().unwrap(),2)});
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::SigninFinish, expired_finish.clone())
                .unwrap_err()
                .code,
            "aumlok:ceremony-expired"
        );
        let start = owner.signin_start_at(at).unwrap();
        let stored: i64 = owner
            .binding
            .connection()
            .query_row(
                "SELECT count(*) FROM supervisor_ceremony WHERE kind='signin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, 1);
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::SigninFinish, expired_finish)
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        let finish = json!({"ceremony_id":start["ceremony_id"],"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)});
        owner
            .call(PRINCIPAL, Operation::SigninFinish, finish.clone())
            .unwrap();
        owner.signin_start_at(at).unwrap();
        let stored: i64 = owner
            .binding
            .connection()
            .query_row(
                "SELECT count(*) FROM supervisor_ceremony WHERE kind='signin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, 1);
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::SigninFinish, finish)
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        assert!(owner
            .binding
            .connection()
            .execute("DELETE FROM supervisor_ceremony WHERE kind='enrol'", [])
            .is_err());
    }

    #[test]
    fn antibody_signin_restart_prunes_legacy_rows_and_preserves_latest_live_challenge() {
        // Removed ceremonies must refuse with aumlok:ceremony-unknown.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.db");
        let mut owner = open(&path);
        enrol(&mut owner);
        let at = now().unwrap();
        for index in 0_u128..20 {
            owner.binding.connection().execute(
                "INSERT INTO supervisor_ceremony(id,kind,principal,challenge,expires_at,state) VALUES(?1,'signin',?2,?3,?4,?5)",
                params![format!("{index:032x}"), PRINCIPAL, URL_SAFE_NO_PAD.encode([2;32]),
                    if index == 0 {at - 1} else {at + CEREMONY_MS}, if index == 1 {"spent"} else {"live"}],
            ).unwrap();
        }
        // Simulate the old unconditional retention trigger before migration.
        owner
            .binding
            .connection()
            .execute_batch(
                "DROP TRIGGER supervisor_ceremony_retained;
            CREATE TRIGGER supervisor_ceremony_retained BEFORE DELETE ON supervisor_ceremony
            BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-retained'); END;",
            )
            .unwrap();
        drop(owner);
        let mut owner = open(&path);
        let stored: i64 = owner
            .binding
            .connection()
            .query_row(
                "SELECT count(*) FROM supervisor_ceremony WHERE kind='signin'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, 1);
        let start = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        assert_eq!(start["ceremony_id"], format!("{:032x}", 19));
        assert_eq!(owner.call(PRINCIPAL, Operation::SigninFinish,
            json!({"ceremony_id":format!("{:032x}",0),"assertion":assertion(&URL_SAFE_NO_PAD.encode([2;32]),2)})
        ).unwrap_err().code, "aumlok:ceremony-unknown");
        owner.call(PRINCIPAL, Operation::SigninFinish,
            json!({"ceremony_id":start["ceremony_id"],"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)})
        ).unwrap();
    }

    #[test]
    fn signin_challenge_replay_counter_and_aura_transaction_hold() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.db");
        let mut owner = open(&path);
        enrol(&mut owner);
        owner.binding.connection().execute_batch("CREATE TABLE gate_owner(singleton INTEGER PRIMARY KEY,sign_count INTEGER NOT NULL,credential_id TEXT NOT NULL)").unwrap();
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO gate_owner VALUES(1,1,?1)",
                [gate::sha256(URL_SAFE_NO_PAD.encode(CREDENTIAL).as_bytes())],
            )
            .unwrap();
        let start = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        let challenge = start["public_key"]["challenge"].as_str().unwrap();
        assert_eq!(
            owner
                .call(
                    PRINCIPAL,
                    Operation::SigninFinish,
                    json!({"ceremony_id":start["ceremony_id"],"assertion":assertion("wrong",2)})
                )
                .unwrap_err()
                .code,
            "aumlok:assertion-refused"
        );
        assert!(owner
            .call(
                PRINCIPAL,
                Operation::SigninFinish,
                json!({"ceremony_id":start["ceremony_id"],"assertion":assertion(challenge,0)})
            )
            .is_err());
        let finish = json!({"ceremony_id":start["ceremony_id"],"assertion":assertion(challenge,2)});
        owner
            .call(PRINCIPAL, Operation::SigninFinish, finish.clone())
            .unwrap();
        assert!(owner
            .call(PRINCIPAL, Operation::SigninFinish, finish)
            .is_err());
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 2);
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT sign_count FROM gate_owner WHERE singleton=1",
                    [],
                    |r| r.get::<_, u32>(0)
                )
                .unwrap(),
            2
        );
        owner
            .binding
            .connection()
            .execute("UPDATE gate_owner SET sign_count=3 WHERE singleton=1", [])
            .unwrap();
        let next = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        assert!(owner.call(PRINCIPAL,Operation::SigninFinish,json!({"ceremony_id":next["ceremony_id"],"assertion":assertion(next["public_key"]["challenge"].as_str().unwrap(),3)})).is_err());

        assert!(owner
            .binding
            .connection()
            .execute("UPDATE supervisor_owner SET counter=1", [])
            .is_err());
        let entries = aura::read_entries(owner.binding.connection()).unwrap();
        assert_eq!(
            entries.iter().filter(|e| e.kind == "aumlok.signin").count(),
            1
        );
        aura::walk(&entries, &owner.signer.verifying_key(), None).unwrap();
    }
    #[test]
    fn signin_aura_failure_rolls_back_counter_and_ceremony() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.db");
        let mut owner = open(&path);
        enrol(&mut owner);
        let start = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        let id = start["ceremony_id"].as_str().unwrap();
        let tx = owner
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        append(
            &tx,
            &owner.signer,
            now().unwrap(),
            "aumlok.signin",
            id,
            json!({"test":"already-terminal"}),
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(owner.call(PRINCIPAL,Operation::SigninFinish,json!({"ceremony_id":id,"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)})).is_err());
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT state FROM supervisor_ceremony WHERE id=?1",
                    [id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "live"
        );
    }
    #[test]
    fn passkey_proof_verifies_raw_credential_and_reports_gate_fingerprint() {
        let credential = webauthn::Credential {
            owner_id: PRINCIPAL.into(),
            credential_id: URL_SAFE_NO_PAD.encode(CREDENTIAL),
            public_key: webauthn::PublicKey::Ed25519(
                *SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes(),
            ),
            user_handle: URL_SAFE_NO_PAD.encode(NODE.as_bytes()),
            sign_count: 0,
            backup_eligible: false,
        };
        let proof = PasskeyProof {
            rp: RP.into(),
            origin: format!("https://{RP}"),
            credential: Arc::new(Mutex::new(Some(credential.clone()))),
        };
        let auth = canonical(&json!({"v":1,"node":NODE,"operation":"disposable"})).unwrap();
        let challenge = webauthn::owner_authorization_challenge(&auth).unwrap();
        let material = assertion(&challenge, 4);
        let verified =
            gate::OwnerProof::verify(&proof, &auth, &serde_json::to_vec(&material).unwrap())
                .unwrap();
        assert_eq!(
            verified.credential_id,
            gate::sha256(credential.credential_id.as_bytes())
        );
        assert_eq!(verified.counter, 4);
        let mut wrong = material.clone();
        wrong["credential_id"] = json!(URL_SAFE_NO_PAD.encode(b"foreign"));
        assert!(
            gate::OwnerProof::verify(&proof, &auth, &serde_json::to_vec(&wrong).unwrap()).is_err()
        );
        assert!(gate::OwnerProof::verify(
            &proof,
            &canonical(&json!({"v":1,"node":NODE,"operation":"changed"})).unwrap(),
            &serde_json::to_vec(&material).unwrap()
        )
        .is_err());
    }

    #[test]
    fn antibody_passkey_proof_checks_current_counter() {
        let credential = webauthn::Credential {
            owner_id: PRINCIPAL.into(),
            credential_id: URL_SAFE_NO_PAD.encode(CREDENTIAL),
            public_key: webauthn::PublicKey::Ed25519(
                *SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes(),
            ),
            user_handle: URL_SAFE_NO_PAD.encode(NODE.as_bytes()),
            sign_count: 6,
            backup_eligible: false,
        };
        let proof = PasskeyProof {
            rp: RP.into(),
            origin: format!("https://{RP}"),
            credential: Arc::new(Mutex::new(Some(credential))),
        };
        let auth = canonical(&json!({"v":1,"node":NODE,"operation":"counter-check"})).unwrap();
        let challenge = webauthn::owner_authorization_challenge(&auth).unwrap();
        for count in [1, 0, 6] {
            // Expected refusal: aumlok:counter-replayed, even before the gate's transaction CAS.
            assert!(matches!(
                gate::OwnerProof::verify(
                    &proof,
                    &auth,
                    &serde_json::to_vec(&assertion(&challenge, count)).unwrap(),
                ),
                Err(gate::Error::Refused("aumlok:counter-replayed"))
            ));
        }
        assert_eq!(
            gate::OwnerProof::verify(
                &proof,
                &auth,
                &serde_json::to_vec(&assertion(&challenge, 7)).unwrap()
            )
            .unwrap()
            .counter,
            7
        );
    }

    #[test]
    fn antibody_owner_counter_ignores_foreign_credential() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let mut owner = open(&directory.path().join("node.db"));
        enrol(&mut owner);
        owner.binding.connection().execute_batch(
            "CREATE TABLE gate_owner(singleton INTEGER PRIMARY KEY,sign_count INTEGER NOT NULL,credential_id TEXT NOT NULL);
             INSERT INTO gate_owner VALUES(1,4294967295,'foreign-credential');",
        ).unwrap();
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
        let start = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        // A foreign credential's high-water mark must not cause aumlok:assertion-refused for the owner.
        owner.call(PRINCIPAL,Operation::SigninFinish,json!({"ceremony_id":start["ceremony_id"],"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)})).unwrap();
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 2);
    }

    #[test]
    fn antibody_owner_counter_writeback_checks_credential_and_high_water() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let mut owner = open(&directory.path().join("node.db"));
        enrol(&mut owner);
        let pinned = owner.credential().unwrap().unwrap();
        let proof = PasskeyProof {
            rp: RP.into(),
            origin: format!("https://{RP}"),
            credential: Arc::new(Mutex::new(Some(pinned.clone()))),
        };
        let tx = owner
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let foreign = gate::VerifiedProof {
            credential_id: "ff".repeat(32),
            counter: 2,
        };
        // Expected refusal: gate:credential-mismatch; another credential never advances the owner.
        assert!(matches!(
            gate::OwnerProof::persist_counter(&proof, &tx, &foreign),
            Err(gate::Error::Refused("gate:credential-mismatch"))
        ));
        for counter in [0, 1] {
            let stale = gate::VerifiedProof {
                credential_id: gate::sha256(pinned.credential_id.as_bytes()),
                counter,
            };
            // Expected refusal: gate:counter-replay; writeback cannot lower or repeat the mark.
            assert!(matches!(
                gate::OwnerProof::persist_counter(&proof, &tx, &stale),
                Err(gate::Error::Refused("gate:counter-replay"))
            ));
        }
        let next = gate::VerifiedProof {
            credential_id: gate::sha256(pinned.credential_id.as_bytes()),
            counter: 2,
        };
        gate::OwnerProof::persist_counter(&proof, &tx, &next).unwrap();
        tx.commit().unwrap();
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 2);
    }
    #[test]
    fn ceremony_expiry_context_and_counterless_single_use_hold() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("node.db");
        let mut owner = open(&path);
        let id = hex::encode([1; 16]);
        let challenge = URL_SAFE_NO_PAD.encode([2; 32]);
        owner.binding.connection().execute("INSERT INTO supervisor_ceremony(id,kind,principal,challenge,expires_at,state) VALUES(?1,'enrol',?2,?3,?4,'live')",params![id,PRINCIPAL,challenge,now().unwrap()-1]).unwrap();
        assert_eq!(
            owner
                .call(
                    PRINCIPAL,
                    Operation::EnrolFinish,
                    json!({"enrolment_id":id,"attestation":registration(&challenge)})
                )
                .unwrap_err()
                .code,
            "aumlok:ceremony-expired"
        );
        assert!(owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_ceremony SET challenge='changed' WHERE id=?1",
                [&id]
            )
            .is_err());
        assert!(owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_ceremony SET expires_at=expires_at+999999 WHERE id=?1",
                [&id]
            )
            .is_err());
        let start = owner
            .call(PRINCIPAL, Operation::EnrolStart, json!({}))
            .unwrap();
        let staged=owner.call(PRINCIPAL,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],"attestation":registration(start["public_key"]["challenge"].as_str().unwrap())})).unwrap();
        owner.call(PRINCIPAL,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],"assertion":assertion(staged["public_key"]["challenge"].as_str().unwrap(),0)})).unwrap();
        let signin = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        let finish = json!({"ceremony_id":signin["ceremony_id"],"assertion":assertion(signin["public_key"]["challenge"].as_str().unwrap(),0)});
        owner
            .call(PRINCIPAL, Operation::SigninFinish, finish.clone())
            .unwrap();
        assert_eq!(
            owner
                .call(PRINCIPAL, Operation::SigninFinish, finish)
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 0);
        let after = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        owner.call(PRINCIPAL,Operation::SigninFinish,json!({"ceremony_id":after["ceremony_id"],"assertion":assertion(after["public_key"]["challenge"].as_str().unwrap(),1)})).unwrap();
        let forbidden = owner
            .call(PRINCIPAL, Operation::SigninStart, json!({}))
            .unwrap();
        assert_eq!(owner.call(PRINCIPAL,Operation::SigninFinish,json!({"ceremony_id":forbidden["ceremony_id"],"assertion":assertion(forbidden["public_key"]["challenge"].as_str().unwrap(),0)})).unwrap_err().code,"aumlok:assertion-refused");
    }

    fn refresh_fixture() -> (tempfile::TempDir, Owner, String, String) {
        let directory = tempfile::tempdir_in(".").unwrap();
        let mut owner = open(&directory.path().join("refresh.db"));
        enrol(&mut owner);
        let prepared = prepare_fast(&mut owner);
        let phrase = prepared["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        owner
            .call(PRINCIPAL, Operation::BindingConfirm, prepared)
            .unwrap();
        let digest = [71; 32];
        let principal = format!("session:{}", hex::encode(digest));
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
                params![digest, now().unwrap() + CEREMONY_MS],
            )
            .unwrap();
        (directory, owner, principal, phrase)
    }

    fn prepared_refresh(owner: &mut Owner, principal: &str, phrase: &str) -> (Value, Value) {
        let start = owner
            .call(principal, Operation::BindingRefresh, json!({}))
            .unwrap();
        let prepare = json!({"ceremony_id":start["ceremony_id"],"current_phrase":phrase,"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)});
        let prepared = owner
            .call(principal, Operation::BindingRefreshPrepare, prepare.clone())
            .unwrap();
        (prepared, prepare)
    }

    fn backup_request(start: &Value, phrase: &str, count: u32) -> Value {
        json!({"backup_id":start["backup_id"],"current_phrase":phrase,
            "assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),count),
            "prf_output":URL_SAFE_NO_PAD.encode([81;32])})
    }

    #[test]
    fn antibody_backup_enrolment_opts_into_prf_without_requiring_support() {
        for supported in [false, true] {
            let directory = tempfile::tempdir_in(".").unwrap();
            let mut owner = open(&directory.path().join("prf-enrol.db"));
            let start = owner
                .call(PRINCIPAL, Operation::EnrolStart, json!({}))
                .unwrap();
            assert_eq!(start["public_key"]["extensions"], json!({"prf":{}}));
            let staged = owner.call(PRINCIPAL,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],
                "attestation":registration_prf(start["public_key"]["challenge"].as_str().unwrap(),supported)})).unwrap();
            assert_eq!(
                owner
                    .call(
                        PRINCIPAL,
                        Operation::EnrolFinish,
                        json!({"enrolment_id":start["enrolment_id"],
                "assertion":assertion(staged["public_key"]["challenge"].as_str().unwrap(),1)})
                    )
                    .unwrap()["state"],
                "enrolled"
            );
        }
    }

    #[test]
    fn antibody_backup_accepts_signed_prf_extensions_without_widening_signin() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        owner.kdf = KdfMode::DisposableTwin;
        for (count, length) in [(2, 32), (3, 48)] {
            let mut extension = b"\xa1\x6bhmac-secret\x58".to_vec();
            extension.push(length);
            extension.extend(vec![8; usize::from(length)]);
            let start = owner
                .call(&principal, Operation::BindingBackupStart, json!({}))
                .unwrap();
            let mut request = backup_request(&start, &phrase, count);
            request["assertion"] = assertion_extensions(
                start["public_key"]["challenge"].as_str().unwrap(),
                count,
                &extension,
            );
            let mut tampered = request.clone();
            let mut auth = URL_SAFE_NO_PAD
                .decode(
                    tampered["assertion"]["authenticator_data"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap();
            *auth.last_mut().unwrap() ^= 1;
            tampered["assertion"]["authenticator_data"] = json!(URL_SAFE_NO_PAD.encode(auth));
            assert_eq!(
                owner
                    .call(&principal, Operation::BindingBackupFinish, tampered)
                    .unwrap_err()
                    .code,
                "aumlok:assertion-refused"
            );
            assert_eq!(
                owner
                    .call(&principal, Operation::BindingBackupFinish, request)
                    .unwrap()["version"],
                2
            );
            let signin = owner
                .call(PRINCIPAL, Operation::SigninStart, json!({}))
                .unwrap();
            assert_eq!(owner.call(PRINCIPAL,Operation::SigninFinish,json!({"ceremony_id":signin["ceremony_id"],
                "assertion":assertion_extensions(signin["public_key"]["challenge"].as_str().unwrap(),count+1,&extension)})).unwrap_err().code,"aumlok:assertion-refused");
        }
    }

    #[test]
    fn antibody_backup_requires_fresh_owner_assertion_and_preserves_online_unlock() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        owner.kdf = KdfMode::DisposableTwin;
        let before = owner.binding.binding().unwrap().unwrap();
        let root = envelope::open(&before.envelope, &Phrase::parse(&phrase).unwrap()).unwrap();
        let start = owner
            .call(&principal, Operation::BindingBackupStart, json!({}))
            .unwrap();
        assert_eq!(
            start["public_key"]["extensions"]["prf"]["eval"]["first"],
            URL_SAFE_NO_PAD.encode(envelope::BACKUP_PRF_SALT)
        );
        let valid = backup_request(&start, &phrase, 2);
        let mut foreign = valid.clone();
        foreign["assertion"]["credential_id"] = json!(URL_SAFE_NO_PAD.encode(b"stranger"));
        assert_eq!(
            owner
                .call(&principal, Operation::BindingBackupFinish, foreign)
                .unwrap_err()
                .code,
            "aumlok:assertion-refused"
        );
        let mut altered = valid.clone();
        altered["assertion"] = assertion(&URL_SAFE_NO_PAD.encode([11; 32]), 2);
        assert_eq!(
            owner
                .call(&principal, Operation::BindingBackupFinish, altered)
                .unwrap_err()
                .code,
            "aumlok:assertion-refused"
        );
        let output = owner
            .call(&principal, Operation::BindingBackupFinish, valid.clone())
            .unwrap();
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 2);
        assert_eq!(output["version"], 2);
        let json = String::from_utf8(canonical(&output).unwrap()).unwrap();
        let backup = envelope::BackupEnvelope::from_canonical_json(&json).unwrap();
        assert_eq!(
            *envelope::open_backup(&backup, &Phrase::parse(&phrase).unwrap(), &[81; 32]).unwrap(),
            *root
        );
        assert!(
            envelope::open_backup(&backup, &Phrase::parse(&phrase).unwrap(), &[82; 32]).is_err()
        );
        assert_eq!(
            owner
                .call(&principal, Operation::BindingBackupFinish, valid)
                .unwrap_err()
                .code,
            "aumlok:backup-unknown"
        );
        assert_eq!(
            owner.binding.binding().unwrap().unwrap().envelope,
            before.envelope
        );
        assert_eq!(
            *owner
                .binding
                .open_current(
                    &refresh::envelope_sha256(&before.envelope),
                    &principal,
                    &Phrase::parse(&phrase).unwrap(),
                    now().unwrap()
                )
                .unwrap(),
            *root
        );
        assert_eq!(
            owner
                .call(&principal, Operation::BindingEnvelope, json!({}))
                .unwrap()["version"],
            1
        );
        assert!(envelope::Envelope::from_canonical_json(&json).is_err());
        assert_eq!(owner.root().unwrap().unwrap().as_ref(), root.as_ref());
    }

    #[test]
    fn antibody_backup_is_session_bound_expiring_and_prf_required() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        owner.kdf = KdfMode::DisposableTwin;
        let at = now().unwrap();
        let start = owner.backup_start_at(&principal, at).unwrap();
        let valid = backup_request(&start, &phrase, 2);
        let other = format!("session:{}", hex::encode([72; 32]));
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_session VALUES(?1,?2,0)",
                params![[72_u8; 32], at + 2 * CEREMONY_MS],
            )
            .unwrap();
        assert_eq!(
            owner
                .backup_finish_at(&other, valid.clone(), at)
                .unwrap_err()
                .code,
            "aumlok:ceremony-principal"
        );
        let mut absent = valid.clone();
        absent["prf_output"] = json!("");
        assert_eq!(
            owner
                .backup_finish_at(&principal, absent, at)
                .unwrap_err()
                .code,
            "aumlok:backup-prf-required"
        );
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
        // Keep the session valid past the backup ceremony's expiry.
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_session VALUES(?1,?2,0)",
                params![[73_u8; 32], at + 2 * CEREMONY_MS],
            )
            .unwrap();
        let long = format!("session:{}", hex::encode([73; 32]));
        let expiring = owner.backup_start_at(&long, at).unwrap();
        assert_eq!(
            owner
                .backup_finish_at(
                    &long,
                    backup_request(&expiring, &phrase, 2),
                    at + CEREMONY_MS
                )
                .unwrap_err()
                .code,
            "aumlok:ceremony-expired"
        );
        owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_session SET revoked=1 WHERE digest=?1",
                [[71_u8; 32]],
            )
            .unwrap();
        assert_eq!(
            owner
                .backup_finish_at(&principal, valid, at)
                .unwrap_err()
                .code,
            "frontdoor:session-required"
        );
    }

    #[test]
    fn antibody_backup_counterless_assertion_cannot_be_replayed() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        owner.kdf = KdfMode::DisposableTwin;
        owner
            .binding
            .connection()
            .execute_batch(
                "DROP TRIGGER supervisor_owner_pin; UPDATE supervisor_owner SET counter=0",
            )
            .unwrap();
        let start = owner
            .call(&principal, Operation::BindingBackupStart, json!({}))
            .unwrap();
        let request = backup_request(&start, &phrase, 0);
        assert_eq!(
            owner
                .call(&principal, Operation::BindingBackupFinish, request.clone())
                .unwrap()["version"],
            2
        );
        assert_eq!(
            owner
                .call(&principal, Operation::BindingBackupFinish, request)
                .unwrap_err()
                .code,
            "aumlok:backup-unknown"
        );
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 0);
    }

    #[test]
    fn antibody_backup_spends_wrong_phrase_assertion_and_limits_only_its_session() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        owner.kdf = KdfMode::DisposableTwin;
        let before = owner.binding.binding().unwrap().unwrap();
        for count in 2..=6 {
            let start = owner
                .call(&principal, Operation::BindingBackupStart, json!({}))
                .unwrap();
            let wrong = backup_request(&start, "wrong phrase", count);
            assert_eq!(
                owner
                    .call(&principal, Operation::BindingBackupFinish, wrong.clone())
                    .unwrap_err()
                    .code,
                "aumlok:current-phrase"
            );
            assert_eq!(
                owner
                    .call(&principal, Operation::BindingBackupFinish, wrong)
                    .unwrap_err()
                    .code,
                "aumlok:backup-unknown"
            );
        }
        let limited = owner
            .call(&principal, Operation::BindingBackupStart, json!({}))
            .unwrap();
        assert_eq!(
            owner
                .call(
                    &principal,
                    Operation::BindingBackupFinish,
                    backup_request(&limited, &phrase, 7)
                )
                .unwrap_err()
                .code,
            "aumlok:phrase-rate-limited"
        );
        let other = format!("session:{}", hex::encode([72; 32]));
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_session VALUES(?1,?2,0)",
                params![[72_u8; 32], now().unwrap() + CEREMONY_MS],
            )
            .unwrap();
        let start = owner
            .call(&other, Operation::BindingBackupStart, json!({}))
            .unwrap();
        assert_eq!(
            owner
                .call(
                    &other,
                    Operation::BindingBackupFinish,
                    backup_request(&start, &phrase, 8)
                )
                .unwrap()["version"],
            2
        );
        assert_eq!(
            owner.binding.binding().unwrap().unwrap().envelope,
            before.envelope
        );
    }

    #[test]
    fn antibody_backup_start_is_bounded_and_refresh_invalidates_old_download_ceremony() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        owner.kdf = KdfMode::DisposableTwin;
        let at = now().unwrap();
        let start = owner.backup_start_at(&principal, at).unwrap();
        for _ in 0..32 {
            assert_eq!(owner.backup_start_at(&principal, at).unwrap(), start);
        }
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row("SELECT count(*) FROM supervisor_backup", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let prepared = prepared_refresh(&mut owner, &principal, &phrase).0;
        owner.call(&principal,Operation::BindingRefreshConfirm,json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":phrase,"words":prepared["words"]})).unwrap();
        let new_phrase = prepared["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|word| word.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            owner
                .call(
                    &principal,
                    Operation::BindingBackupFinish,
                    backup_request(&start, &new_phrase, 3)
                )
                .unwrap_err()
                .code,
            "aumlok:envelope-retired"
        );
        let next = owner
            .call(&principal, Operation::BindingBackupStart, json!({}))
            .unwrap();
        assert_ne!(next["backup_id"], start["backup_id"]);
    }

    #[test]
    fn antibody_refresh_lost_prepare_response_returns_live_id_before_assertion() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        let (prepared, request) = prepared_refresh(&mut owner, &principal, &phrase);
        let expected = json!({"ceremony_id":prepared["ceremony_id"],"state":"live","expires_at":prepared["expires_at"]});
        assert_eq!(
            owner
                .call(&principal, Operation::BindingRefresh, json!({}))
                .unwrap(),
            expected
        );
        assert_eq!(
            owner
                .call(&principal, Operation::BindingRefreshPrepare, request)
                .unwrap(),
            expected
        );
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 2);
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM supervisor_refresh_approval",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        let resumed = owner
            .call(
                &principal,
                Operation::BindingRefreshResume,
                json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":phrase}),
            )
            .unwrap();
        assert_eq!(resumed["words"], prepared["words"]);
    }

    #[test]
    fn antibody_refresh_lost_confirm_response_reports_committed_without_words() {
        let (directory, mut owner, principal, phrase) = refresh_fixture();
        let (prepared, _) = prepared_refresh(&mut owner, &principal, &phrase);
        let confirm = json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":phrase,"words":prepared["words"]});
        let completed = owner
            .call(
                &principal,
                Operation::BindingRefreshConfirm,
                confirm.clone(),
            )
            .unwrap();
        assert_eq!(completed["state"], "committed");
        drop(owner);
        let mut owner = open(&directory.path().join("refresh.db"));
        let confirmed = owner
            .call(&principal, Operation::BindingRefreshConfirm, confirm)
            .unwrap();
        assert_eq!(confirmed, completed);
        let resumed = owner.call(&principal, Operation::BindingRefreshResume, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":"deliberately malformed"})).unwrap();
        assert_eq!(resumed, completed);
        assert_eq!(resumed.as_object().unwrap().len(), 3);
        for table in ["aumlok_retired_envelope", "aumlok_current_envelope"] {
            assert_eq!(
                owner
                    .binding
                    .connection()
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM aura WHERE op=?1 AND phase='terminal'",
                    [prepared["ceremony_id"].as_str().unwrap()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row("SELECT count(*) FROM aumlok_phrase_guesses", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    fn add_session(owner: &Owner, digest: [u8; 32]) -> String {
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
                params![digest, now().unwrap() + CEREMONY_MS],
            )
            .unwrap();
        format!("session:{}", hex::encode(digest))
    }

    #[test]
    fn antibody_refresh_other_live_session_reports_retry_without_approval_or_spend() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        let other = add_session(&owner, [81; 32]);
        let other_approval = owner.refresh_start(&other).unwrap();
        let (prepared, _) = prepared_refresh(&mut owner, &principal, &phrase);
        let count = owner
            .binding
            .connection()
            .query_row(
                "SELECT count(*) FROM supervisor_refresh_approval",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        for body in [
            None,
            Some(
                json!({"ceremony_id":other_approval["ceremony_id"],"current_phrase":phrase,"assertion":assertion(other_approval["public_key"]["challenge"].as_str().unwrap(),3)}),
            ),
        ] {
            let refused = match body {
                Some(body) => owner.refresh_prepare(&other, body),
                None => owner.refresh_start(&other),
            }
            .unwrap_err();
            assert_eq!(refused.code, "aumlok:refresh-live");
            assert_eq!(refused.expires_at, prepared["expires_at"].as_i64());
            assert_eq!(owner.credential().unwrap().unwrap().sign_count, 2);
            assert_eq!(
                owner
                    .binding
                    .connection()
                    .query_row(
                        "SELECT count(*) FROM supervisor_refresh_approval",
                        [],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                count
            );
            assert_eq!(
                owner
                    .binding
                    .connection()
                    .query_row(
                        "SELECT state FROM supervisor_refresh_approval WHERE id=?1",
                        [other_approval["ceremony_id"].as_str().unwrap()],
                        |row| row.get::<_, String>(0)
                    )
                    .unwrap(),
                "live"
            );
        }
    }

    #[test]
    fn antibody_refresh_cancel_after_lost_confirm_reports_committed_after_restart() {
        let (directory, mut owner, principal, phrase) = refresh_fixture();
        let (prepared, _) = prepared_refresh(&mut owner, &principal, &phrase);
        let completed = owner.refresh_confirm(&principal, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":phrase,"words":prepared["words"]})).unwrap();
        drop(owner);
        let mut owner = open(&directory.path().join("refresh.db"));
        assert_eq!(
            owner
                .refresh_cancel(&principal, json!({"ceremony_id":prepared["ceremony_id"]}))
                .unwrap(),
            completed
        );
        let other = add_session(&owner, [82; 32]);
        assert_eq!(
            owner
                .refresh_cancel(&other, json!({"ceremony_id":prepared["ceremony_id"]}))
                .unwrap_err()
                .code,
            "aumlok:ceremony-principal"
        );
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM aura WHERE op=?1 AND phase='terminal'",
                    [prepared["ceremony_id"].as_str().unwrap()],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn antibody_logout_everywhere_requires_session_and_exact_passkey_action() {
        let (_directory, mut owner, principal, _) = refresh_fixture();
        let other = add_session(&owner, [83; 32]);
        assert_eq!(
            owner
                .logout_everywhere_start("owner:agent")
                .unwrap_err()
                .code,
            "frontdoor:session-required"
        );
        let start = owner.logout_everywhere_start(&principal).unwrap();
        assert_eq!(start["auth"]["op"], "permission");
        assert_eq!(start["auth"]["target"], "aumlok/session/revoke-all");
        let shared = owner.logout_everywhere_start(&principal).unwrap();
        assert_eq!(shared["ceremony_id"], start["ceremony_id"]);
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM supervisor_logout_approval",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        let correct = json!({"ceremony_id":start["ceremony_id"],"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)});
        assert_eq!(
            owner
                .logout_everywhere_finish(&other, correct.clone())
                .unwrap_err()
                .code,
            "aumlok:ceremony-principal"
        );
        let refresh = owner.refresh_start(&principal).unwrap();
        assert_eq!(owner.logout_everywhere_finish(&principal,json!({"ceremony_id":start["ceremony_id"],"assertion":assertion(refresh["public_key"]["challenge"].as_str().unwrap(),2)})).unwrap_err().code,"aumlok:assertion-refused");
        assert_eq!(
            owner
                .logout_everywhere_finish("owner:agent", correct.clone())
                .unwrap_err()
                .code,
            "frontdoor:session-required"
        );
        assert!(owner.session_valid([71; 32], now().unwrap()).unwrap());
        assert!(owner.session_valid([83; 32], now().unwrap()).unwrap());
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
        owner
            .logout_everywhere_finish(&principal, correct.clone())
            .unwrap();
        assert_eq!(
            owner
                .logout_everywhere_finish(&principal, correct)
                .unwrap_err()
                .code,
            "frontdoor:session-required"
        );
    }

    #[test]
    fn antibody_logout_everywhere_approval_slot_reuses_and_replaces_before_expiry() {
        let (_directory, mut owner, principal, _) = refresh_fixture();
        let at = now().unwrap();
        let first = owner.logout_everywhere_start_at(&principal, at).unwrap();
        for offset in 1..200 {
            assert_eq!(
                owner
                    .logout_everywhere_start_at(&principal, at + offset)
                    .unwrap()["ceremony_id"],
                first["ceremony_id"]
            );
        }
        let next_at = at + CEREMONY_MS - SIGNIN_SHARE_MIN_MS + 1;
        let next = owner
            .logout_everywhere_start_at(&principal, next_at)
            .unwrap();
        assert_ne!(next["ceremony_id"], first["ceremony_id"]);
        assert_eq!(next["auth"]["expires_at"], next_at + CEREMONY_MS);
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM supervisor_logout_approval WHERE principal=?1",
                    [&principal],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(owner.logout_everywhere_finish(&principal,json!({"ceremony_id":first["ceremony_id"],"assertion":assertion(first["public_key"]["challenge"].as_str().unwrap(),2)})).unwrap_err().code,"aumlok:ceremony-unknown");
    }

    #[test]
    fn antibody_logout_everywhere_rebuilds_authorization_and_refuses_expiry() {
        let (_directory, mut owner, principal, _) = refresh_fixture();
        let start = owner.logout_everywhere_start(&principal).unwrap();
        let id = start["ceremony_id"].as_str().unwrap();
        assert!(owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_logout_approval SET auth='{}' WHERE id=?1",
                [id]
            )
            .is_err());
        assert!(owner.binding.connection().execute("INSERT INTO supervisor_logout_approval SELECT 'duplicate',principal,auth,expires_at FROM supervisor_logout_approval WHERE id=?1",[id]).is_err());
        owner
            .binding
            .connection()
            .execute_batch("DROP TRIGGER supervisor_logout_approval_pin")
            .unwrap();
        let mut tampered = start["auth"].clone();
        tampered["target"] = json!("aumlok/binding/refresh");
        owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_logout_approval SET auth=?1 WHERE id=?2",
                params![
                    String::from_utf8(canonical(&tampered).unwrap()).unwrap(),
                    id
                ],
            )
            .unwrap();
        let challenge =
            webauthn::owner_authorization_challenge(&canonical(&tampered).unwrap()).unwrap();
        assert_eq!(
            owner
                .logout_everywhere_finish(
                    &principal,
                    json!({"ceremony_id":id,"assertion":assertion(&challenge,2)})
                )
                .unwrap_err()
                .code,
            "aumlok:assertion-refused"
        );
        owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_logout_approval SET auth=?1,expires_at=?2 WHERE id=?3",
                params![
                    String::from_utf8(canonical(&start["auth"]).unwrap()).unwrap(),
                    now().unwrap() - 1,
                    id
                ],
            )
            .unwrap();
        assert_eq!(owner.logout_everywhere_finish(&principal,json!({"ceremony_id":id,"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)})).unwrap_err().code,"aumlok:ceremony-expired");
        assert!(owner.session_valid([71; 32], now().unwrap()).unwrap());
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
    }

    #[test]
    fn antibody_logout_everywhere_revokes_every_session_and_refresh_atomically() {
        let (directory, mut owner, principal, phrase) = refresh_fixture();
        let other = add_session(&owner, [84; 32]);
        for (parent, child) in [([71; 32], [91; 32]), ([84; 32], [92; 32])] {
            owner
                .create_chat_session(parent, child, now().unwrap() + 60_000)
                .unwrap();
        }
        owner.refresh_start(&other).unwrap();
        owner.logout_everywhere_start(&other).unwrap();
        let (prepared, _) = prepared_refresh(&mut owner, &principal, &phrase);
        let original = owner.binding.binding().unwrap().unwrap();
        let start = owner.logout_everywhere_start(&principal).unwrap();
        let finish = json!({"ceremony_id":start["ceremony_id"],"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),3)});
        let injection = Connection::open(directory.path().join("refresh.db")).unwrap();
        injection.execute_batch("CREATE TRIGGER test_logout_failure BEFORE INSERT ON aura WHEN json_extract(NEW.body,'$.action')='signout-everywhere' BEGIN SELECT RAISE(ABORT,'test logout failure'); END;").unwrap();
        assert!(owner
            .logout_everywhere_finish(&principal, finish.clone())
            .is_err());
        for digest in [[71; 32], [84; 32]] {
            assert!(owner.session_valid(digest, now().unwrap()).unwrap());
        }
        for digest in [[91; 32], [92; 32]] {
            assert!(owner.chat_session_valid(digest, now().unwrap()).unwrap());
        }
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 2);
        assert!(owner
            .binding
            .live_refresh(&principal, now().unwrap())
            .unwrap()
            .is_some());
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM supervisor_logout_approval",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        injection
            .execute_batch("DROP TRIGGER test_logout_failure")
            .unwrap();
        assert_eq!(
            owner.logout_everywhere_finish(&principal, finish).unwrap(),
            json!({"ok":true})
        );
        for digest in [[71; 32], [84; 32]] {
            assert!(!owner.session_valid(digest, now().unwrap()).unwrap());
        }
        for digest in [[91; 32], [92; 32]] {
            assert!(!owner.chat_session_valid(digest, now().unwrap()).unwrap());
        }
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 3);
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT state FROM aumlok_refresh WHERE id=?1",
                    [prepared["ceremony_id"].as_str().unwrap()],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "CANCELLED"
        );
        for table in ["supervisor_refresh_approval", "supervisor_logout_approval"] {
            assert_eq!(
                owner
                    .binding
                    .connection()
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        assert_eq!(
            owner.binding.binding().unwrap().unwrap().envelope,
            original.envelope
        );
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM aura WHERE op=?1 AND phase='terminal'",
                    [start["ceremony_id"].as_str().unwrap()],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        drop(owner);
        let mut owner = open(&directory.path().join("refresh.db"));
        for digest in [[71; 32], [84; 32]] {
            assert!(!owner.session_valid(digest, now().unwrap()).unwrap());
        }
        for digest in [[91; 32], [92; 32]] {
            assert!(!owner.chat_session_valid(digest, now().unwrap()).unwrap());
        }
        let signin = owner.signin_start().unwrap();
        owner.signin_session(json!({"ceremony_id":signin["ceremony_id"],"assertion":assertion(signin["public_key"]["challenge"].as_str().unwrap(),4)}),[85;32],now().unwrap() + CEREMONY_MS).unwrap();
        assert!(owner.session_valid([85; 32], now().unwrap()).unwrap());
        let recovered = format!("session:{}", hex::encode([85; 32]));
        let approval = owner.refresh_start(&recovered).unwrap();
        let next = owner.refresh_prepare(&recovered,json!({"ceremony_id":approval["ceremony_id"],"current_phrase":phrase,"assertion":assertion(approval["public_key"]["challenge"].as_str().unwrap(),5)})).unwrap();
        assert!(next["words"].is_array());
    }

    #[test]
    fn antibody_refresh_cancel_requires_live_owner_session_and_keeps_phrase() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        let (prepared, _) = prepared_refresh(&mut owner, &principal, &phrase);
        let cancel = json!({"ceremony_id":prepared["ceremony_id"]});
        assert_eq!(
            owner
                .call(
                    "owner:agent",
                    Operation::BindingRefreshCancel,
                    cancel.clone()
                )
                .unwrap_err()
                .code,
            "frontdoor:session-required"
        );
        let other_digest = [76; 32];
        let other = format!("session:{}", hex::encode(other_digest));
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
                params![other_digest, now().unwrap() + CEREMONY_MS],
            )
            .unwrap();
        assert_eq!(
            owner
                .call(&other, Operation::BindingRefreshCancel, cancel.clone())
                .unwrap_err()
                .code,
            "aumlok:ceremony-principal"
        );
        assert_eq!(
            owner
                .call(&principal, Operation::BindingRefreshCancel, cancel)
                .unwrap(),
            json!({"ok":true})
        );
        let binding = owner.binding.binding().unwrap().unwrap();
        assert!(envelope::open(&binding.envelope, &Phrase::parse(&phrase).unwrap()).is_ok());
        let start = owner
            .call(&principal, Operation::BindingRefresh, json!({}))
            .unwrap();
        let prepared = owner.call(&principal, Operation::BindingRefreshPrepare, json!({"ceremony_id":start["ceremony_id"],"current_phrase":phrase,"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),3)})).unwrap();
        assert!(prepared["words"].is_array());
    }

    #[test]
    fn antibody_refresh_approval_slot_is_bounded_without_shortening_ceremony() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        let at = now().unwrap();
        let first = owner.refresh_start_at(&principal, at - 180_000).unwrap();
        let shared = owner.refresh_start_at(&principal, at).unwrap();
        assert_eq!(shared["ceremony_id"], first["ceremony_id"]);
        let prepared = owner.refresh_prepare_at(&principal, json!({"ceremony_id":first["ceremony_id"],"current_phrase":phrase,"assertion":assertion(first["public_key"]["challenge"].as_str().unwrap(),2)}), at).unwrap();
        assert_eq!(prepared["expires_at"], at + CEREMONY_MS);
        assert!(
            prepared["expires_at"].as_i64().unwrap()
                > first["auth"]["expires_at"].as_i64().unwrap()
        );
        owner
            .refresh_cancel(&principal, json!({"ceremony_id":prepared["ceremony_id"]}))
            .unwrap();
        let replacement = owner.refresh_start_at(&principal, at).unwrap();
        assert_ne!(replacement["ceremony_id"], first["ceremony_id"]);
        for offset in 1..200 {
            assert_eq!(
                owner.refresh_start_at(&principal, at + offset).unwrap()["ceremony_id"],
                replacement["ceremony_id"]
            );
        }
        let almost_expired = at + CEREMONY_MS - SIGNIN_SHARE_MIN_MS + 1;
        let fresh = owner.refresh_start_at(&principal, almost_expired).unwrap();
        assert_ne!(fresh["ceremony_id"], replacement["ceremony_id"]);
        assert_eq!(fresh["auth"]["expires_at"], almost_expired + CEREMONY_MS);
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM supervisor_refresh_approval WHERE principal=?1",
                    [&principal],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(owner.refresh_prepare_at(&principal, json!({"ceremony_id":replacement["ceremony_id"],"current_phrase":phrase,"assertion":assertion(replacement["public_key"]["challenge"].as_str().unwrap(),3)}), almost_expired).unwrap_err().code, "aumlok:ceremony-unknown");
    }

    #[test]
    fn antibody_refresh_approval_startup_prunes_legacy_rows_per_session() {
        let (directory, mut owner, principal, _) = refresh_fixture();
        let at = now().unwrap();
        let current = owner.refresh_start_at(&principal, at).unwrap();
        for (id, expires, state) in [
            ("legacy-live", at + CEREMONY_MS, "live"),
            ("legacy-expired", at - 1, "live"),
            ("legacy-spent", at + CEREMONY_MS, "spent"),
        ] {
            owner
                .binding
                .connection()
                .execute(
                    "INSERT INTO supervisor_refresh_approval VALUES(?1,?2,?3,?4,?5)",
                    params![
                        id,
                        principal,
                        String::from_utf8(canonical(&current["auth"]).unwrap()).unwrap(),
                        expires,
                        state
                    ],
                )
                .unwrap();
        }
        drop(owner);
        let owner = open(&directory.path().join("refresh.db"));
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT count(*) FROM supervisor_refresh_approval WHERE principal=?1",
                    [&principal],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT id FROM supervisor_refresh_approval WHERE principal=?1",
                    [&principal],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "legacy-live"
        );
    }

    #[test]
    fn antibody_refresh_approval_pins_session_auth_expiry_and_spent_state() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        let start = owner
            .call(&principal, Operation::BindingRefresh, json!({}))
            .unwrap();
        let id = start["ceremony_id"].as_str().unwrap();
        for update in ["principal='other'", "auth='{}'", "expires_at=expires_at+1"] {
            assert!(owner
                .binding
                .connection()
                .execute(
                    &format!("UPDATE supervisor_refresh_approval SET {update} WHERE id=?1"),
                    [id]
                )
                .is_err());
        }
        assert!(owner
            .binding
            .connection()
            .execute("DELETE FROM supervisor_refresh_approval WHERE id=?1", [id])
            .is_err());
        let other_digest = [72; 32];
        let other = format!("session:{}", hex::encode(other_digest));
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
                params![other_digest, now().unwrap() + CEREMONY_MS],
            )
            .unwrap();
        let finish = json!({"ceremony_id":id,"current_phrase":phrase,"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)});
        assert_eq!(
            owner
                .call(&other, Operation::BindingRefreshPrepare, finish.clone())
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        let binding = owner.binding.binding().unwrap().unwrap();
        let expired_id = hex::encode([73; 16]);
        let expires = now().unwrap() - 1;
        let (expired_auth, _) =
            refresh_authorization(NODE, &binding, &expired_id, &hex::encode([74; 32]), expires)
                .unwrap();
        let auth_bytes = canonical(&expired_auth).unwrap();
        owner
            .binding
            .connection()
            .execute(
                "INSERT INTO supervisor_refresh_approval VALUES(?1,?2,?3,?4,'live')",
                params![
                    expired_id,
                    principal,
                    String::from_utf8(auth_bytes.clone()).unwrap(),
                    expires
                ],
            )
            .unwrap();
        let proof = assertion(
            &webauthn::owner_authorization_challenge(&auth_bytes).unwrap(),
            2,
        );
        assert_eq!(
            owner
                .call(
                    &principal,
                    Operation::BindingRefreshPrepare,
                    json!({"ceremony_id":expired_id,"current_phrase":phrase,"assertion":proof})
                )
                .unwrap_err()
                .code,
            "aumlok:ceremony-expired"
        );
        owner
            .call(&principal, Operation::BindingRefreshPrepare, finish)
            .unwrap();
        assert!(owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_refresh_approval SET state='live' WHERE id=?1",
                [id]
            )
            .is_err());
        assert!(owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_refresh_approval SET state='spent' WHERE id=?1",
                [id]
            )
            .is_err());
    }

    #[test]
    fn antibody_refresh_rebuilds_authorization_before_accepting_passkey() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        let start = owner
            .call(&principal, Operation::BindingRefresh, json!({}))
            .unwrap();
        let id = start["ceremony_id"].as_str().unwrap();
        let mut auth = start["auth"].clone();
        auth["new_sha256"] = json!(hex::encode([75; 32]));
        let bytes = canonical(&auth).unwrap();
        owner
            .binding
            .connection()
            .execute_batch("DROP TRIGGER supervisor_refresh_approval_pin")
            .unwrap();
        owner
            .binding
            .connection()
            .execute(
                "UPDATE supervisor_refresh_approval SET auth=?1 WHERE id=?2",
                params![String::from_utf8(bytes.clone()).unwrap(), id],
            )
            .unwrap();
        let proof = assertion(&webauthn::owner_authorization_challenge(&bytes).unwrap(), 2);
        assert_eq!(
            owner
                .call(
                    &principal,
                    Operation::BindingRefreshPrepare,
                    json!({"ceremony_id":id,"current_phrase":phrase,"assertion":proof})
                )
                .unwrap_err()
                .code,
            "aumlok:refresh-stale"
        );
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row("SELECT count(*) FROM aumlok_refresh", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn antibody_refresh_invalid_signature_has_no_guess_or_effect() {
        let (_directory, mut owner, principal, phrase) = refresh_fixture();
        let start = owner
            .call(&principal, Operation::BindingRefresh, json!({}))
            .unwrap();
        let mut proof = assertion(start["public_key"]["challenge"].as_str().unwrap(), 2);
        proof["signature"] = json!(URL_SAFE_NO_PAD.encode([0; 64]));
        let error = owner.call(&principal,Operation::BindingRefreshPrepare,json!({"ceremony_id":start["ceremony_id"],"current_phrase":phrase,"assertion":proof})).unwrap_err();
        assert_eq!(error.code, "aumlok:assertion-refused");
        for table in ["aumlok_refresh", "aumlok_phrase_guesses"] {
            assert_eq!(
                owner
                    .binding
                    .connection()
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
    }

    #[test]
    fn antibody_refresh_start_aura_failure_preserves_approval_counter_and_envelope() {
        let (directory, mut owner, principal, phrase) = refresh_fixture();
        let injection = Connection::open(directory.path().join("refresh.db")).unwrap();
        let start = owner
            .call(&principal, Operation::BindingRefresh, json!({}))
            .unwrap();
        let id = start["ceremony_id"].as_str().unwrap();
        let finish = json!({"ceremony_id":id,"current_phrase":phrase,"assertion":assertion(start["public_key"]["challenge"].as_str().unwrap(),2)});
        injection.execute_batch("CREATE TRIGGER test_refresh_start_failure BEFORE INSERT ON aura WHEN json_extract(NEW.body,'$.stage')='start' BEGIN SELECT RAISE(ABORT,'test refresh start failure'); END;").unwrap();
        assert!(owner
            .call(&principal, Operation::BindingRefreshPrepare, finish.clone())
            .is_err());
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 1);
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row("SELECT count(*) FROM aumlok_refresh", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            owner
                .binding
                .connection()
                .query_row(
                    "SELECT state FROM supervisor_refresh_approval WHERE id=?1",
                    [id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "live"
        );
        injection
            .execute_batch("DROP TRIGGER test_refresh_start_failure")
            .unwrap();
        owner
            .call(&principal, Operation::BindingRefreshPrepare, finish)
            .unwrap();
        assert_eq!(owner.credential().unwrap().unwrap().sign_count, 2);
    }
}
