// SPDX-License-Identifier: AGPL-3.0-or-later
//! Refresh rewraps the current root. The supervisor verifies the passkey assertion.
//! A downloaded retired envelope remains decryptable offline; node unlock refuses it.

use crate::binding::{subject_from_root, BindingStore};
use crate::envelope::{open, reseal, Envelope, KdfParams};
use crate::phrase::{entropy, Phrase};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS aumlok_current_envelope (
    id INTEGER PRIMARY KEY CHECK(id=1),
    subject TEXT NOT NULL,
    envelope_sha256 TEXT NOT NULL UNIQUE,
    envelope TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS aumlok_refresh (
    id TEXT PRIMARY KEY NOT NULL,
    version INTEGER NOT NULL CHECK(version=1),
    state TEXT NOT NULL CHECK(state IN ('LIVE','COMMITTING','COMMITTED','CANCELLED','EXPIRED')),
    principal TEXT NOT NULL,
    assertion_id TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    old_sha256 TEXT NOT NULL,
    new_sha256 TEXT NOT NULL UNIQUE,
    envelope TEXT NOT NULL,
    phrase_cipher BLOB NOT NULL CHECK(length(phrase_cipher) BETWEEN 41 AND 1040),
    issued_at INTEGER NOT NULL CHECK(issued_at>=0),
    expires_at INTEGER NOT NULL,
    CHECK(expires_at>issued_at AND expires_at-issued_at<=300000),
    CHECK(old_sha256<>new_sha256)
);
CREATE UNIQUE INDEX IF NOT EXISTS aumlok_refresh_one_live ON aumlok_refresh(version)
    WHERE state IN ('LIVE','COMMITTING');
CREATE TABLE IF NOT EXISTS aumlok_retired_envelope (
    envelope_sha256 TEXT PRIMARY KEY NOT NULL,
    envelope TEXT NOT NULL,
    subject TEXT NOT NULL,
    retired_at INTEGER NOT NULL CHECK(retired_at>=0),
    ceremony_id TEXT NOT NULL UNIQUE REFERENCES aumlok_refresh(id)
);
CREATE TABLE IF NOT EXISTS aumlok_phrase_guesses (
    principal TEXT PRIMARY KEY NOT NULL,
    window_start INTEGER NOT NULL,
    failures INTEGER NOT NULL CHECK(failures BETWEEN 1 AND 5)
);
CREATE TRIGGER IF NOT EXISTS aumlok_current_initial
BEFORE INSERT ON aumlok_current_envelope
WHEN EXISTS(SELECT 1 FROM aumlok_current_envelope)
 OR NOT EXISTS(SELECT 1 FROM aumlok_binding
    WHERE state='COMPLETED' AND subject=NEW.subject AND envelope=NEW.envelope)
BEGIN SELECT RAISE(ABORT,'aumlok:current-initial'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_current_no_delete BEFORE DELETE ON aumlok_current_envelope
BEGIN SELECT RAISE(ABORT,'aumlok:current-retained'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_current_switch BEFORE UPDATE ON aumlok_current_envelope
WHEN NEW.id IS NOT OLD.id OR NEW.subject IS NOT OLD.subject
 OR EXISTS(SELECT 1 FROM aumlok_retired_envelope WHERE envelope_sha256=NEW.envelope_sha256)
 OR NOT EXISTS(SELECT 1 FROM aumlok_refresh r JOIN aumlok_retired_envelope t ON t.ceremony_id=r.id
    WHERE r.state='COMMITTING' AND r.subject=OLD.subject AND r.old_sha256=OLD.envelope_sha256
      AND r.new_sha256=NEW.envelope_sha256 AND r.envelope=NEW.envelope
      AND t.envelope_sha256=OLD.envelope_sha256 AND t.envelope=OLD.envelope)
BEGIN SELECT RAISE(ABORT,'aumlok:current-switch'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_refresh_initial BEFORE INSERT ON aumlok_refresh
WHEN NEW.state<>'LIVE' OR EXISTS(SELECT 1 FROM aumlok_refresh WHERE id=NEW.id OR assertion_id=NEW.assertion_id)
 OR NOT EXISTS(SELECT 1 FROM aumlok_current_envelope
    WHERE subject=NEW.subject AND envelope_sha256=NEW.old_sha256)
BEGIN SELECT RAISE(ABORT,'aumlok:refresh-initial'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_refresh_no_delete BEFORE DELETE ON aumlok_refresh
BEGIN SELECT RAISE(ABORT,'aumlok:refresh-retained'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_refresh_forward BEFORE UPDATE ON aumlok_refresh
WHEN NOT ((OLD.state='LIVE' AND NEW.state IN ('COMMITTING','CANCELLED','EXPIRED'))
 OR (OLD.state='COMMITTING' AND NEW.state='COMMITTED'))
 OR NEW.id IS NOT OLD.id OR NEW.version IS NOT OLD.version OR NEW.principal IS NOT OLD.principal
 OR NEW.assertion_id IS NOT OLD.assertion_id OR NEW.subject IS NOT OLD.subject
 OR NEW.old_sha256 IS NOT OLD.old_sha256 OR NEW.new_sha256 IS NOT OLD.new_sha256
 OR NEW.envelope IS NOT OLD.envelope OR NEW.phrase_cipher IS NOT OLD.phrase_cipher
 OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
BEGIN SELECT RAISE(ABORT,'aumlok:refresh-transition'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_refresh_committed BEFORE UPDATE ON aumlok_refresh
WHEN NEW.state='COMMITTED' AND NOT EXISTS(
 SELECT 1 FROM aumlok_current_envelope c JOIN aumlok_retired_envelope t ON t.ceremony_id=NEW.id
 WHERE c.envelope_sha256=NEW.new_sha256 AND c.envelope=NEW.envelope AND c.subject=NEW.subject
 AND t.envelope_sha256=NEW.old_sha256 AND t.subject=NEW.subject)
BEGIN SELECT RAISE(ABORT,'aumlok:refresh-unsettled'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_retired_initial BEFORE INSERT ON aumlok_retired_envelope
WHEN EXISTS(SELECT 1 FROM aumlok_retired_envelope WHERE envelope_sha256=NEW.envelope_sha256 OR ceremony_id=NEW.ceremony_id)
 OR NOT EXISTS(SELECT 1 FROM aumlok_refresh r JOIN aumlok_current_envelope c ON c.envelope_sha256=r.old_sha256
 WHERE r.id=NEW.ceremony_id AND r.state='COMMITTING' AND c.envelope=NEW.envelope
 AND c.subject=NEW.subject AND c.envelope_sha256=NEW.envelope_sha256)
BEGIN SELECT RAISE(ABORT,'aumlok:retirement-stage'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_retired_no_update BEFORE UPDATE ON aumlok_retired_envelope
BEGIN SELECT RAISE(ABORT,'aumlok:retired-immutable'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_retired_no_delete BEFORE DELETE ON aumlok_retired_envelope
BEGIN SELECT RAISE(ABORT,'aumlok:retired-retained'); END;
"#;

const MAX_FAILURES: i64 = 5;
const GUESS_WINDOW_MS: i64 = 60_000;
const MAX_CEREMONY_MS: i64 = 300_000;

/// Construct only after verifying an owner assertion for this refresh and envelope.
/// The principal is supervisor-authenticated; assertion_id identifies the spent challenge.
pub struct VerifiedRefreshApproval {
    principal: String,
    subject: String,
    envelope_sha256: String,
    assertion_id: String,
}

impl VerifiedRefreshApproval {
    pub fn new(
        principal: String,
        subject: String,
        envelope_sha256: String,
        assertion_id: String,
    ) -> Self {
        Self {
            principal,
            subject,
            envelope_sha256,
            assertion_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct RefreshError {
    code: &'static str,
    position: Option<usize>,
}

impl RefreshError {
    pub fn refused(code: &'static str) -> Self {
        Self {
            code,
            position: None,
        }
    }
    pub fn code(self) -> &'static str {
        self.code
    }
    pub fn position(self) -> Option<usize> {
        self.position
    }
    fn mismatch(position: usize) -> Self {
        Self {
            code: "aumlok:word-mismatch",
            position: Some(position),
        }
    }
}

pub struct RefreshPreparation {
    pub ceremony_id: String,
    pub phrase: Phrase,
    pub entropy_bits: f64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRefresh {
    pub ceremony_id: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct RefreshRecord {
    pub ceremony_id: String,
    pub subject: String,
    pub old_envelope_sha256: String,
    pub new_envelope_sha256: String,
    pub envelope: Envelope,
}

impl RefreshRecord {
    pub fn kind(&self) -> &'static str {
        "aumlok.bind"
    }
    pub fn phase(&self) -> &'static str {
        "terminal"
    }
    pub fn body(&self) -> String {
        format!("{{\"envelope_sha256\":{{\"new\":\"{}\",\"old\":\"{}\"}},\"refresh\":true,\"subject\":\"{}\"}}",
            self.new_envelope_sha256, self.old_envelope_sha256, self.subject)
    }
}

pub(crate) struct CurrentEnvelope {
    pub subject: String,
    pub envelope: Envelope,
    sha256: String,
}

struct Ceremony {
    record: RefreshRecord,
    principal: String,
    state: String,
    expires_at: i64,
    phrase_cipher: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    PreparedWritten,
    PreparedCommitted,
    Confirming,
    Retired,
    Switched,
    AuraWritten,
    CommittedWritten,
    Committed,
    CancelledWritten,
    Cancelled,
    ExpiredWritten,
    Expired,
}

fn storage(_: rusqlite::Error) -> RefreshError {
    RefreshError::refused("aumlok:refresh-storage")
}
fn corrupt() -> RefreshError {
    RefreshError::refused("aumlok:refresh-corrupt")
}

pub fn envelope_sha256(envelope: &Envelope) -> String {
    hex::encode(Sha256::digest(envelope.to_canonical_json().as_bytes()))
}

pub(crate) fn initialize_current(connection: &Connection) -> Result<(), RefreshError> {
    if read_current(connection)?.is_some() {
        return Ok(());
    }
    let history: bool = connection
        .query_row("SELECT EXISTS(SELECT 1 FROM aumlok_refresh)", [], |row| {
            row.get(0)
        })
        .map_err(storage)?;
    if history {
        return Err(corrupt());
    }
    let original: Option<(String, String)> = connection
        .query_row(
            "SELECT subject,envelope FROM aumlok_binding WHERE state='COMPLETED'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    if let Some((subject, json)) = original {
        let envelope = Envelope::from_canonical_json(&json).map_err(|_| corrupt())?;
        connection
            .execute(
                "INSERT INTO aumlok_current_envelope VALUES(1,?1,?2,?3)",
                params![subject, envelope_sha256(&envelope), json],
            )
            .map_err(storage)?;
    }
    Ok(())
}

pub(crate) fn read_current(
    connection: &Connection,
) -> Result<Option<CurrentEnvelope>, RefreshError> {
    let row: Option<(String, String, String)> = connection
        .query_row(
            "SELECT subject,envelope_sha256,envelope FROM aumlok_current_envelope WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage)?;
    row.map(|(subject, sha256, json)| {
        let envelope = Envelope::from_canonical_json(&json).map_err(|_| corrupt())?;
        if sha256 != envelope_sha256(&envelope) {
            return Err(corrupt());
        }
        Ok(CurrentEnvelope {
            subject,
            sha256,
            envelope,
        })
    })
    .transpose()
}

fn current(connection: &Connection) -> Result<CurrentEnvelope, RefreshError> {
    read_current(connection)?.ok_or_else(|| RefreshError::refused("aumlok:binding-required"))
}

fn read_ceremony(connection: &Connection, id: &str) -> Result<Ceremony, RefreshError> {
    let ceremony = connection.query_row(
        "SELECT version,state,principal,subject,old_sha256,new_sha256,envelope,expires_at,phrase_cipher FROM aumlok_refresh WHERE id=?1", [id],
        |row| Ok((row.get::<_,u32>(0)?, row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,
            row.get::<_,String>(4)?,row.get::<_,String>(5)?,row.get::<_,String>(6)?,row.get::<_,i64>(7)?,row.get::<_,Vec<u8>>(8)?)))
        .optional().map_err(storage)?.ok_or_else(|| RefreshError::refused("aumlok:ceremony-unknown"))?;
    let (
        version,
        state,
        principal,
        subject,
        old_sha256,
        new_sha256,
        json,
        expires_at,
        phrase_cipher,
    ) = ceremony;
    if version != 1 {
        return Err(RefreshError::refused("aumlok:refresh-version"));
    }
    let envelope = Envelope::from_canonical_json(&json).map_err(|_| corrupt())?;
    if envelope_sha256(&envelope) != new_sha256 {
        return Err(corrupt());
    }
    Ok(Ceremony {
        record: RefreshRecord {
            ceremony_id: id.into(),
            subject,
            old_envelope_sha256: old_sha256,
            new_envelope_sha256: new_sha256,
            envelope,
        },
        state,
        principal,
        expires_at,
        phrase_cipher,
    })
}

fn validate_principal_time(principal: &str, now: i64) -> Result<(), RefreshError> {
    if principal.is_empty() || principal.len() > 256 || now < 0 {
        return Err(RefreshError::refused("aumlok:refresh-input"));
    }
    Ok(())
}

fn check_live(ceremony: &Ceremony, principal: &str) -> Result<(), RefreshError> {
    if ceremony.principal != principal {
        return Err(RefreshError::refused("aumlok:ceremony-principal"));
    }
    if ceremony.state == "EXPIRED" {
        return Err(RefreshError::refused("aumlok:ceremony-expired"));
    }
    if ceremony.state != "LIVE" {
        return Err(RefreshError::refused("aumlok:ceremony-spent"));
    }
    Ok(())
}

fn check_rate(connection: &Connection, principal: &str, now: i64) -> Result<(), RefreshError> {
    let guesses: Option<(i64, i64)> = connection
        .query_row(
            "SELECT window_start,failures FROM aumlok_phrase_guesses WHERE principal=?1",
            [principal],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    if guesses.is_some_and(|(start, count)| {
        count >= MAX_FAILURES && now.saturating_sub(start) < GUESS_WINDOW_MS
    }) {
        return Err(RefreshError::refused("aumlok:phrase-rate-limited"));
    }
    Ok(())
}

fn wrong_guess<T>(
    transaction: Transaction<'_>,
    principal: &str,
    now: i64,
    error: RefreshError,
) -> Result<T, RefreshError> {
    record_wrong_guess(&transaction, principal, now)?;
    transaction.commit().map_err(storage)?;
    Err(error)
}

fn record_wrong_guess(
    connection: &Connection,
    principal: &str,
    now: i64,
) -> Result<(), RefreshError> {
    connection.execute("INSERT INTO aumlok_phrase_guesses VALUES(?1,?2,1)
        ON CONFLICT(principal) DO UPDATE SET failures=CASE WHEN ?2-window_start>=60000 THEN 1 ELSE failures+1 END,
        window_start=CASE WHEN ?2-window_start>=60000 THEN ?2 ELSE window_start END", params![principal,now]).map_err(storage)?;
    Ok(())
}

fn open_root(
    current: &CurrentEnvelope,
    phrase: &Phrase,
) -> Result<Zeroizing<[u8; 32]>, RefreshError> {
    let root = open(&current.envelope, phrase)
        .map_err(|_| RefreshError::refused("aumlok:current-phrase"))?;
    if subject_from_root(&root) != current.subject {
        return Err(corrupt());
    }
    Ok(root)
}

fn phrase_cipher(root: &[u8; 32]) -> Result<XChaCha20Poly1305, RefreshError> {
    let mut digest = Sha256::new();
    digest.update(b"aukora:aumlok-refresh-phrase-key:v1\0");
    digest.update(root);
    let key = Zeroizing::new(<[u8; 32]>::from(digest.finalize()));
    XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| corrupt())
}

fn protect_phrase(root: &[u8; 32], phrase: &Phrase, id: &str) -> Result<Vec<u8>, RefreshError> {
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| RefreshError::refused("aumlok:random-unavailable"))?;
    let mut bytes = Zeroizing::new(phrase.as_str().as_bytes().to_vec());
    phrase_cipher(root)?
        .encrypt_in_place(&XNonce::from(nonce), id.as_bytes(), &mut *bytes)
        .map_err(|_| corrupt())?;
    Ok([nonce.as_slice(), bytes.as_slice()].concat())
}

fn recover_phrase(root: &[u8; 32], ceremony: &Ceremony) -> Result<Phrase, RefreshError> {
    if !(41..=1040).contains(&ceremony.phrase_cipher.len()) {
        return Err(corrupt());
    }
    let nonce: [u8; 24] = ceremony.phrase_cipher[..24]
        .try_into()
        .map_err(|_| corrupt())?;
    let mut bytes = Zeroizing::new(ceremony.phrase_cipher[24..].to_vec());
    phrase_cipher(root)?
        .decrypt_in_place(
            &XNonce::from(nonce),
            ceremony.record.ceremony_id.as_bytes(),
            &mut *bytes,
        )
        .map_err(|_| corrupt())?;
    let text = std::str::from_utf8(&bytes).map_err(|_| corrupt())?;
    Phrase::parse(text).map_err(|_| corrupt())
}

fn draw_replacement(
    current: &Phrase,
    mut draw: impl FnMut() -> Result<Phrase, crate::PhraseError>,
) -> Result<Phrase, RefreshError> {
    let mut phrase = draw().map_err(|error| RefreshError::refused(error.code()))?;
    while phrase == *current {
        phrase = draw().map_err(|error| RefreshError::refused(error.code()))?;
    }
    Ok(phrase)
}

enum RefreshPhrase<'a> {
    Parsed(&'a Phrase),
    Typed(&'a str),
}

impl BindingStore {
    /// Return only this session's live ceremony, without opening its phrase.
    pub fn live_refresh(
        &mut self,
        principal: &str,
        now: i64,
    ) -> Result<Option<LiveRefresh>, RefreshError> {
        validate_principal_time(principal, now)?;
        self.recover_refresh(now)?;
        self.connection
            .query_row(
                "SELECT id,expires_at FROM aumlok_refresh WHERE state='LIVE' AND principal=?1",
                [principal],
                |row| {
                    Ok(LiveRefresh {
                        ceremony_id: row.get(0)?,
                        expires_at: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(storage)
    }

    /// Other sessions receive only the retry time, never the ceremony or phrase.
    pub fn other_live_refresh_expiry(
        &mut self,
        principal: &str,
        now: i64,
    ) -> Result<Option<i64>, RefreshError> {
        validate_principal_time(principal, now)?;
        self.recover_refresh(now)?;
        self.connection
            .query_row(
                "SELECT expires_at FROM aumlok_refresh WHERE state='LIVE' AND principal<>?1",
                [principal],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)
    }

    /// Committed retries reveal the subject only to the ceremony's session.
    pub fn committed_refresh_subject(
        &self,
        id: &str,
        principal: &str,
        now: i64,
    ) -> Result<Option<String>, RefreshError> {
        validate_principal_time(principal, now)?;
        let ceremony = read_ceremony(&self.connection, id)?;
        if ceremony.principal != principal {
            return Err(RefreshError::refused("aumlok:ceremony-principal"));
        }
        Ok((ceremony.state == "COMMITTED").then_some(ceremony.record.subject))
    }

    pub fn parse_refresh_phrase(
        &mut self,
        principal: &str,
        text: &str,
        now: i64,
    ) -> Result<Phrase, RefreshError> {
        validate_principal_time(principal, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        check_rate(&transaction, principal, now)?;
        match Phrase::parse(text) {
            Ok(phrase) => Ok(phrase),
            Err(_) => wrong_guess(
                transaction,
                principal,
                now,
                RefreshError::refused("aumlok:current-phrase"),
            ),
        }
    }

    /// Persist the displayed phrase encrypted under the opened root, never in plaintext.
    pub fn prepare_refresh(
        &mut self,
        principal: &str,
        current_phrase: &Phrase,
        proof: Option<VerifiedRefreshApproval>,
        now: i64,
        expires_at: i64,
        kdf: KdfParams,
    ) -> Result<RefreshPreparation, RefreshError> {
        self.prepare_refresh_at(
            principal,
            current_phrase,
            proof,
            now,
            expires_at,
            kdf,
            |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_refresh_at(
        &mut self,
        principal: &str,
        current_phrase: &Phrase,
        proof: Option<VerifiedRefreshApproval>,
        now: i64,
        expires_at: i64,
        kdf: KdfParams,
        step: impl FnMut(Step) -> Result<(), RefreshError>,
    ) -> Result<RefreshPreparation, RefreshError> {
        self.prepare_refresh_with_at(
            principal,
            RefreshPhrase::Parsed(current_phrase),
            proof,
            now,
            expires_at,
            kdf,
            |_| Ok(()),
            |_, _| Ok(()),
            step,
        )
    }

    /// Spend the supervisor assertion and append its start fact with the prepared phrase.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_refresh_with(
        &mut self,
        principal: &str,
        current_phrase: &Phrase,
        proof: Option<VerifiedRefreshApproval>,
        now: i64,
        expires_at: i64,
        kdf: KdfParams,
        start: impl FnOnce(&Transaction<'_>, &RefreshRecord) -> Result<(), RefreshError>,
    ) -> Result<RefreshPreparation, RefreshError> {
        self.prepare_refresh_with_at(
            principal,
            RefreshPhrase::Parsed(current_phrase),
            proof,
            now,
            expires_at,
            kdf,
            |_| Ok(()),
            start,
            |_| Ok(()),
        )
    }

    /// Spend verified approval together with preparation or a refused phrase guess.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_refresh_authorized(
        &mut self,
        principal: &str,
        current_phrase: &str,
        proof: Option<VerifiedRefreshApproval>,
        now: i64,
        expires_at: i64,
        kdf: KdfParams,
        authorize: impl FnOnce(&Transaction<'_>) -> Result<(), RefreshError>,
        start: impl FnOnce(&Transaction<'_>, &RefreshRecord) -> Result<(), RefreshError>,
    ) -> Result<RefreshPreparation, RefreshError> {
        self.prepare_refresh_with_at(
            principal,
            RefreshPhrase::Typed(current_phrase),
            proof,
            now,
            expires_at,
            kdf,
            authorize,
            start,
            |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_refresh_with_at(
        &mut self,
        principal: &str,
        current_phrase: RefreshPhrase<'_>,
        proof: Option<VerifiedRefreshApproval>,
        now: i64,
        expires_at: i64,
        kdf: KdfParams,
        authorize: impl FnOnce(&Transaction<'_>) -> Result<(), RefreshError>,
        start: impl FnOnce(&Transaction<'_>, &RefreshRecord) -> Result<(), RefreshError>,
        mut step: impl FnMut(Step) -> Result<(), RefreshError>,
    ) -> Result<RefreshPreparation, RefreshError> {
        validate_principal_time(principal, now)?;
        if expires_at <= now || expires_at.saturating_sub(now) > MAX_CEREMONY_MS {
            return Err(RefreshError::refused("aumlok:refresh-input"));
        }
        let proof = proof.ok_or_else(|| RefreshError::refused("aumlok:passkey-required"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let current = current(&transaction)?;
        if proof.principal != principal
            || proof.subject != current.subject
            || proof.envelope_sha256 != current.sha256
            || proof.assertion_id.is_empty()
            || proof.assertion_id.len() > 256
        {
            return Err(RefreshError::refused("aumlok:refresh-proof"));
        }
        let used: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM aumlok_refresh WHERE assertion_id=?1)",
                [&proof.assertion_id],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if used {
            return Err(RefreshError::refused("aumlok:refresh-proof-spent"));
        }
        transaction
            .execute(
                "UPDATE aumlok_refresh SET state='EXPIRED' WHERE state='LIVE' AND expires_at<=?1",
                [now],
            )
            .map_err(storage)?;
        let live: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM aumlok_refresh WHERE state='LIVE')",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if live {
            transaction.commit().map_err(storage)?;
            return Err(RefreshError::refused("aumlok:refresh-live"));
        }
        authorize(&transaction)?;
        if let Err(error) = check_rate(&transaction, principal, now) {
            transaction.commit().map_err(storage)?;
            return Err(error);
        }
        let parsed;
        let current_phrase = match current_phrase {
            RefreshPhrase::Parsed(phrase) => phrase,
            RefreshPhrase::Typed(text) => {
                parsed = match Phrase::parse(text) {
                    Ok(phrase) => phrase,
                    Err(_) => {
                        return wrong_guess(
                            transaction,
                            principal,
                            now,
                            RefreshError::refused("aumlok:current-phrase"),
                        )
                    }
                };
                &parsed
            }
        };
        let root = match open_root(&current, current_phrase) {
            Ok(root) => root,
            Err(error) if error.code() == "aumlok:current-phrase" => {
                return wrong_guess(transaction, principal, now, error)
            }
            Err(error) => return Err(error),
        };
        let phrase = draw_replacement(current_phrase, Phrase::draw)?;
        let envelope =
            reseal(&root, &phrase, kdf).map_err(|error| RefreshError::refused(error.code()))?;
        let mut random = [0; 16];
        getrandom::fill(&mut random)
            .map_err(|_| RefreshError::refused("aumlok:random-unavailable"))?;
        let id = hex::encode(random);
        let protected = protect_phrase(&root, &phrase, &id)?;
        transaction
            .execute(
                "INSERT INTO aumlok_refresh VALUES(?1,1,'LIVE',?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    id,
                    principal,
                    proof.assertion_id,
                    current.subject,
                    current.sha256,
                    envelope_sha256(&envelope),
                    envelope.to_canonical_json(),
                    protected,
                    now,
                    expires_at
                ],
            )
            .map_err(storage)?;
        step(Step::PreparedWritten)?;
        start(
            &transaction,
            &RefreshRecord {
                ceremony_id: id.clone(),
                subject: current.subject,
                old_envelope_sha256: current.sha256,
                new_envelope_sha256: envelope_sha256(&envelope),
                envelope,
            },
        )?;
        transaction.commit().map_err(storage)?;
        step(Step::PreparedCommitted)?;
        Ok(RefreshPreparation {
            ceremony_id: id,
            phrase,
            entropy_bits: entropy().minimum_bits,
            expires_at,
        })
    }

    pub fn resume_refresh(
        &mut self,
        id: &str,
        principal: &str,
        current_phrase: &Phrase,
        now: i64,
    ) -> Result<RefreshPreparation, RefreshError> {
        validate_principal_time(principal, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let ceremony = read_ceremony(&transaction, id)?;
        check_live(&ceremony, principal)?;
        if now >= ceremony.expires_at {
            expire(transaction, id)?;
            return Err(RefreshError::refused("aumlok:ceremony-expired"));
        }
        check_rate(&transaction, principal, now)?;
        let current = current(&transaction)?;
        check_source(&ceremony, &current)?;
        let root = match open_root(&current, current_phrase) {
            Ok(root) => root,
            Err(error) if error.code() == "aumlok:current-phrase" => {
                return wrong_guess(transaction, principal, now, error)
            }
            Err(error) => return Err(error),
        };
        let phrase = recover_phrase(&root, &ceremony)?;
        Ok(RefreshPreparation {
            ceremony_id: id.into(),
            phrase,
            entropy_bits: entropy().minimum_bits,
            expires_at: ceremony.expires_at,
        })
    }

    /// The callback appends the terminal Aura row using this transaction; it must have no external effects.
    pub fn confirm_refresh<F>(
        &mut self,
        id: &str,
        principal: &str,
        current_phrase: &Phrase,
        typed: &[String],
        now: i64,
        append_aura: F,
    ) -> Result<RefreshRecord, RefreshError>
    where
        F: FnOnce(&Transaction<'_>, &RefreshRecord) -> Result<(), RefreshError>,
    {
        self.confirm_refresh_at(
            id,
            principal,
            current_phrase,
            typed,
            now,
            append_aura,
            |_| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn confirm_refresh_at<F>(
        &mut self,
        id: &str,
        principal: &str,
        current_phrase: &Phrase,
        typed: &[String],
        now: i64,
        append_aura: F,
        mut step: impl FnMut(Step) -> Result<(), RefreshError>,
    ) -> Result<RefreshRecord, RefreshError>
    where
        F: FnOnce(&Transaction<'_>, &RefreshRecord) -> Result<(), RefreshError>,
    {
        validate_principal_time(principal, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let ceremony = read_ceremony(&transaction, id)?;
        check_live(&ceremony, principal)?;
        if now >= ceremony.expires_at {
            expire(transaction, id)?;
            return Err(RefreshError::refused("aumlok:ceremony-expired"));
        }
        check_rate(&transaction, principal, now)?;
        let current = current(&transaction)?;
        check_source(&ceremony, &current)?;
        let root = match open_root(&current, current_phrase) {
            Ok(root) => root,
            Err(error) if error.code() == "aumlok:current-phrase" => {
                record_wrong_guess(&transaction, principal, now)?;
                transaction.commit().map_err(storage)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let expected = recover_phrase(&root, &ceremony)?;
        let mismatch = expected
            .as_str()
            .split(' ')
            .enumerate()
            .find_map(|(i, word)| {
                (typed.get(i).map(String::as_str) != Some(word)).then_some(i + 1)
            });
        if let Some(position) = mismatch {
            record_wrong_guess(&transaction, principal, now)?;
            transaction.commit().map_err(storage)?;
            return Err(RefreshError::mismatch(position));
        }
        if typed.len() != 7 {
            record_wrong_guess(&transaction, principal, now)?;
            transaction.commit().map_err(storage)?;
            return Err(RefreshError::refused("aumlok:phrase-word-count"));
        }
        let new_root = open(&ceremony.record.envelope, &expected).map_err(|_| corrupt())?;
        if *new_root != *root {
            return Err(corrupt());
        }
        let changed = transaction
            .execute(
                "UPDATE aumlok_refresh SET state='COMMITTING' WHERE id=?1 AND state='LIVE'",
                [id],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(RefreshError::refused("aumlok:ceremony-spent"));
        }
        step(Step::Confirming)?;
        transaction
            .execute(
                "INSERT INTO aumlok_retired_envelope VALUES(?1,?2,?3,?4,?5)",
                params![
                    current.sha256,
                    current.envelope.to_canonical_json(),
                    current.subject,
                    now,
                    id
                ],
            )
            .map_err(storage)?;
        step(Step::Retired)?;
        let changed = transaction
            .execute(
                "UPDATE aumlok_current_envelope SET envelope_sha256=?1,envelope=?2
            WHERE id=1 AND envelope_sha256=?3",
                params![
                    ceremony.record.new_envelope_sha256,
                    ceremony.record.envelope.to_canonical_json(),
                    current.sha256
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(RefreshError::refused("aumlok:refresh-stale"));
        }
        step(Step::Switched)?;
        append_aura(&transaction, &ceremony.record)?;
        step(Step::AuraWritten)?;
        transaction
            .execute(
                "UPDATE aumlok_refresh SET state='COMMITTED' WHERE id=?1 AND state='COMMITTING'",
                [id],
            )
            .map_err(storage)?;
        step(Step::CommittedWritten)?;
        transaction.commit().map_err(storage)?;
        step(Step::Committed)?;
        Ok(ceremony.record)
    }

    pub fn cancel_refresh(
        &mut self,
        id: &str,
        principal: &str,
        now: i64,
    ) -> Result<Option<String>, RefreshError> {
        self.cancel_refresh_at(id, principal, now, |_| Ok(()))
    }

    fn cancel_refresh_at(
        &mut self,
        id: &str,
        principal: &str,
        now: i64,
        mut step: impl FnMut(Step) -> Result<(), RefreshError>,
    ) -> Result<Option<String>, RefreshError> {
        validate_principal_time(principal, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let ceremony = read_ceremony(&transaction, id)?;
        if ceremony.principal != principal {
            return Err(RefreshError::refused("aumlok:ceremony-principal"));
        }
        if ceremony.state == "COMMITTED" {
            return Ok(Some(ceremony.record.subject));
        }
        check_live(&ceremony, principal)?;
        if now >= ceremony.expires_at {
            expire(transaction, id)?;
            return Err(RefreshError::refused("aumlok:ceremony-expired"));
        }
        transaction
            .execute(
                "UPDATE aumlok_refresh SET state='CANCELLED' WHERE id=?1 AND state='LIVE'",
                [id],
            )
            .map_err(storage)?;
        step(Step::CancelledWritten)?;
        transaction.commit().map_err(storage)?;
        step(Step::Cancelled)?;
        Ok(None)
    }

    /// Recovery preserves live words and never retries the Aura callback.
    pub fn recover_refresh(&mut self, now: i64) -> Result<(), RefreshError> {
        self.recover_refresh_at(now, |_| Ok(()))
    }

    fn recover_refresh_at(
        &mut self,
        now: i64,
        mut step: impl FnMut(Step) -> Result<(), RefreshError>,
    ) -> Result<(), RefreshError> {
        validate_principal_time("recovery", now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let incomplete: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM aumlok_refresh WHERE state='COMMITTING')",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if incomplete {
            return Err(corrupt());
        }
        transaction
            .execute(
                "UPDATE aumlok_refresh SET state='EXPIRED' WHERE state='LIVE' AND expires_at<=?1",
                [now],
            )
            .map_err(storage)?;
        step(Step::ExpiredWritten)?;
        transaction.commit().map_err(storage)?;
        step(Step::Expired)?;
        Ok(())
    }

    /// Node unlock selects only the current envelope; retired backups have no node authority.
    pub fn open_current(
        &mut self,
        sha256: &str,
        principal: &str,
        phrase: &Phrase,
        now: i64,
    ) -> Result<Zeroizing<[u8; 32]>, RefreshError> {
        validate_principal_time(principal, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let retired: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM aumlok_retired_envelope WHERE envelope_sha256=?1)",
                [sha256],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if retired {
            return Err(RefreshError::refused("aumlok:envelope-retired"));
        }
        let current = current(&transaction)?;
        if current.sha256 != sha256 {
            return Err(RefreshError::refused("aumlok:envelope-not-current"));
        }
        check_rate(&transaction, principal, now)?;
        match open_root(&current, phrase) {
            Ok(root) => Ok(root),
            Err(error) if error.code() == "aumlok:current-phrase" => {
                record_wrong_guess(&transaction, principal, now)?;
                transaction.commit().map_err(storage)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
}

fn check_source(ceremony: &Ceremony, current: &CurrentEnvelope) -> Result<(), RefreshError> {
    if ceremony.record.old_envelope_sha256 != current.sha256
        || ceremony.record.subject != current.subject
    {
        return Err(RefreshError::refused("aumlok:refresh-stale"));
    }
    Ok(())
}

fn expire(transaction: Transaction<'_>, id: &str) -> Result<(), RefreshError> {
    transaction
        .execute(
            "UPDATE aumlok_refresh SET state='EXPIRED' WHERE id=?1 AND state='LIVE'",
            [id],
        )
        .map_err(storage)?;
    transaction.commit().map_err(storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{BindingOutcome, BindingRecord};
    use std::path::Path;
    use std::process::Command;

    fn kdf() -> KdfParams {
        KdfParams {
            memory_kib: 32,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn bound(path: &Path) -> (BindingStore, Phrase, BindingRecord) {
        let mut store = BindingStore::open(path).unwrap();
        let phrase = Phrase::draw().unwrap();
        let binding = store.prepare(&phrase, kdf()).unwrap();
        store.confirm(&binding.subject).unwrap();
        let binding = match store
            .complete(&binding.subject, |_| Ok::<(), ()>(()))
            .unwrap()
        {
            BindingOutcome::Completed(binding) => binding,
            _ => panic!("binding failed"),
        };
        (store, phrase, binding)
    }

    fn proof(binding: &BindingRecord) -> VerifiedRefreshApproval {
        VerifiedRefreshApproval::new(
            "owner".into(),
            binding.subject.clone(),
            envelope_sha256(&binding.envelope),
            "assertion".into(),
        )
    }

    fn prepare(
        store: &mut BindingStore,
        phrase: &Phrase,
        binding: &BindingRecord,
    ) -> RefreshPreparation {
        store
            .prepare_refresh("owner", phrase, Some(proof(binding)), 1000, 2000, kdf())
            .unwrap()
    }

    fn words(phrase: &Phrase) -> Vec<String> {
        phrase.as_str().split(' ').map(str::to_owned).collect()
    }

    fn count(connection: &Connection, table: &str) -> i64 {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn approval(binding: &BindingRecord, id: &str) -> VerifiedRefreshApproval {
        VerifiedRefreshApproval::new(
            "owner".into(),
            binding.subject.clone(),
            envelope_sha256(&binding.envelope),
            id.into(),
        )
    }

    fn spend_test_approval(transaction: &Transaction<'_>, id: &str) -> Result<(), RefreshError> {
        transaction
            .execute("INSERT INTO test_authorizations VALUES(?1)", [id])
            .map_err(|_| RefreshError::refused("aumlok:refresh-proof-spent"))?;
        Ok(())
    }

    #[test]
    fn antibody_refresh_metadata_is_session_scoped_and_expiry_bounded() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("metadata.sqlite"));
        let preparation = prepare(&mut store, &old, &binding);
        assert_eq!(store.live_refresh("other", 1001).unwrap(), None);
        assert_eq!(
            store.live_refresh("owner", 1001).unwrap(),
            Some(LiveRefresh {
                ceremony_id: preparation.ceremony_id.clone(),
                expires_at: 2000
            })
        );
        assert_eq!(store.live_refresh("owner", 2000).unwrap(), None);
        assert_eq!(
            read_ceremony(&store.connection, &preparation.ceremony_id)
                .unwrap()
                .state,
            "EXPIRED"
        );
    }

    #[test]
    fn antibody_refresh_committed_status_survives_restart_without_phrase() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("committed-status.sqlite");
        let (mut store, old, binding) = bound(&path);
        let preparation = prepare(&mut store, &old, &binding);
        assert_eq!(
            store
                .committed_refresh_subject(&preparation.ceremony_id, "owner", 1001)
                .unwrap(),
            None
        );
        store
            .confirm_refresh(
                &preparation.ceremony_id,
                "owner",
                &old,
                &words(&preparation.phrase),
                1001,
                |_, _| Ok(()),
            )
            .unwrap();
        drop(store);
        let store = BindingStore::open(&path).unwrap();
        assert_eq!(
            store
                .committed_refresh_subject(&preparation.ceremony_id, "owner", 2001)
                .unwrap(),
            Some(binding.subject)
        );
        assert_eq!(
            store
                .committed_refresh_subject(&preparation.ceremony_id, "other", 2001)
                .unwrap_err()
                .code(),
            "aumlok:ceremony-principal"
        );
    }

    #[test]
    fn antibody_refresh_cancel_committed_returns_subject_without_repeating_effect() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("cancel-committed.sqlite");
        let (mut store, old, binding) = bound(&path);
        let preparation = prepare(&mut store, &old, &binding);
        store
            .confirm_refresh(
                &preparation.ceremony_id,
                "owner",
                &old,
                &words(&preparation.phrase),
                1001,
                |_, _| Ok(()),
            )
            .unwrap();
        drop(store);
        let mut store = BindingStore::open(&path).unwrap();
        assert_eq!(
            store
                .cancel_refresh(&preparation.ceremony_id, "owner", 2001)
                .unwrap(),
            Some(binding.subject)
        );
        assert_eq!(
            store
                .cancel_refresh(&preparation.ceremony_id, "other", 2001)
                .unwrap_err()
                .code(),
            "aumlok:ceremony-principal"
        );
        assert_eq!(count(&store.connection, "aumlok_retired_envelope"), 1);
    }

    #[test]
    fn antibody_refresh_other_session_retry_metadata_is_expiry_only() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("other-metadata.sqlite"));
        prepare(&mut store, &old, &binding);
        assert_eq!(
            store.other_live_refresh_expiry("owner", 1001).unwrap(),
            None
        );
        assert_eq!(
            store.other_live_refresh_expiry("other", 1001).unwrap(),
            Some(2000)
        );
        assert_eq!(
            store.other_live_refresh_expiry("other", 2000).unwrap(),
            None
        );
    }

    #[test]
    fn antibody_refresh_cancel_preserves_owner_and_refuses_other_session() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("cancel-owner.sqlite"));
        let preparation = prepare(&mut store, &old, &binding);
        assert_eq!(
            store
                .cancel_refresh(&preparation.ceremony_id, "other", 1001)
                .unwrap_err()
                .code(),
            "aumlok:ceremony-principal"
        );
        assert!(store.live_refresh("owner", 1001).unwrap().is_some());
        store
            .cancel_refresh(&preparation.ceremony_id, "owner", 1001)
            .unwrap();
        assert_eq!(store.live_refresh("owner", 1001).unwrap(), None);
        assert_eq!(store.binding().unwrap().unwrap().envelope, binding.envelope);
        assert!(store
            .open_current(&envelope_sha256(&binding.envelope), "owner", &old, 1001)
            .is_ok());
        assert_eq!(
            store
                .resume_refresh(&preparation.ceremony_id, "owner", &old, 1001)
                .err()
                .unwrap()
                .code(),
            "aumlok:ceremony-spent"
        );
        store
            .prepare_refresh(
                "owner",
                &old,
                Some(approval(&binding, "next")),
                1001,
                2001,
                kdf(),
            )
            .unwrap();
    }

    #[test]
    fn antibody_refresh_wrong_phrase_spends_authorization_with_guess() {
        let directory = tempfile::tempdir_in(".").unwrap();
        for malformed in [false, true] {
            let path = directory.path().join(format!("wrong-{malformed}.sqlite"));
            let (mut store, old, binding) = bound(&path);
            store
                .connection
                .execute_batch("CREATE TABLE test_authorizations(id TEXT PRIMARY KEY)")
                .unwrap();
            let wrong = loop {
                let phrase = Phrase::draw().unwrap();
                if phrase != old {
                    break phrase;
                }
            };
            let text = if malformed {
                "not a binding phrase"
            } else {
                wrong.as_str()
            };
            let refused = store.prepare_refresh_authorized(
                "owner",
                text,
                Some(approval(&binding, "wrong")),
                1000,
                2000,
                kdf(),
                |tx| spend_test_approval(tx, "wrong"),
                |_, _| panic!("a wrong current phrase must not start refresh"),
            );
            assert_eq!(refused.err().unwrap().code(), "aumlok:current-phrase");
            assert_eq!(count(&store.connection, "test_authorizations"), 1);
            assert_eq!(count(&store.connection, "aumlok_refresh"), 0);
            assert_eq!(
                store
                    .connection
                    .query_row(
                        "SELECT failures FROM aumlok_phrase_guesses WHERE principal='owner'",
                        [],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                1
            );
            let replay = store.prepare_refresh_authorized(
                "owner",
                old.as_str(),
                Some(approval(&binding, "wrong")),
                1001,
                2000,
                kdf(),
                |tx| spend_test_approval(tx, "wrong"),
                |_, _| Ok(()),
            );
            assert_eq!(replay.err().unwrap().code(), "aumlok:refresh-proof-spent");
            assert_eq!(count(&store.connection, "aumlok_refresh"), 0);
            store
                .prepare_refresh_authorized(
                    "owner",
                    old.as_str(),
                    Some(approval(&binding, "fresh")),
                    1001,
                    2000,
                    kdf(),
                    |tx| spend_test_approval(tx, "fresh"),
                    |_, _| Ok(()),
                )
                .unwrap();
            assert_eq!(count(&store.connection, "test_authorizations"), 2);
            assert_eq!(count(&store.connection, "aumlok_refresh"), 1);
        }
    }

    #[test]
    fn antibody_refresh_rate_refusal_spends_but_live_refusal_preserves_authorization() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("refusals.sqlite"));
        store
            .connection
            .execute_batch("CREATE TABLE test_authorizations(id TEXT PRIMARY KEY)")
            .unwrap();
        for attempt in 0..5 {
            let id = format!("wrong-{attempt}");
            let result = store.prepare_refresh_authorized(
                "owner",
                "not a binding phrase",
                Some(approval(&binding, &id)),
                1000,
                2000,
                kdf(),
                |tx| spend_test_approval(tx, &id),
                |_, _| Ok(()),
            );
            assert_eq!(result.err().unwrap().code(), "aumlok:current-phrase");
        }
        let limited = store.prepare_refresh_authorized(
            "owner",
            old.as_str(),
            Some(approval(&binding, "limited")),
            1000,
            2000,
            kdf(),
            |tx| spend_test_approval(tx, "limited"),
            |_, _| Ok(()),
        );
        assert_eq!(limited.err().unwrap().code(), "aumlok:phrase-rate-limited");
        assert_eq!(count(&store.connection, "test_authorizations"), 6);
        assert_eq!(
            store
                .connection
                .query_row("SELECT failures FROM aumlok_phrase_guesses", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            5
        );
        store
            .prepare_refresh_authorized(
                "owner",
                old.as_str(),
                Some(approval(&binding, "first")),
                61000,
                62000,
                kdf(),
                |tx| spend_test_approval(tx, "first"),
                |_, _| Ok(()),
            )
            .unwrap();
        let live = store.prepare_refresh_authorized(
            "owner",
            old.as_str(),
            Some(approval(&binding, "second")),
            61000,
            62000,
            kdf(),
            |tx| spend_test_approval(tx, "second"),
            |_, _| Ok(()),
        );
        assert_eq!(live.err().unwrap().code(), "aumlok:refresh-live");
        assert_eq!(count(&store.connection, "test_authorizations"), 7);
        assert_eq!(count(&store.connection, "aumlok_refresh"), 1);
    }

    #[test]
    fn antibody_refresh_authorization_and_start_errors_roll_back_spend() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("authorized.sqlite"));
        store
            .connection
            .execute_batch("CREATE TABLE test_authorizations(id TEXT PRIMARY KEY)")
            .unwrap();
        let authorization_error = store.prepare_refresh_authorized(
            "owner",
            old.as_str(),
            Some(approval(&binding, "failure")),
            1000,
            2000,
            kdf(),
            |tx| {
                spend_test_approval(tx, "failure")?;
                Err(RefreshError::refused("aumlok:test-authorization-failure"))
            },
            |_, _| panic!("failed authorization must not start refresh"),
        );
        assert_eq!(
            authorization_error.err().unwrap().code(),
            "aumlok:test-authorization-failure"
        );
        assert_eq!(count(&store.connection, "test_authorizations"), 0);
        assert_eq!(count(&store.connection, "aumlok_phrase_guesses"), 0);
        assert_eq!(count(&store.connection, "aumlok_refresh"), 0);
        let start_error = store.prepare_refresh_authorized(
            "owner",
            old.as_str(),
            Some(approval(&binding, "failure")),
            1000,
            2000,
            kdf(),
            |tx| spend_test_approval(tx, "failure"),
            |_, _| Err(RefreshError::refused("aumlok:test-start-failure")),
        );
        assert_eq!(
            start_error.err().unwrap().code(),
            "aumlok:test-start-failure"
        );
        assert_eq!(count(&store.connection, "test_authorizations"), 0);
        assert_eq!(count(&store.connection, "aumlok_refresh"), 0);
        let prepared = store
            .prepare_refresh_authorized(
                "owner",
                old.as_str(),
                Some(approval(&binding, "failure")),
                1000,
                2000,
                kdf(),
                |tx| spend_test_approval(tx, "failure"),
                |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!(count(&store.connection, "test_authorizations"), 1);
        assert_eq!(count(&store.connection, "aumlok_refresh"), 1);
        assert!(
            store
                .resume_refresh(&prepared.ceremony_id, "owner", &old, 1001)
                .unwrap()
                .phrase
                == prepared.phrase
        );
    }

    #[test]
    fn antibody_refresh_start_callback_is_atomic_with_preparation() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("callback.sqlite"));
        store
            .connection
            .execute_batch("CREATE TABLE test_start(id TEXT PRIMARY KEY)")
            .unwrap();
        let result = store.prepare_refresh_with(
            "owner",
            &old,
            Some(proof(&binding)),
            1000,
            2000,
            kdf(),
            |tx, record| {
                tx.execute("INSERT INTO test_start VALUES(?1)", [&record.ceremony_id])
                    .map_err(storage)?;
                Err(RefreshError::refused("aumlok:test-start-refused"))
            },
        );
        assert_eq!(result.err().unwrap().code(), "aumlok:test-start-refused");
        assert_eq!(count(&store.connection, "aumlok_refresh"), 0);
        assert_eq!(count(&store.connection, "test_start"), 0);
        let prep = store
            .prepare_refresh_with(
                "owner",
                &old,
                Some(proof(&binding)),
                1000,
                2000,
                kdf(),
                |tx, record| {
                    tx.execute("INSERT INTO test_start VALUES(?1)", [&record.ceremony_id])
                        .map_err(storage)?;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(count(&store.connection, "test_start"), 1);
        assert_eq!(
            store
                .resume_refresh(&prep.ceremony_id, "owner", &old, 1001)
                .unwrap()
                .phrase,
            prep.phrase
        );
    }

    #[test]
    fn antibody_malformed_refresh_phrase_guesses_are_session_limited() {
        let mut store = BindingStore::in_memory().unwrap();
        for _ in 0..5 {
            assert_eq!(
                store
                    .parse_refresh_phrase("session-a", "not a phrase", 1000)
                    .err()
                    .unwrap()
                    .code(),
                "aumlok:current-phrase"
            );
        }
        assert_eq!(
            store
                .parse_refresh_phrase("session-a", "not a phrase", 1000)
                .err()
                .unwrap()
                .code(),
            "aumlok:phrase-rate-limited"
        );
        assert_eq!(
            store
                .parse_refresh_phrase("session-b", "not a phrase", 1000)
                .err()
                .unwrap()
                .code(),
            "aumlok:current-phrase"
        );
        assert_eq!(
            store
                .parse_refresh_phrase("session-a", "not a phrase", 61000)
                .err()
                .unwrap()
                .code(),
            "aumlok:current-phrase"
        );
    }

    const STEPS: [Step; 12] = [
        Step::PreparedWritten,
        Step::PreparedCommitted,
        Step::Confirming,
        Step::Retired,
        Step::Switched,
        Step::AuraWritten,
        Step::CommittedWritten,
        Step::Committed,
        Step::CancelledWritten,
        Step::Cancelled,
        Step::ExpiredWritten,
        Step::Expired,
    ];

    #[test]
    #[ignore = "child process for crash_at_every_transition_recovers_one_current_envelope"]
    fn crash_child() {
        let path = std::env::var("AUMLOK_REFRESH_TEST_DB").unwrap();
        let target = std::env::var("AUMLOK_REFRESH_TEST_STEP").unwrap();
        let phrase = Phrase::parse(&std::env::var("AUMLOK_REFRESH_TEST_PHRASE").unwrap()).unwrap();
        let mut store = BindingStore::open(path).unwrap();
        let binding = store.binding().unwrap().unwrap();
        let crash = |step: Step| -> Result<(), RefreshError> {
            if format!("{step:?}") == target {
                std::process::exit(86);
            }
            Ok(())
        };
        match target.as_str() {
            "PreparedWritten" | "PreparedCommitted" => {
                store
                    .prepare_refresh_at(
                        "owner",
                        &phrase,
                        Some(proof(&binding)),
                        1000,
                        2000,
                        kdf(),
                        crash,
                    )
                    .unwrap();
            }
            "CancelledWritten" | "Cancelled" => {
                let id: String = store
                    .connection
                    .query_row("SELECT id FROM aumlok_refresh", [], |row| row.get(0))
                    .unwrap();
                store.cancel_refresh_at(&id, "owner", 1001, crash).unwrap();
            }
            "ExpiredWritten" | "Expired" => {
                store.recover_refresh_at(2000, crash).unwrap();
            }
            _ => {
                let id: String = store
                    .connection
                    .query_row("SELECT id FROM aumlok_refresh", [], |row| row.get(0))
                    .unwrap();
                let displayed = store.resume_refresh(&id, "owner", &phrase, 1001).unwrap();
                store
                    .confirm_refresh_at(
                        &id,
                        "owner",
                        &phrase,
                        &words(&displayed.phrase),
                        1001,
                        |transaction, record| {
                            transaction
                                .execute(
                                    "INSERT INTO test_aura VALUES(?1,?2,?3,?4)",
                                    params![
                                        record.ceremony_id,
                                        record.kind(),
                                        record.phase(),
                                        record.body()
                                    ],
                                )
                                .map_err(storage)?;
                            Ok(())
                        },
                        crash,
                    )
                    .unwrap();
            }
        }
        panic!("crash checkpoint missed");
    }

    #[test]
    fn crash_at_every_transition_recovers_one_current_envelope() {
        for step in STEPS {
            let directory = tempfile::tempdir_in(".").unwrap();
            let path = directory.path().join("crash.sqlite");
            let (mut store, old, binding) = bound(&path);
            store
                .connection
                .execute_batch(
                    "CREATE TABLE test_aura(op TEXT PRIMARY KEY,kind TEXT,phase TEXT,body TEXT)",
                )
                .unwrap();
            let preparation = if matches!(step, Step::PreparedWritten | Step::PreparedCommitted) {
                None
            } else {
                Some(prepare(&mut store, &old, &binding))
            };
            drop(store);
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "refresh::tests::crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("AUMLOK_REFRESH_TEST_DB", &path)
                .env("AUMLOK_REFRESH_TEST_STEP", format!("{step:?}"))
                .env("AUMLOK_REFRESH_TEST_PHRASE", old.as_str())
                .output()
                .unwrap();
            assert_eq!(
                child.status.code(),
                Some(86),
                "{step:?}: {}",
                String::from_utf8_lossy(&child.stderr)
            );
            let mut recovered = BindingStore::open(&path).unwrap();
            let before_recovery: Option<String> = recovered
                .connection
                .query_row("SELECT state FROM aumlok_refresh", [], |row| row.get(0))
                .optional()
                .unwrap();
            let now = if matches!(step, Step::Expired | Step::ExpiredWritten) {
                2000
            } else {
                1001
            };
            recovered.recover_refresh(now).unwrap();
            recovered.recover_refresh(now).unwrap();
            assert_eq!(
                count(&recovered.connection, "aumlok_current_envelope"),
                1,
                "{step:?}"
            );
            let current = recovered.binding().unwrap().unwrap();
            assert_eq!(current.subject, binding.subject);
            let committed = step == Step::Committed;
            assert_eq!(
                count(&recovered.connection, "aumlok_retired_envelope"),
                i64::from(committed),
                "{step:?}"
            );
            assert_eq!(
                count(&recovered.connection, "test_aura"),
                i64::from(committed),
                "{step:?}"
            );
            if let Some(preparation) = preparation {
                assert_eq!(
                    open(&current.envelope, &old).is_ok(),
                    !committed,
                    "{step:?}"
                );
                assert_eq!(
                    open(&current.envelope, &preparation.phrase).is_ok(),
                    committed,
                    "{step:?}"
                );
                if committed {
                    assert_eq!(
                        recovered
                            .open_current(&envelope_sha256(&binding.envelope), "owner", &old, now)
                            .unwrap_err()
                            .code(),
                        "aumlok:envelope-retired"
                    );
                } else if !matches!(step, Step::Cancelled | Step::Expired | Step::ExpiredWritten) {
                    let resumed = recovered
                        .resume_refresh(&preparation.ceremony_id, "owner", &old, now)
                        .unwrap();
                    assert_eq!(resumed.phrase, preparation.phrase, "{step:?}");
                }
                match step {
                    Step::CancelledWritten | Step::ExpiredWritten => {
                        assert_eq!(before_recovery.as_deref(), Some("LIVE"))
                    }
                    Step::Cancelled => assert_eq!(before_recovery.as_deref(), Some("CANCELLED")),
                    Step::Expired => assert_eq!(before_recovery.as_deref(), Some("EXPIRED")),
                    Step::Committed => assert_eq!(before_recovery.as_deref(), Some("COMMITTED")),
                    _ => assert_eq!(before_recovery.as_deref(), Some("LIVE")),
                }
            } else {
                assert_eq!(current.envelope, binding.envelope);
                assert_eq!(
                    count(&recovered.connection, "aumlok_refresh"),
                    i64::from(step == Step::PreparedCommitted)
                );
            }
        }
    }

    #[test]
    fn sqlite_retain_current_retired_and_ceremony_and_forbid_rewrites() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("guards.sqlite"));
        let preparation = prepare(&mut store, &old, &binding);
        for sql in ["DELETE FROM aumlok_refresh", "UPDATE aumlok_refresh SET state='COMMITTED'",
            "UPDATE aumlok_refresh SET principal='other',state='CANCELLED'",
            "UPDATE aumlok_refresh SET version=2,state='CANCELLED'",
            "INSERT OR REPLACE INTO aumlok_refresh SELECT * FROM aumlok_refresh",
            "DELETE FROM aumlok_current_envelope",
            "UPDATE aumlok_current_envelope SET envelope_sha256='forged'",
            "INSERT OR REPLACE INTO aumlok_current_envelope SELECT * FROM aumlok_current_envelope",
            "INSERT INTO aumlok_retired_envelope SELECT envelope_sha256,envelope,subject,1001,'forged' FROM aumlok_current_envelope"] {
            assert!(store.connection.execute_batch(sql).is_err(),"accepted {sql}");
        }
        store
            .confirm_refresh(
                &preparation.ceremony_id,
                "owner",
                &old,
                &words(&preparation.phrase),
                1001,
                |_, _| Ok(()),
            )
            .unwrap();
        for sql in ["DELETE FROM aumlok_retired_envelope", "UPDATE aumlok_retired_envelope SET retired_at=0",
            "INSERT OR REPLACE INTO aumlok_retired_envelope SELECT * FROM aumlok_retired_envelope",
            "UPDATE aumlok_refresh SET state='LIVE'", "DELETE FROM aumlok_refresh",
            "UPDATE aumlok_current_envelope SET envelope=(SELECT envelope FROM aumlok_retired_envelope),envelope_sha256=(SELECT envelope_sha256 FROM aumlok_retired_envelope)"] {
            assert!(store.connection.execute_batch(sql).is_err(),"accepted {sql}");
        }
        let retired_at: i64 = store
            .connection
            .query_row(
                "SELECT retired_at FROM aumlok_retired_envelope",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retired_at, 1001);
        assert_eq!(count(&store.connection, "aumlok_current_envelope"), 1);
    }

    #[test]
    fn phrase_is_encrypted_authenticated_and_pinned_to_ceremony() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("secret.sqlite"));
        let preparation = prepare(&mut store, &old, &binding);
        let ceremony = read_ceremony(&store.connection, &preparation.ceremony_id).unwrap();
        assert!(!ceremony
            .phrase_cipher
            .windows(preparation.phrase.as_str().len())
            .any(|window| window == preparation.phrase.as_str().as_bytes()));
        let root = open(&binding.envelope, &old).unwrap();
        assert_eq!(
            recover_phrase(&root, &ceremony).unwrap(),
            preparation.phrase
        );
        let mut changed = ceremony;
        changed.record.ceremony_id.push('0');
        assert!(recover_phrase(&root, &changed).is_err());
        for i in 0..changed.phrase_cipher.len() {
            let mut ceremony = read_ceremony(&store.connection, &preparation.ceremony_id).unwrap();
            ceremony.phrase_cipher[i] ^= 1;
            assert!(recover_phrase(&root, &ceremony).is_err());
        }
    }

    #[test]
    fn pending_phrase_cipher_matches_independent_domain_and_aad_vector() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/refresh-phrase-v1.json")).unwrap();
        let root: [u8; 32] = hex::decode(vector["root_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = hex::decode(vector["nonce_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut bytes = hex::decode(vector["plaintext_hex"].as_str().unwrap()).unwrap();
        phrase_cipher(&root)
            .unwrap()
            .encrypt_in_place(
                &XNonce::from(nonce),
                vector["ceremony_id"].as_str().unwrap().as_bytes(),
                &mut bytes,
            )
            .unwrap();
        assert_eq!(
            hex::encode(bytes),
            vector["ciphertext_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn missing_or_corrupt_current_never_revives_historical_envelope() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("corrupt.sqlite"));
        let preparation = prepare(&mut store, &old, &binding);
        store
            .confirm_refresh(
                &preparation.ceremony_id,
                "owner",
                &old,
                &words(&preparation.phrase),
                1001,
                |_, _| Ok(()),
            )
            .unwrap();
        store.connection.execute_batch("DROP TRIGGER aumlok_current_switch; UPDATE aumlok_current_envelope SET envelope_sha256='bad'").unwrap();
        assert!(store.binding().is_err());
        assert!(store
            .open_current("bad", "owner", &preparation.phrase, 1002)
            .is_err());
        store
            .connection
            .execute_batch(
                "DROP TRIGGER aumlok_current_no_delete; DELETE FROM aumlok_current_envelope",
            )
            .unwrap();
        assert!(store.binding().is_err());
        assert!(initialize_current(&store.connection).is_err());
    }

    #[test]
    fn legacy_completed_binding_initializes_current_before_recovery() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("legacy.sqlite");
        let (store, old, binding) = bound(&path);
        store
            .connection
            .execute_batch(
                "DROP TRIGGER aumlok_current_no_delete; DELETE FROM aumlok_current_envelope",
            )
            .unwrap();
        drop(store);
        let mut store = BindingStore::open(&path).unwrap();
        assert_eq!(store.binding().unwrap().unwrap().envelope, binding.envelope);
        assert!(store
            .open_current(&envelope_sha256(&binding.envelope), "owner", &old, 1000)
            .is_ok());
    }

    #[test]
    fn source_subject_new_root_and_version_are_checked_independently() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("subject.sqlite"));
        let preparation = prepare(&mut store, &old, &binding);
        store.connection.execute_batch("DROP TRIGGER aumlok_refresh_forward; PRAGMA ignore_check_constraints=ON; UPDATE aumlok_refresh SET version=2").unwrap();
        assert_eq!(
            store
                .resume_refresh(&preparation.ceremony_id, "owner", &old, 1001)
                .err()
                .unwrap()
                .code(),
            "aumlok:refresh-version"
        );
        store
            .connection
            .execute_batch("UPDATE aumlok_refresh SET version=1,old_sha256='stale'")
            .unwrap();
        assert_eq!(
            store
                .resume_refresh(&preparation.ceremony_id, "owner", &old, 1001)
                .err()
                .unwrap()
                .code(),
            "aumlok:refresh-stale"
        );
        store
            .connection
            .execute(
                "UPDATE aumlok_refresh SET old_sha256=?1",
                [envelope_sha256(&binding.envelope)],
            )
            .unwrap();
        let alien = crate::envelope::seal(&preparation.phrase, kdf()).unwrap();
        store
            .connection
            .execute(
                "UPDATE aumlok_refresh SET envelope=?1,new_sha256=?2",
                params![
                    alien.envelope.to_canonical_json(),
                    envelope_sha256(&alien.envelope)
                ],
            )
            .unwrap();
        assert_eq!(
            store
                .confirm_refresh(
                    &preparation.ceremony_id,
                    "owner",
                    &old,
                    &words(&preparation.phrase),
                    1001,
                    |_, _| panic!("alien root reached Aura")
                )
                .err()
                .unwrap()
                .code(),
            "aumlok:refresh-corrupt"
        );
        store
            .connection
            .execute_batch("DROP TRIGGER aumlok_current_switch")
            .unwrap();
        let subject = subject_from_root(&[7; 32]);
        store
            .connection
            .execute("UPDATE aumlok_current_envelope SET subject=?1", [subject])
            .unwrap();
        assert_eq!(
            store
                .open_current(&envelope_sha256(&binding.envelope), "owner", &old, 1001)
                .err()
                .unwrap()
                .code(),
            "aumlok:refresh-corrupt"
        );
    }

    #[test]
    fn replacement_draw_refuses_random_failure_and_redraws_identical_phrase() {
        let old = Phrase::draw().unwrap();
        let mut new = Phrase::draw().unwrap();
        while new == old {
            new = Phrase::draw().unwrap();
        }
        let mut draws = 0;
        let replacement = draw_replacement(&old, || {
            draws += 1;
            Phrase::parse(if draws == 1 {
                old.as_str()
            } else {
                new.as_str()
            })
        })
        .unwrap();
        assert_eq!(draws, 2);
        assert_eq!(replacement, new);
        assert_eq!(
            draw_replacement(&old, || Err(crate::PhraseError::RandomUnavailable))
                .err()
                .unwrap()
                .code(),
            "aumlok:random-unavailable"
        );
    }

    #[test]
    fn refresh_input_and_schema_bounds_refuse_without_creating_authority() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("input.sqlite"));
        for (principal, now, expires) in [
            ("", 1000, 2000),
            ("owner", -1, 2000),
            ("owner", 1000, 1000),
            ("owner", 1000, 301001),
        ] {
            assert_eq!(
                store
                    .prepare_refresh(principal, &old, Some(proof(&binding)), now, expires, kdf())
                    .err()
                    .unwrap()
                    .code(),
                "aumlok:refresh-input"
            );
        }
        let long = "x".repeat(257);
        assert_eq!(
            store
                .prepare_refresh(&long, &old, Some(proof(&binding)), 1000, 2000, kdf())
                .err()
                .unwrap()
                .code(),
            "aumlok:refresh-input"
        );
        for id in ["", long.as_str()] {
            let approval = VerifiedRefreshApproval::new(
                "owner".into(),
                binding.subject.clone(),
                envelope_sha256(&binding.envelope),
                id.into(),
            );
            assert_eq!(
                store
                    .prepare_refresh("owner", &old, Some(approval), 1000, 2000, kdf())
                    .err()
                    .unwrap()
                    .code(),
                "aumlok:refresh-proof"
            );
        }
        assert_eq!(count(&store.connection, "aumlok_refresh"), 0);
        assert_eq!(
            store
                .cancel_refresh("unknown", "owner", 1000)
                .err()
                .unwrap()
                .code(),
            "aumlok:ceremony-unknown"
        );
        let preparation = prepare(&mut store, &old, &binding);
        for sql in ["UPDATE aumlok_refresh SET state='EXPIRED',expires_at=301001",
            "INSERT INTO aumlok_phrase_guesses VALUES('stranger',1000,6)",
            "INSERT INTO aumlok_current_envelope SELECT 2,subject,'other',envelope FROM aumlok_current_envelope",
            "INSERT INTO aumlok_refresh SELECT 'other',version,'COMMITTED',principal,'other',subject,old_sha256,'other',envelope,phrase_cipher,issued_at,expires_at FROM aumlok_refresh"] {
            assert!(store.connection.execute_batch(sql).is_err(),"accepted {sql}");
        }
        store
            .connection
            .execute_batch("DROP TRIGGER aumlok_refresh_forward")
            .unwrap();
        assert!(store
            .connection
            .execute_batch("UPDATE aumlok_refresh SET state='COMMITTED'")
            .is_err());
        store
            .connection
            .execute_batch("UPDATE aumlok_refresh SET new_sha256='wrong'")
            .unwrap();
        assert_eq!(
            store
                .resume_refresh(&preparation.ceremony_id, "owner", &old, 1001)
                .err()
                .unwrap()
                .code(),
            "aumlok:refresh-corrupt"
        );
    }

    #[test]
    fn failed_sqlite_commit_rolls_back_refresh_and_aura_together() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let (mut store, old, binding) = bound(&directory.path().join("commit.sqlite"));
        let preparation = prepare(&mut store, &old, &binding);
        store.connection.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE test_parent(id INTEGER PRIMARY KEY);
            CREATE TABLE test_aura(op TEXT PRIMARY KEY, parent_id INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED)").unwrap();
        assert_eq!(
            store
                .confirm_refresh(
                    &preparation.ceremony_id,
                    "owner",
                    &old,
                    &words(&preparation.phrase),
                    1001,
                    |tx, record| {
                        tx.execute("INSERT INTO test_aura VALUES(?1,99)", [&record.ceremony_id])
                            .map_err(storage)?;
                        Ok(())
                    }
                )
                .err()
                .unwrap()
                .code(),
            "aumlok:refresh-storage"
        );
        assert_eq!(count(&store.connection, "test_aura"), 0);
        assert_eq!(count(&store.connection, "aumlok_retired_envelope"), 0);
        assert_eq!(store.binding().unwrap().unwrap().envelope, binding.envelope);
        drop(store);
        let mut reopened = BindingStore::open(directory.path().join("commit.sqlite")).unwrap();
        reopened.recover_refresh(1002).unwrap();
        assert_eq!(
            reopened
                .resume_refresh(&preparation.ceremony_id, "owner", &old, 1002)
                .unwrap()
                .phrase,
            preparation.phrase
        );
    }
}
