// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::Path;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::webauthn::{
    canonical_value, decode_base64url, validate_origin, verify_assertion, verify_registration,
    AssertionMaterial, Config, Credential, Refusal, RegistrationCandidate, RegistrationContext,
    RegistrationMaterial, Result, VerifiedAssertion,
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS aumlok_ceremony (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('enrolment','assertion')),
    state TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    user_handle TEXT NOT NULL,
    claim_sha256 BLOB,
    challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
    possession_challenge TEXT,
    candidate TEXT,
    credential TEXT,
    sign_count INTEGER CHECK(sign_count BETWEEN 0 AND 4294967295),
    session_sha256 BLOB,
    issued_at INTEGER NOT NULL DEFAULT 0 CHECK(issued_at >= 0),
    CHECK(expires_at > issued_at AND expires_at - issued_at <= 300000),
    CHECK(session_sha256 IS NULL OR length(session_sha256)=32),
    CHECK(state NOT IN ('reserved','enrolled') OR session_sha256 IS NOT NULL),
    CHECK((kind='enrolment' AND state!='fresh') OR session_sha256 IS NULL),
    CHECK((kind='enrolment' AND state IN ('fresh','reserved','enrolled','failed'))
       OR (kind='assertion' AND state IN ('live','consumed'))),
    CHECK((kind='enrolment' AND length(claim_sha256)=32)
       OR (kind='assertion' AND claim_sha256 IS NULL)),
    CHECK((candidate IS NULL) = (possession_challenge IS NULL)),
    CHECK((credential IS NULL) = (sign_count IS NULL)),
    CHECK((state='enrolled') = (credential IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS aumlok_one_enrolment
    ON aumlok_ceremony(kind) WHERE kind='enrolment' AND state!='failed';
CREATE UNIQUE INDEX IF NOT EXISTS aumlok_claim_once
    ON aumlok_ceremony(claim_sha256) WHERE kind='enrolment';
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_no_delete
BEFORE DELETE ON aumlok_ceremony
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-retained'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_no_replace
BEFORE INSERT ON aumlok_ceremony
WHEN EXISTS(SELECT 1 FROM aumlok_ceremony
            WHERE id=NEW.id OR (kind='enrolment' AND state!='failed' AND NEW.kind='enrolment')
               OR (kind='enrolment' AND NEW.kind='enrolment' AND claim_sha256=NEW.claim_sha256))
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-retained'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_challenge_once
BEFORE INSERT ON aumlok_ceremony
WHEN EXISTS(SELECT 1 FROM aumlok_ceremony
            WHERE challenge=NEW.challenge OR possession_challenge=NEW.challenge)
BEGIN SELECT RAISE(ABORT,'aumlok:challenge-already-issued'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_possession_once
BEFORE UPDATE ON aumlok_ceremony
WHEN OLD.possession_challenge IS NULL AND NEW.possession_challenge IS NOT NULL
 AND EXISTS(SELECT 1 FROM aumlok_ceremony
            WHERE challenge=NEW.possession_challenge
               OR possession_challenge=NEW.possession_challenge)
BEGIN SELECT RAISE(ABORT,'aumlok:challenge-already-issued'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_initial_state
BEFORE INSERT ON aumlok_ceremony
WHEN (NEW.kind='enrolment' AND NEW.state!='fresh')
  OR (NEW.kind='assertion' AND NEW.state!='live')
  OR NEW.candidate IS NOT NULL OR NEW.credential IS NOT NULL
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-state'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_enrolment_closed
BEFORE INSERT ON aumlok_ceremony
WHEN NEW.kind='enrolment'
 AND EXISTS(SELECT 1 FROM aumlok_ceremony WHERE state='enrolled')
BEGIN SELECT RAISE(ABORT,'aumlok:enrollment-closed'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_context_pin
BEFORE UPDATE ON aumlok_ceremony
WHEN NEW.id IS NOT OLD.id OR NEW.kind IS NOT OLD.kind
 OR NEW.owner_id IS NOT OLD.owner_id OR NEW.rp_id IS NOT OLD.rp_id
 OR NEW.origin IS NOT OLD.origin OR NEW.user_handle IS NOT OLD.user_handle
 OR NEW.claim_sha256 IS NOT OLD.claim_sha256 OR NEW.challenge IS NOT OLD.challenge
 OR NEW.expires_at IS NOT OLD.expires_at
 OR NEW.issued_at IS NOT OLD.issued_at
 OR (OLD.session_sha256 IS NOT NULL AND NEW.session_sha256 IS NOT OLD.session_sha256)
 OR (OLD.candidate IS NOT NULL AND NEW.candidate IS NOT OLD.candidate)
 OR (OLD.possession_challenge IS NOT NULL
     AND NEW.possession_challenge IS NOT OLD.possession_challenge)
 OR (OLD.credential IS NOT NULL AND NEW.credential IS NOT OLD.credential)
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-context-changed'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_session_stage
BEFORE UPDATE ON aumlok_ceremony
WHEN OLD.session_sha256 IS NULL AND NEW.session_sha256 IS NOT NULL
 AND (OLD.state!='fresh' OR NEW.state!='reserved')
BEGIN SELECT RAISE(ABORT,'aumlok:session-stage'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_forward_state
BEFORE UPDATE ON aumlok_ceremony
WHEN NOT (NEW.state=OLD.state
 OR (OLD.state='fresh' AND NEW.state IN ('reserved','failed'))
 OR (OLD.state='reserved' AND NEW.state IN ('enrolled','failed'))
 OR (OLD.state='live' AND NEW.state='consumed'))
BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-rewind'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_candidate_stage
BEFORE UPDATE ON aumlok_ceremony
WHEN OLD.candidate IS NULL AND NEW.candidate IS NOT NULL
 AND (OLD.state!='reserved' OR NEW.state!='reserved')
BEGIN SELECT RAISE(ABORT,'aumlok:registration-stage'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_enrolment_stage
BEFORE UPDATE ON aumlok_ceremony
WHEN OLD.credential IS NULL AND NEW.credential IS NOT NULL
 AND (OLD.state!='reserved' OR OLD.candidate IS NULL OR NEW.state!='enrolled')
BEGIN SELECT RAISE(ABORT,'aumlok:possession-required'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_counter_forward
BEFORE UPDATE ON aumlok_ceremony
WHEN NEW.sign_count < OLD.sign_count
BEGIN SELECT RAISE(ABORT,'aumlok:counter-replayed'); END;
"#;

const MAX_CEREMONY_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentSetup {
    pub id: String,
    pub owner_id: String,
    pub rp_id: String,
    pub origin: String,
    pub user_handle: String,
    pub claim_sha256: [u8; 32],
    pub registration_challenge: String,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyState {
    Fresh,
    Reserved,
    Enrolled,
    Failed,
    Live,
    Consumed,
}

impl CeremonyState {
    fn parse(state: &str) -> Result<Self> {
        match state {
            "fresh" => Ok(Self::Fresh),
            "reserved" => Ok(Self::Reserved),
            "enrolled" => Ok(Self::Enrolled),
            "failed" => Ok(Self::Failed),
            "live" => Ok(Self::Live),
            "consumed" => Ok(Self::Consumed),
            _ => Err(Refusal("aumlok:store-corrupt")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ceremony {
    pub id: String,
    pub state: CeremonyState,
    pub challenge: String,
    pub expires_at: i64,
    pub candidate: Option<RegistrationCandidate>,
}

// Only the first successful claim spend returns the random bearer secret.
// Snapshots and restart resumption never contain it.
pub struct EnrollmentReservation {
    pub ceremony: Ceremony,
    pub session_secret: String,
}

impl std::fmt::Debug for EnrollmentReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentReservation")
            .field("ceremony", &self.ceremony)
            .field("session_secret", &"[redacted]")
            .finish()
    }
}

pub struct CeremonyStore {
    connection: Connection,
}

impl CeremonyStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_connection(Connection::open(path).map_err(store_error)?)
    }

    pub fn from_connection(connection: Connection) -> Result<Self> {
        // Legacy claim-resumable rows cannot gain session authority by upgrade.
        let columns = {
            let mut statement = connection
                .prepare("PRAGMA table_info(aumlok_ceremony)")
                .map_err(store_error)?;
            let names = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(store_error)?;
            names
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(store_error)?
        };
        if !columns.is_empty()
            && (!columns.iter().any(|name| name == "session_sha256")
                || !columns.iter().any(|name| name == "issued_at"))
        {
            return Err(Refusal("aumlok:store-version"));
        }
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(store_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(store_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(store_error)?;
        connection.execute_batch(SCHEMA).map_err(store_error)?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn configure_enrollment(&mut self, setup: &EnrollmentSetup, now: i64) -> Result<()> {
        if !valid_id(&setup.id)
            || setup.owner_id.is_empty()
            || setup.rp_id.is_empty()
            || setup.origin.is_empty()
            || setup.user_handle.is_empty()
            || setup.registration_challenge.is_empty()
            || now < 0
        {
            return Err(Refusal("aumlok:ceremony-data-invalid"));
        }
        validate_origin(&setup.rp_id, &setup.origin)?;
        decode_base64url(&setup.user_handle, 64)?;
        valid_challenge(&setup.registration_challenge)?;
        self.writer(|tx| {
            if let Some(row) = load_row(tx, &setup.id)? {
                if row.state == "failed" {
                    return Err(Refusal("aumlok:enrollment-failed"));
                }
                if row.state == "enrolled" {
                    return Err(Refusal("aumlok:enrollment-closed"));
                }
                if row.kind != "enrolment" {
                    return Err(Refusal("aumlok:ceremony-already-issued"));
                }
            }
            if let Some(row) = enrolment_row(tx)? {
                if row.state != "enrolled" && expired(&row, now)? {
                    fail_enrollment(tx, &row.id)?;
                    if row.id == setup.id {
                        return Err(Refusal("aumlok:enrollment-failed"));
                    }
                }
            }
            if let Some(row) = enrolment_row(tx)? {
                if row.id != setup.id || row.state == "enrolled" {
                    return Err(Refusal("aumlok:enrollment-closed"));
                }
                if row.owner_id != setup.owner_id
                    || row.rp_id != setup.rp_id
                    || row.origin != setup.origin
                    || row.user_handle != setup.user_handle
                    || row.claim_sha256.as_deref() != Some(setup.claim_sha256.as_slice())
                    || row.challenge != setup.registration_challenge
                    || row.expires_at != cap_expiry(setup.expires_at, row.issued_at)
                {
                    return Err(Refusal("aumlok:setup-changed"));
                }
                return Ok(());
            }
            if setup.expires_at <= now {
                return Err(Refusal("aumlok:ceremony-data-invalid"));
            }
            if tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM aumlok_ceremony WHERE claim_sha256=?1)",
                    [setup.claim_sha256],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(store_error)?
            {
                return Err(Refusal("aumlok:claim-already-issued"));
            }
            tx.execute(
                "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin, \
                 user_handle,claim_sha256,challenge,expires_at,issued_at) \
                 VALUES(?1,'enrolment','fresh',?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    setup.id,
                    setup.owner_id,
                    setup.rp_id,
                    setup.origin,
                    setup.user_handle,
                    setup.claim_sha256,
                    setup.registration_challenge,
                    cap_expiry(setup.expires_at, now),
                    now
                ],
            )
            .map_err(store_error)?;
            Ok(())
        })
    }

    pub fn reserve_enrollment(
        &mut self,
        id: &str,
        claim_code: &str,
        now: i64,
    ) -> Result<EnrollmentReservation> {
        if !decode_base64url(claim_code, 32).is_ok_and(|bytes| bytes.len() == 32) {
            return Err(Refusal("aumlok:claim-invalid"));
        }
        self.writer(|tx| {
            let mut row = required_row(tx, id, "enrolment")?;
            if row.state != "fresh" {
                return Err(Refusal("aumlok:claim-spent"));
            }
            let digest = Sha256::digest(claim_code.as_bytes());
            let expected = row
                .claim_sha256
                .as_deref()
                .ok_or(Refusal("aumlok:store-corrupt"))?;
            if !equal_hash(expected, &digest) {
                return Err(Refusal("aumlok:claim-invalid"));
            }
            if expired(&row, now)? {
                fail_enrollment(tx, id)?;
                return Err(Refusal("aumlok:claim-expired"));
            }
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret).map_err(|_| Refusal("aumlok:random-unavailable"))?;
            let session_digest = Sha256::digest(secret);
            let changed = tx
                .execute(
                    "UPDATE aumlok_ceremony SET state='reserved',session_sha256=?2 \
                     WHERE id=?1 AND state='fresh'",
                    params![id, session_digest.as_slice()],
                )
                .map_err(store_error)?;
            if changed != 1 {
                return Err(Refusal("aumlok:claim-spent"));
            }
            row.state = "reserved".to_owned();
            Ok(EnrollmentReservation {
                ceremony: row.snapshot()?,
                session_secret: URL_SAFE_NO_PAD.encode(secret),
            })
        })
    }

    // Restart resumption uses the private secret, never the already-spent claim.
    pub fn resume_enrollment(
        &mut self,
        id: &str,
        session_secret: &str,
        now: i64,
    ) -> Result<Ceremony> {
        self.writer(|tx| {
            let row = required_row(tx, id, "enrolment")?;
            require_session(&row, session_secret)?;
            if row.state != "reserved" {
                return Err(Refusal("aumlok:enrollment-closed"));
            }
            if expired(&row, now)? {
                fail_enrollment(tx, id)?;
                return Err(Refusal("aumlok:claim-expired"));
            }
            row.snapshot()
        })
    }

    pub fn register(
        &mut self,
        id: &str,
        session_secret: &str,
        material: &RegistrationMaterial,
        now: i64,
    ) -> Result<Ceremony> {
        self.writer(|tx| {
            let row = required_row(tx, id, "enrolment")?;
            require_session(&row, session_secret)?;
            if row.state != "reserved" {
                return Err(Refusal("aumlok:enrollment-closed"));
            }
            if row.candidate.is_some() {
                return Err(Refusal("aumlok:registration-closed"));
            }
            if expired(&row, now)? {
                fail_enrollment(tx, id)?;
                return Err(Refusal("aumlok:claim-expired"));
            }
            let context = RegistrationContext {
                owner_id: row.owner_id.clone(),
                rp_id: row.rp_id.clone(),
                origin: row.origin.clone(),
                user_handle: row.user_handle.clone(),
                existing_credential_ids: vec![],
            };
            let candidate = match verify_registration(material, &context, &row.challenge) {
                Ok(candidate) => candidate,
                Err(error) => {
                    fail_enrollment(tx, id)?;
                    return Err(error);
                }
            };
            // Commit every verified candidate field using the same canonical
            // encoding as owner authorizations.
            let candidate_value = serde_json::to_value(&candidate).map_err(store_error)?;
            let mut candidate_bytes = Vec::new();
            canonical_value(&candidate_value, 0, &mut candidate_bytes)?;
            let candidate_digest = Sha256::digest(&candidate_bytes);
            let mut possession = Sha256::new();
            possession.update(b"aukora:enrol-possession:v1\0");
            possession.update(id.as_bytes());
            possession.update(candidate_digest);
            let possession_challenge = URL_SAFE_NO_PAD.encode(possession.finalize());
            let candidate_json = serde_json::to_string(&candidate).map_err(store_error)?;
            let changed = tx
                .execute(
                    "UPDATE aumlok_ceremony SET candidate=?2,possession_challenge=?3 \
                     WHERE id=?1 AND state='reserved' AND candidate IS NULL",
                    params![id, candidate_json, possession_challenge],
                )
                .map_err(store_error)?;
            if changed != 1 {
                return Err(Refusal("aumlok:registration-closed"));
            }
            required_row(tx, id, "enrolment")?.snapshot()
        })
    }

    pub fn finish_enrollment(
        &mut self,
        id: &str,
        session_secret: &str,
        material: &AssertionMaterial,
        now: i64,
    ) -> Result<Credential> {
        self.writer(|tx| {
            let row = required_row(tx, id, "enrolment")?;
            require_session(&row, session_secret)?;
            if row.state != "reserved" {
                return Err(Refusal("aumlok:enrollment-closed"));
            }
            if expired(&row, now)? {
                fail_enrollment(tx, id)?;
                return Err(Refusal("aumlok:claim-expired"));
            }
            let mut candidate = row
                .parsed_candidate()?
                .ok_or(Refusal("aumlok:registration-required"))?;
            let challenge = row
                .possession_challenge
                .as_deref()
                .ok_or(Refusal("aumlok:store-corrupt"))?;
            let config = Config {
                rp_id: row.rp_id,
                origin: row.origin,
                credential: candidate.credential.clone(),
            };
            let checked = match verify_assertion(
                material,
                &config,
                &row.owner_id,
                challenge,
                Some(candidate.credential.sign_count),
            ) {
                Ok(checked) => checked,
                Err(error) => {
                    fail_enrollment(tx, id)?;
                    return Err(error);
                }
            };
            candidate.credential.sign_count = checked.sign_count;
            let credential_json =
                serde_json::to_string(&candidate.credential).map_err(store_error)?;
            let changed = tx
                .execute(
                    "UPDATE aumlok_ceremony SET state='enrolled',credential=?2,sign_count=?3 \
                     WHERE id=?1 AND state='reserved' AND credential IS NULL",
                    params![id, credential_json, checked.sign_count],
                )
                .map_err(store_error)?;
            if changed != 1 {
                return Err(Refusal("aumlok:enrollment-closed"));
            }
            Ok(candidate.credential)
        })
    }

    pub fn credential(&self) -> Result<Option<Credential>> {
        enrolment_row(&self.connection)?
            .filter(|row| row.state == "enrolled")
            .map(|row| row.parsed_credential())
            .transpose()
    }

    pub fn ceremony(&self, id: &str) -> Result<Option<Ceremony>> {
        load_row(&self.connection, id)?
            .map(|row| row.snapshot())
            .transpose()
    }

    pub fn issue_assertion(
        &mut self,
        id: &str,
        challenge: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<Ceremony> {
        if !valid_id(id) || challenge.is_empty() || now < 0 || expires_at <= now {
            return Err(Refusal("aumlok:ceremony-data-invalid"));
        }
        valid_challenge(challenge)?;
        self.writer(|tx| {
            let enrollment = enrolment_row(tx)?
                .filter(|row| row.state == "enrolled")
                .ok_or(Refusal("aumlok:owner-not-enrolled"))?;
            if load_row(tx, id)?.is_some() {
                return Err(Refusal("aumlok:ceremony-already-issued"));
            }
            tx.execute(
                "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin, \
                 user_handle,challenge,expires_at,issued_at) \
                 VALUES(?1,'assertion','live',?2,?3,?4,?5,?6,?7,?8)",
                params![
                    id,
                    enrollment.owner_id,
                    enrollment.rp_id,
                    enrollment.origin,
                    enrollment.user_handle,
                    challenge,
                    cap_expiry(expires_at, now),
                    now
                ],
            )
            .map_err(store_error)?;
            required_row(tx, id, "assertion")?.snapshot()
        })
    }

    // A committed spend precedes verification, so an interrupted attempt stays spent.
    pub fn consume_assertion(
        &mut self,
        id: &str,
        material: &AssertionMaterial,
        now: i64,
    ) -> Result<VerifiedAssertion> {
        let row = self.spend_assertion(id)?;
        self.writer(|tx| {
            if expired(&row, now)? {
                return Err(Refusal("aumlok:ceremony-expired"));
            }
            let enrollment = enrolment_row(tx)?
                .filter(|row| row.state == "enrolled")
                .ok_or(Refusal("aumlok:owner-not-enrolled"))?;
            let credential = enrollment.parsed_credential()?;
            let prior = credential.sign_count;
            let config = Config {
                rp_id: enrollment.rp_id,
                origin: enrollment.origin,
                credential,
            };
            let checked = verify_assertion(
                material,
                &config,
                &row.owner_id,
                &row.challenge,
                Some(prior),
            )?;
            if prior != 0 || checked.sign_count != 0 {
                let changed = tx
                    .execute(
                        "UPDATE aumlok_ceremony SET sign_count=?2 \
                         WHERE id=?1 AND state='enrolled' AND sign_count=?3",
                        params![enrollment.id, checked.sign_count, prior],
                    )
                    .map_err(store_error)?;
                if changed != 1 {
                    return Err(Refusal("aumlok:counter-changed"));
                }
            }
            Ok(checked)
        })
    }

    fn spend_assertion(&mut self, id: &str) -> Result<Row> {
        self.writer(|tx| {
            let row = required_row(tx, id, "assertion")?;
            if row.state != "live" {
                return Err(Refusal("aumlok:ceremony-consumed"));
            }
            let changed = tx
                .execute(
                    "UPDATE aumlok_ceremony SET state='consumed' WHERE id=?1 AND state='live'",
                    [id],
                )
                .map_err(store_error)?;
            if changed != 1 || required_row(tx, id, "assertion")?.state != "consumed" {
                return Err(Refusal("aumlok:challenge-burn-unconfirmed"));
            }
            Ok(row)
        })
    }

    fn writer<T>(&mut self, action: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        let result = action(&tx);
        if matches!(
            &result,
            Err(Refusal("aumlok:store" | "aumlok:store-corrupt"))
        ) {
            tx.rollback().map_err(store_error)?;
        } else {
            tx.commit().map_err(store_error)?;
        }
        result
    }
}

fn store_error(_: impl std::fmt::Display) -> Refusal {
    Refusal("aumlok:store")
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_challenge(challenge: &str) -> Result<()> {
    if decode_base64url(challenge, 32)?.len() != 32 {
        return Err(Refusal("aumlok:ceremony-data-invalid"));
    }
    Ok(())
}

fn cap_expiry(requested: i64, now: i64) -> i64 {
    requested.min(now.saturating_add(MAX_CEREMONY_MS))
}

fn equal_hash(expected: &[u8], actual: &[u8]) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual.iter())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

fn require_session(row: &Row, session_secret: &str) -> Result<()> {
    let secret =
        decode_base64url(session_secret, 32).map_err(|_| Refusal("aumlok:session-invalid"))?;
    if secret.len() != 32
        || !row
            .session_sha256
            .as_deref()
            .is_some_and(|expected| equal_hash(expected, &Sha256::digest(&secret)))
    {
        return Err(Refusal("aumlok:session-invalid"));
    }
    Ok(())
}

fn expired(row: &Row, now: i64) -> Result<bool> {
    if now < row.issued_at {
        return Err(Refusal("aumlok:clock-invalid"));
    }
    Ok(now >= row.expires_at)
}

fn fail_enrollment(tx: &Transaction<'_>, id: &str) -> Result<()> {
    tx.execute(
        "UPDATE aumlok_ceremony SET state='failed' WHERE id=?1 AND state IN ('fresh','reserved')",
        [id],
    )
    .map_err(store_error)?;
    if required_row(tx, id, "enrolment")?.state != "failed" {
        return Err(Refusal("aumlok:challenge-burn-unconfirmed"));
    }
    Ok(())
}

struct Row {
    id: String,
    kind: String,
    state: String,
    owner_id: String,
    rp_id: String,
    origin: String,
    user_handle: String,
    claim_sha256: Option<Vec<u8>>,
    challenge: String,
    expires_at: i64,
    possession_challenge: Option<String>,
    candidate: Option<String>,
    credential: Option<String>,
    sign_count: Option<u32>,
    session_sha256: Option<Vec<u8>>,
    issued_at: i64,
}

impl Row {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            kind: row.get(1)?,
            state: row.get(2)?,
            owner_id: row.get(3)?,
            rp_id: row.get(4)?,
            origin: row.get(5)?,
            user_handle: row.get(6)?,
            claim_sha256: row.get(7)?,
            challenge: row.get(8)?,
            expires_at: row.get(9)?,
            possession_challenge: row.get(10)?,
            candidate: row.get(11)?,
            credential: row.get(12)?,
            sign_count: row.get("sign_count")?,
            session_sha256: row.get("session_sha256")?,
            issued_at: row.get("issued_at")?,
        })
    }

    fn parsed_candidate(&self) -> Result<Option<RegistrationCandidate>> {
        self.candidate
            .as_deref()
            .map(|text| serde_json::from_str(text).map_err(|_| Refusal("aumlok:store-corrupt")))
            .transpose()
    }

    fn parsed_credential(&self) -> Result<Credential> {
        let text = self
            .credential
            .as_deref()
            .ok_or(Refusal("aumlok:store-corrupt"))?;
        let mut credential: Credential =
            serde_json::from_str(text).map_err(|_| Refusal("aumlok:store-corrupt"))?;
        credential.sign_count = self.sign_count.ok_or(Refusal("aumlok:store-corrupt"))?;
        Ok(credential)
    }

    fn snapshot(&self) -> Result<Ceremony> {
        Ok(Ceremony {
            id: self.id.clone(),
            state: CeremonyState::parse(&self.state)?,
            challenge: self
                .possession_challenge
                .as_ref()
                .unwrap_or(&self.challenge)
                .clone(),
            expires_at: self.expires_at,
            candidate: self.parsed_candidate()?,
        })
    }
}

fn load_row(connection: &Connection, id: &str) -> Result<Option<Row>> {
    connection
        .query_row("SELECT * FROM aumlok_ceremony WHERE id=?1", [id], Row::read)
        .optional()
        .map_err(store_error)
}

fn enrolment_row(connection: &Connection) -> Result<Option<Row>> {
    connection
        .query_row(
            "SELECT * FROM aumlok_ceremony WHERE kind='enrolment' AND state!='failed'",
            [],
            Row::read,
        )
        .optional()
        .map_err(store_error)
}

fn required_row(connection: &Connection, id: &str, kind: &str) -> Result<Row> {
    load_row(connection, id)?
        .filter(|row| row.kind == kind)
        .ok_or(Refusal("aumlok:ceremony-not-found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn process_exit_after_spend_cannot_revive_assertion() {
        const ID: &str = "00000000000000000000000000000003";
        const CHILD_PATH: &str = "AUMLOK_TEST_CRASH_DATABASE";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let mut store = CeremonyStore::open(path).unwrap();
            store.spend_assertion(ID).unwrap();
            std::process::exit(0);
        }
        let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let path = directory.path().join("crash.db");
        let store = CeremonyStore::open(&path).unwrap();
        store.connection().execute(
            "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,challenge,expires_at) \
             VALUES(?1,'assertion','live','test-owner','owner.test','https://owner.test','dXNlcg','challenge',10000)",
            [ID],
        ).unwrap();
        drop(store);
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ceremony::tests::process_exit_after_spend_cannot_revive_assertion",
            ])
            .env(CHILD_PATH, &path)
            .status()
            .unwrap();
        assert!(status.success());
        let mut store = CeremonyStore::open(&path).unwrap();
        assert_eq!(
            store.ceremony(ID).unwrap().unwrap().state,
            CeremonyState::Consumed
        );
        let material = AssertionMaterial {
            kind: "passkey".into(),
            credential_id: "credential".into(),
            client_data_json: "client".into(),
            authenticator_data: "authenticator".into(),
            signature: "signature".into(),
            user_handle: None,
        };
        assert_eq!(
            store.consume_assertion(ID, &material, 1).unwrap_err().0,
            "aumlok:ceremony-consumed"
        );
    }
}
