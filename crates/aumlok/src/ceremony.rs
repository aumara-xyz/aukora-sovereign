// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable nonauthorizing ceremony state and transaction-bound possession finishes.

use crate::webauthn::{
    inspect_assertion, verify_registration, AssertionMaterial, Credential, ExtensionPolicy,
    OriginContext, RegistrationCandidate, RegistrationContext, RegistrationMaterial,
};
use canon::authority::{AuthorityTxn, AuthorityVersion, OwnerBinding};
use canon::digest::Digest32;
use canon::ids::{CredentialId, SessionId, SubjectId};
use canon::{Refusal, Result};
use sha2::{Digest, Sha256};

pub use canon::ids::RequestId as CeremonyId;
pub const MAX_CEREMONY_MS: i64 = 300_000;
pub const NONCE_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyPurpose {
    Enrolment,
    SignIn,
    Binding,
    Refresh,
    Backup,
    PairDevice,
}

impl CeremonyPurpose {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "enrolment" => Ok(Self::Enrolment),
            "signin" => Ok(Self::SignIn),
            "binding" => Ok(Self::Binding),
            "refresh" => Ok(Self::Refresh),
            "backup" => Ok(Self::Backup),
            "pair-device" => Ok(Self::PairDevice),
            _ => Err(refusal("ceremony-kind")),
        }
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Enrolment => "enrolment",
            Self::SignIn => "signin",
            Self::Binding => "binding",
            Self::Refresh => "refresh",
            Self::Backup => "backup",
            Self::PairDevice => "pair-device",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyState {
    Fresh,
    Reserved,
    Registered,
    Spent,
    Finished,
    Failed,
    Expired,
}

impl CeremonyState {
    fn from_wire(value: &str) -> Result<Self> {
        match value {
            "fresh" => Ok(Self::Fresh),
            "reserved" => Ok(Self::Reserved),
            "registered" => Ok(Self::Registered),
            "spent" => Ok(Self::Spent),
            "finished" => Ok(Self::Finished),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            _ => Err(refusal("store-corrupt")),
        }
    }
}

/// Non-authorizing persisted state. Secret claim/session values are never stored here.
#[derive(Clone, Debug)]
pub struct CeremonySnapshot {
    pub version: u16,
    pub id: CeremonyId,
    pub purpose: CeremonyPurpose,
    pub state: CeremonyState,
    pub origins: OriginContext,
    pub session: SessionId,
    pub subject: Option<SubjectId>,
    pub credential: Option<CredentialId>,
    pub nonce: [u8; NONCE_BYTES],
    pub expires_at_ms: i64,
    pub authority: AuthorityVersion,
    pub candidate_digest: Option<Digest32>,
}

/// Begin inputs contain no browser-supplied nonce or expiry; the service creates them.
#[derive(Clone, Debug)]
pub struct BeginCeremony {
    pub purpose: CeremonyPurpose,
    pub session: SessionId,
    pub credential: Option<CredentialId>,
}

/// Claim bytes are bearer secrets only for bootstrap admission, never owner approval.
pub struct ClaimSecret(pub zeroize::Zeroizing<Vec<u8>>);
pub struct ResumeSecret(pub zeroize::Zeroizing<Vec<u8>>);

pub struct EnrolmentReservation {
    pub ceremony: CeremonySnapshot,
    pub resume_secret: ResumeSecret,
}

/// Persistence adapter for nonauthorizing data, without credential or counter writers.
pub trait CeremonyStore {
    fn load(&mut self, id: &CeremonyId) -> Result<CeremonySnapshot>;
    fn begin(&mut self, request: &BeginCeremony, now_ms: i64) -> Result<CeremonySnapshot>;
    fn reserve_enrolment(
        &mut self,
        id: &CeremonyId,
        claim: &ClaimSecret,
        now_ms: i64,
    ) -> Result<EnrolmentReservation>;
    fn resume_enrolment(
        &mut self,
        id: &CeremonyId,
        secret: &ResumeSecret,
        now_ms: i64,
    ) -> Result<CeremonySnapshot>;
    fn register_candidate(
        &mut self,
        id: &CeremonyId,
        secret: &ResumeSecret,
        registration: &RegistrationMaterial,
        now_ms: i64,
    ) -> Result<CeremonySnapshot>;
}

/// Identity metadata read from trusted ceremony configuration, never an assertion.
#[derive(Clone, Debug)]
pub struct EnrolmentIdentity {
    pub owner_id: String,
    pub user_handle: Vec<u8>,
}

/// Locked ceremony reads on the same Aura transaction as verification and finalization.
pub trait CeremonyReadTxn: AuthorityTxn {
    fn ceremony(&mut self, id: &CeremonyId) -> Result<CeremonySnapshot>;
    fn credential(&mut self, id: &CredentialId) -> Result<Credential>;
    fn enrolment_candidate(&mut self, id: &CeremonyId) -> Result<RegistrationCandidate>;
    fn require_resume_secret(&mut self, id: &CeremonyId, secret: &ResumeSecret) -> Result<()>;

    /// Check the current authenticated session and persisted issue/last-seen times.
    /// Reject a replaced session, clock rewind, expiry or revoked/stale session epoch.
    fn require_live_context(&mut self, _ceremony: &CeremonySnapshot, _now_ms: i64) -> Result<()> {
        Err(refusal("ceremony-adapter"))
    }

    /// Return the current locked authority state, including its owner-binding epoch.
    fn ceremony_authority(&mut self) -> Result<AuthorityVersion> {
        Err(refusal("ceremony-adapter"))
    }

    /// Bootstrap admission must still hold and no owner binding may already exist.
    fn enrolment_identity(&mut self, _id: &CeremonyId) -> Result<EnrolmentIdentity> {
        Err(refusal("ceremony-adapter"))
    }

    /// Consume this capability only in its originating transaction. Re-read ceremony,
    /// epoch, session, candidate/binding and unused nonce; compare all exact fields.
    /// Atomically persist the checked counter, consume the nonce, install the first
    /// credential or sign-in session, and append a signed aumlok.enrol/signin row.
    /// Enrolment refuses any existing owner. Do not commit here or use a fact row.
    fn stage_ceremony_finish(&mut self, _proof: VerifiedCeremonyFinish) -> Result<()> {
        Err(refusal("ceremony-adapter"))
    }
}

/// A private-field nonclone capability; it exists only after full WebAuthn verification.
#[derive(Debug)]
pub struct VerifiedCeremonyFinish {
    transaction_id: Digest32,
    ceremony: CeremonySnapshot,
    credential: Credential,
    assertion: AssertionMaterial,
    signed_bytes_digest: Digest32,
    now_ms: i64,
}

impl VerifiedCeremonyFinish {
    pub fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }
    pub fn ceremony(&self) -> &CeremonySnapshot {
        &self.ceremony
    }
    pub fn credential(&self) -> &Credential {
        &self.credential
    }
    pub fn assertion(&self) -> &AssertionMaterial {
        &self.assertion
    }
    pub fn signed_bytes_digest(&self) -> Digest32 {
        self.signed_bytes_digest
    }
    pub fn now_ms(&self) -> i64 {
        self.now_ms
    }
}

/// Successful finish remains transaction-bound and noncloneable.
#[derive(Debug)]
pub struct SignIn {
    session: SessionId,
    subject: SubjectId,
    credential: CredentialId,
    epoch: u64,
    transaction_id: Digest32,
}

impl SignIn {
    pub fn session(&self) -> SessionId {
        self.session
    }
    pub fn subject(&self) -> SubjectId {
        self.subject
    }
    pub fn credential(&self) -> &CredentialId {
        &self.credential
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }
}

fn checked_snapshot<T: CeremonyReadTxn + ?Sized>(
    txn: &mut T,
    id: &CeremonyId,
    purpose: CeremonyPurpose,
    state: CeremonyState,
    now_ms: i64,
) -> Result<CeremonySnapshot> {
    let row = txn.ceremony(id)?;
    if row.id != *id || row.version != 1 || row.purpose != purpose || row.state != state {
        return Err(refusal("ceremony-state"));
    }
    crate::webauthn::validate_origins(&row.origins)?;
    if row.origins.expected_top_origin.is_none() {
        return Err(refusal("top-origin-invalid"));
    }
    if now_ms < 0 || now_ms >= row.expires_at_ms {
        return Err(refusal("ceremony-expired"));
    }
    txn.require_live_context(&row, now_ms)?;
    let current = txn.ceremony_authority()?;
    if current.epoch != row.authority.epoch
        || current.sequence < row.authority.sequence
        || (current.sequence == row.authority.sequence
            && current.previous_hash != row.authority.previous_hash)
    {
        return Err(refusal("ceremony-stale"));
    }
    Ok(row)
}

/// Registration and possession have separate challenges; the latter commits to the candidate.
pub fn possession_challenge(row: &CeremonySnapshot) -> Result<[u8; NONCE_BYTES]> {
    let digest = row
        .candidate_digest
        .ok_or_else(|| refusal("registration-required"))?;
    let mut hash = Sha256::new();
    hash.update(b"aukora:enrol-possession:v1\0");
    hash.update(row.id.to_string().as_bytes());
    hash.update(digest.as_bytes());
    Ok(hash.finalize().into())
}

pub fn finish_enrolment<T: CeremonyReadTxn + ?Sized>(
    txn: &mut T,
    ceremony: &CeremonyId,
    resume: &ResumeSecret,
    assertion: &AssertionMaterial,
    now_ms: i64,
) -> Result<Credential> {
    let row = checked_snapshot(
        txn,
        ceremony,
        CeremonyPurpose::Enrolment,
        CeremonyState::Registered,
        now_ms,
    )?;
    txn.require_resume_secret(ceremony, resume)?;
    let candidate = txn.enrolment_candidate(ceremony)?;
    if row.candidate_digest != Some(candidate_digest(&candidate)?)
        || row.credential.is_some()
        || row.subject.is_none()
    {
        return Err(refusal("ceremony-candidate"));
    }
    let identity = txn.enrolment_identity(ceremony)?;
    validate_identity(&identity)?;
    let top_origin = row
        .origins
        .expected_top_origin
        .clone()
        .ok_or_else(|| refusal("top-origin-invalid"))?;
    let mut credential = Credential {
        version: 1,
        binding: OwnerBinding {
            v: 1,
            algorithm: candidate.public_key.algorithm,
            credential_id: candidate.credential_id.clone(),
            public_key: candidate.public_key.clone(),
            epoch: row.authority.epoch,
            relying_party: row.origins.relying_party.clone(),
            owner_origin: row.origins.owner_origin.clone(),
            top_origin,
            sign_counter: candidate.initial_counter,
        },
        owner_id: identity.owner_id,
        user_handle: identity.user_handle,
        backup_eligible: candidate.backup_eligible,
    };
    let observation = inspect_assertion(
        assertion,
        &credential,
        &row.origins,
        &possession_challenge(&row)?,
        ExtensionPolicy::None,
    )?;
    credential.binding.sign_counter = observation.counter();
    txn.stage_ceremony_finish(VerifiedCeremonyFinish {
        transaction_id: txn.transaction_id(),
        ceremony: row,
        credential: credential.clone(),
        assertion: assertion.clone(),
        signed_bytes_digest: observation.signed_bytes_digest(),
        now_ms,
    })?;
    Ok(credential)
}

pub fn finish_signin<T: CeremonyReadTxn + ?Sized>(
    txn: &mut T,
    ceremony: &CeremonyId,
    assertion: &AssertionMaterial,
    now_ms: i64,
) -> Result<SignIn> {
    let row = checked_snapshot(
        txn,
        ceremony,
        CeremonyPurpose::SignIn,
        CeremonyState::Fresh,
        now_ms,
    )?;
    let credential_id = row
        .credential
        .clone()
        .ok_or_else(|| refusal("credential-id"))?;
    let mut credential = txn.credential(&credential_id)?;
    let binding = txn.owner_binding(&credential_id)?;
    if credential.binding != binding
        || binding.epoch != row.authority.epoch
        || binding.relying_party != row.origins.relying_party
        || binding.owner_origin != row.origins.owner_origin
        || Some(binding.top_origin.as_str()) != row.origins.expected_top_origin.as_deref()
    {
        return Err(refusal("ceremony-stale"));
    }
    let subject = row.subject.ok_or_else(|| refusal("ceremony-subject"))?;
    let observation = inspect_assertion(
        assertion,
        &credential,
        &row.origins,
        &row.nonce,
        ExtensionPolicy::None,
    )?;
    credential.binding.sign_counter = observation.counter();
    let signed_in = SignIn {
        session: row.session,
        subject,
        credential: credential_id,
        epoch: row.authority.epoch,
        transaction_id: txn.transaction_id(),
    };
    txn.stage_ceremony_finish(VerifiedCeremonyFinish {
        transaction_id: txn.transaction_id(),
        ceremony: row,
        credential,
        assertion: assertion.clone(),
        signed_bytes_digest: observation.signed_bytes_digest(),
        now_ms,
    })?;
    Ok(signed_in)
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}

fn validate_identity(identity: &EnrolmentIdentity) -> Result<()> {
    if identity.owner_id.is_empty()
        || identity.owner_id.len() > 256
        || identity.owner_id.chars().any(char::is_control)
        || identity.user_handle.is_empty()
        || identity.user_handle.len() > crate::webauthn::MAX_USER_HANDLE_BYTES
    {
        return Err(refusal("ceremony-data-invalid"));
    }
    Ok(())
}

/// Candidate persistence is a new versioned wrapper, never an added v1 WebAuthn field.
fn candidate_value(candidate: &RegistrationCandidate) -> serde_json::Value {
    serde_json::json!({
        "v": 1, "credential_id": hex::encode(candidate.credential_id.as_bytes()),
        "algorithm": candidate.public_key.algorithm.wire_name(), "key_version": candidate.public_key.v,
        "public_key": hex::encode(&candidate.public_key.bytes), "initial_counter": candidate.initial_counter,
        "backup_eligible": candidate.backup_eligible, "backup_state": candidate.backup_state,
        "aaguid": hex::encode(candidate.aaguid), "client_data_digest": candidate.client_data_digest.to_string(),
        "attestation_digest": candidate.attestation_digest.to_string(),
    })
}

pub fn candidate_digest(candidate: &RegistrationCandidate) -> Result<Digest32> {
    let bytes = serde_json::to_vec(&candidate_value(candidate))
        .map_err(|_| refusal("ceremony-candidate"))?;
    Ok(Digest32::from_bytes(Sha256::digest(bytes).into()))
}

#[cfg(not(target_arch = "wasm32"))]
mod durable {
    use super::*;
    use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
    use serde::{Deserialize, Serialize};
    use subtle::ConstantTimeEq;
    const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS aumlok_ceremonies_v1(
 id BLOB PRIMARY KEY CHECK(length(id)=16),
 purpose TEXT NOT NULL CHECK(purpose IN ('enrolment','signin','binding','refresh','backup','pair-device')),
 state TEXT NOT NULL CHECK(state IN ('fresh','reserved','registered','spent','finished','failed','expired')),
 context TEXT NOT NULL, nonce BLOB NOT NULL UNIQUE CHECK(length(nonce)=32),
 issued INTEGER NOT NULL CHECK(issued>=0), deadline INTEGER NOT NULL,
 last_seen INTEGER NOT NULL, claim_digest BLOB UNIQUE, resume_digest BLOB,
 candidate TEXT, candidate_digest BLOB,
 CHECK(deadline>issued AND deadline-issued<=300000 AND last_seen>=issued),
 CHECK(claim_digest IS NULL OR length(claim_digest)=32),
 CHECK(resume_digest IS NULL OR length(resume_digest)=32),
 CHECK(candidate_digest IS NULL OR length(candidate_digest)=32),
 CHECK((candidate IS NULL)=(candidate_digest IS NULL)),
 CHECK((purpose='enrolment')=(claim_digest IS NOT NULL)),
 CHECK(state NOT IN ('reserved','registered') OR resume_digest IS NOT NULL),
 CHECK(state!='registered' OR candidate IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS aumlok_ceremony_kdf_v1(id INTEGER PRIMARY KEY CHECK(id=1),key BLOB NOT NULL CHECK(length(key)=32));
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_kdf_no_update_v1 BEFORE UPDATE ON aumlok_ceremony_kdf_v1 BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-key-immutable'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_kdf_no_delete_v1 BEFORE DELETE ON aumlok_ceremony_kdf_v1 BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-key-immutable'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_kdf_no_replace_v1 BEFORE INSERT ON aumlok_ceremony_kdf_v1 WHEN EXISTS(SELECT 1 FROM aumlok_ceremony_kdf_v1) BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-key-immutable'); END;
CREATE UNIQUE INDEX IF NOT EXISTS aumlok_ceremonies_enrolment_v1
 ON aumlok_ceremonies_v1(purpose) WHERE purpose='enrolment' AND state NOT IN ('failed','expired');
CREATE TRIGGER IF NOT EXISTS aumlok_ceremonies_retain_v1
 BEFORE DELETE ON aumlok_ceremonies_v1 BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-retained'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremonies_new_v1
 BEFORE INSERT ON aumlok_ceremonies_v1
 WHEN NEW.state!='fresh' OR NEW.resume_digest IS NOT NULL OR NEW.candidate IS NOT NULL
 OR EXISTS(SELECT 1 FROM aumlok_ceremonies_v1 WHERE id=NEW.id OR nonce=NEW.nonce)
 BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-state'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremonies_forward_v1
 BEFORE UPDATE ON aumlok_ceremonies_v1
 WHEN NEW.id IS NOT OLD.id OR NEW.purpose IS NOT OLD.purpose OR NEW.context IS NOT OLD.context
 OR NEW.nonce IS NOT OLD.nonce OR NEW.issued IS NOT OLD.issued OR NEW.deadline IS NOT OLD.deadline
 OR NEW.claim_digest IS NOT OLD.claim_digest OR NEW.last_seen<OLD.last_seen
 OR (OLD.resume_digest IS NOT NULL AND NEW.resume_digest IS NOT OLD.resume_digest)
 OR (OLD.candidate IS NOT NULL AND (NEW.candidate IS NOT OLD.candidate OR NEW.candidate_digest IS NOT OLD.candidate_digest))
 OR (OLD.resume_digest IS NULL AND NEW.resume_digest IS NOT NULL AND NOT(OLD.state='fresh' AND NEW.state='reserved'))
 OR (OLD.candidate IS NULL AND NEW.candidate IS NOT NULL AND NOT(OLD.state='reserved' AND NEW.state='registered'))
 OR NOT(NEW.state=OLD.state OR (OLD.state='fresh' AND NEW.state IN ('reserved','spent','failed','expired'))
 OR (OLD.state='reserved' AND NEW.state IN ('registered','failed','expired'))
 OR (OLD.state='registered' AND NEW.state IN ('spent','failed','expired'))
 OR (OLD.state='spent' AND NEW.state='finished'))
 BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-rewind'); END;
"#;
    /// Trusted service configuration. A digest admits bootstrap; it grants no owner authority.
    #[derive(Clone, Debug)]
    pub struct CeremonyConfig {
        pub origins: OriginContext,
        pub identity: EnrolmentIdentity,
        pub subject: SubjectId,
        pub authority: AuthorityVersion,
        pub claim_digest: Option<Digest32>,
        /// Frontdoor-selected session after admission; never a browser-chosen handle.
        pub trusted_session: SessionId,
    }
    /// This store only writes nonauthorizing state. Authority writes belong to Aura.
    pub struct SqliteCeremonyStore {
        connection: Connection,
        config: CeremonyConfig,
        resume_key: zeroize::Zeroizing<[u8; 32]>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StoredContext {
        v: u16,
        rp: String,
        owner_origin: String,
        top_origin: String,
        owner_id: String,
        user_handle: String,
        session: String,
        subject: String,
        credential: Option<String>,
        epoch: u64,
        sequence: u64,
        previous_hash: Option<String>,
    }
    struct Row {
        id: CeremonyId,
        purpose: CeremonyPurpose,
        state: CeremonyState,
        context: StoredContext,
        nonce: [u8; 32],
        issued: i64,
        deadline: i64,
        last_seen: i64,
        claim_digest: Option<Vec<u8>>,
        resume_digest: Option<Vec<u8>>,
        candidate: Option<String>,
        candidate_digest: Option<Digest32>,
    }
    impl SqliteCeremonyStore {
        pub fn open(path: &std::path::Path, config: CeremonyConfig) -> Result<Self> {
            let file = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(|_| refusal("store-error"))?;
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o600))
                .map_err(|_| refusal("store-error"))?;
            let connection = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(store_error)?;
            Self::from_connection(connection, config)
        }
        fn from_connection(connection: Connection, config: CeremonyConfig) -> Result<Self> {
            if !connection.is_autocommit() || connection.path().is_none_or(str::is_empty) {
                return Err(refusal("store-not-durable"));
            }
            crate::webauthn::validate_origins(&config.origins)?;
            if config.origins.expected_top_origin.is_none()
                || config.authority.sequence == 0
                || config.authority.sequence > 9_007_199_254_740_991
                || config.authority.epoch > 9_007_199_254_740_991
                || (config.authority.sequence == 1) != config.authority.previous_hash.is_none()
            {
                return Err(refusal("ceremony-data-invalid"));
            }
            validate_identity(&config.identity)?;
            connection
                .busy_timeout(std::time::Duration::from_secs(2))
                .map_err(store_error)?;
            connection
                .execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
                .map_err(store_error)?;
            let journal: String = connection
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
                .map_err(store_error)?;
            if journal != "wal" {
                return Err(refusal("store-not-durable"));
            }
            connection.execute_batch(SCHEMA).map_err(store_error)?;
            let mut generated = zeroize::Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut generated[..]).map_err(|_| refusal("random-unavailable"))?;
            connection.execute("INSERT INTO aumlok_ceremony_kdf_v1(id,key) SELECT 1,?1 WHERE NOT EXISTS(SELECT 1 FROM aumlok_ceremony_kdf_v1)",[generated.as_slice()]).map_err(store_error)?;
            let stored: Vec<u8> = connection
                .query_row(
                    "SELECT key FROM aumlok_ceremony_kdf_v1 WHERE id=1",
                    [],
                    |row| row.get(0),
                )
                .map_err(store_error)?;
            let stored = zeroize::Zeroizing::new(stored);
            let resume_key = zeroize::Zeroizing::new(
                stored
                    .as_slice()
                    .try_into()
                    .map_err(|_| refusal("store-corrupt"))?,
            );
            Ok(Self {
                connection,
                config,
                resume_key,
            })
        }
        /// Read candidate data for an Aura adapter; this does not install a binding.
        pub fn candidate(&mut self, id: &CeremonyId) -> Result<RegistrationCandidate> {
            let row = load_row(&self.connection, id)?;
            let text = row
                .candidate
                .as_deref()
                .ok_or_else(|| refusal("registration-required"))?;
            let candidate = parse_candidate(text)?;
            if row.candidate_digest != Some(candidate_digest(&candidate)?) {
                return Err(refusal("store-corrupt"));
            }
            Ok(candidate)
        }
        fn write<R>(
            &mut self,
            action: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<R>,
        ) -> Result<R> {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(store_error)?;
            let result = action(&transaction);
            // Failed WebAuthn and expiry transitions are durable before the refusal is returned.
            transaction.commit().map_err(store_error)?;
            result
        }
    }
    impl CeremonyStore for SqliteCeremonyStore {
        fn load(&mut self, id: &CeremonyId) -> Result<CeremonySnapshot> {
            load_row(&self.connection, id)?.snapshot()
        }
        fn begin(&mut self, request: &BeginCeremony, now_ms: i64) -> Result<CeremonySnapshot> {
            if request.session != self.config.trusted_session {
                return Err(refusal("session-invalid"));
            }
            if !(0..=9_007_199_254_740_991 - MAX_CEREMONY_MS).contains(&now_ms)
                || (request.purpose == CeremonyPurpose::Enrolment && request.credential.is_some())
                || (request.purpose != CeremonyPurpose::Enrolment && request.credential.is_none())
            {
                return Err(refusal("ceremony-data-invalid"));
            }
            let deadline = now_ms
                .checked_add(MAX_CEREMONY_MS)
                .ok_or_else(|| refusal("ceremony-data-invalid"))?;
            let mut nonce = [0; 32];
            let mut id_bytes = [0; 16];
            getrandom::fill(&mut nonce).map_err(|_| refusal("random-unavailable"))?;
            getrandom::fill(&mut id_bytes).map_err(|_| refusal("random-unavailable"))?;
            let id = CeremonyId::from_bytes(id_bytes);
            let claim = if request.purpose == CeremonyPurpose::Enrolment {
                Some(
                    self.config
                        .claim_digest
                        .ok_or_else(|| refusal("claim-invalid"))?
                        .as_bytes()
                        .to_vec(),
                )
            } else {
                None
            };
            let context = StoredContext {
                v: 1,
                rp: self.config.origins.relying_party.clone(),
                owner_origin: self.config.origins.owner_origin.clone(),
                top_origin: self
                    .config
                    .origins
                    .expected_top_origin
                    .clone()
                    .ok_or_else(|| refusal("top-origin-invalid"))?,
                owner_id: self.config.identity.owner_id.clone(),
                user_handle: hex::encode(&self.config.identity.user_handle),
                session: request.session.to_string(),
                subject: self.config.subject.to_string(),
                credential: request
                    .credential
                    .as_ref()
                    .map(|id| hex::encode(id.as_bytes())),
                epoch: self.config.authority.epoch,
                sequence: self.config.authority.sequence,
                previous_hash: self
                    .config
                    .authority
                    .previous_hash
                    .map(|value| value.to_string()),
            };
            let context = serde_json::to_string(&context).map_err(|_| refusal("store-corrupt"))?;
            self.write(|tx| {
                tx.execute("UPDATE aumlok_ceremonies_v1 SET state='expired',last_seen=?1 WHERE deadline<=?1 AND last_seen<=?1 AND state IN ('fresh','reserved','registered')",[now_ms]).map_err(store_error)?;
                let previous:Option<Vec<u8>>=tx.query_row("SELECT id FROM aumlok_ceremonies_v1 WHERE purpose=?1 AND json_extract(context,'$.session')=?2 AND state IN ('fresh','reserved','registered') ORDER BY issued DESC LIMIT 1",params![request.purpose.wire_name(),request.session.to_string()],|row|row.get(0)).optional().map_err(store_error)?;
                if let Some(previous)=previous {
                    let previous=CeremonyId::from_bytes(previous.try_into().map_err(|_|refusal("store-corrupt"))?);
                    let row=load_row(tx,&previous)?;
                    if serde_json::to_string(&row.context).map_err(|_|refusal("store-corrupt"))?!=context || row.claim_digest!=claim { return Err(refusal("ceremony-context-changed")); }
                    touch(tx,&row,now_ms)?;
                    return load_row(tx,&previous)?.snapshot();
                }
                tx.execute("INSERT INTO aumlok_ceremonies_v1(id,purpose,state,context,nonce,issued,deadline,last_seen,claim_digest) VALUES(?1,?2,'fresh',?3,?4,?5,?6,?5,?7)",
                    params![id.as_bytes().as_slice(),request.purpose.wire_name(),context,nonce.as_slice(),now_ms,deadline,claim]).map_err(store_error)?;
                load_row(tx,&id)?.snapshot()
            })
        }
        fn reserve_enrolment(
            &mut self,
            id: &CeremonyId,
            claim: &ClaimSecret,
            now_ms: i64,
        ) -> Result<EnrolmentReservation> {
            let key = self.resume_key.clone();
            let session = self.config.trusted_session;
            self.write(|tx| {
                let row=load_row(tx,id)?;
                require_session(&row,session)?;
                if row.purpose!=CeremonyPurpose::Enrolment || !matches!(row.state,CeremonyState::Fresh|CeremonyState::Reserved|CeremonyState::Registered) { return Err(refusal("claim-spent")); }
                require_secret(&row.claim_digest,&claim.0,"claim-invalid")?;
                touch(tx,&row,now_ms)?;
                let mut secret=zeroize::Zeroizing::new(vec![0u8;32]);
                let mut info=b"aukora:ceremony-resume:v1\0".to_vec();
                info.extend_from_slice(id.as_bytes());
                info.extend_from_slice(row.claim_digest.as_deref().ok_or_else(||refusal("store-corrupt"))?);
                hkdf::Hkdf::<Sha256>::new(Some(&row.nonce),key.as_slice()).expand(&info,&mut secret).map_err(|_|refusal("store-corrupt"))?;
                let digest=Sha256::digest(&secret);
                if row.state!=CeremonyState::Fresh {
                    require_secret(&row.resume_digest,&secret,"session-invalid")?;
                    return Ok(EnrolmentReservation {ceremony:load_row(tx,id)?.snapshot()?,resume_secret:ResumeSecret(secret)});
                }
                let changed=tx.execute("UPDATE aumlok_ceremonies_v1 SET state='reserved',resume_digest=?2 WHERE id=?1 AND state='fresh'",
                    params![id.as_bytes().as_slice(),digest.as_slice()]).map_err(store_error)?;
                if changed!=1 { return Err(refusal("claim-spent")); }
                Ok(EnrolmentReservation { ceremony:load_row(tx,id)?.snapshot()?,resume_secret:ResumeSecret(secret) })
            })
        }
        fn resume_enrolment(
            &mut self,
            id: &CeremonyId,
            secret: &ResumeSecret,
            now_ms: i64,
        ) -> Result<CeremonySnapshot> {
            let session = self.config.trusted_session;
            self.write(|tx| {
                let row = load_row(tx, id)?;
                require_session(&row, session)?;
                require_resume(&row, secret)?;
                touch(tx, &row, now_ms)?;
                load_row(tx, id)?.snapshot()
            })
        }
        fn register_candidate(
            &mut self,
            id: &CeremonyId,
            secret: &ResumeSecret,
            material: &RegistrationMaterial,
            now_ms: i64,
        ) -> Result<CeremonySnapshot> {
            let session = self.config.trusted_session;
            self.write(|tx| {
                let row=load_row(tx,id)?;
                require_session(&row,session)?;
                require_resume(&row,secret)?;
                touch(tx,&row,now_ms)?;
                let snapshot=row.snapshot()?;
                let context=RegistrationContext {
                    origins:snapshot.origins,owner_id:row.context.owner_id.clone(),
                    user_handle:decode_hex(&row.context.user_handle)?,existing_credentials:Vec::new(),
                    challenge:row.nonce,extensions:ExtensionPolicy::RegistrationPrf,
                };
                let candidate=match verify_registration(material,&context) {
                    Ok(candidate)=>candidate,
                    Err(error)=>{
                        if row.state==CeremonyState::Registered {return Err(refusal("registration-closed"));}
                        tx.execute("UPDATE aumlok_ceremonies_v1 SET state='failed' WHERE id=?1 AND state='reserved'",[id.as_bytes().as_slice()]).map_err(store_error)?;
                        return Err(error);
                    }
                };
                let digest=candidate_digest(&candidate)?;
                if row.state==CeremonyState::Registered {
                    return if row.candidate_digest==Some(digest) {load_row(tx,id)?.snapshot()} else {Err(refusal("registration-closed"))};
                }
                let text=serde_json::to_string(&candidate_value(&candidate)).map_err(|_| refusal("ceremony-candidate"))?;
                let changed=tx.execute("UPDATE aumlok_ceremonies_v1 SET state='registered',candidate=?2,candidate_digest=?3 WHERE id=?1 AND state='reserved' AND candidate IS NULL",
                    params![id.as_bytes().as_slice(),text,digest.as_bytes().as_slice()]).map_err(store_error)?;
                if changed!=1 { return Err(refusal("registration-closed")); }
                load_row(tx,id)?.snapshot()
            })
        }
    }
    impl Row {
        fn snapshot(&self) -> Result<CeremonySnapshot> {
            if self.context.v != 1
                || self.context.sequence == 0
                || self.context.sequence > 9_007_199_254_740_991
                || self.issued < 0
                || self.last_seen < self.issued
                || self.deadline <= self.issued
                || self.deadline - self.issued > MAX_CEREMONY_MS
            {
                return Err(refusal("store-corrupt"));
            }
            let subject = self
                .context
                .subject
                .strip_prefix("aukora:1:")
                .ok_or_else(|| refusal("store-corrupt"))?;
            let origins = OriginContext {
                relying_party: self.context.rp.clone(),
                owner_origin: self.context.owner_origin.clone(),
                expected_top_origin: Some(self.context.top_origin.clone()),
            };
            crate::webauthn::validate_origins(&origins)?;
            Ok(CeremonySnapshot {
                version: 1,
                id: self.id,
                purpose: self.purpose,
                state: self.state,
                origins,
                session: SessionId::from_hex(&self.context.session)?,
                subject: Some(SubjectId::from_digest(Digest32::from_hex(subject)?)),
                credential: self
                    .context
                    .credential
                    .as_deref()
                    .map(|text| CredentialId::new(decode_hex(text)?))
                    .transpose()?,
                nonce: self.nonce,
                expires_at_ms: self.deadline,
                authority: AuthorityVersion {
                    epoch: self.context.epoch,
                    sequence: self.context.sequence,
                    previous_hash: self
                        .context
                        .previous_hash
                        .as_deref()
                        .map(Digest32::from_hex)
                        .transpose()?,
                },
                candidate_digest: self.candidate_digest,
            })
        }
    }
    fn load_row(connection: &Connection, id: &CeremonyId) -> Result<Row> {
        let raw=connection.query_row("SELECT purpose,state,context,nonce,issued,deadline,last_seen,claim_digest,resume_digest,candidate,candidate_digest FROM aumlok_ceremonies_v1 WHERE id=?1",
            [id.as_bytes().as_slice()],|r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?,r.get::<_,i64>(6)?,r.get::<_,Option<Vec<u8>>>(7)?,r.get::<_,Option<Vec<u8>>>(8)?,r.get::<_,Option<String>>(9)?,r.get::<_,Option<Vec<u8>>>(10)?)))
            .optional().map_err(store_error)?.ok_or_else(|| refusal("ceremony-not-found"))?;
        if raw.2.len() > 8192 || raw.9.as_ref().is_some_and(|value| value.len() > 16384) {
            return Err(refusal("store-corrupt"));
        }
        Ok(Row {
            id: *id,
            purpose: CeremonyPurpose::parse(&raw.0)?,
            state: CeremonyState::from_wire(&raw.1)?,
            context: serde_json::from_str(&raw.2).map_err(|_| refusal("store-corrupt"))?,
            nonce: raw.3.try_into().map_err(|_| refusal("store-corrupt"))?,
            issued: raw.4,
            deadline: raw.5,
            last_seen: raw.6,
            claim_digest: raw.7,
            resume_digest: raw.8,
            candidate: raw.9,
            candidate_digest: raw
                .10
                .map(|bytes| {
                    bytes
                        .try_into()
                        .map(Digest32::from_bytes)
                        .map_err(|_| refusal("store-corrupt"))
                })
                .transpose()?,
        })
    }
    fn touch(tx: &rusqlite::Transaction<'_>, row: &Row, now_ms: i64) -> Result<()> {
        if now_ms < row.issued || now_ms < row.last_seen {
            return Err(refusal("ceremony-clock"));
        }
        if now_ms >= row.deadline {
            tx.execute("UPDATE aumlok_ceremonies_v1 SET state='expired',last_seen=?2 WHERE id=?1 AND state IN ('fresh','reserved','registered')",params![row.id.as_bytes().as_slice(),now_ms]).map_err(store_error)?;
            return Err(refusal("ceremony-expired"));
        }
        tx.execute(
            "UPDATE aumlok_ceremonies_v1 SET last_seen=?2 WHERE id=?1",
            params![row.id.as_bytes().as_slice(), now_ms],
        )
        .map_err(store_error)?;
        Ok(())
    }
    fn require_session(row: &Row, session: SessionId) -> Result<()> {
        if row.context.session != session.to_string() {
            return Err(refusal("session-invalid"));
        }
        Ok(())
    }
    fn require_resume(row: &Row, secret: &ResumeSecret) -> Result<()> {
        if row.purpose != CeremonyPurpose::Enrolment
            || !matches!(
                row.state,
                CeremonyState::Reserved | CeremonyState::Registered
            )
        {
            return Err(refusal("enrolment-closed"));
        }
        require_secret(&row.resume_digest, &secret.0, "session-invalid")
    }
    fn require_secret(
        expected: &Option<Vec<u8>>,
        secret: &[u8],
        reason: &'static str,
    ) -> Result<()> {
        if secret.len() != 32 {
            return Err(refusal(reason));
        }
        let expected = expected.as_deref().ok_or_else(|| refusal(reason))?;
        let actual = Sha256::digest(secret);
        if expected.len() != 32 || !bool::from(expected.ct_eq(actual.as_slice())) {
            return Err(refusal(reason));
        }
        Ok(())
    }
    fn decode_hex(text: &str) -> Result<Vec<u8>> {
        if text
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(refusal("store-corrupt"));
        }
        hex::decode(text).map_err(|_| refusal("store-corrupt"))
    }
    fn parse_candidate(text: &str) -> Result<RegistrationCandidate> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Candidate {
            v: u16,
            credential_id: String,
            algorithm: String,
            key_version: u16,
            public_key: String,
            initial_counter: u32,
            backup_eligible: bool,
            backup_state: bool,
            aaguid: String,
            client_data_digest: String,
            attestation_digest: String,
        }
        let stored: Candidate = serde_json::from_str(text).map_err(|_| refusal("store-corrupt"))?;
        let algorithm = canon::alg::AlgorithmId::from_wire(&stored.algorithm)?;
        let bytes = decode_hex(&stored.public_key)?;
        if stored.v != 1
            || stored.key_version != 1
            || (stored.backup_state && !stored.backup_eligible)
            || !matches!(
                (algorithm, bytes.len()),
                (canon::alg::AlgorithmId::Ed25519, 32)
                    | (canon::alg::AlgorithmId::EcdsaP256Sha256, 65)
            )
        {
            return Err(refusal("store-corrupt"));
        }
        Ok(RegistrationCandidate {
            credential_id: CredentialId::new(decode_hex(&stored.credential_id)?)?,
            public_key: canon::alg::PublicKey {
                v: 1,
                algorithm,
                bytes,
            },
            initial_counter: stored.initial_counter,
            backup_eligible: stored.backup_eligible,
            backup_state: stored.backup_state,
            aaguid: decode_hex(&stored.aaguid)?
                .try_into()
                .map_err(|_| refusal("store-corrupt"))?,
            client_data_digest: Digest32::from_hex(&stored.client_data_digest)?,
            attestation_digest: Digest32::from_hex(&stored.attestation_digest)?,
        })
    }
    fn store_error(_error: rusqlite::Error) -> Refusal {
        refusal("store-error")
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub use durable::{CeremonyConfig, SqliteCeremonyStore};
