//! Durable phrase binding, without an owner authorization or Aura implementation.
//!
//! Contracts v1 specifies the subject shape but no root-key or subject domains.
//! Version 1 uses SHA256("aukora:aumlok-root-key:v1\0" || root32) as an
//! Ed25519 seed and SHA256("aukora:aumlok-subject:v1\0" || public32) as its
//! subject suffix. CONFIRMED is the durable commit point; recovery never retries it.

use crate::envelope::{seal, Envelope, KdfParams};
use crate::phrase::Phrase;
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

pub const BINDING_VERSION: u32 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS aumlok_binding (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version = 1),
    state TEXT NOT NULL CHECK (state IN ('EMPTY','PREPARED','CONFIRMED','COMPLETED','IN_DOUBT')),
    subject TEXT,
    envelope TEXT,
    CHECK (
        (state = 'EMPTY' AND subject IS NULL AND envelope IS NULL)
        OR
        (state <> 'EMPTY' AND typeof(subject) = 'text' AND length(subject) = 73
            AND substr(subject, 1, 9) = 'aukora:1:'
            AND substr(subject, 10) NOT GLOB '*[^0-9a-f]*'
            AND typeof(envelope) = 'text' AND length(envelope) > 0)
    )
);
CREATE TRIGGER IF NOT EXISTS aumlok_binding_no_replace
BEFORE INSERT ON aumlok_binding
WHEN EXISTS (SELECT 1 FROM aumlok_binding)
BEGIN
    SELECT RAISE(ABORT, 'aumlok:binding-exists');
END;
CREATE TRIGGER IF NOT EXISTS aumlok_binding_no_delete
BEFORE DELETE ON aumlok_binding
BEGIN
    SELECT RAISE(ABORT, 'aumlok:binding-final');
END;
CREATE TRIGGER IF NOT EXISTS aumlok_binding_forward_only
BEFORE UPDATE ON aumlok_binding
WHEN NEW.id <> OLD.id OR NEW.version <> OLD.version OR NOT (
    (OLD.state = 'EMPTY' AND NEW.state = 'PREPARED') OR
    (OLD.state = 'PREPARED' AND NEW.state = 'CONFIRMED') OR
    (OLD.state = 'CONFIRMED' AND NEW.state IN ('COMPLETED','IN_DOUBT'))
)
BEGIN
    SELECT RAISE(ABORT, 'aumlok:invalid-transition');
END;
CREATE TRIGGER IF NOT EXISTS aumlok_binding_identity_immutable
BEFORE UPDATE ON aumlok_binding
WHEN OLD.state <> 'EMPTY' AND (NEW.subject IS NOT OLD.subject OR NEW.envelope IS NOT OLD.envelope)
BEGIN
    SELECT RAISE(ABORT, 'aumlok:identity-immutable');
END;
INSERT INTO aumlok_binding (id, state) SELECT 1, 'EMPTY'
WHERE NOT EXISTS (SELECT 1 FROM aumlok_binding);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingState {
    Empty,
    Prepared,
    Confirmed,
    Completed,
    InDoubt,
}

impl BindingState {
    fn from_sql(value: &str) -> Option<Self> {
        match value {
            "EMPTY" => Some(Self::Empty),
            "PREPARED" => Some(Self::Prepared),
            "CONFIRMED" => Some(Self::Confirmed),
            "COMPLETED" => Some(Self::Completed),
            "IN_DOUBT" => Some(Self::InDoubt),
            _ => None,
        }
    }

    fn committed(self) -> bool {
        matches!(self, Self::Confirmed | Self::Completed | Self::InDoubt)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingDisposition {
    Refused,
    InDoubt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct BindingError {
    code: &'static str,
    disposition: BindingDisposition,
}

impl BindingError {
    pub fn code(self) -> &'static str {
        self.code
    }

    pub fn disposition(self) -> BindingDisposition {
        self.disposition
    }

    fn refused(code: &'static str) -> Self {
        Self {
            code,
            disposition: BindingDisposition::Refused,
        }
    }

    fn in_doubt() -> Self {
        Self::uncertain("aumlok:binding-in-doubt")
    }

    fn uncertain(code: &'static str) -> Self {
        Self {
            code,
            disposition: BindingDisposition::InDoubt,
        }
    }
}

#[derive(Clone)]
pub struct BindingRecord {
    pub state: BindingState,
    pub subject: String,
    pub envelope: Envelope,
}

pub enum BindingOutcome {
    Completed(BindingRecord),
    InDoubt(BindingRecord),
}

pub struct BindingStore {
    pub(crate) connection: Connection,
}

/// Derive a versioned subject from a random root, never directly from a phrase.
pub fn subject_from_root(root: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aukora:aumlok-root-key:v1\0");
    hash.update(root);
    let seed = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    let signing = SigningKey::from_bytes(&seed);
    let mut hash = Sha256::new();
    hash.update(b"aukora:aumlok-subject:v1\0");
    hash.update(signing.verifying_key().as_bytes());
    format!("aukora:1:{}", hex::encode(hash.finalize()))
}

impl BindingStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BindingError> {
        let connection = Connection::open(path)
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self, BindingError> {
        let connection = Connection::open_in_memory()
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        Self::from_connection(connection)
    }

    pub fn from_connection(connection: Connection) -> Result<Self, BindingError> {
        Self::initialize(connection)
    }

    fn initialize(mut connection: Connection) -> Result<Self, BindingError> {
        connection
            .busy_timeout(Duration::from_secs(5))
            .and_then(|()| connection.pragma_update(None, "journal_mode", "WAL"))
            .and_then(|()| connection.pragma_update(None, "synchronous", "FULL"))
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        transaction
            .execute_batch(SCHEMA)
            .map_err(|_| BindingError::uncertain("aumlok:binding-schema"))?;
        transaction
            .execute_batch(crate::refresh::SCHEMA)
            .map_err(|_| BindingError::uncertain("aumlok:refresh-schema"))?;
        crate::refresh::initialize_current(&transaction)
            .map_err(|_| BindingError::uncertain("aumlok:refresh-storage"))?;
        transaction
            .commit()
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        let mut store = Self { connection };
        store.recover()?;
        Ok(store)
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// The supervisor hands off its completed binding inside its writer transaction.
    pub fn adopt_completed(
        transaction: &rusqlite::Transaction<'_>,
        root: &[u8; 32],
        envelope: &Envelope,
    ) -> Result<(), BindingError> {
        let subject = subject_from_root(root);
        let json = envelope.to_canonical_json();
        let (state, existing) = read_binding(transaction)?;
        if state != BindingState::Empty {
            let original: Option<(String, String)> = transaction
                .query_row(
                    "SELECT subject,envelope FROM aumlok_binding WHERE state='COMPLETED'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
            return if original == Some((subject, json)) && existing.is_some() {
                Ok(())
            } else {
                Err(BindingError::refused("aumlok:identity-immutable"))
            };
        }
        transaction.execute("UPDATE aumlok_binding SET state='PREPARED',subject=?1,envelope=?2 WHERE id=1 AND state='EMPTY'", rusqlite::params![subject, json])
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        transaction
            .execute(
                "UPDATE aumlok_binding SET state='CONFIRMED' WHERE id=1 AND state='PREPARED'",
                [],
            )
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        write_terminal(transaction, "COMPLETED", &subject)
    }

    pub fn state(&self) -> Result<BindingState, BindingError> {
        read_binding(&self.connection).map(|(state, _)| state)
    }

    pub fn binding(&self) -> Result<Option<BindingRecord>, BindingError> {
        read_binding(&self.connection).map(|(_, binding)| binding)
    }

    /// A prepared bind resumes its persisted envelope without drawing another root.
    pub fn prepare(
        &mut self,
        phrase: &Phrase,
        kdf: KdfParams,
    ) -> Result<BindingRecord, BindingError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        let (state, binding) = read_binding(&transaction)?;
        match state {
            BindingState::Prepared => {
                return binding.ok_or_else(|| BindingError::refused("aumlok:binding-corrupt"));
            }
            BindingState::Completed => {
                return Err(BindingError::refused("aumlok:already-bound"));
            }
            BindingState::Confirmed | BindingState::InDoubt => {
                return Err(BindingError::in_doubt());
            }
            BindingState::Empty => {}
        }
        let sealed = seal(phrase, kdf).map_err(|error| BindingError::refused(error.code()))?;
        let subject = subject_from_root(&sealed.root);
        let envelope = sealed.envelope.to_canonical_json();
        let changed = transaction
            .execute(
                "UPDATE aumlok_binding SET state = 'PREPARED', subject = ?1, envelope = ?2 WHERE id = 1 AND state = 'EMPTY'",
                params![subject, envelope],
            )
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        if changed != 1 {
            return Err(BindingError::refused("aumlok:binding-race"));
        }
        transaction
            .commit()
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        Ok(BindingRecord {
            state: BindingState::Prepared,
            subject,
            envelope: sealed.envelope,
        })
    }

    /// The supervisor calls this only after its owner confirmation ceremony.
    pub fn confirm(&mut self, subject: &str) -> Result<BindingRecord, BindingError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        let (state, binding) = read_binding(&transaction)?;
        let mut binding = match state {
            BindingState::Empty => {
                return Err(BindingError::refused("aumlok:not-prepared"));
            }
            BindingState::Completed => {
                return Err(BindingError::refused("aumlok:already-bound"));
            }
            BindingState::Confirmed | BindingState::InDoubt => {
                return Err(BindingError::in_doubt());
            }
            BindingState::Prepared => {
                binding.ok_or_else(|| BindingError::refused("aumlok:binding-corrupt"))?
            }
        };
        if binding.subject != subject {
            return Err(BindingError::refused("aumlok:subject-mismatch"));
        }
        let changed = transaction
            .execute(
                "UPDATE aumlok_binding SET state = 'CONFIRMED' WHERE id = 1 AND state = 'PREPARED' AND subject = ?1",
                [subject],
            )
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
        if changed != 1 {
            return Err(BindingError::refused("aumlok:binding-race"));
        }
        if transaction.commit().is_err() {
            let _ = self.recover();
            return Err(BindingError::in_doubt());
        }
        binding.state = BindingState::Confirmed;
        Ok(binding)
    }

    /// The finalizer is never retried after an error, panic, or restart.
    pub fn complete<F, E>(
        &mut self,
        subject: &str,
        finalizer: F,
    ) -> Result<BindingOutcome, BindingError>
    where
        F: FnOnce(&BindingRecord) -> Result<(), E>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::in_doubt())?;
        let (state, binding) = read_binding(&transaction).map_err(|_| BindingError::in_doubt())?;
        if state == BindingState::Completed {
            return Err(BindingError::refused("aumlok:already-bound"));
        }
        if state != BindingState::Confirmed {
            return Err(if state.committed() {
                BindingError::in_doubt()
            } else {
                BindingError::refused("aumlok:not-confirmed")
            });
        }
        let binding = binding.ok_or_else(BindingError::in_doubt)?;
        if binding.subject != subject {
            write_terminal(&transaction, "IN_DOUBT", &binding.subject)?;
            transaction.commit().map_err(|_| BindingError::in_doubt())?;
            return Err(BindingError::in_doubt());
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| finalizer(&binding)));
        if !matches!(result, Ok(Ok(()))) {
            write_terminal(&transaction, "IN_DOUBT", subject)?;
            transaction.commit().map_err(|_| BindingError::in_doubt())?;
            let mut binding = binding;
            binding.state = BindingState::InDoubt;
            return Ok(BindingOutcome::InDoubt(binding));
        }
        let completion = write_terminal(&transaction, "COMPLETED", subject);
        if completion.is_err() {
            write_terminal(&transaction, "IN_DOUBT", subject)?;
            transaction.commit().map_err(|_| BindingError::in_doubt())?;
            return Err(BindingError::in_doubt());
        }
        if transaction.commit().is_err() {
            let _ = self.mark_in_doubt();
            return Err(BindingError::in_doubt());
        }
        let mut binding = binding;
        binding.state = BindingState::Completed;
        Ok(BindingOutcome::Completed(binding))
    }

    /// Reconcile a crash after the commit point without re-running the finalizer.
    pub fn recover(&mut self) -> Result<(), BindingError> {
        let (state, _) = read_binding(&self.connection)?;
        if state == BindingState::Confirmed {
            self.mark_in_doubt()?;
        }
        Ok(())
    }

    fn mark_in_doubt(&mut self) -> Result<(), BindingError> {
        let (_, binding) = read_binding(&self.connection).map_err(|_| BindingError::in_doubt())?;
        let binding = binding.ok_or_else(BindingError::in_doubt)?;
        self.set_terminal("IN_DOUBT", &binding.subject)
    }

    fn set_terminal(&mut self, state: &str, subject: &str) -> Result<(), BindingError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| BindingError::in_doubt())?;
        write_terminal(&transaction, state, subject)?;
        transaction.commit().map_err(|_| BindingError::in_doubt())
    }
}

fn write_terminal(connection: &Connection, state: &str, subject: &str) -> Result<(), BindingError> {
    let changed = connection
        .execute(
            "UPDATE aumlok_binding SET state = ?1 WHERE id = 1 AND state = 'CONFIRMED' AND subject = ?2",
            params![state, subject],
        )
        .map_err(|_| BindingError::in_doubt())?;
    if changed != 1 {
        return Err(BindingError::in_doubt());
    }
    if state == "COMPLETED" {
        crate::refresh::initialize_current(connection).map_err(|_| BindingError::in_doubt())?;
    }
    Ok(())
}

fn read_binding(
    connection: &Connection,
) -> Result<(BindingState, Option<BindingRecord>), BindingError> {
    let (version, state, subject, envelope): (u32, String, Option<String>, Option<String>) =
        connection
            .query_row(
                "SELECT version, state, subject, envelope FROM aumlok_binding WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| BindingError::uncertain("aumlok:binding-storage"))?;
    if version != BINDING_VERSION {
        return Err(BindingError::uncertain("aumlok:binding-version"));
    }
    let state = BindingState::from_sql(&state)
        .ok_or_else(|| BindingError::uncertain("aumlok:binding-corrupt"))?;
    let invalid = || {
        if state.committed() {
            BindingError::in_doubt()
        } else {
            BindingError::refused("aumlok:binding-corrupt")
        }
    };
    if state == BindingState::Empty {
        return if subject.is_none() && envelope.is_none() {
            Ok((state, None))
        } else {
            Err(invalid())
        };
    }
    let subject = subject.ok_or_else(invalid)?;
    let mut envelope =
        Envelope::from_canonical_json(&envelope.ok_or_else(invalid)?).map_err(|_| invalid())?;
    if state == BindingState::Completed {
        let current = crate::refresh::read_current(connection)
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        if current.subject != subject {
            return Err(invalid());
        }
        envelope = current.envelope;
    }
    Ok((
        state,
        Some(BindingRecord {
            state,
            subject,
            envelope,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    fn phrase() -> Phrase {
        Phrase::draw().expect("test entropy source")
    }

    fn kdf() -> KdfParams {
        KdfParams {
            memory_kib: 32,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn prepared() -> (BindingStore, BindingRecord) {
        let mut store = BindingStore::in_memory().expect("memory database");
        let binding = store.prepare(&phrase(), kdf()).expect("prepare");
        (store, binding)
    }

    fn confirmed() -> (BindingStore, BindingRecord) {
        let (mut store, binding) = prepared();
        let binding = store.confirm(&binding.subject).expect("confirm");
        (store, binding)
    }

    #[test]
    fn antibody_completed_binding_handoff_pins_identity_and_rolls_back() {
        let mut store =
            BindingStore::from_connection(Connection::open_in_memory().unwrap()).unwrap();
        let phrase = phrase();
        let sealed = seal(&phrase, kdf()).unwrap();
        {
            let tx = store.connection_mut().transaction().unwrap();
            BindingStore::adopt_completed(&tx, &sealed.root, &sealed.envelope).unwrap();
        }
        assert_eq!(store.state().unwrap(), BindingState::Empty);
        let tx = store.connection_mut().transaction().unwrap();
        BindingStore::adopt_completed(&tx, &sealed.root, &sealed.envelope).unwrap();
        tx.commit().unwrap();
        assert_eq!(store.state().unwrap(), BindingState::Completed);
        assert_eq!(
            *store
                .open_current(
                    &crate::refresh::envelope_sha256(&sealed.envelope),
                    "owner",
                    &phrase,
                    1000
                )
                .unwrap(),
            *sealed.root
        );
        let tx = store.connection_mut().transaction().unwrap();
        BindingStore::adopt_completed(&tx, &sealed.root, &sealed.envelope).unwrap();
        assert_eq!(
            BindingStore::adopt_completed(&tx, &[0; 32], &sealed.envelope)
                .unwrap_err()
                .code(),
            "aumlok:identity-immutable"
        );
        let other = seal(&phrase, kdf()).unwrap();
        assert_eq!(
            BindingStore::adopt_completed(&tx, &sealed.root, &other.envelope)
                .unwrap_err()
                .code(),
            "aumlok:identity-immutable"
        );
    }

    fn disposition<T>(result: Result<T, BindingError>) -> BindingError {
        match result {
            Ok(_) => panic!("unexpected acceptance"),
            Err(error) => error,
        }
    }

    #[test]
    fn empty_requires_preparation_before_confirmation_or_completion() {
        let mut store = BindingStore::in_memory().unwrap();
        assert_eq!(store.state().unwrap(), BindingState::Empty);
        assert!(store.binding().unwrap().is_none());
        assert_eq!(
            store.confirm("unknown").err().unwrap().code(),
            "aumlok:not-prepared"
        );
        let mut called = false;
        let error = disposition(store.complete("unknown", |_| {
            called = true;
            Ok::<_, ()>(())
        }));
        assert_eq!(error.code(), "aumlok:not-confirmed");
        assert!(!called);
        assert_eq!(store.state().unwrap(), BindingState::Empty);
    }

    #[test]
    fn prepared_persists_and_resumes_the_original_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("binding.sqlite");
        let mut store = BindingStore::open(&path).unwrap();
        let original = store.prepare(&phrase(), kdf()).unwrap();
        let json = original.envelope.to_canonical_json();
        assert_eq!(store.state().unwrap(), BindingState::Prepared);
        drop(store);
        let mut store = BindingStore::open(&path).unwrap();
        let resumed = store.prepare(&phrase(), kdf()).unwrap();
        assert_eq!(resumed.subject, original.subject);
        assert_eq!(resumed.envelope.to_canonical_json(), json);
        assert_eq!(resumed.state, BindingState::Prepared);
    }

    #[test]
    fn same_phrase_on_another_node_does_not_recreate_identity() {
        let phrase = phrase();
        let mut first = BindingStore::in_memory().unwrap();
        let mut second = BindingStore::in_memory().unwrap();
        let first = first.prepare(&phrase, kdf()).unwrap();
        let second = second.prepare(&phrase, kdf()).unwrap();
        assert_ne!(first.subject, second.subject);
        assert_ne!(
            first.envelope.to_canonical_json(),
            second.envelope.to_canonical_json()
        );
    }

    #[test]
    fn subject_is_versioned_domain_separated_ed25519_public_key_hash() {
        let root = [7; 32];
        let seed: [u8; 32] =
            Sha256::digest([b"aukora:aumlok-root-key:v1\0".as_slice(), &root].concat()).into();
        let public = SigningKey::from_bytes(&seed).verifying_key();
        let expected =
            Sha256::digest([b"aukora:aumlok-subject:v1\0".as_slice(), public.as_bytes()].concat());
        assert_eq!(
            subject_from_root(&root),
            format!("aukora:1:{}", hex::encode(expected))
        );
        assert_ne!(
            subject_from_root(&root),
            format!("aukora:1:{}", hex::encode(Sha256::digest(root)))
        );
        assert_ne!(subject_from_root(&root), subject_from_root(&[8; 32]));
        assert_eq!(subject_from_root(&root).len(), 73);
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/binding-subject-v1.json")).unwrap();
        for vector in vectors["vectors"].as_array().unwrap() {
            let root: [u8; 32] = hex::decode(vector["root_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                subject_from_root(&root),
                vector["subject"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn confirmation_checks_the_prepared_subject() {
        let (mut store, binding) = prepared();
        let error = store.confirm("aukora:1:wrong").err().unwrap();
        assert_eq!(error.code(), "aumlok:subject-mismatch");
        assert_eq!(error.disposition(), BindingDisposition::Refused);
        assert_eq!(store.state().unwrap(), BindingState::Prepared);
        assert_eq!(
            store.confirm(&binding.subject).unwrap().state,
            BindingState::Confirmed
        );
    }

    #[test]
    fn prepared_completion_requires_confirmation() {
        let (mut store, binding) = prepared();
        let mut called = false;
        let error = disposition(store.complete(&binding.subject, |_| {
            called = true;
            Ok::<_, ()>(())
        }));
        assert_eq!(error.code(), "aumlok:not-confirmed");
        assert!(!called);
        assert_eq!(store.state().unwrap(), BindingState::Prepared);
    }

    #[test]
    fn successful_completion_is_final_and_second_bind_is_refused() {
        let (mut store, binding) = confirmed();
        match store
            .complete(&binding.subject, |_| Ok::<_, ()>(()))
            .unwrap()
        {
            BindingOutcome::Completed(result) => assert_eq!(result.state, BindingState::Completed),
            BindingOutcome::InDoubt(_) => panic!("unexpected uncertainty"),
        }
        assert_eq!(store.state().unwrap(), BindingState::Completed);
        assert_eq!(
            store.prepare(&phrase(), kdf()).err().unwrap().code(),
            "aumlok:already-bound"
        );
        assert_eq!(
            store.confirm(&binding.subject).err().unwrap().code(),
            "aumlok:already-bound"
        );
        let mut called = false;
        let error = disposition(store.complete(&binding.subject, |_| {
            called = true;
            Ok::<_, ()>(())
        }));
        assert_eq!(error.code(), "aumlok:already-bound");
        assert!(!called);
        assert_eq!(store.binding().unwrap().unwrap().subject, binding.subject);
    }

    #[test]
    fn postcommit_finalizer_error_is_in_doubt_and_never_retried() {
        let (mut store, binding) = confirmed();
        match store
            .complete(&binding.subject, |_| Err::<(), _>("injected failure"))
            .unwrap()
        {
            BindingOutcome::InDoubt(result) => assert_eq!(result.state, BindingState::InDoubt),
            BindingOutcome::Completed(_) => panic!("failure became success"),
        }
        assert_eq!(store.state().unwrap(), BindingState::InDoubt);
        let error = store.prepare(&phrase(), kdf()).err().unwrap();
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
        assert_eq!(
            store.confirm(&binding.subject).err().unwrap().disposition(),
            BindingDisposition::InDoubt
        );
        let mut called = false;
        let error = disposition(store.complete(&binding.subject, |_| {
            called = true;
            Ok::<_, ()>(())
        }));
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
        assert!(!called);
    }

    #[test]
    fn postcommit_panic_is_in_doubt() {
        let (mut store, binding) = confirmed();
        let result = store
            .complete(&binding.subject, |_| -> Result<(), ()> {
                panic!("injected finalizer panic")
            })
            .unwrap();
        assert!(matches!(result, BindingOutcome::InDoubt(_)));
        assert_eq!(store.state().unwrap(), BindingState::InDoubt);
    }

    #[test]
    fn postcommit_database_failure_is_in_doubt() {
        let (mut store, binding) = confirmed();
        store.connection.execute_batch("CREATE TRIGGER test_completion_failure BEFORE UPDATE ON aumlok_binding WHEN NEW.state = 'COMPLETED' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
        let error = disposition(store.complete(&binding.subject, |_| Ok::<_, ()>(())));
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
        assert_eq!(store.state().unwrap(), BindingState::InDoubt);
    }

    #[test]
    fn failed_commit_is_never_refused() {
        let (mut store, binding) = prepared();
        store.connection.execute_batch("PRAGMA foreign_keys = ON; CREATE TABLE fault_parent (id INTEGER PRIMARY KEY); CREATE TABLE fault_child (parent_id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER test_confirm_commit_failure AFTER UPDATE ON aumlok_binding WHEN NEW.state = 'CONFIRMED' BEGIN INSERT INTO fault_child VALUES (1); END;").unwrap();
        let error = store.confirm(&binding.subject).err().unwrap();
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
        assert_eq!(store.state().unwrap(), BindingState::Prepared);
        store
            .connection
            .execute_batch("DROP TRIGGER test_confirm_commit_failure;")
            .unwrap();
        store.confirm(&binding.subject).unwrap();
        store.connection.execute_batch("CREATE TRIGGER test_complete_commit_failure AFTER UPDATE ON aumlok_binding WHEN NEW.state = 'COMPLETED' BEGIN INSERT INTO fault_child VALUES (1); END;").unwrap();
        let error = disposition(store.complete(&binding.subject, |_| Ok::<_, ()>(())));
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
        assert_eq!(store.state().unwrap(), BindingState::InDoubt);
    }

    #[test]
    fn postcommit_read_transaction_and_initialization_failures_are_in_doubt() {
        let (mut store, binding) = confirmed();
        store.connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        let prepare = store.prepare(&phrase(), kdf()).err().unwrap();
        let confirm = store.confirm(&binding.subject).err().unwrap();
        let complete = disposition(store.complete(&binding.subject, |_| Ok::<_, ()>(())));
        assert_eq!(prepare.disposition(), BindingDisposition::InDoubt);
        assert_eq!(confirm.disposition(), BindingDisposition::InDoubt);
        assert_eq!(complete.disposition(), BindingDisposition::InDoubt);
        store
            .connection
            .execute_batch(
                "ROLLBACK; ALTER TABLE aumlok_binding RENAME TO temporarily_unreadable_binding;",
            )
            .unwrap();
        assert_eq!(
            store.state().err().unwrap().disposition(),
            BindingDisposition::InDoubt
        );
        assert_eq!(
            store.binding().err().unwrap().disposition(),
            BindingDisposition::InDoubt
        );
        store.connection.execute_batch("ALTER TABLE temporarily_unreadable_binding RENAME TO aumlok_binding; PRAGMA query_only = ON;").unwrap();
        let connection = store.connection;
        let error = match BindingStore::initialize(connection) {
            Ok(_) => panic!("read-only initialization accepted"),
            Err(error) => error,
        };
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
    }

    #[test]
    fn wrong_subject_after_commit_is_in_doubt() {
        let (mut store, _) = confirmed();
        let mut called = false;
        let error = disposition(store.complete("wrong", |_| {
            called = true;
            Ok::<_, ()>(())
        }));
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
        assert!(!called);
        assert_eq!(store.state().unwrap(), BindingState::InDoubt);
    }

    #[test]
    fn reopening_confirmed_recovers_in_doubt_with_original_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("binding.sqlite");
        let mut store = BindingStore::open(&path).unwrap();
        let prepared = store.prepare(&phrase(), kdf()).unwrap();
        let confirmed = store.confirm(&prepared.subject).unwrap();
        drop(store);
        let store = BindingStore::open(&path).unwrap();
        let recovered = store.binding().unwrap().unwrap();
        assert_eq!(recovered.state, BindingState::InDoubt);
        assert_eq!(recovered.subject, confirmed.subject);
        assert_eq!(
            recovered.envelope.to_canonical_json(),
            confirmed.envelope.to_canonical_json()
        );
        drop(store);
        assert_eq!(
            BindingStore::open(&path).unwrap().state().unwrap(),
            BindingState::InDoubt
        );
    }

    #[test]
    fn sqlite_is_wal_with_full_synchronous_durability() {
        let directory = tempfile::tempdir().unwrap();
        let store = BindingStore::open(directory.path().join("binding.sqlite")).unwrap();
        let journal: String = store
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        let synchronous: i64 = store
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(journal, "wal");
        assert_eq!(synchronous, 2);
    }

    #[test]
    fn sqlite_forbids_skips_backwards_and_terminal_rewrites() {
        let (mut store, binding) = prepared();
        assert!(store
            .connection
            .execute("UPDATE aumlok_binding SET state = NULL", [])
            .is_err());
        for state in ["EMPTY", "COMPLETED", "IN_DOUBT", "PREPARED"] {
            assert!(
                store
                    .connection
                    .execute("UPDATE aumlok_binding SET state = ?1", [state])
                    .is_err(),
                "accepted {state}"
            );
        }
        store.confirm(&binding.subject).unwrap();
        for state in ["EMPTY", "PREPARED", "CONFIRMED"] {
            assert!(
                store
                    .connection
                    .execute("UPDATE aumlok_binding SET state = ?1", [state])
                    .is_err(),
                "accepted {state}"
            );
        }
        store
            .complete(&binding.subject, |_| Ok::<_, ()>(()))
            .unwrap();
        for state in ["EMPTY", "PREPARED", "CONFIRMED", "IN_DOUBT", "COMPLETED"] {
            assert!(
                store
                    .connection
                    .execute("UPDATE aumlok_binding SET state = ?1", [state])
                    .is_err(),
                "accepted {state}"
            );
        }
    }

    #[test]
    fn sqlite_forbids_replacing_or_deleting_the_single_binding() {
        let (store, binding) = prepared();
        assert!(store
            .connection
            .execute("DELETE FROM aumlok_binding", [])
            .is_err());
        assert!(store
            .connection
            .execute(
                "INSERT OR REPLACE INTO aumlok_binding (id, state) VALUES (1, 'EMPTY')",
                []
            )
            .is_err());
        assert!(store
            .connection
            .execute(
                "INSERT INTO aumlok_binding (id, state) VALUES (2, 'EMPTY')",
                []
            )
            .is_err());
        assert_eq!(store.binding().unwrap().unwrap().subject, binding.subject);
    }

    #[test]
    fn sqlite_singleton_check_rejects_second_rows() {
        let store = BindingStore::in_memory().unwrap();
        store
            .connection
            .execute_batch("DROP TRIGGER aumlok_binding_no_replace;")
            .unwrap();
        assert!(store
            .connection
            .execute(
                "INSERT INTO aumlok_binding (id, state) VALUES (2, 'EMPTY')",
                []
            )
            .is_err());
    }

    #[test]
    fn terminal_compare_and_set_requires_one_matching_binding() {
        let (store, _) = confirmed();
        let error = write_terminal(&store.connection, "COMPLETED", "wrong")
            .err()
            .unwrap();
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
        assert_eq!(store.state().unwrap(), BindingState::Confirmed);
    }

    #[test]
    fn sqlite_identity_and_envelope_are_immutable() {
        let (store, binding) = prepared();
        assert!(store
            .connection
            .execute(
                "UPDATE aumlok_binding SET state = 'CONFIRMED', subject = NULL",
                []
            )
            .is_err());
        assert!(store
            .connection
            .execute(
                "UPDATE aumlok_binding SET state = 'CONFIRMED', envelope = NULL",
                []
            )
            .is_err());
        let other = subject_from_root(&[99; 32]);
        assert!(store
            .connection
            .execute(
                "UPDATE aumlok_binding SET state = 'CONFIRMED', subject = ?1",
                [other]
            )
            .is_err());
        assert!(store
            .connection
            .execute(
                "UPDATE aumlok_binding SET state = 'CONFIRMED', envelope = 'changed'",
                []
            )
            .is_err());
        assert_eq!(store.binding().unwrap().unwrap().subject, binding.subject);
        assert_eq!(store.state().unwrap(), BindingState::Prepared);
    }

    #[test]
    fn sqlite_requires_complete_prepared_payload() {
        let store = BindingStore::in_memory().unwrap();
        assert!(store
            .connection
            .execute("UPDATE aumlok_binding SET state = 'PREPARED'", [])
            .is_err());
        assert!(store.connection.execute("UPDATE aumlok_binding SET state = 'PREPARED', subject = 'aukora:1:short', envelope = 'x'", []).is_err());
        let subject = subject_from_root(&[31; 32]);
        assert!(store
            .connection
            .execute(
                "UPDATE aumlok_binding SET state = 'PREPARED', subject = ?1, envelope = ''",
                [subject]
            )
            .is_err());
        assert_eq!(store.state().unwrap(), BindingState::Empty);
    }

    #[test]
    fn binding_versions_cannot_gain_authority_or_be_rewritten() {
        let (store, binding) = prepared();
        assert!(store
            .connection
            .execute(
                "UPDATE aumlok_binding SET state = 'CONFIRMED', version = 2",
                []
            )
            .is_err());
        store
            .connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        assert!(store
            .connection
            .execute(
                "UPDATE aumlok_binding SET state = 'CONFIRMED', version = 2",
                []
            )
            .is_err());
        store
            .connection
            .execute_batch(
                "DROP TRIGGER aumlok_binding_forward_only; UPDATE aumlok_binding SET version = 2;",
            )
            .unwrap();
        let error = store.binding().err().unwrap();
        assert_eq!(error.code(), "aumlok:binding-version");
        assert_eq!(error.disposition(), BindingDisposition::InDoubt);
        let persisted: String = store
            .connection
            .query_row("SELECT subject FROM aumlok_binding", [], |row| row.get(0))
            .unwrap();
        assert_eq!(persisted, binding.subject);
    }

    #[test]
    fn concurrent_prepares_return_one_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("binding.sqlite");
        let first = BindingStore::open(&path).unwrap();
        let second = BindingStore::open(&path).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|mut store| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let phrase = phrase();
                    barrier.wait();
                    store.prepare(&phrase, kdf()).unwrap()
                })
            })
            .collect();
        let mut bindings = handles.into_iter().map(|handle| handle.join().unwrap());
        let first = bindings.next().unwrap();
        let second = bindings.next().unwrap();
        assert_eq!(first.subject, second.subject);
        assert_eq!(
            first.envelope.to_canonical_json(),
            second.envelope.to_canonical_json()
        );
    }

    #[test]
    fn concurrent_completions_execute_the_finalizer_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("binding.sqlite");
        let mut first = BindingStore::open(&path).unwrap();
        let second = BindingStore::open(&path).unwrap();
        let prepared = first.prepare(&phrase(), kdf()).unwrap();
        first.confirm(&prepared.subject).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|mut store| {
                let barrier = Arc::clone(&barrier);
                let calls = Arc::clone(&calls);
                let subject = prepared.subject.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.complete(&subject, |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        Ok::<_, ()>(())
                    })
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(BindingOutcome::Completed(_))))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(
                    |result| matches!(result, Err(error) if error.code() == "aumlok:already-bound")
                )
                .count(),
            1
        );
    }
}
