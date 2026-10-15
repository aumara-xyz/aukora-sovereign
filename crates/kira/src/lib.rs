//! Encrypted memory and atomic Aura commitments for one owner.
//!
//! Aura is a stub in this checkout. Its adapter must implement [`Ledger`]; no
//! production ledger or alternate journal is provided here.

use std::collections::BTreeMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub mod openviking;

const AAD_DOMAIN: &[u8] = b"aukora:kira-aead:v1\0";
pub const HOSTED_CONTEXT_SCOPE: &str = "hosted-model-context";
const MAX_TIME: i64 = (1_i64 << 53) - 1;
pub const MAX_CATEGORY_BYTES: usize = 64;
pub const MAX_STATEMENT_BYTES: usize = 4 * 1024;
pub const MAX_QUOTE_BYTES: usize = 4 * 1024;
pub const GUEST_WINDOW_MS: i64 = 60_000;
pub const GUEST_MAX_PER_WINDOW: i64 = 32;
const MAX_NOTE_BYTES: usize =
    6 * (MAX_CATEGORY_BYTES + MAX_STATEMENT_BYTES + MAX_QUOTE_BYTES) + 128;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kira:store-unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("kira:ledger-unverified")]
    Ledger(#[from] LedgerError),
    #[error("kira:random-unavailable")]
    Random,
    #[error("kira:authentication-failed")]
    Authentication,
    #[error("kira:store-corrupt")]
    Corrupt,
    #[error("kira:invalid-field")]
    InvalidField,
    #[error("kira:category-invalid")]
    CategoryInvalid,
    #[error("kira:statement-too-large")]
    StatementTooLarge,
    #[error("kira:quote-too-large")]
    QuoteTooLarge,
    #[error("kira:budget-exhausted")]
    BudgetExhausted,
    #[error("kira:budget-unavailable")]
    BudgetUnavailable,
    #[error("kira:note-not-found")]
    NoteNotFound,
    #[error("kira:disclosure-not-permitted")]
    DisclosureNotPermitted,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("aura:unverified")]
pub struct LedgerError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tier {
    Owner,
    Model,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Model => "model",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaveCommitment {
    pub note_id: String,
    pub key_id: String,
    pub ciphertext_sha256: String,
    pub category: String,
    pub tier: Tier,
    pub at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemoteCommitment {
    pub note_id: String,
    pub prior_seq: i64,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionCommitment {
    pub owner_subject: String,
    pub scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Body {
    Save(SaveCommitment),
    Demote(DemoteCommitment),
    Permission(PermissionCommitment),
}

impl Body {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Save(_) => "kira.save",
            Self::Demote(_) => "kira.demote",
            Self::Permission(_) => "kira.permission",
        }
    }
}

/// A C3 `fact` row: `op` is empty and `body` has exactly the variant's fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fact {
    pub actor: String,
    pub at: i64,
    pub body: Body,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub seq: i64,
    pub fact: Fact,
}

pub trait Ledger {
    /// Append to C3's `aura` table in this transaction; never commit separately.
    fn append_inside_transaction(
        &self,
        transaction: &Transaction<'_>,
        fact: &Fact,
    ) -> Result<i64, LedgerError>;

    /// Verify the entire Aura chain (including signatures and non-Kira rows) in
    /// this snapshot, then return its Kira facts in sequence order. Failure to
    /// read or verify any row is an error, even if there are no Kira facts.
    /// Completeness against a retained head remains Aura's responsibility.
    fn verified_entries(&self, transaction: &Transaction<'_>) -> Result<Vec<Entry>, LedgerError>;
}

pub struct Note<'a> {
    pub note_id: &'a str,
    pub key_id: &'a str,
    pub text: &'a str,
    pub category: &'a str,
    pub tier: Tier,
    pub at: i64,
}

/// The caller must verify the owner's passkey authorization before construction.
pub struct VerifiedPermission {
    pub owner_subject: String,
    pub at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    Owner,
    HostedModelContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallItem {
    pub note_id: String,
    pub text: String,
    pub cite_seq: i64,
    pub category: String,
    pub tier: Tier,
    pub attribution: &'static str,
    pub at: i64,
}

impl RecallItem {
    /// This label must accompany text when an adapter builds model context.
    pub fn attribution(&self) -> &'static str {
        self.attribution
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Recall {
    Found(Vec<RecallItem>),
    Empty,
    Undetermined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedNote {
    pub note_id: String,
    pub category: String,
    pub at: i64,
    pub cite_seq: i64,
    pub text: Option<String>,
    pub demoted_seq: Option<i64>,
    pub demoted_at: Option<i64>,
}

pub struct Store<L> {
    connection: Connection,
    ledger: L,
    owner_subject: String,
    root: Option<Zeroizing<[u8; 32]>>,
    openviking: Option<openviking::Client>,
    semantic_io: std::sync::Arc<std::sync::Mutex<()>>,
}

impl<L: Ledger> Store<L> {
    /// Use the supervisor's Aura connection, in the same SQLite database file.
    pub fn new(
        mut connection: Connection,
        ledger: L,
        owner_subject: String,
    ) -> Result<Self, Error> {
        if owner_subject.is_empty() {
            return Err(Error::InvalidField);
        }
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS kira_keys (
                 key_id TEXT PRIMARY KEY NOT NULL,
                 key BLOB NOT NULL CHECK(length(key) = 32)
             );
             CREATE TABLE IF NOT EXISTS kira_notes (
                 note_id TEXT PRIMARY KEY NOT NULL,
                 key_id TEXT UNIQUE NOT NULL REFERENCES kira_keys(key_id),
                 nonce BLOB NOT NULL CHECK(length(nonce) = 24),
                 ciphertext BLOB NOT NULL,
                 category TEXT NOT NULL,
                 tier TEXT NOT NULL CHECK(tier IN ('owner', 'model')),
                 at INTEGER NOT NULL,
                 demoted INTEGER NOT NULL DEFAULT 0 CHECK(demoted IN (0, 1))
             );
             CREATE TABLE IF NOT EXISTS kira_guest_budget (
                 owner_subject TEXT PRIMARY KEY NOT NULL,
                 window_start INTEGER NOT NULL,
                 used INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS kira_semantic_index (
                 uri TEXT PRIMARY KEY NOT NULL,
                 note_id TEXT NOT NULL REFERENCES kira_notes(note_id),
                 byte_start INTEGER NOT NULL,
                 byte_end INTEGER NOT NULL,
                 removal INTEGER NOT NULL DEFAULT 0 CHECK(removal IN (0, 1)),
                 pending INTEGER NOT NULL DEFAULT 1 CHECK(pending IN (0, 1))
             );",
        )?;
        let has_derivation: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('kira_keys') WHERE name = 'derived')",
            [],
            |row| row.get(0),
        )?;
        if !has_derivation {
            connection.execute_batch(
                "ALTER TABLE kira_keys ADD COLUMN derived INTEGER NOT NULL DEFAULT 0
                 CHECK(derived IN (0, 1));",
            )?;
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let has_cold: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='kira_cold')",
            [],
            |row| row.get(0),
        )?;
        if !has_cold {
            tx.execute_batch(
                "CREATE TABLE kira_cold (
                     note_id TEXT PRIMARY KEY NOT NULL REFERENCES kira_notes(note_id),
                     ciphertext BLOB NOT NULL
                 );
                 INSERT INTO kira_cold(note_id, ciphertext)
                     SELECT note_id, ciphertext FROM kira_notes WHERE demoted = 1;
                 UPDATE kira_notes SET ciphertext = X'' WHERE demoted = 1;",
            )?;
        }
        tx.commit()?;
        Ok(Self {
            connection,
            ledger,
            owner_subject,
            root: None,
            openviking: None,
            semantic_io: std::sync::Arc::new(std::sync::Mutex::new(())),
        })
    }

    /// Root-backed notes store a fresh derivation salt rather than their encryption key.
    pub fn with_root(
        connection: Connection,
        ledger: L,
        owner_subject: String,
        root: Zeroizing<[u8; 32]>,
    ) -> Result<Self, Error> {
        let mut store = Self::new(connection, ledger, owner_subject)?;
        store.root = Some(root);
        Ok(store)
    }

    pub fn openviking_enabled(&self) -> bool {
        self.openviking.is_some()
    }

    /// A separate SQLite handle keeps bounded index I/O outside owner locks.
    pub fn fork_with_connection(&self, connection: Connection) -> Result<Self, Error>
    where
        L: Clone,
    {
        let mut fork = Self::new(connection, self.ledger.clone(), self.owner_subject.clone())?;
        fork.root = self.root.clone();
        fork.openviking = self.openviking.clone();
        fork.semantic_io = self.semantic_io.clone();
        Ok(fork)
    }

    /// Only encrypted Kira notes can create an index target.
    pub fn configure_openviking(
        &mut self,
        client: Option<openviking::Client>,
    ) -> Result<(), Error> {
        self.openviking = client;
        let Some(client) = self.openviking.clone() else {
            return Ok(());
        };
        let items = self.recall_verified(Purpose::Owner)?;
        let tx = self.connection.transaction()?;
        for item in items {
            queue_note(&tx, &client, &item.note_id, &item.text)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn save(&mut self, note: Note<'_>) -> Result<i64, Error> {
        if note.note_id.is_empty() || note.key_id.is_empty() || !valid_time(note.at) {
            return Err(Error::InvalidField);
        }
        validate_note(&note)?;
        let material = random_key()?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
        let aad = associated_data(&self.owner_subject, note.note_id, note.key_id)?;
        let key = note_key(
            self.root.as_deref(),
            &material[..],
            &aad,
            self.root.is_some(),
        )?;
        let ciphertext = encrypt(&key[..], &nonce, note.text.as_bytes(), &aad)?;
        let fact = Fact {
            actor: self.owner_subject.clone(),
            at: note.at,
            body: Body::Save(SaveCommitment {
                note_id: note.note_id.to_owned(),
                key_id: note.key_id.to_owned(),
                ciphertext_sha256: ciphertext_hash(&ciphertext),
                category: note.category.to_owned(),
                tier: note.tier,
                at: note.at,
            }),
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO kira_keys (key_id, key, derived) VALUES (?1, ?2, ?3)",
            params![note.key_id, &material[..], i64::from(self.root.is_some())],
        )?;
        tx.execute(
            "INSERT INTO kira_notes (note_id, key_id, nonce, ciphertext, category, tier, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                note.note_id,
                note.key_id,
                &nonce[..],
                ciphertext,
                note.category,
                note.tier.as_str(),
                note.at
            ],
        )?;
        let seq = self.ledger.append_inside_transaction(&tx, &fact)?;
        if let Some(client) = &self.openviking {
            queue_note(&tx, client, note.note_id, note.text)?;
        }
        tx.commit()?;
        if let Some(client) = self.openviking.clone() {
            let _ = self.sync_openviking(&client, client.deadline());
        }
        Ok(seq)
    }

    /// Charge every guest memory attempt before validation or disclosure checks.
    pub fn charge_guest(&mut self, at: i64) -> Result<(), Error> {
        if !valid_time(at) {
            return Err(Error::BudgetUnavailable);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(i64, i64)> = tx
            .query_row(
                "SELECT window_start, used FROM kira_guest_budget WHERE owner_subject = ?1",
                [&self.owner_subject],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (start, used) = match old {
            Some((start, used)) if !valid_time(start) || start > at || used < 0 => {
                return Err(Error::BudgetUnavailable);
            }
            Some((start, used)) if at - start < GUEST_WINDOW_MS => (start, used),
            _ => (at, 0),
        };
        if used >= GUEST_MAX_PER_WINDOW {
            return Err(Error::BudgetExhausted);
        }
        tx.execute(
            "INSERT INTO kira_guest_budget(owner_subject, window_start, used) VALUES (?1, ?2, ?3)
             ON CONFLICT(owner_subject) DO UPDATE SET window_start=excluded.window_start,
                 used=excluded.used",
            params![self.owner_subject, start, used + 1],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn sync_pending_openviking(&mut self) -> Result<(), Error> {
        let Some(client) = self.openviking.clone() else {
            return Ok(());
        };
        let pending: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM kira_semantic_index WHERE pending = 1)",
            [],
            |row| row.get(0),
        )?;
        if pending {
            self.sync_openviking(&client, client.deadline())?;
        }
        Ok(())
    }

    pub fn demote_queued(&mut self, note_id: &str, reason: &str, at: i64) -> Result<i64, Error> {
        self.demote_inner(note_id, reason, at, false)
    }

    /// Demotion retains the ciphertext and key. Repeated demotion cites its row.
    pub fn demote(&mut self, note_id: &str, reason: &str, at: i64) -> Result<i64, Error> {
        self.demote_inner(note_id, reason, at, true)
    }

    fn demote_inner(
        &mut self,
        note_id: &str,
        reason: &str,
        at: i64,
        sync: bool,
    ) -> Result<i64, Error> {
        if !valid_time(at) {
            return Err(Error::InvalidField);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = verified_state(&self.ledger, &tx, &self.owner_subject)?;
        let saved = state.notes.get(note_id).ok_or(Error::NoteNotFound)?;
        if let Some(seq) = saved.demoted_at {
            return Ok(seq);
        }
        let retained = tx.execute(
            "INSERT INTO kira_cold(note_id, ciphertext)
             SELECT note_id, ciphertext FROM kira_notes WHERE note_id = ?1 AND demoted = 0",
            [note_id],
        )?;
        if retained != 1 {
            return Err(Error::Corrupt);
        }
        let changed = tx.execute(
            "UPDATE kira_notes SET demoted = 1, ciphertext = X''
             WHERE note_id = ?1 AND demoted = 0",
            [note_id],
        )?;
        if changed != 1 {
            return Err(Error::Corrupt);
        }
        let fact = Fact {
            actor: self.owner_subject.clone(),
            at,
            body: Body::Demote(DemoteCommitment {
                note_id: note_id.to_owned(),
                prior_seq: saved.seq,
                reason: reason.to_owned(),
            }),
        };
        let seq = self.ledger.append_inside_transaction(&tx, &fact)?;
        tx.execute(
            "UPDATE kira_semantic_index SET removal = 1, pending = 1 WHERE note_id = ?1",
            [note_id],
        )?;
        tx.commit()?;
        if sync {
            if let Some(client) = self.openviking.clone() {
                let _ = self.sync_openviking(&client, client.deadline());
            }
        }
        Ok(seq)
    }

    pub fn permit_hosted_context(&mut self, permission: VerifiedPermission) -> Result<i64, Error> {
        if permission.owner_subject != self.owner_subject || !valid_time(permission.at) {
            return Err(Error::InvalidField);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = verified_state(&self.ledger, &tx, &self.owner_subject)?;
        if let Some(seq) = state.permission_seq {
            return Ok(seq);
        }
        let fact = Fact {
            actor: self.owner_subject.clone(),
            at: permission.at,
            body: Body::Permission(PermissionCommitment {
                owner_subject: permission.owner_subject,
                scope: HOSTED_CONTEXT_SCOPE.to_owned(),
            }),
        };
        let seq = self.ledger.append_inside_transaction(&tx, &fact)?;
        tx.commit()?;
        Ok(seq)
    }

    pub fn recall(&mut self, purpose: Purpose) -> Result<Recall, Error> {
        match self.recall_verified(purpose) {
            Ok(items) if items.is_empty() => Ok(Recall::Empty),
            Ok(items) => Ok(Recall::Found(items)),
            Err(Error::DisclosureNotPermitted) => Err(Error::DisclosureNotPermitted),
            Err(_) => Ok(Recall::Undetermined),
        }
    }

    /// Demoted pages contain commitment metadata and never decrypt cold notes.
    pub fn list(
        &mut self,
        purpose: Purpose,
        forgotten: bool,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ListedNote>, Error> {
        let tx = self.connection.transaction()?;
        let state = verified_state(&self.ledger, &tx, &self.owner_subject)?;
        if !forgotten && purpose == Purpose::HostedModelContext && state.permission_seq.is_none() {
            return Err(Error::DisclosureNotPermitted);
        }
        let mut notes: Vec<_> = state
            .notes
            .into_iter()
            .filter(|(_, saved)| saved.demoted_at.is_some() == forgotten)
            .collect();
        notes.sort_by_key(|(_, saved)| std::cmp::Reverse(saved.seq));
        let start = match before {
            Some(id) => {
                notes
                    .iter()
                    .position(|(note_id, _)| note_id == id)
                    .ok_or(Error::InvalidField)?
                    + 1
            }
            None => 0,
        };
        let mut items = Vec::new();
        for (note_id, saved) in notes.into_iter().skip(start).take(limit) {
            let text = if forgotten {
                None
            } else {
                let aad = associated_data(&self.owner_subject, &note_id, &saved.commitment.key_id)?;
                let (nonce, ciphertext, material, derived) = tx.query_row(
                    "SELECT n.nonce, n.ciphertext, k.key, k.derived FROM kira_notes n
                     JOIN kira_keys k ON k.key_id=n.key_id
                     WHERE n.note_id=?1 AND n.demoted=0",
                    [&note_id],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            stored_key(row, 2)?,
                            row.get::<_, bool>(3)?,
                        ))
                    },
                )?;
                let key = note_key(self.root.as_deref(), &material, &aad, derived)?;
                let plaintext = decrypt(&key[..], &nonce, &ciphertext, &aad)?;
                Some(String::from_utf8(plaintext).map_err(|_| Error::Corrupt)?)
            };
            items.push(ListedNote {
                note_id,
                category: saved.commitment.category,
                at: saved.commitment.at,
                cite_seq: saved.seq,
                text,
                demoted_seq: saved.demoted_at,
                demoted_at: saved.demoted_time,
            });
        }
        tx.commit()?;
        Ok(items)
    }

    pub fn recall_query(
        &mut self,
        purpose: Purpose,
        query: &str,
        limit: usize,
    ) -> Result<Recall, Error> {
        let Some(client) = self.openviking.clone() else {
            return match self.recall(purpose)? {
                Recall::Found(items) => {
                    let query = query.to_lowercase();
                    let items: Vec<_> = items
                        .into_iter()
                        .filter(|item| {
                            query.is_empty() || item.text.to_lowercase().contains(&query)
                        })
                        .take(limit)
                        .collect();
                    Ok(if items.is_empty() {
                        Recall::Empty
                    } else {
                        Recall::Found(items)
                    })
                }
                other => Ok(other),
            };
        };
        match self.recall_semantic(&client, purpose, query, limit) {
            Ok(items) if items.is_empty() => Ok(Recall::Empty),
            Ok(items) => Ok(Recall::Found(items)),
            Err(Error::DisclosureNotPermitted) => Err(Error::DisclosureNotPermitted),
            Err(_) => Ok(Recall::Undetermined),
        }
    }

    fn recall_semantic(
        &mut self,
        client: &openviking::Client,
        purpose: Purpose,
        query: &str,
        limit: usize,
    ) -> Result<Vec<RecallItem>, Error> {
        // Permission precedes every index or search request.
        self.recall_verified(purpose)?;
        let deadline = client.deadline();
        self.sync_openviking(client, deadline)?;
        let hits = client.search(query, deadline).map_err(|_| Error::Corrupt)?;
        // Network answers never supply text, citations, or attribution.
        let mut items = self.recall_verified(purpose)?;
        let mut ranked = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for hit in hits {
            for item in &mut items {
                if seen.contains(&item.note_id) {
                    continue;
                }
                let text = semantic_text(&item.text);
                if !semantic_eligible(&text) {
                    continue;
                }
                if openviking::parts(&text)
                    .iter()
                    .any(|(start, end, _)| client.uri(&item.note_id, *start, *end) == hit.uri)
                {
                    seen.insert(item.note_id.clone());
                    let mut item = item.clone();
                    item.text = text.chars().take(openviking::MAX_ITEM_CHARS).collect();
                    ranked.push(item);
                }
            }
        }
        ranked.truncate(limit.min(openviking::MAX_HITS));
        Ok(ranked)
    }

    fn sync_openviking(
        &mut self,
        client: &openviking::Client,
        deadline: std::time::Instant,
    ) -> Result<(), Error> {
        let semantic_io = self.semantic_io.clone();
        let _guard = semantic_io.try_lock().map_err(|_| Error::Corrupt)?;
        let mut statement = self.connection.prepare(
            "SELECT uri, note_id, byte_start, byte_end, removal FROM kira_semantic_index
             WHERE pending = 1 ORDER BY removal DESC, uri LIMIT 8",
        )?;
        let pending = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)? as usize,
                    row.get::<_, u32>(3)? as usize,
                    row.get::<_, bool>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let items = self.recall_verified(Purpose::Owner)?;
        for (uri, note_id, start, end, removal) in pending {
            if removal {
                client.delete(&uri, deadline).map_err(|_| Error::Corrupt)?;
                self.connection.execute(
                    "DELETE FROM kira_semantic_index WHERE uri = ?1 AND removal = 1",
                    [&uri],
                )?;
            } else {
                let item = items
                    .iter()
                    .find(|item| item.note_id == note_id)
                    .ok_or(Error::Corrupt)?;
                let statement = semantic_text(&item.text);
                let text = statement.get(start..end).ok_or(Error::Corrupt)?;
                if client.uri(&note_id, start, end) != uri {
                    return Err(Error::Corrupt);
                }
                client
                    .write(&uri, text, deadline)
                    .map_err(|_| Error::Corrupt)?;
                self.connection.execute(
                    "UPDATE kira_semantic_index SET pending = 0 WHERE uri = ?1 AND removal = 0",
                    [&uri],
                )?;
            }
        }
        let pending: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM kira_semantic_index WHERE pending = 1)",
            [],
            |row| row.get(0),
        )?;
        if pending {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    fn recall_verified(&mut self, purpose: Purpose) -> Result<Vec<RecallItem>, Error> {
        let tx = self.connection.transaction()?;
        let state = verified_state(&self.ledger, &tx, &self.owner_subject)?;
        if purpose == Purpose::HostedModelContext && state.permission_seq.is_none() {
            return Err(Error::DisclosureNotPermitted);
        }
        let mut items = Vec::new();
        for (note_id, saved) in state.notes {
            if saved.demoted_at.is_some() {
                continue;
            }
            let aad = associated_data(&self.owner_subject, &note_id, &saved.commitment.key_id)?;
            let (nonce, ciphertext, material, derived) = tx.query_row(
                "SELECT n.nonce, n.ciphertext, k.key, k.derived FROM kira_notes n
                 JOIN kira_keys k ON k.key_id = n.key_id
                 WHERE n.note_id = ?1 AND n.demoted = 0",
                [&note_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        stored_key(row, 2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )?;
            let key = note_key(self.root.as_deref(), &material, &aad, derived)?;
            let text = decrypt(&key[..], &nonce, &ciphertext, &aad)?;
            let text = String::from_utf8(text).map_err(|_| Error::Corrupt)?;
            items.push(RecallItem {
                note_id,
                text,
                cite_seq: saved.seq,
                category: saved.commitment.category,
                tier: saved.commitment.tier,
                attribution: match saved.commitment.tier {
                    Tier::Owner => "owner-authored",
                    Tier::Model => "model-authored (untrusted)",
                },
                at: saved.commitment.at,
            });
        }
        items.sort_by_key(|item| item.cite_seq);
        tx.commit()?;
        Ok(items)
    }
}

fn semantic_text(text: &str) -> std::borrow::Cow<'_, str> {
    if let Ok(value) = canon::parse(text.as_bytes()) {
        if let Some(canon::Value::String(statement)) = value.get("statement") {
            return std::borrow::Cow::Owned(statement.clone());
        }
    }
    std::borrow::Cow::Borrowed(text)
}

fn semantic_eligible(text: &str) -> bool {
    let text = text.trim();
    if text.len() < 12 || !text.chars().any(char::is_alphanumeric) {
        return false;
    }
    // Non-ASCII letters wait for Prime's NFKC eligibility normalization.
    if text.chars().any(|c| !c.is_ascii() && c.is_alphanumeric()) {
        return false;
    }
    // Wrapped input waits for a normalized statement-only eligibility check.
    if text.starts_with("From: ")
        && text.split_once("\n\n").is_some_and(|(header, _)| {
            header
                .split_once('\n')
                .is_some_and(|(_, when)| when.starts_with("When: ") && !when.contains('\n'))
        })
    {
        return false;
    }
    let normalized = text.to_lowercase();
    let words: Vec<_> = normalized
        .split(|c: char| !c.is_alphanumeric() && c != '\'')
        .filter(|word| !word.is_empty())
        .collect();
    if words.len() < 2 {
        return false;
    }
    if ["ignore", "disregard", "forget", "override"]
        .iter()
        .any(|word| normalized.contains(word))
        && ["instruction", "prompt", "rule", "message", "direction"]
            .iter()
            .any(|word| normalized.contains(word))
    {
        return false;
    }
    let mut leading = words.as_slice();
    while leading
        .first()
        .is_some_and(|word| matches!(*word, "please" | "now" | "just" | "ok" | "okay" | "so"))
    {
        leading = &leading[1..];
    }
    if words.len() <= 40
        && leading.first().is_some_and(|word| {
            matches!(
                *word,
                "reply"
                    | "respond"
                    | "answer"
                    | "say"
                    | "output"
                    | "print"
                    | "return"
                    | "write"
                    | "type"
                    | "repeat"
                    | "echo"
                    | "pretend"
            )
        })
    {
        return false;
    }
    if leading.starts_with(&["you", "are", "now"]) {
        return false;
    }
    if words.iter().all(|word| {
        matches!(
            *word,
            "ok" | "okay"
                | "yes"
                | "yeah"
                | "yep"
                | "yup"
                | "sure"
                | "thanks"
                | "thank"
                | "you"
                | "got"
                | "it"
                | "understood"
                | "cool"
                | "great"
                | "awesome"
                | "done"
                | "continue"
                | "go"
                | "ahead"
                | "please"
                | "stay"
                | "vigilant"
                | "keep"
                | "going"
                | "carry"
                | "on"
        )
    }) {
        return false;
    }
    if text.len() > 60 {
        return true;
    }
    let claim = words.iter().any(|word| {
        matches!(
            *word,
            "am" | "is"
                | "are"
                | "was"
                | "were"
                | "have"
                | "has"
                | "had"
                | "want"
                | "wants"
                | "prefer"
                | "prefers"
                | "need"
                | "needs"
                | "must"
                | "should"
                | "shall"
                | "will"
                | "won't"
                | "cannot"
                | "can't"
                | "decided"
                | "agreed"
                | "preserve"
                | "require"
                | "requires"
                | "use"
                | "uses"
                | "live"
                | "lives"
                | "means"
                | "contain"
                | "contains"
                | "work"
                | "works"
                | "failed"
                | "succeeded"
                | "stand"
                | "stands"
                | "finished"
                | "never"
                | "always"
                | "only"
                | "exactly"
                | "don't"
                | "not"
                | "no"
                | "stop"
        )
    });
    let named = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .any(|word| {
            let lower = word.to_lowercase();
            if matches!(
                lower.as_str(),
                "i" | "the"
                    | "this"
                    | "that"
                    | "it"
                    | "we"
                    | "you"
                    | "my"
                    | "our"
                    | "your"
                    | "please"
                    | "thanks"
                    | "yes"
                    | "okay"
                    | "stay"
                    | "keep"
                    | "continue"
                    | "go"
                    | "do"
                    | "what"
                    | "how"
                    | "when"
                    | "where"
                    | "why"
                    | "can"
                    | "could"
                    | "would"
                    | "should"
                    | "just"
                    | "now"
                    | "all"
                    | "and"
                    | "but"
                    | "from"
            ) {
                return false;
            }
            let mut chars = word.chars();
            chars.next().is_some_and(char::is_uppercase)
                && word.chars().count() >= 3
                && chars.all(char::is_lowercase)
        });
    claim
        || named
        || text.contains("https://")
        || text.contains("http://")
        || [".mjs", ".js", ".py", ".json", ".md"]
            .iter()
            .any(|suffix| text.contains(suffix))
        || text.matches('"').count() >= 2
}

fn queue_note(
    tx: &Transaction<'_>,
    client: &openviking::Client,
    note_id: &str,
    text: &str,
) -> Result<(), Error> {
    let text = semantic_text(text);
    if !semantic_eligible(&text) {
        return Ok(());
    }
    for (start, end, _) in openviking::parts(&text) {
        tx.execute(
            "INSERT OR IGNORE INTO kira_semantic_index(uri, note_id, byte_start, byte_end) VALUES (?1,?2,?3,?4)",
            params![client.uri(note_id,start,end), note_id, start as i64, end as i64],
        )?;
    }
    Ok(())
}

struct Saved {
    seq: i64,
    commitment: SaveCommitment,
    demoted_at: Option<i64>,
    demoted_time: Option<i64>,
}
struct State {
    notes: BTreeMap<String, Saved>,
    permission_seq: Option<i64>,
}

fn verified_state<L: Ledger>(
    ledger: &L,
    tx: &Transaction<'_>,
    owner: &str,
) -> Result<State, Error> {
    let entries = ledger.verified_entries(tx)?;
    let mut state = State {
        notes: BTreeMap::new(),
        permission_seq: None,
    };
    let mut previous_seq = 0;
    for entry in entries {
        if entry.seq <= previous_seq || !valid_time(entry.fact.at) {
            return Err(Error::Corrupt);
        }
        previous_seq = entry.seq;
        match entry.fact.body {
            Body::Save(commitment) => {
                if entry.fact.actor != owner || entry.fact.at != commitment.at {
                    return Err(Error::Corrupt);
                }
                let note_id = commitment.note_id.clone();
                let saved = Saved {
                    seq: entry.seq,
                    commitment,
                    demoted_at: None,
                    demoted_time: None,
                };
                if state.notes.insert(note_id, saved).is_some() {
                    return Err(Error::Corrupt);
                }
            }
            Body::Demote(demote) => {
                let saved = state.notes.get_mut(&demote.note_id).ok_or(Error::Corrupt)?;
                if entry.fact.actor != owner
                    || demote.prior_seq != saved.seq
                    || saved.demoted_at.is_some()
                {
                    return Err(Error::Corrupt);
                }
                saved.demoted_at = Some(entry.seq);
                saved.demoted_time = Some(entry.fact.at);
            }
            Body::Permission(permission) => {
                if entry.fact.actor == owner
                    && permission.owner_subject == owner
                    && permission.scope == HOSTED_CONTEXT_SCOPE
                {
                    state.permission_seq = Some(entry.seq);
                }
            }
        }
    }
    let mut statement = tx.prepare("SELECT note_id, demoted FROM kira_notes")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut count = 0;
    for row in rows {
        let (note_id, demoted) = row?;
        let saved = state.notes.get(&note_id).ok_or(Error::Corrupt)?;
        if demoted != i64::from(saved.demoted_at.is_some()) {
            return Err(Error::Corrupt);
        }
        count += 1;
    }
    if count != state.notes.len() {
        return Err(Error::Corrupt);
    }
    let cold_count: i64 = tx.query_row("SELECT COUNT(*) FROM kira_cold", [], |row| row.get(0))?;
    let expected_cold = state
        .notes
        .values()
        .filter(|saved| saved.demoted_at.is_some())
        .count();
    if usize::try_from(cold_count).ok() != Some(expected_cold) {
        return Err(Error::Corrupt);
    }
    for (note_id, saved) in &state.notes {
        let (key_id, active, cold, category, tier, at, retained_key) = tx.query_row(
            "SELECT n.key_id, n.ciphertext, c.ciphertext, n.category, n.tier, n.at,
                 EXISTS(SELECT 1 FROM kira_keys k WHERE k.key_id=n.key_id AND length(k.key)=32)
             FROM kira_notes n LEFT JOIN kira_cold c ON c.note_id=n.note_id
             WHERE n.note_id = ?1",
            [note_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            },
        )?;
        let ciphertext = if saved.demoted_at.is_some() {
            if !active.is_empty() {
                return Err(Error::Corrupt);
            }
            cold.ok_or(Error::Corrupt)?
        } else {
            active
        };
        let expected = &saved.commitment;
        if key_id != expected.key_id
            || ciphertext_hash(&ciphertext) != expected.ciphertext_sha256
            || category != expected.category
            || tier != expected.tier.as_str()
            || at != expected.at
            || !retained_key
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(state)
}

fn valid_time(at: i64) -> bool {
    (0..=MAX_TIME).contains(&at)
}

pub fn validate_memory_fields(
    category: &str,
    statement: &str,
    quote: Option<&str>,
) -> Result<(), Error> {
    if category.is_empty()
        || category.len() > MAX_CATEGORY_BYTES
        || !category
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::CategoryInvalid);
    }
    if statement.len() > MAX_STATEMENT_BYTES {
        return Err(Error::StatementTooLarge);
    }
    if quote.is_some_and(|quote| quote.len() > MAX_QUOTE_BYTES) {
        return Err(Error::QuoteTooLarge);
    }
    Ok(())
}

fn validate_note(note: &Note<'_>) -> Result<(), Error> {
    validate_memory_fields(note.category, "", None)?;
    if note.text.len() > MAX_NOTE_BYTES {
        return Err(Error::StatementTooLarge);
    }
    // Guest text is a canonical memory payload; direct text notes stay supported.
    if let Ok(canon::Value::Object(fields)) = canon::parse(note.text.as_bytes()) {
        let value = canon::Value::Object(fields);
        if let (Some(canon::Value::String(category)), Some(canon::Value::String(statement))) =
            (value.get("category"), value.get("statement"))
        {
            let quote = match value.get("quote") {
                None => None,
                Some(canon::Value::String(quote)) => Some(quote.as_str()),
                _ => return Err(Error::InvalidField),
            };
            if category != note.category
                || value.as_object().is_none_or(|fields| {
                    fields.iter().any(|(name, _)| {
                        !matches!(name.as_str(), "category" | "statement" | "quote")
                    })
                })
                || canon::canonical_json(&value).map_err(|_| Error::InvalidField)?
                    != note.text.as_bytes()
            {
                return Err(Error::InvalidField);
            }
            return validate_memory_fields(category, statement, quote);
        }
    }
    validate_memory_fields(note.category, note.text, None)
}

pub fn associated_data(owner_subject: &str, note_id: &str, key_id: &str) -> Result<Vec<u8>, Error> {
    let mut aad = AAD_DOMAIN.to_vec();
    for field in [owner_subject, note_id, key_id] {
        let len = u32::try_from(field.len()).map_err(|_| Error::InvalidField)?;
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(field.as_bytes());
    }
    Ok(aad)
}

fn random_key() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut key[..]).map_err(|_| Error::Random)?;
    Ok(key)
}

fn note_key(
    root: Option<&[u8; 32]>,
    material: &[u8],
    aad: &[u8],
    derived: bool,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let material: &[u8; 32] = material.try_into().map_err(|_| Error::Corrupt)?;
    match (root, derived) {
        (Some(root), true) => {
            let mut hash = Sha256::new();
            hash.update(b"aukora:kira-root-key:v1\0");
            hash.update(root);
            hash.update(material);
            hash.update(aad);
            Ok(Zeroizing::new(hash.finalize().into()))
        }
        (None, false) => Ok(Zeroizing::new(*material)),
        _ => Err(Error::Corrupt),
    }
}

fn stored_key(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(row.get(column)?))
}

fn ciphertext_hash(ciphertext: &[u8]) -> String {
    hex::encode(Sha256::digest(ciphertext))
}

fn encrypt(key: &[u8], nonce: &[u8; 24], text: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Corrupt)?;
    cipher
        .encrypt(&XNonce::from(*nonce), Payload { msg: text, aad })
        .map_err(|_| Error::Authentication)
}

fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce: &[u8; 24] = nonce.try_into().map_err(|_| Error::Corrupt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Corrupt)?;
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests;
