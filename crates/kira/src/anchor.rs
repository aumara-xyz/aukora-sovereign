// SPDX-License-Identifier: AGPL-3.0-or-later
//! Aura-verified anchors and note storage inside the caller’s SQLite transaction.

use canon::{authority::AuthorityTxn, codes, digest::Digest32, ids::SubjectId, Result};

/// The latest kira.save/demote/permission row in the complete verified Aura chain.
/// Sequence is its global Aura sequence; intervening non-Kira rows are verified too.
/// Empty memory history has no fabricated hash. This is not a second ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryHead {
    pub version: u16,
    pub sequence: u64,
    pub hash: Option<Digest32>,
}

impl MemoryHead {
    pub const EMPTY: Self = Self {
        version: 1,
        sequence: 0,
        hash: None,
    };

    pub fn validate(self) -> Result<Self> {
        if self.version != 1
            || self.sequence > canon::json::MAX_SAFE_INTEGER as u64
            || (self.sequence == 0) != self.hash.is_none()
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        Ok(self)
    }
}

/// Counts committed with the head, not inferred from a mutable index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCounts {
    pub saved: u64,
    pub demoted: u64,
    pub quarantined: u64,
}

impl MemoryCounts {
    pub fn validate(self) -> Result<Self> {
        if self.saved > canon::json::MAX_SAFE_INTEGER as u64
            || self.demoted > self.saved
            || self.quarantined > self.saved
        {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        Ok(self)
    }
}

/// Non-authorizing data for a commitment in a C3 body; never extra C3 row keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorClaim {
    pub owner: SubjectId,
    pub head: MemoryHead,
    pub counts: MemoryCounts,
    pub aura_sequence: u64,
    pub aura_hash: Digest32,
}

/// Read verification stays in the Aura snapshot used by the memory operation.
/// Implementors verify the complete signed Aura chain against its retained head,
/// then compare Kira commitments, head and counts. Missing or partial coverage
/// refuses; a row or signature supplied by the caller alone is not verification.
pub trait AuraAnchors {
    fn verify<T: AuthorityTxn + ?Sized>(
        &self,
        transaction: &mut T,
        expected: &AnchorClaim,
    ) -> Result<()>;
}

use crate::{
    notes::{
        self, Demotion, EncryptedNote, MemoryKey, NoteCipher, NotePayload, SaveCommitment,
        SaveReceipt, WrappedMemoryKey, XChaChaCipher,
    },
    permissions::{self, PermissionContext},
};
use canon::{
    authority::{CellCommitment, VerifiedProof},
    ids::NoteId,
    json::Value,
};
use rusqlite::{params, OptionalExtension, Transaction};
use std::collections::{BTreeMap, BTreeSet};

impl AnchorClaim {
    pub fn validate(&self) -> Result<()> {
        self.head.validate()?;
        self.counts.validate()?;
        if self.aura_sequence > canon::json::MAX_SAFE_INTEGER as u64
            || self.head.sequence > self.aura_sequence
            || (self.head.sequence == self.aura_sequence
                && self.head.hash.is_some_and(|h| h != self.aura_hash))
            || (self.head.sequence == 0
                && (self.counts.saved != 0
                    || self.counts.demoted != 0
                    || self.counts.quarantined != 0))
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        Ok(())
    }
}

/// A new schema binds retained metadata without placing it in Aura in the clear.
/// The original save-v1 and encrypted-note-v1 formats keep their exact keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedSave {
    pub commitment: SaveCommitment,
    pub metadata_sha256: Digest32,
}
impl RetainedSave {
    pub fn canonical_body(&self) -> Result<Value> {
        Value::checked_object(vec![
            (
                "schema".into(),
                notes::text("aukora-kira-retained-save-v2")?,
            ),
            (
                "body".into(),
                Value::checked_object(vec![
                    ("commitment".into(), self.commitment.canonical_body()?),
                    (
                        "metadata_sha256".into(),
                        notes::text(self.metadata_sha256.to_string())?,
                    ),
                ])?,
            ),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct SavedAnchor {
    pub receipt: SaveReceipt,
    pub metadata_sha256: Digest32,
}

/// Complete verified Aura projection, never constructed from the note tables.
pub struct LedgerMemory {
    pub anchor: AnchorClaim,
    pub saves: BTreeMap<NoteId, SavedAnchor>,
    pub demotions: BTreeMap<NoteId, Demotion>,
    pub quarantined: BTreeSet<NoteId>,
}

/// Aura supplies this adapter; Kira has no ledger signer or independent connection.
/// Every method must check that `sql` is the active transaction identified by `txn`.
/// Verification covers all Aura rows, signatures and its retained head, including
/// owner-authorized demotions/permissions. Reads must include every retained save.
/// Appends never commit. Errors abort both the Aura append and Kira's SQL savepoint.
pub trait MemoryLedger {
    fn verify<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        sql: &Transaction<'_>,
        txn: &mut T,
        context: &PermissionContext,
    ) -> Result<LedgerMemory>;
    /// Append nonauthorizing kira.save with this v2 content-free body, then return
    /// its signed citation and updated anchor. This cannot grant any permission.
    fn append_save<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        sql: &Transaction<'_>,
        txn: &mut T,
        context: &PermissionContext,
        save: &RetainedSave,
        at_ms: u64,
    ) -> Result<SaveReceipt>;
}

/// An absent Aura route refuses before a note table is read or changed.
pub struct UnavailableMemoryLedger;
impl MemoryLedger for UnavailableMemoryLedger {
    fn verify<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        _: &Transaction<'_>,
        _: &mut T,
        _: &PermissionContext,
    ) -> Result<LedgerMemory> {
        Err(codes::KIRA_LEDGER_UNVERIFIED)
    }
    fn append_save<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        _: &Transaction<'_>,
        _: &mut T,
        _: &PermissionContext,
        _: &RetainedSave,
        _: u64,
    ) -> Result<SaveReceipt> {
        Err(codes::KIRA_STORE_UNAVAILABLE)
    }
}

/// AUMLOK unwraps only a key bound to this owner and envelope epoch.
/// Returned bytes are transient; the persistent tables contain only wrapped keys.
pub trait MemoryKeys {
    fn for_save(&self, context: &PermissionContext) -> Result<(WrappedMemoryKey, MemoryKey)>;
    fn unwrap(&self, owner: &SubjectId, wrapped: &WrappedMemoryKey) -> Result<MemoryKey>;
}

#[derive(Clone, Debug)]
pub struct RetainedNote {
    pub encrypted: EncryptedNote,
    pub wrapped_key: WrappedMemoryKey,
    pub receipt: SaveReceipt,
    pub category: String,
    pub at_ms: u64,
    pub demotion: Option<Demotion>,
    pub quarantined: bool,
    pub cell: CellCommitment,
}
impl RetainedNote {
    pub fn metadata_sha256(&self) -> Result<Digest32> {
        metadata_hash(&self.category, self.at_ms, &self.wrapped_key, &self.cell)
    }
}

pub struct MemorySnapshot {
    pub anchor: AnchorClaim,
    pub notes: BTreeMap<NoteId, RetainedNote>,
}

/// A borrowed Aura-owned SQLite transaction; there is no open, commit or delete API.
/// The ledger adapter checks connection identity before any memory operation.
pub struct SqliteMemory<'a, L: MemoryLedger> {
    pub(crate) sql: &'a Transaction<'a>,
    pub(crate) ledger: &'a L,
    pub(crate) keys: &'a dyn MemoryKeys,
}
impl<'a, L: MemoryLedger> SqliteMemory<'a, L> {
    pub fn new(sql: &'a Transaction<'a>, ledger: &'a L, keys: &'a dyn MemoryKeys) -> Self {
        Self { sql, ledger, keys }
    }

    /// Called during Aura's schema transaction. Original ciphertext and envelopes
    /// are immutable; demotion adds a marker without rewriting or removing either.
    pub fn initialize<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
    ) -> Result<()> {
        if self.sql.is_autocommit() {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
        permissions::verify_context(txn, context)?;
        self.ledger.verify(self.sql, txn, context)?;
        self.sql.execute_batch("CREATE TABLE IF NOT EXISTS kira_notes_v1 (
            owner TEXT NOT NULL, note TEXT NOT NULL, envelope BLOB NOT NULL,
            wrapped BLOB NOT NULL, category TEXT NOT NULL, at_ms INTEGER NOT NULL,
            module TEXT NOT NULL, input TEXT NOT NULL, effect TEXT NOT NULL,
            PRIMARY KEY(owner,note));
            CREATE TABLE IF NOT EXISTS kira_demotions_v1 (
            owner TEXT NOT NULL, note TEXT NOT NULL, seq INTEGER NOT NULL,
            at_ms INTEGER NOT NULL, PRIMARY KEY(owner,note));
            CREATE TABLE IF NOT EXISTS kira_budget_v1 (
            owner TEXT PRIMARY KEY, start INTEGER NOT NULL, used INTEGER NOT NULL);
            CREATE TRIGGER IF NOT EXISTS kira_note_no_update BEFORE UPDATE ON kira_notes_v1 BEGIN SELECT RAISE(ABORT,'immutable'); END;
            CREATE TRIGGER IF NOT EXISTS kira_note_no_delete BEFORE DELETE ON kira_notes_v1 BEGIN SELECT RAISE(ABORT,'immutable'); END;
            CREATE TRIGGER IF NOT EXISTS kira_demotion_no_update BEFORE UPDATE ON kira_demotions_v1 BEGIN SELECT RAISE(ABORT,'immutable'); END;
            CREATE TRIGGER IF NOT EXISTS kira_demotion_no_delete BEFORE DELETE ON kira_demotions_v1 BEGIN SELECT RAISE(ABORT,'immutable'); END;")
            .map_err(storage_error)
    }

    pub fn verified_anchor<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
    ) -> Result<AnchorClaim> {
        if self.sql.is_autocommit() {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
        permissions::verify_context(txn, context)?;
        let anchor = self.ledger.verify(self.sql, txn, context)?.anchor;
        anchor.validate()?;
        if anchor.owner != context.owner_subject {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        Ok(anchor)
    }

    pub fn snapshot<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
    ) -> Result<MemorySnapshot> {
        if self.sql.is_autocommit() {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
        permissions::verify_context(txn, context)?;
        let verified = self.ledger.verify(self.sql, txn, context)?;
        verified.anchor.validate()?;
        if verified.anchor.owner != context.owner_subject
            || verified.saves.len() as u64 != verified.anchor.counts.saved
            || verified.demotions.len() as u64 != verified.anchor.counts.demoted
            || verified.quarantined.len() as u64 != verified.anchor.counts.quarantined
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        let mut stmt = self.sql.prepare("SELECT note,envelope,wrapped,category,at_ms,module,input,effect FROM kira_notes_v1 WHERE owner=?1 ORDER BY note").map_err(storage_error)?;
        let mut rows = stmt
            .query([context.owner_subject.to_string()])
            .map_err(storage_error)?;
        let mut notes = BTreeMap::new();
        while let Some(row) = rows.next().map_err(storage_error)? {
            let id = NoteId::new(row.get(0).map_err(storage_error)?)?;
            let saved = verified.saves.get(&id).ok_or(codes::KIRA_STORE_CORRUPT)?;
            let envelope = row
                .get_ref(1)
                .map_err(storage_error)?
                .as_blob()
                .map_err(|_| codes::KIRA_STORE_CORRUPT)?;
            let wrapped = row
                .get_ref(2)
                .map_err(storage_error)?
                .as_blob()
                .map_err(|_| codes::KIRA_STORE_CORRUPT)?;
            let encrypted = decode_envelope(envelope)?;
            let key = decode_wrapped(wrapped)?;
            let retained = RetainedNote {
                encrypted,
                wrapped_key: key,
                receipt: saved.receipt.clone(),
                category: row.get(3).map_err(storage_error)?,
                at_ms: db_integer(row.get::<_, i64>(4).map_err(storage_error)?)?,
                cell: CellCommitment {
                    module_sha256: Digest32::from_hex(
                        &row.get::<_, String>(5).map_err(storage_error)?,
                    )?,
                    input_sha256: Digest32::from_hex(
                        &row.get::<_, String>(6).map_err(storage_error)?,
                    )?,
                    effect_sha256: Digest32::from_hex(
                        &row.get::<_, String>(7).map_err(storage_error)?,
                    )?,
                },
                demotion: verified.demotions.get(&id).cloned(),
                quarantined: verified.quarantined.contains(&id),
            };
            retained.receipt.validate()?;
            notes::NoteContent::new(retained.category.clone(), "metadata".into(), None)?;
            if retained.at_ms > canon::json::MAX_SAFE_INTEGER as u64
                || retained.encrypted.note_id != id
                || retained.encrypted.owner != context.owner_subject
                || retained.wrapped_key.key_id != retained.encrypted.key_id
                || retained.wrapped_key.root_epoch != retained.encrypted.root_epoch
                || retained.receipt.anchor.owner != context.owner_subject
                || retained.receipt.cite_seq > verified.anchor.head.sequence
                || retained.receipt.commitment
                    != SaveCommitment::from_encrypted(&retained.encrypted)?
                || retained.metadata_sha256()? != saved.metadata_sha256
            {
                return Err(codes::KIRA_STORE_CORRUPT);
            }
            let marker: Option<(i64, i64)> = self
                .sql
                .query_row(
                    "SELECT seq,at_ms FROM kira_demotions_v1 WHERE owner=?1 AND note=?2",
                    params![context.owner_subject.to_string(), id.as_str()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(storage_error)?;
            let expected = if let Some(d) = &retained.demotion {
                d.validate()?;
                if d.note_id != id
                    || d.save_sequence != retained.receipt.cite_seq
                    || d.head.sequence > verified.anchor.head.sequence
                {
                    return Err(codes::KIRA_STORE_CORRUPT);
                }
                Some((d.demoted_sequence as i64, d.demoted_at_ms as i64))
            } else {
                None
            };
            if marker != expected || notes.insert(id, retained).is_some() {
                return Err(codes::KIRA_STORE_CORRUPT);
            }
        }
        let count: i64 = self
            .sql
            .query_row(
                "SELECT count(*) FROM kira_demotions_v1 WHERE owner=?1",
                [context.owner_subject.to_string()],
                |r| r.get(0),
            )
            .map_err(storage_error)?;
        if notes.len() != verified.saves.len()
            || count != verified.demotions.len() as i64
            || verified
                .quarantined
                .iter()
                .any(|id| !notes.contains_key(id))
        {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        Ok(MemorySnapshot {
            anchor: verified.anchor,
            notes,
        })
    }

    pub(crate) fn decrypt(&self, note: &RetainedNote) -> Result<NotePayload> {
        if note.quarantined {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
        if SaveCommitment::from_encrypted(&note.encrypted)? != note.receipt.commitment {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        let key = self.keys.unwrap(&note.encrypted.owner, &note.wrapped_key)?;
        let clear = XChaChaCipher.open(&key, &note.encrypted)?;
        let payload = NotePayload::decode(&clear)?;
        if payload.content.category() != note.category
            || payload.at_ms != note.at_ms
            || payload.root_epoch != note.encrypted.root_epoch
        {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        Ok(payload)
    }

    pub(crate) fn insert(&self, note: &RetainedNote) -> Result<()> {
        self.sql.execute("INSERT INTO kira_notes_v1(owner,note,envelope,wrapped,category,at_ms,module,input,effect) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![note.encrypted.owner.to_string(),note.encrypted.note_id.as_str(),note.encrypted.canonical_bytes()?,wrapped_bytes(&note.wrapped_key)?,note.category,note.at_ms as i64,note.cell.module_sha256.to_string(),note.cell.input_sha256.to_string(),note.cell.effect_sha256.to_string()]).map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn charge(&self, context: &PermissionContext, at: u64) -> Result<()> {
        let previous: Option<(i64, u32)> = self
            .sql
            .query_row(
                "SELECT start,used FROM kira_budget_v1 WHERE owner=?1",
                [context.owner_subject.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?;
        let (start, used) = match previous {
            Some((start, _)) if start < 0 || start as u64 > at => {
                return Err(codes::KIRA_STORE_UNAVAILABLE)
            }
            Some((start, used)) if at - (start as u64) < notes::GUEST_WINDOW_MS => {
                (start as u64, used)
            }
            _ => (at, 0),
        };
        if used >= notes::GUEST_WINDOW_SAVES {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
        self.sql.execute("INSERT INTO kira_budget_v1(owner,start,used) VALUES (?1,?2,?3) ON CONFLICT(owner) DO UPDATE SET start=excluded.start,used=excluded.used",params![context.owner_subject.to_string(),start as i64,used+1]).map_err(storage_error)?;
        Ok(())
    }
}

impl<L: MemoryLedger> AuraAnchors for SqliteMemory<'_, L> {
    fn verify<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        expected: &AnchorClaim,
    ) -> Result<()> {
        // Epoch comes from the verified owner projection, never the expected anchor.
        let state = txn
            .authority_state(
                permissions::OWNER_STATE_NAMESPACE,
                &expected.owner.to_string(),
            )?
            .ok_or(codes::KIRA_LEDGER_UNVERIFIED)?;
        let epoch = notes::number(notes::field(&state, "epoch")?)?;
        let context = PermissionContext {
            owner_subject: expected.owner,
            current_principal: expected.owner,
            owner_epoch: epoch,
        };
        if self.verified_anchor(txn, &context)? != *expected {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        Ok(())
    }
}

pub(crate) fn storage_error(_: rusqlite::Error) -> canon::Refusal {
    codes::KIRA_STORE_UNAVAILABLE
}

pub(crate) fn wrapped_bytes(key: &WrappedMemoryKey) -> Result<Vec<u8>> {
    key.validate()?;
    Ok(Value::checked_object(vec![
        ("schema".into(), notes::text("aukora-kira-wrapped-key-v1")?),
        ("algorithm".into(), notes::text(key.algorithm.wire_name())?),
        ("key_id".into(), notes::text(key.key_id.to_string())?),
        ("epoch".into(), notes::integer(key.root_epoch)?),
        ("nonce".into(), notes::text(notes::hex(&key.nonce))?),
        (
            "ciphertext".into(),
            notes::text(notes::hex(&key.ciphertext))?,
        ),
    ])?
    .canonical_bytes())
}
fn decode_wrapped(bytes: &[u8]) -> Result<WrappedMemoryKey> {
    use notes::{field, number, string, unhex};
    if bytes.len() > 1024 {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let v = notes::parse_canonical(bytes)?;
    if string(field(&v, "schema")?)? != "aukora-kira-wrapped-key-v1"
        || string(field(&v, "algorithm")?)? != "xchacha20-poly1305"
    {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let key = WrappedMemoryKey {
        version: 1,
        algorithm: canon::alg::AlgorithmId::XChaCha20Poly1305,
        key_id: NoteId::new(string(field(&v, "key_id")?)?.into())?,
        root_epoch: number(field(&v, "epoch")?)?,
        nonce: unhex(string(field(&v, "nonce")?)?)?
            .try_into()
            .map_err(|_| codes::KIRA_STORE_CORRUPT)?,
        ciphertext: unhex(string(field(&v, "ciphertext")?)?)?,
    };
    if wrapped_bytes(&key)? != bytes {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    Ok(key)
}
fn decode_envelope(bytes: &[u8]) -> Result<EncryptedNote> {
    use notes::{field, number, string, unhex};
    if bytes.len() > 2 * notes::MAX_NOTE_BYTES + 4096 {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let wrapper = notes::parse_canonical(bytes)?;
    if string(field(&wrapper, "schema")?)? != "aukora-kira-note-v1" {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let v = field(&wrapper, "body")?;
    let owner = string(field(v, "owner")?)?
        .strip_prefix("aukora:1:")
        .ok_or(codes::KIRA_STORE_CORRUPT)?;
    if string(field(v, "algorithm")?)? != "xchacha20-poly1305" {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let note = EncryptedNote {
        version: 1,
        algorithm: canon::alg::AlgorithmId::XChaCha20Poly1305,
        owner: SubjectId::from_digest(Digest32::from_hex(owner)?),
        note_id: NoteId::new(string(field(v, "note_id")?)?.into())?,
        key_id: NoteId::new(string(field(v, "key_id")?)?.into())?,
        root_epoch: number(field(v, "root_epoch")?)?,
        nonce: unhex(string(field(v, "nonce")?)?)?
            .try_into()
            .map_err(|_| codes::KIRA_STORE_CORRUPT)?,
        ciphertext: unhex(string(field(v, "ciphertext")?)?)?,
    };
    if note.canonical_bytes()? != bytes {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    Ok(note)
}
fn metadata_hash(
    category: &str,
    at: u64,
    wrapped: &WrappedMemoryKey,
    cell: &CellCommitment,
) -> Result<Digest32> {
    Ok(notes::sha256(
        &Value::checked_object(vec![
            ("schema".into(), notes::text("aukora-kira-metadata-v1")?),
            ("category".into(), notes::text(category)?),
            ("at".into(), notes::integer(at)?),
            (
                "wrapped_key_sha256".into(),
                notes::text(notes::sha256(&wrapped_bytes(wrapped)?).to_string())?,
            ),
            (
                "module".into(),
                notes::text(cell.module_sha256.to_string())?,
            ),
            ("input".into(), notes::text(cell.input_sha256.to_string())?),
            (
                "effect".into(),
                notes::text(cell.effect_sha256.to_string())?,
            ),
        ])?
        .canonical_bytes(),
    ))
}

fn db_integer(n: i64) -> Result<u64> {
    if !(0..=canon::json::MAX_SAFE_INTEGER).contains(&n) {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    Ok(n as u64)
}

impl<L: MemoryLedger> crate::notes::MemoryStore for SqliteMemory<'_, L> {
    fn save<
        T: canon::authority::AuthorityTxn + ?Sized,
        P: crate::permissions::MemoryPermissions,
        C: crate::notes::SaveCell,
    >(
        &mut self,
        txn: &mut T,
        permissions: &mut P,
        context: &PermissionContext,
        cell: &C,
        request: crate::notes::SaveRequest,
    ) -> Result<SaveReceipt> {
        use crate::notes::{NoteContent, NoteForm};
        use crate::permissions::{Permission, PermissionRequest, PermissionScope};
        let before = self.snapshot(txn, context)?;
        let grant = permissions.require(
            txn,
            context,
            &PermissionRequest {
                permission: Permission::Store,
                scope: PermissionScope::local_memory(),
            },
        )?;
        if grant.change.context != *context
            || grant.change.action != crate::permissions::PermissionAction::Grant
            || grant.change.request.permission != Permission::Store
            || grant.change.request.scope != PermissionScope::local_memory()
            || grant.record.authority.epoch != context.owner_epoch
            || grant.record.authority.sequence == 0
            || grant.record.authority.sequence > before.anchor.aura_sequence
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        let content = NoteContent::new(
            request.put.category,
            request.put.statement,
            request.put.quote,
        )?;
        notes::ReviewBy::new(request.at_ms)?;
        request.form.validate()?;
        let recomputed = cell.replay(&content)?;
        if recomputed != request.put.cell {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        if let NoteForm::Summary { originals } = &request.form {
            for id in originals {
                let original = before.notes.get(id).ok_or(codes::KIRA_NOTE_NOT_FOUND)?;
                if self.decrypt(original)?.form != NoteForm::Original {
                    return Err(codes::KIRA_INVALID_FIELD);
                }
            }
        }
        let (wrapped, key) = self.keys.for_save(context)?;
        wrapped.validate()?;
        if wrapped.root_epoch != context.owner_epoch {
            return Err(codes::KIRA_AUTHENTICATION_FAILED);
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| codes::KIRA_RANDOM_UNAVAILABLE)?;
        let id = NoteId::new(notes::hex(&random))?;
        if before.notes.contains_key(&id) {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        let payload = NotePayload {
            content,
            origin: request.origin,
            form: request.form,
            at_ms: request.at_ms,
            review_by: request.review_by,
            root_epoch: context.owner_epoch,
        };
        let clear = payload.canonical_bytes()?;
        let encrypted = XChaChaCipher.seal(
            &key,
            &context.owner_subject,
            &id,
            &wrapped.key_id,
            context.owner_epoch,
            &clear,
        )?;
        let reopened = XChaChaCipher.open(
            &self.keys.unwrap(&context.owner_subject, &wrapped)?,
            &encrypted,
        )?;
        if *reopened != *clear {
            return Err(codes::KIRA_AUTHENTICATION_FAILED);
        }
        let commitment = SaveCommitment::from_encrypted(&encrypted)?;
        let metadata_sha256 = metadata_hash(
            payload.content.category(),
            payload.at_ms,
            &wrapped,
            &recomputed,
        )?;
        let body = RetainedSave {
            commitment: commitment.clone(),
            metadata_sha256,
        };
        self.sql
            .execute_batch("SAVEPOINT kira_save")
            .map_err(storage_error)?;
        let result = (|| {
            self.charge(context, request.at_ms)?;
            let receipt = self
                .ledger
                .append_save(self.sql, txn, context, &body, request.at_ms)?;
            receipt.validate()?;
            if receipt.commitment != commitment
                || receipt.anchor.owner != context.owner_subject
                || receipt.cite_seq <= before.anchor.aura_sequence
                || receipt.anchor.head.sequence != receipt.cite_seq
                || receipt.anchor.counts.saved != before.anchor.counts.saved + 1
                || receipt.anchor.counts.demoted != before.anchor.counts.demoted
                || receipt.anchor.counts.quarantined != before.anchor.counts.quarantined
            {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
            let retained = RetainedNote {
                encrypted,
                wrapped_key: wrapped,
                receipt: receipt.clone(),
                category: payload.content.category().into(),
                at_ms: payload.at_ms,
                demotion: None,
                quarantined: false,
                cell: recomputed,
            };
            self.insert(&retained)?;
            let after = self.snapshot(txn, context)?;
            if after.anchor != receipt.anchor || !after.notes.contains_key(&id) {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
            self.sql
                .execute_batch("RELEASE kira_save")
                .map_err(storage_error)?;
            Ok(receipt)
        })();
        self.abort_on_error(result)
    }

    fn demote<T: canon::authority::AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        context: &PermissionContext,
        proof: VerifiedProof,
        note_id: &NoteId,
        expected_head: MemoryHead,
        at_ms: u64,
    ) -> Result<Demotion> {
        use canon::authority::{BaseDigest, Kind, OwnerOperation, PendingAuthorityRecord, Phase};
        let before = self.snapshot(txn, context)?;
        if before.anchor.head != expected_head {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        notes::ReviewBy::new(at_ms)?;
        let note = before
            .notes
            .get(note_id)
            .ok_or(codes::KIRA_NOTE_NOT_FOUND)?;
        if note.demotion.is_some() {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        let auth = proof.authorization();
        let binding = txn.owner_binding(proof.credential_id())?;
        if proof.transaction_id() != txn.transaction_id()
            || binding.epoch != context.owner_epoch
            || binding.credential_id != *proof.credential_id()
            || binding.public_key != *proof.public_key()
            || binding.algorithm != proof.algorithm()
            || auth.epoch != context.owner_epoch
            || auth.subject != context.owner_subject
            || auth.op != OwnerOperation::Apply
            || auth.target != format!("kira.note:{}", note_id)
            || auth.cell.is_some()
            || auth.base_sha256 != BaseDigest::Present(note.receipt.commitment.encrypted_sha256)
            || auth.new_sha256
                != notes::sha256(&Demotion::target_bytes(
                    note_id,
                    note.receipt.cite_seq,
                    expected_head,
                )?)
        {
            return Err(codes::GATE_AUTHORIZATION_MISMATCH);
        }
        let rebuilt = txn.rebuild_authorization(&auth.proposal, OwnerOperation::Apply)?;
        if rebuilt != *auth
            || permissions::authorization_bytes(&rebuilt)? != proof.authorization_bytes()
        {
            return Err(codes::GATE_AUTHORIZATION_MISMATCH);
        }
        self.sql
            .execute_batch("SAVEPOINT kira_demote")
            .map_err(storage_error)?;
        let result = (|| {
            let coordinates = txn
                .authority_append_context(&proof)
                .map_err(|_| codes::KIRA_STORE_UNAVAILABLE)?;
            if coordinates.authority.epoch != context.owner_epoch
                || coordinates.authority.sequence != before.anchor.aura_sequence + 1
                || coordinates.authority.previous_hash != Some(before.anchor.aura_hash)
                || coordinates.at < 0
                || coordinates.at as u64 != at_ms
                || rebuilt.expires_at <= coordinates.at
            {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
            let pending = PendingAuthorityRecord {
                v: 1,
                algorithm: canon::alg::AlgorithmId::Sha256,
                authority: coordinates.authority,
                at: coordinates.at,
                kind: Kind::KiraDemote,
                actor: context.owner_subject.to_string(),
                operation: Some(coordinates.operation_id),
                phase: Phase::Terminal,
                body: notes::parse_canonical(&Demotion::target_bytes(
                    note_id,
                    note.receipt.cite_seq,
                    expected_head,
                )?)?,
            };
            txn.persist_counter(&proof)?;
            txn.consume(&proof)?;
            let row = txn.append(proof, pending.clone())?;
            if row.v != pending.v
                || row.algorithm != pending.algorithm
                || row.authority != pending.authority
                || row.at != pending.at
                || row.kind != pending.kind
                || row.actor != pending.actor
                || row.operation != pending.operation
                || row.phase != pending.phase
                || row.body != pending.body
            {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
            let d = Demotion {
                note_id: note_id.clone(),
                save_sequence: note.receipt.cite_seq,
                demoted_sequence: row.authority.sequence,
                demoted_at_ms: at_ms,
                head: MemoryHead {
                    version: 1,
                    sequence: row.authority.sequence,
                    hash: Some(row.hash),
                },
            };
            d.validate()?;
            self.sql
                .execute(
                    "INSERT INTO kira_demotions_v1(owner,note,seq,at_ms) VALUES (?1,?2,?3,?4)",
                    params![
                        context.owner_subject.to_string(),
                        note_id.as_str(),
                        d.demoted_sequence as i64,
                        at_ms as i64
                    ],
                )
                .map_err(storage_error)?;
            let after = self.snapshot(txn, context)?;
            if after.anchor.head != d.head
                || after.anchor.counts.saved != before.anchor.counts.saved
                || after.anchor.counts.demoted != before.anchor.counts.demoted + 1
                || after.anchor.counts.quarantined != before.anchor.counts.quarantined
                || after.notes.get(note_id).and_then(|n| n.demotion.as_ref()) != Some(&d)
            {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
            self.sql
                .execute_batch("RELEASE kira_demote")
                .map_err(storage_error)?;
            Ok(d)
        })();
        self.abort_on_error(result)
    }
}

impl<L: MemoryLedger> SqliteMemory<'_, L> {
    fn abort_on_error<R>(&self, result: Result<R>) -> Result<R> {
        if result.is_err() {
            // End the SQL transaction; subsequent memory operations refuse it.
            self.sql.execute_batch("ROLLBACK").map_err(storage_error)?;
        }
        result
    }
}
