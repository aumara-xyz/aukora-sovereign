// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cutting an archive from Kira's tables, and restoring an authenticated one into them with the
//! original note ids.

use super::{MemoryArchive, BACKUP_RESTORE_TARGET, BACKUP_ROLLBACK};
use crate::{
    anchor::{storage_error, wrapped_bytes, AnchorClaim, MemoryHead, MemoryLedger, SqliteMemory},
    permissions::{
        self, MemoryPermissions, Permission, PermissionAction, PermissionContext,
        PermissionRequest, PermissionScope,
    },
};
use canon::{authority::AuthorityTxn, codes, digest::Digest32, ids::NoteId, Result};
use rusqlite::params;
use std::collections::BTreeSet;

impl<L: MemoryLedger> SqliteMemory<'_, L> {
    /// Cut the lossless archive of this owner's memory at the head the ledger verifies in `txn`.
    /// The snapshot is read through `snapshot`, so every note is checked against Aura first.
    /// `receipts`, when given, are Aura's canonical cold-proof bytes read in the same transaction;
    /// they must cover the archive's Aura tip or the cut refuses. Cutting reads and writes nothing
    /// else, and sending or exporting the result is authorized separately.
    pub fn cut_archive<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
        receipts: Option<Vec<u8>>,
    ) -> Result<MemoryArchive> {
        let snapshot = self.snapshot(txn, context)?;
        MemoryArchive::from_snapshot(&snapshot, context.owner_epoch, receipts)
    }

    /// Put an authenticated archive back into an empty store with its original note ids.
    ///
    /// The node's Aura history must already be restored and verified: the ledger projection has to
    /// say exactly what the archive says (same head, counts, saves, citations, ciphertext
    /// commitments, demotions and quarantines), and a forgotten note stays forgotten. `floor` is the
    /// newest head the caller knows from outside the archive, or `MemoryHead::EMPTY` when it knows
    /// none; an older archive refuses. Restoring needs the current `Store` grant and cannot create
    /// permissions, spend an approval or move the head. All inserts share one savepoint, and
    /// the store is read back through `snapshot` before success is reported. Any failure ends the
    /// SQL transaction, as the other memory operations do.
    pub fn restore_archive<T: AuthorityTxn + ?Sized, P: MemoryPermissions + ?Sized>(
        &self,
        txn: &mut T,
        permissions: &P,
        context: &PermissionContext,
        archive: &MemoryArchive,
        floor: MemoryHead,
    ) -> Result<AnchorClaim> {
        if self.sql.is_autocommit() {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
        context.validate()?;
        archive.validate()?;
        floor.validate()?;
        if archive.owner != context.owner_subject {
            return Err(codes::KIRA_AUTHENTICATION_FAILED);
        }
        if archive.head.sequence < floor.sequence
            || (archive.head.sequence == floor.sequence && archive.head != floor)
        {
            return Err(BACKUP_ROLLBACK);
        }
        permissions::verify_context(txn, context)?;
        let verified = self.ledger.verify(self.sql, txn, context)?;
        verified.anchor.validate()?;
        if verified.anchor.owner != context.owner_subject
            || verified.anchor.head != archive.head
            || verified.anchor.counts != archive.counts
            || verified.anchor.aura_sequence < archive.aura_sequence
            || (verified.anchor.aura_sequence == archive.aura_sequence
                && verified.anchor.aura_hash != archive.aura_hash)
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        let request = PermissionRequest {
            permission: Permission::Store,
            scope: PermissionScope::local_memory(),
        };
        let grant = permissions.require(txn, context, &request)?;
        if grant.change.context != *context
            || grant.change.action != PermissionAction::Grant
            || grant.change.request != request
            || grant.record.authority.epoch != context.owner_epoch
            || grant.record.authority.sequence == 0
            || grant.record.authority.sequence > verified.anchor.aura_sequence
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        let archived: BTreeSet<&NoteId> = archive.notes.iter().map(|n| &n.note_id).collect();
        if verified.saves.len() != archived.len()
            || !verified.saves.keys().all(|id| archived.contains(id))
            || !verified.quarantined.iter().all(|id| archived.contains(id))
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        for note in &archive.notes {
            let saved = verified
                .saves
                .get(&note.note_id)
                .ok_or(codes::KIRA_LEDGER_UNVERIFIED)?;
            let demotion = match (verified.demotions.get(&note.note_id), &note.demotion) {
                (None, None) => true,
                (Some(ledger), Some(kept)) => {
                    ledger.save_sequence == note.cite_seq
                        && ledger.demoted_sequence == kept.demoted_sequence
                        && ledger.demoted_at_ms == kept.demoted_at_ms
                }
                _ => false,
            };
            if saved.receipt.cite_seq != note.cite_seq
                || saved.receipt.commitment.encrypted_sha256 != Digest32::sha256(&note.envelope)
                || !demotion
                || verified.quarantined.contains(&note.note_id) != note.quarantined
            {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
        }
        let owner = context.owner_subject.to_string();
        let existing: i64 = self
            .sql
            .query_row(
                "SELECT (SELECT count(*) FROM kira_notes_v1 WHERE owner=?1) + (SELECT count(*) FROM kira_demotions_v1 WHERE owner=?1)",
                [&owner],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if existing != 0 {
            return Err(BACKUP_RESTORE_TARGET);
        }
        self.sql
            .execute_batch("SAVEPOINT kira_restore")
            .map_err(storage_error)?;
        let result = (|| {
            for note in &archive.notes {
                self.sql
                    .execute(
                        "INSERT INTO kira_notes_v1(owner,note,envelope,wrapped,category,at_ms,module,input,effect) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                        params![
                            owner,
                            note.note_id.as_str(),
                            note.envelope,
                            note.wrapped_key,
                            note.category,
                            note.at_ms as i64,
                            note.cell.module_sha256.to_string(),
                            note.cell.input_sha256.to_string(),
                            note.cell.effect_sha256.to_string()
                        ],
                    )
                    .map_err(storage_error)?;
                if let Some(demotion) = &note.demotion {
                    self.sql
                        .execute(
                            "INSERT INTO kira_demotions_v1(owner,note,seq,at_ms) VALUES (?1,?2,?3,?4)",
                            params![
                                owner,
                                note.note_id.as_str(),
                                demotion.demoted_sequence as i64,
                                demotion.demoted_at_ms as i64
                            ],
                        )
                        .map_err(storage_error)?;
                }
            }
            // The read-back checks every ciphertext, wrapped key, citation and marker against Aura.
            let after = self.snapshot(txn, context)?;
            if after.anchor != verified.anchor || after.notes.len() != archive.notes.len() {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
            for note in &archive.notes {
                let kept = after
                    .notes
                    .get(&note.note_id)
                    .ok_or(codes::KIRA_STORE_CORRUPT)?;
                if kept.encrypted.canonical_bytes()? != note.envelope
                    || wrapped_bytes(&kept.wrapped_key)? != note.wrapped_key
                    || kept.category != note.category
                    || kept.at_ms != note.at_ms
                    || kept.cell != note.cell
                    || kept.demotion.is_some() != note.demotion.is_some()
                    || kept.quarantined != note.quarantined
                {
                    return Err(codes::KIRA_STORE_CORRUPT);
                }
            }
            self.sql
                .execute_batch("RELEASE kira_restore")
                .map_err(storage_error)?;
            Ok(after.anchor)
        })();
        if result.is_err() {
            self.sql.execute_batch("ROLLBACK").map_err(storage_error)?;
        }
        result
    }
}
