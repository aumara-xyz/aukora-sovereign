// SPDX-License-Identifier: AGPL-3.0-or-later
//! Storage versions are separate from frozen C3 wire versions.

use canon::{digest::Digest32, Result};

pub const CURRENT_SCHEMA: u32 = 3;
pub const C3_COLUMNS: [&str; 10] = [
    "seq", "prev", "hash", "sig", "at", "kind", "actor", "op", "phase", "body",
];

/// Migration paths are closed; unknown versions cannot be inferred or repaired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Migration {
    /// Adds the frozen kind registry and terminal/append guards without rewriting rows.
    FrozenRowsToGuardedRows,
    /// Adds side-table wrappers and transactional authority storage, preserving C3 bytes.
    GuardedRowsToAuthorityStorage,
}

impl Migration {
    pub const fn versions(self) -> (u32, u32) {
        match self {
            Self::FrozenRowsToGuardedRows => (1, 2),
            Self::GuardedRowsToAuthorityStorage => (2, 3),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationReceipt {
    pub migration: Migration,
    pub preserved_rows: u64,
    pub previous_head: Option<Digest32>,
}

/// Required objects are verified from SQLite's schema before authority is enabled.
pub const REQUIRED_OBJECTS: &[&str] = &[
    "aura",
    "aura_one_terminal",
    "aura_insert_guard",
    "aura_update_guard",
    "aura_delete_guard",
    "aura_record_wrappers",
    "authority_bindings",
    "authority_challenges",
    "authority_consumptions",
    "authority_proposals",
    "authority_declines",
    "authority_permissions",
    "authority_floor",
];

/// Wave-1 contract: BEGIN IMMEDIATE, exact admitted schema, byte/type comparison
/// of every historical C3 column, rollback on any mismatch, no synthesized history.
/// This function is crate-private so callers cannot migrate an active transaction.
pub(crate) fn migrate(_connection: &mut rusqlite::Connection) -> Result<Vec<MigrationReceipt>> {
    crate::unavailable()
}
