// SPDX-License-Identifier: AGPL-3.0-or-later
//! Transactional replacement of the legacy ceremony claim uniqueness constraint.

use canon::{Refusal, Result};
use rusqlite::{Connection, TransactionBehavior};

const TABLE: &str = "aumlok_ceremonies_v1";
const STAGING: &str = "aumlok_ceremonies_claim_migration_v1";

pub(crate) fn initialize(
    connection: &mut Connection,
    table_schema: &str,
    guards: &str,
) -> Result<()> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store_error)?;
    let leftover: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1)",
            [STAGING],
            |row| row.get(0),
        )
        .map_err(store_error)?;
    if leftover || table_schema.matches(TABLE).count() != 1 {
        return Err(corrupt());
    }
    let legacy: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_index_list(?1) AS i
             WHERE i.\"unique\"=1 AND i.partial=0
             AND (SELECT count(*) FROM pragma_index_info(i.name))=1
             AND EXISTS(SELECT 1 FROM pragma_index_info(i.name) WHERE name='claim_digest'))",
            [TABLE],
            |row| row.get(0),
        )
        .map_err(store_error)?;
    if legacy {
        // Replacing a referenced table could execute foreign-key delete actions.
        let referenced: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema AS s,
                 pragma_foreign_key_list(s.name) AS f
                 WHERE s.type='table' AND f.\"table\"=?1 COLLATE NOCASE)",
                [TABLE],
                |row| row.get(0),
            )
            .map_err(store_error)?;
        // Only the guards supplied by this module's caller may be rebuilt.
        let unknown_guard: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE tbl_name=?1
                 AND type IN ('trigger','index') AND sql IS NOT NULL AND name NOT IN
                 ('aumlok_ceremonies_enrolment_v1','aumlok_ceremonies_retain_v1',
                  'aumlok_ceremonies_new_v1','aumlok_ceremonies_forward_v1'))",
                [TABLE],
                |row| row.get(0),
            )
            .map_err(store_error)?;
        if referenced || unknown_guard {
            return Err(corrupt());
        }
        tx.execute_batch(&table_schema.replacen(TABLE, STAGING, 1))
            .map_err(store_error)?;
        tx.execute_batch(
            "INSERT INTO aumlok_ceremonies_claim_migration_v1
             (id,purpose,state,context,nonce,issued,deadline,last_seen,claim_digest,
              resume_digest,candidate,candidate_digest)
             SELECT id,purpose,state,context,nonce,issued,deadline,last_seen,claim_digest,
              resume_digest,candidate,candidate_digest FROM aumlok_ceremonies_v1;
             DROP TABLE aumlok_ceremonies_v1;
             ALTER TABLE aumlok_ceremonies_claim_migration_v1 RENAME TO aumlok_ceremonies_v1;",
        )
        .map_err(store_error)?;
    } else {
        tx.execute_batch(table_schema).map_err(store_error)?;
    }
    tx.execute_batch(guards).map_err(store_error)?;
    tx.commit().map_err(store_error)
}

fn corrupt() -> Refusal {
    Refusal {
        organ: "aumlok",
        reason: "store-corrupt",
    }
}

fn store_error(_error: rusqlite::Error) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason: "store-error",
    }
}
