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

const ROW_TABLE: &str = "CREATE TABLE aura(
    seq INTEGER PRIMARY KEY CHECK(seq BETWEEN 1 AND 9007199254740991),
    prev TEXT NOT NULL,hash TEXT NOT NULL UNIQUE,sig TEXT NOT NULL,
    at INTEGER NOT NULL,kind TEXT NOT NULL,actor TEXT NOT NULL,
    op TEXT NOT NULL,phase TEXT NOT NULL,body TEXT NOT NULL)";

const GUARDS: &str = "
CREATE UNIQUE INDEX aura_one_terminal ON aura(op) WHERE phase='terminal';
CREATE TRIGGER aura_update_guard BEFORE UPDATE ON aura BEGIN
 SELECT RAISE(ABORT,'aura:update-forbidden'); END;
CREATE TRIGGER aura_delete_guard BEFORE DELETE ON aura BEGIN
 SELECT RAISE(ABORT,'aura:delete-forbidden'); END;
CREATE TRIGGER aura_insert_guard BEFORE INSERT ON aura BEGIN
 SELECT CASE WHEN typeof(NEW.seq)!='integer' OR typeof(NEW.at)!='integer'
  OR NEW.at NOT BETWEEN -9007199254740991 AND 9007199254740991
  OR typeof(NEW.prev)!='text' OR typeof(NEW.hash)!='text' OR typeof(NEW.sig)!='text'
  OR typeof(NEW.kind)!='text' OR typeof(NEW.actor)!='text' OR typeof(NEW.op)!='text'
  OR typeof(NEW.phase)!='text' OR typeof(NEW.body)!='text'
  THEN RAISE(ABORT,'aura:row-type') END;
 SELECT CASE WHEN NEW.seq != 1 + coalesce((SELECT max(seq) FROM aura),0)
  THEN RAISE(ABORT,'aura:sequence-gap') END;
 SELECT CASE WHEN NEW.prev != coalesce((SELECT hash FROM aura ORDER BY seq DESC LIMIT 1),'aukora:aura-record:v1')
  THEN RAISE(ABORT,'aura:broken-link') END;
 SELECT CASE WHEN length(NEW.hash)!=64 OR NEW.hash GLOB '*[^0123456789abcdef]*'
  THEN RAISE(ABORT,'aura:hash-invalid') END;
 SELECT CASE WHEN NEW.phase NOT IN ('fact','intent','settle','terminal')
  OR (NEW.phase!='fact' AND NEW.op='')
  THEN RAISE(ABORT,'aura:phase-invalid') END;
 SELECT CASE WHEN NEW.kind NOT IN ('boot.facts','gate.propose','gate.review',
  'gate.consume','gate.apply','gate.retire','gate.refuse','gate.expire','gate.recover',
  'floor.advance','aumlok.enrol','aumlok.bind','aumlok.signin','broker.grant',
  'broker.reserve','broker.settle','broker.revoke','kira.save','kira.demote',
  'kira.permission','sandbox.start','sandbox.exit','nostr.bind')
  THEN RAISE(ABORT,'aura:kind-invalid') END;
END;";

const AUTHORITY_TABLES: &str = "
CREATE TABLE aura_record_wrappers(
 seq INTEGER PRIMARY KEY REFERENCES aura(seq),epoch INTEGER NOT NULL CHECK(epoch BETWEEN 0 AND 9007199254740991),
 algorithm TEXT NOT NULL,signatures BLOB NOT NULL,public_keys BLOB NOT NULL,root TEXT NOT NULL);
CREATE TABLE authority_bindings(credential TEXT NOT NULL PRIMARY KEY,body BLOB NOT NULL,counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295));
CREATE TABLE authority_proposals(
 id TEXT NOT NULL PRIMARY KEY,operation TEXT NOT NULL UNIQUE,target TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','consumed','applied','refused','expired','retired','incomplete','failed','conflict','unknown')),body BLOB NOT NULL);
CREATE UNIQUE INDEX authority_active_target ON authority_proposals(target) WHERE status IN ('pending','consumed');
CREATE TABLE authority_challenges(
 proposal TEXT NOT NULL,action TEXT NOT NULL,challenge TEXT NOT NULL UNIQUE,
 body BLOB NOT NULL,card BLOB NOT NULL,spent INTEGER NOT NULL DEFAULT 0 CHECK(spent IN (0,1)),
 PRIMARY KEY(proposal,action));
CREATE TABLE authority_consumptions(
 approval TEXT NOT NULL PRIMARY KEY,proposal TEXT NOT NULL UNIQUE,operation TEXT NOT NULL,
 epoch INTEGER NOT NULL CHECK(epoch BETWEEN 0 AND 9007199254740991),sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 9007199254740991),proof BLOB NOT NULL,
 credential TEXT NOT NULL,counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),action TEXT NOT NULL,
 appended INTEGER NOT NULL DEFAULT 0 CHECK(appended IN (0,1)),previous_hash TEXT);
CREATE TABLE authority_declines(
 proposal TEXT NOT NULL PRIMARY KEY,operation_digest TEXT NOT NULL,evidence_digest TEXT NOT NULL,
 target TEXT NOT NULL,epoch INTEGER NOT NULL,sequence INTEGER NOT NULL,previous_hash TEXT);
CREATE TABLE authority_permissions(permission TEXT NOT NULL PRIMARY KEY,body BLOB NOT NULL);
CREATE TABLE authority_floor(id INTEGER PRIMARY KEY CHECK(id=1),state BLOB NOT NULL);
CREATE TRIGGER aura_wrapper_update_guard BEFORE UPDATE ON aura_record_wrappers BEGIN
 SELECT RAISE(ABORT,'aura:update-forbidden'); END;
CREATE TRIGGER aura_wrapper_delete_guard BEFORE DELETE ON aura_record_wrappers BEGIN
 SELECT RAISE(ABORT,'aura:delete-forbidden'); END;";

fn storage_error(_: rusqlite::Error) -> canon::Refusal {
    canon::codes::AURA_TRANSACTION
}

fn schema_error() -> canon::Refusal {
    canon::Refusal {
        organ: "aura",
        reason: "schema-mismatch",
    }
}

type SchemaObjects = Vec<(String, String, String, Option<String>)>;

fn objects(connection: &rusqlite::Connection) -> Result<SchemaObjects> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name,tbl_name",
        )
        .map_err(storage_error)?;
    let result = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(storage_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(storage_error);
    result
}

fn install(connection: &rusqlite::Connection, version: u32) -> Result<()> {
    connection.execute_batch(ROW_TABLE).map_err(storage_error)?;
    if version >= 2 {
        connection.execute_batch(GUARDS).map_err(storage_error)?;
    }
    if version >= 3 {
        connection
            .execute_batch(AUTHORITY_TABLES)
            .map_err(storage_error)?;
    }
    Ok(())
}

fn verify_schema(connection: &rusqlite::Connection, version: u32) -> Result<()> {
    let expected = rusqlite::Connection::open_in_memory().map_err(storage_error)?;
    install(&expected, version)?;
    let wanted = objects(&expected)?;
    // The node keeps other organs' tables (AUMLOK's ceremonies, Kira's notes) in this same file so that one authority
    // transaction can span them. Aura owns exactly its own tables: every object on an Aura table, and any object
    // named like one of Aura's, must match the installed schema exactly; other organs' objects are theirs to check.
    let tables: std::collections::BTreeSet<&str> = wanted.iter().map(|object| object.2.as_str()).collect();
    let owned = |name: &str| name.starts_with("aura") || name.starts_with("authority_");
    let found: SchemaObjects = objects(connection)?
        .into_iter()
        .filter(|object| tables.contains(object.2.as_str()) || owned(&object.1) || owned(&object.2))
        .collect();
    if found != wanted {
        return Err(schema_error());
    }
    Ok(())
}

fn row_snapshot(connection: &rusqlite::Connection) -> Result<(u64, Option<Digest32>)> {
    use rusqlite::OptionalExtension;
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM aura", [], |row| row.get(0))
        .map_err(storage_error)?;
    let head: Option<String> = connection
        .query_row(
            "SELECT hash FROM aura ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    connection
        .execute_batch("CREATE TEMP TABLE aura_preserved AS SELECT * FROM main.aura")
        .map_err(storage_error)?;
    Ok((
        u64::try_from(rows).map_err(|_| schema_error())?,
        head.map(|hash| Digest32::from_hex(&hash)).transpose()?,
    ))
}

fn compare_snapshot(connection: &rusqlite::Connection) -> Result<()> {
    let projection = C3_COLUMNS
        .iter()
        .flat_map(|column| [column.to_string(), format!("typeof({column})")])
        .collect::<Vec<_>>()
        .join(",");
    for (left, right) in [
        ("main.aura", "temp.aura_preserved"),
        ("temp.aura_preserved", "main.aura"),
    ] {
        let sql = format!("SELECT EXISTS(SELECT {projection} FROM {left} EXCEPT SELECT {projection} FROM {right})");
        let changed: bool = connection
            .query_row(&sql, [], |row| row.get(0))
            .map_err(storage_error)?;
        if changed {
            return Err(canon::Refusal {
                organ: "aura",
                reason: "migration-changed-history",
            });
        }
    }
    connection
        .execute_batch("DROP TABLE temp.aura_preserved")
        .map_err(storage_error)?;
    Ok(())
}

/// Admits only exact schemas and compares every retained SQLite value and type.
/// Nonempty old schemas lack authenticated wrappers and require an external key;
/// this entry point refuses them before changing schema or inferring authority.
pub(crate) fn migrate(connection: &mut rusqlite::Connection) -> Result<Vec<MigrationReceipt>> {
    use rusqlite::TransactionBehavior;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    let temp_count: i64 = transaction
        .query_row("SELECT count(*) FROM temp.sqlite_schema", [], |row| {
            row.get(0)
        })
        .map_err(storage_error)?;
    if temp_count != 0 {
        return Err(schema_error());
    }
    let mut version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(storage_error)?;
    let mut receipts = Vec::new();
    if version == 0 && objects(&transaction)?.is_empty() {
        install(&transaction, CURRENT_SCHEMA)?;
    } else {
        if !(1..=CURRENT_SCHEMA).contains(&version) {
            return Err(schema_error());
        }
        verify_schema(&transaction, version)?;
        if version < CURRENT_SCHEMA {
            let retained: i64 = transaction
                .query_row("SELECT count(*) FROM aura", [], |row| row.get(0))
                .map_err(storage_error)?;
            if retained != 0 {
                return Err(canon::Refusal {
                    organ: "aura",
                    reason: "migration-trusted-key-required",
                });
            }
        }
        while version < CURRENT_SCHEMA {
            let (preserved_rows, previous_head) = row_snapshot(&transaction)?;
            let migration = match version {
                1 => {
                    transaction.execute_batch(GUARDS).map_err(storage_error)?;
                    Migration::FrozenRowsToGuardedRows
                }
                2 => {
                    transaction
                        .execute_batch(AUTHORITY_TABLES)
                        .map_err(storage_error)?;
                    Migration::GuardedRowsToAuthorityStorage
                }
                _ => return Err(schema_error()),
            };
            compare_snapshot(&transaction)?;
            version += 1;
            verify_schema(&transaction, version)?;
            receipts.push(MigrationReceipt {
                migration,
                preserved_rows,
                previous_head,
            });
        }
    }
    verify_schema(&transaction, CURRENT_SCHEMA)?;
    transaction
        .pragma_update(None, "user_version", CURRENT_SCHEMA)
        .map_err(storage_error)?;
    transaction.commit().map_err(storage_error)?;
    Ok(receipts)
}

/// Verify the current schema without accepting an unrecognised storage layout.
pub(crate) fn validate(connection: &rusqlite::Connection) -> Result<()> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(storage_error)?;
    let temporary: i64 = connection
        .query_row("SELECT count(*) FROM temp.sqlite_schema", [], |row| {
            row.get(0)
        })
        .map_err(storage_error)?;
    if version != CURRENT_SCHEMA || temporary != 0 {
        return Err(schema_error());
    }
    verify_schema(connection, CURRENT_SCHEMA)
}
