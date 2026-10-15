//! Signed Aura records and RFC 6962 observations (contracts C2 and C3).

mod cold;
pub mod merkle;
mod migration;
mod verification;

use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{canonical_json, parse, Error as CanonError};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rusqlite::config::DbConfig;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{
    params, Connection, OptionalExtension, Transaction, TransactionBehavior, TransactionState,
};
use sha2::{Digest, Sha256};

pub use canon::Value;
pub use cold::{export_cold_proof, export_cold_proof_database};
pub use merkle::{PresentedHead, RetainedHead};
pub use migration::SchemaMigration;

/// Raw-row, materialized-row, proof-hash and in-memory terminal-state budgets.
/// Database verification streams; oversized rows or bounded buffers fail closed.
/// These budgets bound raw bytes and bookkeeping, not total RSS or JSON allocation overhead.
pub const MAX_BUFFER_BYTES: usize = 8 * 1024 * 1024;

pub const DOMAIN: &str = "aukora:aura-record:v1";
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const KINDS: &[&str] = &[
    "boot.facts",
    "gate.propose",
    "gate.review",
    "gate.consume",
    "gate.apply",
    "gate.retire",
    "gate.refuse",
    "gate.expire",
    "gate.recover",
    "floor.advance",
    "aumlok.enrol",
    "aumlok.bind",
    "aumlok.signin",
    "broker.grant",
    "broker.reserve",
    "broker.settle",
    "broker.revoke",
    "kira.save",
    "kira.demote",
    "kira.permission",
    "sandbox.start",
    "sandbox.exit",
    "nostr.bind",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code} (sequence {sequence:?})")]
pub struct Error {
    pub code: &'static str,
    pub sequence: Option<u64>,
}

impl Error {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            sequence: None,
        }
    }

    fn at(mut self, sequence: u64) -> Self {
        self.sequence = Some(sequence);
        self
    }
}

fn sql_error(error: rusqlite::Error) -> Error {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.extended_code == rusqlite::ffi::SQLITE_BUSY_SNAPSHOT =>
        {
            Error::new("aura:busy-snapshot")
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::DatabaseBusy
                || failure.code == rusqlite::ErrorCode::DatabaseLocked =>
        {
            Error::new("aura:busy")
        }
        _ => Error::new("aura:database"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEntry {
    pub at: i64,
    pub kind: String,
    pub actor: String,
    pub op: String,
    pub phase: String,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub sequence: u64,
    pub prev: String,
    pub hash: String,
    pub sig: String,
    pub at: i64,
    pub kind: String,
    pub actor: String,
    pub op: String,
    pub phase: String,
    pub body: Value,
}

impl Entry {
    pub fn fields(&self) -> NewEntry {
        NewEntry {
            at: self.at,
            kind: self.kind.clone(),
            actor: self.actor.clone(),
            op: self.op.clone(),
            phase: self.phase.clone(),
            body: self.body.clone(),
        }
    }
}

/// The caller retains the key and signs only the raw entry digest.
pub trait Signer {
    fn sign(&self, hash: &[u8; 32]) -> Result<[u8; 64], Error>;
}

impl Signer for SigningKey {
    fn sign(&self, hash: &[u8; 32]) -> Result<[u8; 64], Error> {
        ed25519_dalek::Signer::try_sign(self, hash)
            .map(|signature: Signature| signature.to_bytes())
            .map_err(|_| Error::new("aura:signing"))
    }
}

/// Configure and admit a file-backed connection before opening a transaction.
/// SQL guards protect ordinary statements on this connection. A holder of the raw
/// `Connection` can replace the authorizer or disable database configuration;
/// other connections and direct file writers are outside this guard. Admission
/// alone does not authenticate an existing history against an external head.
pub fn initialize(connection: &Connection) -> Result<(), Error> {
    if let Some(migration) = initialize_with_report(connection)? {
        eprintln!("{migration}");
    }
    Ok(())
}

/// Initialize as [`initialize`], returning a migration fact instead of logging it.
/// Fresh and already-current databases return `None`; no Aura row is written.
pub fn initialize_with_report(connection: &Connection) -> Result<Option<SchemaMigration>, Error> {
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .map_err(sql_error)?;
    if mode != "wal" {
        return Err(Error::new("aura:wal-unavailable"));
    }
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(sql_error)?;
    let migration = if schema_objects(connection, "main")?.is_empty() {
        // One transaction: a crash mid-create must leave an empty file, never a partial
        // schema that every later open refuses as a mismatch.
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        if schema_objects(&transaction, "main")?.is_empty() {
            transaction
                .execute_batch(include_str!("schema.sql"))
                .map_err(sql_error)?;
        }
        validate_schema(&transaction)?;
        transaction.commit().map_err(sql_error)?;
        None
    } else {
        migration::migrate_v1(connection)?
    };
    validate_schema(connection)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(sql_error)?;
    connection
        .authorizer(Some(aura_authorizer))
        .map_err(sql_error)?;
    Ok(migration)
}

type SchemaObject = (String, String, String, Option<String>);

fn qualifier_follows(mut input: std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    while let Some(character) = input.next() {
        if character.is_whitespace() {
            continue;
        }
        if character == '/' && input.peek() == Some(&'*') {
            input.next();
            while let Some(character) = input.next() {
                if character == '*' && input.peek() == Some(&'/') {
                    input.next();
                    break;
                }
            }
        } else if character == '-' && input.peek() == Some(&'-') {
            input.next();
            for character in input.by_ref() {
                if character == '\n' {
                    break;
                }
            }
        } else {
            return character == '.';
        }
    }
    false
}

// SQL identifiers also catch views and foreign keys mentioning Aura. Ignore
// string literals and comments: a body CHECK containing 'aura' is unrelated.
fn mentions_aura(sql: &str) -> bool {
    let mut input = sql.chars().peekable();
    let mut expect_table = false;
    let mut table_list = false;
    let mut contexts = Vec::new();
    while let Some(character) = input.next() {
        if character == '\'' {
            let mut quoted = String::new();
            while let Some(character) = input.next() {
                if character == '\'' {
                    if input.peek() == Some(&'\'') {
                        input.next();
                    } else {
                        break;
                    }
                }
                quoted.push(character);
            }
            // SQLite accepts single quotes for table identifiers in these
            // positions, while the same token in an expression is a literal.
            if expect_table && quoted.eq_ignore_ascii_case("aura") {
                return true;
            }
            expect_table = expect_table && qualifier_follows(input.clone());
        } else if character == '-' && input.peek() == Some(&'-') {
            input.next();
            for character in input.by_ref() {
                if character == '\n' {
                    break;
                }
            }
        } else if character == '/' && input.peek() == Some(&'*') {
            input.next();
            while let Some(character) = input.next() {
                if character == '*' && input.peek() == Some(&'/') {
                    input.next();
                    break;
                }
            }
        } else if character == '"' || character == '`' || character == '[' {
            let end = if character == '[' { ']' } else { character };
            let mut identifier = String::new();
            while let Some(character) = input.next() {
                if character == end {
                    if end != ']' && input.peek() == Some(&end) {
                        input.next();
                    } else {
                        break;
                    }
                }
                identifier.push(character);
            }
            if identifier.eq_ignore_ascii_case("aura") {
                return true;
            }
            expect_table = expect_table && qualifier_follows(input.clone());
        } else if character.is_alphanumeric() || character == '_' {
            let mut identifier = String::from(character);
            while input
                .peek()
                .is_some_and(|c| c.is_alphanumeric() || *c == '_')
            {
                identifier.push(input.next().unwrap());
            }
            if identifier.eq_ignore_ascii_case("aura") {
                return true;
            }
            match identifier.to_ascii_lowercase().as_str() {
                "from" | "join" => {
                    expect_table = true;
                    table_list = true;
                }
                "references" | "update" | "into" => {
                    expect_table = true;
                    table_list = false;
                }
                "on" => expect_table = false,
                "select" | "where" | "group" | "order" | "limit" | "having" | "union"
                | "except" | "intersect" | "set" | "values" => {
                    expect_table = false;
                    table_list = false;
                }
                "or" | "rollback" | "abort" | "fail" | "ignore" | "replace" if expect_table => {}
                _ => expect_table = expect_table && qualifier_follows(input.clone()),
            }
        } else if character == '(' {
            contexts.push((table_list, expect_table));
            table_list = expect_table;
        } else if character == ')' {
            if let Some((parent_list, _)) = contexts.pop() {
                table_list = parent_list;
            }
            expect_table = false;
        } else if character == ',' {
            expect_table = table_list;
        } else if character == ';' {
            table_list = false;
            expect_table = false;
        }
    }
    false
}

fn schema_objects(connection: &Connection, schema: &str) -> Result<Vec<SchemaObject>, Error> {
    // schema is a private constant, never caller-supplied SQL.
    let mut statement = connection
        .prepare(&format!("SELECT type,name,tbl_name,sql FROM {schema}.sqlite_schema ORDER BY type,name,tbl_name,sql"))
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut objects = Vec::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        let object: SchemaObject = (
            row.get(0).map_err(sql_error)?,
            row.get(1).map_err(sql_error)?,
            row.get(2).map_err(sql_error)?,
            row.get(3).map_err(sql_error)?,
        );
        if object.1.eq_ignore_ascii_case("aura")
            || object.2.eq_ignore_ascii_case("aura")
            || object.3.as_deref().is_some_and(mentions_aura)
        {
            objects.push(object);
        }
    }
    Ok(objects)
}

fn validate_schema(connection: &Connection) -> Result<(), Error> {
    let expected = Connection::open_in_memory().map_err(sql_error)?;
    expected
        .execute_batch(include_str!("schema.sql"))
        .map_err(sql_error)?;
    if schema_objects(connection, "main")? != schema_objects(&expected, "main")? {
        return Err(Error::new("aura:schema-mismatch"));
    }
    if !schema_objects(connection, "temp")?.is_empty() {
        return Err(Error::new("aura:temp-schema-mismatch"));
    }
    Ok(())
}

fn aura_authorizer(context: AuthContext<'_>) -> Authorization {
    use AuthAction::*;
    let protected = |name: &str| name.eq_ignore_ascii_case("aura");
    let denied = match context.action {
        CreateIndex { table_name, .. }
        | CreateTrigger { table_name, .. }
        | DropIndex { table_name, .. }
        | DropTrigger { table_name, .. }
        | DropTable { table_name }
        | DropVtable { table_name, .. }
        | AlterTable { table_name, .. }
        | Update { table_name, .. }
        | Delete { table_name } => protected(table_name),
        CreateTable { table_name } | CreateVtable { table_name, .. } => protected(table_name),
        CreateView { view_name } | DropView { view_name } => protected(view_name),
        CreateTempTable { .. }
        | CreateTempIndex { .. }
        | CreateTempTrigger { .. }
        | CreateTempView { .. } => true,
        Pragma {
            pragma_name,
            pragma_value: Some(value),
        } => {
            let pragma = pragma_name.to_ascii_lowercase();
            match pragma.as_str() {
                "writable_schema" | "ignore_check_constraints" | "recursive_triggers" => true,
                "journal_mode" => !value.eq_ignore_ascii_case("wal"),
                "synchronous" => !value.eq_ignore_ascii_case("full") && value != "2",
                _ => false,
            }
        }
        Attach { .. } | Detach { .. } => true,
        _ => false,
    };
    if denied {
        Authorization::Deny
    } else {
        Authorization::Allow
    }
}

/// A caller-owned transaction certified to have begun with `BEGIN IMMEDIATE`.
/// Its ordinary SQL operations share the exact transaction used by append.
#[derive(Debug)]
pub struct ImmediateTransaction<'connection>(Transaction<'connection>);

impl<'connection> std::ops::Deref for ImmediateTransaction<'connection> {
    type Target = Transaction<'connection>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ImmediateTransaction<'_> {
    pub fn commit(self) -> rusqlite::Result<()> {
        self.0.commit()
    }
    pub fn rollback(self) -> rusqlite::Result<()> {
        self.0.rollback()
    }
}

mod transaction_seal {
    pub trait Sealed {}
}

/// Sealed append input: raw rusqlite transactions are accepted only to return a
/// named refusal. Use [`begin`] even if a raw transaction was opened IMMEDIATE;
/// SQLite's Write state cannot distinguish IMMEDIATE from upgraded DEFERRED.
pub trait AppendTransaction: transaction_seal::Sealed {
    fn aura_transaction(&self) -> &Transaction<'_>;
    fn is_certified_immediate(&self) -> bool;
}

impl transaction_seal::Sealed for ImmediateTransaction<'_> {}
impl AppendTransaction for ImmediateTransaction<'_> {
    fn aura_transaction(&self) -> &Transaction<'_> {
        &self.0
    }
    fn is_certified_immediate(&self) -> bool {
        true
    }
}

impl transaction_seal::Sealed for Transaction<'_> {}
impl AppendTransaction for Transaction<'_> {
    fn aura_transaction(&self) -> &Transaction<'_> {
        self
    }
    fn is_certified_immediate(&self) -> bool {
        false
    }
}

/// An organ's own transaction, proven to hold the main database's write lock.
///
/// Organs that own their transaction type (the gate, Kira) begin it IMMEDIATE
/// themselves and append through their ledger trait. SQLite never grants the
/// write lock to a transaction whose view is stale (a WAL snapshot that missed
/// a commit fails with SQLITE_BUSY_SNAPSHOT; in rollback mode a reader's SHARED
/// lock blocks other commits), so a transaction in Write state reads the
/// latest committed tip. Append re-checks the state before its INSERT.
#[derive(Debug)]
pub struct WriteLocked<'a, 'connection>(&'a Transaction<'connection>);

impl<'a, 'connection> WriteLocked<'a, 'connection> {
    /// The organ's state change and the Aura row commit atomically only when both
    /// live in the one WAL-mode `main` database: a second attached file would make
    /// the commit non-atomic across files. The organ must also not roll the Aura row
    /// back to a savepoint while keeping its own change.
    pub fn new(transaction: &'a Transaction<'connection>) -> Result<Self, Error> {
        if transaction.is_autocommit() {
            return Err(Error::new("aura:no-transaction"));
        }
        if transaction
            .transaction_state(Some("main"))
            .map_err(sql_error)?
            != TransactionState::Write
        {
            return Err(Error::new("aura:immediate-required"));
        }
        let mode: String = transaction
            .query_row("PRAGMA main.journal_mode", [], |row| row.get(0))
            .map_err(sql_error)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(Error::new("aura:not-initialized"));
        }
        let mut schemas = transaction
            .prepare("SELECT name FROM pragma_database_list")
            .map_err(sql_error)?;
        let names = schemas
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sql_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_error)?;
        if names.iter().any(|name| name != "main" && name != "temp") {
            return Err(Error::new("aura:attached-database"));
        }
        Ok(Self(transaction))
    }
}

impl transaction_seal::Sealed for WriteLocked<'_, '_> {}
impl AppendTransaction for WriteLocked<'_, '_> {
    fn aura_transaction(&self) -> &Transaction<'_> {
        self.0
    }
    fn is_certified_immediate(&self) -> bool {
        true
    }
}

/// Take the shared writer lock before any caller reads or state changes.
/// Busy errors require retrying the complete caller transaction.
pub fn begin(connection: &mut Connection) -> Result<ImmediateTransaction<'_>, Error> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map(ImmediateTransaction)
        .map_err(sql_error)
}

fn require_append_transaction(owner: &impl AppendTransaction) -> Result<(), Error> {
    let transaction = owner.aura_transaction();
    if transaction.is_autocommit() {
        return Err(Error::new("aura:no-transaction"));
    }
    if !owner.is_certified_immediate() {
        return Err(Error::new("aura:immediate-required"));
    }
    if transaction
        .transaction_state(Some("main"))
        .map_err(sql_error)?
        != TransactionState::Write
    {
        return Err(Error::new("aura:immediate-required"));
    }
    Ok(())
}

fn validate(fields: &NewEntry) -> Result<(), Error> {
    if !KINDS.contains(&fields.kind.as_str()) {
        return Err(Error::new("aura:unknown-kind"));
    }
    if !["intent", "settle", "terminal", "fact"].contains(&fields.phase.as_str()) {
        return Err(Error::new("aura:invalid-phase"));
    }
    if fields.phase == "terminal" && fields.op.is_empty() {
        return Err(Error::new("aura:missing-operation"));
    }
    if fields.at.unsigned_abs() > MAX_SAFE_INTEGER {
        return Err(Error::new("aura:invalid-time"));
    }
    canonical_json(&fields.body).map_err(invalid_body)?;
    Ok(())
}

fn invalid_body(_: CanonError) -> Error {
    Error::new("aura:invalid-body")
}

fn append_canonical_member(
    output: &mut Vec<u8>,
    first: &mut bool,
    name: &'static str,
    value: &Value,
) -> Result<(), Error> {
    if !*first {
        output.push(b',');
    }
    *first = false;
    output.extend(canonical_json(&Value::String(name.into())).map_err(invalid_body)?);
    output.push(b':');
    output.extend(canonical_json(value).map_err(invalid_body)?);
    Ok(())
}

/// Canonicalize the fixed C2 preimage without charging its envelope against
/// the C1 body-depth limit. Every key and value is still encoded by `canon`.
fn entry_preimage(prev: &str, fields: &NewEntry, sequence: u64) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut first = true;
    output.push(b'{');
    for (name, value) in [
        ("actor", Value::String(fields.actor.clone())),
        ("at", Value::Integer(fields.at)),
        ("body", fields.body.clone()),
        ("domain", Value::String(DOMAIN.into())),
        ("kind", Value::String(fields.kind.clone())),
        ("op", Value::String(fields.op.clone())),
        ("phase", Value::String(fields.phase.clone())),
        ("prev", Value::String(prev.into())),
        ("sequence", Value::Integer(sequence as i64)),
    ] {
        append_canonical_member(&mut output, &mut first, name, &value)?;
    }
    output.push(b'}');
    Ok(output)
}

pub fn entry_hash(prev: &str, fields: &NewEntry, sequence: u64) -> Result<[u8; 32], Error> {
    validate(fields)?;
    if sequence == 0 || sequence > MAX_SAFE_INTEGER {
        return Err(Error::new("aura:invalid-sequence"));
    }
    Ok(Sha256::digest(entry_preimage(prev, fields, sequence)?).into())
}

/// Append inside the caller's `BEGIN IMMEDIATE` transaction without committing.
/// The main database must already hold a write lock; DEFERRED read transactions
/// are refused before reading the tip. Existing histories need an authenticated
/// walk at boot: this constant-work tip lookup does not scan for interior gaps.
pub fn append(
    append_transaction: &impl AppendTransaction,
    signer: &impl Signer,
    key: &VerifyingKey,
    fields: &NewEntry,
) -> Result<Entry, Error> {
    require_append_transaction(append_transaction)?;
    let transaction = append_transaction.aura_transaction();
    validate(fields)?;
    let tip: Option<(i64, String)> = transaction
        .query_row(
            "SELECT seq,hash FROM main.aura ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql_error)?;
    let (last, prev) = tip.unwrap_or_else(|| (0, DOMAIN.to_owned()));
    if last < 0 || last >= MAX_SAFE_INTEGER as i64 {
        return Err(Error::new("aura:sequence-gap"));
    }
    let sequence = (last + 1) as u64;
    let hash_bytes = entry_hash(&prev, fields, sequence)?;
    let hash = hex::encode(hash_bytes);
    let signature = Signature::from_bytes(&signer.sign(&hash_bytes)?);
    key.verify_strict(&hash_bytes, &signature)
        .map_err(|_| Error::new("aura:signing"))?;
    let sig = STANDARD.encode(signature.to_bytes());
    let body_bytes = canonical_json(&fields.body).map_err(invalid_body)?;
    let admitted_body = parse(&body_bytes).map_err(invalid_body)?;
    let body = String::from_utf8(body_bytes).expect("canonical JSON is UTF-8");
    // A signer implementation can call back into the connection. Never let an
    // implicit rollback turn the following INSERT into an autocommit write.
    require_append_transaction(append_transaction)?;
    let changed = transaction.execute(
        "INSERT INTO main.aura(seq,prev,hash,sig,at,kind,actor,op,phase,body) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![sequence as i64, prev, hash, sig, fields.at, fields.kind, fields.actor, fields.op, fields.phase, body],
    ).map_err(|error| {
        if transaction.is_autocommit() { Error::new("aura:transaction-lost") } else { sql_error(error) }
    })?;
    if changed != 1 {
        return Err(Error::new("aura:not-inserted"));
    }
    let stored_hash: Option<String> = transaction
        .query_row(
            "SELECT hash FROM main.aura WHERE seq=?1",
            [sequence as i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_error)?;
    if stored_hash.as_deref() != Some(hash.as_str()) {
        return Err(Error::new("aura:stored-hash-mismatch"));
    }
    Ok(Entry {
        sequence,
        prev,
        hash,
        sig,
        at: fields.at,
        kind: fields.kind.clone(),
        actor: fields.actor.clone(),
        op: fields.op.clone(),
        phase: fields.phase.clone(),
        body: admitted_body,
    })
}

/// Compatibility materialization with a fixed budget; use the database APIs for long logs.
#[cfg(test)]
mod storage_error_tests {
    use super::*;

    #[test]
    fn antibody_aura_fresh_schema_is_created_in_one_transaction() {
        // Grok review (2026-10-15): a crash part-way through creating a fresh ledger must
        // leave an empty file that the next open creates again, not a partial schema.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fresh.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .authorizer(Some(|context: AuthContext<'_>| match context.action {
                AuthAction::CreateTrigger {
                    trigger_name: "aura_next_sequence",
                    ..
                } => Authorization::Deny,
                _ => Authorization::Allow,
            }))
            .unwrap();
        assert!(initialize(&connection).is_err());
        drop(connection);
        let reopened = Connection::open(&path).unwrap();
        assert!(schema_objects(&reopened, "main").unwrap().is_empty());
        initialize(&reopened).unwrap();
        validate_schema(&reopened).unwrap();
    }

    #[test]
    fn drop_table_authorizer_is_independent_of_delete_guard() {
        let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let connection = Connection::open(directory.path().join("drop.db")).unwrap();
        initialize(&connection).unwrap();
        connection
            .authorizer(Some(|context: AuthContext<'_>| {
                match context.action {
                    // Implicit DELETE and DROP TRIGGER requests must not mask
                    // removal of the independent DROP TABLE policy.
                    AuthAction::DropTable { .. } => aura_authorizer(context),
                    _ => Authorization::Allow,
                }
            }))
            .unwrap();
        let error = connection
            .execute_batch("DROP TABLE main.aura")
            .unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::AuthorizationForStatementDenied)
        );
    }

    #[test]
    fn stale_deferred_raw_write_preserves_the_busy_snapshot_code() {
        let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let path = directory.path().join("snapshot.db");
        let mut writer = Connection::open(&path).unwrap();
        initialize(&writer).unwrap();
        writer
            .execute_batch("CREATE TABLE state(value INTEGER); INSERT INTO state VALUES(0)")
            .unwrap();
        let mut reader = Connection::open(&path).unwrap();
        initialize(&reader).unwrap();
        let stale = reader.transaction().unwrap();
        stale
            .query_row("SELECT value FROM state", [], |row| row.get::<_, i64>(0))
            .unwrap();
        let winner = begin(&mut writer).unwrap();
        winner.execute("UPDATE state SET value=1", []).unwrap();
        winner.commit().unwrap();
        let error = stale.execute("UPDATE state SET value=2", []).unwrap_err();
        assert_eq!(
            error.sqlite_error().unwrap().extended_code,
            rusqlite::ffi::SQLITE_BUSY_SNAPSHOT
        );
        assert_eq!(sql_error(error).code, "aura:busy-snapshot");
        stale.rollback().unwrap();
    }
}

pub fn read_entries(connection: &Connection) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    let mut bytes = 0usize;
    scan_entries(connection, |entry, row_bytes| {
        bytes = bytes.saturating_add(row_bytes + 256);
        if bytes > MAX_BUFFER_BYTES {
            return Err(Error::new("aura:memory-limit").at(entry.sequence));
        }
        entries.push(entry);
        Ok(())
    })?;
    Ok(entries)
}

const ENTRY_COLUMNS: &str = "seq,prev,hash,sig,at,kind,actor,op,phase,body,
    length(CAST(prev AS BLOB))+length(CAST(hash AS BLOB))+length(CAST(sig AS BLOB))+
    length(CAST(kind AS BLOB))+length(CAST(actor AS BLOB))+length(CAST(op AS BLOB))+
    length(CAST(phase AS BLOB))+length(CAST(body AS BLOB))";

/// Read one bounded, canonical row, with the same decoding checks as `read_entries`.
/// Authenticate the chain with `walk_database` in the same transaction before using it.
pub fn read_entry(connection: &Connection, sequence: u64) -> Result<Option<Entry>, Error> {
    if sequence == 0 || sequence > MAX_SAFE_INTEGER {
        return Err(Error::new("aura:invalid-sequence"));
    }
    let mut statement = connection
        .prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM main.aura WHERE seq=?1"
        ))
        .map_err(sql_error)?;
    let mut rows = statement.query([sequence as i64]).map_err(sql_error)?;
    rows.next()
        .map_err(sql_error)?
        .map(decode_entry)
        .transpose()
        .map(|row| row.map(|(entry, _)| entry))
}

fn decode_entry(row: &rusqlite::Row<'_>) -> Result<(Entry, usize), Error> {
    let sequence = u64::try_from(row.get::<_, i64>(0).map_err(sql_error)?)
        .map_err(|_| Error::new("aura:invalid-sequence"))?;
    let row_bytes = usize::try_from(row.get::<_, i64>(10).map_err(sql_error)?)
        .map_err(|_| Error::new("aura:memory-limit").at(sequence))?;
    // Bound allocations before copying SQLite strings or parsing the JSON tree.
    if row_bytes > MAX_BUFFER_BYTES {
        return Err(Error::new("aura:memory-limit").at(sequence));
    }
    let body: String = row.get(9).map_err(sql_error)?;
    let value = parse(body.as_bytes()).map_err(|error| invalid_body(error).at(sequence))?;
    if canonical_json(&value).map_err(invalid_body)? != body.as_bytes() {
        return Err(Error::new("aura:noncanonical-body").at(sequence));
    }
    Ok((
        Entry {
            sequence,
            prev: row.get(1).map_err(sql_error)?,
            hash: row.get(2).map_err(sql_error)?,
            sig: row.get(3).map_err(sql_error)?,
            at: row.get(4).map_err(sql_error)?,
            kind: row.get(5).map_err(sql_error)?,
            actor: row.get(6).map_err(sql_error)?,
            op: row.get(7).map_err(sql_error)?,
            phase: row.get(8).map_err(sql_error)?,
            body: value,
        },
        row_bytes,
    ))
}

fn scan_entries(
    connection: &Connection,
    mut consume: impl FnMut(Entry, usize) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM main.aura ORDER BY seq"
        ))
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let (entry, row_bytes) = decode_entry(row)?;
        consume(entry, row_bytes)?;
    }
    Ok(())
}

fn digest(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::new("aura:invalid-hash"));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::new("aura:invalid-hash"))?;
    Ok(bytes)
}

/// Verify each record against an independently supplied node public key.
/// A retained head detects rollback; a head alone cannot localize a fully re-signed rewrite.
pub fn walk(
    entries: &[Entry],
    key: &VerifyingKey,
    retained: Option<&RetainedHead>,
) -> Result<(), Error> {
    let mut verification = verification::Verification::new(key, retained)?;
    for entry in entries {
        verification.push(entry)?;
    }
    verification.finish()
}

/// Stream a ledger snapshot without materializing its records.
/// Completeness without an independent retained observation remains UNCHECKED.
pub fn walk_database(
    connection: &Connection,
    key: &VerifyingKey,
    retained: Option<&RetainedHead>,
) -> Result<(), Error> {
    scan_verified_entries(connection, key, retained, |_, _| Ok(()))
}

fn read_snapshot<T>(
    connection: &Connection,
    read: impl FnOnce(&Connection) -> Result<T, Error>,
) -> Result<T, Error> {
    if !connection.is_autocommit() {
        return read(connection);
    }
    let transaction = connection.unchecked_transaction().map_err(sql_error)?;
    let result = read(&transaction)?;
    transaction.commit().map_err(sql_error)?;
    Ok(result)
}

fn scan_verified_entries(
    connection: &Connection,
    key: &VerifyingKey,
    retained: Option<&RetainedHead>,
    mut consume: impl FnMut(Entry, merkle::Hash) -> Result<(), Error>,
) -> Result<(), Error> {
    read_snapshot(connection, |snapshot| {
        let mut verification = verification::Verification::for_database(key, retained)?;
        let mut prior_terminal = snapshot
            .prepare(
                "SELECT seq FROM main.aura WHERE phase='terminal' AND op=?1 AND seq<?2 LIMIT 1",
            )
            .map_err(sql_error)?;
        scan_entries(snapshot, |entry, _| {
            let hash = verification.push(&entry)?;
            if entry.phase == "terminal" {
                let prior: Option<i64> = prior_terminal
                    .query_row(params![entry.op, entry.sequence as i64], |row| row.get(0))
                    .optional()
                    .map_err(sql_error)?;
                if prior.is_some() {
                    return Err(Error::new("aura:duplicate-terminal").at(entry.sequence));
                }
            }
            consume(entry, hash)
        })?;
        verification.finish()
    })
}

/// A retained copy can localize a rewrite even if the attacker re-signs the suffix.
/// An empty retained copy is UNCHECKED, returned as `aura:empty-retained`.
pub fn walk_against_prefix(
    entries: &[Entry],
    retained: &[Entry],
    key: &VerifyingKey,
) -> Result<(), Error> {
    if retained.is_empty() {
        return Err(Error::new("aura:empty-retained"));
    }
    walk(retained, key, None)?;
    let differs = entries.iter().zip(retained).position(|(a, b)| a != b);
    let chain = walk(entries, key, None);
    if let Some(index) = differs {
        if chain
            .as_ref()
            .err()
            .and_then(|e| e.sequence)
            .is_none_or(|seq| (index as u64) < seq)
        {
            return Err(Error::new("aura:retained-entry-differs").at(index as u64 + 1));
        }
    }
    chain?;
    if entries.len() < retained.len() {
        return Err(Error::new("aura:shorter-than-retained").at(entries.len() as u64 + 1));
    }
    Ok(())
}

/// Verify and derive both documents from one read snapshot of the ledger.
pub fn export(
    entries: &[Entry],
    key: &VerifyingKey,
    retained_size: usize,
) -> Result<(RetainedHead, PresentedHead), Error> {
    if entries.len() > MAX_BUFFER_BYTES / 32 {
        return Err(Error::new("aura:memory-limit"));
    }
    walk(entries, key, None)?;
    let hashes = entries
        .iter()
        .map(|entry| digest(&entry.hash))
        .collect::<Result<Vec<_>, _>>()?;
    export_hashes(&hashes, retained_size)
}

/// Stream records from one snapshot; retain only bounded 32-byte entry digests for proofs.
/// A full authentication walk is deliberate: no untrusted cached checkpoint gains authority.
pub fn export_database(
    connection: &Connection,
    key: &VerifyingKey,
    retained_size: usize,
) -> Result<(RetainedHead, PresentedHead), Error> {
    export_database_bounded(connection, key, retained_size, MAX_BUFFER_BYTES)
}

fn export_database_bounded(
    connection: &Connection,
    key: &VerifyingKey,
    retained_size: usize,
    hash_budget: usize,
) -> Result<(RetainedHead, PresentedHead), Error> {
    let mut hashes = Vec::new();
    scan_verified_entries(connection, key, None, |entry, hash| {
        if hashes.len() >= hash_budget / 32 {
            return Err(Error::new("aura:memory-limit").at(entry.sequence));
        }
        hashes.push(hash);
        Ok(())
    })?;
    export_hashes(&hashes, retained_size)
}

fn export_hashes(
    hashes: &[merkle::Hash],
    retained_size: usize,
) -> Result<(RetainedHead, PresentedHead), Error> {
    Ok((
        merkle::retained_head(hashes, retained_size)?,
        merkle::presented_head(hashes, retained_size)?,
    ))
}

/// Missing terminal rows are checked only after the caller declares an operation complete.
pub fn require_terminal(connection: &Connection, operation: &str) -> Result<(), Error> {
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM main.aura WHERE op=?1 AND phase='terminal'",
            [operation],
            |r| r.get(0),
        )
        .map_err(sql_error)?;
    if operation.is_empty() || count != 1 {
        return Err(Error::new("aura:terminal-count"));
    }
    Ok(())
}

#[cfg(test)]
mod bounded_export_tests {
    use super::*;

    #[test]
    fn streaming_proof_hashes_stop_at_budget() {
        let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let mut connection = Connection::open(directory.path().join("aura.db")).unwrap();
        initialize(&connection).unwrap();
        let key = SigningKey::from_bytes(&[19; 32]);
        let transaction = begin(&mut connection).unwrap();
        let fields = NewEntry {
            at: 0,
            kind: "boot.facts".into(),
            actor: "a".into(),
            op: String::new(),
            phase: "fact".into(),
            body: Value::Object(Vec::new()),
        };
        for _ in 0..3 {
            append(&transaction, &key, &key.verifying_key(), &fields).unwrap();
        }
        transaction.commit().unwrap();
        assert_eq!(
            export_database_bounded(&connection, &key.verifying_key(), 1, 64).unwrap_err(),
            Error {
                code: "aura:memory-limit",
                sequence: Some(3)
            }
        );
        export_database_bounded(&connection, &key.verifying_key(), 1, 96).unwrap();
    }
}
