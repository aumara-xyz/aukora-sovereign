use aura::{
    append, begin, initialize, read_entries, Error, NewEntry, Signer, Value, WriteLocked, DOMAIN,
};
use ed25519_dalek::SigningKey;
use rusqlite::config::DbConfig;
use rusqlite::hooks::{AuthContext, Authorization};
use rusqlite::{Connection, ErrorCode};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn database() -> (tempfile::TempDir, Connection) {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connection = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&connection).unwrap();
    (directory, connection)
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[19; 32])
}

fn fields() -> NewEntry {
    NewEntry {
        at: 1_700_000_000_000,
        kind: "boot.facts".into(),
        actor: "supervisor".into(),
        op: String::new(),
        phase: "fact".into(),
        body: Value::Object(vec![("facts".into(), Value::Bool(true))]),
    }
}

// Tamper fixtures intentionally remove the SQL guard, to test each independent
// admission/storage protection rather than letting another guard mask a mutant.
fn clear_sql_guard(connection: &Connection) {
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
}

#[test]
fn admission_rejects_every_extra_main_aura_object() {
    for sql in [
        "CREATE TRIGGER zz_drop BEFORE INSERT ON aura WHEN NEW.kind='gate.consume' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE UNIQUE INDEX zz_extra ON aura(actor)",
        "CREATE VIEW zz_view AS SELECT * FROM main.aura",
        "CREATE VIEW zz_quoted AS SELECT * FROM main.\"AuRa\"",
        "CREATE VIEW zz_single AS SELECT * FROM 'aura'",
        "CREATE VIEW zz_single_qualified AS SELECT * FROM main.'aura'",
        "CREATE VIEW zz_comment AS SELECT * FROM main/*x*/.'aura'",
        "CREATE VIEW zz_comment_single AS SELECT * FROM 'main'/*x*/.'aura'",
        "CREATE TABLE gate_state(value INTEGER); CREATE TRIGGER refs_update AFTER INSERT ON gate_state BEGIN UPDATE OR REPLACE 'aura' SET actor='other'; END",
        "CREATE TABLE refs_single(id INTEGER REFERENCES 'aura'(seq))",
        "CREATE TABLE gate_state(value INTEGER); CREATE TRIGGER refs_trigger AFTER INSERT ON gate_state BEGIN INSERT INTO 'aura'(seq) VALUES(1); END",
        "CREATE TABLE gate_state(value INTEGER); CREATE VIEW comma_refs AS SELECT * FROM gate_state, 'aura'",
        "CREATE TABLE gate_state(x INTEGER); CREATE VIEW zz_join AS SELECT * FROM gate_state a JOIN gate_state b ON a.x=b.x, 'aura'",
        "CREATE TABLE refs(id INTEGER REFERENCES aura(seq))",
    ] {
        let (_directory, connection) = database();
        clear_sql_guard(&connection);
        connection.execute_batch(sql).unwrap();
        assert_eq!(initialize(&connection).unwrap_err().code, "aura:schema-mismatch", "{sql}");
    }
}

#[test]
fn admission_rejects_every_temp_aura_object() {
    for sql in [
        "CREATE TEMP TABLE aura AS SELECT * FROM main.aura",
        "CREATE TEMP TRIGGER zz_ignore BEFORE INSERT ON main.aura BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TEMP VIEW zz_shadow AS SELECT * FROM main.aura",
    ] {
        let (_directory, connection) = database();
        clear_sql_guard(&connection);
        connection.execute_batch(sql).unwrap();
        assert_eq!(
            initialize(&connection).unwrap_err().code,
            "aura:temp-schema-mismatch",
            "{sql}"
        );
    }
}

#[test]
fn admission_preserves_unrelated_organ_tables_and_is_idempotent() {
    let (_directory, connection) = database();
    connection
        .execute_batch("CREATE TABLE gate_state(value TEXT CHECK(value!='aura')); -- aura\n")
        .unwrap();
    initialize(&connection).unwrap();
}

#[test]
fn authorizer_denies_rewrite_drop_alter_temp_and_unsafe_pragmas() {
    let (_directory, connection) = database();
    clear_sql_guard(&connection);
    connection
        .execute_batch("ATTACH ':memory:' AS attached")
        .unwrap();
    initialize(&connection).unwrap();
    for sql in [
        "DROP TRIGGER aura_no_update",
        "DROP TRIGGER aura_no_delete",
        "DROP INDEX aura_one_terminal",
        "DROP TABLE aura",
        "ALTER TABLE aura RENAME TO aura_old",
        "UPDATE aura SET actor='attacker'",
        "DELETE FROM aura",
        "CREATE INDEX extra ON aura(actor)",
        "CREATE TRIGGER extra BEFORE INSERT ON aura BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TEMP TABLE aura AS SELECT * FROM main.aura",
        "CREATE TEMP TRIGGER extra BEFORE INSERT ON main.aura BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TEMP VIEW aura AS SELECT * FROM main.aura",
        "PRAGMA writable_schema=ON",
        "PRAGMA ignore_check_constraints=ON",
        "PRAGMA recursive_triggers=OFF",
        "PRAGMA journal_mode=DELETE",
        "PRAGMA synchronous=OFF",
        "ATTACH ':memory:' AS peer",
        "DETACH attached",
    ] {
        let error = connection.execute_batch(sql).unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(ErrorCode::AuthorizationForStatementDenied),
            "{sql}: {error}"
        );
    }
}

#[test]
fn defensive_configuration_blocks_schema_writes_without_authorizer() {
    let (_directory, connection) = database();
    assert!(connection
        .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .unwrap());
    clear_sql_guard(&connection);
    connection
        .execute_batch("PRAGMA writable_schema=ON")
        .unwrap();
    assert!(connection
        .execute("DELETE FROM sqlite_schema WHERE name='aura_no_delete'", [])
        .is_err());
}

#[test]
fn ignored_insert_is_refused_instead_of_returning_a_ghost_receipt() {
    let (_directory, mut connection) = database();
    clear_sql_guard(&connection);
    connection.execute_batch("CREATE TABLE gate_state(spent INTEGER); INSERT INTO gate_state VALUES(0);
        CREATE TRIGGER zz_ignore BEFORE INSERT ON aura WHEN NEW.seq=2 BEGIN SELECT RAISE(IGNORE); END").unwrap();
    let transaction = begin(&mut connection).unwrap();
    append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
    transaction
        .execute("UPDATE gate_state SET spent=1", [])
        .unwrap();
    let mut consume = fields();
    consume.kind = "gate.consume".into();
    assert_eq!(
        append(&transaction, &key(), &key().verifying_key(), &consume)
            .unwrap_err()
            .code,
        "aura:not-inserted"
    );
    transaction.rollback().unwrap();
    assert!(read_entries(&connection).unwrap().is_empty());
    assert_eq!(
        connection
            .query_row("SELECT spent FROM gate_state", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn append_checks_the_hash_actually_stored_by_after_insert_triggers() {
    let (_directory, mut connection) = database();
    clear_sql_guard(&connection);
    connection.execute_batch("DROP TRIGGER aura_no_update;
        CREATE TRIGGER zz_rewrite AFTER INSERT ON aura BEGIN
          UPDATE aura SET hash='abababababababababababababababababababababababababababababababab' WHERE seq=NEW.seq;
        END").unwrap();
    let transaction = begin(&mut connection).unwrap();
    assert_eq!(
        append(&transaction, &key(), &key().verifying_key(), &fields())
            .unwrap_err()
            .code,
        "aura:stored-hash-mismatch"
    );
    transaction.rollback().unwrap();
    assert!(read_entries(&connection).unwrap().is_empty());
}

#[test]
fn append_reads_and_writes_main_even_after_a_temp_shadow_is_planted() {
    let (directory, mut connection) = database();
    let transaction = begin(&mut connection).unwrap();
    let first = append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
    transaction.commit().unwrap();
    clear_sql_guard(&connection);
    connection
        .execute_batch("CREATE TEMP TABLE aura AS SELECT * FROM main.aura WHERE 0")
        .unwrap();
    let transaction = begin(&mut connection).unwrap();
    let second = append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
    assert_eq!((second.sequence, second.prev), (2, first.hash));
    transaction.commit().unwrap();
    let observer = Connection::open(directory.path().join("aura.db")).unwrap();
    assert_eq!(read_entries(&observer).unwrap().len(), 2);
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM temp.aura", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn wrong_key_and_faulty_signatures_never_enter_the_ledger() {
    struct Faulty;
    impl Signer for Faulty {
        fn sign(&self, _: &[u8; 32]) -> Result<[u8; 64], Error> {
            Ok([0; 64])
        }
    }
    let (_directory, mut connection) = database();
    let transaction = begin(&mut connection).unwrap();
    for _ in 0..12 {
        append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
    }
    let wrong = SigningKey::from_bytes(&[7; 32]);
    assert_eq!(
        append(&transaction, &wrong, &key().verifying_key(), &fields())
            .unwrap_err()
            .code,
        "aura:signing"
    );
    assert_eq!(
        append(&transaction, &Faulty, &key().verifying_key(), &fields())
            .unwrap_err()
            .code,
        "aura:signing"
    );
    assert_eq!(
        append(&transaction, &key(), &key().verifying_key(), &fields())
            .unwrap()
            .sequence,
        13
    );
    transaction.commit().unwrap();
    let entries = read_entries(&connection).unwrap();
    assert_eq!(entries.len(), 13);
    aura::export(&entries, &key().verifying_key(), 8).unwrap();
}

#[test]
fn implicit_rollback_refuses_an_autocommit_refusal_append() {
    let (directory, mut connection) = database();
    connection.execute_batch("CREATE TABLE ceremony(spent INTEGER); INSERT INTO ceremony VALUES(0);
        CREATE TRIGGER ceremony_guard BEFORE UPDATE ON ceremony BEGIN SELECT RAISE(ROLLBACK, 'spent'); END").unwrap();
    let transaction = begin(&mut connection).unwrap();
    let mut entry = fields();
    entry.kind = "gate.consume".into();
    entry.op = "op1".into();
    entry.phase = "intent".into();
    append(&transaction, &key(), &key().verifying_key(), &entry).unwrap();
    assert!(transaction
        .execute("UPDATE ceremony SET spent=1", [])
        .is_err());
    assert!(transaction.is_autocommit());
    entry.kind = "gate.refuse".into();
    entry.phase = "terminal".into();
    assert_eq!(
        append(&transaction, &key(), &key().verifying_key(), &entry)
            .unwrap_err()
            .code,
        "aura:no-transaction"
    );
    let observer = Connection::open(directory.path().join("aura.db")).unwrap();
    assert!(read_entries(&observer).unwrap().is_empty());
    assert!(transaction.rollback().is_err());
}

#[test]
fn signer_callback_cannot_rollback_then_escape_the_transaction() {
    struct RollbackSigner<'a>(&'a Connection);
    impl Signer for RollbackSigner<'_> {
        fn sign(&self, hash: &[u8; 32]) -> Result<[u8; 64], Error> {
            self.0.execute_batch("ROLLBACK").unwrap();
            Signer::sign(&key(), hash)
        }
    }
    let (_directory, mut connection) = database();
    let transaction = begin(&mut connection).unwrap();
    assert_eq!(
        append(
            &transaction,
            &RollbackSigner(&transaction),
            &key().verifying_key(),
            &fields()
        )
        .unwrap_err()
        .code,
        "aura:no-transaction"
    );
    assert!(read_entries(&transaction).unwrap().is_empty());
}

#[test]
fn insert_rollback_has_a_distinct_transaction_lost_code() {
    let (_directory, mut connection) = database();
    clear_sql_guard(&connection);
    connection.execute_batch("CREATE TRIGGER zz_rollback BEFORE INSERT ON aura BEGIN SELECT RAISE(ROLLBACK, 'lost'); END").unwrap();
    let transaction = begin(&mut connection).unwrap();
    assert_eq!(
        append(&transaction, &key(), &key().verifying_key(), &fields())
            .unwrap_err()
            .code,
        "aura:transaction-lost"
    );
    assert!(transaction.is_autocommit());
    assert!(read_entries(&transaction).unwrap().is_empty());
}

#[test]
fn deferred_stale_snapshot_is_refused_before_tip_read_and_can_retry_whole_transaction() {
    let (directory, mut writer) = database();
    writer
        .execute_batch("CREATE TABLE gate_state(spent INTEGER); INSERT INTO gate_state VALUES(0)")
        .unwrap();
    let mut stale = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&stale).unwrap();
    let transaction = stale.transaction().unwrap();
    transaction
        .query_row("SELECT spent FROM gate_state", [], |r| r.get::<_, i64>(0))
        .unwrap();
    let winner = begin(&mut writer).unwrap();
    append(&winner, &key(), &key().verifying_key(), &fields()).unwrap();
    winner.commit().unwrap();
    assert_eq!(
        append(&transaction, &key(), &key().verifying_key(), &fields())
            .unwrap_err()
            .code,
        "aura:immediate-required"
    );
    transaction.rollback().unwrap();
    let retry = begin(&mut stale).unwrap();
    assert_eq!(
        append(&retry, &key(), &key().verifying_key(), &fields())
            .unwrap()
            .sequence,
        2
    );
    retry.commit().unwrap();
}

#[test]
fn deferred_already_upgraded_to_write_is_still_refused() {
    let (_directory, mut connection) = database();
    connection
        .execute_batch("CREATE TABLE organ_state(spent INTEGER); INSERT INTO organ_state VALUES(0)")
        .unwrap();
    let transaction = connection.transaction().unwrap();
    transaction
        .execute("UPDATE organ_state SET spent=1", [])
        .unwrap();
    assert_eq!(
        transaction.transaction_state(Some("main")).unwrap(),
        rusqlite::TransactionState::Write
    );
    assert_eq!(
        append(&transaction, &key(), &key().verifying_key(), &fields())
            .unwrap_err()
            .code,
        "aura:immediate-required"
    );
    transaction.rollback().unwrap();
    assert!(read_entries(&connection).unwrap().is_empty());
}

#[test]
fn certified_transaction_reopened_deferred_by_signer_is_refused() {
    struct ReopenSigner<'a>(&'a Connection);
    impl Signer for ReopenSigner<'_> {
        fn sign(&self, hash: &[u8; 32]) -> Result<[u8; 64], Error> {
            self.0.execute_batch("ROLLBACK; BEGIN DEFERRED").unwrap();
            Signer::sign(&key(), hash)
        }
    }
    let (_directory, mut connection) = database();
    let transaction = begin(&mut connection).unwrap();
    assert_eq!(
        append(
            &transaction,
            &ReopenSigner(&transaction),
            &key().verifying_key(),
            &fields()
        )
        .unwrap_err()
        .code,
        "aura:immediate-required"
    );
    assert!(!transaction.is_autocommit());
    assert!(read_entries(&transaction).unwrap().is_empty());
    transaction.rollback().unwrap();
}

#[test]
fn fresh_deferred_transaction_is_refused_without_signing() {
    struct Never;
    impl Signer for Never {
        fn sign(&self, _: &[u8; 32]) -> Result<[u8; 64], Error> {
            panic!("must refuse before signing")
        }
    }
    let (_directory, mut connection) = database();
    let transaction = connection.transaction().unwrap();
    assert_eq!(
        append(&transaction, &Never, &key().verifying_key(), &fields())
            .unwrap_err()
            .code,
        "aura:immediate-required"
    );
}

#[test]
fn immediate_begin_reports_busy_as_retryable() {
    let (directory, mut writer) = database();
    let mut contender = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&contender).unwrap();
    contender.busy_timeout(std::time::Duration::ZERO).unwrap();
    let winner = begin(&mut writer).unwrap();
    assert_eq!(begin(&mut contender).err().unwrap().code, "aura:busy");
    winner.rollback().unwrap();
    begin(&mut contender).unwrap().rollback().unwrap();
}

#[test]
fn append_tip_lookup_has_constant_sqlite_work_on_a_long_ledger() {
    let (_directory, mut connection) = database();
    // Storage-only filler isolates tip cost from signature/whole-history work.
    connection
        .execute_batch(&format!(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4096)
      INSERT INTO main.aura SELECT x,CASE WHEN x=1 THEN '{DOMAIN}' ELSE printf('%064x',x-1) END,
        printf('%064x',x),'',0,'boot.facts','supervisor','','fact','{{}}' FROM n ORDER BY x"
        ))
        .unwrap();
    let transaction = begin(&mut connection).unwrap();
    let steps = Arc::new(AtomicUsize::new(0));
    let counter = steps.clone();
    transaction
        .progress_handler(
            1,
            Some(move || counter.fetch_add(1, Ordering::Relaxed) >= 1000),
        )
        .unwrap();
    let entry = append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
    transaction
        .progress_handler(0, None::<fn() -> bool>)
        .unwrap();
    assert_eq!(entry.sequence, 4097);
    assert_eq!(entry.prev, format!("{:064x}", 4096));
    assert!(steps.load(Ordering::Relaxed) < 1000);
}

#[test]
fn an_organ_transaction_holding_the_write_lock_appends_through_write_locked() {
    let (_directory, mut connection) = database();
    connection
        .execute_batch("CREATE TABLE organ_state(spent INTEGER); INSERT INTO organ_state VALUES(0)")
        .unwrap();
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    transaction
        .execute("UPDATE organ_state SET spent=1", [])
        .unwrap();
    let locked = WriteLocked::new(&transaction).unwrap();
    assert_eq!(
        append(&locked, &key(), &key().verifying_key(), &fields())
            .unwrap()
            .sequence,
        1
    );
    transaction.commit().unwrap();
    assert_eq!(read_entries(&connection).unwrap().len(), 1);
}

#[test]
fn write_locked_refuses_transactions_without_the_write_lock() {
    let (directory, mut writer) = database();
    writer
        .execute_batch("CREATE TABLE organ_state(spent INTEGER); INSERT INTO organ_state VALUES(0)")
        .unwrap();
    let fresh = writer.transaction().unwrap();
    assert_eq!(
        WriteLocked::new(&fresh).unwrap_err().code,
        "aura:immediate-required"
    );
    fresh
        .query_row("SELECT spent FROM organ_state", [], |r| r.get::<_, i64>(0))
        .unwrap();
    assert_eq!(
        WriteLocked::new(&fresh).unwrap_err().code,
        "aura:immediate-required"
    );
    fresh.rollback().unwrap();
    // A stale snapshot can never reach the write lock, so it can never be certified.
    let mut stale = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&stale).unwrap();
    let reader = stale.transaction().unwrap();
    reader
        .query_row("SELECT spent FROM organ_state", [], |r| r.get::<_, i64>(0))
        .unwrap();
    let winner = begin(&mut writer).unwrap();
    append(&winner, &key(), &key().verifying_key(), &fields()).unwrap();
    winner.commit().unwrap();
    assert!(reader
        .execute("UPDATE organ_state SET spent=2", [])
        .is_err());
    assert_eq!(
        WriteLocked::new(&reader).unwrap_err().code,
        "aura:immediate-required"
    );
}

#[test]
fn write_locked_refuses_attached_databases_and_non_wal_connections() {
    let directory = tempfile::tempdir().unwrap();
    // Initialized connections already refuse ATTACH; this guards one whose authorizer was replaced.
    let mut attached = Connection::open(directory.path().join("wal.db")).unwrap();
    attached
        .execute_batch(&format!(
            "PRAGMA journal_mode=WAL; CREATE TABLE t(x); ATTACH DATABASE '{}' AS organ",
            directory.path().join("organ.db").display()
        ))
        .unwrap();
    let transaction = attached
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute("INSERT INTO t VALUES(1)", []).unwrap();
    assert_eq!(
        WriteLocked::new(&transaction).unwrap_err().code,
        "aura:attached-database"
    );
    transaction.rollback().unwrap();
    // A connection that never ran initialize (rollback journal) is refused.
    let mut raw = Connection::open(directory.path().join("raw.db")).unwrap();
    raw.execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE t(x)")
        .unwrap();
    let transaction = raw
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute("INSERT INTO t VALUES(1)", []).unwrap();
    assert_eq!(
        WriteLocked::new(&transaction).unwrap_err().code,
        "aura:not-initialized"
    );
}
