use std::time::{Duration, Instant};

use aura::{
    append, begin, entry_hash, export, initialize_with_report, read_entries, walk, walk_database,
    NewEntry, Signer, Value, DOMAIN,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use rusqlite::config::DbConfig;
use rusqlite::hooks::{AuthContext, Authorization};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection, ErrorCode};

const V1: &str = include_str!("../src/schema_v1.sql");
const V2: &str = include_str!("../src/schema.sql");
const COLUMNS: &str = "seq,prev,hash,sig,at,kind,actor,op,phase,body";
const V1_KINDS: &[&str] = &[
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
];

fn key() -> SigningKey {
    SigningKey::from_bytes(&[52; 32])
}

fn database(schema: &str) -> (tempfile::TempDir, Connection) {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connection = Connection::open(directory.path().join("migration.db")).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL")
        .unwrap();
    connection.execute_batch(schema).unwrap();
    (directory, connection)
}

fn query_values(connection: &Connection, sql: &str, columns: usize) -> Vec<Vec<SqlValue>> {
    let mut statement = connection.prepare(sql).unwrap();
    let mapped = statement
        .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
        .unwrap();
    mapped.collect::<rusqlite::Result<_>>().unwrap()
}

fn rows(connection: &Connection) -> Vec<Vec<SqlValue>> {
    query_values(
        connection,
        &format!("SELECT {COLUMNS} FROM main.aura ORDER BY seq"),
        10,
    )
}

fn schema(connection: &Connection) -> Vec<Vec<SqlValue>> {
    query_values(
        connection,
        "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name,tbl_name,sql",
        4,
    )
}

fn expected_schema(sql: &str) -> Vec<Vec<SqlValue>> {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(sql).unwrap();
    schema(&connection)
}

fn aura_schema(connection: &Connection) -> Vec<Vec<SqlValue>> {
    query_values(
        connection,
        "SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name='aura' OR tbl_name='aura' ORDER BY type,name,tbl_name,sql",
        4,
    )
}

fn schema_version(connection: &Connection) -> i64 {
    connection
        .query_row("PRAGMA schema_version", [], |row| row.get(0))
        .unwrap()
}

fn nostr_binding() -> NewEntry {
    NewEntry {
        at: 1_760_000_000_000,
        kind: "nostr.bind".into(),
        actor: "supervisor".into(),
        op: String::new(),
        phase: "fact".into(),
        body: Value::Object(vec![("pubkey".into(), Value::String("d".repeat(64)))]),
    }
}

fn append_nostr(connection: &mut Connection) {
    let transaction = begin(connection).unwrap();
    let entry = append(
        &transaction,
        &key(),
        &key().verifying_key(),
        &nostr_binding(),
    )
    .unwrap();
    assert_eq!(entry.kind, "nostr.bind");
    transaction.commit().unwrap();
}

fn seed_signed_v1(connection: &mut Connection) {
    let transaction = connection.transaction().unwrap();
    let mut previous = DOMAIN.to_owned();
    for (kind_index, kind) in V1_KINDS.iter().enumerate() {
        for (phase_index, phase) in ["intent", "settle", "terminal", "fact"].iter().enumerate() {
            let sequence = (kind_index * 4 + phase_index + 1) as u64;
            let fields = NewEntry {
                at: sequence as i64 * 1000 - 40_000,
                kind: (*kind).into(),
                actor: format!("supervisor 雪\0{kind_index}"),
                op: if *phase == "fact" {
                    String::new()
                } else {
                    format!("operation-{kind_index}")
                },
                phase: (*phase).into(),
                body: Value::Object(vec![
                    ("kind".into(), Value::String((*kind).into())),
                    ("sequence".into(), Value::Integer(sequence as i64)),
                    ("text".into(), Value::String("雪\0\n\"\\".into())),
                ]),
            };
            let hash = entry_hash(&previous, &fields, sequence).unwrap();
            let signature = STANDARD.encode(Signer::sign(&key(), &hash).unwrap());
            let hash = hex::encode(hash);
            let body = String::from_utf8(canon::canonical_json(&fields.body).unwrap()).unwrap();
            transaction
                .execute(
                    "INSERT INTO main.aura(seq,prev,hash,sig,at,kind,actor,op,phase,body) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![sequence as i64, previous, hash, signature, fields.at, fields.kind, fields.actor, fields.op, fields.phase, body],
                )
                .unwrap();
            previous = hash;
        }
    }
    transaction.commit().unwrap();
}

fn migrated_database() -> (tempfile::TempDir, Connection) {
    let (directory, mut connection) = database(V1);
    seed_signed_v1(&mut connection);
    assert_eq!(
        initialize_with_report(&connection).unwrap().unwrap().rows,
        88
    );
    (directory, connection)
}

fn clear_authorizer(connection: &Connection) {
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
}

fn raw_insert(
    connection: &Connection,
    sequence: i64,
    previous: &str,
    hash: &str,
    operation: &str,
    phase: &str,
) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO main.aura(seq,prev,hash,sig,at,kind,actor,op,phase,body) VALUES(?1,?2,?3,'',0,'boot.facts','supervisor',?4,?5,'{}')",
        params![sequence, previous, hash, operation, phase],
    )
}

#[test]
fn antibody_schema_v2_fresh_accepts_signed_nostr_bind() {
    let (_directory, mut connection) = database("");
    assert_eq!(initialize_with_report(&connection).unwrap(), None);
    assert_eq!(schema(&connection), expected_schema(V2));
    assert_eq!(
        V2,
        V1.replace(
            "'sandbox.start','sandbox.exit'",
            "'sandbox.start','sandbox.exit','nostr.bind'"
        )
    );
    assert_eq!(aura::KINDS.last(), Some(&"nostr.bind"));
    append_nostr(&mut connection);
    let entries = read_entries(&connection).unwrap();
    assert_eq!(entries.len(), 1);
    walk(&entries, &key().verifying_key(), None).unwrap();
    walk_database(&connection, &key().verifying_key(), None).unwrap();
}

#[test]
fn antibody_schema_v1_migration_preserves_every_signed_column() {
    let (_directory, mut connection) = database(V1);
    seed_signed_v1(&mut connection);
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE organ_parent(id INTEGER PRIMARY KEY, state BLOB NOT NULL);
             CREATE TABLE organ_child(id INTEGER REFERENCES organ_parent(id));
             INSERT INTO organ_parent VALUES(7,x'0001ff');
             INSERT INTO organ_child VALUES(7);",
        )
        .unwrap();
    let organ_schema_before: Vec<_> = schema(&connection)
        .into_iter()
        .filter(|object| object[2] != SqlValue::Text("aura".into()))
        .collect();
    let organ_before = query_values(
        &connection,
        "SELECT organ_parent.id,state,organ_child.id FROM organ_parent JOIN organ_child USING(id)",
        3,
    );
    let before = rows(&connection);
    let entries_before = read_entries(&connection).unwrap();
    let (retained, _) = export(&entries_before, &key().verifying_key(), 64).unwrap();
    walk_database(&connection, &key().verifying_key(), Some(&retained)).unwrap();
    let report = initialize_with_report(&connection).unwrap().unwrap();
    assert_eq!(report.rows, before.len() as u64);
    assert_eq!(aura_schema(&connection), expected_schema(V2));
    assert_eq!(rows(&connection), before);
    assert_eq!(
        connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        schema(&connection)
            .into_iter()
            .filter(|object| object[2] != SqlValue::Text("aura".into()))
            .collect::<Vec<_>>(),
        organ_schema_before
    );
    assert_eq!(
        query_values(
            &connection,
            "SELECT organ_parent.id,state,organ_child.id FROM organ_parent JOIN organ_child USING(id)",
            3,
        ),
        organ_before
    );
    let entries_after = read_entries(&connection).unwrap();
    assert_eq!(entries_after, entries_before);
    walk(&entries_after, &key().verifying_key(), Some(&retained)).unwrap();
    walk_database(&connection, &key().verifying_key(), Some(&retained)).unwrap();
    append_nostr(&mut connection);
    let entries = read_entries(&connection).unwrap();
    assert_eq!(&entries[..entries_before.len()], &entries_before);
    assert_eq!(entries.len(), 89);
    walk(&entries, &key().verifying_key(), Some(&retained)).unwrap();
    walk_database(&connection, &key().verifying_key(), Some(&retained)).unwrap();
}

#[test]
fn antibody_schema_v2_reopen_does_not_migrate_again() {
    let (directory, connection) = migrated_database();
    let before = rows(&connection);
    let schema_before = schema(&connection);
    let version_before = schema_version(&connection);
    drop(connection);
    let connection = Connection::open(directory.path().join("migration.db")).unwrap();
    assert_eq!(initialize_with_report(&connection).unwrap(), None);
    assert_eq!(schema_version(&connection), version_before);
    assert_eq!(schema(&connection), schema_before);
    assert_eq!(rows(&connection), before);
    assert_eq!(initialize_with_report(&connection).unwrap(), None);
    assert_eq!(schema_version(&connection), version_before);
}

#[test]
fn antibody_schema_v1_lookalikes_are_refused_without_rebuild() {
    let changed_check = V1.replace(
        "'sandbox.start','sandbox.exit'",
        "'sandbox.start','sandbox.exit','unapproved.fixture'",
    );
    for (name, sql, modification) in [
        (
            "extra trigger",
            V1,
            "CREATE TRIGGER extra BEFORE INSERT ON aura BEGIN SELECT 1; END",
        ),
        ("changed CHECK", changed_check.as_str(), ""),
        ("missing index", V1, "DROP INDEX aura_one_terminal"),
    ] {
        let (directory, mut connection) = database(sql);
        seed_signed_v1(&mut connection);
        connection.execute_batch(modification).unwrap();
        let rows_before = rows(&connection);
        let schema_before = schema(&connection);
        let version_before = schema_version(&connection);
        assert_eq!(
            initialize_with_report(&connection).unwrap_err().code,
            "aura:schema-mismatch",
            "{name}"
        );
        assert_eq!(schema(&connection), schema_before, "{name}");
        assert_eq!(schema_version(&connection), version_before, "{name}");
        assert_eq!(rows(&connection), rows_before, "{name}");
        drop(connection);
        let connection = Connection::open(directory.path().join("migration.db")).unwrap();
        assert_eq!(schema(&connection), schema_before, "{name}");
        assert_eq!(rows(&connection), rows_before, "{name}");
    }
}

#[test]
fn antibody_schema_v1_temp_aura_objects_are_refused_without_rebuild() {
    for sql in [
        "CREATE TEMP TABLE aura AS SELECT * FROM main.aura",
        "CREATE TEMP VIEW shadow AS SELECT * FROM main.aura",
        "CREATE TEMP TRIGGER extra BEFORE INSERT ON main.aura BEGIN SELECT RAISE(IGNORE); END",
    ] {
        let (_directory, mut connection) = database(V1);
        seed_signed_v1(&mut connection);
        let rows_before = rows(&connection);
        let schema_before = schema(&connection);
        let version_before = schema_version(&connection);
        connection.execute_batch(sql).unwrap();
        let temp_before = query_values(
            &connection,
            "SELECT type,name,tbl_name,sql FROM temp.sqlite_schema ORDER BY type,name,tbl_name,sql",
            4,
        );
        assert_eq!(
            initialize_with_report(&connection).unwrap_err().code,
            "aura:temp-schema-mismatch",
            "{sql}"
        );
        assert_eq!(schema(&connection), schema_before, "{sql}");
        assert_eq!(schema_version(&connection), version_before, "{sql}");
        assert_eq!(rows(&connection), rows_before, "{sql}");
        assert_eq!(
            query_values(
                &connection,
                "SELECT type,name,tbl_name,sql FROM temp.sqlite_schema ORDER BY type,name,tbl_name,sql",
                4,
            ),
            temp_before,
            "{sql}"
        );
    }
}

#[test]
fn antibody_schema_migrated_update_and_delete_triggers_still_refuse() {
    let (_directory, connection) = migrated_database();
    clear_authorizer(&connection);
    let before = rows(&connection);
    for (sql, refusal) in [
        (
            "UPDATE aura SET actor='attacker' WHERE seq=40",
            "aura:update-forbidden",
        ),
        ("DELETE FROM aura WHERE seq=40", "aura:delete-forbidden"),
    ] {
        assert!(connection
            .execute(sql, [])
            .unwrap_err()
            .to_string()
            .contains(refusal));
        assert_eq!(rows(&connection), before);
    }
}

#[test]
fn antibody_schema_migrated_insert_guards_still_refuse() {
    let (_directory, connection) = migrated_database();
    clear_authorizer(&connection);
    let before = rows(&connection);
    let tail: String = connection
        .query_row(
            "SELECT hash FROM aura ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let first: String = connection
        .query_row("SELECT hash FROM aura WHERE seq=1", [], |row| row.get(0))
        .unwrap();
    let fresh_hash = "f1".repeat(32);
    for (sequence, previous, hash, operation, phase, refusal) in [
        (
            90,
            tail.as_str(),
            fresh_hash.as_str(),
            "",
            "fact",
            "aura:sequence-gap",
        ),
        (
            89,
            DOMAIN,
            fresh_hash.as_str(),
            "",
            "fact",
            "aura:broken-link",
        ),
        (
            89,
            tail.as_str(),
            first.as_str(),
            "",
            "fact",
            "aura:duplicate-hash",
        ),
        (
            89,
            tail.as_str(),
            fresh_hash.as_str(),
            "operation-0",
            "terminal",
            "aura:duplicate-terminal",
        ),
    ] {
        assert!(
            raw_insert(&connection, sequence, previous, hash, operation, phase)
                .unwrap_err()
                .to_string()
                .contains(refusal)
        );
        assert_eq!(rows(&connection), before);
    }
}

#[test]
fn antibody_schema_migrated_terminal_index_still_refuses_without_trigger() {
    let (_directory, connection) = migrated_database();
    clear_authorizer(&connection);
    connection
        .execute_batch("DROP TRIGGER aura_next_sequence")
        .unwrap();
    let before = rows(&connection);
    let failure = raw_insert(
        &connection,
        89,
        "",
        &"f2".repeat(32),
        "operation-0",
        "terminal",
    )
    .unwrap_err();
    assert!(failure
        .to_string()
        .contains("UNIQUE constraint failed: aura.op"));
    assert_eq!(rows(&connection), before);
}

#[test]
fn antibody_schema_migrated_authorizer_still_denies_reconfiguration() {
    let (_directory, connection) = migrated_database();
    let before = rows(&connection);
    for sql in [
        "DROP TRIGGER aura_no_update",
        "DROP TRIGGER aura_no_delete",
        "DROP INDEX aura_one_terminal",
        "DROP TABLE aura",
        "ALTER TABLE aura RENAME TO discarded",
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
    ] {
        let error = connection.execute_batch(sql).unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(ErrorCode::AuthorizationForStatementDenied),
            "{sql}: {error}"
        );
    }
    assert_eq!(rows(&connection), before);
    assert_eq!(schema(&connection), expected_schema(V2));
}

#[test]
fn antibody_schema_migrated_defensive_still_blocks_schema_writes() {
    let (_directory, connection) = migrated_database();
    assert!(connection
        .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .unwrap());
    clear_authorizer(&connection);
    connection
        .execute_batch("PRAGMA writable_schema=ON")
        .unwrap();
    assert!(connection
        .execute("DELETE FROM sqlite_schema WHERE name='aura_no_delete'", [])
        .is_err());
    assert_eq!(schema(&connection), expected_schema(V2));
}

#[test]
fn antibody_schema_v1_large_migration_is_exact_and_timed() {
    let (_directory, connection) = database(V1);
    // Storage-only rows isolate migration time from signing and verification.
    connection
        .execute_batch(&format!(
            "BEGIN IMMEDIATE;
             WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100000)
             INSERT INTO main.aura
             SELECT x,CASE WHEN x=1 THEN '{DOMAIN}' ELSE printf('%064x',x-1) END,
                    printf('%064x',x),'',x-50000,'boot.facts','large fixture','','fact',
                    printf('{{\"sequence\":%d}}',x) FROM n ORDER BY x;
             CREATE TABLE expected_history AS SELECT * FROM main.aura;
             COMMIT;"
        ))
        .unwrap();
    let started = Instant::now();
    let report = initialize_with_report(&connection).unwrap().unwrap();
    let elapsed = started.elapsed();
    eprintln!("aura schema v1 to v2, {} rows: {elapsed:.3?}", report.rows);
    assert_eq!(report.rows, 100_000);
    assert!(
        elapsed < Duration::from_secs(60),
        "migration took {elapsed:?}"
    );
    let mut expected = connection
        .prepare(&format!(
            "SELECT {COLUMNS} FROM expected_history ORDER BY seq"
        ))
        .unwrap();
    let mut actual = connection
        .prepare(&format!("SELECT {COLUMNS} FROM main.aura ORDER BY seq"))
        .unwrap();
    let mut expected_rows = expected.query([]).unwrap();
    let mut actual_rows = actual.query([]).unwrap();
    let mut count = 0;
    loop {
        match (expected_rows.next().unwrap(), actual_rows.next().unwrap()) {
            (Some(expected), Some(actual)) => {
                count += 1;
                for column in 0..10 {
                    assert_eq!(
                        actual.get_ref(column).unwrap(),
                        expected.get_ref(column).unwrap(),
                        "sequence {count}, column {column}"
                    );
                }
            }
            (None, None) => break,
            _ => panic!("migration changed row count after sequence {count}"),
        }
    }
    assert_eq!(count, 100_000);
}
