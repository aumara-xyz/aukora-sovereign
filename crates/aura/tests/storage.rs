use aura::{
    append, entry_hash, export, initialize, read_entries, require_terminal, walk,
    walk_against_prefix, Entry, Error, NewEntry, Signer, Value, DOMAIN, MAX_SAFE_INTEGER,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, SigningKey};
use rusqlite::hooks::{AuthContext, Authorization};
use rusqlite::{params, Connection};

fn database() -> (tempfile::TempDir, Connection) {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connection = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&connection).unwrap();
    (directory, connection)
}
// Deliberately isolate the SQL trigger/constraint fallback from the authorizer.
fn clear_sql_guard(connection: &Connection) {
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
}

fn fields() -> NewEntry {
    NewEntry {
        at: 1700000000000,
        kind: "boot.facts".into(),
        actor: "supervisor".into(),
        op: String::new(),
        phase: "fact".into(),
        body: Value::Object(vec![
            ("z".into(), Value::Integer(1)),
            ("a".into(), Value::String("facts".into())),
        ]),
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[19; 32])
}

fn fixture() -> (tempfile::TempDir, Connection, Vec<Entry>) {
    let (directory, mut connection) = database();
    let transaction = aura::begin(&mut connection).unwrap();
    let entries = (0..4)
        .map(|_| append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap())
        .collect();
    transaction.commit().unwrap();
    (directory, connection, entries)
}

fn insert(
    connection: &Connection,
    seq: i64,
    prev: &str,
    hash: &str,
    operation: (&str, &str),
    body: &str,
    conflict: &str,
) -> rusqlite::Result<usize> {
    connection.execute(&format!("INSERT {conflict} INTO aura(seq,prev,hash,sig,at,kind,actor,op,phase,body) VALUES (?1,?2,?3,'',0,'boot.facts','supervisor',?4,?5,?6)"), params![seq,prev,hash,operation.0,operation.1,body])
}

#[test]
fn wal_full_and_file_backing_are_required() {
    let (_directory, connection) = database();
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    assert_eq!(synchronous, 2);
    assert_eq!(
        initialize(&Connection::open_in_memory().unwrap())
            .unwrap_err()
            .code,
        "aura:wal-unavailable"
    );
}
#[test]
fn caller_transaction_owns_atomic_commit_and_rollback_without_gaps() {
    let (directory, mut connection) = database();
    connection
        .execute_batch("CREATE TABLE gate_state (spent INTEGER); INSERT INTO gate_state VALUES(0)")
        .unwrap();
    let observer = Connection::open(directory.path().join("aura.db")).unwrap();
    observer.busy_timeout(std::time::Duration::ZERO).unwrap();
    {
        let transaction = aura::begin(&mut connection).unwrap();
        transaction
            .execute("UPDATE gate_state SET spent=1", [])
            .unwrap();
        let entry = append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
        assert_eq!(entry.sequence, 1);
        assert_eq!(entry.prev, DOMAIN);
        assert!(read_entries(&observer).unwrap().is_empty());
        assert!(observer.execute_batch("BEGIN IMMEDIATE").is_err());
        transaction.rollback().unwrap();
    }
    assert!(read_entries(&connection).unwrap().is_empty());
    assert_eq!(
        connection
            .query_row("SELECT spent FROM gate_state", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let transaction = aura::begin(&mut connection).unwrap();
    transaction
        .execute("UPDATE gate_state SET spent=1", [])
        .unwrap();
    let first = append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
    let second = append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
    assert_eq!((first.sequence, second.sequence), (1, 2));
    assert_eq!(second.prev, first.hash);
    transaction.commit().unwrap();
    assert_eq!(read_entries(&observer).unwrap(), vec![first, second]);
    assert_eq!(
        observer
            .query_row("SELECT spent FROM gate_state", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn update_is_refused() {
    let (_directory, connection, entries) = fixture();
    clear_sql_guard(&connection);
    let failure = connection
        .execute("UPDATE aura SET actor='attacker' WHERE seq=2", [])
        .unwrap_err();
    assert!(failure.to_string().contains("aura:update-forbidden"));
    assert_eq!(read_entries(&connection).unwrap(), entries);
}

#[test]
fn delete_is_refused() {
    let (_directory, connection, entries) = fixture();
    clear_sql_guard(&connection);
    let failure = connection
        .execute("DELETE FROM aura WHERE seq=2", [])
        .unwrap_err();
    assert!(failure.to_string().contains("aura:delete-forbidden"));
    assert_eq!(read_entries(&connection).unwrap(), entries);
}

#[test]
fn inserts_require_next_sequence_correct_link_and_no_replacement() {
    let (_directory, connection, entries) = fixture();
    clear_sql_guard(&connection);
    let h = "ab".repeat(32);
    assert!(
        insert(&connection, 6, &entries[3].hash, &h, ("", "fact"), "{}", "")
            .unwrap_err()
            .to_string()
            .contains("aura:sequence-gap")
    );
    assert!(insert(&connection, 5, DOMAIN, &h, ("", "fact"), "{}", "")
        .unwrap_err()
        .to_string()
        .contains("aura:broken-link"));
    connection
        .pragma_update(None, "recursive_triggers", false)
        .unwrap();
    assert!(insert(
        &connection,
        5,
        &entries[3].hash,
        &entries[0].hash,
        ("", "fact"),
        "{}",
        "OR REPLACE"
    )
    .unwrap_err()
    .to_string()
    .contains("aura:duplicate-hash"));
    assert!(insert(
        &connection,
        2,
        &entries[0].hash,
        &h,
        ("", "fact"),
        "{}",
        "OR REPLACE"
    )
    .is_err());
    assert_eq!(read_entries(&connection).unwrap(), entries);
}

#[test]
fn operation_requires_exactly_one_terminal_and_replace_cannot_erase_it() {
    let (_directory, mut connection) = database();
    clear_sql_guard(&connection);
    let mut fields = fields();
    fields.op = "operation-1".into();
    fields.phase = "intent".into();
    let transaction = aura::begin(&mut connection).unwrap();
    append(&transaction, &key(), &key().verifying_key(), &fields).unwrap();
    assert_eq!(
        require_terminal(&transaction, &fields.op).unwrap_err().code,
        "aura:terminal-count"
    );
    fields.phase = "terminal".into();
    let terminal = append(&transaction, &key(), &key().verifying_key(), &fields).unwrap();
    require_terminal(&transaction, &fields.op).unwrap();
    assert!(append(&transaction, &key(), &key().verifying_key(), &fields).is_err());
    transaction
        .pragma_update(None, "recursive_triggers", false)
        .unwrap();
    assert!(insert(
        &transaction,
        3,
        &terminal.hash,
        &"ab".repeat(32),
        (&fields.op, "terminal"),
        "{}",
        "OR REPLACE"
    )
    .unwrap_err()
    .to_string()
    .contains("aura:duplicate-terminal"));
    transaction.commit().unwrap();
    assert!(require_terminal(&connection, "").is_err());
    assert!(require_terminal(&connection, "absent").is_err());
    assert_eq!(read_entries(&connection).unwrap().len(), 2);
}

#[test]
fn invalid_fields_are_refused_before_insertion() {
    let (_directory, mut connection) = database();
    let transaction = aura::begin(&mut connection).unwrap();
    let mut cases = Vec::new();
    let mut value = fields();
    value.kind = "new.kind".into();
    cases.push((value, "aura:unknown-kind"));
    let mut value = fields();
    value.phase = "success".into();
    cases.push((value, "aura:invalid-phase"));
    let mut value = fields();
    value.phase = "terminal".into();
    cases.push((value, "aura:missing-operation"));
    let mut value = fields();
    value.at = MAX_SAFE_INTEGER as i64 + 1;
    cases.push((value, "aura:invalid-time"));
    let mut value = fields();
    value.body = Value::Object(vec![
        ("duplicate".into(), Value::Null),
        ("duplicate".into(), Value::Null),
    ]);
    cases.push((value, "aura:invalid-body"));
    for (value, code) in cases {
        assert_eq!(
            append(&transaction, &key(), &key().verifying_key(), &value)
                .unwrap_err()
                .code,
            code
        );
    }
    assert!(read_entries(&transaction).unwrap().is_empty());
    assert!(entry_hash(DOMAIN, &fields(), 0).is_err());
    assert!(entry_hash(DOMAIN, &fields(), MAX_SAFE_INTEGER + 1).is_err());
    assert_eq!(
        append(&transaction, &key(), &key().verifying_key(), &fields())
            .unwrap()
            .sequence,
        1
    );
}

#[test]
fn signing_failure_does_not_insert_or_consume_sequence() {
    struct Refuse;
    impl Signer for Refuse {
        fn sign(&self, _: &[u8; 32]) -> Result<[u8; 64], Error> {
            Err(Error::new("aura:test-signing"))
        }
    }
    let (_directory, mut connection) = database();
    let transaction = aura::begin(&mut connection).unwrap();
    assert_eq!(
        append(&transaction, &Refuse, &key().verifying_key(), &fields())
            .unwrap_err()
            .code,
        "aura:test-signing"
    );
    assert!(read_entries(&transaction).unwrap().is_empty());
    let entry = append(&transaction, &key(), &key().verifying_key(), &fields()).unwrap();
    assert_eq!(entry.sequence, 1);
    let hash = hex::decode(&entry.hash).unwrap();
    let signature = Signature::from_slice(&STANDARD.decode(&entry.sig).unwrap()).unwrap();
    key()
        .verifying_key()
        .verify_strict(&hash, &signature)
        .unwrap();
    assert!(key()
        .verifying_key()
        .verify_strict(entry.hash.as_bytes(), &signature)
        .is_err());
}

#[test]
fn walk_names_first_sequence_and_authenticates_every_hash_and_signature() {
    let (_directory, _connection, entries) = fixture();
    walk(&entries, &key().verifying_key(), None).unwrap();
    let mut broken = entries.clone();
    broken[1].sequence = 8;
    assert_eq!(
        walk(&broken, &key().verifying_key(), None).unwrap_err(),
        Error {
            code: "aura:sequence-gap",
            sequence: Some(2)
        }
    );
    let mut broken = entries.clone();
    broken[1].prev = DOMAIN.into();
    assert_eq!(
        walk(&broken, &key().verifying_key(), None)
            .unwrap_err()
            .code,
        "aura:broken-link"
    );
    let mut broken = entries.clone();
    broken[1].body = Value::Object(vec![("tampered".into(), Value::Bool(true))]);
    assert_eq!(
        walk(&broken, &key().verifying_key(), None).unwrap_err(),
        Error {
            code: "aura:hash-mismatch",
            sequence: Some(2)
        }
    );
    for hash in [
        entries[1].hash.to_uppercase(),
        "ff".repeat(32),
        "AA".repeat(32),
        "a".repeat(63),
        "gg".repeat(32),
    ] {
        let mut broken = entries.clone();
        broken[1].hash = hash;
        assert_eq!(
            walk(&broken, &key().verifying_key(), None)
                .unwrap_err()
                .sequence,
            Some(2)
        );
    }
    for signature in [
        entries[1].sig.trim_end_matches('=').to_string(),
        STANDARD.encode([0; 64]),
        "not base64".into(),
        "".into(),
        entries[0].sig.clone(),
    ] {
        let mut broken = entries.clone();
        broken[1].sig = signature;
        assert_eq!(
            walk(&broken, &key().verifying_key(), None).unwrap_err(),
            Error {
                code: "aura:invalid-signature",
                sequence: Some(2)
            }
        );
    }
    assert_eq!(
        walk(
            &entries,
            &SigningKey::from_bytes(&[22; 32]).verifying_key(),
            None
        )
        .unwrap_err()
        .sequence,
        Some(1)
    );
    let mut terminal = entries[0].clone();
    terminal.op = "op".into();
    terminal.phase = "terminal".into();
    let mut duplicate = vec![terminal.clone(), terminal];
    resign(&mut duplicate);
    assert_eq!(
        walk(&duplicate, &key().verifying_key(), None).unwrap_err(),
        Error {
            code: "aura:duplicate-terminal",
            sequence: Some(2)
        }
    );
}

fn resign(entries: &mut [Entry]) {
    let mut prev = DOMAIN.to_string();
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.sequence = index as u64 + 1;
        entry.prev = prev;
        let hash = entry_hash(&entry.prev, &entry.fields(), entry.sequence).unwrap();
        entry.hash = hex::encode(hash);
        entry.sig = STANDARD.encode(Signer::sign(&key(), &hash).unwrap());
        prev = entry.hash.clone();
    }
}

#[test]
fn retained_head_detects_rollback_and_prefix_localizes_a_resigned_rewrite() {
    let (_directory, _connection, entries) = fixture();
    let (head, presented) = export(&entries, &key().verifying_key(), 4).unwrap();
    assert_eq!(presented.tree_size, 4);
    walk(&entries, &key().verifying_key(), Some(&head)).unwrap();
    assert_eq!(
        walk(&entries[..2], &key().verifying_key(), Some(&head)).unwrap_err(),
        Error {
            code: "aura:shorter-than-retained",
            sequence: Some(3)
        }
    );
    let mut rewrite = entries.clone();
    rewrite[1].body = Value::Object(vec![("rewrite".into(), Value::Bool(true))]);
    resign(&mut rewrite);
    assert_eq!(
        walk(&rewrite, &key().verifying_key(), Some(&head))
            .unwrap_err()
            .code,
        "aura:retained-head-mismatch"
    );
    assert_eq!(
        walk_against_prefix(&rewrite, &entries, &key().verifying_key()).unwrap_err(),
        Error {
            code: "aura:retained-entry-differs",
            sequence: Some(2)
        }
    );
    assert_eq!(
        walk_against_prefix(&entries[..2], &entries, &key().verifying_key())
            .unwrap_err()
            .sequence,
        Some(3)
    );
    walk_against_prefix(&entries, &entries[..2], &key().verifying_key()).unwrap();
    let mut damaged = entries.clone();
    damaged[0].body = Value::Bool(false);
    assert_eq!(
        walk_against_prefix(&damaged, &entries, &key().verifying_key())
            .unwrap_err()
            .sequence,
        Some(1)
    );
    assert!(export(&damaged, &key().verifying_key(), 2).is_err());
    for field in ["schema", "convention", "size", "zero", "root", "hash"] {
        let mut invalid = head.clone();
        match field {
            "schema" => invalid.schema = "other".into(),
            "convention" => invalid.leaf_convention = "other".into(),
            "size" => invalid.tree_size = 3,
            "zero" => {
                invalid.sequence = 0;
                invalid.tree_size = 0
            }
            "root" => invalid.root = "00".repeat(32),
            _ => invalid.hash = "00".repeat(32),
        }
        assert!(
            walk(&entries, &key().verifying_key(), Some(&invalid)).is_err(),
            "{field}"
        );
    }
}

#[test]
fn database_body_is_strict_and_canonical_on_read() {
    for body in [
        "{\"a\":1,\"a\":2}",
        "1.0",
        "-0",
        "{ \"a\":1}",
        "{\"z\":1,\"a\":2}",
    ] {
        let (_directory, connection) = database();
        insert(
            &connection,
            1,
            DOMAIN,
            &"ab".repeat(32),
            ("", "fact"),
            body,
            "",
        )
        .unwrap();
        assert_eq!(read_entries(&connection).unwrap_err().sequence, Some(1));
    }
}

#[test]
fn authenticated_walk_refuses_preexisting_sequence_gap() {
    let (_directory, connection, _entries) = fixture();
    clear_sql_guard(&connection);
    connection
        .execute_batch("DROP TRIGGER aura_no_delete; DELETE FROM aura WHERE seq=2")
        .unwrap();
    assert_eq!(
        walk(
            &read_entries(&connection).unwrap(),
            &key().verifying_key(),
            None
        )
        .unwrap_err()
        .code,
        "aura:sequence-gap"
    );
}

#[test]
fn table_constraints_refuse_invalid_rows_even_without_insert_trigger() {
    for (column, value) in [
        ("seq", "0"),
        ("seq", "9007199254740992"),
        ("hash", "'short'"),
        (
            "hash",
            "'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg'",
        ),
        ("at", "9007199254740992"),
        ("at", "1.5"),
        ("kind", "'invented'"),
        ("phase", "'success'"),
    ] {
        let (_directory, connection) = database();
        clear_sql_guard(&connection);
        connection
            .execute_batch("DROP TRIGGER aura_next_sequence")
            .unwrap();
        let mut columns = vec![
            ("seq", "1"),
            ("prev", "'aukora:aura-record:v1'"),
            (
                "hash",
                "'abababababababababababababababababababababababababababababababab'",
            ),
            ("sig", "''"),
            ("at", "0"),
            ("kind", "'boot.facts'"),
            ("actor", "'supervisor'"),
            ("op", "''"),
            ("phase", "'fact'"),
            ("body", "'{}'"),
        ];
        columns
            .iter_mut()
            .find(|(name, _)| *name == column)
            .unwrap()
            .1 = value;
        let values = columns
            .iter()
            .map(|(_, value)| *value)
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            connection
                .execute(&format!("INSERT INTO aura VALUES ({values})"), [])
                .is_err(),
            "{column}={value}"
        );
    }
    let (_directory, connection) = database();
    clear_sql_guard(&connection);
    connection
        .execute_batch("DROP TRIGGER aura_next_sequence")
        .unwrap();
    assert!(insert(
        &connection,
        1,
        DOMAIN,
        &"ab".repeat(32),
        ("", "terminal"),
        "{}",
        ""
    )
    .is_err());
    insert(
        &connection,
        1,
        DOMAIN,
        &"ab".repeat(32),
        ("op", "terminal"),
        "{}",
        "",
    )
    .unwrap();
    assert!(insert(
        &connection,
        2,
        DOMAIN,
        &"cd".repeat(32),
        ("op", "terminal"),
        "{}",
        ""
    )
    .is_err());
    assert!(insert(
        &connection,
        2,
        DOMAIN,
        &"ab".repeat(32),
        ("different", "fact"),
        "{}",
        ""
    )
    .is_err());
}

#[test]
fn initialize_refuses_existing_noop_triggers_and_incompatible_schema() {
    for name in ["aura_no_update", "aura_no_delete", "aura_next_sequence"] {
        let (_directory, connection) = database();
        initialize(&connection).unwrap();
        clear_sql_guard(&connection);
        connection.execute_batch(&format!("DROP TRIGGER {name}; CREATE TRIGGER {name} BEFORE INSERT ON aura BEGIN SELECT 1; END")).unwrap();
        assert_eq!(
            initialize(&connection).unwrap_err().code,
            "aura:schema-mismatch"
        );
    }
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connection = Connection::open(directory.path().join("aura.db")).unwrap();
    connection
        .execute_batch("CREATE TABLE aura(seq INTEGER PRIMARY KEY,op TEXT,phase TEXT)")
        .unwrap();
    assert_eq!(
        initialize(&connection).unwrap_err().code,
        "aura:schema-mismatch"
    );
}
