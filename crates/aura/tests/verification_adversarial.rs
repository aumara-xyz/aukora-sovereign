use aura::{
    entry_hash, export, export_database, initialize, read_entries, require_terminal, walk,
    walk_against_prefix, walk_database, Entry, Error, NewEntry, Signer, Value, DOMAIN,
    MAX_BUFFER_BYTES,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};

fn fixture(size: usize) -> (SigningKey, Vec<Entry>) {
    let key = SigningKey::from_bytes(&[19; 32]);
    let mut prev = DOMAIN.to_string();
    let entries = (1..=size)
        .map(|sequence| {
            let fields = NewEntry {
                at: 0,
                kind: "boot.facts".into(),
                actor: "a".into(),
                op: String::new(),
                phase: "fact".into(),
                body: Value::Object(vec![("index".into(), Value::Integer(sequence as i64))]),
            };
            let hash = entry_hash(&prev, &fields, sequence as u64).unwrap();
            let entry = Entry {
                sequence: sequence as u64,
                prev: prev.clone(),
                hash: hex::encode(hash),
                sig: STANDARD.encode(key.sign(&hash).unwrap()),
                at: fields.at,
                kind: fields.kind,
                actor: fields.actor,
                op: fields.op,
                phase: fields.phase,
                body: fields.body,
            };
            prev.clone_from(&entry.hash);
            entry
        })
        .collect();
    (key, entries)
}

fn resign(entries: &mut [Entry], key: &SigningKey) {
    let mut prev = DOMAIN.to_string();
    for entry in entries {
        entry.prev = prev;
        let hash = entry_hash(&entry.prev, &entry.fields(), entry.sequence).unwrap();
        entry.hash = hex::encode(hash);
        entry.sig = STANDARD.encode(key.sign(&hash).unwrap());
        prev = entry.hash.clone();
    }
}

fn database() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connection = Connection::open(dir.path().join("aura.db")).unwrap();
    initialize(&connection).unwrap();
    (dir, connection)
}

fn store(connection: &mut Connection, entries: &[Entry]) {
    let tx = connection.transaction().unwrap();
    for e in entries {
        tx.execute(
            "INSERT INTO main.aura VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                e.sequence as i64,
                e.prev,
                e.hash,
                e.sig,
                e.at,
                e.kind,
                e.actor,
                e.op,
                e.phase,
                String::from_utf8(canon::canonical_json(&e.body).unwrap()).unwrap()
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
}

#[test]
fn re_signed_prefix_precedes_later_damage() {
    let (key, mut entries) = fixture(12);
    let honest = entries.clone();
    let (head, _) = export(&entries, &key.verifying_key(), 8).unwrap();
    entries[1].body = Value::Object(vec![("rewrite".into(), Value::Bool(true))]);
    resign(&mut entries, &key);
    entries[9].body = Value::Object(vec![("unsigned_damage".into(), Value::Bool(true))]);
    let expected = Error {
        code: "aura:retained-head-mismatch",
        sequence: Some(8),
    };
    assert_eq!(
        walk(&entries, &key.verifying_key(), Some(&head)).unwrap_err(),
        expected
    );
    assert_eq!(
        walk_against_prefix(&entries, &honest[..8], &key.verifying_key()).unwrap_err(),
        Error {
            code: "aura:retained-entry-differs",
            sequence: Some(2)
        }
    );
    let (_dir, mut conn) = database();
    store(&mut conn, &entries);
    assert_eq!(
        walk_database(&conn, &key.verifying_key(), Some(&head)).unwrap_err(),
        expected
    );
    let mut suffix = honest;
    suffix[9].body = Value::Bool(false);
    assert_eq!(
        walk(&suffix, &key.verifying_key(), Some(&head))
            .unwrap_err()
            .sequence,
        Some(10)
    );
}

#[test]
fn empty_retained_is_unchecked() {
    let (key, entries) = fixture(2);
    for presented in [&[][..], entries.as_slice()] {
        assert_eq!(
            walk_against_prefix(presented, &[], &key.verifying_key())
                .unwrap_err()
                .code,
            "aura:empty-retained"
        );
    }
    let (mut head, _) = export(&entries, &key.verifying_key(), 1).unwrap();
    head.sequence = 0;
    head.tree_size = 0;
    assert_eq!(
        walk(&[], &key.verifying_key(), Some(&head))
            .unwrap_err()
            .code,
        "aura:empty-retained"
    );
    assert_eq!(
        walk(&entries, &key.verifying_key(), Some(&head))
            .unwrap_err()
            .code,
        "aura:empty-retained"
    );
}

#[test]
fn main_reads_and_terminal_checks_ignore_temp_shadow_after_hook_bypass() {
    use rusqlite::hooks::AuthContext;
    let (key, mut entries) = fixture(1);
    entries[0].op = "op".into();
    entries[0].phase = "terminal".into();
    resign(&mut entries, &key);
    let (_dir, mut connection) = database();
    store(&mut connection, &entries);
    connection
        .authorizer(None::<fn(AuthContext<'_>) -> rusqlite::hooks::Authorization>)
        .unwrap();
    connection
        .execute_batch("CREATE TEMP TABLE aura AS SELECT * FROM main.aura WHERE 0")
        .unwrap();
    assert_eq!(read_entries(&connection).unwrap(), entries);
    require_terminal(&connection, "op").unwrap();
    walk_database(&connection, &key.verifying_key(), None).unwrap();
    assert_eq!(
        export_database(&connection, &key.verifying_key(), 1).unwrap(),
        export(&entries, &key.verifying_key(), 1).unwrap()
    );
}

#[test]
fn materialized_200000_row_reproduction_has_a_fixed_budget() {
    use rusqlite::hooks::AuthContext;
    let (_dir, conn) = database();
    conn.authorizer(None::<fn(AuthContext<'_>) -> rusqlite::hooks::Authorization>)
        .unwrap();
    conn.execute_batch("DROP TRIGGER aura_next_sequence")
        .unwrap();
    conn.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<200000) INSERT INTO main.aura SELECT x,'aukora:aura-record:v1',printf('%064x',x),'',0,'kira.save','a','','fact','{}' FROM n", []).unwrap();
    let failure = read_entries(&conn).unwrap_err();
    assert_eq!(failure.code, "aura:memory-limit");
    assert!(failure.sequence.unwrap() < 200000);
}

#[test]
fn oversized_row_is_refused_before_parsing_and_copying() {
    let (_dir, conn) = database();
    let body = format!("\"{}\"", "a".repeat(MAX_BUFFER_BYTES + 1));
    conn.execute(
        "INSERT INTO main.aura VALUES(1,?1,?2,'',0,'boot.facts','a','','fact',?3)",
        params![DOMAIN, "ab".repeat(32), body],
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[19; 32]);
    assert_eq!(read_entries(&conn).unwrap_err().code, "aura:memory-limit");
    assert_eq!(
        walk_database(&conn, &key.verifying_key(), None)
            .unwrap_err()
            .code,
        "aura:memory-limit"
    );
    assert_eq!(
        export_database(&conn, &key.verifying_key(), 1)
            .unwrap_err()
            .code,
        "aura:memory-limit"
    );
}

#[test]
fn streaming_export_and_walk_outgrow_materialization_budget() {
    let (key, mut entries) = fixture(140);
    for e in &mut entries {
        e.body = Value::String("a".repeat(65536));
    }
    resign(&mut entries, &key);
    let (_dir, mut connection) = database();
    store(&mut connection, &entries);
    assert_eq!(
        read_entries(&connection).unwrap_err().code,
        "aura:memory-limit"
    );
    walk_database(&connection, &key.verifying_key(), None).unwrap();
    for m in [1, 2, 4, 8, 16, 32, 63, 139, 140] {
        assert_eq!(
            export_database(&connection, &key.verifying_key(), m).unwrap(),
            export(&entries, &key.verifying_key(), m).unwrap()
        );
    }
}

#[test]
fn proof_hash_buffer_refuses_unbounded_export() {
    let empty = Entry {
        sequence: 1,
        prev: DOMAIN.into(),
        hash: String::new(),
        sig: String::new(),
        at: 0,
        kind: "boot.facts".into(),
        actor: String::new(),
        op: String::new(),
        phase: "fact".into(),
        body: Value::Null,
    };
    let entries = vec![empty; MAX_BUFFER_BYTES / 32 + 1];
    let key = SigningKey::from_bytes(&[19; 32]);
    assert_eq!(
        export(&entries, &key.verifying_key(), 1).unwrap_err().code,
        "aura:memory-limit"
    );
}

#[test]
fn terminal_state_has_a_fixed_budget() {
    let (key, mut entries) = fixture(2);
    entries[0].phase = "terminal".into();
    entries[0].op = "x".repeat(MAX_BUFFER_BYTES - 128);
    entries[1].phase = "terminal".into();
    entries[1].op = "y".into();
    resign(&mut entries, &key);
    assert_eq!(
        walk(&entries, &key.verifying_key(), None).unwrap_err(),
        Error {
            code: "aura:memory-limit",
            sequence: Some(2)
        }
    );
}
