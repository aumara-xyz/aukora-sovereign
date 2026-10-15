use aura::{append, begin, initialize, read_entries, read_entry, walk_database, NewEntry, Value};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};

fn database() -> (tempfile::TempDir, Connection) {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connection = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&connection).unwrap();
    (directory, connection)
}

fn fields() -> NewEntry {
    NewEntry {
        at: 0,
        kind: "boot.facts".into(),
        actor: "supervisor".into(),
        op: String::new(),
        phase: "fact".into(),
        body: Value::Object(Vec::new()),
    }
}

#[test]
fn antibody_single_row_outgrows_materialization_budget() {
    // Bulk reads refuse aura:memory-limit; an authenticated single-row read must succeed.
    let (_directory, mut connection) = database();
    let signer = SigningKey::from_bytes(&[53; 32]);
    let mut fields = fields();
    fields.body = Value::String("a".repeat(65_536));
    let transaction = begin(&mut connection).unwrap();
    let mut last = None;
    for _ in 0..140 {
        last = Some(append(&transaction, &signer, &signer.verifying_key(), &fields).unwrap());
    }
    transaction.commit().unwrap();
    assert_eq!(
        read_entries(&connection).unwrap_err().code,
        "aura:memory-limit"
    );
    let snapshot = connection.transaction().unwrap();
    walk_database(&snapshot, &signer.verifying_key(), None).unwrap();
    assert_eq!(read_entry(&snapshot, 140).unwrap(), last);
    assert!(read_entry(&snapshot, 141).unwrap().is_none());
}

#[test]
fn antibody_database_walk_outgrows_terminal_budget() {
    // No aura:memory-limit may depend on accumulated terminal identifiers.
    let (_directory, mut connection) = database();
    let signer = SigningKey::from_bytes(&[54; 32]);
    let mut fields = fields();
    fields.phase = "terminal".into();
    let transaction = begin(&mut connection).unwrap();
    for index in 0..3 {
        fields.op = format!("{index}{}", "x".repeat(aura::MAX_BUFFER_BYTES / 3));
        append(&transaction, &signer, &signer.verifying_key(), &fields).unwrap();
    }
    transaction.commit().unwrap();
    walk_database(&connection, &signer.verifying_key(), None).unwrap();
}

fn raw_database() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("CREATE TABLE aura(seq INTEGER PRIMARY KEY,prev TEXT,hash TEXT,sig TEXT,at INTEGER,kind TEXT,actor TEXT,op TEXT,phase TEXT,body TEXT)")
        .unwrap();
    connection
}

#[test]
fn antibody_database_walk_refuses_duplicate_terminals() {
    // A valid signature cannot excuse aura:duplicate-terminal.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let connection = raw_database();
    let signer = SigningKey::from_bytes(&[55; 32]);
    let mut fields = fields();
    fields.op = "duplicate-operation".into();
    fields.phase = "terminal".into();
    let mut previous = aura::DOMAIN.to_owned();
    for sequence in 1..=2 {
        let hash = aura::entry_hash(&previous, &fields, sequence).unwrap();
        let signature = aura::Signer::sign(&signer, &hash).unwrap();
        let hash = hex::encode(hash);
        connection
            .execute(
                "INSERT INTO aura VALUES(?1,?2,?3,?4,0,'boot.facts','supervisor',?5,'terminal','{}')",
                params![sequence as i64, previous, hash, STANDARD.encode(signature), fields.op],
            )
            .unwrap();
        previous = hash;
    }
    let failure = walk_database(&connection, &signer.verifying_key(), None).unwrap_err();
    assert_eq!(failure.code, "aura:duplicate-terminal");
    assert_eq!(failure.sequence, Some(2));
}

#[test]
fn antibody_single_row_refuses_noncanonical_body() {
    // Same aura:noncanonical-body check as bulk decoding, before interpretation.
    let connection = raw_database();
    connection
        .execute("INSERT INTO aura VALUES(1,'previous','hash','',0,'boot.facts','a','','fact','{ \"k\":1}')", [])
        .unwrap();
    assert_eq!(
        read_entry(&connection, 1).unwrap_err().code,
        "aura:noncanonical-body"
    );
}

#[test]
fn antibody_single_row_refuses_oversized_row() {
    // Same aura:memory-limit allocation check as bulk decoding.
    let connection = raw_database();
    connection
        .execute(
            "INSERT INTO aura VALUES(1,'previous','hash','',0,'boot.facts','a','','fact',?1)",
            [format!("\"{}\"", "a".repeat(aura::MAX_BUFFER_BYTES))],
        )
        .unwrap();
    assert_eq!(
        read_entry(&connection, 1).unwrap_err().code,
        "aura:memory-limit"
    );
}
