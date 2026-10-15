use aura::{
    append, begin, export_cold_proof, export_cold_proof_database, initialize, NewEntry, Value,
};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

fn fixture() -> (tempfile::TempDir, Connection, SigningKey, Vec<aura::Entry>) {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let mut db = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&db).unwrap();
    let key = SigningKey::from_bytes(&[37; 32]);
    let tx = begin(&mut db).unwrap();
    let entries = (0..4)
        .map(|index| {
            append(
                &tx,
                &key,
                &key.verifying_key(),
                &NewEntry {
                    at: 1_700_000_000_000 + index,
                    kind: "boot.facts".into(),
                    actor: "supervisor".into(),
                    op: String::new(),
                    phase: "fact".into(),
                    body: Value::Object(vec![
                        ("index".into(), Value::Integer(index)),
                        ("message".into(), Value::String("honest".into())),
                    ]),
                },
            )
            .unwrap()
        })
        .collect();
    tx.commit().unwrap();
    (directory, db, key, entries)
}

#[test]
fn cold_database_and_slice_exports_match_portable_node_vector() {
    let (_directory, db, key, entries) = fixture();
    let expected = include_bytes!("vectors/cold-proof-v1.json");
    assert_eq!(
        export_cold_proof(&entries, &key.verifying_key()).unwrap(),
        expected
    );
    assert_eq!(
        export_cold_proof_database(&db, &key.verifying_key()).unwrap(),
        expected
    );
}

#[test]
fn antibody_cold_export_authenticates_rows_and_public_key() {
    let (_directory, db, key, mut entries) = fixture();
    let forged = SigningKey::from_bytes(&[38; 32]).verifying_key();
    assert_eq!(
        export_cold_proof(&entries, &forged).unwrap_err().code,
        "aura:invalid-signature"
    );
    assert_eq!(
        export_cold_proof_database(&db, &forged).unwrap_err().code,
        "aura:invalid-signature"
    );
    entries[1].body = Value::Object(vec![]);
    assert_eq!(
        export_cold_proof(&entries, &key.verifying_key())
            .unwrap_err()
            .code,
        "aura:hash-mismatch"
    );
}

#[test]
fn antibody_cold_export_refuses_unverifiable_container_depth() {
    for depth in 61..=64 {
        let (_directory, mut db, key, _) = fixture();
        let mut body = Value::Integer(0);
        for _ in 0..depth {
            body = Value::Object(vec![("a".into(), body)]);
        }
        let tx = begin(&mut db).unwrap();
        let entry = append(
            &tx,
            &key,
            &key.verifying_key(),
            &NewEntry {
                at: 0,
                kind: "boot.facts".into(),
                actor: "supervisor".into(),
                op: String::new(),
                phase: "fact".into(),
                body,
            },
        )
        .unwrap();
        tx.commit().unwrap();
        let entries = aura::read_entries(&db).unwrap();
        assert_eq!(entries.last(), Some(&entry));
        let exported = export_cold_proof(&entries, &key.verifying_key());
        if depth == 61 {
            canon::parse(&exported.unwrap()).unwrap();
            export_cold_proof_database(&db, &key.verifying_key()).unwrap();
        } else {
            assert_eq!(exported.unwrap_err().code, "aura:invalid-body");
            assert_eq!(
                export_cold_proof_database(&db, &key.verifying_key())
                    .unwrap_err()
                    .code,
                "aura:invalid-body"
            );
        }
    }
}
