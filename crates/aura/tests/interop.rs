use aura::merkle::{presented_head, retained_head, Hash, RetainedHead};
use aura::{append, entry_hash, export, initialize, walk, Entry, NewEntry, Value};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../../../tests/support/node.rs"]
mod test_node;

fn fixture(size: usize) -> (Vec<Entry>, SigningKey) {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let mut connection = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&connection).unwrap();
    let key = SigningKey::from_bytes(&[37; 32]);
    let transaction = aura::begin(&mut connection).unwrap();
    let entries = (0..size)
        .map(|index| {
            append(
                &transaction,
                &key,
                &key.verifying_key(),
                &NewEntry {
                    at: 1_700_000_000_000 + index as i64,
                    kind: "boot.facts".into(),
                    actor: "supervisor".into(),
                    op: String::new(),
                    phase: "fact".into(),
                    body: Value::Object(vec![
                        ("index".into(), Value::Integer(index as i64)),
                        ("message".into(), Value::String("honest".into())),
                    ]),
                },
            )
            .unwrap()
        })
        .collect();
    transaction.commit().unwrap();
    (entries, key)
}

fn stored_hashes(entries: &[Entry]) -> Vec<Hash> {
    entries
        .iter()
        .map(|entry| hex::decode(&entry.hash).unwrap().try_into().unwrap())
        .collect()
}

fn fields(entry: &Entry) -> NewEntry {
    NewEntry {
        at: entry.at,
        kind: entry.kind.clone(),
        actor: entry.actor.clone(),
        op: entry.op.clone(),
        phase: entry.phase.clone(),
        body: entry.body.clone(),
    }
}

fn rederived_hashes(entries: &[Entry]) -> Vec<Hash> {
    entries
        .iter()
        .map(|entry| entry_hash(&entry.prev, &fields(entry), entry.sequence).unwrap())
        .collect()
}

fn verify(retained: &str, presented: &str) -> String {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let retained_path = directory.path().join("retained.json");
    let presented_path = directory.path().join("presented.json");
    fs::write(&retained_path, retained).unwrap();
    fs::write(&presented_path, presented).unwrap();
    let verifier = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify.py");
    let output = Command::new("python3")
        .arg(verifier)
        .arg(retained_path)
        .arg(presented_path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("python3 must run the unchanged independent verifier");
    assert!(
        output.status.success(),
        "verifier failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn append_only(output: &str) -> bool {
    output.lines().any(|line| line == "VERDICT: APPEND_ONLY")
}

#[test]
fn unchanged_python_verifier_accepts_all_183_honest_power_of_two_exports() {
    let (entries, key) = fixture(40);
    let hashes = stored_hashes(&entries);
    let mut checked = 0;
    for retained_size in [1, 2, 4, 8, 16, 32] {
        let retained = retained_head(&hashes, retained_size).unwrap();
        let retained_json = retained.to_json().unwrap();
        for presented_size in retained_size..=40 {
            let (exported_retained, presented) = export(
                &entries[..presented_size],
                &key.verifying_key(),
                retained_size,
            )
            .unwrap();
            assert_eq!(exported_retained, retained);
            let output = verify(&retained_json, &presented.to_json().unwrap());
            assert!(
                append_only(&output),
                "M={retained_size}, N={presented_size}: {output}"
            );
            walk(
                &entries[..presented_size],
                &key.verifying_key(),
                Some(&retained),
            )
            .unwrap();
            checked += 1;
        }
    }
    assert_eq!(checked, 183);
    println!("PYTHON_EXPORT_MATRIX: 183/183 VERDICT: APPEND_ONLY");
}

fn assert_hostile(
    entries: &[Entry],
    retained: &RetainedHead,
    key: &SigningKey,
    expected_sequence: u64,
    name: &str,
) {
    let failure = walk(entries, &key.verifying_key(), Some(retained)).unwrap_err();
    assert_eq!(failure.sequence, Some(expected_sequence), "{name}");
    assert!(
        export(entries, &key.verifying_key(), retained.tree_size).is_err(),
        "safe exporter must refuse {name}"
    );
    let hashes = rederived_hashes(entries);
    let presented_json = if entries.len() >= retained.tree_size {
        presented_head(&hashes, retained.tree_size)
            .unwrap()
            .to_json()
            .unwrap()
    } else {
        // A hostile peer can send a smaller head even though the writer refuses to export one.
        let old_head = retained_head(&hashes, hashes.len()).unwrap();
        String::from_utf8(
            canon::canonical_json(&Value::Object(vec![
                (
                    "schema".into(),
                    Value::String("aukora-aura-presented-head-v1".into()),
                ),
                (
                    "leafConvention".into(),
                    Value::String("rfc6962-leaf-sha256-0x00-prefixed-v1".into()),
                ),
                ("treeSize".into(), Value::Integer(hashes.len() as i64)),
                ("root".into(), Value::String(old_head.root)),
                (
                    "retainedTreeSize".into(),
                    Value::Integer(retained.tree_size as i64),
                ),
                ("proofFromPrevious".into(), Value::Array(Vec::new())),
            ]))
            .unwrap(),
        )
        .unwrap()
    };
    let output = verify(&retained.to_json().unwrap(), &presented_json);
    assert!(!append_only(&output), "{name}: {output}");
}

#[test]
fn hostile_logs_never_pass_python_and_walk_names_first_bad_sequence() {
    let (entries, key) = fixture(12);
    let hashes = stored_hashes(&entries);
    let retained = retained_head(&hashes, 8).unwrap();

    let mut body_flip = entries.clone();
    body_flip[1].body = Value::Object(vec![
        ("index".into(), Value::Integer(1)),
        ("message".into(), Value::String("Honest".into())),
    ]);
    assert_hostile(&body_flip, &retained, &key, 2, "early body byte flip");

    assert_hostile(&entries[..6], &retained, &key, 7, "tail truncation");
    assert_hostile(&entries[..4], &retained, &key, 5, "old head replay");

    let mut reordered = entries.clone();
    reordered.swap(1, 2);
    assert_hostile(&reordered, &retained, &key, 2, "entries reordered");
    println!("HOSTILE_EXPORTS: 4/4 rejected; first bad sequences 2,7,5,2");
}

#[test]
fn node_prime_rule_jsonl_rederives_to_identical_rust_entry_hashes() {
    let vector: PathBuf =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/prime-chain.mjs");
    let output = Command::new(test_node::node())
        .arg(vector)
        .output()
        .expect("the supplied Node executable must run Prime's restated rule");
    assert!(
        output.status.success(),
        "Node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let jsonl = String::from_utf8(output.stdout).unwrap();
    assert!(jsonl.ends_with('\n'));
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let log = directory.path().join("prime.jsonl");
    fs::write(&log, jsonl).unwrap();
    let mut count = 0;
    let mut previous = "aukora:aura-record:v1".to_string();
    for line in fs::read_to_string(log).unwrap().lines() {
        let entry = canon::parse(line.as_bytes()).unwrap();
        let Value::Integer(sequence) = entry.get("sequence").unwrap() else {
            panic!("sequence is not an integer")
        };
        let sequence = *sequence as u64;
        let fields = NewEntry {
            at: integer_field(&entry, "at"),
            kind: string_field(&entry, "kind").into(),
            actor: string_field(&entry, "actor").into(),
            op: string_field(&entry, "op").into(),
            phase: string_field(&entry, "phase").into(),
            body: entry.get("body").unwrap().clone(),
        };
        assert_eq!(string_field(&entry, "prev"), previous);
        let hash = hex::encode(entry_hash(&previous, &fields, sequence).unwrap());
        assert_eq!(string_field(&entry, "hash"), hash);
        previous = hash;
        count += 1;
    }
    assert_eq!(count, 5);
    println!("PRIME_NODE_HASHES: 5/5 identical Rust hashes");
}

fn string_field<'a>(value: &'a Value, name: &str) -> &'a str {
    match value.get(name) {
        Some(Value::String(value)) => value,
        _ => panic!("{name} is not a string"),
    }
}

fn integer_field(value: &Value, name: &str) -> i64 {
    match value.get(name) {
        Some(Value::Integer(value)) => *value,
        _ => panic!("{name} is not an integer"),
    }
}
