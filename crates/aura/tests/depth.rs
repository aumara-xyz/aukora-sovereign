use aura::{append, entry_hash, initialize, read_entries, walk, NewEntry, Value, DOMAIN};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use std::path::Path;
use std::process::Command;

#[path = "../../../tests/support/node.rs"]
mod test_node;

fn database() -> (tempfile::TempDir, Connection) {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connection = Connection::open(directory.path().join("aura.db")).unwrap();
    initialize(&connection).unwrap();
    (directory, connection)
}

fn nested_fields(depth: usize, object: bool) -> NewEntry {
    let mut body = Value::Integer(0);
    for _ in 0..depth {
        body = if object {
            Value::Object(vec![("a".into(), body)])
        } else {
            Value::Array(vec![body])
        };
    }
    NewEntry {
        at: 0,
        kind: "boot.facts".into(),
        actor: "a".into(),
        op: String::new(),
        phase: "fact".into(),
        body,
    }
}

#[test]
fn c1_depth64_is_hashable_and_matches_prime() {
    let vector = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/prime-depth.mjs");
    let output = Command::new(test_node::node())
        .arg(vector)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let key = SigningKey::from_bytes(&[31; 32]);
    let mut count = 0;
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        // This controlled Node fixture wraps a depth-64 body in two reporting
        // objects, so read its fixed metadata without admitting that wrapper.
        let metadata = line.strip_prefix("{\"kind\":\"").unwrap();
        let (kind, metadata) = metadata.split_once("\",\"depth\":").unwrap();
        let (depth, _) = metadata.split_once(',').unwrap();
        let depth = depth.parse::<usize>().unwrap();
        let object = kind == "object";
        let fields = nested_fields(depth, object);
        let bytes = entry_hash(DOMAIN, &fields, 1).unwrap();
        let hash = line.rsplit_once("\"hash\":\"").unwrap().1;
        let hash = hash.strip_suffix("\"}").unwrap();
        assert_eq!(hex::encode(bytes), hash);
        let expected = match (object, depth) {
            (false, 63) => "2a153b2aff1b7efeee5839acc76468d1f2bcbd111ef2e9aae4a3f0558ba3e710",
            (false, 64) => "492712e974f7b20c14d3fbe2eb510b5be8d92dbe981611270d082c41b892feff",
            (true, 63) => "79b337a85f10adf5f2692d38bba7d9f011c5a7c16d2449069f78f7e16ad56923",
            (true, 64) => "ea82b0f7d9905bd8b325fc75db8a93e231bb7521f12aa608635f406ee551f62d",
            _ => panic!("unexpected Prime depth vector"),
        };
        assert_eq!(hex::encode(bytes), expected);
        let (_directory, mut connection) = database();
        let transaction = aura::begin(&mut connection).unwrap();
        let entry = append(&transaction, &key, &key.verifying_key(), &fields).unwrap();
        assert_eq!(entry.hash, hex::encode(bytes));
        transaction.commit().unwrap();
        let stored = read_entries(&connection).unwrap();
        assert_eq!(stored, [entry]);
        walk(&stored, &key.verifying_key(), None).unwrap();
        count += 1;
    }
    assert_eq!(count, 4);
    println!(
        "C1_DEPTH_PRIME: 4/4 depth 63/64 array/object hashes match Node; append/read/walk pass"
    );
}

#[test]
fn c1_depth65_is_refused_on_append_hash_and_read() {
    let key = SigningKey::from_bytes(&[31; 32]);
    for object in [false, true] {
        let fields = nested_fields(65, object);
        assert_eq!(
            entry_hash(DOMAIN, &fields, 1).unwrap_err().code,
            "aura:invalid-body"
        );
        let (_directory, mut connection) = database();
        {
            let transaction = aura::begin(&mut connection).unwrap();
            assert_eq!(
                append(&transaction, &key, &key.verifying_key(), &fields)
                    .unwrap_err()
                    .code,
                "aura:invalid-body"
            );
            assert!(read_entries(&transaction).unwrap().is_empty());
        }
        let signature = ed25519_dalek::Signer::sign(&key, &[0; 32]);
        connection.execute(
            "INSERT INTO main.aura(seq,prev,hash,sig,at,kind,actor,op,phase,body) VALUES(1,?1,?2,?3,0,'boot.facts','a','','fact',?4)",
            params![DOMAIN, "00".repeat(32), STANDARD.encode(signature.to_bytes()), if object { format!("{}0{}", "{\"a\":".repeat(65), "}".repeat(65)) } else { format!("{}0{}", "[".repeat(65), "]".repeat(65)) }],
        ).unwrap();
        let error = read_entries(&connection).unwrap_err();
        assert_eq!(error.code, "aura:invalid-body");
        assert_eq!(error.sequence, Some(1));
    }
    println!("C1_DEPTH_REFUSAL: depth 65 arrays/objects refused on append/hash/read");
}
