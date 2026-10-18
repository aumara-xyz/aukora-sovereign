// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detached verification is adopted only for the exact unchanged connection generation.
use super::*;
use canon::{
    alg::{AlgorithmId, PublicKey, Signature, Signatures},
    authority::{AuthorityTxn, FactKind, FactRecord},
    json::Value,
};
use ed25519_dalek::{Signer, SigningKey};

struct Node(SigningKey);
impl RecordSigner for Node {
    fn public_keys(&self) -> Result<Vec<PublicKey>> {
        Ok(vec![PublicKey {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: self.0.verifying_key().to_bytes().to_vec(),
        }])
    }
    fn sign_entry_hash(&self, hash: Digest32) -> Result<Signatures> {
        Signatures::new(vec![Signature {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: self.0.sign(hash.as_bytes()).to_bytes().to_vec(),
        }])
    }
}
struct Clock;
impl TrustedClock for Clock {
    fn now_ms(&self) -> Result<i64> {
        Ok(1_800_000_000_000)
    }
}
struct Database(std::path::PathBuf);
impl Database {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        Self(
            std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("aura-read-snapshot-{name}.sqlite3")),
        )
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn append(ledger: &mut Ledger, services: TransactionServices<'_>) -> Result<()> {
    let mut txn = ledger.begin(services)?;
    let context = txn.observation_context()?;
    txn.append_fact(FactRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: context.authority,
        at: context.at,
        kind: FactKind::BootFacts,
        actor: "snapshot-regression".into(),
        body: Value::object(Vec::new())?,
    })?;
    txn.commit()
}

#[test]
fn separate_connection_commit_is_verified_before_writer_and_not_scanned_again() -> Result<()> {
    let db = Database::new();
    let signer = Node(SigningKey::from_bytes(&[19; 32]));
    let clock = Clock;
    let services = TransactionServices {
        signer: &signer,
        clock: &clock,
    };
    let mut host = Ledger::open(&db.0)?;
    let mut separate = Ledger::open(&db.0)?;
    append(&mut separate, services).expect("append separate");
    let generation = host.read_generation()?;
    let verified = Ledger::read_snapshot(&db.0, services, |snapshot| {
        assert_eq!(snapshot.current_version()?.sequence, 2);
        Ok(snapshot.verified())
    })?;
    let scans = super::super::io::VERIFY_CALLS.with(|calls| calls.get());
    let txn = host
        .begin_verified(services, generation, verified)?
        .expect("fresh generation");
    assert_eq!(txn.current_version()?.sequence, 2);
    assert_eq!(
        super::super::io::VERIFY_CALLS.with(|calls| calls.get()),
        scans,
        "entering the writer repeated detached full verification"
    );
    drop(txn);
    Ok(())
}

#[test]
fn unchanged_head_does_not_hide_external_or_local_side_table_changes() -> Result<()> {
    let db = Database::new();
    let signer = Node(SigningKey::from_bytes(&[20; 32]));
    let clock = Clock;
    let services = TransactionServices {
        signer: &signer,
        clock: &clock,
    };
    let mut host = Ledger::open(&db.0)?;
    host.connection
        .execute_batch("CREATE TABLE snapshot_test(value INTEGER)")
        .unwrap();
    append(&mut host, services).expect("append host");
    let head = host.verified.next()?;
    let generation = host.read_generation()?;
    let verified = Ledger::read_snapshot(&db.0, services, |snapshot| Ok(snapshot.verified()))?;
    let external = rusqlite::Connection::open(&db.0).unwrap();
    external
        .execute("INSERT INTO snapshot_test VALUES(1)", [])
        .unwrap();
    assert!(host
        .begin_verified(services, generation, verified)?
        .is_none());
    assert_eq!(host.verified.next()?, head);

    let generation = host.read_generation()?;
    let verified = Ledger::read_snapshot(&db.0, services, |snapshot| Ok(snapshot.verified()))?;
    host.connection
        .execute("INSERT INTO snapshot_test VALUES(2)", [])
        .unwrap();
    assert!(host
        .begin_verified(services, generation, verified)?
        .is_none());
    assert_eq!(host.verified.next()?, head);
    Ok(())
}
