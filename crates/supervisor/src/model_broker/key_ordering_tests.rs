// SPDX-License-Identifier: AGPL-3.0-or-later
//! The supervisor's card-before-key and reconcile-before-swap ordering, beyond the key file's own tests.

use super::*;
use canon::{
    alg::{PublicKey, Signature, Signatures},
    digest::Digest32,
};
use ed25519_dalek::{Signer, SigningKey};
use std::{fs::File, os::unix::fs::PermissionsExt};

const OLD: &str = "sk-0123456789abcdef0123456789abcdef";
const NEW: &str = "sk-fedcba9876543210fedcba9876543210";

struct TestSigner(SigningKey);
impl aura::RecordSigner for TestSigner {
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

struct Rig {
    directory: PathBuf,
    broker: Arc<ModelBroker>,
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn rig() -> Rig {
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).unwrap();
    let directory = std::env::temp_dir().join(format!("model-key-ordering-{}", hex::encode(nonce)));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = std::fs::canonicalize(directory).unwrap();
    let ledger = Arc::new(
        HostLedger::open(
            &directory.join("aura.sqlite3"),
            Arc::new(TestSigner(SigningKey::from_bytes(&[61; 32]))),
            Arc::new(crate::adapters::HostClock),
        )
        .unwrap(),
    );
    // An unconfigured gate deterministically refuses the card, before any owner scope can be used.
    let gate = Arc::new(
        GateAdapter::start(
            directory.clone(),
            File::open(&directory).unwrap(),
            gate::service::GateConfig {
                node: canon::ids::NodeId::from_bytes([62; 16]),
                targets: Vec::new(),
                proposal_lifetime_ms: 300_000,
                ceremony_lifetime_ms: 300_000,
            },
            ledger.clone(),
        )
        .unwrap(),
    );
    let config = BrokerConfig {
        v: 1,
        socket: PathBuf::from("/run/aukora-broker/broker.sock"),
        peer_uids: vec![1001],
        max_request_bytes: None,
        budget: BudgetConfig {
            models: vec!["deepseek-flash".into()],
            prices: Prices {
                cache_read_microusd_per_mtok: 1,
                input_microusd_per_mtok: 2,
                output_microusd_per_mtok: 3,
            },
            total_cap_microusd: 1000,
            per_request_cap_microusd: 10,
            max_requests: 100,
            valid_days: 2,
        },
    };
    let broker = Arc::new(ModelBroker {
        config,
        keys: Arc::new(KeyInbox::new()),
        key_file: KeyFile::new(&directory),
        key_said: Mutex::new(None),
        key_step: Mutex::new(()),
        gate,
        ledger,
    });
    broker.hold(OLD.to_owned(), 1).unwrap();
    Rig { directory, broker }
}

#[test]
fn a_key_whose_card_cannot_be_raised_changes_neither_the_held_key_nor_the_stored_key() {
    let rig = rig();
    let digest = KeyApproval::for_key(OLD).key_sha256;
    assert_eq!(rig.broker.sync_key(Some(&digest), 2), Step::Persisted);
    let scope = PrincipalScope {
        subject: canon::ids::SubjectId::from_digest(Digest32::sha256(b"key-ordering-owner")),
        epoch: 1,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let result = runtime.block_on(rig.broker.stage_key(scope, NEW.to_owned(), 3));
    assert!(result.is_err());
    assert_eq!(
        rig.broker.keys.key_sha256().unwrap().as_deref(),
        Some(digest.as_str())
    );
    assert_eq!(
        std::fs::read(rig.directory.join("model-key")).unwrap(),
        OLD.as_bytes()
    );
}

#[test]
fn a_pending_key_swap_waits_for_an_older_save_then_removes_it_and_cannot_restore_it() {
    let rig = rig();
    let digest = KeyApproval::for_key(OLD).key_sha256;
    let step = rig.broker.key_step.lock().unwrap();
    let broker = rig.broker.clone();
    let (began_send, began_recv) = std::sync::mpsc::channel();
    let (done_send, done_recv) = std::sync::mpsc::channel();
    let swap = std::thread::spawn(move || {
        began_send.send(()).unwrap();
        broker.hold_pending_key(NEW.to_owned(), 4).unwrap();
        done_send.send(()).unwrap();
    });
    began_recv.recv().unwrap();
    assert!(
        done_recv.try_recv().is_err(),
        "the swap cannot run inside an older reconcile pass"
    );
    assert_eq!(
        reconcile(&rig.broker.keys, &rig.broker.key_file, Some(&digest), 3),
        Step::Persisted
    );
    drop(step);
    done_recv.recv().unwrap();
    swap.join().unwrap();
    assert_eq!(
        rig.broker.keys.key_sha256().unwrap(),
        Some(KeyApproval::for_key(NEW).key_sha256)
    );
    assert!(
        !rig.directory.join("model-key").exists(),
        "the preceding save was removed after the swap"
    );
    assert_eq!(rig.broker.sync_key(Some(&digest), 5), Step::Idle);
    assert!(
        !rig.directory.join("model-key").exists(),
        "the next pass cannot restore the old approved key"
    );
}
