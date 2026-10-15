// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rusqlite::{params, Connection, Transaction};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[path = "../../../tests/support/node.rs"]
mod test_node;

const TARGET: &str = "plugins/test/accent.json";
const BASE: &[u8] = b"{\"accent\": \"#FFD700\"}";
const NEW: &[u8] = b"{\"accent\": \"#1E90FF\"}";
const OTHER: &[u8] = b"{\"accent\": \"#FF0000\"}";
const START: i64 = 1_800_000_000_000;

#[derive(Clone)]
struct TestClock {
    time: Arc<AtomicI64>,
    fail: Arc<AtomicBool>,
}

impl TestClock {
    fn new() -> Self {
        Self {
            time: Arc::new(AtomicI64::new(START)),
            fail: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set(&self, value: i64) {
        self.time.store(value, Ordering::SeqCst);
    }

    fn advance(&self, value: i64) {
        self.time.fetch_add(value, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> Result<i64> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Refused("gate:test-clock"));
        }
        Ok(self.time.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Default)]
struct MemoryStore {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    writes: Arc<AtomicUsize>,
    unreadable: Arc<AtomicBool>,
    fail_write: Arc<AtomicBool>,
    corrupt_write: Arc<AtomicBool>,
}

impl MemoryStore {
    fn new() -> Self {
        let store = Self::default();
        store.set(BASE);
        store
    }

    fn set(&self, bytes: &[u8]) {
        self.files
            .lock()
            .unwrap()
            .insert(TARGET.to_owned(), bytes.to_vec());
    }

    fn write_count(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }
}

impl TargetStore for MemoryStore {
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>> {
        if self.unreadable.load(Ordering::SeqCst) {
            return Err(Error::Refused("gate:test-unreadable"));
        }
        Ok(self.files.lock().unwrap().get(target).cloned())
    }

    fn write(&self, target: &str, bytes: &[u8], _operation_id: &str) -> Result<()> {
        if self.fail_write.load(Ordering::SeqCst) {
            return Err(Error::Refused("gate:test-write-failed"));
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        let bytes = if self.corrupt_write.load(Ordering::SeqCst) {
            OTHER
        } else {
            bytes
        };
        self.files
            .lock()
            .unwrap()
            .insert(target.to_owned(), bytes.to_vec());
        Ok(())
    }
}

#[derive(Clone)]
struct TestProof {
    clock: TestClock,
    advance_to: Arc<AtomicI64>,
    fail_clock: Arc<AtomicBool>,
    credential_id: Arc<Mutex<String>>,
}

impl TestProof {
    fn new(clock: &TestClock) -> Self {
        Self {
            clock: clock.clone(),
            advance_to: Arc::new(AtomicI64::new(0)),
            fail_clock: Arc::new(AtomicBool::new(false)),
            credential_id: Arc::new(Mutex::new("33".repeat(32))),
        }
    }

    fn sign(auth: &[u8], counter: u32) -> Vec<u8> {
        Self::sign_with(auth, counter, 7)
    }

    fn sign_with(auth: &[u8], counter: u32, seed: u8) -> Vec<u8> {
        let counter_bytes = counter.to_be_bytes();
        let mut signed = auth.to_vec();
        signed.extend_from_slice(&counter_bytes);
        let signature = SigningKey::from_bytes(&[seed; 32]).sign(&signed);
        let mut proof = counter_bytes.to_vec();
        proof.extend_from_slice(&signature.to_bytes());
        proof
    }
}

impl OwnerProof for TestProof {
    fn verify(&self, auth_bytes: &[u8], proof: &[u8]) -> Result<VerifiedProof> {
        if proof.len() != 68 {
            return Err(Error::Refused("gate:owner-proof"));
        }
        let counter = u32::from_be_bytes(proof[..4].try_into().unwrap());
        let signature = Signature::from_bytes(proof[4..].try_into().unwrap());
        let mut signed = auth_bytes.to_vec();
        signed.extend_from_slice(&proof[..4]);
        SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .verify_strict(&signed, &signature)
            .map_err(|_| Error::Refused("gate:owner-proof"))?;
        let advance_to = self.advance_to.load(Ordering::SeqCst);
        if advance_to != 0 {
            self.clock.set(advance_to);
        }
        if self.fail_clock.load(Ordering::SeqCst) {
            self.clock.fail.store(true, Ordering::SeqCst);
        }
        Ok(VerifiedProof {
            counter,
            credential_id: self.credential_id.lock().unwrap().clone(),
        })
    }
}

#[derive(Clone, Default)]
struct TestLedger {
    fail_next: Arc<AtomicBool>,
    fail_count: Arc<AtomicUsize>,
    clock: Option<TestClock>,
    advance_kind: Arc<Mutex<Option<&'static str>>>,
    advance_to: Arc<AtomicI64>,
}

fn initialize_test_ledger(db: &Connection) {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS aura(
            seq INTEGER PRIMARY KEY,
            prev TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            sig TEXT NOT NULL,
            at INTEGER NOT NULL,
            kind TEXT NOT NULL,
            actor TEXT NOT NULL,
            op TEXT NOT NULL,
            phase TEXT NOT NULL,
            body TEXT NOT NULL);
         CREATE UNIQUE INDEX IF NOT EXISTS aura_one_terminal ON aura(op)
            WHERE phase='terminal';
         CREATE TRIGGER IF NOT EXISTS aura_no_update BEFORE UPDATE ON aura
            BEGIN SELECT RAISE(ABORT,'append-only'); END;
         CREATE TRIGGER IF NOT EXISTS aura_no_delete BEFORE DELETE ON aura
            BEGIN SELECT RAISE(ABORT,'append-only'); END;",
    )
    .unwrap();
}

impl Ledger for TestLedger {
    fn append(&self, tx: &Transaction<'_>, row: &LedgerRow) -> Result<LedgerRef> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(Error::Refused("gate:test-ledger-failed"));
        }
        if self
            .fail_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(Error::Refused("gate:test-ledger-failed"));
        }
        let seq: i64 = tx.query_row("SELECT COALESCE(MAX(seq),0)+1 FROM aura", [], |r| r.get(0))?;
        let prev = if seq == 1 {
            "aukora:aura-record:v1".to_owned()
        } else {
            tx.query_row("SELECT hash FROM aura WHERE seq=?", [seq - 1], |r| r.get(0))?
        };
        let hash = sha256(
            format!(
                "{seq}\0{prev}\0{}\0{}\0{}\0{}\0{}\0{}",
                row.at, row.kind, row.actor, row.op, row.phase, row.body
            )
            .as_bytes(),
        );
        let signature = SigningKey::from_bytes(&[9; 32]).sign(&hex::decode(&hash).unwrap());
        tx.execute(
            "INSERT INTO aura(seq,prev,hash,sig,at,kind,actor,op,phase,body)
             VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                seq,
                prev,
                hash,
                hex::encode(signature.to_bytes()),
                row.at,
                row.kind,
                row.actor,
                row.op,
                row.phase,
                row.body
            ],
        )?;
        if *self.advance_kind.lock().unwrap() == Some(row.kind) {
            self.clock
                .as_ref()
                .unwrap()
                .set(self.advance_to.load(Ordering::SeqCst));
        }
        Ok(LedgerRef { seq, hash })
    }

    fn read_verified(&self, db: &Connection, reference: &LedgerRef) -> Result<VerifiedLedgerRow> {
        let (prev, hash, sig, at, kind, actor, op, phase, body): (
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            String,
            String,
        ) = db.query_row(
            "SELECT prev,hash,sig,at,kind,actor,op,phase,body FROM aura WHERE seq=?",
            [reference.seq],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            },
        )?;
        let expected = sha256(
            format!(
                "{}\0{prev}\0{at}\0{kind}\0{actor}\0{op}\0{phase}\0{body}",
                reference.seq
            )
            .as_bytes(),
        );
        if hash != reference.hash || hash != expected {
            return Err(Error::Refused("gate:test-ledger-hash"));
        }
        let signature =
            hex::decode(sig).map_err(|_| Error::Refused("gate:test-ledger-signature"))?;
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| Error::Refused("gate:test-ledger-signature"))?;
        SigningKey::from_bytes(&[9; 32])
            .verifying_key()
            .verify_strict(
                &hex::decode(&hash).unwrap(),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| Error::Refused("gate:test-ledger-signature"))?;
        Ok(VerifiedLedgerRow {
            kind,
            op,
            phase,
            body,
        })
    }
}

fn config() -> Config {
    Config {
        node: "11".repeat(16),
        gate_pubkey_sha256: "55".repeat(32),
        owner: OwnerState {
            subject: format!("aukora:1:{}", "22".repeat(32)),
            epoch: 1,
            binding_sha256: "33".repeat(32),
            sign_count: 0,
        },
        limits: Limits::default(),
    }
}

fn permissive_limits() -> Limits {
    Limits {
        max_pending: 32,
        max_per_window: 100,
        guest_max_per_window: 100,
        reject_cooldown_ms: 0,
        dedupe_ms: 0,
        ..Limits::default()
    }
}

static NEXT_KEY: AtomicUsize = AtomicUsize::new(1);

fn proposal_request(bytes: &[u8]) -> ProposalRequest {
    ProposalRequest {
        target: TARGET.to_owned(),
        base_sha256: sha256(BASE),
        new_bytes: bytes.to_vec(),
        note: "Set the test accent to blue.".to_owned(),
        idempotency_key: format!("{:032x}", NEXT_KEY.fetch_add(1, Ordering::SeqCst)),
        cell: None,
    }
}

fn consume_request(review: &Review, decision: Decision, counter: u32) -> ConsumeRequest {
    ConsumeRequest {
        proposal_id: review.proposal_id.clone(),
        challenge: review.challenge.clone(),
        base_sha256: review.base_sha256.clone(),
        new_sha256: review.new_sha256.clone(),
        display_sha256: review.display_sha256.clone(),
        decision,
        proof: TestProof::sign(&review.auth_bytes, counter),
    }
}

fn terminal_rows(db: &Connection, id: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM aura WHERE op=? AND phase='terminal'",
        [id],
        |r| r.get(0),
    )
    .unwrap()
}

fn count_kind(db: &Connection, id: &str, kind: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM aura WHERE op=? AND kind=?",
        params![id, kind],
        |r| r.get(0),
    )
    .unwrap()
}

fn target_spec() -> TargetSpec {
    TargetSpec {
        name: TARGET.to_owned(),
        ..TargetSpec::theme()
    }
}

type TestGate = Gate<MemoryStore, TestLedger, TestProof, TestClock>;

struct Fixture {
    gate: TestGate,
    store: MemoryStore,
    clock: TestClock,
    ledger: TestLedger,
    proof: TestProof,
    cfg: Config,
    directory: TempDir,
}

fn fixture() -> Fixture {
    fixture_with(permissive_limits())
}

#[test]
fn guest_cannot_read_or_propose_supervisor_targets_and_card_keeps_review_live() {
    let mut f = fixture();
    let spec = TargetSpec::supervisor("broker/key").unwrap();
    f.gate.targets.insert(spec.name.clone(), spec);
    let bytes = canonical(&serde_json::json!({"v":1,"key_sha256":"a".repeat(64)}))
        .unwrap()
        .into_bytes();
    let request = ProposalRequest {
        target: "broker/key".into(),
        base_sha256: "absent".into(),
        new_bytes: bytes,
        note: String::new(),
        idempotency_key: "owner-key".into(),
        cell: None,
    };
    assert!(f.gate.guest().propose(request.clone()).is_err());
    let proposal = f.gate.owner().raise(request).unwrap();
    assert!(f.gate.guest().read("broker/key").is_err());
    let review = f.gate.owner().review(&proposal.id).unwrap();
    assert_eq!(
        f.gate.owner().card(&proposal.id).unwrap(),
        review.card_bytes
    );
    let live: i64 = f
        .gate
        .db
        .query_row(
            "SELECT count(*) FROM gate_reviews WHERE challenge=? AND state='live'",
            [review.challenge],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(live, 1);
}

fn antibody_release_record(component: char) -> Vec<u8> {
    canonical(&json!({"v":1,"digest":component.to_string().repeat(64),
        "components":{"node":"b".repeat(64),"harness":"c".repeat(64),"guest":"d".repeat(64)}}))
    .unwrap()
    .into_bytes()
}

fn antibody_release_evidence(bytes: &[u8]) -> Value {
    json!({"new_sha256":sha256(bytes),"antibody_corpus_sha256":"e".repeat(64),
        "antibody_pass_count":2,"antibody_total":2,"antibody_ids":["claim-reuse","wrong-origin"]})
}

#[test]
fn antibody_release_card_binds_replay_facts_to_exact_bytes_without_approval() {
    let mut f = fixture();
    f.gate
        .targets
        .insert("release".into(), TargetSpec::supervisor("release").unwrap());
    f.gate.require_release_evidence().unwrap();
    let bytes = antibody_release_record('a');
    let evidence = antibody_release_evidence(&bytes);
    let request = ProposalRequest {
        target: "release".into(),
        base_sha256: "absent".into(),
        new_bytes: bytes.clone(),
        note: String::new(),
        idempotency_key: "release-facts".into(),
        cell: None,
    };
    assert_eq!(
        f.gate
            .owner()
            .raise(request.clone())
            .unwrap_err()
            .to_string(),
        "gate:review-facts-unavailable"
    );
    f.gate
        .set_release_evidence(&sha256(&bytes), &evidence)
        .unwrap();
    let proposal = f.gate.owner().raise(request).unwrap();
    let card_bytes = f.gate.owner().card(&proposal.id).unwrap();
    let card: Value = serde_json::from_slice(&card_bytes).unwrap();
    let facts = card["facts"].as_array().unwrap();
    assert!(facts.contains(&json!(["antibody_corpus_sha256", "e".repeat(64)])));
    assert!(facts.contains(&json!(["antibody_pass_count/total", "2/2"])));
    assert_eq!(card["target_review"]["pinned"]["antibody_ids_count"], 2);
    assert_eq!(
        card["target_review"]["pinned"]["antibody_ids_sha256"],
        sha256(canonical(&evidence["antibody_ids"]).unwrap().as_bytes())
    );
    assert!(card["target_review"]["pinned"]
        .get("antibody_ids")
        .is_none());
    assert_eq!(f.gate.state(&proposal.id).unwrap(), Some(State::Pending));
    assert_eq!(f.store.write_count(), 0);

    let unrelated = antibody_release_record('f');
    let spec = &f.gate.targets["release"];
    assert!(crate::card::checked_review_facts(spec, None, &unrelated, false).is_err());
    let review = f.gate.owner().review(&proposal.id).unwrap();
    assert_eq!(review.card_bytes, card_bytes);
    assert_eq!(
        serde_json::from_slice::<Value>(&review.auth_bytes).unwrap()["op"],
        "release"
    );
    assert_eq!(review.display_sha256, sha256(&review.card_bytes));
    f.gate
        .set_release_evidence(&sha256(&unrelated), &antibody_release_evidence(&unrelated))
        .unwrap();
    assert_eq!(
        f.gate.owner().card(&proposal.id).unwrap(),
        review.card_bytes
    );
    assert_eq!(
        f.gate
            .owner()
            .consume(consume_request(&review, Decision::Allow, 0))
            .unwrap(),
        State::Applied
    );
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn antibody_release_replay_evidence_cannot_be_rewritten_after_review() {
    let mut f = fixture();
    f.gate
        .targets
        .insert("release".into(), TargetSpec::supervisor("release").unwrap());
    let bytes = antibody_release_record('a');
    let hash = sha256(&bytes);
    let evidence = antibody_release_evidence(&bytes);
    f.gate.set_release_evidence(&hash, &evidence).unwrap();
    let proposal = f
        .gate
        .owner()
        .raise(ProposalRequest {
            target: "release".into(),
            base_sha256: "absent".into(),
            new_bytes: bytes,
            note: String::new(),
            idempotency_key: "release-reviewed".into(),
            cell: None,
        })
        .unwrap();
    let review = f.gate.owner().review(&proposal.id).unwrap();
    let mut changed = evidence.clone();
    changed["antibody_corpus_sha256"] = json!("f".repeat(64));
    assert_eq!(
        f.gate
            .set_release_evidence(&hash, &changed)
            .unwrap_err()
            .to_string(),
        "gate:review-facts-changed"
    );
    f.gate.set_release_evidence(&hash, &evidence).unwrap();
    assert_eq!(
        f.gate.owner().card(&proposal.id).unwrap(),
        review.card_bytes
    );
}

#[test]
fn antibody_release_retirement_or_expiry_allows_new_corpus_without_rewriting_review() {
    for retire in [true, false] {
        let mut f = fixture();
        f.gate
            .targets
            .insert("release".into(), TargetSpec::supervisor("release").unwrap());
        let bytes = antibody_release_record('a');
        let hash = sha256(&bytes);
        let evidence = antibody_release_evidence(&bytes);
        f.gate.set_release_evidence(&hash, &evidence).unwrap();
        let request = ProposalRequest {
            target: "release".into(),
            base_sha256: "absent".into(),
            new_bytes: bytes,
            note: String::new(),
            idempotency_key: "release-original".into(),
            cell: None,
        };
        let original = f.gate.owner().raise(request.clone()).unwrap();
        let review = f.gate.owner().review(&original.id).unwrap();
        let sequence: i64 = f
            .gate
            .db
            .query_row(
                "SELECT issue_seq FROM gate_reviews WHERE challenge=?",
                [&review.challenge],
                |row| row.get(0),
            )
            .unwrap();
        let signed_review: String = f
            .gate
            .db
            .query_row("SELECT body FROM aura WHERE seq=?", [sequence], |row| {
                row.get(0)
            })
            .unwrap();
        if retire {
            let auth = f.gate.owner().retire_authorization(&original.id).unwrap();
            f.gate
                .owner()
                .retire(&original.id, &TestProof::sign(&auth, 0))
                .unwrap();
            assert_eq!(f.gate.state(&original.id).unwrap(), Some(State::Retired));
        } else {
            f.clock.set(original.expires_at);
            assert_eq!(f.gate.state(&original.id).unwrap(), Some(State::Pending));
        }
        let changed = json!({"new_sha256":hash,"antibody_corpus_sha256":"f".repeat(64),
            "antibody_pass_count":3,"antibody_total":3,
            "antibody_ids":["claim-reuse","wrong-origin","session-revoked"]});
        f.gate.set_release_evidence(&hash, &changed).unwrap();
        let next = f
            .gate
            .owner()
            .raise(ProposalRequest {
                idempotency_key: "release-next".into(),
                ..request
            })
            .unwrap();
        if !retire {
            assert_eq!(f.gate.state(&original.id).unwrap(), Some(State::Expired));
        }
        let card: Value = serde_json::from_slice(&f.gate.owner().card(&next.id).unwrap()).unwrap();
        assert_eq!(card["target_review"]["pinned"]["antibody_ids_count"], 3);
        assert_eq!(
            card["target_review"]["pinned"]["antibody_corpus_sha256"],
            changed["antibody_corpus_sha256"]
        );
        let facts = card["facts"].as_array().unwrap();
        assert!(facts.contains(&json!(["antibody_corpus_sha256", "f".repeat(64)])));
        assert!(facts.contains(&json!(["antibody_pass_count/total", "3/3"])));
        let retained: Vec<u8> = f
            .gate
            .db
            .query_row(
                "SELECT card FROM gate_reviews WHERE challenge=?",
                [&review.challenge],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, review.card_bytes);
        let retained_signed: String = f
            .gate
            .db
            .query_row("SELECT body FROM aura WHERE seq=?", [sequence], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(retained_signed, signed_review);
        assert_eq!(f.store.write_count(), 0);
    }
}

#[test]
fn antibody_release_evidence_remains_pinned_for_every_active_state() {
    for state in [
        State::Pending,
        State::Applying,
        State::Incomplete,
        State::Conflict,
    ] {
        let mut f = fixture();
        f.gate
            .targets
            .insert("release".into(), TargetSpec::supervisor("release").unwrap());
        let bytes = antibody_release_record('a');
        let hash = sha256(&bytes);
        let evidence = antibody_release_evidence(&bytes);
        f.gate.set_release_evidence(&hash, &evidence).unwrap();
        let proposal = f
            .gate
            .owner()
            .raise(ProposalRequest {
                target: "release".into(),
                base_sha256: "absent".into(),
                new_bytes: bytes,
                note: String::new(),
                idempotency_key: "release-active".into(),
                cell: None,
            })
            .unwrap();
        if state != State::Pending {
            let review = f.gate.owner().review(&proposal.id).unwrap();
            assert_eq!(
                f.gate
                    .consume(consume_request(&review, Decision::Allow, 0))
                    .unwrap(),
                State::Applying
            );
            if state != State::Applying {
                f.gate
                    .db
                    .execute(
                        "UPDATE gate_proposals SET state=? WHERE id=?",
                        params![state.as_str(), proposal.id],
                    )
                    .unwrap();
            }
        }
        let mut changed = evidence;
        changed["antibody_corpus_sha256"] = json!("f".repeat(64));
        assert_eq!(
            f.gate
                .set_release_evidence(&hash, &changed)
                .unwrap_err()
                .to_string(),
            "gate:review-facts-changed",
            "{}",
            state.as_str()
        );
        if matches!(state, State::Incomplete | State::Conflict) {
            let auth = f
                .gate
                .owner()
                .reconcile_authorization(&proposal.id)
                .unwrap();
            f.gate
                .owner()
                .reconcile(&proposal.id, &TestProof::sign(&auth, 0))
                .unwrap();
            f.gate.set_release_evidence(&hash, &changed).unwrap();
        }
    }
}

#[test]
fn antibody_release_replay_evidence_refuses_mismatched_and_incomplete_facts() {
    let mut f = fixture();
    f.gate
        .targets
        .insert("release".into(), TargetSpec::supervisor("release").unwrap());
    let bytes = antibody_release_record('a');
    let hash = sha256(&bytes);
    let valid = antibody_release_evidence(&bytes);
    for (field, value) in [
        ("new_sha256", json!("f".repeat(64))),
        ("antibody_corpus_sha256", json!("E".repeat(64))),
        ("antibody_total", json!(3)),
        ("antibody_pass_count", json!(3)),
        ("antibody_pass_count", json!(-1)),
        ("antibody_ids", json!(["claim-reuse", "claim-reuse"])),
        ("antibody_ids", json!(["claim-reuse", "invalid id"])),
        ("antibody_ids", json!([])),
        ("supervisor_binary_sha256", json!("E".repeat(64))),
        ("proposal_id", json!("invalid")),
        ("refusal_code", json!("gate:owner-proof")),
        ("failed_ids", json!(["wrong-origin", "wrong-origin"])),
        ("missing_ids", json!(["invalid id"])),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(
            f.gate.set_release_evidence(&hash, &invalid).is_err(),
            "{field}"
        );
    }
    for field in valid.as_object().unwrap().keys() {
        let mut invalid = valid.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            f.gate.set_release_evidence(&hash, &invalid).is_err(),
            "{field}"
        );
    }
    assert!(f
        .gate
        .set_release_evidence(&"F".repeat(64), &valid)
        .is_err());
    f.gate.set_release_evidence(&hash, &valid).unwrap();
}

fn immune_gate_fixture(evidence: Value) -> (Fixture, Proposal) {
    let mut f = fixture();
    f.gate
        .targets
        .insert("release".into(), TargetSpec::supervisor("release").unwrap());
    let bytes = antibody_release_record('a');
    f.gate
        .set_release_evidence(&sha256(&bytes), &evidence)
        .unwrap();
    let proposal = f
        .gate
        .owner()
        .raise(ProposalRequest {
            target: "release".into(),
            base_sha256: "absent".into(),
            new_bytes: bytes,
            note: String::new(),
            idempotency_key: "immune-follow-up".into(),
            cell: None,
        })
        .unwrap();
    (f, proposal)
}

#[test]
fn antibody_release_card_stays_bounded_with_450_failed_and_missing_vectors() {
    let bytes = antibody_release_record('a');
    let ids: Vec<String> = (0..450)
        .rev()
        .map(|index| format!("antibody-{index:04}-{}", "v".repeat(90)))
        .collect();
    let mut evidence = antibody_release_evidence(&bytes);
    evidence["antibody_total"] = json!(ids.len());
    evidence["antibody_pass_count"] = json!(0);
    evidence["antibody_ids"] = json!(ids);
    evidence["failed_ids"] = json!(ids);
    evidence["missing_ids"] = json!(ids);
    evidence["refusal_code"] = json!("immune:antibody-failed");
    let (mut f, proposal) = immune_gate_fixture(evidence.clone());
    let card_bytes = f.gate.owner().card(&proposal.id).unwrap();
    assert!(card_bytes.len() <= 12_000);
    let card: Value = serde_json::from_slice(&card_bytes).unwrap();
    let mut sorted = ids.clone();
    sorted.sort();
    for field in ["antibody_ids", "failed_ids", "missing_ids"] {
        assert!(card["target_review"]["pinned"].get(field).is_none());
        assert_eq!(
            card["target_review"]["pinned"][format!("{field}_count")],
            450
        );
        assert_eq!(
            card["target_review"]["pinned"][format!("{field}_sha256")],
            sha256(canonical(&json!(sorted)).unwrap().as_bytes())
        );
    }
    assert_eq!(
        card["target_review"]["pinned"]["failed_ids_preview"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert_eq!(
        f.gate.targets["release"].pinned_facts.as_ref().unwrap()[sha256(&bytes)],
        evidence
    );
    assert!(f.gate.release_requires_override(&proposal.id).unwrap());
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn antibody_release_evidence_is_selected_and_frozen_by_proposal_id() {
    let bytes = antibody_release_record('a');
    let hash = sha256(&bytes);
    let evidence = antibody_release_evidence(&bytes);
    let (mut f, proposal) = immune_gate_fixture(evidence.clone());
    let mut pinned = evidence;
    pinned["proposal_id"] = json!(proposal.id);
    pinned["supervisor_binary_sha256"] = json!("7".repeat(64));
    f.gate
        .set_release_proposal_evidence(&proposal.id, &pinned)
        .unwrap();
    f.gate
        .targets
        .get_mut("release")
        .unwrap()
        .pinned_facts
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove(&hash);
    let card: Value = serde_json::from_slice(&f.gate.owner().card(&proposal.id).unwrap()).unwrap();
    assert_eq!(card["target_review"]["pinned"]["proposal_id"], proposal.id);
    assert_eq!(
        card["target_review"]["pinned"]["supervisor_binary_sha256"],
        "7".repeat(64)
    );
    f.gate.owner().review(&proposal.id).unwrap();
    pinned["supervisor_binary_sha256"] = json!("8".repeat(64));
    assert_eq!(
        f.gate
            .set_release_proposal_evidence(&proposal.id, &pinned)
            .unwrap_err()
            .to_string(),
        "gate:review-facts-changed"
    );
}

#[test]
fn antibody_failing_release_requires_explicit_passkey_override_card() {
    let mut evidence = antibody_release_evidence(&antibody_release_record('a'));
    evidence["antibody_pass_count"] = json!(1);
    evidence["failed_ids"] = json!(["wrong-origin"]);
    evidence["missing_ids"] = json!([]);
    evidence["refusal_code"] = json!("immune:antibody-failed");
    let (mut f, proposal) = immune_gate_fixture(evidence);
    let normal_card = f.gate.owner().card(&proposal.id).unwrap();
    assert_eq!(
        f.gate.owner().review(&proposal.id).unwrap_err().to_string(),
        "immune:override-required"
    );
    assert_eq!(
        f.gate
            .db
            .query_row("SELECT count(*) FROM gate_reviews", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let review = f.gate.owner().review_despite(&proposal.id).unwrap();
    let card: Value = serde_json::from_slice(&review.card_bytes).unwrap();
    assert_eq!(card["release_override"], true);
    assert!(card["says"]
        .as_str()
        .unwrap()
        .contains("Approve despite failing antibodies"));
    assert_ne!(review.display_sha256, sha256(&normal_card));
    let mut auth: Value = serde_json::from_slice(&review.auth_bytes).unwrap();
    assert_eq!(auth["op"], "release");
    auth["display_sha256"] = json!(sha256(&normal_card));
    let mut request = consume_request(&review, Decision::Allow, 0);
    request.proof = TestProof::sign(canonical(&auth).unwrap().as_bytes(), 0);
    assert!(f.gate.owner().consume(request).is_err());
    assert_eq!(f.store.write_count(), 0);
    let review = f.gate.owner().review_despite(&proposal.id).unwrap();
    assert_eq!(
        f.gate
            .owner()
            .consume(consume_request(&review, Decision::Allow, 0))
            .unwrap(),
        State::Applied
    );
    assert_eq!(f.store.write_count(), 1);
    assert!(f
        .gate
        .owner()
        .consume(consume_request(&review, Decision::Allow, 0))
        .is_err());
}

fn temp_directory() -> TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/gate-tests");
    fs::create_dir_all(&root).unwrap();
    tempfile::Builder::new()
        .prefix("gate-")
        .tempdir_in(root)
        .unwrap()
}

fn fixture_with(limits: Limits) -> Fixture {
    let directory = temp_directory();
    let store = MemoryStore::new();
    let clock = TestClock::new();
    let ledger = TestLedger {
        clock: Some(clock.clone()),
        ..TestLedger::default()
    };
    let proof = TestProof::new(&clock);
    let cfg = Config { limits, ..config() };
    let db = Connection::open(directory.path().join("gate.db")).unwrap();
    initialize_test_ledger(&db);
    let gate = Gate::open(
        db,
        cfg.clone(),
        vec![target_spec()],
        store.clone(),
        ledger.clone(),
        proof.clone(),
        clock.clone(),
    )
    .unwrap();
    Fixture {
        gate,
        store,
        clock,
        ledger,
        proof,
        cfg,
        directory,
    }
}

fn fresh_database() -> Connection {
    let directory = temp_directory().keep();
    Connection::open(directory.join("fresh.db")).unwrap()
}

fn release_fixture_gate(f: &mut Fixture) {
    let memory = fresh_database();
    initialize_test_ledger(&memory);
    let replacement = Gate::open(
        memory,
        f.cfg.clone(),
        vec![],
        f.store.clone(),
        f.ledger.clone(),
        f.proof.clone(),
        f.clock.clone(),
    )
    .unwrap();
    drop(std::mem::replace(&mut f.gate, replacement));
}

fn reopen(f: &mut Fixture) -> TestGate {
    release_fixture_gate(f);
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    initialize_test_ledger(&db);
    Gate::open(
        db,
        f.cfg.clone(),
        vec![target_spec()],
        f.store.clone(),
        f.ledger.clone(),
        f.proof.clone(),
        f.clock.clone(),
    )
    .unwrap()
}

#[test]
fn approve_once_with_exact_stored_bytes_and_one_terminal_row() {
    // Prime packages/boundary-gate/checks/gate.mjs: owner approval: single use, signed receipt with HMAC evidence, replay/expiry/stale/truncation refused.
    // Prime tests/aukora-owner-authorization.test.mjs: signed v3 receipt joins the exact proof, issuance, and durable consumption.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    assert_eq!(p.state, State::Pending);
    assert_eq!(f.store.write_count(), 0);
    let r = f.gate.review(&p.id).unwrap();
    let request = consume_request(&r, Decision::Allow, 0);
    assert_eq!(f.gate.consume(request).unwrap(), State::Applying);
    assert_eq!(f.store.write_count(), 0);
    assert!(f.gate.receipt(&p.id).unwrap().is_none());
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 1);
    assert_eq!(f.gate.apply(&p.id).unwrap(), State::Applied);
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(), NEW);
    assert_eq!(f.store.write_count(), 1);
    let receipt = f.gate.receipt(&p.id).unwrap().unwrap();
    assert!(receipt.contains(&p.id));
    assert!(receipt.contains(&sha256(NEW)));
    let receipt_value: Value = serde_json::from_str(&receipt).unwrap();
    assert_eq!(receipt_value["v"], 3);
    assert_eq!(receipt_value["kind"], "change");
    assert_eq!(receipt_value["approver"], f.cfg.owner.subject);
    assert_eq!(receipt_value["pubkey_fp"], &f.cfg.gate_pubkey_sha256[..16]);
    assert_eq!(
        receipt_value["gate_pubkey_sha256"],
        f.cfg.gate_pubkey_sha256
    );
    assert_eq!(receipt_value["owner_accepted_at_ms"], START);
    assert_eq!(receipt_value["owner_authorization"]["version"], 1);
    assert_eq!(
        receipt_value["owner_authorization"]["kind"],
        "aukora-owner-authorization-ref/v1"
    );
    assert!(
        receipt_value["owner_consumption"]["review_issue"]["seq"]
            .as_i64()
            .unwrap()
            > 0
    );
    assert_eq!(
        receipt_value["owner_consumption"]["review_issue"]["hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert!(f.gate.review(&p.id).is_err());
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(f.gate.receipt(&p.id).unwrap().unwrap(), receipt);
    assert_eq!(f.gate.recover().unwrap(), 0);
}

#[test]
fn approval_survives_restart_but_spent_proof_cannot_replay() {
    // Prime packages/boundary-gate/checks/harness-boundary.mjs: restart report preserves the exact owner pending row and signed review.
    // Prime tests/owner-passkey-gate.test.mjs: replay across restart.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    let mut reopened = reopen(&mut f);
    assert_eq!(reopened.state(&p.id).unwrap(), Some(State::Pending));
    assert_eq!(
        reopened
            .consume(consume_request(&r, Decision::Allow, 0))
            .unwrap(),
        State::Applying
    );
    assert_eq!(reopened.apply(&p.id).unwrap(), State::Applied);
    drop(reopened);
    let mut reopened = reopen(&mut f);
    assert!(reopened
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert!(reopened.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(terminal_rows(&reopened.db, &p.id), 1);
}

#[test]
fn review_is_full_fresh_and_latest_only() {
    // Prime packages/boundary-gate/checks/owner-review.mjs: review gives full stored bytes/diff and a fresh challenge; approve applies once with a signed receipt.
    // Prime tests/aukora-owner-authorization.test.mjs: a newer review invalidates the earlier challenge and proof.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let first = f.gate.review(&p.id).unwrap();
    let second = f.gate.review(&p.id).unwrap();
    assert_eq!(hex::decode(&first.challenge).unwrap().len(), 32);
    assert_ne!(first.challenge, second.challenge);
    assert_eq!(first.base_sha256, sha256(BASE));
    assert_eq!(first.new_sha256, sha256(NEW));
    assert_eq!(first.display_sha256, sha256(&first.card_bytes));
    assert_eq!(first.expires_at, START + f.cfg.limits.review_ttl_ms);
    let card = std::str::from_utf8(&first.card_bytes).unwrap();
    let card_value: Value = serde_json::from_str(card).unwrap();
    assert_eq!(
        card_value["from_to"]["new"],
        String::from_utf8(NEW.to_vec()).unwrap()
    );
    assert!(card.contains("model_note"));
    assert!(f
        .gate
        .consume(consume_request(&first, Decision::Allow, 0))
        .is_err());
    assert!(f
        .gate
        .consume(consume_request(&second, Decision::Allow, 0))
        .is_err());
    let fresh = f.gate.review(&p.id).unwrap();
    assert_eq!(
        f.gate
            .consume(consume_request(&fresh, Decision::Allow, 0))
            .unwrap(),
        State::Applying
    );
    assert_eq!(f.gate.apply(&p.id).unwrap(), State::Applied);
}

#[test]
fn malformed_or_substituted_approval_burns_review() {
    // Prime packages/boundary-gate/checks/owner-review.mjs: refuse changes nothing; wrong/forged/expired/mismatched decisions are refused and consume the challenge.
    // Prime tests/aukora-owner-authorization.test.mjs: every G authorization field is checked against the independent review.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    for alteration in 0..6 {
        let r = f.gate.review(&p.id).unwrap();
        let mut request = consume_request(&r, Decision::Allow, 0);
        match alteration {
            0 => request.challenge = "44".repeat(32),
            1 => request.base_sha256 = "55".repeat(32),
            2 => request.new_sha256 = "66".repeat(32),
            3 => request.display_sha256 = "77".repeat(32),
            4 => request.proof.clear(),
            5 => request.proof = TestProof::sign_with(&r.auth_bytes, 0, 8),
            _ => unreachable!(),
        }
        assert!(f.gate.consume(request).is_err(), "alteration {alteration}");
        assert!(
            f.gate
                .consume(consume_request(&r, Decision::Allow, 0))
                .is_err(),
            "burn {alteration}"
        );
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
        assert_eq!(f.store.write_count(), 0);
        assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    }
}

#[test]
fn proof_for_other_review_or_other_proposal_is_refused() {
    // Prime packages/owner-key/checks/authorization.test.mjs: changed operation, target, hashes, gate, challenge, owner and expiry cannot be substituted.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let old = f.gate.review(&p.id).unwrap();
    let current = f.gate.review(&p.id).unwrap();
    let mut request = consume_request(&current, Decision::Allow, 0);
    request.proof = TestProof::sign(&old.auth_bytes, 0);
    assert!(f.gate.consume(request).is_err());
    let current = f.gate.review(&p.id).unwrap();
    let mut altered_auth = current.auth_bytes.clone();
    altered_auth.push(b' ');
    let mut request = consume_request(&current, Decision::Allow, 0);
    request.proof = TestProof::sign(&altered_auth, 0);
    assert!(f.gate.consume(request).is_err());
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn stale_base_at_approval_refuses_without_a_spend_or_write() {
    // Prime packages/boundary-gate/checks/gate.mjs: owner approval: single use, signed receipt with HMAC evidence, replay/expiry/stale/truncation refused.
    // Prime packages/owner-key/checks/gate-caller.test.mjs: missing custody, substituted proof, legacy approval and stale actual target never authorize effects.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.store.set(OTHER);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(), OTHER);
    f.store.set(BASE);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
}

#[test]
fn stale_base_after_spend_is_not_overwritten_or_retried() {
    // Prime tests/aukora-owner-authorization.test.mjs: owner-authorized apply rechecks the base after spend and refuses without retry.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.store.set(OTHER);
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(), OTHER);
    assert_eq!(f.store.write_count(), 0);
    f.gate.recover().unwrap();
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Failed));
    assert!(f.gate.apply(&p.id).is_err());
    assert!(f.gate.retire_authorization(&p.id).is_err());
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
}

#[test]
fn decline_then_execute_has_zero_effects() {
    // Prime tests/aukora-owner-authorization.test.mjs: rejecting a review requires no proof and cannot trigger a target write.
    // Prime packages/boundary-gate/checks/gate.mjs: propose channel can never approve: no approve op, every non-closing outcome refused and recorded.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    let mut deny = consume_request(&r, Decision::Deny, 0);
    deny.proof.clear();
    assert_eq!(f.gate.consume(deny).unwrap(), State::Refused);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert!(f.gate.apply(&p.id).is_err());
    assert!(f.gate.review(&p.id).is_err());
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(), BASE);
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
}

#[test]
fn unknown_never_allows_and_never_retires() {
    // Prime unknown decision burns this review and leaves the proposal pending.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    let result = f.gate.consume(consume_request(&r, Decision::Unknown, 0));
    assert!(result.is_err() || matches!(result, Ok(State::Pending)));
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 0);
    assert_eq!(f.store.write_count(), 0);
    assert!(f.gate.receipt(&p.id).unwrap().is_none());
    let fresh = f.gate.review(&p.id).unwrap();
    assert_ne!(fresh.challenge, r.challenge);
}

#[test]
fn proposal_and_review_expire_at_the_exact_deadline() {
    // Prime tests/aukora-owner-authorization.test.mjs: the authorization expires at its exact deadline.
    // Prime packages/boundary-gate/checks/owner-review.mjs: an expired pending proposal is swept live: not listed to the owner, does not block the next proposal, cannot be reviewed.
    for is_proposal in [false, true] {
        let mut f = fixture();
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        let r = f.gate.review(&p.id).unwrap();
        f.clock.set(if is_proposal {
            p.expires_at
        } else {
            r.expires_at
        });
        assert!(f
            .gate
            .consume(consume_request(&r, Decision::Allow, 0))
            .is_err());
        assert_eq!(f.store.write_count(), 0);
        if is_proposal {
            f.gate.recover().unwrap();
            assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Expired));
            assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
        }
    }
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.clock.set(r.expires_at - 1);
    assert_eq!(
        f.gate
            .consume(consume_request(&r, Decision::Allow, 0))
            .unwrap(),
        State::Applying
    );
    f.clock.set(p.expires_at + 1);
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Failed));
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn late_verifier_expiry_rolls_back_acceptance_and_burns_challenge() {
    // Prime tests/aukora-owner-authorization.test.mjs: final commit rechecks current expiry and fresh synchronous trusted state.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.proof.advance_to.store(r.expires_at, Ordering::SeqCst);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    assert_ne!(f.gate.state(&p.id).unwrap(), Some(State::Applying));
    f.proof.advance_to.store(0, Ordering::SeqCst);
    f.clock.set(START);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn owner_epoch_or_binding_change_invalidates_review() {
    // Prime tests/aukora-owner-authorization.test.mjs: commit rechecks epoch, root, registry, and activation against current trusted state.
    for change_binding in [false, true] {
        let mut f = fixture();
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        let r = f.gate.review(&p.id).unwrap();
        let mut owner = f.cfg.owner.clone();
        owner.epoch += 1;
        if change_binding {
            owner.binding_sha256 = "44".repeat(32);
        }
        f.gate.owner_update(owner).unwrap();
        assert!(f
            .gate
            .consume(consume_request(&r, Decision::Allow, 0))
            .is_err());
        assert_eq!(f.store.write_count(), 0);
    }
}

#[test]
fn ledger_failure_rolls_back_spend_but_burns_live_review() {
    // Prime tests/aukora-owner-authorization.test.mjs: either ignored CAS rolls back the accepted proof, spend, and applying transition.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.ledger.fail_next.store(true, Ordering::SeqCst);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    assert_eq!(f.store.write_count(), 0);
    let fresh = f.gate.review(&p.id).unwrap();
    assert_eq!(
        f.gate
            .consume(consume_request(&fresh, Decision::Allow, 1))
            .unwrap(),
        State::Applying
    );
}

#[test]
fn counters_allow_zero_and_refuse_nonzero_reuse() {
    // Prime plan/SPEC.md §4: counter of 0 is valid; monotonicity only when both values are non-zero; replay rests on the challenge.
    let mut f = fixture();
    for (counter, expected) in [(0, true), (1, true), (1, false), (0, false), (2, true)] {
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        let r = f.gate.review(&p.id).unwrap();
        let result = f
            .gate
            .consume(consume_request(&r, Decision::Allow, counter));
        if expected {
            assert_eq!(result.unwrap(), State::Applying);
            assert_eq!(f.gate.apply(&p.id).unwrap(), State::Applied);
            f.store.set(BASE);
        } else {
            assert!(result.is_err());
            assert_eq!(f.store.write_count(), 2);
            let denial = f.gate.review(&p.id).unwrap();
            f.gate
                .consume(consume_request(&denial, Decision::Deny, 0))
                .unwrap();
        }
    }
    assert_eq!(f.store.write_count(), 3);
}

#[test]
fn two_connections_consume_one_signed_proof_once() {
    // Lifetime flock admits a single Gate, even before a challenge is consumed.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    let second = Connection::open(f.directory.path().join("gate.db")).unwrap();
    let result = Gate::open(
        second,
        f.cfg.clone(),
        vec![target_spec()],
        f.store.clone(),
        f.ledger.clone(),
        f.proof.clone(),
        f.clock.clone(),
    );
    assert!(result.is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert_eq!(
        f.gate
            .consume(consume_request(&r, Decision::Allow, 1))
            .unwrap(),
        State::Applying
    );
    assert_eq!(f.gate.apply(&p.id).unwrap(), State::Applied);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 1);
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
}

#[test]
fn retirement_is_owner_signed_idempotent_and_burns_identifiers() {
    // Prime #7 I1-I9, summarized in plan/CARRY-LIST.md: pending only, owner proof, one receipt, burned operation and idempotency ids.
    let mut f = fixture();
    let request = proposal_request(NEW);
    let key = request.idempotency_key.clone();
    let p = f.gate.propose(request).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    let auth = f.gate.retire_authorization(&p.id).unwrap();
    let auth_text = String::from_utf8(auth.clone()).unwrap();
    assert!(auth_text.contains("retire"));
    assert!(auth_text.contains(&p.id));
    assert!(auth_text.contains(&p.digest));
    assert!(f
        .gate
        .retire(&p.id, &TestProof::sign_with(&auth, 0, 8))
        .is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    let receipt = f.gate.retire(&p.id, &TestProof::sign(&auth, 0)).unwrap();
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Retired));
    assert_eq!(
        f.gate.retire(&p.id, &TestProof::sign(&auth, 0)).unwrap(),
        receipt
    );
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.retire"), 1);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert!(f.gate.apply(&p.id).is_err());
    let mut reuse = proposal_request(NEW);
    reuse.idempotency_key = key;
    assert!(f.gate.propose(reuse).is_err());
    f.gate.prune().unwrap();
    assert_eq!(
        f.gate.retire(&p.id, &TestProof::sign(&auth, 0)).unwrap(),
        receipt
    );
    let mut reopened = reopen(&mut f);
    assert_eq!(
        reopened.retire(&p.id, &TestProof::sign(&auth, 0)).unwrap(),
        receipt
    );
    assert!(reopened.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn reviewed_live_proposal_blocks_replacement_until_retired() {
    // Prime #7 I1-I9, summarized in plan/CARRY-LIST.md: a live reviewed operation blocks a fresh proposal for the same target.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    f.gate.review(&p.id).unwrap();
    assert!(f.gate.propose(proposal_request(OTHER)).is_err());
    let auth = f.gate.retire_authorization(&p.id).unwrap();
    f.gate.retire(&p.id, &TestProof::sign(&auth, 0)).unwrap();
    let replacement = f.gate.propose(proposal_request(OTHER)).unwrap();
    assert_ne!(replacement.id, p.id);
    assert_eq!(replacement.state, State::Pending);
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn closed_and_spent_states_cannot_be_retired() {
    // Prime #7 I1-I9, summarized in plan/CARRY-LIST.md: retire is pending-only and unknown cannot be retired.
    for state in [
        State::Refused,
        State::Expired,
        State::Applying,
        State::Applied,
    ] {
        let mut f = fixture();
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        match state {
            State::Refused => {
                f.gate.reject(&p.id).unwrap();
            }
            State::Expired => {
                f.clock.set(p.expires_at);
                f.gate.recover().unwrap();
            }
            State::Applying | State::Applied => {
                let r = f.gate.review(&p.id).unwrap();
                f.gate
                    .consume(consume_request(&r, Decision::Allow, 0))
                    .unwrap();
                if state == State::Applied {
                    f.gate.apply(&p.id).unwrap();
                }
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(
                f.gate.retire_authorization(&p.id),
                Err(Error::Refused("gate:not-retirable"))
            ),
            "{state:?}"
        );
    }
}

#[test]
fn prune_retains_every_pending_and_applied_blob_reference() {
    // Prime packages/boundary-gate/src/gate.mjs: prune retains every pending base/new and every retained applied version.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    assert_eq!(f.gate.prune().unwrap(), 0);
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    assert_eq!(f.gate.prune().unwrap(), 0);
    assert_eq!(f.gate.apply(&p.id).unwrap(), State::Applied);
    assert_eq!(f.gate.prune().unwrap(), 0);
    assert!(f.gate.receipt(&p.id).unwrap().is_some());
    let mut request = proposal_request(OTHER);
    request.base_sha256 = sha256(NEW);
    let abandoned = f.gate.propose(request).unwrap();
    f.gate.cancel(&abandoned.id).unwrap();
    assert_eq!(f.gate.prune().unwrap(), 1);
    assert_eq!(f.gate.prune().unwrap(), 0);
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Applied));
}

#[test]
fn blob_corruption_before_approval_burns_review_without_effect() {
    // Prime tests/aukora-owner-authorization.test.mjs: stored bytes are hash-checked before durable consumption.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .db
        .execute(
            "UPDATE gate_blobs SET bytes=? WHERE sha256=?",
            params![OTHER, p.new_sha256],
        )
        .unwrap();
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
}

#[test]
fn blob_corruption_after_spend_is_never_written() {
    // Prime packages/boundary-gate/src/gate.mjs: applyConsumed uses only hash-checked bytes from the gate's version store.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.gate
        .db
        .execute(
            "UPDATE gate_blobs SET bytes=? WHERE sha256=?",
            params![OTHER, p.new_sha256],
        )
        .unwrap();
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(), BASE);
    f.gate.recover().unwrap();
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Failed));
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
}

#[test]
fn failed_write_is_spent_terminal_and_never_retried() {
    // Prime packages/boundary-gate/checks/gate.mjs: crash reconciliation never replays an approval; stale pending expire at start.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.store.fail_write.store(true, Ordering::SeqCst);
    assert!(f.gate.apply(&p.id).is_err());
    f.store.fail_write.store(false, Ordering::SeqCst);
    f.gate.recover().unwrap();
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Failed));
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 0);
    assert!(f.gate.receipt(&p.id).unwrap().is_none());
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
}

#[test]
fn post_write_hash_mismatch_never_fabricates_success() {
    // Prime packages/boundary-gate/src/gate.mjs: applyConsumed verifies post-write hash and retains uncertainty without retry.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.store.corrupt_write.store(true, Ordering::SeqCst);
    assert!(f.gate.apply(&p.id).is_err());
    f.gate.recover().unwrap();
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Conflict));
    assert!(f.gate.receipt(&p.id).unwrap().is_none());
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
}

#[test]
fn receipt_and_terminal_ledger_failure_preserve_incomplete_not_applied() {
    // Prime tests/aukora-owner-authorization.test.mjs: interrupted finalization is reconciled on reopen without a second effect.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.ledger.fail_next.store(true, Ordering::SeqCst);
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(), NEW);
    assert!(f.gate.receipt(&p.id).unwrap().is_none());
    let mut reopened = reopen(&mut f);
    assert_eq!(reopened.state(&p.id).unwrap(), Some(State::Incomplete));
    assert!(reopened.apply(&p.id).is_err());
    assert!(reopened.receipt(&p.id).unwrap().is_none());
    assert_eq!(terminal_rows(&reopened.db, &p.id), 1);
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn recovery_reads_but_never_writes_and_terminal_states_are_final() {
    // Prime tests/aukora-owner-authorization.test.mjs: interrupted finalization is reconciled on reopen without a second effect.
    // Sovereign plan/SPEC.md §4 deliberately changes Prime legacy bytes-present recovery from applied to incomplete.
    for (bytes, expected) in [
        (BASE, State::Failed),
        (NEW, State::Incomplete),
        (OTHER, State::Conflict),
    ] {
        let mut f = fixture();
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        let r = f.gate.review(&p.id).unwrap();
        f.gate
            .consume(consume_request(&r, Decision::Allow, 0))
            .unwrap();
        f.gate
            .db
            .execute(
                "UPDATE gate_proposals SET write_claimed=1 WHERE id=?",
                [&p.id],
            )
            .unwrap();
        f.store.set(bytes);
        let mut reopened = reopen(&mut f);
        assert_eq!(reopened.state(&p.id).unwrap(), Some(expected));
        assert_eq!(terminal_rows(&reopened.db, &p.id), 1);
        assert_eq!(reopened.recover().unwrap(), 0);
        f.store.set(BASE);
        assert_eq!(reopened.recover().unwrap(), 0);
        assert_eq!(reopened.state(&p.id).unwrap(), Some(expected));
        assert!(reopened.apply(&p.id).is_err());
        assert!(reopened.receipt(&p.id).unwrap().is_none());
        assert_eq!(f.store.write_count(), 0);
    }
}

#[test]
fn unreadable_recovery_is_terminal_unknown_and_cannot_retire_or_retry() {
    // A claimed unreadable target remains applying with a non-terminal fact.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.gate
        .db
        .execute(
            "UPDATE gate_proposals SET write_claimed=1 WHERE id=?",
            [&p.id],
        )
        .unwrap();
    f.store.unreadable.store(true, Ordering::SeqCst);
    let mut reopened = reopen(&mut f);
    assert_eq!(reopened.state(&p.id).unwrap(), Some(State::Applying));
    assert!(reopened.receipt(&p.id).unwrap().is_none());
    assert_eq!(terminal_rows(&reopened.db, &p.id), 0);
    let facts: i64 = reopened
        .db
        .query_row(
            "SELECT COUNT(*) FROM aura WHERE op=? AND kind='gate.recover' AND phase='fact'",
            [&p.id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(facts > 0);
    assert!(reopened.apply(&p.id).is_err());
    f.store.unreadable.store(false, Ordering::SeqCst);
    drop(reopened);
    let reopened = reopen(&mut f);
    assert_eq!(reopened.state(&p.id).unwrap(), Some(State::Failed));
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(terminal_rows(&reopened.db, &p.id), 1);
}

#[test]
fn ignored_challenge_proposal_or_counter_cas_rolls_back_every_acceptance_fact() {
    // Prime tests/aukora-owner-authorization.test.mjs: either ignored CAS rolls back the accepted proof, spend, and applying transition.
    for trigger in [
        "CREATE TRIGGER ignore_cas BEFORE UPDATE ON gate_reviews WHEN NEW.state='spent' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TRIGGER ignore_cas BEFORE UPDATE ON gate_proposals WHEN NEW.state='applying' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TRIGGER ignore_cas BEFORE UPDATE OF sign_count ON gate_owner BEGIN SELECT RAISE(IGNORE); END",
    ] {
        let mut f = fixture();
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        let r = f.gate.review(&p.id).unwrap();
        f.gate.db.execute_batch(trigger).unwrap();
        assert!(f.gate.consume(consume_request(&r, Decision::Allow, 1)).is_err());
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
        assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
        let consumed: i64 = f.gate.db.query_row("SELECT COUNT(*) FROM gate_consumptions", [], |r| r.get(0)).unwrap();
        assert_eq!(consumed, 0);
        let counter: i64 = f.gate.db.query_row("SELECT sign_count FROM gate_owner", [], |r| r.get(0)).unwrap();
        assert_eq!(counter, 0);
        f.gate.db.execute_batch("DROP TRIGGER ignore_cas").unwrap();
        assert!(f.gate.consume(consume_request(&r, Decision::Allow, 1)).is_err());
        assert_eq!(f.store.write_count(), 0);
    }
}

#[test]
fn zero_counter_never_updates_counter_and_nonzero_counter_does() {
    // Sovereign SPEC §4: counter compare-and-set only when non-zero.
    let mut f = fixture();
    f.gate.db.execute_batch("CREATE TRIGGER no_counter_write BEFORE UPDATE OF sign_count ON gate_owner BEGIN SELECT RAISE(ABORT,'counter update forbidden'); END").unwrap();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    assert_eq!(
        f.gate
            .consume(consume_request(&r, Decision::Allow, 0))
            .unwrap(),
        State::Applying
    );
    assert_eq!(f.gate.apply(&p.id).unwrap(), State::Applied);
    f.store.set(BASE);
    let p = f.gate.propose(proposal_request(OTHER)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn commit_failure_burns_challenge_without_retaining_acceptance() {
    // Sovereign Issue #4: any error inside consume burns the challenge while retaining the writer lock.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate.db.execute_batch(
        "CREATE TABLE test_parent(id INTEGER PRIMARY KEY);
         CREATE TABLE test_deferred(parent INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER fail_consume_commit AFTER INSERT ON gate_consumptions BEGIN INSERT INTO test_deferred VALUES(1); END;"
    ).unwrap();
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    let consumed: i64 = f
        .gate
        .db
        .query_row("SELECT COUNT(*) FROM gate_consumptions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(consumed, 0);
    let deferred: i64 = f
        .gate
        .db
        .query_row("SELECT COUNT(*) FROM test_deferred", [], |r| r.get(0))
        .unwrap();
    assert_eq!(deferred, 0);
    f.gate
        .db
        .execute_batch("DROP TRIGGER fail_consume_commit")
        .unwrap();
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    let fresh = f.gate.review(&p.id).unwrap();
    assert_eq!(
        f.gate
            .consume(consume_request(&fresh, Decision::Allow, 1))
            .unwrap(),
        State::Applying
    );
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn failing_clock_during_consume_still_burns_review() {
    // Prime tests/aukora-owner-authorization.test.mjs: final commit rechecks current expiry and fresh synchronous trusted state.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.proof.fail_clock.store(true, Ordering::SeqCst);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    f.proof.fail_clock.store(false, Ordering::SeqCst);
    f.clock.fail.store(false, Ordering::SeqCst);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 1))
        .is_err());
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn lost_or_damaged_review_issuance_never_authorizes_an_effect() {
    // Prime tests/aukora-owner-authorization.test.mjs: review binds the exact G body to a durable signed issuance anchor.
    for remove in [false, true] {
        let mut f = fixture();
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        let r = f.gate.review(&p.id).unwrap();
        if remove {
            f.gate
                .db
                .execute_batch(
                    "DROP TRIGGER aura_no_delete; DELETE FROM aura WHERE kind='gate.review'",
                )
                .unwrap();
        } else {
            f.gate.db.execute_batch("DROP TRIGGER aura_no_update; UPDATE aura SET body='{}' WHERE kind='gate.review'").unwrap();
        }
        assert!(f
            .gate
            .consume(consume_request(&r, Decision::Allow, 0))
            .is_err());
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
        assert_eq!(f.store.write_count(), 0);
        assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    }
}

#[test]
fn missing_completion_storage_before_consume_refuses_and_burns() {
    // Prime tests/aukora-owner-authorization.test.mjs: missing completion storage before authorization refuses the effect and rolls back acceptance.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate.db.execute_batch("DROP TABLE gate_receipts").unwrap();
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    let mut reopened = reopen(&mut f);
    assert!(reopened
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn lost_or_damaged_completion_is_never_recreated_by_receipt_or_recovery() {
    // Prime tests/aukora-owner-authorization.test.mjs: missing completion evidence after apply is unavailable and cannot be reconstructed by polling.
    // Prime tests/aukora-owner-authorization.test.mjs: damaged retained bytes or coordinates cannot be rebuilt from the signed apply ledger.
    for damage in 0..3 {
        let mut f = fixture();
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        let r = f.gate.review(&p.id).unwrap();
        f.gate
            .consume(consume_request(&r, Decision::Allow, 0))
            .unwrap();
        f.gate.apply(&p.id).unwrap();
        match damage {
            0 => f.gate.db.execute_batch("DROP TRIGGER gate_receipts_no_delete; DELETE FROM gate_receipts").unwrap(),
            1 => f.gate.db.execute_batch("DROP TRIGGER gate_receipts_no_update; UPDATE gate_receipts SET body='{}'").unwrap(),
            2 => f.gate.db.execute_batch("DROP TRIGGER aura_no_update; UPDATE aura SET body='{}' WHERE kind='gate.apply'").unwrap(),
            _ => unreachable!(),
        }
        assert!(f.gate.receipt(&p.id).ok().flatten().is_none());
        assert_eq!(f.gate.recover().unwrap(), 0);
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Applied));
        assert!(f.gate.apply(&p.id).is_err());
        assert!(f.gate.receipt(&p.id).ok().flatten().is_none());
        assert_eq!(f.store.write_count(), 1);
    }
}

#[test]
fn retained_rows_cannot_rewind_by_update_delete_or_replace() {
    // Prime packages/boundary-gate/src/ledger.mjs: durable review, consumption and original completion facts cannot revive or disappear.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    assert!(f
        .gate
        .db
        .execute(
            "UPDATE gate_proposals SET state='applied' WHERE id=?",
            [&p.id]
        )
        .is_err());
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.gate.apply(&p.id).unwrap();
    for sql in [
        "UPDATE gate_proposals SET state='pending'",
        "DELETE FROM gate_proposals",
        "INSERT OR REPLACE INTO gate_proposals SELECT id,target,base_sha256,new_sha256,digest,idempotency_key,note,cell,created,expires_at,updated,'pending',reviewed,operator_only,write_claimed FROM gate_proposals",
        "UPDATE gate_reviews SET state='live'",
        "DELETE FROM gate_reviews",
        "INSERT OR REPLACE INTO gate_reviews SELECT challenge,proposal_id,base_sha256,new_sha256,display_sha256,auth,card,owner_text,issued_at,expires_at,issue_seq,issue_hash,'live' FROM gate_reviews",
        "UPDATE gate_consumptions SET proof_sha256='bad'",
        "DELETE FROM gate_consumptions",
        "INSERT OR REPLACE INTO gate_consumptions SELECT * FROM gate_consumptions",
        "UPDATE gate_receipts SET body='{}'",
        "DELETE FROM gate_receipts",
        "INSERT OR REPLACE INTO gate_receipts SELECT * FROM gate_receipts",
        "UPDATE aura SET body='{}'",
        "DELETE FROM aura",
        "INSERT OR REPLACE INTO aura SELECT * FROM aura",
        "UPDATE gate_owner SET epoch=0",
        "DELETE FROM gate_owner",
        "INSERT OR REPLACE INTO gate_owner SELECT * FROM gate_owner",
    ] {
        assert!(f.gate.db.execute_batch(sql).is_err(), "{sql}");
    }
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Applied));
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn decision_property_requires_an_explicit_allow() {
    // plan/CARRY-LIST.md I-04: exhaustive three-valued property; the twin collapsing Unknown must fail.
    for (decision, expected) in [
        (Decision::Deny, false),
        (Decision::Unknown, false),
        (Decision::Allow, true),
    ] {
        assert_eq!(decision.permits(), expected, "{decision:?}");
    }
}

#[test]
fn operator_proposal_cannot_be_created_or_closed_by_guest() {
    // Prime packages/boundary-gate/checks/harness-boundary.mjs: owner-only close refuses every propose outcome without consuming the owner review.
    let mut f = fixture();
    release_fixture_gate(&mut f);
    let mut spec = target_spec();
    spec.operator_only = true;
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    let mut gate = Gate::open(
        db,
        f.cfg,
        vec![spec],
        f.store.clone(),
        f.ledger,
        f.proof,
        f.clock,
    )
    .unwrap();
    assert!(gate.propose(proposal_request(NEW)).is_err());
    let p = gate.raise(proposal_request(NEW)).unwrap();
    assert!(gate.cancel(&p.id).is_err());
    assert_eq!(gate.state(&p.id).unwrap(), Some(State::Pending));
    let r = gate.review(&p.id).unwrap();
    assert!(gate.cancel(&p.id).is_err());
    assert_eq!(
        gate.consume(consume_request(&r, Decision::Allow, 0))
            .unwrap(),
        State::Applying
    );
    assert_eq!(gate.apply(&p.id).unwrap(), State::Applied);
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn receipt_commit_failure_is_terminal_without_a_second_write() {
    // Sovereign Issue #4: receipt and its terminal ledger row commit together; every error preserves a spent effect.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.gate.db.execute_batch(
        "CREATE TABLE test_parent(id INTEGER PRIMARY KEY);
         CREATE TABLE test_deferred(parent INTEGER REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER fail_receipt_commit AFTER INSERT ON gate_receipts BEGIN INSERT INTO test_deferred VALUES(1); END;"
    ).unwrap();
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Incomplete));
    assert!(f.gate.receipt(&p.id).unwrap().is_none());
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.apply"), 0);
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
    f.gate
        .db
        .execute_batch("DROP TRIGGER fail_receipt_commit")
        .unwrap();
    f.store.set(BASE);
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(f.gate.recover().unwrap(), 0);
}

#[test]
fn storage_guards_report_their_own_refusals() {
    // Sovereign Issue #4: independent guards remain tested when a later guard also refuses.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let wrong_owner = "{}";
    assert!(matches!(
        assert_owner(&f.gate.db, wrong_owner),
        Err(Error::Refused("gate:owner-state-changed"))
    ));
    f.gate
        .db
        .execute(
            "UPDATE gate_blobs SET bytes=? WHERE sha256=?",
            params![OTHER, p.new_sha256],
        )
        .unwrap();
    assert!(matches!(
        load_blob(&f.gate.db, &p.new_sha256),
        Err(Error::Refused("gate:blob-hash"))
    ));
    let missing = "ee".repeat(32);
    assert!(matches!(
        load_blob(&f.gate.db, &missing),
        Err(Error::Refused("gate:blob-missing"))
    ));
    f.gate.db.execute_batch("CREATE TRIGGER ignore_transition BEFORE UPDATE ON gate_proposals WHEN NEW.state='applying' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let tx = f.gate.db.transaction().unwrap();
    assert!(matches!(
        transition(&tx, &p, State::Applying, START),
        Err(Error::Refused("gate:state-conflict"))
    ));
    counter_cas(&tx, &"33".repeat(32), 1).unwrap();
    assert!(matches!(
        counter_cas(&tx, &"33".repeat(32), 1),
        Err(Error::Refused("gate:counter-replay"))
    ));
    tx.execute_batch("CREATE TRIGGER ignore_counter BEFORE UPDATE OF sign_count ON gate_owner BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert!(matches!(
        counter_cas(&tx, &"33".repeat(32), 2),
        Err(Error::Refused("gate:counter-conflict"))
    ));
}

#[test]
fn ignored_invalidation_cannot_revive_a_burned_challenge() {
    // Sovereign Issue #4: every refused owner attempt burns its challenge even if a snapshot invalidation is ignored.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate.db.execute_batch("CREATE TRIGGER ignore_invalidation BEFORE UPDATE ON gate_reviews WHEN NEW.state='invalidated' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let mut bad = consume_request(&r, Decision::Allow, 0);
    bad.proof.clear();
    assert!(f.gate.consume(bad).is_err());
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert_eq!(f.store.write_count(), 0);
    let burned: i64 = f
        .gate
        .db
        .query_row(
            "SELECT COUNT(*) FROM gate_burns WHERE challenge=?",
            [&r.challenge],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(burned, 1);
    for sql in [
        "UPDATE gate_burns SET challenge=challenge",
        "DELETE FROM gate_burns",
        "INSERT OR REPLACE INTO gate_burns SELECT * FROM gate_burns",
    ] {
        assert!(f.gate.db.execute_batch(sql).is_err(), "{sql}");
    }
}

#[test]
fn authentic_proposal_row_cannot_substitute_for_review_issuance() {
    // Prime tests/aukora-owner-authorization.test.mjs: review binds the exact G body to a durable signed issuance anchor.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    let (seq, hash): (i64, String) = f
        .gate
        .db
        .query_row(
            "SELECT seq,hash FROM aura WHERE kind='gate.propose' AND op=?",
            [&p.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    f.gate
        .db
        .execute_batch("DROP TRIGGER gate_reviews_facts")
        .unwrap();
    f.gate
        .db
        .execute(
            "UPDATE gate_reviews SET issue_seq=?,issue_hash=? WHERE challenge=?",
            params![seq, hash, r.challenge],
        )
        .unwrap();
    assert!(matches!(
        f.gate.consume(consume_request(&r, Decision::Allow, 0)),
        Err(Error::Refused("gate:review-evidence-unavailable"))
    ));
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
}

#[test]
fn authentic_proposal_row_cannot_substitute_for_consumption() {
    // Prime tests/aukora-owner-authorization.test.mjs: signed v3 receipt joins the exact proof, issuance, and durable consumption.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    let (seq, hash): (i64, String) = f
        .gate
        .db
        .query_row(
            "SELECT seq,hash FROM aura WHERE kind='gate.propose' AND op=?",
            [&p.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    f.gate
        .db
        .execute_batch("DROP TRIGGER gate_consumptions_no_update")
        .unwrap();
    f.gate
        .db
        .execute(
            "UPDATE gate_consumptions SET consume_seq=?,consume_hash=? WHERE proposal_id=?",
            params![seq, hash, p.id],
        )
        .unwrap();
    assert!(matches!(
        f.gate.apply(&p.id),
        Err(Error::Refused("gate:consumption-evidence-unavailable"))
    ));
    assert_eq!(f.store.write_count(), 0);
    assert!(f.gate.receipt(&p.id).unwrap().is_none());
}

#[test]
fn durable_write_claim_prevents_retry_when_settlement_audit_fails() {
    // Sovereign Issue #4: any uncertain write is spent even if both receipt and recovery ledger appends fail.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    f.ledger.fail_count.store(2, Ordering::SeqCst);
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Applying));
    assert_eq!(f.store.write_count(), 1);
    assert!(f.gate.receipt(&p.id).unwrap().is_none());
    f.store.set(BASE);
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(), 1);
    f.gate.recover().unwrap();
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Failed));
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
}

#[test]
fn regenerated_card_must_equal_the_signed_display() {
    // Prime tests/owner-passkey-gate.test.mjs: exact card changed after review refuses.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate.targets.get_mut(TARGET).unwrap().says = "Trusted description changed after review.";
    assert!(matches!(
        f.gate.consume(consume_request(&r, Decision::Allow, 0)),
        Err(Error::Refused("gate:display-mismatch"))
    ));
    assert_eq!(f.store.write_count(), 0);
    assert!(f
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
}

#[test]
fn ledger_callback_cannot_expire_issuance_or_final_consumption() {
    // Prime tests/aukora-owner-authorization.test.mjs: late trusted-state callback expiry rolls back issuance and its signed anchor.
    // Prime tests/aukora-owner-authorization.test.mjs: final commit rechecks current expiry and fresh synchronous trusted state.
    for at_issuance in [true, false] {
        let mut f = fixture();
        let p = f.gate.propose(proposal_request(NEW)).unwrap();
        if at_issuance {
            *f.ledger.advance_kind.lock().unwrap() = Some("gate.review");
            f.ledger
                .advance_to
                .store(START + f.cfg.limits.review_ttl_ms, Ordering::SeqCst);
            assert!(f.gate.review(&p.id).is_err());
            assert_eq!(count_kind(&f.gate.db, &p.id, "gate.review"), 0);
        } else {
            let r = f.gate.review(&p.id).unwrap();
            *f.ledger.advance_kind.lock().unwrap() = Some("gate.consume");
            f.ledger.advance_to.store(r.expires_at, Ordering::SeqCst);
            assert!(f
                .gate
                .consume(consume_request(&r, Decision::Allow, 1))
                .is_err());
            assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
            *f.ledger.advance_kind.lock().unwrap() = None;
            f.clock.set(START);
            assert!(f
                .gate
                .consume(consume_request(&r, Decision::Allow, 1))
                .is_err());
        }
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
        assert_eq!(f.store.write_count(), 0);
    }
}

#[test]
fn owner_raise_survives_guest_rate_window_and_cooldown_exhaustion() {
    // Guest transport, window and rejection history do not charge an owner raise.
    let mut f = review_regressions::operator_fixture(Limits {
        guest_max_per_window: 2,
        max_per_window: 1,
        reject_cooldown_ms: 60_000,
        ..permissive_limits()
    });
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    f.gate.reject(&p.id).unwrap();
    assert!(f.gate.propose(proposal_request(OTHER)).is_err());
    assert!(f.gate.propose(proposal_request(OTHER)).is_err());
    let req = review_regressions::operator_request(&f, b"release");
    let before: i64 = f
        .gate
        .db
        .query_row("SELECT used FROM gate_budget", [], |r| r.get(0))
        .unwrap();
    let p = f.gate.raise(req).unwrap();
    let after: i64 = f
        .gate
        .db
        .query_row("SELECT used FROM gate_budget", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after);
    let r = f.gate.review(&p.id).unwrap();
    f.gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    assert_eq!(f.gate.apply(&p.id).unwrap(), State::Applied);
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn gate_canonical_values_match_node_and_refuse_non_contract_integers() {
    // Frozen CONTRACTS.md C1: gate-built signed values use JavaScript UTF-16 key order and exact JSON escaping.
    let value = serde_json::json!({"\u{e000}":"late","😀":"early","text":"\u{1}\u{7f}\u{2028}\u{2029}\"\\\n","integer":9_007_199_254_740_991_i64});
    let encoded = canonical(&value).unwrap();
    let output = Command::new(test_node::node())
        .args(["-e", "function c(v){if(Array.isArray(v))return '['+v.map(c).join(',')+']';if(v!==null&&typeof v==='object')return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+c(v[k])).join(',')+'}';return JSON.stringify(v)}process.stdout.write(c(JSON.parse(process.argv[1])))", &value.to_string()])
        .output().unwrap();
    assert!(output.status.success());
    assert_eq!(encoded.as_bytes(), output.stdout);
    for number in [
        serde_json::json!(1.5),
        serde_json::json!(9_007_199_254_740_992_i64),
        serde_json::json!(-9_007_199_254_740_992_i64),
    ] {
        assert!(canonical(&number).is_err());
    }
}

#[test]
fn missing_configured_node_fails_canonical_comparison_with_variable_name() {
    let directory = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::gate_canonical_values_match_node_and_refuse_non_contract_integers",
            "--nocapture",
        ])
        .env("AUKORA_NODE", directory.path().join("missing-node"))
        .output()
        .unwrap();
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{diagnostic}");
    assert!(diagnostic.contains("AUKORA_NODE:"), "{diagnostic}");
}

#[test]
fn backup_restore_retains_retirement_receipt_and_burned_identifiers() {
    // Prime #7 I1-I9, summarized in plan/CARRY-LIST.md: restore carries retirement records.
    let mut f = fixture();
    let request = proposal_request(NEW);
    let key = request.idempotency_key.clone();
    let p = f.gate.propose(request).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    let auth = f.gate.retire_authorization(&p.id).unwrap();
    let proof = TestProof::sign(&auth, 0);
    let receipt = f.gate.retire(&p.id, &proof).unwrap();
    let backup = f.directory.path().join("restored.db");
    f.gate
        .db
        .execute("VACUUM INTO ?", [backup.to_str().unwrap()])
        .unwrap();
    let db = Connection::open(backup).unwrap();
    let mut restored = Gate::open(
        db,
        f.cfg,
        vec![target_spec()],
        f.store.clone(),
        f.ledger,
        f.proof,
        f.clock,
    )
    .unwrap();
    assert_eq!(restored.retire(&p.id, &proof).unwrap(), receipt);
    assert!(restored
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert!(restored.apply(&p.id).is_err());
    let mut request = proposal_request(NEW);
    request.idempotency_key = key;
    assert!(restored.propose(request).is_err());
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn expiry_sweeps_on_reopen_and_frees_pending_admission() {
    // Prime packages/boundary-gate/checks/gate.mjs: crash reconciliation never replays an approval; stale pending expire at start.
    let mut f = fixture_with(Limits::default());
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    f.clock.set(p.expires_at);
    let mut reopened = reopen(&mut f);
    assert_eq!(reopened.state(&p.id).unwrap(), Some(State::Expired));
    assert_eq!(terminal_rows(&reopened.db, &p.id), 1);
    assert_eq!(reopened.recover().unwrap(), 0);
    assert!(reopened.review(&p.id).is_err());
    assert!(reopened.propose(proposal_request(OTHER)).is_ok());
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn guest_budget_charges_refusals_across_reopen_and_leaves_owner_available() {
    // Prime packages/boundary-gate/checks/harness-boundary.mjs: durable budget charges refused calls across instances/reopen while exact owner proof applies.
    let limits = Limits {
        guest_max_per_window: 2,
        ..permissive_limits()
    };
    let mut f = fixture_with(limits);
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let mut wrong_target = proposal_request(OTHER);
    wrong_target.target = "plugins/unregistered/data.json".to_owned();
    assert!(f.gate.propose(wrong_target).is_err());
    let mut reopened = reopen(&mut f);
    let before: i64 = reopened
        .db
        .query_row("SELECT COUNT(*) FROM aura", [], |r| r.get(0))
        .unwrap();
    for _ in 0..5 {
        assert!(reopened.propose(proposal_request(OTHER)).is_err());
    }
    let after: i64 = reopened
        .db
        .query_row("SELECT COUNT(*) FROM aura", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after, "budget exhaustion appends no new row");
    let r = reopened.review(&p.id).unwrap();
    reopened
        .consume(consume_request(&r, Decision::Allow, 0))
        .unwrap();
    assert_eq!(reopened.apply(&p.id).unwrap(), State::Applied);
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn guest_budget_resets_only_at_window_and_reversed_clock_refuses() {
    // Prime packages/boundary-gate/checks/harness-boundary.mjs: budget has a bounded new window and a reversed gate clock never resets it.
    let limits = Limits {
        guest_max_per_window: 1,
        guest_window_ms: 1000,
        ..permissive_limits()
    };
    let mut f = fixture_with(limits);
    let mut invalid = proposal_request(NEW);
    invalid.target = "plugins/unregistered/data.json".to_owned();
    assert!(f.gate.propose(invalid).is_err());
    f.clock.set(START + 999);
    assert!(matches!(
        f.gate.propose(proposal_request(NEW)),
        Err(Error::Refused("gate:budget-exhausted"))
    ));
    f.clock.set(START - 1);
    assert!(matches!(
        f.gate.propose(proposal_request(NEW)),
        Err(Error::Refused("gate:budget-unavailable"))
    ));
    f.clock.set(START + 1000);
    assert!(f.gate.propose(proposal_request(NEW)).is_ok());
}

#[test]
fn default_pending_window_cooldown_and_dedupe_match_prime() {
    // Prime packages/boundary-gate/checks/gate.mjs: rate limits are global (not per session label): 1 pending, 3 per window, cooldown after reject, dedupe.
    let mut f = fixture_with(Limits::default());
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    assert!(f.gate.propose(proposal_request(OTHER)).is_err());
    f.gate.cancel(&p.id).unwrap();
    let p = f.gate.propose(proposal_request(OTHER)).unwrap();
    f.gate.cancel(&p.id).unwrap();
    let green = b"{\"accent\": \"#008000\"}";
    let p = f.gate.propose(proposal_request(green)).unwrap();
    f.gate.cancel(&p.id).unwrap();
    let black = b"{\"accent\": \"#000000\"}";
    assert!(f.gate.propose(proposal_request(black)).is_err());
    f.clock.advance(f.cfg.limits.window_ms + 1);
    let p = f.gate.propose(proposal_request(black)).unwrap();
    f.gate.reject(&p.id).unwrap();
    let white = b"{\"accent\": \"#FFFFFF\"}";
    assert!(f.gate.propose(proposal_request(white)).is_err());
    f.clock.advance(f.cfg.limits.reject_cooldown_ms + 1);
    assert!(f.gate.propose(proposal_request(black)).is_err());
    assert!(f.gate.propose(proposal_request(white)).is_ok());
}

#[test]
fn admission_requires_allowlist_current_base_new_bytes_and_bounded_note() {
    // Prime packages/boundary-gate/checks/gate.mjs: content rules: printable ASCII, size, schema, required and current base, no identical change.
    let mut f = fixture();
    for bad_base in ["".to_owned(), "absent".to_owned(), "ff".repeat(32)] {
        let mut request = proposal_request(NEW);
        let code = if bad_base.is_empty() {
            "gate:base-required"
        } else {
            "gate:stale-base"
        };
        request.base_sha256 = bad_base;
        assert!(matches!(f.gate.propose(request), Err(Error::Refused(actual)) if actual == code));
    }
    assert!(f.gate.propose(proposal_request(BASE)).is_err());
    let mut request = proposal_request(NEW);
    request.note = "w".repeat(4001);
    assert!(f.gate.propose(request).is_err());
    let mut request = proposal_request(NEW);
    request.target = "plugins/user/x/index.js".to_owned();
    assert!(f.gate.propose(request).is_err());
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn empty_registry_fails_closed_and_full_display_is_required() {
    // Prime packages/boundary-gate/checks/gate.mjs: a gate with an empty registry refuses every proposal (fail closed).
    // Prime packages/boundary-gate/checks/gate.mjs: owner approval: single use, signed receipt with HMAC evidence, replay/expiry/stale/truncation refused.
    let f = fixture();
    let db = fresh_database();
    initialize_test_ledger(&db);
    let mut gate = Gate::open(
        db,
        f.cfg,
        vec![],
        f.store.clone(),
        f.ledger,
        f.proof,
        f.clock,
    )
    .unwrap();
    assert!(gate.propose(proposal_request(NEW)).is_err());
    let mut small = fixture_with(Limits {
        display_max_bytes: 10,
        ..permissive_limits()
    });
    assert!(small.gate.propose(proposal_request(NEW)).is_err());
    assert_eq!(small.store.write_count(), 0);
    let mut after_review = fixture();
    let p = after_review.gate.propose(proposal_request(NEW)).unwrap();
    let r = after_review.gate.review(&p.id).unwrap();
    after_review.gate.config.limits.display_max_bytes = 10;
    assert!(after_review
        .gate
        .consume(consume_request(&r, Decision::Allow, 0))
        .is_err());
    assert_eq!(after_review.store.write_count(), 0);
}

#[derive(Clone)]
struct FileStore {
    directory: PathBuf,
}

fn sync_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

impl FileStore {
    fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_path_buf(),
        }
    }

    fn write_count(&self) -> usize {
        fs::read_to_string(self.directory.join("writes"))
            .map(|value| value.parse().unwrap())
            .unwrap_or(0)
    }
}

impl TargetStore for FileStore {
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>> {
        if target != TARGET {
            return Err(Error::Refused("gate:test-target"));
        }
        match fs::read(self.directory.join(target)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Refused("gate:test-read")),
        }
    }

    fn write(&self, target: &str, bytes: &[u8], operation_id: &str) -> Result<()> {
        if target != TARGET {
            return Err(Error::Refused("gate:test-target"));
        }
        crate::fs_store::FsStore::new(self.directory.canonicalize()?)?.write(
            target,
            bytes,
            operation_id,
        )?;
        sync_file(
            &self.directory.join("writes"),
            (self.write_count() + 1).to_string().as_bytes(),
        );
        Ok(())
    }
}

type FileGate = Gate<FileStore, TestLedger, TestProof, TestClock>;

fn file_gate(directory: &Path) -> FileGate {
    let db = Connection::open(directory.join("gate.db")).unwrap();
    initialize_test_ledger(&db);
    let clock = TestClock::new();
    Gate::open(
        db,
        Config {
            limits: permissive_limits(),
            ..config()
        },
        vec![target_spec()],
        FileStore::new(directory),
        TestLedger::default(),
        TestProof::new(&clock),
        clock,
    )
    .unwrap()
}

fn path0_crash_request() -> ProposalRequest {
    ProposalRequest {
        idempotency_key: "path0-crash-retry".into(),
        ..proposal_request(NEW)
    }
}

fn file_review(gate: &FileGate, id: &str) -> Option<Review> {
    gate.db
        .query_row(
            "SELECT proposal_id,challenge,base_sha256,new_sha256,display_sha256,expires_at,auth,card FROM gate_reviews WHERE proposal_id=? ORDER BY issue_seq DESC LIMIT 1",
            [id],
            |row| {
                Ok(Review {
                    proposal_id: row.get(0)?,
                    challenge: row.get(1)?,
                    base_sha256: row.get(2)?,
                    new_sha256: row.get(3)?,
                    display_sha256: row.get(4)?,
                    expires_at: row.get(5)?,
                    auth_bytes: row.get(6)?,
                    card_bytes: row.get(7)?,
                })
            },
        )
        .optional()
        .unwrap()
}

fn abort_file_gate(directory: &Path, boundary: &str, recovering: bool) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::crash_child", "--ignored", "--nocapture"])
        .env("GATE_CRASH_CHILD", "1")
        .env("GATE_CRASH_AT", boundary)
        .env("GATE_CRASH_DIRECTORY", directory)
        .env("GATE_CRASH_RECOVERING", if recovering { "1" } else { "0" })
        .current_dir(directory)
        .output()
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            output.status.signal(),
            Some(6),
            "{boundary}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(not(unix))]
    assert!(!output.status.success(), "{boundary}");
}

#[test]
#[ignore = "helper process for antibody_path0_crash_retry_never_rewrites_or_fabricates_success"]
fn crash_child() {
    if std::env::var("GATE_CRASH_CHILD").as_deref() != Ok("1") {
        return;
    }
    let directory = PathBuf::from(std::env::var_os("GATE_CRASH_DIRECTORY").unwrap());
    if std::env::var("GATE_CRASH_RECOVERING").as_deref() == Ok("1") {
        let _gate = file_gate(&directory);
    } else {
        crate::fs_store::FsStore::new(directory.canonicalize().unwrap())
            .unwrap()
            .write(TARGET, BASE, "initial")
            .unwrap();
        let mut gate = file_gate(&directory);
        let p = gate.guest().propose(path0_crash_request()).unwrap();
        let review = gate.owner().review(&p.id).unwrap();
        gate.owner()
            .consume(consume_request(&review, Decision::Allow, 1))
            .unwrap();
    }
    panic!("requested crash failpoint was not reached");
}

#[test]
fn antibody_path0_crash_retry_never_rewrites_or_fabricates_success() {
    let boundaries = [
        ("before-propose-commit", None, 0),
        ("after-propose-commit", Some(State::Pending), 0),
        ("before-review-commit", Some(State::Pending), 0),
        ("after-review-commit", Some(State::Pending), 0),
        ("before-consume-commit", Some(State::Pending), 0),
        ("after-consume-commit", Some(State::Failed), 0),
        ("before-write-claim-commit", Some(State::Failed), 0),
        ("after-write-claim-commit", Some(State::Failed), 0),
        ("before-write", Some(State::Failed), 0),
        ("after-write", Some(State::Incomplete), 1),
        ("before-receipt", Some(State::Incomplete), 1),
        ("after-receipt", Some(State::Incomplete), 1),
        ("after-receipt-commit", Some(State::Applied), 1),
    ];
    for (boundary, expected, writes) in boundaries {
        let directory = temp_directory();
        abort_file_gate(directory.path(), boundary, false);
        let mut gate = file_gate(directory.path());
        let prior: Option<String> = gate
            .db
            .query_row("SELECT id FROM gate_proposals", [], |row| row.get(0))
            .optional()
            .unwrap();
        let state = prior
            .as_ref()
            .and_then(|id| gate.guest().state(id).unwrap());
        assert_eq!(state, expected, "{boundary}");
        let store = FileStore::new(directory.path());
        assert_eq!(store.write_count(), writes, "{boundary}");
        assert_eq!(gate.recover().unwrap(), 0, "{boundary}");
        if let Some(id) = &prior {
            assert_eq!(
                gate.receipt(id).unwrap().is_some(),
                expected == Some(State::Applied),
                "{boundary}: no fabricated receipt"
            );
            assert_eq!(
                terminal_rows(&gate.db, id),
                i64::from(expected != Some(State::Pending)),
                "{boundary}"
            );
        }
        let p = gate.guest().propose(path0_crash_request()).unwrap();
        if let Some(id) = prior {
            assert_eq!(p.id, id, "{boundary}: retry reuses the durable proposal");
        }
        let review =
            file_review(&gate, &p.id).unwrap_or_else(|| gate.owner().review(&p.id).unwrap());
        let request = consume_request(&review, Decision::Allow, 1);
        let (final_state, final_writes) = match expected {
            None | Some(State::Pending) => {
                assert_eq!(
                    gate.owner().consume(request.clone()).unwrap(),
                    State::Applied
                );
                for kind in ["gate.propose", "gate.review", "gate.consume", "gate.apply"] {
                    assert_eq!(count_kind(&gate.db, &p.id, kind), 1, "{boundary}: {kind}");
                }
                (State::Applied, 1)
            }
            Some(state) => {
                assert!(gate.owner().consume(request.clone()).is_err(), "{boundary}");
                (state, writes)
            }
        };
        assert!(
            gate.owner().consume(request).is_err(),
            "{boundary}: approval replay"
        );
        assert!(gate.apply(&p.id).is_err(), "{boundary}: effect replay");
        assert_eq!(
            store.write_count(),
            final_writes,
            "{boundary}: one effect at most"
        );
        assert_eq!(terminal_rows(&gate.db, &p.id), 1, "{boundary}");
        assert_eq!(
            gate.guest().propose(path0_crash_request()).unwrap().id,
            p.id
        );
        let proposals: i64 = gate
            .db
            .query_row("SELECT count(*) FROM gate_proposals", [], |row| row.get(0))
            .unwrap();
        assert_eq!(proposals, 1, "{boundary}: idempotent guest retry");
        drop(gate);
        for _ in 0..2 {
            let mut again = file_gate(directory.path());
            assert_eq!(
                again.guest().state(&p.id).unwrap(),
                Some(final_state),
                "{boundary}"
            );
            assert_eq!(again.recover().unwrap(), 0, "{boundary}");
            assert!(again.apply(&p.id).is_err(), "{boundary}");
            assert_eq!(
                again.receipt(&p.id).unwrap().is_some(),
                final_state == State::Applied,
                "{boundary}: no fabricated recovery receipt"
            );
            assert_eq!(store.write_count(), final_writes, "{boundary}");
            assert_eq!(terminal_rows(&again.db, &p.id), 1, "{boundary}");
        }
    }
}

#[test]
fn antibody_path0_recovery_crash_never_rewrites_or_fabricates_success() {
    for boundary in ["before-recover-commit", "after-recover-commit"] {
        let directory = temp_directory();
        abort_file_gate(directory.path(), "after-write", false);
        abort_file_gate(directory.path(), boundary, true);
        let store = FileStore::new(directory.path());
        for _ in 0..2 {
            let mut gate = file_gate(directory.path());
            let id: String = gate
                .db
                .query_row("SELECT id FROM gate_proposals", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                gate.guest().state(&id).unwrap(),
                Some(State::Incomplete),
                "{boundary}"
            );
            let review = file_review(&gate, &id).unwrap();
            assert!(gate
                .owner()
                .consume(consume_request(&review, Decision::Allow, 1))
                .is_err());
            assert!(gate.apply(&id).is_err(), "{boundary}");
            assert_eq!(gate.recover().unwrap(), 0, "{boundary}");
            assert!(gate.receipt(&id).unwrap().is_none(), "{boundary}");
            assert_eq!(count_kind(&gate.db, &id, "gate.apply"), 0, "{boundary}");
            assert_eq!(terminal_rows(&gate.db, &id), 1, "{boundary}");
            assert_eq!(store.write_count(), 1, "{boundary}: recovery never writes");
        }
    }
}

mod review_regressions {
    use super::*;
    include!("review_regressions.rs");
}

mod antibody_tests {
    use super::*;
    include!("antibody_tests.rs");
}

mod extra_tests {
    use super::*;
    include!("extra_tests.rs");
}

#[path = "standing_tests.rs"]
mod standing_tests;
