// SPDX-License-Identifier: AGPL-3.0-or-later
// Regression ports of review 2 A1/A2/A3 and review 3 W1/W3.
use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const TARGET: &str = "plugins/auth/accent.json";
const BASE: &[u8] = b"{\"accent\": \"#FFD700\"}";
const NEW: &[u8] = b"{\"accent\": \"#1E90FF\"}";
const OTHER: &[u8] = b"{\"accent\": \"#FF0000\"}";
const START: i64 = 1_800_000_000_000;

#[derive(Clone)]
struct Store(Arc<Mutex<Option<Vec<u8>>>>, Arc<AtomicUsize>);
impl TargetStore for Store {
    fn read(&self, _: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn write(&self, _: &str, bytes: &[u8], _: &str) -> Result<()> {
        self.1.fetch_add(1, Ordering::SeqCst);
        *self.0.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }
}
struct FixedClock(Arc<AtomicI64>);
impl Clock for FixedClock {
    fn now_ms(&self) -> Result<i64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
// The verified identifier comes from the key used by the cryptographic adapter,
// independently of the owner state or browser authorization being checked.
struct Proof;
impl Proof {
    fn sign(auth: &[u8], counter: u32, seed: u8) -> Vec<u8> {
        let mut signed = auth.to_vec();
        signed.extend_from_slice(&counter.to_be_bytes());
        let signature = SigningKey::from_bytes(&[seed; 32]).sign(&signed);
        let mut bytes = vec![seed];
        bytes.extend_from_slice(&counter.to_be_bytes());
        bytes.extend_from_slice(&signature.to_bytes());
        bytes
    }
}
impl OwnerProof for Proof {
    fn verify(&self, auth: &[u8], proof: &[u8]) -> Result<VerifiedProof> {
        if proof.len() != 69 || ![7, 8].contains(&proof[0]) {
            return Err(Error::Refused("gate:owner-proof"));
        }
        let mut signed = auth.to_vec();
        signed.extend_from_slice(&proof[1..5]);
        SigningKey::from_bytes(&[proof[0]; 32])
            .verifying_key()
            .verify_strict(
                &signed,
                &Signature::from_bytes(proof[5..].try_into().unwrap()),
            )
            .map_err(|_| Error::Refused("gate:owner-proof"))?;
        Ok(VerifiedProof {
            credential_id: if proof[0] == 7 { "33" } else { "44" }.repeat(32),
            counter: u32::from_be_bytes(proof[1..5].try_into().unwrap()),
        })
    }
}
struct TestLedger {
    store: Store,
    clock: Arc<AtomicI64>,
    change_kind: Mutex<Option<&'static str>>,
    change_bytes: Mutex<Option<Vec<u8>>>,
    change_time: AtomicI64,
    change_owner: Mutex<Option<OwnerState>>,
}
impl Ledger for TestLedger {
    fn append(&self, tx: &Transaction<'_>, row: &LedgerRow) -> Result<LedgerRef> {
        let seq: i64 = tx.query_row("SELECT coalesce(max(seq),0)+1 FROM aura", [], |r| r.get(0))?;
        let hash =
            sha256(format!("{seq}:{}:{}:{}:{}", row.kind, row.op, row.phase, row.body).as_bytes());
        tx.execute(
            "INSERT INTO aura VALUES(?,?,?,?,?,?)",
            params![seq, hash, row.kind, row.actor, row.op, row.phase],
        )?;
        tx.execute(
            "INSERT INTO aura_bodies VALUES(?,?)",
            params![seq, row.body],
        )?;
        let mut kind = self.change_kind.lock().unwrap();
        if *kind == Some(row.kind) {
            if let Some(bytes) = self.change_bytes.lock().unwrap().take() {
                *self.store.0.lock().unwrap() = Some(bytes);
            }
            let at = self.change_time.swap(0, Ordering::SeqCst);
            if at != 0 {
                self.clock.store(at, Ordering::SeqCst);
            }
            if let Some(owner) = self.change_owner.lock().unwrap().take() {
                tx.execute("UPDATE gate_owner SET owner_text=?,epoch=?,credential_id=?,sign_count=0 WHERE singleton=1",params![owner_text(&owner)?,owner.epoch,owner.binding_sha256])?;
            }
            *kind = None;
        }
        Ok(LedgerRef { seq, hash })
    }
    fn read_verified(&self, db: &Connection, r: &LedgerRef) -> Result<VerifiedLedgerRow> {
        db.query_row(
            "SELECT kind,op,phase,body FROM aura JOIN aura_bodies USING(seq) WHERE seq=? AND hash=?",
            params![r.seq, r.hash],
            |row| Ok(VerifiedLedgerRow {kind:row.get(0)?,op:row.get(1)?,phase:row.get(2)?,body:row.get(3)?}),
        ).map_err(Error::from)
    }
}
type TestGate = Gate<Store, TestLedger, Proof, FixedClock>;
fn fixture() -> (TestGate, tempfile::TempDir) {
    fixture_with_counter(0)
}
fn fixture_with_counter(sign_count: u32) -> (TestGate, tempfile::TempDir) {
    let dir = tempfile::Builder::new()
        .prefix(".gate-auth-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let db = Connection::open(dir.path().join("gate.db")).unwrap();
    db.execute_batch(
        "CREATE TABLE aura(seq INTEGER PRIMARY KEY,hash TEXT UNIQUE,kind TEXT,actor TEXT,op TEXT,phase TEXT);
         CREATE TABLE aura_bodies(seq INTEGER PRIMARY KEY,body TEXT);
         CREATE UNIQUE INDEX one_terminal ON aura(op) WHERE phase='terminal';",
    ).unwrap();
    let config = Config {
        node: "11".repeat(16),
        gate_pubkey_sha256: "99".repeat(32),
        owner: OwnerState {
            subject: format!("aukora:1:{}", "22".repeat(32)),
            epoch: 1,
            binding_sha256: "33".repeat(32),
            sign_count,
        },
        limits: Limits {
            max_pending: 100,
            max_per_window: 100,
            reject_cooldown_ms: 0,
            dedupe_ms: 0,
            ..Limits::default()
        },
    };
    let mut target = TargetSpec::theme();
    target.name = TARGET.into();
    let store = Store(
        Arc::new(Mutex::new(Some(BASE.to_vec()))),
        Arc::new(AtomicUsize::new(0)),
    );
    let clock = Arc::new(AtomicI64::new(START));
    let ledger = TestLedger {
        store: store.clone(),
        clock: clock.clone(),
        change_kind: Mutex::new(None),
        change_bytes: Mutex::new(None),
        change_time: AtomicI64::new(0),
        change_owner: Mutex::new(None),
    };
    let gate = Gate::open(
        db,
        config,
        vec![target],
        store,
        ledger,
        Proof,
        FixedClock(clock),
    )
    .unwrap();
    (gate, dir)
}
fn proposal(gate: &mut TestGate, base: &[u8], new: &[u8], key: &str) -> Proposal {
    gate.propose(ProposalRequest {
        target: TARGET.into(),
        base_sha256: sha256(base),
        new_bytes: new.to_vec(),
        note: "change colour".into(),
        idempotency_key: key.into(),
        cell: None,
    })
    .unwrap()
}
fn request(r: &Review, decision: Decision, counter: u32, seed: u8) -> ConsumeRequest {
    ConsumeRequest {
        proposal_id: r.proposal_id.clone(),
        challenge: r.challenge.clone(),
        base_sha256: r.base_sha256.clone(),
        new_sha256: r.new_sha256.clone(),
        display_sha256: r.display_sha256.clone(),
        decision,
        proof: Proof::sign(&r.auth_bytes, counter, seed),
    }
}
fn reopen_with_counter(gate: TestGate, sign_count: u32) -> TestGate {
    let Gate {
        db,
        mut config,
        targets,
        store,
        ledger,
        proof,
        clock,
        _writer_lock,
    } = gate;
    drop(_writer_lock);
    config.owner.sign_count = sign_count;
    Gate::open(
        db,
        config,
        targets.into_values().collect(),
        store,
        ledger,
        proof,
        clock,
    )
    .unwrap()
}

#[test]
fn antibody_gate_open_seeds_owner_credential_counter() {
    let (mut gate, _dir) = fixture_with_counter(6);
    let p = proposal(&mut gate, BASE, NEW, "counter-seed");
    for counter in [0, 1, 6] {
        let r = gate.review(&p.id).unwrap();
        // A cloned credential below the owner high-water mark must return gate:counter-replay.
        assert!(matches!(
            gate.consume(request(&r, Decision::Allow, counter, 7)),
            Err(Error::Refused("gate:counter-replay"))
        ));
    }
    let fresh = gate.review(&p.id).unwrap();
    assert_eq!(
        gate.consume(request(&fresh, Decision::Allow, 7, 7))
            .unwrap(),
        State::Applying
    );
}

#[test]
fn antibody_gate_reopen_merges_owner_credential_high_water() {
    let (gate, _dir) = fixture_with_counter(5);
    let mut gate = reopen_with_counter(gate, 6);
    let p = proposal(&mut gate, BASE, NEW, "counter-reopen");
    let r = gate.review(&p.id).unwrap();
    // A stale clone after an intervening owner sign-in must return gate:counter-replay.
    assert!(matches!(
        gate.consume(request(&r, Decision::Allow, 6, 7)),
        Err(Error::Refused("gate:counter-replay"))
    ));
    let fresh = gate.review(&p.id).unwrap();
    gate.consume(request(&fresh, Decision::Allow, 7, 7))
        .unwrap();
    gate.apply(&p.id).unwrap();
    let mut gate = reopen_with_counter(gate, 1);
    let p = proposal(&mut gate, NEW, OTHER, "counter-no-rewind");
    let r = gate.review(&p.id).unwrap();
    // An older startup snapshot must preserve gate:counter-replay for the consumed value.
    assert!(matches!(
        gate.consume(request(&r, Decision::Allow, 7, 7)),
        Err(Error::Refused("gate:counter-replay"))
    ));
    let fresh = gate.review(&p.id).unwrap();
    assert_eq!(
        gate.consume(request(&fresh, Decision::Allow, 8, 7))
            .unwrap(),
        State::Applying
    );
}

#[test]
fn antibody_gate_owner_epoch_preserves_same_credential_high_water() {
    let (mut gate, _dir) = fixture_with_counter(6);
    let mut owner = gate.config.owner.clone();
    owner.epoch = 2;
    owner.sign_count = 1;
    gate.owner_update(owner).unwrap();
    let p = proposal(&mut gate, BASE, NEW, "counter-binding");
    for counter in [1, 0, 6] {
        let r = gate.review(&p.id).unwrap();
        // Binding the same owner credential must preserve gate:counter-replay.
        assert!(matches!(
            gate.consume(request(&r, Decision::Allow, counter, 7)),
            Err(Error::Refused("gate:counter-replay"))
        ));
    }
    let fresh = gate.review(&p.id).unwrap();
    assert_eq!(
        gate.consume(request(&fresh, Decision::Allow, 7, 7))
            .unwrap(),
        State::Applying
    );
}

#[test]
fn antibody_gate_owner_epoch_imports_same_credential_high_water() {
    let (mut gate, _dir) = fixture_with_counter(5);
    let mut owner = gate.config.owner.clone();
    owner.epoch = 2;
    owner.sign_count = 6;
    gate.owner_update(owner).unwrap();
    let p = proposal(&mut gate, BASE, NEW, "counter-binding-advance");
    let r = gate.review(&p.id).unwrap();
    // The owner ceremony's newer mark must cause gate:counter-replay for its consumed value.
    assert!(matches!(
        gate.consume(request(&r, Decision::Allow, 6, 7)),
        Err(Error::Refused("gate:counter-replay"))
    ));
    let fresh = gate.review(&p.id).unwrap();
    assert_eq!(
        gate.consume(request(&fresh, Decision::Allow, 7, 7))
            .unwrap(),
        State::Applying
    );
}

#[test]
fn antibody_gate_owner_rotation_seeds_replacement_credential_counter() {
    let (mut gate, _dir) = fixture_with_counter(100);
    let mut owner = gate.config.owner.clone();
    owner.epoch = 2;
    owner.binding_sha256 = "44".repeat(32);
    owner.sign_count = 5;
    gate.owner_update(owner).unwrap();
    let p = proposal(&mut gate, BASE, NEW, "counter-replacement");
    for counter in [1, 0, 5] {
        let r = gate.review(&p.id).unwrap();
        // Replacement key enrolment must cause gate:counter-replay below its own high-water mark.
        assert!(matches!(
            gate.consume(request(&r, Decision::Allow, counter, 8)),
            Err(Error::Refused("gate:counter-replay"))
        ));
    }
    let fresh = gate.review(&p.id).unwrap();
    assert_eq!(
        gate.consume(request(&fresh, Decision::Allow, 6, 8))
            .unwrap(),
        State::Applying
    );
}

#[test]
fn antibody_gate_storage_preserves_same_credential_counter_across_epochs() {
    let (gate, _dir) = fixture_with_counter(6);
    // A same-key epoch update must return gate:owner-monotonic rather than rewind the counter.
    let error = gate
        .db
        .execute(
            "UPDATE gate_owner SET epoch=epoch+1,sign_count=1 WHERE singleton=1",
            [],
        )
        .unwrap_err();
    assert!(error.to_string().contains("gate:owner-monotonic"));
}

#[test]
fn a1_w3_unknown_without_proof_burns_challenge_and_keeps_pending() {
    let (mut gate, _dir) = fixture();
    let p = proposal(&mut gate, BASE, NEW, "unknown");
    let r = gate.review(&p.id).unwrap();
    let mut input = request(&r, Decision::Unknown, 0, 7);
    input.proof = vec![0; 3];
    assert!(matches!(
        gate.consume(input),
        Err(Error::Refused("gate:unknown-decision"))
    ));
    assert_eq!(gate.state(&p.id).unwrap(), Some(State::Pending));
    let burns: i64 = gate
        .db
        .query_row(
            "SELECT count(*) FROM gate_burns WHERE challenge=?",
            [&r.challenge],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(burns, 1);
    let terminals: i64 = gate
        .db
        .query_row(
            "SELECT count(*) FROM aura WHERE op=? AND phase='terminal'",
            [&p.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(terminals, 0);
    assert!(gate.consume(request(&r, Decision::Allow, 0, 7)).is_err());
    let fresh = gate.review(&p.id).unwrap();
    assert_eq!(
        gate.consume(request(&fresh, Decision::Allow, 0, 7))
            .unwrap(),
        State::Applying
    );
}

#[test]
fn a2_deny_without_proof_has_unsigned_actor() {
    let (mut gate, _dir) = fixture();
    let p = proposal(&mut gate, BASE, NEW, "deny");
    let r = gate.review(&p.id).unwrap();
    let mut input = request(&r, Decision::Deny, 0, 7);
    input.proof = vec![0; 3];
    assert_eq!(gate.consume(input).unwrap(), State::Refused);
    let actor: String = gate
        .db
        .query_row(
            "SELECT actor FROM aura WHERE op=? AND phase='terminal'",
            [&p.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(actor, "owner-channel (unsigned)");
}

#[test]
fn a3_rotation_accepts_new_lower_counter_and_refuses_old_credential() {
    let (mut gate, _dir) = fixture();
    let p = proposal(&mut gate, BASE, NEW, "old");
    let r = gate.review(&p.id).unwrap();
    gate.consume(request(&r, Decision::Allow, 100, 7)).unwrap();
    gate.apply(&p.id).unwrap();
    let mut next = gate.config.owner.clone();
    next.epoch = 2;
    next.binding_sha256 = "44".repeat(32);
    gate.owner_update(next).unwrap();
    let count: u32 = gate
        .db
        .query_row("SELECT sign_count FROM gate_owner", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    let p2 = proposal(&mut gate, NEW, OTHER, "new");
    let r2 = gate.review(&p2.id).unwrap();
    assert!(matches!(
        gate.consume(request(&r2, Decision::Allow, 101, 7)),
        Err(Error::Refused("gate:credential-mismatch"))
    ));
    let fresh = gate.review(&p2.id).unwrap();
    assert_eq!(
        gate.consume(request(&fresh, Decision::Allow, 5, 8))
            .unwrap(),
        State::Applying
    );
}

#[test]
fn w1_zero_counter_after_nonzero_is_refused_for_apply_and_retire() {
    let (mut gate, _dir) = fixture();
    let p = proposal(&mut gate, BASE, NEW, "five");
    let r = gate.review(&p.id).unwrap();
    gate.consume(request(&r, Decision::Allow, 5, 7)).unwrap();
    gate.apply(&p.id).unwrap();
    let p2 = proposal(&mut gate, NEW, OTHER, "zero");
    let r2 = gate.review(&p2.id).unwrap();
    assert!(matches!(
        gate.consume(request(&r2, Decision::Allow, 0, 7)),
        Err(Error::Refused("gate:counter-replay"))
    ));
    let auth = gate.retire_authorization(&p2.id).unwrap();
    assert!(matches!(
        gate.retire(&p2.id, &Proof::sign(&auth, 0, 7)),
        Err(Error::Refused("gate:counter-replay"))
    ));
}

#[test]
fn c5_apply_and_retire_share_epoch_operation_gate_and_fresh_ceremony_layout() {
    let (mut gate, _dir) = fixture();
    let p = proposal(&mut gate, BASE, NEW, "auth");
    let r = gate.review(&p.id).unwrap();
    let apply: Value = serde_json::from_slice(&r.auth_bytes).unwrap();
    assert_eq!(apply["epoch"], 1);
    assert_eq!(apply["owner_epoch"], 1);
    assert_eq!(apply["operation"], p.digest);
    assert_eq!(apply["owner_root_id"], "33".repeat(32));
    assert_eq!(apply["binding_sha256"], "33".repeat(32));
    assert_eq!(apply["issued_at"], START);
    assert_eq!(apply["gate"], "99".repeat(32));
    assert_eq!(apply["pubkey_fp"], "99".repeat(8));
    assert_eq!(apply["op"], "apply");
    let retire1: Value =
        serde_json::from_slice(&gate.retire_authorization(&p.id).unwrap()).unwrap();
    let retire2: Value =
        serde_json::from_slice(&gate.retire_authorization(&p.id).unwrap()).unwrap();
    assert_eq!(
        retire1.as_object().unwrap().keys().collect::<Vec<_>>(),
        apply.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    for field in [
        "epoch",
        "owner_epoch",
        "operation",
        "owner_root_id",
        "binding_sha256",
        "gate",
        "pubkey_fp",
        "proposal",
        "base_sha256",
        "new_sha256",
        "cell",
        "target",
        "node",
        "subject",
    ] {
        assert_eq!(retire1[field], apply[field], "field {field}");
    }
    assert_eq!(retire1["op"], "retire");
    assert_eq!(retire1["issued_at"], START);
    assert!(retire1["expires_at"].as_i64().unwrap() > START);
    assert!(hex_width(retire1["challenge"].as_str().unwrap(), 64));
    assert_ne!(retire1["challenge"], apply["challenge"]);
    assert_ne!(retire1["challenge"], retire2["challenge"]);
    assert_ne!(retire1["display_sha256"], apply["display_sha256"]);
    assert!(gate
        .retire(&p.id, &Proof::sign(&r.auth_bytes, 0, 7))
        .is_err());
}

#[test]
fn c5_absent_base_is_literal_and_gate_key_pin_must_be_a_sha256() {
    let (mut gate, _dir) = fixture();
    let mut invalid = gate.config.clone();
    invalid.gate_pubkey_sha256 = "x".repeat(64);
    assert!(matches!(
        validate_config(&invalid),
        Err(Error::Refused("gate:node"))
    ));
    *gate.store.0.lock().unwrap() = None;
    let p = gate
        .propose(ProposalRequest {
            target: TARGET.into(),
            base_sha256: "absent".into(),
            new_bytes: NEW.to_vec(),
            note: "create theme".into(),
            idempotency_key: "absent".into(),
            cell: None,
        })
        .unwrap();
    let auth: Value = serde_json::from_slice(&gate.review(&p.id).unwrap().auth_bytes).unwrap();
    assert_eq!(auth["base_sha256"], "absent");
}

fn interrupted_write(gate: &mut TestGate) -> Proposal {
    let pending = proposal(gate, BASE, NEW, "interrupted");
    let review = gate.review(&pending.id).unwrap();
    gate.consume(request(&review, Decision::Allow, 0, 7))
        .unwrap();
    gate.db
        .execute(
            "UPDATE gate_proposals SET write_claimed=1 WHERE id=?",
            [&pending.id],
        )
        .unwrap();
    *gate.store.0.lock().unwrap() = Some(NEW.to_vec());
    let applying = load_proposal(&gate.db, &pending.id).unwrap().unwrap();
    let tx = gate
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    reconcile(
        &tx,
        &gate.ledger,
        &gate.store,
        &applying,
        "gate",
        START,
        None,
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(gate.state(&pending.id).unwrap(), Some(State::Incomplete));
    load_proposal(&gate.db, &pending.id).unwrap().unwrap()
}

#[test]
fn owner_actions_refuse_expired_retirement_and_old_issuance() {
    let (mut gate, _dir) = fixture();
    let p = proposal(&mut gate, BASE, NEW, "retire-expiry");
    let first = gate.retire_authorization(&p.id).unwrap();
    let second = gate.retire_authorization(&p.id).unwrap();
    assert!(gate.retire(&p.id, &Proof::sign(&first, 0, 7)).is_err());
    let auth: Value = serde_json::from_slice(&second).unwrap();
    gate.clock
        .0
        .store(auth["expires_at"].as_i64().unwrap(), Ordering::SeqCst);
    *gate.ledger.change_kind.lock().unwrap() = Some("gate.retire");
    assert!(matches!(
        gate.retire(&p.id, &Proof::sign(&second, 0, 7)),
        Err(Error::Refused("gate:expired"))
    ));
    assert_eq!(
        *gate.ledger.change_kind.lock().unwrap(),
        Some("gate.retire")
    );
    assert_eq!(gate.state(&p.id).unwrap(), Some(State::Pending));
}

#[test]
fn owner_actions_recheck_clock_and_owner_after_signed_ledger_callback() {
    for change_owner in [false, true] {
        let (mut gate, _dir) = fixture();
        let p = proposal(&mut gate, BASE, NEW, "retire-final");
        let bytes = gate.retire_authorization(&p.id).unwrap();
        let auth: Value = serde_json::from_slice(&bytes).unwrap();
        *gate.ledger.change_kind.lock().unwrap() = Some("gate.retire");
        if change_owner {
            let mut owner = gate.config.owner.clone();
            owner.epoch += 1;
            owner.binding_sha256 = "44".repeat(32);
            *gate.ledger.change_owner.lock().unwrap() = Some(owner);
        } else {
            gate.ledger
                .change_time
                .store(auth["expires_at"].as_i64().unwrap(), Ordering::SeqCst);
        }
        let failure = gate.retire(&p.id, &Proof::sign(&bytes, 0, 7)).unwrap_err();
        assert!(matches!(
            failure,
            Error::Refused("gate:owner-state-changed") | Error::Refused("gate:expired")
        ));
        assert_eq!(gate.state(&p.id).unwrap(), Some(State::Pending));
        assert!(gate.receipt(&p.id).unwrap().is_none());
    }
}

#[test]
fn reconcile_requires_current_credential_and_snapshot_then_lifts_fence_without_write() {
    let (mut gate, _dir) = fixture();
    let p = interrupted_write(&mut gate);
    let auth = gate.reconcile_authorization(&p.id).unwrap();
    assert!(matches!(
        gate.reconcile(&p.id, &Proof::sign(&auth, 0, 8)),
        Err(Error::Refused("gate:credential-mismatch"))
    ));
    *gate.store.0.lock().unwrap() = Some(OTHER.to_vec());
    *gate.ledger.change_kind.lock().unwrap() = Some("gate.recover");
    *gate.ledger.change_bytes.lock().unwrap() = Some(NEW.to_vec());
    assert!(matches!(
        gate.reconcile(&p.id, &Proof::sign(&auth, 0, 7)),
        Err(Error::Refused("gate:reconcile-target-changed"))
    ));
    assert_eq!(
        *gate.ledger.change_kind.lock().unwrap(),
        Some("gate.recover")
    );
    *gate.ledger.change_kind.lock().unwrap() = None;
    *gate.ledger.change_bytes.lock().unwrap() = None;
    let fresh = gate.reconcile_authorization(&p.id).unwrap();
    let receipt: Value =
        serde_json::from_str(&gate.reconcile(&p.id, &Proof::sign(&fresh, 0, 7)).unwrap()).unwrap();
    assert_eq!(receipt["base_sha256"], sha256(OTHER));
    assert_eq!(receipt["retry"], false);
    assert_eq!(gate.store.1.load(Ordering::SeqCst), 0);
    assert_eq!(gate.state(&p.id).unwrap(), Some(State::Incomplete));
    assert_eq!(
        proposal(&mut gate, OTHER, NEW, "after-reconcile").state,
        State::Pending
    );
}

#[test]
fn reconcile_final_guard_rechecks_target_and_deadline_after_ledger_callback() {
    for change_target in [false, true] {
        let (mut gate, _dir) = fixture();
        let p = interrupted_write(&mut gate);
        let auth = gate.reconcile_authorization(&p.id).unwrap();
        let value: Value = serde_json::from_slice(&auth).unwrap();
        *gate.ledger.change_kind.lock().unwrap() = Some("gate.recover");
        if change_target {
            *gate.ledger.change_bytes.lock().unwrap() = Some(OTHER.to_vec());
        } else {
            gate.ledger
                .change_time
                .store(value["expires_at"].as_i64().unwrap(), Ordering::SeqCst);
        }
        let error = gate
            .reconcile(&p.id, &Proof::sign(&auth, 0, 7))
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Refused("gate:reconcile-target-changed") | Error::Refused("gate:expired")
        ));
        let closed: bool = gate
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM gate_reconciliations WHERE proposal_id=?)",
                [&p.id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!closed);
        assert_eq!(gate.store.1.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn current_owner_binding_is_checked_independently_of_mutable_counter_storage() {
    let (mut gate, _dir) = fixture();
    let mut owner = gate.config.owner.clone();
    owner.epoch = 2;
    owner.binding_sha256 = "44".repeat(32);
    gate.owner_update(owner).unwrap();
    // A damaged mutable counter row cannot turn an earlier key into the new owner.
    gate.db
        .execute_batch("DROP TRIGGER gate_owner_monotonic")
        .unwrap();
    gate.db
        .execute("UPDATE gate_owner SET credential_id=?", ["33".repeat(32)])
        .unwrap();
    let p = proposal(&mut gate, BASE, NEW, "damaged-credential");
    let r = gate.review(&p.id).unwrap();
    assert!(matches!(
        gate.consume(request(&r, Decision::Allow, 0, 7)),
        Err(Error::Refused("gate:credential-mismatch"))
    ));
}

#[test]
fn counterless_zero_is_scoped_to_verified_credential() {
    let (mut gate, _dir) = fixture();
    let tx = gate
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(matches!(
        counter_cas(&tx, &"44".repeat(32), 0),
        Err(Error::Refused("gate:credential-mismatch"))
    ));
}

#[test]
fn receipt_v3_contains_verified_owner_and_authorization_coordinates() {
    let (mut gate, _dir) = fixture();
    let p = proposal(&mut gate, BASE, NEW, "receipt");
    let r = gate.review(&p.id).unwrap();
    let input = request(&r, Decision::Allow, 0, 7);
    let proof_hash = sha256(&input.proof);
    gate.consume(input).unwrap();
    gate.apply(&p.id).unwrap();
    let receipt: Value = serde_json::from_str(&gate.receipt(&p.id).unwrap().unwrap()).unwrap();
    assert_eq!(receipt["v"], 3);
    assert_eq!(receipt["kind"], "change");
    assert_eq!(receipt["approver"], gate.config.owner.subject);
    assert_eq!(receipt["pubkey_fp"], "99".repeat(8));
    assert_eq!(
        receipt["gate_pubkey_sha256"],
        gate.config.gate_pubkey_sha256
    );
    assert_eq!(receipt["owner_accepted_at_ms"], START);
    assert_eq!(receipt["owner_authorization"]["version"], 1);
    assert_eq!(
        receipt["owner_authorization"]["kind"],
        "aukora-owner-authorization-ref/v1"
    );
    assert_eq!(receipt["owner_authorization"]["proof_sha256"], proof_hash);
    assert_eq!(
        receipt["owner_authorization"]["authorization_id"],
        sha256(
            &[
                b"aukora:owner-authorization:v1\0".as_slice(),
                r.auth_bytes.as_slice()
            ]
            .concat()
        )
    );
    let consume: &Value = &receipt["owner_consumption"];
    assert_eq!(consume["ledger_seq"], consume["seq"]);
    assert_eq!(consume["ledger_hash"], consume["hash"]);
    let issue: &Value = &consume["review_issue"];
    assert_eq!(issue["ledger_seq"], issue["seq"]);
    assert_eq!(issue["ledger_hash"], issue["hash"]);
    let review_seq: i64 = gate
        .db
        .query_row(
            "SELECT issue_seq FROM gate_reviews WHERE challenge=?",
            [&r.challenge],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(issue["ledger_seq"], review_seq);
    let review_actor: String = gate
        .db
        .query_row("SELECT actor FROM aura WHERE seq=?", [review_seq], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(review_actor, "gate");
    let owners: i64 = gate
        .db
        .query_row(
            "SELECT count(*) FROM aura WHERE actor=? AND kind IN ('gate.consume','gate.apply')",
            [&gate.config.owner.subject],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(owners, 2);
}

#[test]
fn owner_action_issuance_rechecks_deadline_and_owner_after_ledger_callback() {
    for change_owner in [false, true] {
        let (mut gate, _dir) = fixture();
        let p = proposal(&mut gate, BASE, NEW, "issue-final");
        *gate.ledger.change_kind.lock().unwrap() = Some("gate.review");
        if change_owner {
            let mut owner = gate.config.owner.clone();
            owner.epoch += 1;
            owner.binding_sha256 = "44".repeat(32);
            *gate.ledger.change_owner.lock().unwrap() = Some(owner);
        } else {
            gate.ledger
                .change_time
                .store(START + gate.config.limits.review_ttl_ms, Ordering::SeqCst);
        }
        let error = gate.retire_authorization(&p.id).unwrap_err();
        assert!(matches!(
            error,
            Error::Refused("gate:owner-state-changed") | Error::Refused("gate:expired")
        ));
        let actions: i64 = gate
            .db
            .query_row("SELECT count(*) FROM gate_actions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(actions, 0);
    }
}

#[test]
fn owner_action_issuance_must_be_exact_signed_review_semantics() {
    for field in [
        "kind",
        "op",
        "phase",
        "authorization",
        "card",
        "owner_state",
    ] {
        let (mut gate, _dir) = fixture();
        let p = proposal(&mut gate, BASE, NEW, "issue-semantics");
        let auth = gate.retire_authorization(&p.id).unwrap();
        let (body,at):(String,i64)=gate.db.query_row("SELECT body,? FROM aura_bodies WHERE seq=(SELECT issue_seq FROM gate_actions WHERE proposal_id=?)",params![START,p.id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        let mut body: Value = serde_json::from_str(&body).unwrap();
        let mut row = LedgerRow {
            at,
            kind: "gate.review",
            actor: "gate".into(),
            op: p.id.clone(),
            phase: "fact",
            body: String::new(),
        };
        match field {
            "kind" => row.kind = "gate.propose",
            "op" => row.op = "another-proposal".into(),
            "phase" => row.phase = "intent",
            _ => body[field] = Value::Null,
        }
        row.body = canonical(&body).unwrap();
        let tx = gate
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let wrong = gate.ledger.append(&tx, &row).unwrap();
        tx.commit().unwrap();
        gate.db
            .execute_batch("DROP TRIGGER gate_actions_facts")
            .unwrap();
        gate.db
            .execute(
                "UPDATE gate_actions SET issue_seq=?,issue_hash=? WHERE proposal_id=?",
                params![wrong.seq, wrong.hash, p.id],
            )
            .unwrap();
        assert!(
            matches!(
                gate.retire(&p.id, &Proof::sign(&auth, 0, 7)),
                Err(Error::Refused("gate:review-evidence-unavailable"))
            ),
            "{field}"
        );
        assert_eq!(gate.state(&p.id).unwrap(), Some(State::Pending));
    }
}

#[test]
fn forged_reconciliation_metadata_cannot_lift_fence() {
    let (mut gate, _dir) = fixture();
    let p = interrupted_write(&mut gate);
    let (seq, hash): (i64, String) = gate
        .db
        .query_row(
            "SELECT seq,hash FROM aura WHERE op=? AND kind='gate.recover'",
            [&p.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    gate.db
        .execute(
            "INSERT INTO gate_reconciliations VALUES(?,?,?,?)",
            params![p.id, sha256(NEW), seq, hash],
        )
        .unwrap();
    assert!(verified_reconciliation(&gate.db, &gate.ledger, &p.id).is_err());
    let attempt = gate.propose(ProposalRequest {
        target: TARGET.into(),
        base_sha256: sha256(NEW),
        new_bytes: OTHER.to_vec(),
        note: "forged fence clear".into(),
        idempotency_key: "forged".into(),
        cell: None,
    });
    assert!(attempt.is_err());
}

#[test]
fn signed_reconciliation_survives_reopen_and_retire_is_idempotent() {
    let (mut gate, dir) = fixture();
    let p = interrupted_write(&mut gate);
    let auth = gate.reconcile_authorization(&p.id).unwrap();
    gate.reconcile(&p.id, &Proof::sign(&auth, 0, 7)).unwrap();
    assert_eq!(
        verified_reconciliation(&gate.db, &gate.ledger, &p.id)
            .unwrap()
            .unwrap()
            .0,
        sha256(NEW)
    );
    let config = gate.config.clone();
    let store = gate.store.clone();
    let time = gate.clock.0.clone();
    let targets = gate.targets.values().cloned().collect();
    drop(gate);
    let ledger = TestLedger {
        store: store.clone(),
        clock: time.clone(),
        change_kind: Mutex::new(None),
        change_bytes: Mutex::new(None),
        change_time: AtomicI64::new(0),
        change_owner: Mutex::new(None),
    };
    let mut reopened = Gate::open(
        Connection::open(dir.path().join("gate.db")).unwrap(),
        config,
        targets,
        store,
        ledger,
        Proof,
        FixedClock(time),
    )
    .unwrap();
    let next = proposal(&mut reopened, NEW, OTHER, "after-reopen");
    let retire = reopened.retire_authorization(&next.id).unwrap();
    let proof = Proof::sign(&retire, 0, 7);
    let once = reopened.retire(&next.id, &proof).unwrap();
    let twice = reopened.retire(&next.id, &proof).unwrap();
    assert_eq!(once, twice);
    let count: i64 = reopened
        .db
        .query_row(
            "SELECT count(*) FROM aura WHERE op=? AND phase='terminal'",
            [&next.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn reconciliation_fence_metadata_must_match_every_signed_authorization_fact() {
    for field in [
        "kind",
        "op",
        "phase",
        "receipt.v",
        "receipt.kind",
        "receipt.operation",
        "receipt.operation_id",
        "receipt.digest",
        "receipt.base_sha256",
        "receipt.retry",
        "base-format",
        "authorization.v",
        "authorization.op",
        "authorization.proposal",
        "authorization.target",
        "authorization.operation",
        "authorization.subject",
        "authorization.owner_epoch",
        "authorization.gate",
        "ref.version",
        "ref.kind",
        "ref.authorization_id",
        "proof-empty",
        "ref.proof_sha256",
    ] {
        let (mut gate, _dir) = fixture();
        let p = interrupted_write(&mut gate);
        let auth = gate.reconcile_authorization(&p.id).unwrap();
        gate.reconcile(&p.id, &Proof::sign(&auth, 0, 7)).unwrap();
        let (seq,body):(i64,String)=gate.db.query_row("SELECT seq,body FROM gate_reconciliations JOIN aura_bodies USING(seq) WHERE proposal_id=?",[&p.id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        let mut body: Value = serde_json::from_str(&body).unwrap();
        let mut row = LedgerRow {
            at: START,
            kind: "gate.recover",
            actor: gate.config.owner.subject.clone(),
            op: p.id.clone(),
            phase: "fact",
            body: String::new(),
        };
        let mut base = sha256(NEW);
        match field {
            "kind" => row.kind = "gate.review",
            "op" => row.op = "another-proposal".into(),
            "phase" => row.phase = "settle",
            "receipt.v" => body["receipt"]["v"] = json!(2),
            "receipt.retry" => body["receipt"]["retry"] = json!(true),
            "base-format" => {
                base = "invalid".into();
                body["receipt"]["base_sha256"] = json!(base);
            }
            "authorization.v" => body["authorization"]["v"] = json!(2),
            "authorization.owner_epoch" => body["authorization"]["owner_epoch"] = json!(2),
            "ref.version" => body["receipt"]["owner_authorization"]["version"] = json!(2),
            "proof-empty" => {
                body["proof_hex"] = json!("");
                body["receipt"]["owner_authorization"]["proof_sha256"] = json!(sha256(b""));
            }
            name if name.starts_with("receipt.") => {
                body["receipt"][name.strip_prefix("receipt.").unwrap()] = json!("wrong")
            }
            name if name.starts_with("authorization.") => {
                body["authorization"][name.strip_prefix("authorization.").unwrap()] = json!("wrong")
            }
            name if name.starts_with("ref.") => {
                body["receipt"]["owner_authorization"][name.strip_prefix("ref.").unwrap()] =
                    json!("wrong")
            }
            _ => unreachable!(),
        }
        // Keep the authorization's digest valid so each semantic comparison is
        // independently necessary rather than hidden behind a hash mismatch.
        if field.starts_with("authorization.") {
            body["receipt"]["owner_authorization"]["authorization_id"] = json!(sha256(
                &[
                    b"aukora:owner-authorization:v1\0".as_slice(),
                    canonical(&body["authorization"]).unwrap().as_bytes()
                ]
                .concat()
            ));
        }
        row.body = canonical(&body).unwrap();
        let tx = gate
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let wrong = gate.ledger.append(&tx, &row).unwrap();
        tx.commit().unwrap();
        assert!(wrong.seq > seq);
        gate.db
            .execute_batch("DROP TRIGGER gate_reconciliations_no_update")
            .unwrap();
        gate.db
            .execute(
                "UPDATE gate_reconciliations SET base_sha256=?,seq=?,hash=? WHERE proposal_id=?",
                params![base, wrong.seq, wrong.hash, p.id],
            )
            .unwrap();
        assert!(
            matches!(
                verified_reconciliation(&gate.db, &gate.ledger, &p.id),
                Err(Error::Refused("gate:reconciliation-unavailable"))
            ),
            "{field}"
        );
    }
}
