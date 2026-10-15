// Review scratch reproductions, inverted into assertions of the required protections.
const OPTARGET: &str = "plugins/test/approval.json";

pub(super) fn operator_fixture(limits: Limits) -> Fixture {
    let mut f = fixture_with(limits);
    release_fixture_gate(&mut f);
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    f.gate = Gate::open(db, f.cfg.clone(), vec![target_spec(),
        TargetSpec::custom(OPTARGET, 256, |_| Ok(()))], f.store.clone(),
        f.ledger.clone(), f.proof.clone(), f.clock.clone()).unwrap();
    f
}

pub(super) fn operator_request(f: &Fixture, bytes: &[u8]) -> ProposalRequest {
    ProposalRequest {
        target: OPTARGET.into(),
        base_sha256: f.store.files.lock().unwrap().get(OPTARGET).map(|b| sha256(b)).unwrap_or("absent".into()),
        new_bytes: bytes.to_vec(), note: "Release.".into(),
        idempotency_key: format!("operator-{}", NEXT_KEY.fetch_add(1, Ordering::SeqCst)), cell: None,
    }
}

fn spend(f: &mut Fixture) -> String {
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    assert_eq!(f.gate.consume(consume_request(&r, Decision::Allow, 0)).unwrap(), State::Applying);
    p.id
}

fn mark_claimed(gate: &TestGate, id: &str) {
    gate.db.execute("UPDATE gate_proposals SET write_claimed=1 WHERE id=?", [id]).unwrap();
}

#[test]
fn f1_prewrite_read_error_is_failed_without_claim_or_write() {
    let mut f = fixture();
    let id = spend(&mut f);
    f.store.unreadable.store(true, Ordering::SeqCst);
    assert!(f.gate.apply(&id).is_err());
    f.store.unreadable.store(false, Ordering::SeqCst);
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(f.gate.state(&id).unwrap(), Some(State::Failed));
    assert_eq!(terminal_rows(&f.gate.db, &id), 1);
    assert!(f.gate.propose(proposal_request(OTHER)).is_ok());
}

#[test]
fn f2_unclaimed_unreadable_restart_is_failed() {
    let mut f = fixture();
    let id = spend(&mut f);
    f.store.unreadable.store(true, Ordering::SeqCst);
    let g = reopen(&mut f);
    assert_eq!(g.state(&id).unwrap(), Some(State::Failed));
    assert_eq!(terminal_rows(&g.db, &id), 1);
    assert_eq!(f.store.write_count(), 0);
    drop(g);
    f.store.unreadable.store(false, Ordering::SeqCst);
    let mut g = reopen(&mut f);
    assert_eq!(g.state(&id).unwrap(), Some(State::Failed));
    assert!(g.propose(proposal_request(OTHER)).is_ok());
}

#[test]
fn f3_unknown_burns_review_and_leaves_pending_without_fence() {
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    let mut req = consume_request(&r, Decision::Unknown, 0);
    req.proof = vec![0; 3];
    let result = f.gate.consume(req);
    assert!(result.is_err() || matches!(result, Ok(State::Pending)));
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert!(f.gate.consume(consume_request(&r, Decision::Allow, 0)).is_err());
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 0);
    assert_eq!(f.store.write_count(), 0);
    let fresh = f.gate.review(&p.id).unwrap();
    assert_ne!(fresh.challenge, r.challenge);
}

#[test]
fn f4_second_open_is_locked_and_cannot_recover_live_approval() {
    let mut f = fixture();
    let id = spend(&mut f);
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    let result = Gate::open(db, f.cfg.clone(), vec![target_spec()], f.store.clone(),
        f.ledger.clone(), f.proof.clone(), f.clock.clone());
    assert!(result.is_err());
    assert_eq!(f.gate.state(&id).unwrap(), Some(State::Applying));
    assert_eq!(f.gate.apply(&id).unwrap(), State::Applied);
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn f5_preclaim_clock_failure_is_reconciled_and_never_writes_late() {
    let mut f = fixture();
    let id = spend(&mut f);
    f.clock.fail.store(true, Ordering::SeqCst);
    assert!(f.gate.apply(&id).is_err());
    f.clock.fail.store(false, Ordering::SeqCst);
    assert_eq!(f.gate.state(&id).unwrap(), Some(State::Failed));
    f.clock.advance(48 * 3_600_000);
    assert!(f.gate.apply(&id).is_err());
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(terminal_rows(&f.gate.db, &id), 1);
}

#[test]
fn f6_claim_failure_reconciles_without_waiting_for_restart() {
    let mut f = fixture();
    let id = spend(&mut f);
    mark_claimed(&f.gate, &id);
    assert!(f.gate.apply(&id).is_err());
    assert_eq!(f.gate.state(&id).unwrap(), Some(State::Failed));
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(terminal_rows(&f.gate.db, &id), 1);
    assert!(f.gate.propose(proposal_request(OTHER)).is_ok());
}

#[test]
fn a4_card_size_checked_at_propose_and_again_before_review() {
    // The original 4000-control-byte reproduction is either refused before review,
    // or fully displayable and consumable after cleaning; it never traps a signed owner.
    let mut original = fixture();
    let mut request = proposal_request(NEW);
    request.note = "\u{1}".repeat(4000);
    if let Ok(p) = original.gate.propose(request) {
        let review = original.gate.review(&p.id).unwrap();
        assert!(review.card_bytes.len() <= original.cfg.limits.display_max_bytes);
        assert_eq!(original.gate.consume(consume_request(&review, Decision::Allow, 0)).unwrap(), State::Applying);
    }
    let mut f = fixture_with(Limits { display_max_bytes: 10, ..permissive_limits() });
    let mut req = proposal_request(NEW);
    req.note = "\u{1}".repeat(4000);
    assert!(f.gate.propose(req).is_err());
    assert_eq!(f.store.write_count(), 0);
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    f.gate.config.limits.display_max_bytes = 10;
    assert!(f.gate.review(&p.id).is_err());
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.review"), 0);
}

#[test]
fn a5_second_same_target_live_review_is_refused() {
    let mut f = fixture();
    let a = f.gate.propose(proposal_request(NEW)).unwrap();
    let b = f.gate.propose(proposal_request(OTHER)).unwrap();
    let ra = f.gate.review(&a.id).unwrap();
    assert!(f.gate.review(&b.id).is_err());
    assert_eq!(count_kind(&f.gate.db, &b.id, "gate.review"), 0);
    assert_eq!(f.gate.consume(consume_request(&ra, Decision::Allow, 0)).unwrap(), State::Applying);
}

#[test]
fn a6_automatic_rows_never_claim_owner_actor() {
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    f.gate.review(&p.id).unwrap();
    for kind in ["gate.propose", "gate.review"] {
        let actor: String = f.gate.db.query_row("SELECT actor FROM aura WHERE op=? AND kind=?", params![p.id, kind], |r| r.get(0)).unwrap();
        assert_ne!(actor, f.cfg.owner.subject);
        assert!(matches!(actor.as_str(), "gate" | "supervisor" | "guest"));
    }
    f.clock.set(p.expires_at);
    let g = reopen(&mut f);
    let actor: String = g.db.query_row("SELECT actor FROM aura WHERE op=? AND kind='gate.expire'", [&p.id], |r| r.get(0)).unwrap();
    assert_ne!(actor, f.cfg.owner.subject);
    assert!(matches!(actor.as_str(), "gate" | "supervisor"));
}

#[test]
fn a7_owner_reconcile_lifts_incomplete_fence_without_retry() {
    for bytes in [NEW, OTHER] {
        let mut f = fixture();
        let id = spend(&mut f);
        mark_claimed(&f.gate, &id);
        f.store.set(bytes);
        let mut g = reopen(&mut f);
        assert_eq!(g.state(&id).unwrap(), Some(if bytes == NEW { State::Incomplete } else { State::Conflict }));
        let mut next = proposal_request(if bytes == NEW { OTHER } else { NEW });
        next.base_sha256 = sha256(bytes);
        assert!(g.propose(next.clone()).is_err());
        let auth = g.reconcile_authorization(&id).unwrap();
        assert!(g.reconcile(&id, &[0; 3]).is_err());
        let auth = g.reconcile_authorization(&id).unwrap_or(auth);
        let receipt = g.reconcile(&id, &TestProof::sign(&auth, 0)).unwrap();
        assert!(receipt.contains(&sha256(bytes)));
        assert_eq!(f.store.write_count(), 0);
        assert!(g.propose(next).is_ok());
        assert!(g.apply(&id).is_err());
        assert_eq!(f.store.write_count(), 0);
        assert_eq!(terminal_rows(&g.db, &id), 1);
    }
}

#[test]
fn a8_guest_idempotency_key_cannot_squat_owner_origin() {
    let mut f = operator_fixture(permissive_limits());
    let mut guest = proposal_request(NEW);
    guest.idempotency_key = "raise-1".into();
    let gp = f.gate.propose(guest).unwrap();
    let mut owner = operator_request(&f, b"release-A");
    owner.idempotency_key = "raise-1".into();
    let op = f.gate.raise(owner.clone()).unwrap();
    assert_ne!(gp.id, op.id);
    assert_eq!(f.gate.raise(owner).unwrap().id, op.id);
}

#[test]
fn w2c_owner_raise_obeys_rejected_byte_dedupe() {
    let mut f = operator_fixture(Limits::default());
    let p = f.gate.raise(operator_request(&f, b"release-A")).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate.consume(consume_request(&r, Decision::Deny, 0)).unwrap();
    f.clock.advance(61_000);
    assert!(f.gate.raise(operator_request(&f, b"release-A")).is_err());
}

#[test]
fn w4_model_note_is_cleaned_bounded_labelled_and_data_only() {
    let mut f = fixture();
    let mut req = proposal_request(NEW);
    req.note = format!("GATE-VERIFIED \u{202e}FFD700 dlog\u{202c} {}", "x".repeat(3000));
    let p = f.gate.propose(req).unwrap();
    assert!(p.note.bytes().all(|byte| (0x20..=0x7e).contains(&byte)));
    assert!(p.note.len() <= 120);
    assert!(!p.note.contains("GATE-"));
    assert!(!p.note.contains('\u{202e}'));
    let r = f.gate.review(&p.id).unwrap();
    let card = String::from_utf8(r.card_bytes).unwrap();
    assert!(card.contains("UNVERIFIED MODEL NOTE; DATA ONLY"));
    assert!(!card.contains('\u{202e}'));
    assert!(!card.contains("GATE-VERIFIED"));
    let parsed: Value = serde_json::from_str(&card).unwrap();
    let note = parsed["model_note"].as_str().unwrap();
    assert!(note.is_ascii());
    assert!(note.len() <= 120);
    assert!(!note.contains("GATE-"));
    assert_eq!(parsed["from_to"]["base"], String::from_utf8(BASE.to_vec()).unwrap());
    assert_eq!(parsed["from_to"]["new"], String::from_utf8(NEW.to_vec()).unwrap());
}

#[test]
fn consume_implicit_rollback_burns_in_a_fresh_transaction() {
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let r = f.gate.review(&p.id).unwrap();
    f.gate.db.execute_batch("CREATE TRIGGER rollback_consume BEFORE INSERT ON aura WHEN NEW.kind='gate.consume' BEGIN SELECT RAISE(ROLLBACK,'injected transaction rollback'); END").unwrap();
    assert!(f.gate.consume(consume_request(&r, Decision::Allow, 1)).is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    let burned: bool = f.gate.db.query_row("SELECT EXISTS(SELECT 1 FROM gate_burns WHERE challenge=?)", [&r.challenge], |r| r.get(0)).unwrap();
    assert!(burned);
    assert_eq!(count_kind(&f.gate.db, &p.id, "gate.consume"), 0);
    assert_eq!(f.store.write_count(), 0);
    f.gate.db.execute_batch("DROP TRIGGER rollback_consume").unwrap();
    assert!(f.gate.consume(consume_request(&r, Decision::Allow, 1)).is_err());
}

#[test]
fn receipt_implicit_rollback_reconciles_without_another_write() {
    let mut f = fixture();
    let id = spend(&mut f);
    f.gate.db.execute_batch("CREATE TRIGGER rollback_receipt BEFORE INSERT ON gate_receipts BEGIN SELECT RAISE(ROLLBACK,'injected transaction rollback'); END").unwrap();
    assert!(f.gate.apply(&id).is_err());
    assert_eq!(f.gate.state(&id).unwrap(), Some(State::Incomplete));
    assert_eq!(f.store.write_count(), 1);
    assert!(f.gate.receipt(&id).unwrap().is_none());
    assert_eq!(terminal_rows(&f.gate.db, &id), 1);
    assert!(f.gate.apply(&id).is_err());
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn recovery_commits_each_row_and_names_the_first_blocker() {
    let mut f = fixture();
    let mut ids = vec![];
    for _ in 0..3 { ids.push(f.gate.propose(proposal_request(NEW)).unwrap().id); }
    for id in &ids {
        let r = f.gate.review(id).unwrap();
        f.gate.consume(consume_request(&r, Decision::Allow, 0)).unwrap();
        mark_claimed(&f.gate, id);
    }
    ids.sort();
    f.store.set(NEW);
    let blocker = ids[1].clone();
    f.gate.db.execute_batch(&format!("CREATE TRIGGER fail_recovery BEFORE INSERT ON aura WHEN NEW.kind='gate.recover' AND NEW.op='{blocker}' BEGIN SELECT RAISE(ABORT,'injected recovery blocker'); END")).unwrap();
    release_fixture_gate(&mut f);
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    let result = Gate::open(db, f.cfg.clone(), vec![target_spec()], f.store.clone(),
        f.ledger.clone(), f.proof.clone(), f.clock.clone());
    let error = match result { Ok(_) => panic!("recovery bypassed blocker"), Err(error) => error.to_string() };
    assert!(error.contains(&blocker), "{error}");
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    let states: Vec<String> = ids.iter().map(|id| db.query_row("SELECT state FROM gate_proposals WHERE id=?", [id], |r| r.get(0)).unwrap()).collect();
    assert_eq!(states, ["incomplete", "applying", "applying"]);
    assert_eq!(terminal_rows(&db, &ids[0]), 1);
    assert_eq!(terminal_rows(&db, &ids[1]), 0);
    assert_eq!(terminal_rows(&db, &ids[2]), 0);
    db.execute_batch("DROP TRIGGER fail_recovery").unwrap();
    let g = reopen(&mut f);
    for id in ids { assert_eq!(g.state(&id).unwrap(), Some(State::Incomplete)); }
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn startup_refuses_drift_from_last_applied_receipt() {
    let mut f = fixture();
    let id = spend(&mut f);
    assert_eq!(f.gate.apply(&id).unwrap(), State::Applied);
    release_fixture_gate(&mut f);
    f.store.set(OTHER);
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    let result = Gate::open(db, f.cfg.clone(), vec![target_spec()], f.store.clone(),
        f.ledger.clone(), f.proof.clone(), f.clock.clone());
    let error = match result { Ok(_) => panic!("applied bytes drift accepted at startup"), Err(error) => error.to_string() };
    assert!(error.contains(&id));
    assert!(error.contains("applied-target-drift"));
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn cancel_and_reject_audit_each_nonpending_reviewed_and_operator_refusal() {
    let mut f = operator_fixture(permissive_limits());
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    f.gate.review(&p.id).unwrap();
    for reject in [false, true] {
        let before = count_kind(&f.gate.db, &p.id, "gate.refuse");
        assert!(if reject {f.gate.reject(&p.id)} else {f.gate.cancel(&p.id)}.is_err());
        assert_eq!(count_kind(&f.gate.db, &p.id, "gate.refuse"), before + 1);
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
        assert_eq!(terminal_rows(&f.gate.db, &p.id), 0);
    }
    let op = f.gate.raise(operator_request(&f, b"release-A")).unwrap();
    for reject in [false, true] {
        let before = count_kind(&f.gate.db, &op.id, "gate.refuse");
        assert!(if reject {f.gate.reject(&op.id)} else {f.gate.cancel(&op.id)}.is_err());
        assert_eq!(count_kind(&f.gate.db, &op.id, "gate.refuse"), before + 1);
        assert_eq!(f.gate.state(&op.id).unwrap(), Some(State::Pending));
    }
    let r = f.gate.review(&p.id).unwrap();
    f.gate.consume(consume_request(&r, Decision::Deny, 0)).unwrap();
    for reject in [false, true] {
        let before = count_kind(&f.gate.db, &p.id, "gate.refuse");
        assert!(if reject {f.gate.reject(&p.id)} else {f.gate.cancel(&p.id)}.is_err());
        assert_eq!(count_kind(&f.gate.db, &p.id, "gate.refuse"), before + 1);
        assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
    }
}

#[test]
fn spent_owner_snapshot_cannot_apply_after_owner_update() {
    let mut f = fixture();
    let id = spend(&mut f);
    let mut owner = f.cfg.owner.clone();
    owner.epoch += 1;
    owner.binding_sha256 = "44".repeat(32);
    f.gate.owner_update(owner).unwrap();
    assert!(f.gate.apply(&id).is_err());
    assert_eq!(f.gate.state(&id).unwrap(), Some(State::Failed));
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn owner_action_issuance_and_reconciliation_metadata_are_retained() {
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    f.gate.retire_authorization(&p.id).unwrap();
    for sql in [
        "DELETE FROM gate_actions", "UPDATE gate_actions SET auth=x'00'",
        "UPDATE gate_actions SET state='live'", "UPDATE gate_actions SET challenge='replacement'",
    ] { assert!(f.gate.db.execute_batch(sql).is_err(), "{sql}"); }
    // Use the existing unsigned pending record's consume ceremony for the retained reconciliation.
    let r = f.gate.review(&p.id).unwrap();
    f.gate.consume(consume_request(&r, Decision::Allow, 0)).unwrap();
    mark_claimed(&f.gate, &p.id);
    f.store.set(NEW);
    f.gate.recover().unwrap();
    let auth = f.gate.reconcile_authorization(&p.id).unwrap();
    f.gate.reconcile(&p.id, &TestProof::sign(&auth, 0)).unwrap();
    for sql in ["UPDATE gate_reconciliations SET base_sha256='absent'", "DELETE FROM gate_reconciliations"] {
        assert!(f.gate.db.execute_batch(sql).is_err(), "{sql}");
    }
}
