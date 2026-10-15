use super::*;
use std::thread;

fn permission(f: &mut Fixture, mode: &str, targets: &[&str], count: i64, expires: i64) -> Proposal {
    let spec = TargetSpec::supervisor(standing::TARGET).unwrap();
    f.gate.targets.insert(spec.name.clone(), spec);
    let bytes = canonical(&json!({"v":1,"mode":mode,"targets":targets,"kinds":["put"],"max_count":count,"expires_at":expires,"nonce":"aa".repeat(16)})).unwrap().into_bytes();
    let base = target_hash(&f.store.read(standing::TARGET).unwrap());
    f.gate
        .owner()
        .raise(ProposalRequest {
            target: standing::TARGET.into(),
            base_sha256: base,
            new_bytes: bytes,
            note: String::new(),
            idempotency_key: format!("permission-{}", NEXT_KEY.fetch_add(1, Ordering::SeqCst)),
            cell: None,
        })
        .unwrap()
}
fn activate(f: &mut Fixture, mode: &str, targets: &[&str], count: i64, expires: i64) -> String {
    let p = permission(f, mode, targets, count, expires);
    let r = f.gate.owner().review(&p.id).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&r.auth_bytes).unwrap()["op"],
        "permission"
    );
    assert_eq!(
        f.gate
            .owner()
            .consume(consume_request(&r, Decision::Allow, 0))
            .unwrap(),
        State::Applied
    );
    p.id
}
fn next(f: &mut Fixture, target: &str, bytes: &[u8]) -> Proposal {
    let mut r = proposal_request(bytes);
    r.target = target.into();
    r.base_sha256 = target_hash(&f.store.read(target).unwrap());
    f.gate.guest().propose(r).unwrap()
}

#[test]
fn antibody_slider_scope_count_expiry_and_default() {
    let mut f = fixture();
    assert_eq!(next(&mut f, TARGET, NEW).state, State::Pending);
    let expires = START + 1000;
    activate(&mut f, "risky", &[TARGET], 1, expires);
    assert_eq!(next(&mut f, TARGET, OTHER).state, State::Applied);
    assert_eq!(next(&mut f, TARGET, NEW).state, State::Pending);
    assert_eq!(f.gate.slider_status().unwrap()["remaining"], 0);
    let mut f = fixture();
    let other = "plugins/test/other.json";
    f.gate.targets.insert(
        other.into(),
        TargetSpec {
            name: other.into(),
            ..target_spec()
        },
    );
    activate(&mut f, "limits", &[TARGET], 10, START + 1000);
    assert_eq!(next(&mut f, other, NEW).state, State::Pending);
    f.clock.set(START + 1000);
    assert_eq!(next(&mut f, TARGET, NEW).state, State::Pending);
}

#[test]
fn antibody_slider_change_requires_passkey_and_binds_limits() {
    let mut f = fixture();
    let p = permission(&mut f, "limits", &[TARGET], 2, START + 1000);
    assert_eq!(f.gate.slider_status().unwrap()["mode"], "ask");
    let r = f.gate.owner().review(&p.id).unwrap();
    let mut request = consume_request(&r, Decision::Allow, 0);
    request.proof = vec![];
    assert!(f.gate.owner().consume(request).is_err());
    assert_eq!(f.gate.slider_status().unwrap()["mode"], "ask");
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert!(f
        .gate
        .guest()
        .propose(ProposalRequest {
            target: standing::TARGET.into(),
            base_sha256: "absent".into(),
            new_bytes: b"{}".to_vec(),
            note: String::new(),
            idempotency_key: "guest-slider".into(),
            cell: None
        })
        .is_err());
    let invalid = json!({"v":1,"mode":"limits","targets":[TARGET],"kinds":["put"],"max_count":0,"expires_at":START+1000,"nonce":"aa".repeat(16)});
    assert!(standing::validate(canonical(&invalid).unwrap().as_bytes()).is_err());
    let spec = TargetSpec::supervisor(standing::TARGET).unwrap();
    let mut invalid = invalid;
    invalid["max_count"] = json!(1);
    invalid["expires_at"] = json!(START + standing::DAY_MS + 1);
    assert!(spec
        .validate_at(canonical(&invalid).unwrap().as_bytes(), START)
        .is_err());
}

#[test]
fn antibody_slider_risky_targets_cell_and_large_overwrite_always_ask() {
    let mut f = fixture();
    activate(&mut f, "limits", &[TARGET], 10, START + 1000);
    for target in [
        "release",
        "broker/key",
        "broker/grant",
        "floor/current",
        "identity/key",
        "gate/permission",
        "plugins/floor/state.json",
    ] {
        assert!(standing::protected_target(target));
        let record = json!({"v":1,"mode":"limits","targets":[target],"kinds":["put"],"max_count":1,"expires_at":START+1000,"nonce":"aa".repeat(16)});
        assert!(
            standing::validate(canonical(&record).unwrap().as_bytes()).is_err(),
            "{target}"
        );
    }
    let mut r = proposal_request(NEW);
    r.cell = Some(Cell {
        module_sha256: "aa".repeat(32),
        input_sha256: "bb".repeat(32),
        effect_sha256: "cc".repeat(32),
    });
    assert_eq!(f.gate.guest().propose(r).unwrap().state, State::Pending);
    let mut f = fixture();
    let mut critical = target_spec();
    critical.risk = "critical";
    f.gate.targets.insert(TARGET.into(), critical);
    activate(&mut f, "limits", &[TARGET], 10, START + 1000);
    assert_eq!(next(&mut f, TARGET, NEW).state, State::Pending);
    // Test the size predicate directly: the production registry currently caps files at 4 KiB.
    let mut f = fixture();
    let p = f.gate.propose(proposal_request(NEW)).unwrap();
    let large = vec![b'x'; 65_537];
    let mut p = p;
    p.base_sha256 = sha256(&large);
    let tx = f.gate.db.transaction().unwrap();
    put_blob(&tx, &p.base_sha256, &large).unwrap();
    tx.commit().unwrap();
    assert!(!standing::safe(&f.gate.db, &p, &target_spec()).unwrap());
}

#[test]
fn antibody_slider_aura_references_permission_and_revoke_is_immediate() {
    let mut f = fixture();
    let permission = activate(&mut f, "risky", &[TARGET], 10, START + 1000);
    let p = next(&mut f, TARGET, NEW);
    assert_eq!(p.state, State::Applied);
    let body: String = f
        .gate
        .db
        .query_row(
            "SELECT body FROM aura WHERE kind='gate.consume' AND op=?",
            [&p.id],
            |r| r.get(0),
        )
        .unwrap();
    let body: Value = serde_json::from_str(&body).unwrap();
    let status = f.gate.slider_status().unwrap();
    assert_eq!(body["standing_permission"]["proposal"], permission);
    assert_eq!(
        body["standing_permission"]["authorization_sha256"],
        status["authorization_sha256"]
    );
    let receipt: Value = serde_json::from_str(&f.gate.receipt(&p.id).unwrap().unwrap()).unwrap();
    assert_eq!(receipt["standing_permission"], body["standing_permission"]);
    assert_eq!(
        receipt["owner_authorization"]["authorization_sha256"],
        status["authorization_sha256"]
    );
    assert_eq!(
        receipt["owner_authorization"]["proof_sha256"],
        body["standing_permission"]["proof_sha256"]
    );
    activate(&mut f, "ask", &[], 0, START + 1000);
    assert_eq!(next(&mut f, TARGET, OTHER).state, State::Pending);
    assert!(!f.gate.slider_status().unwrap()["active"].as_bool().unwrap());
}

#[test]
fn antibody_slider_count_is_exact_under_concurrent_proposals() {
    let mut f = fixture();
    activate(&mut f, "limits", &[TARGET], 3, START + 1000);
    let gate = Arc::new(Mutex::new(f.gate));
    let threads = (0..12)
        .map(|i| {
            let gate = gate.clone();
            thread::spawn(move || {
                let mut gate = gate.lock().unwrap();
                let mut request =
                    proposal_request(format!("{{\"accent\": \"#{i:06X}\"}}").as_bytes());
                request.base_sha256 = target_hash(&gate.store.read(TARGET).unwrap());
                gate.guest().propose(request).unwrap().state
            })
        })
        .collect::<Vec<_>>();
    let states = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == State::Applied)
            .count(),
        3
    );
    let gate = gate.lock().unwrap();
    assert_eq!(
        gate.db
            .query_row("SELECT count(*) FROM gate_auto", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(gate.slider_status().unwrap()["remaining"], 0);
}

#[test]
fn antibody_slider_revoke_supersedes_unfinished_review_without_reviving_old_signature() {
    let mut f = fixture();
    activate(&mut f, "risky", &[TARGET], 5, START + 1000);
    let pending = permission(&mut f, "limits", &[TARGET], 20, START + 2000);
    let stale = f.gate.owner().review(&pending.id).unwrap();
    activate(&mut f, "ask", &[], 0, START + 1000);
    assert!(f
        .gate
        .owner()
        .consume(consume_request(&stale, Decision::Allow, 0))
        .is_err());
    assert_eq!(next(&mut f, TARGET, NEW).state, State::Pending);
}

#[test]
fn antibody_slider_permission_and_count_survive_reopen() {
    let mut f = fixture();
    activate(&mut f, "limits", &[TARGET], 1, START + 1000);
    assert_eq!(next(&mut f, TARGET, NEW).state, State::Applied);
    release_fixture_gate(&mut f);
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    f.gate = Gate::open(
        db,
        f.cfg.clone(),
        vec![
            target_spec(),
            TargetSpec::supervisor(standing::TARGET).unwrap(),
        ],
        f.store.clone(),
        f.ledger.clone(),
        f.proof.clone(),
        f.clock.clone(),
    )
    .unwrap();
    assert_eq!(f.gate.slider_status().unwrap()["remaining"], 0);
    assert_eq!(next(&mut f, TARGET, OTHER).state, State::Pending);
}

#[test]
fn antibody_slider_idempotent_replay_and_audit_failure_never_spend_twice() {
    let mut f = fixture();
    activate(&mut f, "limits", &[TARGET], 2, START + 1000);
    let request = proposal_request(NEW);
    let p = f.gate.guest().propose(request.clone()).unwrap();
    assert_eq!(p.state, State::Applied);
    assert_eq!(
        f.gate.guest().propose(request).unwrap().state,
        State::Applied
    );
    assert_eq!(f.gate.slider_status().unwrap()["remaining"], 1);
    f.gate.db.execute_batch("CREATE TRIGGER fail_auto_audit BEFORE INSERT ON aura WHEN NEW.kind='gate.consume' BEGIN SELECT RAISE(ABORT,'test:audit'); END").unwrap();
    let mut request = proposal_request(OTHER);
    request.base_sha256 = sha256(NEW);
    assert!(f.gate.guest().propose(request).is_err());
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(), NEW);
    assert_eq!(f.gate.slider_status().unwrap()["remaining"], 1);
}

#[test]
fn antibody_slider_permission_schema_is_closed_and_has_positive_bounded_authority() {
    let valid = json!({"v":1,"mode":"limits","targets":[TARGET],"kinds":["put"],"max_count":1,"expires_at":START+1000,"nonce":"aa".repeat(16)});
    for (field, value) in [
        ("v", json!(2)),
        ("mode", json!("always")),
        ("targets", json!([])),
        ("targets", json!(["plugins/Identity/key.md"])),
        ("targets", json!(["plugins/test/../note.md"])),
        ("kinds", json!(["delete"])),
        ("max_count", json!(0)),
        ("max_count", json!(1_000_001)),
        ("expires_at", json!(0)),
        ("nonce", json!("bad")),
        ("extra", json!(true)),
    ] {
        let mut record = valid.clone();
        record[field] = value;
        assert!(
            standing::validate(canonical(&record).unwrap().as_bytes()).is_err(),
            "{field}: {record}"
        );
    }
    let duplicate = canonical(&valid).unwrap().replacen("{", "{\"v\":1,", 1);
    assert!(standing::validate(duplicate.as_bytes()).is_err());
}

#[test]
fn antibody_slider_failed_signed_revoke_disables_prior_permission() {
    let mut f = fixture();
    activate(&mut f, "limits", &[TARGET], 5, START + 1000);
    let revoke = permission(&mut f, "ask", &[], 0, START + 1000);
    let review = f.gate.owner().review(&revoke.id).unwrap();
    f.store.fail_write.store(true, Ordering::SeqCst);
    assert!(f
        .gate
        .owner()
        .consume(consume_request(&review, Decision::Allow, 0))
        .is_err());
    f.store.fail_write.store(false, Ordering::SeqCst);
    assert_eq!(f.gate.state(&revoke.id).unwrap(), Some(State::Failed));
    assert_eq!(next(&mut f, TARGET, NEW).state, State::Pending);
    assert_eq!(f.gate.slider_status().unwrap()["mode"], "ask");
}

#[test]
fn antibody_slider_owner_epoch_change_disables_standing_permission() {
    let mut f = fixture();
    activate(&mut f, "limits", &[TARGET], 5, START + 1000);
    let mut owner = f.cfg.owner.clone();
    owner.epoch += 1;
    owner.binding_sha256 = "44".repeat(32);
    f.gate.owner().owner_update(owner).unwrap();
    assert_eq!(next(&mut f, TARGET, NEW).state, State::Pending);
    assert_eq!(f.gate.slider_status().unwrap()["mode"], "ask");
}
