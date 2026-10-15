// SPDX-License-Identifier: AGPL-3.0-or-later

const SUPERVISOR_TARGETS: [&str; 4] = ["release", "broker/key", "broker/grant", "kira/permission"];

#[test]
fn antibody_path0_card_commits_cell_digests_and_exact_bytes() {
    let mut f = fixture();
    let mut request = proposal_request(NEW);
    let cell = Cell {
        module_sha256: "a".repeat(64),
        input_sha256: "b".repeat(64),
        effect_sha256: "c".repeat(64),
    };
    request.cell = Some(cell.clone());
    let proposal = f.gate.guest().propose(request).unwrap();
    let review = f.gate.owner().review(&proposal.id).unwrap();
    let card: Value = serde_json::from_slice(&review.card_bytes).unwrap();
    let auth: Value = serde_json::from_slice(&review.auth_bytes).unwrap();
    let facts = card["facts"].as_array().unwrap();
    for field in ["module_sha256", "input_sha256", "effect_sha256"] {
        assert!(facts.contains(&json!([format!("cell.{field}"), cell.value()[field]])));
    }
    assert_eq!(card["from_to"]["base"], std::str::from_utf8(BASE).unwrap());
    assert_eq!(card["from_to"]["new"], std::str::from_utf8(NEW).unwrap());
    assert_eq!(auth["cell"], cell.value());
    assert_eq!(auth["operation"], proposal.digest);
    assert_eq!(auth["display_sha256"], sha256(&review.card_bytes));
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
    assert_eq!(f.store.files.lock().unwrap()[TARGET], NEW);
    assert_eq!(f.store.write_count(), 1);
}

#[test]
fn antibody_path0_card_refuses_corrupt_retained_cell_digests() {
    for field in ["module_sha256", "input_sha256", "effect_sha256"] {
        for invalid in [json!("A".repeat(64)), json!("a".repeat(63)), json!(null)] {
            let mut f = fixture();
            let mut request = proposal_request(NEW);
            let cell = Cell {
                module_sha256: "a".repeat(64),
                input_sha256: "b".repeat(64),
                effect_sha256: "c".repeat(64),
            };
            request.cell = Some(cell.clone());
            let proposal = f.gate.guest().propose(request).unwrap();
            let mut damaged = cell.value();
            damaged[field] = invalid;
            f.gate
                .db
                .execute_batch("DROP TRIGGER gate_proposals_facts")
                .unwrap();
            f.gate
                .db
                .execute(
                    "UPDATE gate_proposals SET cell=? WHERE id=?",
                    params![canonical(&damaged).unwrap(), proposal.id],
                )
                .unwrap();
            assert!(matches!(
                f.gate.owner().card(&proposal.id),
                Err(Error::Refused("gate:cell"))
            ));
            assert!(matches!(
                f.gate.owner().review(&proposal.id),
                Err(Error::Refused("gate:cell"))
            ));
            assert_eq!(count_kind(&f.gate.db, &proposal.id, "gate.review"), 0);
            assert_eq!(f.store.write_count(), 0);
        }
    }
}

fn supervisor_fixture(target: &str) -> Fixture {
    let mut f = fixture_with(Limits::default());
    let spec = TargetSpec::supervisor(target).unwrap();
    f.gate.targets.insert(spec.name.clone(), spec);
    f
}

fn supervisor_request(target: &str) -> ProposalRequest {
    let body = match target {
        "release" => json!({"v":1,"digest":"a".repeat(64),"components":{
            "node":"b".repeat(64),"harness":"c".repeat(64),"guest":"d".repeat(64)}}),
        "broker/key" => json!({"v":1,"key_sha256":"a".repeat(64)}),
        "broker/grant" => json!({"v":1,"provider":"openrouter","model":"deepseek/deepseek-chat",
            "cap_microusd":1000,"per_request_cap_microusd":100,"max_requests":10,
            "expires_at":START+86_400_000,"nonce":"a".repeat(32)}),
        "kira/permission" => {
            json!({"v":1,"purpose":"hosted-context","model_provider":"openrouter"})
        }
        _ => panic!("unregistered supervisor target"),
    };
    ProposalRequest {
        target: target.into(),
        base_sha256: "absent".into(),
        new_bytes: canonical(&body).unwrap().into_bytes(),
        note: String::new(),
        idempotency_key: "antibody-owner".into(),
        cell: None,
    }
}

#[test]
fn antibody_release_authorization_is_frozen_c5_for_independent_floor() {
    let mut f = supervisor_fixture("release");
    let proposal = f.gate.owner().raise(supervisor_request("release")).unwrap();
    let review = f.gate.owner().review(&proposal.id).unwrap();
    let auth: serde_json::Value = serde_json::from_slice(&review.auth_bytes).unwrap();
    assert_eq!(auth["op"], "release");
    assert_eq!(auth.as_object().unwrap().len(), 14);
    for field in [
        "v",
        "node",
        "subject",
        "op",
        "proposal",
        "target",
        "epoch",
        "operation",
        "base_sha256",
        "new_sha256",
        "cell",
        "display_sha256",
        "challenge",
        "expires_at",
    ] {
        assert!(auth.get(field).is_some(), "missing C5 field {field}");
    }
    assert_eq!(auth["operation"], proposal.digest);
    assert_eq!(auth["display_sha256"], sha256(&review.card_bytes));
}

fn pre_a3_release_review(f: &mut Fixture, proposal: &Proposal) -> Review {
    let tx = f.gate.db.transaction().unwrap();
    let card = card_bytes(&tx, proposal, f.gate.targets.get("release").unwrap()).unwrap();
    let display = sha256(&card);
    let challenge = "ab".repeat(32);
    let expires = proposal
        .expires_at
        .min(START + f.gate.config.limits.review_ttl_ms);
    let mut auth: Value = serde_json::from_slice(
        &authorization_for_op(
            &tx,
            &f.gate.config,
            proposal,
            &challenge,
            START,
            expires,
            &display,
            "reconcile",
        )
        .unwrap(),
    )
    .unwrap();
    auth["op"] = json!("release");
    assert_eq!(auth.as_object().unwrap().len(), 21);
    let owner = owner_text(&f.gate.config.owner).unwrap();
    let issue = append(
        &f.gate.ledger,
        &tx,
        START,
        "gate.review",
        "gate",
        &proposal.id,
        "fact",
        json!({"authorization":auth,"owner_state":serde_json::from_str::<Value>(&owner).unwrap(),"card":serde_json::from_slice::<Value>(&card).unwrap()}),
    )
    .unwrap();
    let auth = canonical(&auth).unwrap().into_bytes();
    tx.execute("INSERT INTO gate_reviews(challenge,proposal_id,base_sha256,new_sha256,display_sha256,auth,card,owner_text,issued_at,expires_at,issue_seq,issue_hash,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'live')",params![challenge,proposal.id,proposal.base_sha256,proposal.new_sha256,display,auth,card,owner,START,expires,issue.seq,issue.hash]).unwrap();
    tx.execute(
        "UPDATE gate_proposals SET reviewed=1 WHERE id=?",
        [&proposal.id],
    )
    .unwrap();
    tx.commit().unwrap();
    Review {
        proposal_id: proposal.id.clone(),
        challenge,
        base_sha256: proposal.base_sha256.clone(),
        new_sha256: proposal.new_sha256.clone(),
        display_sha256: display,
        expires_at: expires,
        auth_bytes: auth,
        card_bytes: card,
    }
}

#[test]
fn antibody_pre_a3_release_review_requires_fresh_approval() {
    let mut f = supervisor_fixture("release");
    let proposal = f.gate.owner().raise(supervisor_request("release")).unwrap();
    let old = pre_a3_release_review(&mut f, &proposal);
    assert!(matches!(
        f.gate.consume(consume_request(&old, Decision::Allow, 0)),
        Err(Error::Refused("gate:pre-a3-release-reapprove"))
    ));
    assert_eq!(
        load_proposal(&f.gate.db, &proposal.id)
            .unwrap()
            .unwrap()
            .state,
        State::Pending
    );
    let (state, burned): (String, bool) = f.gate.db.query_row(
        "SELECT state,EXISTS(SELECT 1 FROM gate_burns WHERE challenge=?) FROM gate_reviews WHERE challenge=?",
        params![old.challenge,old.challenge],
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).unwrap();
    assert_eq!(state, "invalidated");
    assert!(burned);
    assert_eq!(f.store.write_count(), 0);
    assert_eq!(count_kind(&f.gate.db, &proposal.id, "gate.consume"), 0);

    let fresh = f.gate.owner().review(&proposal.id).unwrap();
    let auth: Value = serde_json::from_slice(&fresh.auth_bytes).unwrap();
    assert_eq!(auth.as_object().unwrap().len(), 14);
    assert_ne!(fresh.challenge, old.challenge);
    assert_eq!(
        f.gate
            .consume(consume_request(&fresh, Decision::Allow, 0))
            .unwrap(),
        State::Applying
    );
    assert_eq!(f.gate.apply(&proposal.id).unwrap(), State::Applied);
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(count_kind(&f.gate.db, &proposal.id, "gate.consume"), 1);
}

#[test]
fn antibody_release_reconciliation_preserves_owner_replacement() {
    let mut f = supervisor_fixture("release");
    let original = supervisor_request("release");
    let proposal = f.gate.owner().raise(original.clone()).unwrap();
    let review = f.gate.owner().review(&proposal.id).unwrap();
    assert_eq!(
        f.gate
            .consume(consume_request(&review, Decision::Allow, 0))
            .unwrap(),
        State::Applying
    );
    f.gate
        .db
        .execute(
            "UPDATE gate_proposals SET write_claimed=1 WHERE id=?",
            [&proposal.id],
        )
        .unwrap();
    f.store
        .files
        .lock()
        .unwrap()
        .insert("release".into(), original.new_bytes.clone());
    f.gate.recover().unwrap();
    assert_eq!(f.gate.state(&proposal.id).unwrap(), Some(State::Incomplete));
    let mut replacement = original.clone();
    replacement.base_sha256 = sha256(&original.new_bytes);
    replacement.idempotency_key = "antibody-reconciled-release".into();
    let mut record: Value = serde_json::from_slice(&replacement.new_bytes).unwrap();
    record["digest"] = json!("e".repeat(64));
    replacement.new_bytes = canonical(&record).unwrap().into_bytes();
    assert!(matches!(
        f.gate.owner().raise(replacement.clone()),
        Err(Error::Refused("gate:target-fenced"))
    ));
    let auth = f
        .gate
        .owner()
        .reconcile_authorization(&proposal.id)
        .unwrap();
    f.gate
        .owner()
        .reconcile(&proposal.id, &TestProof::sign(&auth, 0))
        .unwrap();
    assert!(verified_reconciliation(&f.gate.db, &f.ledger, &proposal.id)
        .unwrap()
        .is_some());
    assert_eq!(f.store.write_count(), 0);
    let next = f.gate.owner().raise(replacement.clone()).unwrap();
    let review = f.gate.owner().review(&next.id).unwrap();
    assert_eq!(
        f.gate
            .owner()
            .consume(consume_request(&review, Decision::Allow, 0))
            .unwrap(),
        State::Applied
    );
    assert_eq!(f.store.write_count(), 1);
    assert_eq!(
        f.store.read("release").unwrap(),
        Some(replacement.new_bytes)
    );
}

fn guest_request(bytes: &[u8], key: &str) -> ProposalRequest {
    ProposalRequest {
        idempotency_key: key.into(),
        ..proposal_request(bytes)
    }
}

#[test]
fn antibody_guest_proposal_rate_cannot_block_supervisor_raises() {
    // Expect gate:proposal-rate for the guest; its cancelled history cannot block owner raises.
    for target in SUPERVISOR_TARGETS {
        let mut f = supervisor_fixture(target);
        for n in 0..f.cfg.limits.max_per_window {
            let p = f
                .gate
                .guest()
                .propose(guest_request(NEW, &format!("antibody-guest-{n}")))
                .unwrap();
            assert_eq!(f.gate.guest().cancel(&p.id).unwrap(), State::Expired);
        }
        assert!(matches!(
            f.gate
                .guest()
                .propose(guest_request(OTHER, "antibody-overflow")),
            Err(Error::Refused("gate:proposal-rate"))
        ));
        let before: i64 = f
            .gate
            .db
            .query_row("SELECT used FROM gate_budget", [], |r| r.get(0))
            .unwrap();
        let p = f.gate.owner().raise(supervisor_request(target)).unwrap();
        assert_eq!(p.state, State::Pending, "{target}");
        let after: i64 = f
            .gate
            .db
            .query_row("SELECT used FROM gate_budget", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            before, after,
            "{target}: owner raises do not charge the guest"
        );
        assert_eq!(f.clock.now_ms().unwrap(), START);
        assert_eq!(f.store.write_count(), 0);
    }
}

#[test]
fn antibody_guest_reject_cooldown_cannot_block_supervisor_raises() {
    // Expect gate:reject-cooldown for the guest; rejection cannot block owner raises.
    for target in SUPERVISOR_TARGETS {
        let mut f = supervisor_fixture(target);
        let p = f
            .gate
            .guest()
            .propose(guest_request(NEW, "antibody-rejected"))
            .unwrap();
        assert_eq!(f.gate.owner().reject(&p.id).unwrap(), State::Refused);
        assert!(matches!(
            f.gate
                .guest()
                .propose(guest_request(OTHER, "antibody-cooldown")),
            Err(Error::Refused("gate:reject-cooldown"))
        ));
        let p = f.gate.owner().raise(supervisor_request(target)).unwrap();
        assert_eq!(p.state, State::Pending, "{target}");
        assert_eq!(f.clock.now_ms().unwrap(), START);
        assert_eq!(f.store.write_count(), 0);
    }
}

#[test]
fn antibody_operator_rate_window_cannot_block_guest_proposals() {
    // Expect gate:proposal-rate only for the operator that filled its own window.
    let mut f = review_regressions::operator_fixture(Limits {
        ttl_ms: 1_000,
        ..Limits::default()
    });
    for n in 0..f.cfg.limits.max_per_window {
        let mut request =
            review_regressions::operator_request(&f, format!("release-{n}").as_bytes());
        request.idempotency_key = format!("antibody-operator-{n}");
        let p = f.gate.owner().raise(request).unwrap();
        f.clock.set(p.expires_at);
        assert_eq!(f.gate.recover().unwrap(), 1);
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Expired));
    }
    let request = review_regressions::operator_request(&f, b"release-overflow");
    assert!(matches!(
        f.gate.owner().raise(request),
        Err(Error::Refused("gate:proposal-rate"))
    ));
    let p = f
        .gate
        .guest()
        .propose(guest_request(NEW, "antibody-guest"))
        .unwrap();
    assert_eq!(p.state, State::Pending);
    let used: i64 = f
        .gate
        .db
        .query_row("SELECT used FROM gate_budget", [], |r| r.get(0))
        .unwrap();
    assert_eq!(used, 1);
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn antibody_operator_reject_cooldown_cannot_block_guest_proposals() {
    // Expect gate:reject-cooldown only for the operator whose proposal was denied.
    let mut f = review_regressions::operator_fixture(Limits::default());
    let request = review_regressions::operator_request(&f, b"release-denied");
    let p = f.gate.owner().raise(request).unwrap();
    let r = f.gate.owner().review(&p.id).unwrap();
    assert_eq!(
        f.gate
            .owner()
            .consume(consume_request(&r, Decision::Deny, 0))
            .unwrap(),
        State::Refused
    );
    let request = review_regressions::operator_request(&f, b"release-next");
    assert!(matches!(
        f.gate.owner().raise(request),
        Err(Error::Refused("gate:reject-cooldown"))
    ));
    let p = f
        .gate
        .guest()
        .propose(guest_request(NEW, "antibody-guest"))
        .unwrap();
    assert_eq!(p.state, State::Pending);
    assert_eq!(f.clock.now_ms().unwrap(), START);
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn antibody_supervisor_withdrawal_records_signed_terminal_and_allows_replacement() {
    let mut f = supervisor_fixture("release");
    let request = supervisor_request("release");
    let p = f.gate.owner().raise(request.clone()).unwrap();
    assert_eq!(
        f.gate.owner().withdraw_unreviewed(&p.id).unwrap(),
        State::Expired
    );
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Expired));
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 1);
    let (seq, hash, actor): (i64, String, String) = f
        .gate
        .db
        .query_row(
            "SELECT seq,hash,actor FROM aura WHERE op=? AND phase='terminal'",
            [&p.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let row = f
        .ledger
        .read_verified(&f.gate.db, &LedgerRef { seq, hash })
        .unwrap();
    assert_eq!(actor, "supervisor");
    assert_eq!(row.kind, "gate.expire");
    assert_eq!(row.op, p.id);
    assert_eq!(row.phase, "terminal");
    assert_eq!(
        serde_json::from_str::<Value>(&row.body).unwrap(),
        json!({"state":"expired","action":"withdraw","reason":"superseded"})
    );
    assert!(f.gate.owner().review(&p.id).is_err());
    let mut next = request;
    next.idempotency_key = "antibody-next-release".into();
    let replacement = f.gate.owner().raise(next).unwrap();
    assert_eq!(replacement.state, State::Pending);
    assert_eq!(f.clock.now_ms().unwrap(), START);
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn antibody_supervisor_withdrawal_refuses_guest_raised_proposals() {
    let mut f = fixture();
    let p = f.gate.guest().propose(proposal_request(NEW)).unwrap();
    assert!(matches!(
        f.gate.owner().withdraw_unreviewed(&p.id),
        Err(Error::Refused("gate:operator-only"))
    ));
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 0);
    assert_eq!(f.store.write_count(), 0);
}

#[test]
fn antibody_supervisor_withdrawal_refuses_every_issued_approval_challenge() {
    for mode in ["live", "expired", "invalidated", "burned"] {
        let mut f = supervisor_fixture("release");
        let p = f.gate.owner().raise(supervisor_request("release")).unwrap();
        let review = f.gate.owner().review(&p.id).unwrap();
        match mode {
            "expired" => f.clock.set(review.expires_at),
            "invalidated" => {
                f.gate
                    .db
                    .execute(
                        "UPDATE gate_reviews SET state='invalidated' WHERE challenge=?",
                        [&review.challenge],
                    )
                    .unwrap();
            }
            "burned" => {
                assert!(f
                    .gate
                    .owner()
                    .consume(consume_request(&review, Decision::Unknown, 0))
                    .is_err());
            }
            _ => {}
        }
        assert!(
            matches!(
                f.gate.owner().withdraw_unreviewed(&p.id),
                Err(Error::Refused("gate:owner-retirement-required"))
            ),
            "{mode}"
        );
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending), "{mode}");
        assert_eq!(terminal_rows(&f.gate.db, &p.id), 0, "{mode}");
        assert_eq!(f.store.write_count(), 0, "{mode}");
    }
}

#[test]
fn antibody_supervisor_withdrawal_refuses_issued_retirement_challenges() {
    for mode in ["live", "expired", "invalidated"] {
        let mut f = supervisor_fixture("release");
        let p = f.gate.owner().raise(supervisor_request("release")).unwrap();
        let auth = f.gate.owner().retire_authorization(&p.id).unwrap();
        if mode == "expired" {
            let auth: Value = serde_json::from_slice(&auth).unwrap();
            f.clock.set(auth["expires_at"].as_i64().unwrap());
        } else if mode == "invalidated" {
            f.gate
                .db
                .execute(
                    "UPDATE gate_actions SET state='invalidated' WHERE proposal_id=?",
                    [&p.id],
                )
                .unwrap();
        }
        assert!(
            matches!(
                f.gate.owner().withdraw_unreviewed(&p.id),
                Err(Error::Refused("gate:owner-retirement-required"))
            ),
            "{mode}"
        );
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending), "{mode}");
        assert_eq!(terminal_rows(&f.gate.db, &p.id), 0, "{mode}");
        assert_eq!(f.store.write_count(), 0, "{mode}");
    }
}

#[test]
fn antibody_supervisor_withdrawal_refuses_nonpending_proposals() {
    for state in [
        State::Applying,
        State::Applied,
        State::Incomplete,
        State::Failed,
        State::Conflict,
        State::Refused,
        State::Expired,
        State::Retired,
    ] {
        let mut f = supervisor_fixture("release");
        let p = f.gate.owner().raise(supervisor_request("release")).unwrap();
        let tx = f.gate.db.transaction().unwrap();
        if matches!(state, State::Applied | State::Failed | State::Conflict) {
            transition(&tx, &p, State::Applying, START).unwrap();
            let p = load_proposal(&tx, &p.id).unwrap().unwrap();
            transition(&tx, &p, state, START).unwrap();
        } else {
            transition(&tx, &p, state, START).unwrap();
        }
        tx.commit().unwrap();
        assert!(
            matches!(
                f.gate.owner().withdraw_unreviewed(&p.id),
                Err(Error::Refused("gate:not-pending"))
            ),
            "{state:?}"
        );
        assert_eq!(f.gate.state(&p.id).unwrap(), Some(state), "{state:?}");
        assert_eq!(terminal_rows(&f.gate.db, &p.id), 0, "{state:?}");
        assert_eq!(f.store.write_count(), 0, "{state:?}");
    }
}

#[test]
fn antibody_supervisor_withdrawal_requires_atomic_ledger_commit() {
    let mut f = supervisor_fixture("release");
    let p = f.gate.owner().raise(supervisor_request("release")).unwrap();
    f.ledger.fail_next.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.gate.owner().withdraw_unreviewed(&p.id),
        Err(Error::Refused("gate:test-ledger-failed"))
    ));
    assert_eq!(f.gate.state(&p.id).unwrap(), Some(State::Pending));
    assert_eq!(terminal_rows(&f.gate.db, &p.id), 0);
    assert_eq!(f.store.write_count(), 0);
}
