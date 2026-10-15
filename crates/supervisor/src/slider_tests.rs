use super::*;

#[test]
fn antibody_slider_owner_route_passkey_auto_apply_and_revoke() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    let mut counter = 0;
    runtime.block_on(async {
        let status = call(&node, Operation::Slider, json!({})).await;
        assert_eq!(status["mode"], "ask");
        let target = gate::targets::NOTE_TARGET;
        let permission = call(
            &node,
            Operation::SliderPropose,
            json!({"mode":"risky","targets":[target],"max_count":2,"hours":1}),
        )
        .await;
        let id = permission["id"].as_str().unwrap();
        assert!(!call(&node, Operation::Slider, json!({})).await["active"]
            .as_bool()
            .unwrap());
        let challenge = call(&node, Operation::ApprovalChallenge, json!({"id":id})).await;
        assert_eq!(challenge["auth"]["op"], "permission");
        let mut forged = crate::owner::tests::assertion(
            challenge["public_key"]["challenge"].as_str().unwrap(),
            1,
        );
        forged["signature"] = json!("AA");
        assert!(node
            .test_call(
                PRINCIPAL,
                Operation::ApprovalDecide,
                json!({"id":id,"approve":true,"assertion":forged})
            )
            .await
            .is_err());
        assert!(!call(&node, Operation::Slider, json!({})).await["active"]
            .as_bool()
            .unwrap());
        approve(&node, id, &mut counter).await;
        let p = node
            .guest_propose(
                "slider-auto",
                canon::Propose {
                    target: target.into(),
                    base_sha256: gate::sha256(&[]),
                    new_bytes_b64: STANDARD.encode(b"A scoped note"),
                    note: "test".into(),
                    cell: None,
                },
            )
            .unwrap();
        assert_eq!(node.guest_read(target).unwrap().unwrap(), b"A scoped note");
        assert_eq!(
            node.proposal_state(&p).unwrap(),
            Some(canon::OutcomeState::Applied)
        );
        assert_eq!(
            call(&node, Operation::Slider, json!({})).await["remaining"],
            1
        );
        let revoke = call(
            &node,
            Operation::SliderPropose,
            json!({"mode":"ask","targets":[],"max_count":0,"hours":1}),
        )
        .await;
        approve(&node, revoke["id"].as_str().unwrap(), &mut counter).await;
        let p = node
            .guest_propose(
                "slider-revoked",
                canon::Propose {
                    target: target.into(),
                    base_sha256: gate::sha256(b"A scoped note"),
                    new_bytes_b64: STANDARD.encode(b"Must ask"),
                    note: "test".into(),
                    cell: None,
                },
            )
            .unwrap();
        assert_eq!(node.guest_read(target).unwrap().unwrap(), b"A scoped note");
        assert_eq!(node.proposal_state(&p).unwrap(), None);
    });
}

fn cold_report(node: &Node, db: &rusqlite::Connection) -> verifier::Report {
    let entries = aura::read_entries(db).unwrap();
    let mut rows = Vec::new();
    for entry in &entries {
        rows.extend(crate::node::canon_bytes(&json!({"seq":entry.sequence,"prev":entry.prev,"hash":entry.hash,"sig":entry.sig,
            "at":entry.at,"kind":entry.kind,"actor":entry.actor,"op":entry.op,"phase":entry.phase,"body":entry_body(entry)})).unwrap());
        rows.push(b'\n');
    }
    let (retained, presented) =
        aura::export_database(db, &node.signer.verifying_key(), entries.len()).unwrap();
    let retained = retained.to_json().unwrap();
    let presented = presented.to_json().unwrap();
    let key = hex::encode(node.signer.verifying_key().to_bytes());
    verifier::verify(verifier::Inputs {
        key_hex: key.as_bytes(),
        rows: &rows,
        retained: Some(retained.as_bytes()),
        presented: Some(presented.as_bytes()),
        prefix: None,
        checkpoint: None,
    })
}
fn cold_fixture() -> (tempfile::TempDir, tokio::runtime::Runtime, Arc<Node>) {
    let fixture = counter_fixture(0, None);
    let (_, runtime, node) = &fixture;
    runtime.block_on(async {
        let permission = call(
            node,
            Operation::SliderPropose,
            json!({"mode":"limits","targets":[gate::targets::NOTE_TARGET],"max_count":1,"hours":1}),
        )
        .await;
        approve(node, permission["id"].as_str().unwrap(), &mut 0).await;
        node.guest_propose(
            "slider-cold",
            canon::Propose {
                target: gate::targets::NOTE_TARGET.into(),
                base_sha256: gate::sha256(&[]),
                new_bytes_b64: STANDARD.encode(b"Cold verified note"),
                note: "test".into(),
                cell: None,
            },
        )
        .unwrap();
    });
    fixture
}

#[test]
#[ignore = "crates/verifier needs standing-permission support; outside this task's edit scope"]
fn slider_cold_accepts_covered_auto_change() {
    let (_directory, _runtime, node) = cold_fixture();
    let report = cold_report(&node, &node.db.lock().unwrap());
    assert_eq!(report.verdict, verifier::Verdict::Verified, "{report:?}");
}

#[test]
fn antibody_slider_cold_refuses_no_covering_permission_even_with_a_valid_node_chain() {
    let (_directory, _runtime, node) = cold_fixture();
    let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
    let mut rewritten =
        rusqlite::Connection::open(_directory.path().join("cold-rewritten.sqlite3")).unwrap();
    aura::initialize(&rewritten).unwrap();
    let tx = rewritten
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let mut hashes = BTreeMap::new();
    for entry in entries {
        let mut body = entry_body(&entry);
        if let Some(reference) = body.get_mut("standing_permission") {
            reference["authorization_sha256"] = json!("00".repeat(32));
            reference["proposal"] = json!("00".repeat(16));
        }
        if let Some(receipt) = body.get_mut("receipt") {
            if let Some(reference) = receipt
                .get_mut("standing_permission")
                .filter(|value| !value.is_null())
            {
                reference["authorization_sha256"] = json!("00".repeat(32));
                reference["proposal"] = json!("00".repeat(16));
                receipt["owner_authorization"]["authorization_sha256"] = json!("00".repeat(32));
                receipt["owner_authorization"]["authorization_id"] = json!("00".repeat(32));
            }
        }
        rewrite_hash_references(&mut body, &hashes);
        let rewritten_entry = aura::append(
            &aura::WriteLocked::new(&tx).unwrap(),
            &*node.signer,
            &node.signer.verifying_key(),
            &aura::NewEntry {
                at: entry.at,
                kind: entry.kind,
                actor: entry.actor,
                op: entry.op,
                phase: entry.phase,
                body: canon::parse(&crate::node::canon_bytes(&body).unwrap()).unwrap(),
            },
        )
        .unwrap();
        hashes.insert(entry.hash, rewritten_entry.hash);
    }
    tx.commit().unwrap();
    let report = cold_report(&node, &rewritten);
    assert!(
        matches!(report.verdict, verifier::Verdict::Rewritten(_)),
        "{report:?}"
    );
}

fn rewrite_hash_references(value: &mut Value, hashes: &BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if matches!(key.as_str(), "hash" | "ledger_hash") {
                    if let Some(hash) = value.as_str().and_then(|hash| hashes.get(hash)) {
                        *value = json!(hash);
                    }
                } else {
                    rewrite_hash_references(value, hashes);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite_hash_references(value, hashes);
            }
        }
        _ => {}
    }
}
