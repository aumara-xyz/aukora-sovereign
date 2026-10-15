// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::node::Node;
use crate::runtime::{RuntimeBackend, RuntimeDigests, RuntimeStatus};
use frontdoor::Operation;
use serde_json::{json, Value};
use std::time::Duration;

fn corpus() -> ::immune::Corpus {
    ::immune::Corpus::from_bytes([
        br##"{"expected_refusal":"gate:operator-only","guarded_issue":"#41","id":"a","organ":"gate","scenario":{}}"##.as_slice(),
        br##"{"expected_refusal":"frontdoor:origin","guarded_issue":"#41","id":"b","organ":"frontdoor","scenario":{}}"##.as_slice(),
    ]).unwrap()
}

fn report() -> ::immune::Report {
    ::immune::run(&corpus(), Duration::from_secs(1), |vector| {
        Ok(vector.expected_refusal.clone())
    })
}

fn digests(byte: char) -> RuntimeDigests {
    serde_json::from_value(json!({"digest":byte.to_string().repeat(64),"components":{
        "node":"a".repeat(64),"harness":"b".repeat(64),"guest":"c".repeat(64),
    }}))
    .unwrap()
}

fn measured(node: &Node, digests: &RuntimeDigests) {
    node.runtime_changed(&RuntimeStatus {
        current_digest: digests.digest.clone(),
        approved_digest: None,
        agent: "stopped".into(),
        since: 0,
    })
    .unwrap();
}

async fn approve(node: &Node, id: &str) {
    let challenge = node
        .test_call(
            "immune-test-owner",
            Operation::ApprovalChallenge,
            json!({"id":id}),
        )
        .await
        .unwrap();
    let assertion =
        crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 1);
    let outcome = node
        .test_call(
            "immune-test-owner",
            Operation::ApprovalDecide,
            json!({"id":id,"approve":true,"assertion":assertion}),
        )
        .await
        .unwrap();
    assert_eq!(outcome["state"], "applied");
}

fn pending(node: &Node) -> i64 {
    node.db
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM gate_proposals WHERE target='release' AND state='pending'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

fn refusal_body(node: &Node) -> Value {
    let body: String = node.db.lock().unwrap().query_row("SELECT body FROM aura WHERE kind='gate.refuse' AND phase='fact' ORDER BY seq DESC LIMIT 1",[],|row|row.get(0)).unwrap();
    serde_json::from_str(&body).unwrap()
}

#[test]
fn antibody_applied_corpus_floor_refuses_a_missing_id_after_restart() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let first = digests('1');
    measured(&node, &first);
    assert!(node.propose_immune_release(&first, &report()).unwrap());
    assert!(node.antibody_floor().unwrap().is_empty());
    let id: String = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id FROM gate_proposals WHERE target='release'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    runtime.block_on(approve(&node, &id));
    assert_eq!(
        node.antibody_floor().unwrap(),
        corpus().ids().into_iter().collect()
    );
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    let next = digests('2');
    measured(&node, &next);
    let smaller = ::immune::Corpus::from_bytes([br##"{"expected_refusal":"gate:operator-only","guarded_issue":"#41","id":"a","organ":"gate","scenario":{}}"##.as_slice()]).unwrap();
    let dropped = ::immune::run(&smaller, Duration::from_secs(1), |vector| {
        Ok(vector.expected_refusal.clone())
    });
    assert!(node.propose_immune_release(&next, &dropped).unwrap());
    assert_eq!(pending(&node), 1);
    assert_eq!(refusal_body(&node)["code"], "immune:corpus-regressed");
    assert_eq!(refusal_body(&node)["missing_ids"], json!(["b"]));
}

#[test]
fn antibody_failed_replay_refuses_release_and_shows_the_aura_reason() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('3');
    measured(&node, &current);
    let failed = ::immune::run(&corpus(), Duration::from_secs(1), |_| Ok("ok".into()));
    assert!(node.propose_immune_release(&current, &failed).unwrap());
    assert_eq!(pending(&node), 1);
    assert_eq!(refusal_body(&node)["code"], "immune:antibody-failed");
    assert_eq!(refusal_body(&node)["failed_ids"], json!(["a", "b"]));
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    assert_eq!(listed["pending"][0]["override_required"], true);
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("immune:antibody-failed")
    );
    assert!(node.propose_immune_release(&current, &report()).unwrap());
    assert_eq!(node.release_immune_refusal().unwrap().as_deref(), None);
    assert_eq!(pending(&node), 1);
}

#[test]
fn antibody_exhausted_replay_budget_refuses_release() {
    let (_directory, _runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('4');
    measured(&node, &current);
    let exhausted = ::immune::run(&corpus(), Duration::ZERO, |_| {
        panic!("zero budget cannot replay")
    });
    assert!(node.propose_immune_release(&current, &exhausted).unwrap());
    assert_eq!(pending(&node), 1);
    assert_eq!(refusal_body(&node)["code"], "immune:budget-exhausted");
}

#[test]
fn antibody_release_facts_survive_restart_and_require_passkey_approval() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('5');
    measured(&node, &current);
    let replayed = report();
    assert!(node.propose_immune_release(&current, &replayed).unwrap());
    assert!(node.approved_release().unwrap().is_none());
    assert!(node.antibody_floor().unwrap().is_empty());
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    let card = &listed["pending"][0]["card"];
    assert!(card["facts"]
        .as_array()
        .unwrap()
        .contains(&json!(["antibody_corpus_sha256", replayed.root])));
    assert!(card["facts"]
        .as_array()
        .unwrap()
        .contains(&json!(["antibody_pass_count/total", "2/2"])));
    assert_eq!(
        card["target_review"]["pinned"]["antibody_ids_sha256"],
        gate::sha256(&crate::node::canon_bytes(&json!(["a", "b"])).unwrap())
    );
    let id = listed["pending"][0]["id"].as_str().unwrap();
    let challenge = runtime
        .block_on(node.test_call("owner", Operation::ApprovalChallenge, json!({"id":id})))
        .unwrap();
    let unsigned = runtime.block_on(node.test_call(
        "owner",
        Operation::ApprovalDecide,
        json!({"id":id,"approve":true,"assertion":{}}),
    ));
    assert!(unsigned.is_err());
    assert!(node.approved_release().unwrap().is_none());
    assert_eq!(
        challenge["auth"]["display_sha256"],
        gate::sha256(&crate::node::canon_bytes(card).unwrap())
    );
}

#[test]
fn antibody_runtime_proposal_runs_the_embedded_corpus() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('6');
    measured(&node, &current);
    node.ensure_release(&current).unwrap();
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    let pinned = &listed["pending"][0]["card"]["target_review"]["pinned"];
    let embedded = ::immune::Corpus::embedded().unwrap();
    assert_eq!(pinned["antibody_corpus_sha256"], embedded.root());
    assert_eq!(pinned["antibody_pass_count"], embedded.vectors().len());
    assert_eq!(pinned["antibody_ids_count"], embedded.ids().len());
}

#[test]
fn antibody_release_recovers_a_proposal_committed_before_immune_evidence() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('7');
    let bytes = crate::node::canon_bytes(
        &json!({"v":1,"digest":current.digest,"components":current.components}),
    )
    .unwrap();
    let hash = gate::sha256(&bytes);
    let replayed = report();
    let id = {
        let mut guard = node.gate.lock().unwrap();
        let gate = guard.as_mut().unwrap();
        gate.set_release_evidence(&hash,&json!({"new_sha256":hash,"antibody_corpus_sha256":replayed.root,
            "antibody_pass_count":replayed.passed,"antibody_total":replayed.total,"antibody_ids":replayed.ids})).unwrap();
        gate.owner()
            .raise(gate::ProposalRequest {
                target: "release".into(),
                base_sha256: "absent".into(),
                new_bytes: bytes,
                note: String::new(),
                idempotency_key: "crash-before-immune-fact".into(),
                cell: None,
            })
            .unwrap()
            .id
    };
    assert!(!node.has_release_evidence(&id).unwrap());
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    measured(&node, &current);
    node.ensure_release(&current).unwrap();
    assert!(node.has_release_evidence(&id).unwrap());
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    assert_eq!(listed["pending"].as_array().unwrap().len(), 1);
    assert_eq!(listed["pending"][0]["id"], id);
    assert_eq!(
        listed["pending"][0]["card"]["target_review"]["pinned"]["antibody_ids_count"],
        ::immune::Corpus::embedded().unwrap().ids().len()
    );
}

#[test]
fn antibody_immune_refusal_remains_visible_alongside_owner_cards() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let other = runtime
        .block_on(node.test_call(
            "owner",
            Operation::BrokerKeyPropose,
            json!({"key_sha256":"f".repeat(64)}),
        ))
        .unwrap();
    let current = digests('8');
    measured(&node, &current);
    let failed = ::immune::run(&corpus(), Duration::from_secs(1), |_| Ok("ok".into()));
    assert!(node.propose_immune_release(&current, &failed).unwrap());
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    let items = listed["pending"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["id"], other["id"]);
    assert_eq!(items[1]["state"], "pending");
    assert_eq!(items[1]["override_required"], true);
    assert_eq!(items[2]["state"], "refused");
    assert!(items[2]["card"]["facts"]
        .as_array()
        .unwrap()
        .contains(&json!(["refusal", "immune:antibody-failed"])));
    assert_eq!(
        items[1]["display_sha256"],
        gate::sha256(&crate::node::canon_bytes(&items[1]["card"]).unwrap())
    );
    assert_eq!(pending(&node), 1);
}

#[test]
fn antibody_new_corpus_after_retirement_restores_latest_signed_release_facts() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('9');
    measured(&node, &current);
    assert!(node.propose_immune_release(&current, &report()).unwrap());
    let old_id: String = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id FROM gate_proposals WHERE target='release'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    runtime.block_on(async {
        node.test_call("owner", Operation::ApprovalChallenge, json!({"id":old_id}))
            .await
            .unwrap();
        let retire = node
            .test_call(
                "owner",
                Operation::ApprovalRetireChallenge,
                json!({"id":old_id}),
            )
            .await
            .unwrap();
        let assertion =
            crate::owner::tests::assertion(retire["public_key"]["challenge"].as_str().unwrap(), 1);
        let result = node
            .test_call(
                "owner",
                Operation::ApprovalRetire,
                json!({"id":old_id,"assertion":assertion}),
            )
            .await
            .unwrap();
        assert_eq!(result["state"], "retired");
    });
    let mut expanded = Vec::new();
    for id in ["a", "b", "c"] {
        expanded.push(crate::node::canon_bytes(&json!({"id":id,"guarded_issue":"#41","organ":"gate","scenario":{},"expected_refusal":"gate:operator-only"})).unwrap());
    }
    let expanded = ::immune::Corpus::from_bytes(expanded).unwrap();
    let replayed = ::immune::run(&expanded, Duration::from_secs(1), |vector| {
        Ok(vector.expected_refusal.clone())
    });
    assert!(node.propose_immune_release(&current, &replayed).unwrap());
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    assert_eq!(listed["pending"].as_array().unwrap().len(), 1);
    assert_ne!(listed["pending"][0]["id"], old_id);
    assert_eq!(
        listed["pending"][0]["card"]["target_review"]["pinned"]["antibody_corpus_sha256"],
        expanded.root()
    );
    assert!(node.antibody_floor().unwrap().is_empty());
}

fn release_id(node: &Node) -> String {
    node.db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id FROM gate_proposals WHERE target='release' ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
fn sized_report(count: usize) -> ::immune::Report {
    let vectors = (0..count).map(|i|crate::node::canon_bytes(&json!({"id":format!("guarded-behaviour-{i:05}"),
        "guarded_issue":"#41","organ":"gate","scenario":{},"expected_refusal":"gate:operator-only"})).unwrap()).collect::<Vec<_>>();
    let corpus = ::immune::Corpus::from_bytes(vectors).unwrap();
    ::immune::run(&corpus, Duration::from_secs(5), |v| {
        Ok(v.expected_refusal.clone())
    })
}
fn recorded_evidence(node: &Node, id: &str) -> Value {
    let body: String = node.db.lock().unwrap().query_row("SELECT body FROM aura WHERE kind='gate.propose' AND phase='fact' AND json_extract(body,'$.release_proposal')=? ORDER BY seq DESC LIMIT 1",[id],|r|r.get(0)).unwrap();
    serde_json::from_str::<Value>(&body).unwrap()["immune_release"].clone()
}
fn orphan(node: &Node, current: &RuntimeDigests) -> String {
    let bytes = crate::node::canon_bytes(
        &json!({"v":1,"digest":current.digest,"components":current.components}),
    )
    .unwrap();
    let hash = gate::sha256(&bytes);
    let r = report();
    let mut guard = node.gate.lock().unwrap();
    let gate = guard.as_mut().unwrap();
    gate.set_release_evidence(
        &hash,
        &json!({"new_sha256":hash,"antibody_corpus_sha256":r.root,"antibody_pass_count":r.passed,
        "antibody_total":r.total,"antibody_ids":r.ids}),
    )
    .unwrap();
    gate.owner()
        .raise(gate::ProposalRequest {
            target: "release".into(),
            base_sha256: "absent".into(),
            new_bytes: bytes,
            note: String::new(),
            idempotency_key: "orphan-release".into(),
            cell: None,
        })
        .unwrap()
        .id
}

#[test]
fn antibody_large_corpus_release_card_keeps_full_ids_only_in_aura() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('a');
    measured(&node, &current);
    let r = sized_report(450);
    assert!(node.propose_immune_release(&current, &r).unwrap());
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    let card = &listed["pending"][0]["card"];
    assert!(crate::node::canon_bytes(card).unwrap().len() < 12_000);
    assert!(card["target_review"]["pinned"]
        .get("antibody_ids")
        .is_none());
    assert_eq!(card["target_review"]["pinned"]["antibody_ids_count"], 450);
    assert_eq!(
        card["target_review"]["pinned"]["antibody_ids_sha256"],
        gate::sha256(&crate::node::canon_bytes(&json!(r.ids)).unwrap())
    );
    let id = release_id(&node);
    assert_eq!(recorded_evidence(&node, &id)["antibody_ids"], json!(r.ids));
    runtime.block_on(approve(&node, &id));
    assert_eq!(node.antibody_floor().unwrap().len(), 450);
}

#[test]
fn antibody_gate_release_refusal_is_visible_and_nonfatal() {
    let (_dir, _runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('b');
    measured(&node, &current);
    assert!(node.propose_immune_release(&current, &report()).unwrap());
    let id = release_id(&node);
    node.db
        .lock()
        .unwrap()
        .execute(
            "UPDATE gate_proposals SET state='incomplete' WHERE id=?",
            [&id],
        )
        .unwrap();
    node.ensure_immune_release_with(&current, |_| Ok(report()))
        .unwrap();
    assert_eq!(refusal_body(&node)["code"], "gate:target-fenced");
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("gate:target-fenced")
    );
    assert!(node.ensure_release(&current).is_ok());
}

#[test]
fn antibody_orphan_failed_replay_withdraws_visibly_without_hiding_other_cards() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let other = runtime
        .block_on(node.test_call(
            "owner",
            Operation::BrokerKeyPropose,
            json!({"key_sha256":"f".repeat(64)}),
        ))
        .unwrap();
    let current = digests('c');
    let old = orphan(&node, &current);
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    measured(&node, &current);
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    assert_eq!(listed["pending"][0]["id"], other["id"]);
    assert_eq!(listed["pending"][1]["unavailable"], true);
    let failed = ::immune::run(&corpus(), Duration::from_secs(1), |_| Ok("ok".into()));
    assert!(node.propose_immune_release(&current, &failed).unwrap());
    assert_ne!(release_id(&node), old);
    let old_state: String = node
        .db
        .lock()
        .unwrap()
        .query_row("SELECT state FROM gate_proposals WHERE id=?", [&old], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(old_state, "expired");
    let terminal: i64 = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM aura WHERE op=? AND kind='gate.expire' AND phase='terminal'",
            [&old],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(terminal, 1);
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    assert_eq!(listed["pending"][0]["id"], other["id"]);
    assert_eq!(listed["pending"][1]["override_required"], true);
}

#[test]
fn antibody_release_immune_fact_cannot_be_mistaken_for_proposal_intent() {
    let (_dir, _runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('d');
    assert!(node.propose_immune_release(&current, &report()).unwrap());
    let id = release_id(&node);
    let rows: i64 = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM aura WHERE kind='gate.propose' AND op=?",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
    assert_eq!(recorded_evidence(&node, &id)["proposal_id"], id);
}

#[test]
fn antibody_running_supervisor_binary_and_proposal_id_require_fresh_replay() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('e');
    assert!(node.propose_immune_release(&current, &report()).unwrap());
    let id = release_id(&node);
    let mut e = recorded_evidence(&node, &id);
    assert_eq!(e["supervisor_binary_sha256"], node.binary_sha256);
    e["supervisor_binary_sha256"] = json!("0".repeat(64));
    {
        let mut db = node.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        node.audit(
            &tx,
            "gate.propose",
            "",
            "fact",
            json!({"release_proposal":id,"runtime_digest":current.digest,"immune_release":e}),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    measured(&node, &current);
    assert!(!node.has_release_evidence(&id).unwrap());
    let mut ran = false;
    node.ensure_immune_release_with(&current, |_| {
        ran = true;
        Ok(report())
    })
    .unwrap();
    assert!(ran);
    assert!(node.has_release_evidence(&id).unwrap());
    assert_eq!(
        recorded_evidence(&node, &id)["supervisor_binary_sha256"],
        node.binary_sha256
    );
    let mut e = recorded_evidence(&node, &id);
    e["proposal_id"] = json!("f".repeat(32));
    {
        let mut db = node.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        node.audit(
            &tx,
            "gate.propose",
            "",
            "fact",
            json!({"release_proposal":id,"runtime_digest":current.digest,"immune_release":e}),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    assert!(!node.has_release_evidence(&id).unwrap());
}

#[test]
fn antibody_environment_replay_retries_with_backoff_and_owner_retry() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('f');
    measured(&node, &current);
    node.ensure_immune_release_with(&current, |_| {
        Err(anyhow::anyhow!("immune:replay-unavailable"))
    })
    .unwrap();
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("immune:replay-unavailable")
    );
    assert!(node.release_retry.lock().unwrap().next.unwrap() > std::time::Instant::now());
    node.ensure_immune_release_with(&current, |_| panic!("backoff must prevent replay"))
        .unwrap();
    node.release_retry.lock().unwrap().next = Some(std::time::Instant::now());
    let mut retried = false;
    node.ensure_immune_release_with(&current, |_| {
        retried = true;
        Err(anyhow::anyhow!("immune:replay-unavailable"))
    })
    .unwrap();
    assert!(retried);
    let outcome = runtime
        .block_on(node.test_call("owner", Operation::ReleaseRetry, json!({})))
        .unwrap();
    assert_eq!(outcome["retry"], "scheduled");
    {
        let mut retry = node.release_retry.lock().unwrap();
        retry.last = Some(std::time::Instant::now() - Duration::from_secs(10));
    }
    runtime
        .block_on(node.test_call("owner", Operation::ReleaseRetry, json!({})))
        .unwrap();
    node.ensure_immune_release_with(&current, |_| Ok(report()))
        .unwrap();
    assert_eq!(node.release_immune_refusal().unwrap().as_deref(), None);
    assert!(node.release_retry.lock().unwrap().next.is_none());
}

#[test]
fn antibody_failed_release_requires_separate_passkey_override_route() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('1');
    measured(&node, &current);
    let failed = ::immune::run(&corpus(), Duration::from_secs(1), |_| Ok("ok".into()));
    assert!(node.propose_immune_release(&current, &failed).unwrap());
    let id = release_id(&node);
    let ordinary = runtime
        .block_on(node.test_call("owner", Operation::ApprovalChallenge, json!({"id":id})))
        .unwrap_err();
    assert_eq!(ordinary.code, "immune:override-required");
    let challenge = runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalDespiteChallenge,
            json!({"id":id}),
        ))
        .unwrap();
    assert_eq!(challenge["card"]["release_override"], true);
    assert_eq!(challenge["auth"]["op"], "release");
    let assertion =
        crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 1);
    let normal = runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalDecide,
            json!({"id":id,"approve":true,"assertion":assertion}),
        ))
        .unwrap_err();
    assert_eq!(normal.code, "immune:override-required");
    assert!(node.approved_release().unwrap().is_none());
    let result = runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalDespiteDecide,
            json!({"id":id,"assertion":assertion}),
        ))
        .unwrap();
    assert_eq!(result["state"], "applied");
    assert!(node.approved_release().unwrap().is_some());
    assert_eq!(node.antibody_floor().unwrap().len(), 2);
    assert!(runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalDespiteDecide,
            json!({"id":id,"assertion":assertion})
        ))
        .is_err());
}

#[test]
fn antibody_immune_floor_and_refusal_cache_invalidate_on_new_facts() {
    let (_dir, _runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('2');
    measured(&node, &current);
    assert!(node.antibody_floor().unwrap().is_empty());
    assert_eq!(node.release_immune_refusal().unwrap().as_deref(), None);
    let walks = node.immune_cache.lock().unwrap().walks;
    for _ in 0..3 {
        assert!(node.antibody_floor().unwrap().is_empty());
        assert_eq!(node.release_immune_refusal().unwrap().as_deref(), None);
    }
    assert_eq!(node.immune_cache.lock().unwrap().walks, walks);
    {
        let mut db = node.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        node.audit(
            &tx,
            "floor.advance",
            "",
            "fact",
            json!({"antibody_ids":["old-antibody"]}),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    assert!(node.antibody_floor().unwrap().contains("old-antibody"));
    assert!(node.immune_cache.lock().unwrap().walks > walks);
    let failed = ::immune::run(&corpus(), Duration::from_secs(1), |_| Ok("ok".into()));
    node.propose_immune_release(&current, &failed).unwrap();
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("immune:corpus-regressed")
    );
    let walks = node.immune_cache.lock().unwrap().walks;
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("immune:corpus-regressed")
    );
    assert_eq!(node.immune_cache.lock().unwrap().walks, walks);
}

#[test]
fn antibody_legacy_release_records_an_empty_floor_advance() {
    let (_dir, _runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    node.record_antibody_floor("legacy-release", &json!({"target_review":null}))
        .unwrap();
    let body: String = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT body FROM aura WHERE kind='floor.advance' AND op='legacy-release'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["antibody_ids"],
        json!([])
    );
}

#[test]
fn antibody_reviewed_pending_upgrade_shows_fresh_binary_evidence() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('3');
    measured(&node, &current);
    let id = orphan(&node, &current);
    let old = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    // The pre-immune gate issued a review before the upgrade.
    node.gate
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .owner()
        .review(&id)
        .unwrap();
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    measured(&node, &current);
    node.ensure_immune_release_with(&current, |_| Ok(report()))
        .unwrap();
    let listed = runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
    let item = &listed["pending"][0];
    assert_eq!(item["id"], id);
    assert_eq!(item["reviewed"], true);
    assert_eq!(item["superseded"], false);
    assert_eq!(
        item["card"]["target_review"]["pinned"]["supervisor_binary_sha256"],
        node.binary_sha256
    );
    assert_ne!(item["display_sha256"], old["pending"][0]["display_sha256"]);
    let ch = runtime
        .block_on(node.test_call("owner", Operation::ApprovalChallenge, json!({"id":id})))
        .unwrap();
    assert_eq!(ch["display_sha256"], item["display_sha256"]);
}

#[test]
fn antibody_owner_retry_and_approvals_remain_available_during_replay() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('4');
    measured(&node, &current);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let worker = node.clone();
    let join = std::thread::spawn(move || {
        worker.ensure_immune_release_with(&current, |_| {
            started_tx.send(()).unwrap();
            finish_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(report())
        })
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let owner = node.clone();
    let handle = runtime.handle().clone();
    let (owner_tx, owner_rx) = std::sync::mpsc::channel();
    let owner_join = std::thread::spawn(move || {
        let retry = handle.block_on(owner.test_call("owner", Operation::ReleaseRetry, json!({})));
        owner_tx.send(retry).unwrap();
    });
    let retry = owner_rx.recv_timeout(Duration::from_secs(2));
    finish_tx.send(()).unwrap();
    join.join().unwrap().unwrap();
    owner_join.join().unwrap();
    assert_eq!(
        retry.expect("owner action cannot wait for replay").unwrap()["retry"],
        "scheduled"
    );
    runtime
        .block_on(node.test_call("owner", Operation::Approvals, json!({})))
        .unwrap();
}

#[test]
fn antibody_owner_retirement_reenables_the_waiting_release() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let first = digests('5');
    measured(&node, &first);
    node.propose_immune_release(&first, &report()).unwrap();
    let id = release_id(&node);
    runtime
        .block_on(node.test_call("owner", Operation::ApprovalChallenge, json!({"id":id})))
        .unwrap();
    let next = digests('6');
    measured(&node, &next);
    node.ensure_immune_release_with(&next, |_| panic!("reviewed target stays fenced"))
        .unwrap();
    let ch = runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalRetireChallenge,
            json!({"id":id}),
        ))
        .unwrap();
    let assertion =
        crate::owner::tests::assertion(ch["public_key"]["challenge"].as_str().unwrap(), 1);
    runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalRetire,
            json!({"id":id,"assertion":assertion}),
        ))
        .unwrap();
    let mut ran = false;
    node.ensure_immune_release_with(&next, |_| {
        ran = true;
        Ok(report())
    })
    .unwrap();
    assert!(ran);
    assert_eq!(pending(&node), 1);
    assert_ne!(release_id(&node), id);
}

async fn assert_release_has_no_refusal(node: &Node) {
    assert_eq!(node.release_immune_refusal().unwrap().as_deref(), None);
    let listed = node
        .test_call("owner", Operation::Approvals, json!({}))
        .await
        .unwrap();
    assert!(listed["pending"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["id"] != "immune-refusal"));
    let status = node
        .test_call("owner", Operation::Release, json!({}))
        .await
        .unwrap();
    assert_eq!(status["immune_refusal"], Value::Null);
}

#[test]
fn antibody_release_approved_during_replay_needs_no_duplicate_proposal() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('d');
    measured(&node, &current);
    assert!(node.propose_immune_release(&current, &report()).unwrap());
    let id = release_id(&node);
    node.ensure_immune_release_with(&current, |_| panic!("healthy pending evidence is retained"))
        .unwrap();
    node.request_immune_retry().unwrap();
    let mut replayed = false;
    node.ensure_immune_release_with(&current, |_| {
        replayed = true;
        runtime.block_on(approve(&node, &id));
        Ok(report())
    })
    .unwrap();
    assert!(replayed);
    assert_eq!(pending(&node), 0);
    runtime.block_on(assert_release_has_no_refusal(&node));
    let refusals: i64 = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM aura WHERE kind='gate.refuse' AND phase='fact'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(refusals, 0);
}

#[test]
fn antibody_applied_override_clears_cached_immune_refusal() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('a');
    measured(&node, &current);
    let failed = ::immune::run(&corpus(), Duration::from_secs(1), |_| Ok("ok".into()));
    assert!(node.propose_immune_release(&current, &failed).unwrap());
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("immune:antibody-failed")
    );
    let id = release_id(&node);
    let challenge = runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalDespiteChallenge,
            json!({"id":id}),
        ))
        .unwrap();
    let assertion =
        crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 1);
    let next = digests('b');
    measured(&node, &next);
    assert!(!node.propose_immune_release(&next, &failed).unwrap());
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("gate:target-fenced")
    );
    let result = runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalDespiteDecide,
            json!({"id":id,"assertion":assertion}),
        ))
        .unwrap();
    assert_eq!(result["state"], "applied");
    assert_eq!(
        node.approved_release().unwrap().unwrap().digest,
        current.digest
    );
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("gate:target-fenced")
    );
    measured(&node, &current);
    runtime.block_on(assert_release_has_no_refusal(&node));
    assert_eq!(refusal_body(&node)["code"], "gate:target-fenced");
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    measured(&node, &current);
    runtime.block_on(assert_release_has_no_refusal(&node));
    measured(&node, &next);
    assert!(node.propose_immune_release(&next, &failed).unwrap());
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("immune:antibody-failed")
    );
}

#[test]
fn antibody_applied_review_clears_later_facts_changed_refusal() {
    let (_dir, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('c');
    measured(&node, &current);
    assert!(node.propose_immune_release(&current, &report()).unwrap());
    let id = release_id(&node);
    let challenge = runtime
        .block_on(node.test_call("owner", Operation::ApprovalChallenge, json!({"id":id})))
        .unwrap();
    assert!(!node
        .propose_immune_release(&current, &sized_report(3))
        .unwrap());
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some("gate:review-facts-changed")
    );
    let assertion =
        crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 1);
    let result = runtime
        .block_on(node.test_call(
            "owner",
            Operation::ApprovalDecide,
            json!({"id":id,"approve":true,"assertion":assertion}),
        ))
        .unwrap();
    assert_eq!(result["state"], "applied");
    runtime.block_on(assert_release_has_no_refusal(&node));
    assert_eq!(refusal_body(&node)["code"], "gate:review-facts-changed");
}
