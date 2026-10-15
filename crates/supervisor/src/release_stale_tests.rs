// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::node::Node;
use crate::runtime::{RuntimeBackend, RuntimeDigests, RuntimeStatus};
use frontdoor::Operation;
use serde_json::{json, Value};
use std::time::Duration;

fn digests(byte: char) -> RuntimeDigests {
    serde_json::from_value(json!({"digest":byte.to_string().repeat(64),"components":{
        "node":"a".repeat(64),"harness":"b".repeat(64),"guest":"c".repeat(64),
    }}))
    .unwrap()
}

fn status(node: &Node, current: &RuntimeDigests, approved: Option<&str>, agent: &str) {
    node.runtime_changed(&RuntimeStatus {
        current_digest: current.digest.clone(),
        approved_digest: approved.map(str::to_owned),
        agent: agent.into(),
        since: 0,
    })
    .unwrap();
}

async fn approve(node: &Node, current: &RuntimeDigests) {
    status(node, current, None, "stopped");
    let corpus = ::immune::Corpus::from_bytes([
        br##"{"expected_refusal":"gate:operator-only","guarded_issue":"#54","id":"stale-release","organ":"gate","scenario":{}}"##
            .as_slice(),
    ])
    .unwrap();
    let report = ::immune::run(&corpus, Duration::from_secs(1), |vector| {
        Ok(vector.expected_refusal.clone())
    });
    assert!(node.propose_immune_release(current, &report).unwrap());
    let id: String = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id FROM gate_proposals WHERE target='release' AND state='pending'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let challenge = node
        .test_call("owner", Operation::ApprovalChallenge, json!({"id":id}))
        .await
        .unwrap();
    let assertion =
        crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 1);
    let outcome = node
        .test_call(
            "owner",
            Operation::ApprovalDecide,
            json!({"id":id,"approve":true,"assertion":assertion}),
        )
        .await
        .unwrap();
    assert_eq!(outcome["state"], "applied");
    assert_eq!(node.approved_release().unwrap().as_ref(), Some(current));
}

fn refusal(node: &Node, digest: &str, code: &str) -> i64 {
    let mut db = node.db.lock().unwrap();
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    node.audit(
        &tx,
        "gate.refuse",
        "",
        "fact",
        json!({"code":code,"runtime_digest":digest,"immune_release":{}}),
    )
    .unwrap();
    let seq = tx
        .query_row("SELECT max(seq) FROM aura", [], |row| row.get(0))
        .unwrap();
    tx.commit().unwrap();
    seq
}

async fn assert_refusal(node: &Node, expected: Option<&str>) {
    assert_eq!(node.release_immune_refusal().unwrap().as_deref(), expected);
    let release = node
        .test_call("owner", Operation::Release, json!({}))
        .await
        .unwrap();
    assert_eq!(release["immune_refusal"], json!(expected));
    let approvals = node
        .test_call("owner", Operation::Approvals, json!({}))
        .await
        .unwrap();
    let cards = approvals["pending"].as_array().unwrap();
    let card = cards.iter().find(|card| card["id"] == "immune-refusal");
    if let Some(code) = expected {
        assert!(card.unwrap()["card"]["facts"]
            .as_array()
            .unwrap()
            .contains(&json!(["refusal", code])));
    } else {
        assert!(card.is_none());
    }
}

#[test]
fn antibody_approved_running_release_clears_a_later_cached_refusal() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('1');
    runtime.block_on(approve(&node, &current));
    status(&node, &current, Some(&current.digest), "stopped");
    let seq = refusal(&node, &current.digest, "immune:antibody-failed");
    runtime.block_on(assert_refusal(&node, Some("immune:antibody-failed")));
    status(&node, &current, Some(&current.digest), "running");
    runtime.block_on(assert_refusal(&node, None));
    let config = node.config.clone();
    drop(node);
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    status(&node, &current, Some(&current.digest), "running");
    runtime.block_on(assert_refusal(&node, None));
    let db = node.db.lock().unwrap();
    aura::walk_database(&db, &node.signer.verifying_key(), None).unwrap();
    let body: String = db
        .query_row("SELECT body FROM aura WHERE seq=?", [seq], |row| row.get(0))
        .unwrap();
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["code"], "immune:antibody-failed");
    assert_eq!(body["runtime_digest"], current.digest);
}

#[test]
fn antibody_identical_refusal_clears_when_verified_release_needs_no_proposal() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('2');
    runtime.block_on(approve(&node, &current));
    assert!(!node.config.release_floor);
    status(&node, &current, Some(&current.digest), "stopped");
    refusal(&node, &current.digest, "gate:identical");
    runtime.block_on(assert_refusal(&node, None));
}

#[test]
fn antibody_stale_refusal_requires_the_actual_current_release_approval() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let current = digests('3');
    let other = digests('4');
    runtime.block_on(approve(&node, &current));
    status(&node, &current, Some(&other.digest), "running");
    refusal(&node, &current.digest, "immune:antibody-failed");
    runtime.block_on(assert_refusal(&node, Some("immune:antibody-failed")));
    status(&node, &other, Some(&other.digest), "running");
    refusal(&node, &other.digest, "immune:antibody-failed");
    runtime.block_on(assert_refusal(&node, Some("immune:antibody-failed")));
    refusal(&node, &other.digest, "gate:identical");
    status(&node, &other, Some(&other.digest), "stopped");
    runtime.block_on(assert_refusal(&node, Some("gate:identical")));
}
