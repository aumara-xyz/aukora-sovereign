// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::node::Node;
use crate::runtime::{RuntimeBackend, RuntimeStatus};
use frontdoor::Operation;
use rusqlite::TransactionBehavior;
use serde_json::{json, Value};

fn record_refusal(node: &Node, code: &str) {
    let digest = "a".repeat(64);
    node.runtime_changed(&RuntimeStatus {
        current_digest: digest.clone(),
        approved_digest: None,
        agent: "stopped".into(),
        since: 0,
    })
    .unwrap();
    let mut db = node.db.lock().unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    node.audit(
        &tx,
        "gate.refuse",
        "",
        "fact",
        json!({"code":code,"runtime_digest":digest,"immune_release":{}}),
    )
    .unwrap();
    tx.commit().unwrap();
}

async fn visible_refusal(node: &Node, expected: &str) -> (Value, Value) {
    assert_eq!(
        node.release_immune_refusal().unwrap().as_deref(),
        Some(expected)
    );
    let status = node
        .test_call("owner", Operation::Release, json!({}))
        .await
        .unwrap();
    assert_eq!(status["immune_refusal"], expected);
    let approvals = node
        .test_call("owner", Operation::Approvals, json!({}))
        .await
        .unwrap();
    let card = &approvals["pending"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "immune-refusal")
        .unwrap()["card"];
    assert!(card["facts"]
        .as_array()
        .unwrap()
        .contains(&json!(["refusal", expected])));
    (status, approvals)
}

#[test]
fn antibody_release_refusals_preserve_underlying_codes() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    for code in [
        "gate:identical",
        "immune:floor-unavailable",
        "immune:future-refusal",
    ] {
        record_refusal(&node, code);
        runtime.block_on(visible_refusal(&node, code));
    }
}

#[test]
fn antibody_release_refusals_redact_invalid_codes() {
    let (_directory, runtime, node, _binding) = crate::e2e::binding_fixture(0, None);
    let too_long = format!("immune:{}", "x".repeat(74));
    for code in [
        "immune:floor-unavailable secret=disposable-secret-value",
        "immune:reason:disposable-secret-value",
        "immune:disposable_secret_value",
        "Immune:reason",
        "immune:1reason",
        "immune:",
        "reason",
        too_long.as_str(),
    ] {
        record_refusal(&node, code);
        let (status, approvals) =
            runtime.block_on(visible_refusal(&node, "immune:invalid-refusal-code"));
        for response in [status, approvals] {
            assert!(!response.to_string().contains("disposable-secret-value"));
            assert!(!response.to_string().contains("disposable_secret_value"));
        }
    }
}
