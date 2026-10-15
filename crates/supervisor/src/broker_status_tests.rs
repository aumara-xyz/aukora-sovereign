// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn fixture() -> (tempfile::TempDir, tokio::runtime::Runtime, Arc<Node>) {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/provider-status-state");
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let directory = tempfile::Builder::new().tempdir_in(root).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let config = crate::e2e::config(directory.path());
    let node = Node::open(config, runtime.handle().clone()).unwrap();
    node.db
        .lock()
        .unwrap()
        .execute_batch(include_str!("../../gate/src/schema.sql"))
        .unwrap();
    (directory, runtime, node)
}

fn append(node: &Node, at: i64, kind: &'static str, phase: &'static str, body: Value) {
    let mut db = node.db.lock().unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    node.ledger()
        .append(
            &tx,
            &gate::LedgerRow {
                at,
                kind,
                actor: "broker".into(),
                op: state::random_id().unwrap(),
                phase,
                body: serde_json::to_string(&body).unwrap(),
            },
        )
        .unwrap();
    tx.commit().unwrap();
}

fn status(node: &Node) -> Value {
    node.owner_call(Operation::Broker, json!({})).unwrap()
}

#[test]
fn antibody_owner_model_refusal_projects_only_allowlisted_categories() {
    let (_directory, _runtime, node) = fixture();
    assert!(status(&node)["last_refusal"].is_null());
    const POISON: &str = "sk-or-fake-key-provider-body-must-never-leave-aura-984521";
    for code in [
        "broker:provider-key-rejected",
        "broker:provider-no-credit",
        "broker:provider-rate-limited",
        "broker:provider-request-rejected",
        "broker:provider-unavailable",
        "broker:provider-refused",
    ] {
        append(
            &node,
            1,
            "broker.settle",
            "terminal",
            json!({"outcome":"refused","code":code,"provider_status":402,
                "body":POISON,"next":POISON,"message":POISON}),
        );
        let result = status(&node);
        assert_eq!(result["last_refusal"], json!({"code":code}));
        assert!(!result.to_string().contains(POISON));
        for poison_code in [
            json!(POISON),
            json!({"code":POISON}),
            json!([POISON]),
            Value::Null,
        ] {
            append(
                &node,
                2,
                "broker.settle",
                "terminal",
                json!({"outcome":"refused","code":poison_code}),
            );
            let result = status(&node);
            assert_eq!(result["last_refusal"], json!({"code":code}));
            assert!(!result.to_string().contains(POISON));
        }
    }
}

#[test]
fn antibody_owner_model_refusal_uses_aura_sequence_across_restart() {
    let (_directory, runtime, node) = fixture();
    append(
        &node,
        9_999,
        "broker.settle",
        "terminal",
        json!({"outcome":"refused","code":"broker:provider-no-credit"}),
    );
    append(
        &node,
        1,
        "broker.settle",
        "terminal",
        json!({"outcome":"unknown","code":"broker:provider-unavailable"}),
    );
    let expected = json!({"code":"broker:provider-unavailable"});
    assert_eq!(status(&node)["last_refusal"], expected);
    let config = node.config.clone();
    drop(node);
    let reopened = Node::open(config, runtime.handle().clone()).unwrap();
    assert_eq!(status(&reopened)["last_refusal"], expected);
}

#[test]
fn antibody_owner_model_refusal_requires_a_terminal_refusal() {
    let (_directory, _runtime, node) = fixture();
    for (kind, phase, outcome) in [
        ("broker.settle", "intent", "refused"),
        ("broker.reserve", "terminal", "refused"),
        ("broker.settle", "terminal", "settled"),
    ] {
        append(
            &node,
            1,
            kind,
            phase,
            json!({"outcome":outcome,"code":"broker:provider-no-credit"}),
        );
        assert!(status(&node)["last_refusal"].is_null());
    }
}
