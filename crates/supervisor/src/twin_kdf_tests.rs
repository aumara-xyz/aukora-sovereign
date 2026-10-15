// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use aumlok::envelope::{Envelope, KdfParams};
use frontdoor::Operation;

fn binding_and_refresh_envelopes(node: &Node) -> (Envelope, Envelope) {
    let principal = format!("owner:{NODE_ID}");
    let mut owner = node.owner.lock().unwrap();
    let start = owner
        .call(&principal, Operation::EnrolStart, json!({}))
        .unwrap();
    let staged = owner
        .call(
            &principal,
            Operation::EnrolFinish,
            json!({
                "enrolment_id": start["enrolment_id"],
                "attestation": registration(start["public_key"]["challenge"].as_str().unwrap()).unwrap()
            }),
        )
        .unwrap();
    owner
        .call(
            &principal,
            Operation::EnrolFinish,
            json!({
                "enrolment_id": start["enrolment_id"],
                "assertion": assertion(staged["public_key"]["challenge"].as_str().unwrap(), 1, false)
            }),
        )
        .unwrap();
    let prepared = owner
        .call(&principal, Operation::BindingPrepare, json!({}))
        .unwrap();
    let phrase = prepared["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    owner
        .call(
            &principal,
            Operation::BindingConfirm,
            json!({"ceremony_id": prepared["ceremony_id"], "words": prepared["words"]}),
        )
        .unwrap();
    let signin = owner
        .call(&principal, Operation::SigninStart, json!({}))
        .unwrap();
    let digest = [75; 32];
    owner
        .signin_session(
            json!({
                "ceremony_id": signin["ceremony_id"],
                "assertion": assertion(signin["public_key"]["challenge"].as_str().unwrap(), 2, false)
            }),
            digest,
            crate::state::now_ms().unwrap() + 300_000,
        )
        .unwrap();
    let session = format!("session:{}", hex::encode(digest));
    let approval = owner
        .call(&session, Operation::BindingRefresh, json!({}))
        .unwrap();
    let refreshed = owner
        .call(
            &session,
            Operation::BindingRefreshPrepare,
            json!({
                "ceremony_id": approval["ceremony_id"],
                "current_phrase": phrase,
                "assertion": assertion(approval["public_key"]["challenge"].as_str().unwrap(), 3, false)
            }),
        )
        .unwrap();
    drop(owner);

    let db = node.db.lock().unwrap();
    let binding: String = db
        .query_row(
            "SELECT envelope FROM aumlok_binding WHERE state='COMPLETED'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let refresh: String = db
        .query_row(
            "SELECT envelope FROM aumlok_refresh WHERE id=?1 AND state='LIVE'",
            [refreshed["ceremony_id"].as_str().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    (
        Envelope::from_canonical_json(&binding).unwrap(),
        Envelope::from_canonical_json(&refresh).unwrap(),
    )
}

#[test]
fn antibody_production_node_binding_and_refresh_envelopes_use_production_kdf() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let node = Node::open(twin_config(&root), runtime.handle().clone()).unwrap();
    let (binding, refresh) = binding_and_refresh_envelopes(&node);
    let expected = KdfParams {
        memory_kib: 262_144,
        time_cost: 3,
        parallelism: 1,
    };
    assert_eq!(
        binding.kdf_params(),
        expected,
        "production binding envelope"
    );
    assert_eq!(
        refresh.kdf_params(),
        expected,
        "production refresh envelope"
    );
}

#[test]
fn antibody_twin_node_binding_and_refresh_envelopes_use_disposable_kdf() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let node = runtime.block_on(async { open_twin(&root).unwrap() });
    let (binding, refresh) = binding_and_refresh_envelopes(&node);
    let expected = KdfParams {
        memory_kib: 8,
        time_cost: 1,
        parallelism: 1,
    };
    assert_eq!(binding.kdf_params(), expected, "twin binding envelope");
    assert_eq!(refresh.kdf_params(), expected, "twin refresh envelope");
}
