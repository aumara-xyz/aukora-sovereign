// SPDX-License-Identifier: AGPL-3.0-or-later

#[path = "path0_tests.rs"]
mod path0_tests;

use crate::config::{self, Config};
use crate::dispatcher::GuestOrgans;
use crate::node::Node;
use crate::runtime::{self, RuntimeBackend};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{Direction, Frame, FrameBody, MemoryPut, Status};
use frontdoor::{Backend, Operation};
use gate::TargetStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const PRINCIPAL: &str = "owner:00000000000000000000000000000001";
const KEY: &str = "sk-or-disposable-supervisor-integration-key-673191";

#[path = "reboot_tests.rs"]
mod reboot_tests;

#[path = "openviking_memory_tests.rs"]
mod openviking_memory_tests;

pub(crate) fn config(path: &Path) -> Config {
    let mut prices = BTreeMap::new();
    prices.insert(
        "deepseek/deepseek-chat".into(),
        broker::PriceBasis {
            prompt_microusd_per_token: 1,
            completion_microusd_per_token: 1,
        },
    );
    Config {
        boot_probe: false,
        release_floor: false,
        nostr: config::Nostr::default(),
        openviking: config::OpenViking::default(),
        invite: None,
        node_id: "00000000000000000000000000000001".into(),
        state_dir: path.join("state"),
        listen: "127.0.0.1:3000".parse().unwrap(),
        chat_hostname: "chat-test.example".into(),
        owner_hostname: "owner-test.example".into(),
        chat_origin: "https://chat-test.example".into(),
        owner_origin: "https://owner-test.example".into(),
        trusted_proxy: config::TrustedProxy {
            peers: vec!["127.0.0.1".parse().unwrap()],
        },
        guest: config::Guest {
            node_dir: path.join("runtime-node"),
            harness_dir: path.join("runtime-harness"),
            bundle_dir: path.join("runtime-bundle"),
            subordinate_uid: 100_000,
            subordinate_gid: 100_000,
            work_dir: path.join("guest-work"),
        },
        cgroup_root: path.join("cgroup"),
        broker: config::Broker {
            provider_base_url: "https://openrouter.ai/api/v1".into(),
            allowed_models: vec!["deepseek/deepseek-chat".into()],
            default_model: "deepseek/deepseek-chat".into(),
            prices,
        },
        webauthn: config::WebAuthn {
            rp_id: "owner-test.example".into(),
            origin: "https://owner-test.example".into(),
        },
        limits: config::Limits {
            pids_max: 512,
            memory_max_bytes: 2 * 1024 * 1024 * 1024,
            file_size_max_bytes: launcher::DEFAULT_FILE_SIZE_MAX_BYTES,
            workspace_max_bytes: 4 * 1024 * 1024 * 1024,
            cpu_max: "200000 100000".into(),
            max_connections: 64,
            max_body_bytes: 65_536,
            session_seconds: 86_400,
            request_seconds: 30,
        },
    }
}

async fn call(node: &Node, operation: Operation, body: Value) -> Value {
    node.test_call(PRINCIPAL, operation, body)
        .await
        .unwrap_or_else(|error| panic!("{operation:?}: {}", error.code))
}

async fn approve(node: &Node, id: &str, counter: &mut u32) {
    let challenge = call(node, Operation::ApprovalChallenge, json!({"id":id})).await;
    *counter += 1;
    let assertion = crate::owner::tests::assertion(
        challenge["public_key"]["challenge"].as_str().unwrap(),
        *counter,
    );
    let outcome = call(
        node,
        Operation::ApprovalDecide,
        json!({"id":id,"approve":true,"assertion":assertion}),
    )
    .await;
    assert_eq!(outcome["state"], "applied");
    assert!(outcome["seq"].as_i64().unwrap() > 0);
}

fn counter_fixture(
    enrolled: u32,
    signed_in: Option<u32>,
) -> (tempfile::TempDir, tokio::runtime::Runtime, Arc<Node>) {
    let (directory, runtime, node, _) = binding_fixture(enrolled, signed_in);
    (directory, runtime, node)
}

pub(crate) fn binding_fixture(
    enrolled: u32,
    signed_in: Option<u32>,
) -> (tempfile::TempDir, tokio::runtime::Runtime, Arc<Node>, Value) {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let config = config(&root);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let node = Node::open_for_test(
        config.clone(),
        runtime.handle().clone(),
        config.broker.provider_base_url.clone(),
    )
    .unwrap();
    let prepared = runtime.block_on(async {
        let start = call(&node, Operation::EnrolStart, json!({})).await;
        let registration =
            crate::owner::tests::registration(start["public_key"]["challenge"].as_str().unwrap());
        let staged = call(
            &node,
            Operation::EnrolFinish,
            json!({"enrolment_id":start["enrolment_id"],"attestation":registration}),
        )
        .await;
        let possession = crate::owner::tests::assertion(
            staged["public_key"]["challenge"].as_str().unwrap(),
            enrolled,
        );
        call(
            &node,
            Operation::EnrolFinish,
            json!({"enrolment_id":start["enrolment_id"],"assertion":possession}),
        )
        .await;
        if let Some(counter) = signed_in {
            let start = call(&node, Operation::SigninStart, json!({})).await;
            let assertion = crate::owner::tests::assertion(
                start["public_key"]["challenge"].as_str().unwrap(),
                counter,
            );
            call(
                &node,
                Operation::SigninFinish,
                json!({"ceremony_id":start["ceremony_id"],"assertion":assertion}),
            )
            .await;
        }
        crate::owner::tests::prepare_fast(&mut node.owner.lock().unwrap());
        let prepared = call(&node, Operation::BindingPrepare, json!({})).await;
        call(
            &node,
            Operation::BindingConfirm,
            json!({"ceremony_id":prepared["ceremony_id"],"words":prepared["words"]}),
        )
        .await;
        prepared
    });
    node.db
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM supervisor_session WHERE digest=?1",
            [[0x48; 32]],
        )
        .unwrap();
    (directory, runtime, node, prepared)
}

fn counter_marks(node: &Node) -> (u32, u32) {
    node.db
        .lock()
        .unwrap()
        .query_row(
            "SELECT counter,sign_count FROM supervisor_owner,gate_owner WHERE id=1 AND singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

fn counter_proposal(node: &Node, bytes: &[u8], key: &str) -> String {
    let mut guard = node.gate.lock().unwrap();
    let gate = guard.as_mut().unwrap();
    let current = gate.guest().read(gate::targets::NOTE_TARGET).unwrap();
    gate.guest()
        .propose(gate::ProposalRequest {
            target: gate::targets::NOTE_TARGET.into(),
            base_sha256: current.map_or_else(|| "absent".into(), |bytes| gate::sha256(&bytes)),
            new_bytes: bytes.to_vec(),
            note: String::new(),
            idempotency_key: key.into(),
            cell: None,
        })
        .unwrap()
        .id
}

fn counter_consume(node: &Node, id: &str, count: u32) -> gate::Result<gate::State> {
    let mut guard = node.gate.lock().unwrap();
    let gate = guard.as_mut().unwrap();
    let review = gate.owner().review(id).unwrap();
    let challenge = aumlok::webauthn::owner_authorization_challenge(&review.auth_bytes).unwrap();
    gate.owner().consume(gate::ConsumeRequest {
        proposal_id: id.into(),
        challenge: review.challenge,
        base_sha256: review.base_sha256,
        new_sha256: review.new_sha256,
        display_sha256: review.display_sha256,
        decision: gate::Decision::Allow,
        proof: serde_json::to_vec(&crate::owner::tests::assertion(&challenge, count)).unwrap(),
    })
}

fn refresh_session(node: &Node, byte: u8) -> String {
    let digest = [byte; 32];
    node.db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
            rusqlite::params![digest, crate::state::now_ms().unwrap() + 3_600_000],
        )
        .unwrap();
    format!("session:{}", hex::encode(digest))
}

pub(crate) fn phrase_text(words: &Value) -> String {
    words
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

fn envelope_value(value: &Value) -> aumlok::envelope::Envelope {
    let canonical =
        canon::canonical_json(&canon::parse(&serde_json::to_vec(value).unwrap()).unwrap()).unwrap();
    aumlok::envelope::Envelope::from_canonical_json(std::str::from_utf8(&canonical).unwrap())
        .unwrap()
}

fn entry_body(entry: &aura::Entry) -> Value {
    serde_json::from_slice(&canon::canonical_json(&entry.body).unwrap()).unwrap()
}

async fn refresh_prepare(node: &Node, session: &str, current: &str) -> Value {
    let challenge = node
        .test_call(session, Operation::BindingRefresh, json!({}))
        .await
        .unwrap();
    let assertion =
        crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 0);
    node.test_call(
        session,
        Operation::BindingRefreshPrepare,
        json!({"ceremony_id":challenge["ceremony_id"],"current_phrase":current,"assertion":assertion}),
    )
    .await
    .unwrap()
}

/// The stored canonical bytes of an Aura body, read back as JSON.
fn as_json(body: &aura::Value) -> serde_json::Value {
    serde_json::from_slice(&canon::canonical_json(body).unwrap()).unwrap()
}

/// Every object key and every string value in a JSON body.
fn json_strings(
    value: &serde_json::Value,
    keys: &mut std::collections::BTreeSet<String>,
    values: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                keys.insert(key.clone());
                json_strings(item, keys, values);
            }
        }
        serde_json::Value::Array(items) => items
            .iter()
            .for_each(|item| json_strings(item, keys, values)),
        serde_json::Value::String(text) => values.push(text.clone()),
        _ => {}
    }
}

#[test]
fn antibody_owner_export_is_the_cold_proof_of_the_live_ledger() {
    // Stranger wiring: GET /api/aura/export answers the cold proof (schema aukora-aura-cold-proof-v1)
    // whose head is the node's own head, not an unavailable stub.
    let (_directory, runtime, node, _binding) = binding_fixture(0, None);
    runtime.block_on(async {
        let proof = call(&node, Operation::AuraExport, json!({})).await;
        assert_eq!(proof["schema"], "aukora-aura-cold-proof-v1");
        // The owner page asks without `since` on a fresh browser (Kimi review).
        let head = call(&node, Operation::AuraHead, json!({})).await;
        let text = proof.to_string();
        assert!(
            head["hash"]
                .as_str()
                .is_some_and(|hash| text.contains(hash)),
            "proof lacks the node head"
        );
    });
}

#[test]
fn antibody_refresh_retires_old_phrase_preserves_root_and_records_no_words() {
    let (_directory, runtime, node, binding) = binding_fixture(0, None);
    let session = refresh_session(&node, 31);
    let old_phrase = aumlok::phrase::Phrase::parse(&phrase_text(&binding["words"])).unwrap();
    let before = runtime.block_on(call(&node, Operation::BindingEnvelope, json!({})));
    let old_envelope = envelope_value(&before);
    let old_digest = aumlok::refresh::envelope_sha256(&old_envelope);
    let old_root = aumlok::envelope::open(&old_envelope, &old_phrase).unwrap();
    let subject = node.owner.lock().unwrap().state().unwrap().subject.unwrap();
    runtime.block_on(async {
        let prepared = refresh_prepare(&node, &session, old_phrase.as_str()).await;
        let new_phrase = aumlok::phrase::Phrase::parse(&phrase_text(&prepared["words"])).unwrap();
        assert!(old_phrase.as_str() != new_phrase.as_str());
        assert_eq!(prepared["words"].as_array().unwrap().len(), 7);
        assert_eq!(
            prepared["entropy_bits"],
            aumlok::phrase::entropy().minimum_bits.floor() as u64
        );
        let confirmed = node
            .test_call(
                &session,
                Operation::BindingRefreshConfirm,
                json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":old_phrase.as_str(),"words":prepared["words"]}),
            )
            .await
            .unwrap();
        assert_eq!(confirmed["ok"], true);
        assert_eq!(confirmed["subject"], subject);
        assert!(*node.owner.lock().unwrap().root().unwrap().unwrap() == *old_root);
        assert_eq!(node.owner.lock().unwrap().state().unwrap().subject, Some(subject.clone()));
        let after = call(&node, Operation::BindingEnvelope, json!({})).await;
        assert_ne!(before, after);
        let new_envelope = envelope_value(&after);
        let new_digest = aumlok::refresh::envelope_sha256(&new_envelope);
        let mut store = aumlok::binding::BindingStore::open(node.db_path()).unwrap();
        let now = crate::state::now_ms().unwrap();
        assert_eq!(
            store.open_current(&old_digest, &session, &old_phrase, now).unwrap_err().code(),
            "aumlok:envelope-retired"
        );
        assert_eq!(
            store.open_current(&new_digest, &session, &old_phrase, now).unwrap_err().code(),
            "aumlok:current-phrase"
        );
        assert!(*store.open_current(&new_digest, &session, &new_phrase, now).unwrap() == *old_root);
        let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
        aura::walk(&entries, &node.signer.verifying_key(), None).unwrap();
        let refresh_rows = entries.iter().filter(|entry| entry_body(entry)["refresh"] == true).collect::<Vec<_>>();
        assert!(refresh_rows.iter().any(|entry| entry.phase == "fact" && entry_body(entry)["stage"] == "start"));
        assert!(refresh_rows.iter().any(|entry| entry.phase == "fact" && entry_body(entry)["stage"] == "finish"));
        assert_eq!(refresh_rows.iter().filter(|entry| entry.phase == "terminal").count(), 1);
        // Several curated words are also ledger field names (node, code, reason, refresh, stage...).
        // Rows that never see the phrase define that schema vocabulary; the ceremony's own rows
        // may carry only their fixed fields, and none of their values may be a phrase word.
        const BIND_FIELDS: [&str; 7] = ["refresh", "stage", "subject", "envelope_version", "envelope_sha256", "new", "old"];
        let mut schema = std::collections::BTreeSet::new();
        for entry in entries.iter().filter(|entry| entry.kind != "aumlok.bind") {
            json_strings(&as_json(&entry.body), &mut schema, &mut Vec::new());
        }
        for entry in entries {
            let encoded = String::from_utf8(canon::canonical_json(&entry.body).unwrap()).unwrap();
            let ceremony = entry.kind == "aumlok.bind";
            let mut fields = std::collections::BTreeSet::new();
            let mut values = Vec::new();
            json_strings(&as_json(&entry.body), &mut fields, &mut values);
            if ceremony {
                for field in &fields {
                    assert!(BIND_FIELDS.contains(&field.as_str()), "unexpected field {field} in a phrase ceremony row");
                }
            }
            for phrase in [&old_phrase, &new_phrase] {
                assert!(!encoded.contains(phrase.as_str()));
                assert!(!encoded.contains(&gate::sha256(phrase.as_str().as_bytes())));
                let words: Vec<&str> = phrase.as_str().split(' ').collect();
                for pair in words.windows(2) {
                    assert!(!encoded.contains(&format!("{} {}", pair[0], pair[1])));
                    assert!(!encoded.contains(&format!("\"{}\",\"{}\"", pair[0], pair[1])));
                }
                for word in &words {
                    let stored = values.iter().any(|value| value == word);
                    assert!(
                        !stored || (!ceremony && schema.contains(*word)),
                        "phrase word stored as an Aura value"
                    );
                }
            }
            assert!(entry.body.get("current_phrase").is_none());
            assert!(entry.body.get("words").is_none());
        }
    });
}

#[test]
fn antibody_refresh_requires_live_session_fresh_passkey_and_supervisor_authorization() {
    let (_directory, runtime, node, binding) = binding_fixture(0, None);
    let session = refresh_session(&node, 32);
    let current = phrase_text(&binding["words"]);
    runtime.block_on(async {
        for principal in [PRINCIPAL, "session:0000000000000000000000000000000000000000000000000000000000000000"] {
            assert_eq!(node.test_call(principal, Operation::BindingRefresh, json!({})).await.unwrap_err().code, "frontdoor:session-required");
        }
        let challenge = node.test_call(&session, Operation::BindingRefresh, json!({})).await.unwrap();
        let auth = canon::canonical_json(&canon::parse(&serde_json::to_vec(&challenge["auth"]).unwrap()).unwrap()).unwrap();
        let card = canon::canonical_json(&canon::parse(&serde_json::to_vec(&challenge["card"]).unwrap()).unwrap()).unwrap();
        assert_eq!(challenge["public_key"]["challenge"], aumlok::webauthn::owner_authorization_challenge(&auth).unwrap());
        assert_eq!(challenge["auth"]["display_sha256"], gate::sha256(&card));
        assert_eq!(challenge["display_sha256"], gate::sha256(&card));
        assert_eq!(node.test_call(&session, Operation::BindingRefreshPrepare, json!({"ceremony_id":challenge["ceremony_id"],"current_phrase":current})).await.unwrap_err().code, "aumlok:assertion-refused");
        let assertion = crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 0);
        let supplied = json!({"ceremony_id":challenge["ceremony_id"],"current_phrase":current,"assertion":assertion,"auth":challenge["auth"]});
        assert_eq!(node.test_call(&session, Operation::BindingRefreshPrepare, supplied).await.unwrap_err().code, "frontdoor:invalid-body");
        let second_session = refresh_session(&node, 33);
        let next = node.test_call(&second_session, Operation::BindingRefresh, json!({})).await.unwrap();
        let finish = json!({"ceremony_id":challenge["ceremony_id"],"current_phrase":current,"assertion":assertion});
        let prepared = node.test_call(&session, Operation::BindingRefreshPrepare, finish.clone()).await.unwrap();
        let recovered = node.test_call(&session, Operation::BindingRefreshPrepare, finish).await.unwrap();
        assert_eq!(recovered["ceremony_id"], prepared["ceremony_id"]);
        assert_eq!(recovered["state"], "live");
        assert!(recovered.get("words").is_none());
        let prior_counter = node.owner.lock().unwrap().credential().unwrap().unwrap().sign_count;
        let approvals: i64 = node.db.lock().unwrap().query_row("SELECT count(*) FROM supervisor_refresh_approval",[],|row| row.get(0)).unwrap();
        let refused = node.test_call(&second_session, Operation::BindingRefresh, json!({})).await.unwrap_err();
        assert_eq!(refused.code,"aumlok:refresh-live");
        assert_eq!(refused.expires_at,prepared["expires_at"].as_i64());
        let refused = node.test_call(&second_session, Operation::BindingRefreshPrepare, json!({"ceremony_id":next["ceremony_id"],"current_phrase":current,"assertion":assertion})).await.unwrap_err();
        assert_eq!(refused.code,"aumlok:refresh-live");
        assert_eq!(refused.expires_at,prepared["expires_at"].as_i64());
        assert_eq!(node.owner.lock().unwrap().credential().unwrap().unwrap().sign_count,prior_counter);
        assert_eq!(node.db.lock().unwrap().query_row("SELECT count(*) FROM supervisor_refresh_approval",[],|row| row.get::<_,i64>(0)).unwrap(),approvals);
        let digest = [32; 32];
        node.revoke_session(digest).await.unwrap();
        assert_eq!(node.test_call(&session, Operation::BindingRefresh, json!({})).await.unwrap_err().code, "frontdoor:session-required");
        assert_eq!(node.test_call(&second_session, Operation::BindingRefreshPrepare, json!({"ceremony_id":next["ceremony_id"],"current_phrase":current,"assertion":assertion})).await.unwrap_err().code, "aumlok:assertion-refused");
    });
}

#[test]
fn antibody_refresh_wrong_current_phrase_spends_the_assertion() {
    let (_directory, runtime, node, binding) = binding_fixture(0, None);
    let session = refresh_session(&node, 81);
    let current = phrase_text(&binding["words"]);
    let wrong = loop {
        let phrase = aumlok::phrase::Phrase::draw().unwrap();
        if phrase.as_str() != current {
            break phrase;
        }
    };
    runtime.block_on(async {
        for input in [wrong.as_str(), "not a phrase"] {
            let challenge = node.test_call(&session, Operation::BindingRefresh, json!({})).await.unwrap();
            let proof = crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 0);
            let attempt = json!({"ceremony_id":challenge["ceremony_id"],"current_phrase":input,"assertion":proof});
            assert_eq!(node.test_call(&session,Operation::BindingRefreshPrepare,attempt).await.unwrap_err().code,"aumlok:current-phrase");
            assert_eq!(node.test_call(&session,Operation::BindingRefreshPrepare,json!({"ceremony_id":challenge["ceremony_id"],"current_phrase":current,"assertion":proof})).await.unwrap_err().code,"aumlok:refresh-proof-spent");
        }
        assert_eq!(node.owner.lock().unwrap().credential().unwrap().unwrap().sign_count,0);
    });
}

#[test]
fn antibody_refresh_current_phrase_guess_limit_is_per_session() {
    let (_directory, runtime, node, binding) = binding_fixture(0, None);
    let session = refresh_session(&node, 34);
    let other = refresh_session(&node, 35);
    let current = phrase_text(&binding["words"]);
    let wrong = loop {
        let phrase = aumlok::phrase::Phrase::draw().unwrap();
        if phrase.as_str() != current {
            break phrase;
        }
    };
    runtime.block_on(async {
        for guess in 0..5 {
            let challenge = node.test_call(&session, Operation::BindingRefresh, json!({})).await.unwrap();
            let assertion = crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 0);
            let wrong_input = if guess % 2 == 0 { "not a binding phrase" } else { wrong.as_str() };
            assert_eq!(node.test_call(&session, Operation::BindingRefreshPrepare, json!({"ceremony_id":challenge["ceremony_id"],"current_phrase":wrong_input,"assertion":assertion})).await.unwrap_err().code, "aumlok:current-phrase");
        }
        let challenge = node.test_call(&session, Operation::BindingRefresh, json!({})).await.unwrap();
        let assertion = crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 0);
        assert_eq!(node.test_call(&session, Operation::BindingRefreshPrepare, json!({"ceremony_id":challenge["ceremony_id"],"current_phrase":current,"assertion":assertion})).await.unwrap_err().code, "aumlok:phrase-rate-limited");
        let prepared = refresh_prepare(&node, &other, &current).await;
        assert_eq!(prepared["words"].as_array().unwrap().len(), 7);
    });
}

#[test]
fn antibody_refresh_first_wrong_word_keeps_current_envelope_and_live_ceremony() {
    let (_directory, runtime, node, binding) = binding_fixture(0, None);
    let session = refresh_session(&node, 36);
    let current = phrase_text(&binding["words"]);
    runtime.block_on(async {
        let before = call(&node, Operation::BindingEnvelope, json!({})).await;
        let prepared = refresh_prepare(&node, &session, &current).await;
        let wrong = loop {
            let phrase = aumlok::phrase::Phrase::draw().unwrap();
            if phrase.as_str() != current { break phrase; }
        };
        assert_eq!(node.test_call(&session, Operation::BindingRefreshResume, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":wrong.as_str()})).await.unwrap_err().code, "aumlok:current-phrase");
        assert_eq!(node.test_call(&session, Operation::BindingRefreshConfirm, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":wrong.as_str(),"words":prepared["words"]})).await.unwrap_err().code, "aumlok:current-phrase");
        let mut words = prepared["words"].clone();
        words[1] = json!("wrong");
        words[5] = json!("wrong");
        let error = node.test_call(&session, Operation::BindingRefreshConfirm, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current,"words":words})).await.unwrap_err();
        assert_eq!(error.code, "aumlok:word-mismatch");
        assert_eq!(error.position, Some(2));
        assert_eq!(call(&node, Operation::BindingEnvelope, json!({})).await, before);
        let resumed = node.test_call(&session, Operation::BindingRefreshResume, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current})).await.unwrap();
        assert!(resumed["words"] == prepared["words"]);
        let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
        assert!(!entries.iter().any(|entry| entry.op == prepared["ceremony_id"].as_str().unwrap() && entry.phase == "terminal"));
        node.test_call(&session, Operation::BindingRefreshConfirm, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current,"words":prepared["words"]})).await.unwrap();
    });
}

#[test]
fn antibody_refresh_restart_resumes_same_words_and_commits_once() {
    let (_directory, runtime, node, binding) = binding_fixture(0, None);
    let session = refresh_session(&node, 37);
    let current = phrase_text(&binding["words"]);
    let prepared = runtime.block_on(refresh_prepare(&node, &session, &current));
    let config = node.config.clone();
    drop(node);
    let reopened = Node::open_for_test(
        config.clone(),
        runtime.handle().clone(),
        config.broker.provider_base_url.clone(),
    )
    .unwrap();
    runtime.block_on(async {
        let resumed = reopened.test_call(&session, Operation::BindingRefreshResume, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current})).await.unwrap();
        assert!(resumed == prepared);
        let confirm = json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current,"words":resumed["words"]});
        reopened.test_call(&session, Operation::BindingRefreshConfirm, confirm.clone()).await.unwrap();
        let committed = reopened.test_call(&session, Operation::BindingRefreshConfirm, confirm).await.unwrap();
        assert_eq!(committed["state"], "committed");
        assert!(committed.get("words").is_none());
        let entries = aura::read_entries(&reopened.db.lock().unwrap()).unwrap();
        assert_eq!(entries.iter().filter(|entry| entry.op == prepared["ceremony_id"].as_str().unwrap() && entry.phase == "terminal").count(), 1);
        let terminal = entries.iter().find(|entry| entry.op == prepared["ceremony_id"].as_str().unwrap() && entry.phase == "terminal").unwrap();
        assert_eq!(reopened.owner.lock().unwrap().state().unwrap().subject, entry_body(terminal)["subject"].as_str().map(str::to_owned));
    });
}

#[test]
fn antibody_refresh_aura_failure_rolls_back_envelope_and_ceremony() {
    let (_directory, runtime, node, binding) = binding_fixture(0, None);
    let session = refresh_session(&node, 38);
    let current = phrase_text(&binding["words"]);
    runtime.block_on(async {
        let before = call(&node, Operation::BindingEnvelope, json!({})).await;
        let prepared = refresh_prepare(&node, &session, &current).await;
        let confirm = json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current,"words":prepared["words"]});
        let injection = rusqlite::Connection::open(node.db_path()).unwrap();
        injection.execute_batch("CREATE TRIGGER refresh_test_aura_failure BEFORE INSERT ON aura WHEN NEW.kind='aumlok.bind' AND NEW.phase='terminal' AND json_extract(NEW.body,'$.refresh')=1 BEGIN SELECT RAISE(ABORT,'refresh test Aura failure'); END;").unwrap();
        assert!(node.test_call(&session, Operation::BindingRefreshConfirm, confirm.clone()).await.is_err());
        assert_eq!(call(&node, Operation::BindingEnvelope, json!({})).await, before);
        let resumed = node.test_call(&session, Operation::BindingRefreshResume, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current})).await.unwrap();
        assert!(resumed == prepared);
        injection.execute_batch("DROP TRIGGER refresh_test_aura_failure").unwrap();
        node.test_call(&session, Operation::BindingRefreshConfirm, confirm).await.unwrap();
        let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
        assert_eq!(entries.iter().filter(|entry|entry.op == prepared["ceremony_id"].as_str().unwrap() && entry.phase == "terminal").count(), 1);
        aura::walk(&entries, &node.signer.verifying_key(), None).unwrap();
    });
}

#[test]
fn antibody_refresh_counter_advance_fences_gate_and_signin() {
    let (_directory, runtime, node, binding) = binding_fixture(5, Some(6));
    let session = refresh_session(&node, 39);
    let current = phrase_text(&binding["words"]);
    runtime.block_on(async {
        let start = node.test_call(&session, Operation::BindingRefresh, json!({})).await.unwrap();
        let assertion = crate::owner::tests::assertion(start["public_key"]["challenge"].as_str().unwrap(), 7);
        let prepared = node.test_call(&session, Operation::BindingRefreshPrepare, json!({"ceremony_id":start["ceremony_id"],"current_phrase":current,"assertion":assertion})).await.unwrap();
        assert_eq!(counter_marks(&node), (7, 7));
        let id = counter_proposal(&node, b"after refresh", "refresh-counter");
        let challenge = call(&node, Operation::ApprovalChallenge, json!({"id":id})).await;
        let stale = crate::owner::tests::assertion(challenge["public_key"]["challenge"].as_str().unwrap(), 7);
        assert_eq!(node.test_call(PRINCIPAL, Operation::ApprovalDecide, json!({"id":id,"approve":true,"assertion":stale})).await.unwrap_err().code, "aumlok:counter-replayed");
        let signin = call(&node, Operation::SigninStart, json!({})).await;
        let stale = crate::owner::tests::assertion(signin["public_key"]["challenge"].as_str().unwrap(), 7);
        assert_eq!(node.test_call(PRINCIPAL, Operation::SigninFinish, json!({"ceremony_id":signin["ceremony_id"],"assertion":stale})).await.unwrap_err().code, "aumlok:assertion-refused");
        let fresh = crate::owner::tests::assertion(signin["public_key"]["challenge"].as_str().unwrap(), 8);
        call(&node, Operation::SigninFinish, json!({"ceremony_id":signin["ceremony_id"],"assertion":fresh})).await;
        node.test_call(&session, Operation::BindingRefreshConfirm, json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current,"words":prepared["words"]})).await.unwrap();
        let mut count = 8;
        approve(&node, &id, &mut count).await;
        assert_eq!(counter_marks(&node), (9, 9));
    });
}

#[test]
fn antibody_refresh_session_is_rechecked_inside_prepare_and_confirm_transactions() {
    let (_directory, runtime, node, binding) = binding_fixture(0, None);
    let session = refresh_session(&node, 40);
    let current = phrase_text(&binding["words"]);
    let injection = rusqlite::Connection::open(node.db_path()).unwrap();
    runtime.block_on(async {
        let start = node.test_call(&session, Operation::BindingRefresh, json!({})).await.unwrap();
        let assertion = crate::owner::tests::assertion(start["public_key"]["challenge"].as_str().unwrap(), 0);
        let prepare = json!({"ceremony_id":start["ceremony_id"],"current_phrase":current,"assertion":assertion});
        injection.execute_batch("CREATE TRIGGER refresh_test_revoke_prepare AFTER INSERT ON aumlok_refresh BEGIN UPDATE supervisor_session SET revoked=1; END;").unwrap();
        assert_eq!(node.test_call(&session, Operation::BindingRefreshPrepare, prepare.clone()).await.unwrap_err().code, "frontdoor:session-required");
        assert!(node.session_valid([40;32], crate::state::now_ms().unwrap()).await.unwrap());
        assert_eq!(injection.query_row("SELECT count(*) FROM aumlok_refresh", [], |row|row.get::<_,i64>(0)).unwrap(), 0);
        injection.execute_batch("DROP TRIGGER refresh_test_revoke_prepare").unwrap();
        let prepared = node.test_call(&session, Operation::BindingRefreshPrepare, prepare).await.unwrap();
        let before = call(&node, Operation::BindingEnvelope, json!({})).await;
        injection.execute_batch("CREATE TRIGGER refresh_test_revoke_confirm AFTER UPDATE ON aumlok_current_envelope BEGIN UPDATE supervisor_session SET revoked=1; END;").unwrap();
        let confirm = json!({"ceremony_id":prepared["ceremony_id"],"current_phrase":current,"words":prepared["words"]});
        assert_eq!(node.test_call(&session, Operation::BindingRefreshConfirm, confirm.clone()).await.unwrap_err().code, "frontdoor:session-required");
        assert!(node.session_valid([40;32], crate::state::now_ms().unwrap()).await.unwrap());
        assert_eq!(call(&node, Operation::BindingEnvelope, json!({})).await, before);
        injection.execute_batch("DROP TRIGGER refresh_test_revoke_confirm").unwrap();
        node.test_call(&session, Operation::BindingRefreshConfirm, confirm).await.unwrap();
    });
}

#[test]
fn antibody_large_ledger_keeps_owner_approval_and_startup_available() {
    // No aura:memory-limit on owner approval, authenticated startup, recall or Aura views.
    let (_directory, runtime, node) = counter_fixture(0, None);
    let id = counter_proposal(&node, b"retained owner change", "large-ledger-before");
    let mut counter = 0;
    runtime.block_on(approve(&node, &id, &mut counter));
    runtime.block_on(async {
        let permission = call(&node, Operation::MemoryPermissionPropose, json!({})).await;
        approve(&node, permission["id"].as_str().unwrap(), &mut counter).await;
    });
    let filler = json!({"model_note":"ordinary model text ".repeat(216)});
    {
        let mut db = node.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let ledger = crate::ledger::AuraLedger {
            signer: node.signer.clone(),
        };
        for _ in 0..2048 {
            ledger
                .append(
                    &tx,
                    &gate::LedgerRow {
                        at: 1,
                        kind: "gate.propose",
                        actor: "guest".into(),
                        op: String::new(),
                        phase: "fact",
                        body: serde_json::to_string(&filler).unwrap(),
                    },
                )
                .unwrap();
        }
        tx.commit().unwrap();
        assert_eq!(
            aura::read_entries(&db).unwrap_err().code,
            "aura:memory-limit"
        );
    }
    let config = node.config.clone();
    drop(node);
    let reopened = Node::open_for_test(
        config.clone(),
        runtime.handle().clone(),
        config.broker.provider_base_url.clone(),
    )
    .expect("a ledger above 8 MiB must still start and open the gate");
    assert!(reopened.bound().unwrap());
    assert!(reopened.memory_permission().unwrap());
    let next = counter_proposal(&reopened, b"owner still acts", "large-ledger-after");
    runtime.block_on(approve(&reopened, &next, &mut counter));
    runtime.block_on(async {
        let recent = call(&reopened, Operation::AuraRecent, json!({"limit":2})).await;
        assert_eq!(recent["rows"].as_array().unwrap().len(), 2);
        let retained = call(&reopened, Operation::AuraRetained, json!({})).await;
        assert!(retained["sequence"].as_u64().unwrap() > 2048);
        let recall = call(
            &reopened,
            Operation::MemoryRecall,
            json!({"query":"","limit":10}),
        )
        .await;
        assert_eq!(recall["result"], "empty");
    });
}

fn memory_with_evidence(
    node: &Node,
    category: &str,
    statement: &str,
    quote: Option<&str>,
) -> MemoryPut {
    let mut memory = MemoryPut {
        cell: canon::Cell {
            module_sha256: String::new(),
            input_sha256: String::new(),
            effect_sha256: String::new(),
        },
        statement: statement.into(),
        quote: quote.map(str::to_owned),
        category: category.into(),
    };
    let value = crate::dispatcher::memory_value(&memory);
    let cell = node
        .cell
        .run_memory_put(&crate::dispatcher::memory_key(&value).unwrap(), &value)
        .unwrap();
    memory.cell = canon::Cell {
        module_sha256: cell.module_sha256,
        input_sha256: cell.input_sha256,
        effect_sha256: cell.effect_sha256,
    };
    memory
}

#[test]
fn antibody_memory_burst_refuses_guest_without_blocking_owner() {
    // Wire refusals: kira:invalid-field for bounds, kira:store-unavailable for budget.
    // Owner recall and passkey permission approval remain available.
    let (_directory, runtime, node) = counter_fixture(0, None);
    let (mut guest, supervisor) = UnixStream::pair().unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let dispatcher_node = node.clone();
    let handle = runtime.handle().clone();
    let dispatcher = thread::spawn(move || {
        crate::dispatcher::run(dispatcher_node, supervisor, handle, Box::new(|| {}))
    });
    let cases = [
        (
            memory_with_evidence(&node, &"x".repeat(65), "text", None),
            "kira:invalid-field",
        ),
        (
            memory_with_evidence(&node, "personal", &"x".repeat(4097), None),
            "kira:invalid-field",
        ),
        (
            memory_with_evidence(&node, "personal", "text", Some(&"x".repeat(4097))),
            "kira:invalid-field",
        ),
    ];
    for (index, (memory, code)) in cases.into_iter().enumerate() {
        assert!(
            matches!(guest_request(&mut guest, &format!("bounds-{index}"), FrameBody::MemoryPut(memory)), FrameBody::Refusal(refusal) if refusal.code == code)
        );
    }
    let memory = memory_with_evidence(&node, "personal", "remember bridge", None);
    for index in 3..kira::GUEST_MAX_PER_WINDOW {
        assert!(matches!(
            guest_request(
                &mut guest,
                &format!("save-{index}"),
                FrameBody::MemoryPut(memory.clone())
            ),
            FrameBody::Accepted(_)
        ));
        assert!(
            matches!(canon::read_frame(&mut guest, Direction::Supervisor).unwrap().body, FrameBody::Outcome(outcome) if outcome.state == canon::OutcomeState::Applied)
        );
    }
    let before: i64 = node
        .db
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM aura", [], |row| row.get(0))
        .unwrap();
    for body in [
        FrameBody::MemoryPut(memory),
        FrameBody::MemoryRecall(canon::MemoryRecall {
            query: "bridge".into(),
            limit: 10,
        }),
    ] {
        assert!(
            matches!(guest_request(&mut guest, "exhausted", body), FrameBody::Refusal(refusal) if refusal.code == "kira:store-unavailable")
        );
    }
    let after: i64 = node
        .db
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM aura", [], |row| row.get(0))
        .unwrap();
    assert_eq!(before, after, "exhausted attempts append no ledger rows");
    runtime.block_on(async {
        let recall = call(
            &node,
            Operation::MemoryRecall,
            json!({"query":"bridge","limit":10}),
        )
        .await;
        assert_eq!(recall["result"], "found");
        let permission = call(&node, Operation::MemoryPermissionPropose, json!({})).await;
        let mut counter = 0;
        approve(&node, permission["id"].as_str().unwrap(), &mut counter).await;
    });
    assert!(node.memory_permission().unwrap());
    guest.shutdown(Shutdown::Both).unwrap();
    assert!(dispatcher.join().unwrap().is_err());
}

#[test]
fn antibody_owner_counter_blocks_clone_after_binding() {
    let (_directory, runtime, node) = counter_fixture(5, Some(6));
    let id = counter_proposal(&node, b"only counter seven may apply", "clone-counter");
    runtime.block_on(async {
        for count in [1, 0] {
            let review = call(&node, Operation::ApprovalChallenge, json!({"id":id})).await;
            let assertion = crate::owner::tests::assertion(
                review["public_key"]["challenge"].as_str().unwrap(),
                count,
            );
            // Expected refusal: aumlok:counter-replayed; the challenge is fresh, the clone is stale.
            assert_eq!(
                node.test_call(
                    PRINCIPAL,
                    Operation::ApprovalDecide,
                    json!({"id":id,"approve":true,"assertion":assertion}),
                )
                .await
                .unwrap_err()
                .code,
                "aumlok:counter-replayed"
            );
            assert_eq!(counter_marks(&node), (6, 6));
        }
        let mut count = 6;
        approve(&node, &id, &mut count).await;
    });
    assert_eq!(counter_marks(&node), (7, 7));
}

#[test]
fn antibody_owner_counter_commits_before_supervisor_postprocessing() {
    let (_directory, runtime, node) = counter_fixture(5, Some(6));
    let id = counter_proposal(&node, b"atomic counter writeback", "atomic-counter");
    assert_eq!(
        counter_consume(&node, &id, 7).unwrap(),
        gate::State::Applied
    );
    assert_eq!(counter_marks(&node), (7, 7));
    let stale = counter_proposal(
        &node,
        b"cached mark must not authorize again",
        "cached-counter",
    );
    // Expected refusal: aumlok:counter-replayed; direct consume has advanced the durable mark.
    assert!(matches!(
        counter_consume(&node, &stale, 7),
        Err(gate::Error::Refused("aumlok:counter-replayed"))
    ));
    let config = node.config.clone();
    drop(node);
    let node = Node::open_for_test(
        config.clone(),
        runtime.handle().clone(),
        config.broker.provider_base_url.clone(),
    )
    .unwrap();
    runtime.block_on(async {
        let start = call(&node, Operation::SigninStart, json!({})).await;
        for count in [7, 1, 0] {
            let assertion = crate::owner::tests::assertion(
                start["public_key"]["challenge"].as_str().unwrap(),
                count,
            );
            // Expected refusal: aumlok:assertion-refused; sign-in sees the approval's durable mark.
            assert_eq!(
                node.test_call(
                    PRINCIPAL,
                    Operation::SigninFinish,
                    json!({"ceremony_id":start["ceremony_id"],"assertion":assertion}),
                )
                .await
                .unwrap_err()
                .code,
                "aumlok:assertion-refused"
            );
        }
        let assertion =
            crate::owner::tests::assertion(start["public_key"]["challenge"].as_str().unwrap(), 8);
        call(
            &node,
            Operation::SigninFinish,
            json!({"ceremony_id":start["ceremony_id"],"assertion":assertion}),
        )
        .await;
    });
    assert_eq!(counter_marks(&node), (8, 8));
    let next = stale;
    // Expected refusal: aumlok:counter-replayed, including when the proof adapter was cached earlier.
    assert!(matches!(
        counter_consume(&node, &next, 8),
        Err(gate::Error::Refused("aumlok:counter-replayed"))
    ));
    assert_eq!(
        counter_consume(&node, &next, 9).unwrap(),
        gate::State::Applied
    );
    assert_eq!(counter_marks(&node), (9, 9));
}

#[test]
fn antibody_owner_counter_failed_writeback_burns_without_effect() {
    let (_directory, _runtime, node) = counter_fixture(5, Some(6));
    let id = counter_proposal(
        &node,
        b"never applied on counter conflict",
        "counter-conflict",
    );
    node.db.lock().unwrap().execute_batch(
        "CREATE TRIGGER ignore_owner_counter BEFORE UPDATE OF counter ON supervisor_owner BEGIN SELECT RAISE(IGNORE); END;",
    ).unwrap();
    // Expected refusal: gate:counter-conflict; ignored supervisor CAS must roll back the gate spend.
    assert!(matches!(
        counter_consume(&node, &id, 7),
        Err(gate::Error::Refused("gate:counter-conflict"))
    ));
    assert_eq!(counter_marks(&node), (6, 6));
    let db = node.db.lock().unwrap();
    let burned: u32 = db
        .query_row("SELECT count(*) FROM gate_burns", [], |r| r.get(0))
        .unwrap();
    assert_eq!(burned, 1);
    let state: String = db
        .query_row("SELECT state FROM gate_proposals WHERE id=?1", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(state, "pending");
    db.execute_batch("DROP TRIGGER ignore_owner_counter")
        .unwrap();
    drop(db);
    assert_eq!(
        node.gate
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .guest()
            .read(gate::targets::NOTE_TARGET)
            .unwrap(),
        None
    );
    assert_eq!(
        counter_consume(&node, &id, 7).unwrap(),
        gate::State::Applied
    );
    assert_eq!(counter_marks(&node), (7, 7));
}

#[test]
fn antibody_owner_counter_retirement_is_shared_and_idempotent() {
    let (_directory, _runtime, node) = counter_fixture(5, Some(6));
    let id = counter_proposal(&node, b"retired without applying", "retire-counter");
    let mut guard = node.gate.lock().unwrap();
    let gate = guard.as_mut().unwrap();
    let auth = gate.owner().retire_authorization(&id).unwrap();
    let challenge = aumlok::webauthn::owner_authorization_challenge(&auth).unwrap();
    // Expected refusal for fresh retirement at the stored counter: aumlok:counter-replayed.
    let stale = serde_json::to_vec(&crate::owner::tests::assertion(&challenge, 6)).unwrap();
    assert!(matches!(
        gate.owner().retire(&id, &stale),
        Err(gate::Error::Refused("aumlok:counter-replayed"))
    ));
    let proof = serde_json::to_vec(&crate::owner::tests::assertion(&challenge, 7)).unwrap();
    let receipt = gate.owner().retire(&id, &proof).unwrap();
    assert_eq!(counter_marks(&node), (7, 7));
    assert_eq!(gate.owner().retire(&id, &proof).unwrap(), receipt);
    assert_eq!(counter_marks(&node), (7, 7));
}

#[test]
fn antibody_owner_counterless_approval_never_writes_zero() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    node.db.lock().unwrap().execute_batch(
        "CREATE TRIGGER forbid_owner_counter BEFORE UPDATE OF counter ON supervisor_owner BEGIN SELECT RAISE(ABORT,'zero counter write'); END;
         CREATE TRIGGER forbid_gate_counter BEFORE UPDATE OF sign_count ON gate_owner BEGIN SELECT RAISE(ABORT,'zero counter write'); END;",
    ).unwrap();
    let id = counter_proposal(
        &node,
        b"counterless passkey still authorizes once",
        "zero-counter",
    );
    assert_eq!(
        counter_consume(&node, &id, 0).unwrap(),
        gate::State::Applied
    );
    assert_eq!(counter_marks(&node), (0, 0));
    // Expected refusal: gate:not-pending; a zero counter does not revive a spent approval.
    assert_eq!(
        runtime
            .block_on(node.test_call(PRINCIPAL, Operation::ApprovalChallenge, json!({"id":id})))
            .unwrap_err()
            .code,
        "gate:not-pending"
    );
}

fn bound_node() -> (tempfile::TempDir, tokio::runtime::Runtime, Arc<Node>) {
    bound_node_with_boot_probe(false)
}

fn bound_node_with_boot_probe(
    boot_probe: bool,
) -> (tempfile::TempDir, tokio::runtime::Runtime, Arc<Node>) {
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut config = config(&root);
    config.boot_probe = boot_probe;
    let node = Node::open_for_test(
        config,
        runtime.handle().clone(),
        "https://openrouter.ai/api/v1".into(),
    )
    .unwrap();
    let token = node.owner.lock().unwrap().create_claim().unwrap();
    runtime
        .block_on(node.consume_claim(Sha256::digest(token.as_bytes()).into()))
        .unwrap();
    runtime.block_on(async {
        let start = call(&node, Operation::EnrolStart, json!({})).await;
        let staged = call(
            &node,
            Operation::EnrolFinish,
            json!({
                "enrolment_id":start["enrolment_id"],
                "attestation":crate::owner::tests::registration(
                    start["public_key"]["challenge"].as_str().unwrap()
                )
            }),
        )
        .await;
        call(
            &node,
            Operation::EnrolFinish,
            json!({
                "enrolment_id":start["enrolment_id"],
                "assertion":crate::owner::tests::assertion(
                    staged["public_key"]["challenge"].as_str().unwrap(),1
                )
            }),
        )
        .await;
        crate::owner::tests::prepare_fast(&mut node.owner.lock().unwrap());
        let prepared = call(&node, Operation::BindingPrepare, json!({})).await;
        call(
            &node,
            Operation::BindingConfirm,
            json!({"ceremony_id":prepared["ceremony_id"],"words":prepared["words"]}),
        )
        .await;
    });
    assert!(node.bound().unwrap());
    (directory, runtime, node)
}

fn measure_release(node: &Node, bytes: &[u8]) -> runtime::RuntimeDigests {
    for path in [
        &node.config.guest.node_dir,
        &node.config.guest.harness_dir,
        &node.config.guest.bundle_dir,
    ] {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("runtime.txt"), bytes).unwrap();
    }
    let digests = runtime::measure(&node.runtime_config()).unwrap();
    node.runtime_changed(&runtime::RuntimeStatus {
        current_digest: digests.digest.clone(),
        approved_digest: node.approved_release().unwrap().map(|r| r.digest),
        agent: "stopped".into(),
        since: crate::state::now_ms().unwrap(),
    })
    .unwrap();
    node.ensure_release(&digests).unwrap();
    digests
}

#[test]
fn antibody_boot_probe_failure_keeps_owner_pages_and_pending_approvals() {
    let (_directory, handle, node) = bound_node_with_boot_probe(true);
    let mut status = runtime::RuntimeStatus {
        current_digest: "a".repeat(64),
        approved_digest: Some("a".repeat(64)),
        agent: crate::boot_probe::FAILURE.into(),
        since: crate::state::now_ms().unwrap(),
    };
    node.runtime_changed(&status).unwrap();
    status.agent = runtime::agent_start_status(true).into();
    node.runtime_changed(&status).unwrap();
    handle.block_on(async {
        let proposed = call(
            &node,
            Operation::BrokerKeyPropose,
            json!({"key_sha256":"b".repeat(64)}),
        )
        .await;
        let listing = call(&node, Operation::Approvals, json!({})).await;
        let pending = listing["pending"].as_array().unwrap();
        assert!(pending
            .iter()
            .any(|item| item["id"] == proposed["id"] && item["state"] == "pending"));
        let notice = pending
            .iter()
            .find(|item| item["id"] == "boot-probe-refusal")
            .unwrap();
        assert_eq!(notice["state"], "refused");
        assert!(notice["card"]["facts"]
            .as_array()
            .unwrap()
            .contains(&json!(["refusal", crate::boot_probe::FAILURE])));
        assert_eq!(
            notice["display_sha256"],
            gate::sha256(&crate::node::canon_bytes(&notice["card"]).unwrap())
        );
        assert_eq!(
            call(&node, Operation::Release, json!({})).await["agent"],
            crate::boot_probe::FAILURE
        );
        for operation in [
            Operation::Broker,
            Operation::AuraHead,
            Operation::AuraRecent,
            Operation::AuraRetained,
            Operation::BindingEnvelope,
        ] {
            let body = if operation == Operation::AuraHead {
                json!({"since":1})
            } else {
                json!({})
            };
            call(&node, operation, body).await;
        }
        call(
            &node,
            Operation::MemoryRecall,
            json!({"query":"empty","limit":1}),
        )
        .await;
    });
    status.agent = "running".into();
    node.runtime_changed(&status).unwrap();
    let pending = handle.block_on(call(&node, Operation::Approvals, json!({})));
    assert!(!pending["pending"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == "boot-probe-refusal"));
}

async fn release_cards(node: &Node) -> Vec<Value> {
    call(node, Operation::Approvals, json!({})).await["pending"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["card"]["says"] == "Start the agent runtime")
        .cloned()
        .collect()
}

#[test]
fn antibody_runtime_digest_changes_withdraw_stale_release_and_start_latest() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    let note = counter_proposal(&node, b"unrelated pending guest note", "release-guest-note");
    let key = runtime.block_on(call(
        &node,
        Operation::BrokerKeyPropose,
        json!({"key_sha256":gate::sha256(b"unrelated operator key")}),
    ));
    let mut stale = Vec::new();
    let mut current: Option<(String, runtime::RuntimeDigests)> = None;
    for bytes in [b"runtime one".as_slice(), b"runtime two", b"runtime three"] {
        let digests = measure_release(&node, bytes);
        node.ensure_release(&digests).unwrap();
        let cards = runtime.block_on(release_cards(&node));
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0]["superseded"], false);
        let record: Value =
            serde_json::from_str(cards[0]["card"]["from_to"]["new"].as_str().unwrap()).unwrap();
        assert_eq!(record["digest"], digests.digest);
        if let Some((prior_id, _)) = current.take() {
            assert_eq!(
                node.proposal_state(&prior_id).unwrap(),
                Some(canon::OutcomeState::Expired)
            );
            stale.push(prior_id);
        }
        current = Some((cards[0]["id"].as_str().unwrap().to_owned(), digests));
    }
    assert_eq!(
        node.gate
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .state(&note)
            .unwrap(),
        Some(gate::State::Pending)
    );
    assert_eq!(
        node.gate
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .state(key["id"].as_str().unwrap())
            .unwrap(),
        Some(gate::State::Pending)
    );
    let (id, digests) = current.unwrap();
    assert!(!runtime::launch_allowed(
        node.bound().unwrap(),
        &digests,
        node.approved_release().unwrap().as_ref()
    ));
    let mut counter = 0;
    runtime.block_on(approve(&node, &id, &mut counter));
    assert!(runtime::launch_allowed(
        node.bound().unwrap(),
        &digests,
        node.approved_release().unwrap().as_ref()
    ));
    let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
    aura::walk(&entries, &node.signer.verifying_key(), None).unwrap();
    for id in stale {
        let terminal: Vec<_> = entries
            .iter()
            .filter(|e| e.op == id && e.phase == "terminal")
            .collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0].kind, "gate.expire");
        assert_eq!(terminal[0].actor, "supervisor");
        let body: Value =
            serde_json::from_slice(&canon::canonical_json(&terminal[0].body).unwrap()).unwrap();
        assert_eq!(body["reason"], "superseded");
        assert_eq!(body["action"], "withdraw");
    }

    // The approved digest admits the FD 3 guest stub; its first frame announces startup.
    let (mut guest, supervisor) = UnixStream::pair().unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let dispatch_node = node.clone();
    let ready_node = node.clone();
    let handle = runtime.handle().clone();
    let dispatcher = thread::spawn(move || {
        crate::dispatcher::run(
            dispatch_node,
            supervisor,
            handle,
            Box::new(move || ready_node.mark_agent_running().unwrap()),
        )
    });
    assert!(matches!(
        guest_request(
            &mut guest,
            "latest-release-start",
            FrameBody::Status(Status)
        ),
        FrameBody::StatusReply(_)
    ));
    assert_eq!(
        runtime.block_on(call(&node, Operation::Release, json!({})))["agent"],
        "running"
    );
    guest.shutdown(Shutdown::Both).unwrap();
    assert!(dispatcher.join().unwrap().is_err());
}

#[test]
fn antibody_reviewed_release_is_superseded_until_owner_retirement() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    let initial = measure_release(&node, b"reviewed initial runtime");
    let cards = runtime.block_on(release_cards(&node));
    let id = cards[0]["id"].as_str().unwrap().to_owned();
    runtime.block_on(call(&node, Operation::ApprovalChallenge, json!({"id":id})));
    let changed = measure_release(&node, b"new runtime awaiting retirement");
    let before = aura::read_entries(&node.db.lock().unwrap()).unwrap().len();
    node.ensure_release(&changed).unwrap();
    assert_eq!(
        aura::read_entries(&node.db.lock().unwrap()).unwrap().len(),
        before
    );
    let listed = runtime.block_on(release_cards(&node));
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["id"], id);
    assert_eq!(listed[0]["state"], "pending");
    assert_eq!(listed[0]["reviewed"], true);
    assert_eq!(listed[0]["superseded"], true);
    assert_eq!(listed[0]["card"], cards[0]["card"]);
    assert_eq!(listed[0]["display_sha256"], cards[0]["display_sha256"]);
    let mut counter = 0;
    runtime.block_on(async {
        let challenge = call(&node, Operation::ApprovalRetireChallenge, json!({"id":id})).await;
        counter += 1;
        let assertion = crate::owner::tests::assertion(
            challenge["public_key"]["challenge"].as_str().unwrap(),
            counter,
        );
        let result = call(
            &node,
            Operation::ApprovalRetire,
            json!({"id":id,"assertion":assertion}),
        )
        .await;
        assert_eq!(result["state"], "retired");
    });
    node.ensure_release(&changed).unwrap();
    let replacement = runtime.block_on(release_cards(&node));
    assert_eq!(replacement.len(), 1);
    assert_ne!(replacement[0]["id"], id);
    assert_eq!(replacement[0]["superseded"], false);
    runtime.block_on(approve(
        &node,
        replacement[0]["id"].as_str().unwrap(),
        &mut counter,
    ));
    assert!(runtime::launch_allowed(
        true,
        &changed,
        node.approved_release().unwrap().as_ref()
    ));
    assert!(!runtime::launch_allowed(
        true,
        &initial,
        node.approved_release().unwrap().as_ref()
    ));
}

#[test]
fn antibody_reviewed_release_digest_reversal_retries_after_retirement() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    measure_release(&node, b"original runtime");
    let id = runtime.block_on(release_cards(&node))[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    runtime.block_on(call(&node, Operation::ApprovalChallenge, json!({"id":id})));
    measure_release(&node, b"temporary replacement runtime");
    runtime.block_on(async {
        let ch = call(&node, Operation::ApprovalRetireChallenge, json!({"id":id})).await;
        let assertion =
            crate::owner::tests::assertion(ch["public_key"]["challenge"].as_str().unwrap(), 1);
        call(
            &node,
            Operation::ApprovalRetire,
            json!({"id":id,"assertion":assertion}),
        )
        .await;
    });
    measure_release(&node, b"original runtime");
    let cards = runtime.block_on(release_cards(&node));
    assert_eq!(cards.len(), 1);
    assert_ne!(cards[0]["id"], id);
    assert_eq!(cards[0]["superseded"], false);
}

#[test]
fn antibody_approval_listing_serializes_with_release_withdrawal() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    measure_release(&node, b"runtime withdrawn during listing");
    let id = runtime.block_on(release_cards(&node))[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut guard = node.gate.lock().unwrap();
    let caller = node.clone();
    let handle = runtime.handle().clone();
    let (started, received) = std::sync::mpsc::channel();
    let listing = thread::spawn(move || {
        started.send(()).unwrap();
        handle.block_on(caller.test_call(PRINCIPAL, Operation::Approvals, json!({})))
    });
    received.recv_timeout(Duration::from_secs(5)).unwrap();
    // Give the caller time to wait on the gate before withdrawal commits.
    thread::sleep(Duration::from_millis(100));
    assert!(!listing.is_finished());
    guard
        .as_mut()
        .unwrap()
        .owner()
        .withdraw_unreviewed(&id)
        .unwrap();
    drop(guard);
    let result = listing.join().unwrap().unwrap();
    assert!(result["pending"].as_array().unwrap().is_empty());
}

fn note_proposal(bytes: &[u8], base: &[u8]) -> canon::Propose {
    canon::Propose {
        target: gate::targets::NOTE_TARGET.into(),
        base_sha256: gate::sha256(base),
        new_bytes_b64: STANDARD.encode(bytes),
        note: "untrusted regression fixture".into(),
        cell: None,
    }
}

async fn finish_owner_action(
    node: &Node,
    id: &str,
    challenge_operation: Operation,
    finish_operation: Operation,
    action: &str,
    counter: u32,
) -> Value {
    let challenge = call(node, challenge_operation, json!({"id":id})).await;
    assert_eq!(challenge["auth"]["op"], action);
    assert_eq!(challenge["auth"]["proposal"], id);
    assert_eq!(
        challenge["auth"]["display_sha256"],
        challenge["display_sha256"]
    );
    let card = canon::canonical_json(
        &canon::parse(&serde_json::to_vec(&challenge["card"]).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(challenge["display_sha256"], gate::sha256(&card));
    let auth = canon::canonical_json(
        &canon::parse(&serde_json::to_vec(&challenge["auth"]).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        challenge["public_key"]["challenge"],
        aumlok::webauthn::owner_authorization_challenge(&auth).unwrap()
    );
    let prior_state = node.proposal_state(id).unwrap();
    let apply_auth: Vec<u8> = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT auth FROM gate_reviews WHERE proposal_id=? ORDER BY issued_at DESC LIMIT 1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    let apply_challenge = aumlok::webauthn::owner_authorization_challenge(&apply_auth).unwrap();
    // Expected refusal: aumlok:challenge-or-origin-mismatch; apply cannot sign owner closure.
    assert_eq!(
        node.test_call(
            PRINCIPAL,
            finish_operation,
            json!({"id":id,"assertion":crate::owner::tests::assertion(&apply_challenge,counter)}),
        )
        .await
        .unwrap_err()
        .code,
        "aumlok:challenge-or-origin-mismatch"
    );
    let mut forged = crate::owner::tests::assertion(
        challenge["public_key"]["challenge"].as_str().unwrap(),
        counter + 99,
    );
    forged["signature"] =
        json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 64]));
    // Expected refusal: aumlok:signature-invalid; a well-shaped fake proof cannot close a proposal.
    assert_eq!(
        node.test_call(
            PRINCIPAL,
            finish_operation,
            json!({"id":id,"assertion":forged})
        )
        .await
        .unwrap_err()
        .code,
        "aumlok:signature-invalid"
    );
    assert_eq!(node.proposal_state(id).unwrap(), prior_state);
    let assertion = crate::owner::tests::assertion(
        challenge["public_key"]["challenge"].as_str().unwrap(),
        counter,
    );
    let outcome = call(
        node,
        finish_operation,
        json!({"id":id,"assertion":assertion}),
    )
    .await;
    let stored_counter: u32 = node
        .db
        .lock()
        .unwrap()
        .query_row("SELECT counter FROM supervisor_owner WHERE id=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(stored_counter, counter);
    assert_eq!(
        node.owner
            .lock()
            .unwrap()
            .credential()
            .unwrap()
            .unwrap()
            .sign_count,
        counter
    );
    let signin = call(node, Operation::SigninStart, json!({})).await;
    // Expected refusal: aumlok:assertion-refused; closure counters also fence sign-in replay.
    assert_eq!(
        node.test_call(
            PRINCIPAL,
            Operation::SigninFinish,
            json!({"ceremony_id":signin["ceremony_id"],"assertion":crate::owner::tests::assertion(signin["public_key"]["challenge"].as_str().unwrap(),counter)}),
        )
        .await
        .unwrap_err()
        .code,
        "aumlok:assertion-refused"
    );
    outcome
}

#[test]
fn antibody_owner_retire_reviewed_operator_and_guest_unlocks_target() {
    let (_directory, runtime, node) = bound_node();
    runtime.block_on(async {
        let key = json!({"key_sha256":gate::sha256(b"disposable proposed broker key")});
        let proposed = call(&node, Operation::BrokerKeyPropose, key.clone()).await;
        let id = proposed["id"].as_str().unwrap();
        call(&node, Operation::ApprovalChallenge, json!({"id":id})).await;
        // Expected refusal: gate:owner-retirement-required; reviewed authority needs a passkey.
        assert_eq!(
            node.test_call(
                PRINCIPAL,
                Operation::ApprovalDecide,
                json!({"id":id,"approve":false})
            )
            .await
            .unwrap_err()
            .code,
            "gate:owner-retirement-required"
        );
        // Expected refusal: gate:target-fenced until the owner retires this reviewed proposal.
        assert_eq!(
            node.test_call(PRINCIPAL, Operation::BrokerKeyPropose, key.clone())
                .await
                .unwrap_err()
                .code,
            "gate:target-fenced"
        );
        let listing = call(&node, Operation::Approvals, json!({})).await;
        let listed = listing["pending"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .unwrap();
        assert_eq!(listed["state"], "pending");
        assert_eq!(listed["reviewed"], true);
        assert_eq!(listed["operator_only"], true);
        let outcome = finish_owner_action(
            &node,
            id,
            Operation::ApprovalRetireChallenge,
            Operation::ApprovalRetire,
            "retire",
            2,
        )
        .await;
        assert_eq!(outcome["state"], "retired");
        assert!(outcome["seq"].as_i64().unwrap() > 0);
        assert_eq!(
            node.proposal_state(id).unwrap(),
            Some(canon::OutcomeState::Retired)
        );
        let replacement = call(&node, Operation::BrokerKeyPropose, key).await;
        assert_ne!(replacement["id"], id);

        let guest_id = node
            .guest_propose(
                "retire-reviewed-guest",
                note_proposal(b"guest proposed note", b""),
            )
            .unwrap();
        call(&node, Operation::ApprovalChallenge, json!({"id":guest_id})).await;
        // Expected refusal: gate:owner-retirement-required also protects reviewed guest proposals.
        assert_eq!(
            node.test_call(
                PRINCIPAL,
                Operation::ApprovalDecide,
                json!({"id":guest_id,"approve":false})
            )
            .await
            .unwrap_err()
            .code,
            "gate:owner-retirement-required"
        );
        assert_eq!(
            node.guest_propose(
                "retire-blocked-guest",
                note_proposal(b"next guest note", b"")
            ),
            Err("gate:target-fenced")
        );
        let outcome = finish_owner_action(
            &node,
            &guest_id,
            Operation::ApprovalRetireChallenge,
            Operation::ApprovalRetire,
            "retire",
            3,
        )
        .await;
        assert_eq!(outcome["state"], "retired");
        assert_eq!(node.guest_read(gate::targets::NOTE_TARGET).unwrap(), None);
        assert!(node
            .guest_propose("retire-next-guest", note_proposal(b"next guest note", b""))
            .is_ok());
        let listing = call(&node, Operation::Approvals, json!({})).await;
        assert!(listing["pending"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["id"] != id && p["id"] != guest_id));
    });
}

struct CrashAfterWriteClaim {
    ledger: crate::ledger::AuraLedger,
    store: gate::fs_store::FsStore,
    target: String,
    observed: Vec<u8>,
    crashed: AtomicBool,
}

impl gate::Ledger for CrashAfterWriteClaim {
    fn append(
        &self,
        tx: &rusqlite::Transaction<'_>,
        row: &gate::LedgerRow,
    ) -> gate::Result<gate::LedgerRef> {
        gate::Ledger::append(&self.ledger, tx, row)
    }

    fn read_verified(
        &self,
        db: &rusqlite::Connection,
        reference: &gate::LedgerRef,
    ) -> gate::Result<gate::VerifiedLedgerRow> {
        let row = gate::Ledger::read_verified(&self.ledger, db, reference)?;
        if row.kind == "gate.consume" && !self.crashed.swap(true, Ordering::SeqCst) {
            let claimed: bool = db.query_row(
                "SELECT write_claimed FROM gate_proposals WHERE id=?",
                [&row.op],
                |r| r.get(0),
            )?;
            assert!(claimed, "the crash follows the durable single-write claim");
            self.store.write(&self.target, &self.observed, "cafef00d")?;
            panic!("deterministic crash after write claim, before gate effect");
        }
        Ok(row)
    }
}

fn crash_with_observed_target(node: &Node, id: &str, observed: &[u8]) {
    drop(node.gate.lock().unwrap().take());
    let owner = node.owner.lock().unwrap();
    let subject = owner.state().unwrap().subject.unwrap();
    let credential = owner.credential().unwrap().unwrap();
    drop(owner);
    let root = node.config.state_dir.join("targets");
    let specs = ["release", "broker/key", "broker/grant", "kira/permission"]
        .iter()
        .map(|target| {
            let mut spec = gate::TargetSpec::supervisor(target).unwrap();
            if *target == "broker/grant" {
                spec.pinned_facts = Some(json!({"prices":node.config.broker.prices}));
            }
            spec
        });
    let mut targets = vec![gate::TargetSpec::theme(), gate::TargetSpec::note()];
    targets.extend(specs);
    let mut gate = gate::Gate::open(
        crate::state::connection(&node.db_path()).unwrap(),
        gate::Config {
            node: node.config.node_id.clone(),
            gate_pubkey_sha256: gate::sha256(&node.signer.verifying_key().to_bytes()),
            owner: gate::OwnerState {
                subject,
                epoch: 1,
                binding_sha256: gate::sha256(credential.credential_id.as_bytes()),
                sign_count: credential.sign_count,
            },
            limits: gate::Limits {
                max_pending: 32,
                max_per_window: 32,
                ..gate::Limits::default()
            },
        },
        targets,
        gate::fs_store::FsStore::new(&root).unwrap(),
        CrashAfterWriteClaim {
            ledger: crate::ledger::AuraLedger {
                signer: node.signer.clone(),
            },
            store: gate::fs_store::FsStore::new(&root).unwrap(),
            target: gate::targets::NOTE_TARGET.into(),
            observed: observed.to_vec(),
            crashed: AtomicBool::new(false),
        },
        crate::owner::PasskeyProof {
            rp: node.config.webauthn.rp_id.clone(),
            origin: node.config.webauthn.origin.clone(),
            credential: Arc::new(Mutex::new(Some(credential))),
        },
        crate::ledger::Clock,
    )
    .unwrap();
    let review = gate.owner().review(id).unwrap();
    let challenge = aumlok::webauthn::owner_authorization_challenge(&review.auth_bytes).unwrap();
    let proof = serde_json::to_vec(&crate::owner::tests::assertion(&challenge, 2)).unwrap();
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        gate.owner().consume(gate::ConsumeRequest {
            proposal_id: id.into(),
            challenge: review.challenge,
            base_sha256: review.base_sha256,
            new_sha256: review.new_sha256,
            display_sha256: review.display_sha256,
            decision: gate::Decision::Allow,
            proof,
        })
    }));
    assert!(
        crashed.is_err(),
        "the fixture must interrupt the effect attempt"
    );
    drop(gate);
    node.initialize_organs().unwrap();
}

#[test]
fn antibody_owner_reconcile_conflict_and_incomplete_unlocks_target() {
    for (state, observed) in [
        (
            canon::OutcomeState::Conflict,
            b"external conflicting target".as_slice(),
        ),
        (
            canon::OutcomeState::Incomplete,
            b"approved proposed note".as_slice(),
        ),
    ] {
        let (_directory, runtime, node) = bound_node();
        let id = node
            .guest_propose(
                "reconcile-crashed-note",
                note_proposal(b"approved proposed note", b""),
            )
            .unwrap();
        crash_with_observed_target(&node, &id, observed);
        assert_eq!(node.proposal_state(&id).unwrap(), Some(state));
        // Expected refusal: gate:target-fenced for conflict and incomplete until owner reconciliation.
        assert_eq!(
            node.guest_propose(
                "reconcile-fenced-note",
                note_proposal(b"next proposed note", observed)
            ),
            Err("gate:target-fenced")
        );
        runtime.block_on(async {
            let listing = call(&node, Operation::Approvals, json!({})).await;
            let listed = listing["pending"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["id"] == id)
                .unwrap();
            assert_eq!(
                listed["state"],
                if state == canon::OutcomeState::Conflict {
                    "conflict"
                } else {
                    "incomplete"
                }
            );
            let outcome = finish_owner_action(
                &node,
                &id,
                Operation::ApprovalReconcileChallenge,
                Operation::ApprovalReconcile,
                "reconcile",
                3,
            )
            .await;
            assert_eq!(outcome["state"], "reconciled");
            assert!(outcome["seq"].as_i64().unwrap() > 0);
            assert_eq!(
                node.guest_read(gate::targets::NOTE_TARGET)
                    .unwrap()
                    .unwrap(),
                observed
            );
            assert_eq!(node.proposal_state(&id).unwrap(), Some(state));
            let listing = call(&node, Operation::Approvals, json!({})).await;
            assert!(listing["pending"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["id"] != id));
        });
        let next = node
            .guest_propose(
                "reconcile-next-note",
                note_proposal(b"next proposed note", observed),
            )
            .unwrap();
        assert_ne!(next, id);
        let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
        aura::walk(&entries, &node.signer.verifying_key(), None).unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.op == id && entry.phase == "terminal")
                .count(),
            1
        );
        assert!(entries
            .iter()
            .any(|entry| entry.op == id && entry.kind == "gate.recover" && entry.phase == "fact"));
    }
}

struct Provider {
    url: String,
    calls: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Provider {
    fn start() -> Option<Self> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("UNTESTED supervisor fake-provider HTTP: sandbox bind EPERM; integrator must run");
                return None;
            }
            Err(error) => panic!("fake provider bind: {error}"),
        };
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_calls = calls.clone();
        let worker_stopped = stopped.clone();
        let worker = thread::spawn(move || {
            while !worker_stopped.load(Ordering::Acquire) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("fake provider accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                worker_calls.fetch_add(1, Ordering::Relaxed);
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 16_384);
                }
                let headers = String::from_utf8(headers).unwrap();
                assert!(headers.starts_with("POST /chat/completions HTTP/1.1\r\n"));
                assert!(
                    headers
                        .lines()
                        .any(|line| line
                            .eq_ignore_ascii_case(&format!("authorization: Bearer {KEY}")))
                );
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                    })
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                assert!(!String::from_utf8_lossy(&body).contains(KEY));
                let value: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(value["model"], "deepseek/deepseek-chat");
                let response = br#"{"choices":[{"message":{"content":"provider response","tool_calls":[]},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"cost":0.000007}}"#;
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()).unwrap();
                stream.write_all(response).unwrap();
            }
        });
        Some(Self {
            url,
            calls,
            stopped,
            thread: Some(worker),
        })
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn guest_request(guest: &mut UnixStream, id: &str, body: FrameBody) -> FrameBody {
    canon::write_frame(
        guest,
        &Frame {
            v: 1,
            id: id.into(),
            body,
        },
    )
    .unwrap();
    let reply = canon::read_frame(guest, Direction::Supervisor).unwrap();
    assert_eq!(reply.id, id);
    reply.body
}

#[test]
fn claim_enrol_bind_release_fake_guest_broker_memory_and_aura_end_to_end() {
    let directory = tempfile::tempdir().unwrap();
    let temporary_root = std::fs::canonicalize(directory.path()).unwrap();
    let config = config(&temporary_root);
    for path in [
        &config.guest.node_dir,
        &config.guest.harness_dir,
        &config.guest.bundle_dir,
    ] {
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(path.join("runtime.txt"), b"pinned runtime bytes").unwrap();
    }
    let provider = Provider::start();
    let provider_url = provider
        .as_ref()
        .map(|p| p.url.clone())
        .unwrap_or_else(|| "https://openrouter.ai/api/v1".into());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let handle = runtime.handle().clone();
    let node = Node::open_for_test(config.clone(), handle.clone(), provider_url.clone()).unwrap();
    let digests = runtime::measure(&node.runtime_config()).unwrap();
    assert!(!runtime::launch_allowed(
        node.bound().unwrap(),
        &digests,
        None
    ));
    assert!(node.ensure_release(&digests).is_err());
    let token = node.owner.lock().unwrap().create_claim().unwrap();
    let claim: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let session = [71; 32];
    let expires = crate::state::now_ms().unwrap() + 86_400_000;
    runtime
        .block_on(node.consume_claim_session(claim, session, expires))
        .unwrap();
    assert!(runtime.block_on(node.consume_claim(claim)).is_err());
    runtime.block_on(async {
        let start = call(&node, Operation::EnrolStart, json!({})).await;
        let registration =
            crate::owner::tests::registration(start["public_key"]["challenge"].as_str().unwrap());
        let staged = call(
            &node,
            Operation::EnrolFinish,
            json!({"enrolment_id":start["enrolment_id"],"attestation":registration}),
        )
        .await;
        let possession =
            crate::owner::tests::assertion(staged["public_key"]["challenge"].as_str().unwrap(), 1);
        call(
            &node,
            Operation::EnrolFinish,
            json!({"enrolment_id":start["enrolment_id"],"assertion":possession}),
        )
        .await;
        crate::owner::tests::prepare_fast(&mut node.owner.lock().unwrap());
        let prepared = call(&node, Operation::BindingPrepare, json!({})).await;
        call(
            &node,
            Operation::BindingConfirm,
            json!({"ceremony_id":prepared["ceremony_id"],"words":prepared["words"]}),
        )
        .await;
    });
    assert!(node.bound().unwrap());
    assert_eq!(
        runtime
            .block_on(node.test_call(PRINCIPAL, Operation::Release, json!({})))
            .unwrap_err()
            .code,
        "supervisor:runtime-hash-pending"
    );
    node.runtime_changed(&runtime::RuntimeStatus {
        current_digest: digests.digest.clone(),
        approved_digest: None,
        agent: "stopped".into(),
        since: crate::state::now_ms().unwrap(),
    })
    .unwrap();
    assert_eq!(
        runtime
            .block_on(node.test_call(PRINCIPAL, Operation::Release, json!({})))
            .unwrap()["current_digest"],
        digests.digest
    );
    node.ensure_release(&digests).unwrap();
    let release_id: String = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id FROM gate_proposals WHERE target='release'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut counter = 1;
    runtime.block_on(approve(&node, &release_id, &mut counter));
    let approved = node.approved_release().unwrap();
    assert!(runtime::launch_allowed(
        node.bound().unwrap(),
        &digests,
        approved.as_ref()
    ));
    runtime.block_on(async {
        let proposed = call(&node, Operation::BrokerKeyPropose, json!({"key_sha256":gate::sha256(KEY.as_bytes())})).await;
        let id = proposed["id"].as_str().unwrap();
        assert_eq!(node.test_call(PRINCIPAL, Operation::BrokerKeyRedeem, json!({"id":id,"key":KEY})).await.unwrap_err().code, "broker:key-not-approved");
        approve(&node, id, &mut counter).await;
        assert_eq!(node.test_call(PRINCIPAL, Operation::BrokerKeyRedeem, json!({"id":id,"key":"sk-or-wrong-key-673191"})).await.unwrap_err().code, "broker:key-mismatch");
        call(&node, Operation::BrokerKeyRedeem, json!({"id":id,"key":KEY})).await;
        assert_eq!(node.test_call(PRINCIPAL, Operation::BrokerKeyRedeem, json!({"id":id,"key":KEY})).await.unwrap_err().code, "broker:key-redeemed");
        let grant = call(&node, Operation::BrokerGrantPropose, json!({"model":"deepseek/deepseek-chat","cap_microusd":100_000,"per_request_cap_microusd":10_000,"max_requests":8,"hours":1})).await;
        let cards = call(&node, Operation::Approvals, json!({})).await;
        let card = cards["pending"].as_array().unwrap().iter().find(|pending| pending["id"]==grant["id"]).unwrap();
        let rates = &card["card"]["target_review"]["pinned"]["prices"]["deepseek/deepseek-chat"];
        assert_eq!(rates["prompt_microusd_per_token"],1);
        assert_eq!(rates["completion_microusd_per_token"],1);
        for name in ["prompt_microusd_per_token","completion_microusd_per_token"] {
            assert!(card["card"]["facts"].as_array().unwrap().iter().any(|fact|fact==&json!([name,"1"])));
        }
        approve(&node, grant["id"].as_str().unwrap(), &mut counter).await;
    });
    let (mut guest, supervisor) = UnixStream::pair().unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let launch_id = crate::state::random_id().unwrap();
    node.sandbox_event("sandbox.start", &launch_id, "intent", json!({"stub":true}))
        .unwrap();
    let dispatcher_node = node.clone();
    let ready_node = node.clone();
    let dispatcher = thread::spawn(move || {
        crate::dispatcher::run(
            dispatcher_node,
            supervisor,
            handle,
            Box::new(move || ready_node.mark_agent_running().unwrap()),
        )
    });
    let status = guest_request(&mut guest, "status", FrameBody::Status(Status));
    let FrameBody::StatusReply(status) = status else {
        panic!("status reply required")
    };
    assert!(status.bound && status.ready);
    assert_eq!(status.grant_remaining, Some(100_000));
    if let Some(provider) = &provider {
        let reply = guest_request(
            &mut guest,
            "model",
            FrameBody::ModelCall(canon::ModelCall {
                grant_id: status.grant_id.unwrap(),
                model: "deepseek/deepseek-chat".into(),
                messages: vec![canon::Message {
                    role: "user".into(),
                    content: Some("hello".into()),
                    tool_calls: None,
                    tool_call_id: None,
                }],
                tools: vec![],
                max_output_tokens: 10,
            }),
        );
        assert!(
            matches!(reply, FrameBody::ModelReply(reply) if reply.content.as_deref()==Some("provider response") && reply.usage.cost_microusd==7 && reply.receipt_seq>0)
        );
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(node.status().unwrap().grant_remaining, Some(99_993));
    }
    let proposal = guest_request(
        &mut guest,
        "propose",
        FrameBody::Propose(canon::Propose {
            target: gate::targets::NOTE_TARGET.into(),
            base_sha256: gate::sha256(&[]),
            new_bytes_b64: STANDARD.encode("owner approved once"),
            note: "model note".into(),
            cell: None,
        }),
    );
    let FrameBody::Accepted(proposal) = proposal else {
        panic!("proposal accepted required")
    };
    runtime.block_on(approve(&node, &proposal.proposal_id, &mut counter));
    let outcome = canon::read_frame(&mut guest, Direction::Supervisor).unwrap();
    assert!(
        matches!(outcome.body,FrameBody::Outcome(outcome) if outcome.proposal_id==proposal.proposal_id && outcome.state==canon::OutcomeState::Applied)
    );
    let mut memory = MemoryPut {
        cell: canon::Cell {
            module_sha256: String::new(),
            input_sha256: String::new(),
            effect_sha256: String::new(),
        },
        statement: "remember rainbow bridge".into(),
        quote: None,
        category: "personal".into(),
    };
    let value = crate::dispatcher::memory_value(&memory);
    let cell = node
        .cell
        .run_memory_put(&crate::dispatcher::memory_key(&value).unwrap(), &value)
        .unwrap();
    memory.cell = canon::Cell {
        module_sha256: cell.module_sha256,
        input_sha256: cell.input_sha256,
        effect_sha256: cell.effect_sha256,
    };
    assert!(matches!(
        guest_request(&mut guest, "memory", FrameBody::MemoryPut(memory)),
        FrameBody::Accepted(_)
    ));
    assert!(
        matches!(canon::read_frame(&mut guest,Direction::Supervisor).unwrap().body,FrameBody::Outcome(outcome) if outcome.state==canon::OutcomeState::Applied)
    );
    let recall = || {
        FrameBody::MemoryRecall(canon::MemoryRecall {
            query: "bridge".into(),
            limit: 10,
        })
    };
    assert!(
        matches!(guest_request(&mut guest,"recall",recall()),FrameBody::Recall(recall) if recall.result==canon::RecallResult::Undetermined && recall.items.is_empty())
    );
    runtime.block_on(async {
        let permission = call(&node, Operation::MemoryPermissionPropose, json!({})).await;
        approve(&node, permission["id"].as_str().unwrap(), &mut counter).await;
    });
    assert!(
        matches!(guest_request(&mut guest,"recall-approved",recall()),FrameBody::Recall(recall) if recall.result==canon::RecallResult::Found && recall.items.len()==1 && recall.items[0].text.starts_with("[model-authored (untrusted)]"))
    );
    guest.shutdown(Shutdown::Both).unwrap();
    assert!(dispatcher.join().unwrap().is_err());
    node.sandbox_event(
        "sandbox.exit",
        &launch_id,
        "terminal",
        json!({"stub":true,"status":0}),
    )
    .unwrap();
    let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
    aura::walk(&entries, &node.signer.verifying_key(), None).unwrap();
    let mut operations = BTreeMap::<String, usize>::new();
    for entry in &entries {
        if !entry.op.is_empty() {
            let terminals = operations.entry(entry.op.clone()).or_default();
            *terminals += usize::from(entry.phase == "terminal");
        }
    }
    assert!(!operations.is_empty());
    assert!(
        operations.values().all(|count| *count == 1),
        "every operation requires exactly one terminal"
    );
    assert!(entries
        .iter()
        .any(|entry| entry.kind == "kira.save" && entry.phase == "terminal"));
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.kind == "broker.reserve")
            .count(),
        usize::from(provider.is_some())
    );
    drop(node);
    let mut revised_config = config;
    revised_config
        .broker
        .prices
        .get_mut("deepseek/deepseek-chat")
        .unwrap()
        .prompt_microusd_per_token = 99;
    let reopened =
        Node::open_for_test(revised_config, runtime.handle().clone(), provider_url).unwrap();
    assert_eq!(
        reopened
            .live_grant()
            .unwrap()
            .unwrap()
            .price_basis
            .unwrap()
            .prompt_microusd_per_token,
        1
    );
    assert!(reopened.bound().unwrap());
    assert!(runtime
        .block_on(reopened.session_valid(session, crate::state::now_ms().unwrap()))
        .unwrap());
    assert!(runtime.block_on(reopened.consume_claim(claim)).is_err());
    assert!(runtime::launch_allowed(
        reopened.bound().unwrap(),
        &digests,
        reopened.approved_release().unwrap().as_ref()
    ));
    let recalled = reopened.recall("bridge", 10).unwrap();
    assert_eq!(recalled.result, canon::RecallResult::Found);
    assert_eq!(recalled.items.len(), 1);
}

#[path = "slider_tests.rs"]
mod slider_tests;
