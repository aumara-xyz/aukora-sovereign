// SPDX-License-Identifier: AGPL-3.0-or-later
//! A live claim loses corroboration when a support root is withdrawn or invalid at the final read.

use super::*;

const CLAIM: &str = "The violet ledger is on the shelf by the front door";

fn supported_claim(f: &Fixture, valid_from: Option<u64>, valid_to: Option<u64>) -> (String, String) {
    // Local notes by different authors retain independent roots even when their statements match. Only the owner's
    // sourced claim is a recall candidate; the roots remain readable for checking its support.
    let mut a = note(CLAIM, "local");
    a["valid_from"] = json!(valid_from);
    a["valid_to"] = json!(valid_to);
    let a = call(&f.state, &f.claude, "remember", a)["result"]["id"].as_str().unwrap().to_owned();
    let b = call(&f.state, &f.grok, "remember", note(CLAIM, "local"))["result"]["id"].as_str().unwrap().to_owned();
    let mut claim = note(CLAIM, "builders");
    claim["sources"] = json!([a, b]);
    let claim = call(&f.state, &f.owner, "remember", claim)["result"]["id"].as_str().unwrap().to_owned();
    (claim, a)
}

fn params() -> Value {
    json!({"query": "where is the violet ledger", "author": "peter"})
}

fn assert_unverified(answer: &Value, claim: &str) {
    assert_eq!((answer["status"].clone(), answer["reason"].clone()),
        (json!("undetermined"), json!("similar-note-unverified")), "{answer}");
    let shown = answer["items"].as_array().unwrap().iter().find(|i| i["id"] == claim).expect("claim remains current");
    assert_eq!(shown["evidence"], "unverified", "{shown}");
}

#[test]
fn a_support_root_superseded_during_recall_no_longer_justifies_found() {
    let f = fixture();
    let (claim, root) = supported_claim(&f, None, None);
    let quiet = recall_across_params(&f, &f.owner, params(), || {}).unwrap();
    assert_eq!(quiet["status"], "found", "{quiet}");
    let after = recall_across_params(&f, &f.owner, params(), || {
        assert_eq!(call(&f.state, &f.owner, "supersede", json!({"target": root}))["ok"], true);
    }).unwrap();
    assert_unverified(&after, &claim);
}

fn answer_after_gathering_at(f: &Fixture, gather_at: u64) -> Value {
    let caller = lock(&f.state).caller(&f.owner).unwrap();
    let query = RecallQuery {
        text: "where is the violet ledger".into(),
        caller: caller.pubkey.clone(),
        epoch: 2,
        scopes: vec![],
        author: Some(caller.pubkey.clone()),
        budget_chars: DEFAULT_BUDGET,
        include_local: true,
        include_web: false,
        include_history: false,
        now: gather_at,
    };
    let prepared = lock(&f.state).store.recall_prepare(&query, None).unwrap();
    let outcome = prepared.finish(None);
    assert_eq!(outcome.status, RecallStatus::Found, "the support root is valid at gather time");
    recall_answer(&f.state, &caller, &outcome).unwrap()
}

#[test]
fn a_support_root_expired_since_gather_no_longer_justifies_found() {
    let f = fixture();
    let expired_at = now() - 10;
    let (claim, _) = supported_claim(&f, None, Some(expired_at));
    // Gather at a historical instant immediately before expiry; the final service read uses the real clock.
    let answer = answer_after_gathering_at(&f, expired_at - 1);
    assert_unverified(&answer, &claim);
}

#[test]
fn final_revalidation_uses_final_time_for_a_not_yet_valid_support_root() {
    let f = fixture();
    let starts_at = now() + 86_400;
    let (claim, _) = supported_claim(&f, Some(starts_at), None);
    // An outcome gathered for a later instant cannot lend evidence to a final read before the validity window.
    let answer = answer_after_gathering_at(&f, starts_at + 1);
    assert_unverified(&answer, &claim);
}
