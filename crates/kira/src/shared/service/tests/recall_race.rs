// SPDX-License-Identifier: AGPL-3.0-or-later
//! The service's tests of a recall whose store changes while its models run: the answer, and the evidence behind
//! `found`, are worked out from the notes as they are afterwards.

use super::*;


/// A recall gathered under the lock, then (as if while the models ran) the store changes, then the answer is read.
fn recall_across(f: &Fixture, token: &str, query: &str, between: impl FnOnce()) -> Result<Value> {
    recall_across_params(f, token, json!({"query": query}), between)
}

fn recall_across_params(f: &Fixture, token: &str, params: Value, between: impl FnOnce()) -> Result<Value> {
    let caller = lock(&f.state).caller(token).unwrap();
    let (prepared, _) = recall_gather(&f.state, &caller, parse(params).unwrap()).unwrap();
    between();
    let outcome = prepared.finish(None);
    recall_answer(&f.state, &caller, &outcome)
}

#[test]
fn a_note_that_dies_while_recall_runs_its_models_is_not_returned() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let mut typed = note("The figurine is on the left shelf", "builders");
    typed["capture"] = json!("owner-typed");
    let figurine = call(&f.state, &owner, "remember", typed);
    let figurine = figurine["result"]["id"].as_str().unwrap().to_owned();
    // Nothing changes: found, with the note.
    let quiet = recall_across(&f, &grok, "where is the figurine", || {}).unwrap();
    assert_eq!(quiet["status"], "found", "{quiet}");
    // Superseded in between: not returned as memory, and the answer is not "found".
    let superseded = recall_across(&f, &grok, "where is the figurine", || {
        assert_eq!(call(&f.state, &owner, "supersede", json!({"target": figurine}))["ok"], true);
    })
    .unwrap();
    assert!(superseded["items"].as_array().unwrap().iter().all(|i| i["id"] != figurine.as_str()), "{superseded}");
    assert_eq!((superseded["status"].clone(), superseded["reason"].clone()), (json!("undetermined"), json!("note-changed")));
    // Its author quarantined in between: no text, not even a stub of it as live memory.
    let kettle = call(&f.state, &grok, "remember", note("The kettle lives on the top shelf", "builders"));
    let kettle = kettle["result"]["id"].as_str().unwrap().to_owned();
    let grok_key = lock(&f.state).pubkey_of("grok").unwrap();
    let quarantined = recall_across(&f, &claude, "where does the kettle live", || {
        assert_eq!(call(&f.state, &owner, "quarantine_source", json!({"pubkey": grok_key}))["ok"], true);
    })
    .unwrap();
    assert!(quarantined["items"].as_array().unwrap().iter().all(|i| i["id"] != kettle.as_str()), "{quarantined}");
    assert_ne!(quarantined["status"], "found", "{quarantined}");
    // The caller revoked in between gets nothing.
    let lamp = call(&f.state, &claude, "remember", note("The lamp is by the window", "builders"));
    assert_eq!(lamp["ok"], true);
    let revoked = recall_across(&f, &claude, "where is the lamp", || revoke(&f.dir, "claude").unwrap());
    assert_eq!(revoked.err(), Some(refuse("agent-revoked")));
}

#[test]
fn a_note_whose_author_is_revoked_mid_recall_reads_as_a_fresh_recall_would() {
    // Revoking an author stops its writes and its token; its notes stay readable (quarantine withdraws them). So the
    // answer across the revoke is the same answer a recall started after it gives.
    let f = fixture();
    let (claude, grok) = (f.claude.clone(), f.grok.clone());
    call(&f.state, &claude, "remember", note("The atlas is under the bed", "builders"));
    let across = recall_across(&f, &grok, "where is the atlas", || revoke(&f.dir, "claude").unwrap()).unwrap();
    let after = call(&f.state, &grok, "recall", json!({"query": "where is the atlas"}));
    assert_eq!(across["items"], after["result"]["items"]);
    assert_eq!(across["status"], after["result"]["status"]);
}

/// Grok re-check, part 1: the evidence behind `found` is worked out again from the notes as they are after the reranker ran.
#[test]
fn found_that_rests_on_corroboration_does_not_outlive_a_root_quarantined_in_the_gap() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    // N cites two independent roots stating the same claim, in separate privacy levels.
    let words = "The green ledger is on the shelf by the front door";
    let a = call(&f.state, &claude, "remember", note(words, "local"))["result"]["id"].as_str().unwrap().to_owned();
    let b = remember_id(&f, &grok, words);
    let mut n = note(words, "builders");
    n["sources"] = json!([a, b]);
    let n = call(&f.state, &owner, "remember", n)["result"]["id"].as_str().unwrap().to_owned();
    let q = "where is the green ledger";
    let quiet = recall_across(&f, &owner, q, || {}).unwrap();
    assert_eq!(quiet["status"], "found", "{quiet}");
    assert!(quiet["items"].as_array().unwrap().iter().any(|i| i["text"] == words && i["evidence"] == "corroborated"));
    // While the reranker would run, the owner quarantines one root's author. N is still a current note, but it now
    // stands on one reader-visible hand: the answer is a lead, and the label says so.
    let claude_key = lock(&f.state).pubkey_of("claude").unwrap();
    let after = recall_across(&f, &owner, q, || {
        assert_eq!(call(&f.state, &owner, "quarantine_source", json!({"pubkey": claude_key}))["ok"], true);
    })
    .unwrap();
    assert_eq!((after["status"].clone(), after["reason"].clone()), (json!("undetermined"), json!("similar-note-unverified")), "{after}");
    let shown = after["items"].as_array().unwrap().iter().find(|i| i["id"] == n.as_str() || i["also_by_ids"].as_array().is_some_and(|ids| ids.contains(&json!(n)))).expect("N is still current");
    assert_eq!(shown["evidence"], "unverified", "{shown}");
}

/// A corroborated repeater stops justifying an earlier unsourced copy when it is withdrawn in the gap.
#[test]
fn found_that_rests_on_a_repeater_does_not_outlive_it() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let words = "The red ledger is on the shelf by the front door";
    // Each author's local note is an independent root. The owner's plain copy is kept; its later sourced repeater
    // supplies corroboration. Restrict candidates to the owner so the roots do not independently answer the query.
    let a = call(&f.state, &claude, "remember", note(words, "local"))["result"]["id"].as_str().unwrap().to_owned();
    let b = call(&f.state, &grok, "remember", note(words, "local"))["result"]["id"].as_str().unwrap().to_owned();
    let plain = remember_id(&f, &owner, words);
    // Notes are stamped to the second and ties break by id: wait so the plain copy is certainly the earlier one.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let mut n = note(words, "builders");
    n["sources"] = json!([a, b]);
    let n = call(&f.state, &owner, "remember", n)["result"]["id"].as_str().unwrap().to_owned();
    let params = json!({"query": "where is the red ledger", "author": "peter"});
    let quiet = recall_across_params(&f, &owner, params.clone(), || {}).unwrap();
    assert_eq!(quiet["status"], "found", "{quiet}");
    let shown = quiet["items"].as_array().unwrap().iter().find(|i| i["id"] == plain.as_str()).expect("plain copy is kept");
    assert_eq!(shown["evidence"], "corroborated", "{shown}");
    assert_eq!(shown["also_by_ids"], json!([n]), "{shown}");
    let after = recall_across_params(&f, &owner, params, || {
        assert_eq!(call(&f.state, &owner, "supersede", json!({"target": n}))["ok"], true);
    })
    .unwrap();
    assert_eq!((after["status"].clone(), after["reason"].clone()), (json!("undetermined"), json!("similar-note-unverified")), "{after}");
}

/// Grok review part 3: `found` must be recomputed from what survives the final filtering.
#[test]
fn found_does_not_stand_after_the_note_that_justified_it_is_gone() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let mut backed = note("The figurine is on the left shelf", "builders");
    backed["capture"] = json!("owner-typed");
    let backed = call(&f.state, &owner, "remember", backed)["result"]["id"].as_str().unwrap().to_owned();
    remember_id(&f, &claude, "The figurine was dusted on the shelf last week");
    let quiet = recall_across(&f, &grok, "where is the figurine on the shelf", || {}).unwrap();
    assert_eq!(quiet["status"], "found", "{quiet}");
    // While the reranker would run, the owner supersedes the backed note. One unverified lead is left.
    let after = recall_across(&f, &grok, "where is the figurine on the shelf", || {
        assert_eq!(call(&f.state, &owner, "supersede", json!({"target": backed}))["ok"], true);
    })
    .unwrap();
    assert_eq!((after["status"].clone(), after["reason"].clone()), (json!("undetermined"), json!("similar-note-unverified")), "{after}");
    assert!(after["items"].as_array().unwrap().iter().all(|i| i["id"] != backed.as_str() && i["evidence"] == "unverified"));
}
