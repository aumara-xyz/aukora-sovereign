// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn a_corrected_note_has_one_retired_label_on_every_wire_view() {
    let f = fixture();
    let old = remember_id(&f, &f.claude, "Finding relay severity is HIGH");
    let new = remember_id(&f, &f.claude, "Finding relay severity is MEDIUM");
    let corrected = call(&f.state, &f.claude, "supersede", json!({"target": old, "replacement": new}));
    assert_eq!(corrected["result"]["target"]["validity"], "superseded", "{corrected}");
    let got = call(&f.state, &f.grok, "get", json!({"id": old}));
    assert_eq!(got["result"]["state"], "corrected", "{got}");
    assert_eq!(got["result"]["validity"], "superseded", "{got}");
    assert_eq!(got["result"]["current_id"], new.as_str());
    let listed = call(&f.state, &f.grok, "list_recent", json!({}));
    let shown = listed["result"]["notes"].as_array().unwrap().iter().find(|n| n["id"] == old.as_str()).unwrap();
    assert_eq!(shown["validity"], "superseded");
    let s = lock(&f.state);
    assert_eq!(crate::shared::hybrid::validity(&s.store.get(&old).unwrap().unwrap().meta, now()), "current");
}

#[test]
fn recall_history_labels_and_links_the_original_after_its_replacement() {
    let f = fixture();
    let old = remember_id(&f, &f.claude, "Finding relay severity is HIGH");
    let new = remember_id(&f, &f.claude, "Finding relay severity is MEDIUM");
    assert_eq!(call(&f.state, &f.claude, "supersede", json!({"target": old, "replacement": new}))["ok"], true);
    let q = json!({"query": "finding relay severity"});
    let default = call(&f.state, &f.grok, "recall", q.clone());
    let mut explicit = q.clone();
    explicit["include_history"] = json!(false);
    assert_eq!(call(&f.state, &f.grok, "recall", explicit), default);
    let mut q = q;
    q["include_history"] = json!(true);
    let recalled = call(&f.state, &f.grok, "recall", q);
    assert_eq!(ids_of(&recalled), vec![(new.clone(), Value::Null), (old, json!("superseded"))], "{recalled}");
    let original = &recalled["result"]["items"][1];
    assert_eq!(original["validity"], "superseded");
    assert_eq!(original["state"], "corrected");
    assert_eq!(original["current_id"], new.as_str());
    assert_ne!(recalled["result"]["query_digest"], default["result"]["query_digest"]);
}

#[test]
fn opted_in_history_can_show_a_retraction_without_claiming_a_current_answer() {
    let f = fixture();
    let old = remember_id(&f, &f.claude, "The retired atlas was on the desk");
    assert_eq!(call(&f.state, &f.claude, "supersede", json!({"target": old}))["ok"], true);
    let default = call(&f.state, &f.grok, "recall", json!({"query": "retired atlas"}));
    assert!(ids_of(&default).is_empty(), "{default}");
    let history = call(&f.state, &f.grok, "recall", json!({"query": "retired atlas", "include_history": true}));
    assert_eq!(history["result"]["status"], "empty", "{history}");
    assert_eq!(ids_of(&history), vec![(old, json!("superseded"))]);
    assert_eq!(history["result"]["items"][0]["current_id"], Value::Null);
}

#[test]
fn history_never_reveals_an_unreadable_replacement() {
    let f = fixture();
    let old = remember_id(&f, &f.owner, "The retired atlas was on the desk");
    let new = call(&f.state, &f.owner, "remember", note("The atlas is in the private vault", "local"));
    let new = new["result"]["id"].as_str().unwrap();
    assert_eq!(call(&f.state, &f.owner, "supersede", json!({"target": old, "replacement": new}))["ok"], true);
    let history = call(&f.state, &f.grok, "recall", json!({"query": "retired atlas", "include_history": true}));
    assert_eq!(ids_of(&history), vec![(old, json!("superseded"))], "{history}");
    assert_eq!(history["result"]["items"][0]["current_id"], Value::Null);
    assert!(!history.to_string().contains(new), "{history}");
}

#[test]
fn history_respects_scope_local_privacy_and_resume_slot_access() {
    for restriction in ["scope", "local", "slot"] {
        let f = fixture();
        let write = |text: &str, head: &str| {
            let mut n = note(text, if restriction == "local" { "local" } else { "builders" });
            if restriction == "scope" {
                n["scope"] = json!("owner-only");
            } else if restriction == "slot" {
                n["slot"] = json!("resume:peter");
                n["lane"] = json!("experience");
                n["form"] = json!("snapshot");
                n["expected_head"] = json!(head);
            }
            let reply = call(&f.state, &f.owner, "remember", n);
            reply["result"]["id"].as_str().unwrap_or_else(|| panic!("{reply}")).to_owned()
        };
        let old = write("The secret atlas was on the desk", "none");
        let new = write("The secret atlas is on the shelf", &old);
        let expected = call(&f.state, &f.owner, "get", json!({"id": old}))["result"]["superseded_by"].clone();
        assert_eq!(call(&f.state, &f.owner, "supersede", json!({"target": old, "replacement": new, "expected_current": expected}))["ok"], true);
        let q = json!({"query": "secret atlas", "include_history": true});
        let readable = call(&f.state, &f.owner, "recall", q.clone());
        assert_eq!(ids_of(&readable), vec![(new.clone(), Value::Null), (old.clone(), json!("superseded"))], "{restriction}: {readable}");
        for id in [&old, &new] {
            assert_eq!(call(&f.state, &f.grok, "get", json!({"id": id}))["error"], "kira:not-found");
        }
        let hidden = call(&f.state, &f.grok, "recall", q);
        assert_eq!(hidden["result"]["status"], "empty", "{restriction}: {hidden}");
        assert!(ids_of(&hidden).is_empty(), "{restriction}: {hidden}");
        assert_eq!(hidden["result"]["total"], 0);
        assert!(!hidden.to_string().contains(&old) && !hidden.to_string().contains(&new));
    }
}

#[test]
fn quarantined_history_is_labelled_and_never_returns_the_text() {
    let f = fixture();
    let old = remember_id(&f, &f.claude, "The atlas has a quarantined location");
    let pubkey = lock(&f.state).pubkey_of("claude").unwrap();
    assert_eq!(call(&f.state, &f.owner, "quarantine_source", json!({"pubkey": pubkey}))["ok"], true);
    let got = call(&f.state, &f.grok, "get", json!({"id": old}));
    assert_eq!(got["result"]["validity"], "quarantined", "{got}");
    assert!(got["result"].get("text").is_none());
    let history = call(&f.state, &f.grok, "recall", json!({"query": "atlas quarantined", "include_history": true}));
    assert_eq!(ids_of(&history), vec![(old, json!("quarantined"))], "{history}");
    assert_eq!(history["result"]["items"][0]["validity"], "quarantined");
    assert!(history["result"]["items"][0].get("text").is_none());
}
