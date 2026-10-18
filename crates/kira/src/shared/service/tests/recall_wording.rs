// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn recall_explains_leads_and_keeps_mixed_found_evidence_per_note() {
    let f = fixture();
    let unverified = call(&f.state, &f.claude, "remember", note("The bronze compass is beside the west window", "builders"));
    let unverified = unverified["result"]["id"].clone();
    let ask = || call(&f.state, &f.grok, "recall", json!({"query": "bronze compass west window"}))["result"].clone();
    let leads = ask();
    assert_eq!(leads["status"], "undetermined", "{leads}");
    assert_eq!(leads["reason"], "similar-note-unverified");
    assert_eq!(leads["message"], "Related notes were found, but K2 couldn't establish an evidence-backed answer. Use these as leads to check.");
    assert!(leads["items"].as_array().unwrap().iter().any(|i| i["id"] == unverified && i["evidence"] == "unverified"));

    let mut owner_note = note("The bronze compass is in the drawer by the west window", "builders");
    owner_note["capture"] = json!("owner-typed");
    let supported = call(&f.state, &f.owner, "remember", owner_note)["result"]["id"].clone();
    let found = ask();
    assert_eq!(found["status"], "found", "{found}");
    assert_eq!(found["message"], "Evidence labels apply to each note; found does not verify every returned claim.");
    let items = found["items"].as_array().unwrap();
    assert!(items.iter().any(|i| i["id"] == supported && i["evidence"] == "owner-words"), "{found}");
    assert!(items.iter().any(|i| i["id"] == unverified && i["evidence"] == "unverified"), "{found}");
}

#[test]
fn recall_does_not_describe_other_undetermined_reasons_as_unverified_leads() {
    for reason in ["integrity", "embedder-down", "reranker-down", "index-incomplete", "budget", "note-changed", "note-integrity"] {
        assert_eq!(RecallStatus::Undetermined(reason).message(), None, "{reason}");
    }
    assert_eq!(RecallStatus::Empty.message(), None);
}
