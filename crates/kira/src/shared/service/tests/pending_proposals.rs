// SPDX-License-Identifier: AGPL-3.0-or-later
//! An advisory correction proposal does not change a note's state until acceptance.

use super::*;

#[test]
fn pending_builder_proposals_do_not_dispute_owner_commitments() {
    for lane in ["charter", "ruling", "decision"] {
        let f = fixture();
        let mut charter = note("The production vault quorum requires three hardware keys", "builders");
        charter["lane"] = json!(lane);
        charter["capture"] = json!("owner-typed");
        let original = call(&f.state, &f.owner, "remember", charter);
        assert_eq!(original["result"]["state"], "supported", "{original}");
        let id = original["result"]["id"].as_str().unwrap();
        let replacement = remember_id(&f, &f.claude, "The production vault quorum requires one software key");
        let proposed = call(&f.state, &f.claude, "supersede", json!({
            "target": id, "replacement": replacement, "reason": "An unaccepted builder suggestion"
        }));
        assert_eq!(proposed["result"]["proposed"], true, "{proposed}");
        assert_eq!(proposed["result"]["target"]["state"], "supported", "{proposed}");
        let proposal = &proposed["result"]["event"];
        for token in [&f.owner, &f.claude, &f.grok] {
            let got = call(&f.state, token, "get", json!({"id": id}));
            assert_eq!(got["result"]["state"], "supported", "{got}");
            assert_eq!(got["result"]["proposals"].as_array().unwrap().len(), 1);
            assert_eq!(got["result"]["proposals"][0]["event"], *proposal);
            let listed = call(&f.state, token, "list_recent", json!({}));
            let note = listed["result"]["notes"].as_array().unwrap().iter().find(|n| n["id"] == id).unwrap();
            assert_eq!(note["state"], "supported", "{note}");
            let recalled = call(&f.state, token, "recall", json!({"query": "production vault quorum hardware keys"}));
            let item = recalled["result"]["items"].as_array().unwrap().iter().find(|n| n["id"] == id).unwrap();
            assert_eq!(item["state"], "supported", "{recalled}");
        }
        assert_eq!(call(&f.state, &f.claude, "accept_correction", json!({"proposal": proposal}))["error"], "kira:accept-not-author");
        let accepted = call(&f.state, &f.owner, "accept_correction", json!({"proposal": proposal}));
        assert_eq!(accepted["result"]["target"]["state"], "corrected", "{accepted}");
        assert_eq!(accepted["result"]["target"]["current_id"], replacement.as_str());
        assert_eq!(state_of(&f, &f.grok, &replacement), "resolved");
    }
}
