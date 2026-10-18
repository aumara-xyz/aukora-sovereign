// SPDX-License-Identifier: AGPL-3.0-or-later
//! ARGON-LIVE-4 Break 1: correcting an agent's note grants no authority over its earlier replacement.

use super::*;
use crate::shared::note::{RESUME_SLOT, SELF_SLOT};

fn collateral_attack(f: &Fixture, replacement: &str) -> String {
    let first = remember_id(f, &f.claude, "The production vault quorum is under investigation");
    let hijack = remember_id(f, &f.claude, "HIJACKED BY AGENT: The production vault quorum requires only 1 software key.");
    for next in [replacement, hijack.as_str()] {
        let r = call(&f.state, &f.claude, "supersede", json!({"target": first, "replacement": next}));
        assert_eq!(r["ok"], true, "the report's two own-note corrections must run: {r}");
    }
    assert_eq!(call(&f.state, &f.claude, "get", json!({"id": first}))["result"]["current_id"], hijack.as_str());
    hijack
}

#[test]
fn an_agents_two_corrections_do_not_retire_owner_commitments_or_inherit_their_standing() {
    for lane in ["decision", "charter", "ruling"] {
        let f = fixture();
        let text = "OWNER COMMITMENT: The production vault quorum requires 3 hardware keys.";
        let mut commitment = note(text, "builders");
        commitment["lane"] = json!(lane);
        commitment["capture"] = json!("owner-typed");
        let written = call(&f.state, &f.owner, "remember", commitment);
        let id = written["result"]["id"].as_str().unwrap_or_else(|| panic!("{written}")).to_owned();
        let hijack = collateral_attack(&f, &id);
        for reader in [&f.owner, &f.grok] {
            let got = call(&f.state, reader, "get", json!({"id": id}));
            assert_eq!(got["result"]["text"], text, "{got}");
            assert_eq!((got["result"]["superseded_by"].clone(), got["result"]["current_id"].clone()), (Value::Null, Value::Null), "{got}");
            assert_ne!(got["result"]["state"], "corrected", "{got}");
            let recalled = call(&f.state, reader, "recall", json!({"query": "production vault quorum hardware keys"}));
            let items = recalled["result"]["items"].as_array().unwrap();
            let owner = items.iter().find(|n| n["id"] == id.as_str()).unwrap_or_else(|| panic!("{recalled}"));
            assert!(owner["correction"].is_null() && owner["current_id"].is_null(), "{owner}");
            assert_eq!(owner["evidence"], "owner-words", "{owner}");
            let attacker = items.iter().find(|n| n["id"] == hijack.as_str()).unwrap_or_else(|| panic!("{recalled}"));
            assert_eq!(attacker["evidence"], "unverified", "{attacker}");
        }
    }
}

#[test]
fn an_agents_two_corrections_neither_wipe_owner_slots_nor_make_the_owners_expected_head_stale() {
    for (slot, lane) in [(SELF_SLOT, "self"), (RESUME_SLOT, "resume")] {
        let f = fixture();
        let mut slotted = note("The owner's current handoff", "builders");
        slotted["lane"] = json!(lane);
        slotted["capture"] = json!("owner-typed");
        slotted["slot"] = json!(slot);
        slotted["expected_head"] = json!("none");
        let written = call(&f.state, &f.owner, "remember", slotted.clone());
        let id = written["result"]["id"].as_str().unwrap_or_else(|| panic!("{written}")).to_owned();
        collateral_attack(&f, &id);
        for reader in [&f.owner, &f.claude, &f.grok] {
            let head = call(&f.state, reader, "get", json!({"id": slot}));
            assert_eq!(head["result"]["id"], id.as_str(), "{head}");
            assert!(head["result"]["superseded_by"].is_null() && head["result"]["current_id"].is_null(), "{head}");
        }
        slotted["text"] = json!("The owner's next handoff");
        slotted["expected_head"] = json!(id);
        let updated = call(&f.state, &f.owner, "remember", slotted);
        assert_eq!(updated["ok"], true, "the genuine head still authorizes an owner update: {updated}");
        assert_eq!(call(&f.state, &f.owner, "get", json!({"id": slot}))["result"]["id"], updated["result"]["id"]);
    }
}
