// SPDX-License-Identifier: AGPL-3.0-or-later
//! Slots are prompt input: neither a direct web claim nor inherited web capture belongs in one.

use super::*;

#[test]
fn web_derived_slot_writes_are_refused_before_they_can_become_prompt_input() {
    let f = fixture();
    let mut web = note("The titanium manifold operates at 420 kelvin", "builders");
    web["capture"] = json!("web-derived");
    let source = call(&f.state, &f.claude, "remember", web);
    assert_eq!(source["ok"], true, "{source}");
    // A non-web claim citing that source is web-derived too, including when cited through another note.
    let mut derived = note("The manifold temperature follows the manual", "builders");
    derived["sources"] = json!([source["result"]["id"]]);
    let derived = call(&f.state, &f.claude, "remember", derived);
    assert_eq!(derived["result"]["capture"], "web-derived", "{derived}");
    for (slot, token) in [("aukora:self", &f.owner), ("aukora:resume", &f.owner), ("resume:claude", &f.claude)] {
        for source in [None, Some(&source["result"]["id"]), Some(&derived["result"]["id"])] {
            let mut handoff = note("Resume from the manifold finding", "builders");
            handoff["lane"] = json!("finding");
            handoff["slot"] = json!(slot);
            handoff["expected_head"] = json!("none");
            handoff["capture"] = json!(if source.is_some() { "model-generated" } else { "web-derived" });
            if let Some(source) = source {
                handoff["sources"] = json!([source]);
            }
            let refused = call(&f.state, token, "remember", handoff);
            assert_eq!(refused["error"], "kira:note-slot-web-derived", "{slot}: {refused}");
            assert_eq!(call(&f.state, &f.owner, "get", json!({"id": slot}))["error"], "kira:not-found");
        }
    }
}

#[test]
fn non_web_slots_keep_owner_self_and_agent_handoffs_working() {
    let f = fixture();
    for (slot, lane, capture, token) in [
        ("aukora:self", "self", "owner-typed", &f.owner),
        ("aukora:resume", "resume", "owner-typed", &f.owner),
        ("resume:claude", "experience", "model-generated", &f.claude),
    ] {
        let mut n = note("A clean session handoff", "builders");
        (n["slot"], n["lane"], n["capture"], n["expected_head"]) = (json!(slot), json!(lane), json!(capture), json!("none"));
        let written = call(&f.state, token, "remember", n);
        assert_eq!(written["ok"], true, "{written}");
        assert_eq!(call(&f.state, token, "get", json!({"id": slot}))["result"]["id"], written["result"]["id"]);
    }
}
