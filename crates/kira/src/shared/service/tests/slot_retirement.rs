// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn advancing_a_slot_retires_its_history_and_retracting_it_never_resurrects_an_old_head() {
    for (slot, lane, token_name) in [("aukora:self", "self", "peter"), ("aukora:resume", "resume", "peter"), ("resume:claude", "experience", "claude")] {
        let f = fixture();
        let token = if token_name == "peter" { &f.owner } else { &f.claude };
        let write = |text: &str, expected: &str| {
            let mut n = note(text, "builders");
            (n["slot"], n["lane"], n["form"], n["capture"], n["expected_head"]) =
                (json!(slot), json!(lane), json!("snapshot"), json!(if token_name == "peter" { "owner-typed" } else { "model-generated" }), json!(expected));
            let reply = call(&f.state, token, "remember", n);
            assert_eq!(reply["ok"], true, "{reply}");
            reply["result"]["id"].as_str().unwrap().to_owned()
        };
        let h1 = write("Atlas slot history initial snapshot", "none");
        let h2 = write("Atlas slot history current snapshot", &h1);
        let old = call(&f.state, token, "get", json!({"id": h1}));
        assert_eq!(old["result"]["validity"], "superseded", "{slot}: {old}");
        assert_eq!(old["result"]["current_id"], h2.as_str());
        let recent = call(&f.state, token, "list_recent", json!({}));
        let history = recent["result"]["notes"].as_array().unwrap().iter().find(|n| n["id"] == h1.as_str()).unwrap();
        assert_eq!(history["validity"], "superseded", "{recent}");
        let recalled = call(&f.state, token, "recall", json!({"query": "atlas slot history"}));
        let live: Vec<_> = ids_of(&recalled).into_iter().filter(|(_, correction)| correction.is_null()).collect();
        assert_eq!(live, vec![(h2.clone(), Value::Null)], "{recalled}");
        assert_eq!(call(&f.state, token, "supersede", json!({"target": h2}))["ok"], true);
        assert_eq!(call(&f.state, token, "get", json!({"id": slot}))["error"], "kira:not-found", "a retracted head must leave {slot} empty");
        // The retirement is re-derived from the durable signed history after reopening, too.
        let reopened = Mutex::new(State::open(&f.dir).unwrap());
        assert_eq!(call(&reopened, token, "get", json!({"id": slot}))["error"], "kira:not-found");
        assert_eq!(call(&reopened, token, "get", json!({"id": h1}))["result"]["validity"], "superseded");
    }
}

/// A snapshot that a later snapshot retired cannot be corrected away from the slot: `get(slot)` and the history walk
/// of every earlier snapshot keep naming the same current note, through later snapshots too.
#[test]
fn a_retired_snapshot_cannot_be_corrected_away_from_the_slot_head() {
    let f = fixture();
    let write = |text: &str, expected: &str| {
        let mut n = note(text, "builders");
        (n["slot"], n["lane"], n["form"], n["capture"], n["expected_head"]) =
            (json!("aukora:self"), json!("self"), json!("snapshot"), json!("owner-typed"), json!(expected));
        let reply = call(&f.state, &f.owner, "remember", n);
        assert_eq!(reply["ok"], true, "{reply}");
        reply["result"]["id"].as_str().unwrap().to_owned()
    };
    let a = write("Atlas self snapshot one", "none");
    let b = write("Atlas self snapshot two", &a);
    let other = call(&f.state, &f.owner, "remember", note("Atlas unrelated replacement note", "builders"));
    let r = other["result"]["id"].as_str().unwrap().to_owned();
    let refused = call(&f.state, &f.owner, "supersede", json!({"target": a, "expected_current": b, "replacement": r}));
    assert_eq!(refused["error"], "kira:supersede-stale", "{refused}");
    // Even a correction recorded directly, past the service's check, does not move the old snapshot's walk.
    {
        let mut state = f.state.lock().unwrap();
        let tags = vec![vec!["supersedes".to_owned(), a.clone()], vec!["expected_current".to_owned(), b.clone()],
            vec!["replacement".to_owned(), r.clone()]];
        let event = Event::sign(state.key("peter").unwrap(), now(), SUPERSEDE_KIND, tags, String::new()).unwrap();
        state.store.record(event).unwrap();
    }
    let agree = |head: &str| {
        assert_eq!(call(&f.state, &f.owner, "get", json!({"id": "aukora:self"}))["result"]["id"], head);
        assert_eq!(call(&f.state, &f.owner, "get", json!({"id": a}))["result"]["current_id"], head);
    };
    agree(&b);
    let c = write("Atlas self snapshot three", &b);
    agree(&c);
    assert_eq!(call(&f.state, &f.owner, "get", json!({"id": b}))["result"]["current_id"], c.as_str());
}
