// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn pl5_refused_writes_leave_the_durable_quota_for_valid_writes() {
    let f = fixture();
    for i in 0..RATE_WRITES + 3 {
        let mut invalid = note(&format!("refused scope {i}"), "builders");
        invalid["scope"] = json!("auma");
        assert_eq!(call(&f.state, &f.claude, "remember", invalid)["error"], "kira:scope-refused");
    }
    // Reopening cannot conceal a charge for a refused write.
    let restarted = Mutex::new(State::open(&f.dir).unwrap());
    for i in 0..RATE_WRITES {
        let result = call(&restarted, &f.claude, "remember", note(&format!("valid write {i}"), "builders"));
        assert_eq!(result["ok"], true, "{result}");
    }
    assert_eq!(call(&restarted, &f.claude, "remember", note("over quota", "builders"))["error"], "kira:rate-limited");
}

#[test]
fn pl5_same_second_slot_revert_has_a_distinct_identity() {
    // Retry only if the wall clock crosses a second during the three writes.
    for _ in 0..4 {
        let f = fixture();
        let at = now();
        let mut head = json!("none");
        let mut ids = Vec::new();
        let mut results = Vec::new();
        for text in ["resume text A", "resume text B", "resume text A"] {
            let mut params = note(text, "builders");
            params["slot"] = json!("resume:claude");
            params["expected_head"] = head;
            let result = call(&f.state, &f.claude, "remember", params);
            head = result["result"]["id"].clone();
            ids.push(head.clone());
            results.push(result);
        }
        if now() != at { continue; }
        for result in results { assert_eq!(result["ok"], true, "{result}"); }
        assert_ne!(ids[0], ids[2]);
        // Replaying identical signed bytes remains a genuine duplicate.
        let mut state = lock(&f.state);
        let event = state.store.get(ids[2].as_str().unwrap()).unwrap().unwrap().event;
        assert_eq!(state.store.append(event.verify().unwrap()).unwrap_err(), refuse("note-duplicate"));
        return;
    }
    panic!("could not run three writes within one second");
}

#[test]
fn pl5_a_committed_write_with_a_failed_response_keeps_its_reservation() {
    let f = fixture();
    let mut state = lock(&f.state);
    let _authorization = request_guard(&f.dir).unwrap();
    let caller = state.caller(&f.claude).unwrap();
    let result: Result<()> = state.signed(&caller, |s| {
        let draft: RememberParams = parse(note("committed but response lost", "builders")).unwrap();
        let tags = NoteDraft {
            text: draft.text.clone(), subject: draft.subject, scope: draft.scope, lane: Lane::Evidence,
            form: Form::Fact, privacy: Privacy::Builders, capture: Capture::ModelGenerated, sources: vec![],
            slot: None, valid_from: None, valid_to: None, epoch: 2,
        }.tags(Review::Remembered)?;
        let event = Event::sign(s.key("claude")?, now(), NOTE_KIND, tags, draft.text)?;
        s.store.append(event)?;
        Err(refuse("store-sql"))
    });
    assert_eq!(result, Err(refuse("store-sql")));
    let budget: Value = serde_json::from_slice(&fs::read(f.dir.join("write-rate.json")).unwrap()).unwrap();
    assert_eq!(budget["writes"]["claude"].as_array().unwrap().len(), 1);
}
