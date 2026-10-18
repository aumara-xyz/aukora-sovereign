// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn concurrent_supersedes_of_one_live_target_have_only_one_winner() {
    let f = fixture();
    let target = remember_id(&f, &f.claude, "Atlas concurrency original claim");
    let replacements: Vec<_> = ["first", "second", "third"].into_iter()
        .map(|word| remember_id(&f, &f.claude, &format!("Atlas concurrency {word} replacement"))).collect();
    let barrier = std::sync::Barrier::new(replacements.len());
    // Independent State handles also exercise the existing cross-process requests.lock, rather than only Mutex.
    let states: Vec<_> = replacements.iter().map(|_| Mutex::new(State::open(&f.dir).unwrap())).collect();
    let replies = std::thread::scope(|scope| {
        let jobs: Vec<_> = states.iter().zip(&replacements).map(|(state, replacement)| {
            let (barrier, token, target) = (&barrier, &f.claude, &target);
            scope.spawn(move || {
                barrier.wait();
                call(state, token, "supersede", json!({"target": target, "replacement": replacement}))
            })
        }).collect();
        jobs.into_iter().map(|job| job.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(replies.iter().filter(|reply| reply["ok"] == true).count(), 1, "{replies:?}");
    assert_eq!(replies.iter().filter(|reply| reply["error"] == "kira:supersede-stale").count(), 2, "{replies:?}");
    let current = call(&f.state, &f.claude, "get", json!({"id": target}))["result"]["current_id"].clone();
    for replacement in replacements {
        let state = call(&f.state, &f.claude, "get", json!({"id": replacement}))["result"]["state"].clone();
        assert_eq!(state == "resolved", json!(replacement) == current);
    }
}

#[test]
fn historical_overwritten_and_retracted_replacements_are_not_resolved() {
    let f = fixture();
    let target = remember_id(&f, &f.claude, "Atlas historical original claim");
    let first = remember_id(&f, &f.claude, "Atlas historical first replacement");
    let second = remember_id(&f, &f.claude, "Atlas historical second replacement");
    let correct = |replacement: Option<&str>, at| {
        let mut s = lock(&f.state);
        let mut tags = vec![vec!["supersedes".to_owned(), target.clone()]];
        if let Some(replacement) = replacement {
            tags.push(vec!["replacement".to_owned(), replacement.to_owned()]);
        }
        let event = Event::sign(s.key("claude").unwrap(), at, SUPERSEDE_KIND, tags, String::new()).unwrap();
        s.store.record(event).unwrap();
    };
    // A persisted pre-fix history can contain several authorized corrections of the same original target.
    correct(Some(&first), 1);
    correct(Some(&second), 2);
    let state = |id: &str| call(&f.state, &f.claude, "get", json!({"id": id}))["result"]["state"].clone();
    assert_ne!(state(&first), "resolved");
    assert_eq!(state(&second), "resolved");
    correct(None, 3);
    assert_ne!(state(&first), "resolved");
    assert_ne!(state(&second), "resolved");
}

#[test]
fn an_explicit_current_head_allows_one_override_and_retraction_without_retiring_independent_replacements() {
    let f = fixture();
    let target = remember_id(&f, &f.claude, "Atlas optimistic original claim");
    let first = remember_id(&f, &f.claude, "Atlas optimistic first replacement");
    let second = remember_id(&f, &f.claude, "Atlas optimistic second replacement");
    let initial = call(&f.state, &f.claude, "supersede", json!({"target": target, "replacement": first}));
    let expected = initial["result"]["event"].clone();
    assert!(expected.is_string(), "{initial}");
    assert_eq!(call(&f.state, &f.claude, "supersede", json!({"target": target, "replacement": second}))["error"], "kira:supersede-stale");
    let updated = call(&f.state, &f.claude, "supersede", json!({"target": target, "replacement": second, "expected_current": expected}));
    assert_eq!(updated["ok"], true, "{updated}");
    assert_eq!(call(&f.state, &f.claude, "supersede", json!({"target": target, "expected_current": expected}))["error"], "kira:supersede-stale");
    let retracted = call(&f.state, &f.claude, "supersede", json!({"target": target, "expected_current": updated["result"]["event"]}));
    assert_eq!(retracted["ok"], true, "{retracted}");
    for id in [first, second] {
        let note = call(&f.state, &f.claude, "get", json!({"id": id}));
        assert_ne!(note["result"]["state"], "resolved");
        assert!(note["result"]["superseded_by"].is_null(), "the correction only targets its original note: {note}");
    }
}

#[test]
fn accepting_a_proposal_checks_the_same_head_as_a_direct_correction() {
    let f = fixture();
    let target = remember_id(&f, &f.claude, "Atlas accepted original claim");
    let own = remember_id(&f, &f.claude, "Atlas accepted author replacement");
    let offered = remember_id(&f, &f.grok, "Atlas accepted reviewer replacement");
    let proposal = call(&f.state, &f.grok, "supersede", json!({"target": target, "replacement": offered}))["result"]["event"].clone();
    let changed = call(&f.state, &f.claude, "supersede", json!({"target": target, "replacement": own}));
    assert_eq!(changed["ok"], true, "{changed}");
    assert_eq!(call(&f.state, &f.claude, "accept_correction", json!({"proposal": proposal}))["error"], "kira:supersede-stale");
    let accepted = call(&f.state, &f.claude, "accept_correction", json!({"proposal": proposal, "expected_current": changed["result"]["event"]}));
    assert_eq!(accepted["ok"], true, "{accepted}");
    assert_eq!(accepted["result"]["target"]["current_id"], offered.as_str());
    assert_ne!(call(&f.state, &f.claude, "get", json!({"id": own}))["result"]["state"], "resolved");
}
