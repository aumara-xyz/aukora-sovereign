// SPDX-License-Identifier: AGPL-3.0-or-later
//! PL-6: registrations survive serialized provisioning and interrupted credential saves.

use super::*;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let tag = hex(random32().unwrap().as_ref());
        let dir = std::env::temp_dir().join(format!("kira-registration-{}", &tag[..16]));
        State::open(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn builders() -> Vec<String> {
    vec!["builders".to_owned()]
}

#[test]
fn concurrent_register_keeps_every_successful_token() {
    let dir = Directory::new();
    let ready = std::sync::Barrier::new(4);
    let issued = std::thread::scope(|scope| {
        let mut jobs = Vec::new();
        for index in 0..4 {
            let path = &dir.0;
            let barrier = &ready;
            jobs.push(scope.spawn(move || {
                let name = format!("race{index}");
                barrier.wait();
                let token = register(path, &name, &builders(), false).unwrap();
                (name, token)
            }));
        }
        jobs.into_iter().map(|job| job.join().unwrap()).collect::<Vec<_>>()
    });
    let tokens = load_tokens(&dir.0).unwrap();
    assert_eq!(tokens.len(), 4);
    let mut state = State::open(&dir.0).unwrap();
    for (name, token) in issued {
        assert_eq!(tokens.get(&token_hash(&token)), Some(&name));
        assert_eq!(state.caller(&token).unwrap().name, name);
    }
}

#[test]
fn retry_register_completes_the_key_and_row_left_before_token_issue() {
    let dir = Directory::new();
    // Exactly the durable state after a crash between create_agent and issue_token.
    let state = State::open(&dir.0).unwrap();
    create_agent(&dir.0, &state.store, "race1", &builders(), false).unwrap();
    let key = fs::read(key_path(&dir.0, "race1")).unwrap();
    drop(state);
    let token = register(&dir.0, "race1", &builders(), false).unwrap();
    assert_eq!(fs::read(key_path(&dir.0, "race1")).unwrap(), key);
    assert_eq!(State::open(&dir.0).unwrap().caller(&token).unwrap().name, "race1");
    assert_eq!(register(&dir.0, "race1", &builders(), false), Err(refuse("agent-exists")));
}

#[test]
fn retry_register_completes_a_key_written_before_its_row() {
    let dir = Directory::new();
    write_private(&dir.0.join("register-race2.json"), br#"{"scopes":["builders"],"owner":false}"#, true).unwrap();
    let material = random32().unwrap();
    SecretKey::import(Zeroizing::new(*material)).unwrap();
    write_private(&key_path(&dir.0, "race2"), material.as_ref(), true).unwrap();
    let token = register(&dir.0, "race2", &builders(), false).unwrap();
    assert_eq!(fs::read(key_path(&dir.0, "race2")).unwrap(), material.as_ref());
    assert_eq!(State::open(&dir.0).unwrap().caller(&token).unwrap().name, "race2");
}

#[test]
fn retry_register_completes_after_a_refused_token_save() {
    let dir = Directory::new();
    fs::create_dir(dir.0.join("tokens.json.new")).unwrap();
    assert_eq!(register(&dir.0, "race3", &builders(), false), Err(refuse("state-write")));
    assert!(key_path(&dir.0, "race3").exists());
    fs::remove_dir(dir.0.join("tokens.json.new")).unwrap();
    let token = register(&dir.0, "race3", &builders(), false).unwrap();
    assert_eq!(State::open(&dir.0).unwrap().caller(&token).unwrap().name, "race3");
}

#[test]
fn interrupted_registration_cannot_change_privileges_or_revive_a_revoked_agent() {
    let dir = Directory::new();
    let state = State::open(&dir.0).unwrap();
    create_agent(&dir.0, &state.store, "race4", &builders(), false).unwrap();
    assert_eq!(register(&dir.0, "race4", &["*".to_owned()], false), Err(refuse("agent-exists")));
    assert_eq!(register(&dir.0, "race4", &builders(), true), Err(refuse("agent-exists")));
    state.store.revoke_agent("race4", now()).unwrap();
    assert_eq!(register(&dir.0, "race4", &builders(), false), Err(refuse("agent-exists")));
    assert!(load_tokens(&dir.0).unwrap().is_empty());
}

#[test]
fn cli_retry_recovers_an_interrupted_first_owner_without_an_owner_token() {
    let dir = Directory::new();
    let state = State::open(&dir.0).unwrap();
    create_agent(&dir.0, &state.store, "peter", &["*".to_owned()], true).unwrap();
    drop(state);
    let token_file = dir.0.join("owner.tok");
    cli(&[
        "register".into(), "peter".into(), "--owner".into(), "--state".into(), dir.0.clone().into_os_string(),
        "--token-file".into(), token_file.clone().into_os_string(),
    ]).unwrap();
    let token = fs::read_to_string(token_file).unwrap();
    assert!(State::open(&dir.0).unwrap().caller(token.trim()).unwrap().owner);
}

#[test]
fn key_without_a_row_or_durable_intent_cannot_acquire_unknown_privileges() {
    let dir = Directory::new();
    let material = random32().unwrap();
    write_private(&key_path(&dir.0, "orphan"), material.as_ref(), true).unwrap();
    assert_eq!(register(&dir.0, "orphan", &["*".to_owned()], true), Err(refuse("agent-exists")));
    assert!(load_tokens(&dir.0).unwrap().is_empty());
}

#[test]
fn key_only_intent_refuses_a_retry_with_different_privileges() {
    let dir = Directory::new();
    write_private(&dir.0.join("register-race2.json"), br#"{"scopes":["builders"],"owner":false}"#, true).unwrap();
    let material = random32().unwrap();
    write_private(&key_path(&dir.0, "race2"), material.as_ref(), true).unwrap();
    assert_eq!(register(&dir.0, "race2", &["*".to_owned()], true), Err(refuse("agent-exists")));
    assert!(load_tokens(&dir.0).unwrap().is_empty());
    assert!(register(&dir.0, "race2", &builders(), false).is_ok());
}

#[test]
fn first_owner_retry_replaces_an_unreturned_token_after_interruption() {
    let dir = Directory::new();
    authorization::PROBE.with(|probe| {
        *probe.borrow_mut() = Some(Box::new(|stage| {
            if stage == "token-issued" {
                panic!("interrupted after token save");
            }
        }));
    });
    let interrupted = std::panic::catch_unwind(|| register(&dir.0, "peter", &["*".to_owned()], true));
    authorization::PROBE.with(|probe| *probe.borrow_mut() = None);
    assert!(interrupted.is_err());
    let previous = load_tokens(&dir.0).unwrap();
    assert_eq!(previous.len(), 1);
    let token_file = dir.0.join("owner.tok");
    cli(&[
        "register".into(), "peter".into(), "--owner".into(), "--state".into(), dir.0.clone().into_os_string(),
        "--token-file".into(), token_file.clone().into_os_string(),
    ]).unwrap();
    let token = fs::read_to_string(token_file).unwrap();
    let current = load_tokens(&dir.0).unwrap();
    assert_eq!(current.len(), 1);
    assert!(previous.keys().all(|old| !current.contains_key(old)));
    assert!(State::open(&dir.0).unwrap().caller(token.trim()).unwrap().owner);
    assert!(!dir.0.join("register-peter.json").exists());
}

#[test]
fn importer_never_gains_a_token_through_registration_recovery() {
    let dir = Directory::new();
    let state = State::open(&dir.0).unwrap();
    create_agent(&dir.0, &state.store, IMPORT_AGENT, &["*".to_owned()], false).unwrap();
    assert_eq!(register(&dir.0, IMPORT_AGENT, &["*".to_owned()], false), Err(refuse("agent-takes-no-token")));
    assert!(load_tokens(&dir.0).unwrap().is_empty());
}

#[test]
fn refused_cli_token_delivery_keeps_first_owner_registration_recoverable() {
    let dir = Directory::new();
    let token_file = dir.0.join("not-created").join("owner.tok");
    let args = vec![
        "register".into(), "peter".into(), "--owner".into(), "--state".into(), dir.0.clone().into_os_string(),
        "--token-file".into(), token_file.clone().into_os_string(),
    ];
    assert_eq!(cli(&args), Err(refuse("state-write")));
    assert!(dir.0.join("register-peter.json").exists());
    assert!(!token_file.exists());
    let previous = load_tokens(&dir.0).unwrap();
    fs::create_dir(token_file.parent().unwrap()).unwrap();
    cli(&args).unwrap();
    let token = fs::read_to_string(token_file).unwrap();
    let current = load_tokens(&dir.0).unwrap();
    assert_eq!(current.len(), 1);
    assert!(previous.keys().all(|old| !current.contains_key(old)));
    assert!(State::open(&dir.0).unwrap().caller(token.trim()).unwrap().owner);
    assert!(!dir.0.join("register-peter.json").exists());
}
