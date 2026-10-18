// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use rustix::fs::{flock, FlockOperation};

#[test]
fn authorization_guard_is_owner_only_and_serializes_independent_file_descriptions() {
    let f = fixture();
    let guard = request_guard(&f.dir).unwrap();
    let path = f.dir.join("requests.lock");
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    // An independent open has the same exclusion as a separate CLI process, unlike an in-process mutex.
    let other = fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    assert_eq!(flock(&other, FlockOperation::NonBlockingLockExclusive), Err(rustix::io::Errno::WOULDBLOCK));
    drop(guard);
    flock(&other, FlockOperation::NonBlockingLockExclusive).unwrap();
    drop(other);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(request_guard(&f.dir).err(), Some(refuse("request-lock-mode")));
}

#[test]
fn revocation_holds_the_request_guard_until_its_store_update_and_token_save_finish() {
    let f = fixture();
    // A private token-file directory makes save_tokens fail after the agent row has changed. The operation still
    // releases its guard on error, and the old cached token cannot authenticate against the revoked row.
    let old_tokens = fs::read(f.dir.join(TOKENS)).unwrap();
    fs::create_dir(f.dir.join("tokens.json.new")).unwrap();
    assert_eq!(revoke(&f.dir, "claude"), Err(refuse("state-write")));
    assert_eq!(fs::read(f.dir.join(TOKENS)).unwrap(), old_tokens);
    let reply = call(&f.state, &f.claude, "whoami", json!({}));
    assert_eq!(reply["error"], "kira:agent-revoked", "{reply}");
    request_guard(&f.dir).unwrap();
}

#[test]
fn a_caller_admitted_before_revocation_cannot_start_a_later_recall_phase() {
    let f = fixture();
    let caller = lock(&f.state).caller(&f.claude).unwrap();
    let (prepared, _) = recall_gather(&f.state, &caller, parse(json!({"query": "where is the lamp"})).unwrap()).unwrap();
    // This is a separately opened store, as used by the revoke CLI. Leave tokens.json untouched deliberately:
    // checking only the token map would still admit this caller.
    let side = State::open(&f.dir).unwrap();
    let _authorization = request_guard(&f.dir).unwrap();
    side.store.revoke_agent("claude", now()).unwrap();
    drop(_authorization);
    assert_eq!(recall_gather(&f.state, &caller, parse(json!({"query": "where is the lamp"})).unwrap()).err(), Some(refuse("agent-revoked")));
    assert_eq!(recall_answer(&f.state, &caller, &prepared.finish(None)).err(), Some(refuse("agent-revoked")));
}

struct RevokeOnEmbed {
    dir: PathBuf,
}

impl Embedder for RevokeOnEmbed {
    fn model_id(&self) -> &str {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        // Models run outside both locks: a revoke can complete here, before candidates are gathered.
        revoke(&self.dir, "claude")?;
        Ok(texts.iter().map(|_| vec![1.0, 0.0]).collect())
    }
}

#[test]
fn revocation_during_embedding_is_checked_before_gathering_candidates() {
    let f = fixture();
    lock(&f.state).embedder = Some(Arc::new(RevokeOnEmbed { dir: f.dir.clone() }));
    let reply = call(&f.state, &f.claude, "recall", json!({"query": "where is the lamp"}));
    assert_eq!(reply["error"], "kira:agent-revoked", "{reply}");
}

#[test]
fn recall_gather_refreshes_the_scopes_of_an_already_admitted_caller() {
    let f = fixture();
    let caller = lock(&f.state).caller(&f.claude).unwrap();
    let side = rusqlite::Connection::open(f.dir.join(DB)).unwrap();
    side.execute("UPDATE agents SET scopes = '[\"another-scope\"]', owner = 0 WHERE name = 'claude'", []).unwrap();
    let result = recall_gather(&f.state, &caller, parse(json!({"query": "where is the lamp", "scopes": ["builders"]})).unwrap());
    assert_eq!(result.err(), Some(refuse("scope-refused")));
}

#[test]
fn separate_service_states_share_one_durable_write_budget_under_the_request_guard() {
    let f = fixture();
    let first = Mutex::new(State::open(&f.dir).unwrap());
    let second = Mutex::new(State::open(&f.dir).unwrap());
    let ready = std::sync::Barrier::new(2);
    let write_half = |state: &Mutex<State>, side: &str| {
        ready.wait();
        for index in 0..RATE_WRITES / 2 {
            let reply = call(state, &f.claude, "remember", note(&format!("Concurrent budget {side} write {index}"), "builders"));
            assert_eq!(reply["ok"], true, "{reply}");
        }
    };
    std::thread::scope(|scope| {
        let a = scope.spawn(|| write_half(&first, "first"));
        let b = scope.spawn(|| write_half(&second, "second"));
        a.join().unwrap();
        b.join().unwrap();
    });
    let reply = call(&f.state, &f.claude, "remember", note("The shared budget is full", "builders"));
    assert_eq!(reply["error"], "kira:rate-limited", "{reply}");
}
