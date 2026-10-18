// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
const FILE: &str = "write-rate.json";

#[test]
fn a_restart_keeps_each_agents_unexpired_signatures() {
    let f = fixture();
    // Exercise actual signing, not just serialization of the rate structure.
    for i in 0..RATE_WRITES - 1 {
        assert_eq!(call(&f.state, &f.claude, "remember", note(&format!("before restart {i}"), "builders"))["ok"], true);
    }
    let restarted = Mutex::new(State::open(&f.dir).unwrap());
    assert_eq!(call(&restarted, &f.claude, "remember", note("last allowed signature", "builders"))["ok"], true);
    let restarted = Mutex::new(State::open(&f.dir).unwrap());
    assert_eq!(call(&restarted, &f.claude, "remember", note("over budget after restart", "builders"))["error"], "kira:rate-limited");
    assert_eq!(call(&restarted, &f.grok, "remember", note("a different agents budget", "builders"))["ok"], true);
    assert_eq!(fs::metadata(f.dir.join(FILE)).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn a_failed_durable_reservation_cannot_sign() {
    let f = fixture();
    fs::create_dir(f.dir.join("write-rate.json.new")).unwrap();
    let reply = call(&f.state, &f.claude, "remember", note("must never be signed", "builders"));
    assert_eq!(reply["error"], "kira:state-write");
    assert!(lock(&f.state).store.list_recent(10, None, Some(2)).unwrap().is_empty());
}
