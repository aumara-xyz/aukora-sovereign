// SPDX-License-Identifier: AGPL-3.0-or-later
//! The standing grants' tests (moved out of standing.rs under the 1000-line rule).

use super::*;
use laya::grant::{DoorGrant, DAY_MS as GRANT_DAY};
use std::path::PathBuf;
use std::sync::Arc;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aukora-door-standing-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_private(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn grant_file(dir: &Path, class: CrossingClass, scope: &[&str], per_day: u32) -> (PathBuf, canon::digest::Digest32) {
    let now = now_ms();
    let grant = DoorGrant {
        class,
        scope: scope.iter().map(|s| (*s).to_owned()).collect(),
        per_day,
        not_before: now - 1_000,
        expires_at: now + GRANT_DAY,
        nonce: canon::ids::ProposalId::from_bytes([9; 16]),
    };
    let id = grant.id().unwrap();
    let path = dir.join("grants.json");
    write_private(&path, &GrantSet::default().with_grant(grant).unwrap().canonical_bytes().unwrap());
    (path, id)
}

fn open_standing(dir: &Path, grants: Option<PathBuf>, policy: Option<PathBuf>) -> Standing {
    Standing::open(&StandingFiles { policy, grants }, dir).unwrap()
}

fn read_crossing() -> Crossing {
    Crossing::new(CrossingClass::Memory, "read")
}

#[test]
fn nothing_clears_without_a_grant_even_at_only_risky_things() {
    let dir = temp("nogrant");
    let standing = open_standing(&dir, None, None);
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_grant_clears_until_its_daily_count_is_spent_and_a_restart_gives_nothing_back() {
    let dir = temp("grant");
    let (grants, _) = grant_file(&dir, CrossingClass::Memory, &["read"], 2);
    let first = open_standing(&dir, Some(grants.clone()), None);
    let now = now_ms();
    assert!(matches!(first.settle(&read_crossing(), now, || Ok(())), Settled::Clear));
    assert!(matches!(first.settle(&read_crossing(), now, || Ok(())), Settled::Clear));
    assert!(matches!(first.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap().lines().count(), 2);
    drop(first);
    let again = open_standing(&dir, Some(grants), None);
    assert!(matches!(again.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

fn policy_file(dir: &Path, setting: SliderSetting) -> PathBuf {
    let mut policy = slider::starter().unwrap();
    policy.setting = setting;
    let path = dir.join("slider.json");
    write_private(&path, &policy.canonical_bytes().unwrap());
    path
}

fn request(tool: &str, args: &str, class: &str) -> Request {
    super::super::wire::parse_request(&super::super::wire::test_line("c-1", tool, args, class)).unwrap()
}

#[test]
fn only_a_bare_read_of_auma_s_own_slot_skips_the_slider() {
    assert!(own_slot_read(Class::Memory, &request("kira_get", "{\"id\":\"aukora:self\"}", "memory")));
    assert!(own_slot_read(Class::Memory, &request("kira_get", "{\"id\":\"aukora:resume\"}", "memory")));
    for (tool, args) in [
        ("kira_get", "{\"id\":\"resume:grok\"}"),
        ("kira_get", "{\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}"),
        ("kira_get", "{\"id\":\"aukora:self\",\"x\":1}"),
        ("kira_get", "{\"id\":[\"aukora:self\"]}"),
        ("kira_recall", "{\"query\":\"aukora:self\"}"),
        ("kira_remember", "{\"id\":\"aukora:self\"}"),
    ] {
        assert!(!own_slot_read(Class::Memory, &request(tool, args, "memory")), "{tool} {args}");
    }
    assert!(!own_slot_read(Class::Net, &request("kira_get", "{\"id\":\"aukora:self\"}", "net")));
}

#[test]
fn the_token_the_slider_sees_is_the_one_the_executor_will_use() {
    // Net: the host, lowercased, from the same URL parse the executor uses.
    let net = crossing_of(Class::Net, &request("web_fetch", "{\"url\":\"https://Docs.RS/x\"}", "net")).unwrap();
    assert_eq!((net.class, net.token.as_str()), (CrossingClass::Net, "docs.rs"));
    assert!(crossing_of(Class::Net, &request("web_search", "{\"query\":\"x\"}", "net")).is_none());
    // Memory: reads are `read`, writes name their lane, a tool the door does not forward has no token.
    let read = crossing_of(Class::Memory, &request("kira_recall", "{\"query\":\"x\"}", "memory")).unwrap();
    assert_eq!(read.token, "read");
    let write = crossing_of(Class::Memory, &request("kira_remember", "{\"lane\":\"notes\"}", "memory")).unwrap();
    assert_eq!(write.token, "write:notes");
    assert!(crossing_of(Class::Memory, &request("kira_quarantine_source", "{}", "memory")).is_none());
    // Outside the workspace: one path, however many of the seven argument names carry it; two different paths (or one
    // that is not text) have no single token, so the call asks instead of being graded by the first one found.
    let one = |args: &str| crossing_of(Class::FsOutside, &request("read", args, "fs-outside")).map(|c| c.token);
    assert_eq!(one("{\"file_path\":\"/srv/shared/x\"}").as_deref(), Some("/srv/shared/x"));
    assert_eq!(one("{\"file_path\":\"/srv/shared/x\",\"path\":\"/srv/shared/x\"}").as_deref(), Some("/srv/shared/x"));
    assert_eq!(one("{\"file_path\":\"/srv/shared/x\",\"path\":\"/etc/shadow\"}"), None);
    assert_eq!(one("{\"paths\":[\"/srv/shared/x\",\"/etc/shadow\"]}"), None);
    assert_eq!(one("{\"cwd\":\"/srv/shared/x\",\"paths\":[\"/srv/shared/x\"]}").as_deref(), Some("/srv/shared/x"));
    assert_eq!(one("{\"file_path\":7}"), None);
    assert_eq!(one("{}"), None);
}

#[test]
fn trusted_clears_inside_a_live_grant_with_no_count_and_only_there() {
    let dir = temp("trusted");
    let (grants, id) = grant_file(&dir, CrossingClass::Memory, &["read"], 2);
    let standing = open_standing(&dir, Some(grants.clone()), Some(policy_file(&dir, SliderSetting::Trusted)));
    let now = now_ms();
    // The grant says two a day; trusted does not count, so ten clear, and each is logged against the grant.
    for _ in 0..10 {
        assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Clear));
    }
    let log = std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 10);
    assert!(log.lines().all(|line| line.contains(&id.to_string())));
    // No grant for the lane: the setting grants nothing by itself.
    assert!(matches!(standing.settle(&Crossing::new(CrossingClass::Memory, "write:notes"), now, || Ok(())), Settled::Ask));
    // The same grant under "limits" runs out after two.
    let limits = temp("trusted-control");
    let (grants, _) = grant_file(&limits, CrossingClass::Memory, &["read"], 2);
    let control = open_standing(&limits, Some(grants), Some(policy_file(&limits, SliderSetting::WithinTodayLimits)));
    let results: Vec<_> = (0..4).map(|_| matches!(control.settle(&read_crossing(), now, || Ok(())), Settled::Clear)).collect();
    assert_eq!(results, [true, true, false, false]);
    // Plugin crossings never clear, under trusted either.
    assert!(matches!(standing.settle(&Crossing::new(CrossingClass::Plugin, "x@y"), now, || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(limits);
}

#[test]
fn a_trusted_clear_still_stops_when_the_grant_is_revoked_or_the_door_would_refuse() {
    let dir = temp("trusted-stop");
    let (grants, id) = grant_file(&dir, CrossingClass::Memory, &["read"], 1);
    let standing = open_standing(&dir, Some(grants.clone()), Some(policy_file(&dir, SliderSetting::Trusted)));
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Err("lane-closed".to_owned())), Settled::Refuse(_)));
    assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap(), "");
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Clear));
    let mut set = GrantSet::parse(&std::fs::read(&grants).unwrap()).unwrap();
    assert!(set.revoke(id).is_ok());
    std::fs::remove_file(&grants).unwrap();
    write_private(&grants, &set.canonical_bytes().unwrap());
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_clock_that_steps_back_cannot_revive_an_expired_grant_or_reset_the_day() {
    let dir = temp("clock");
    let now = now_ms();
    // A grant that expires one minute from now.
    let grant = DoorGrant {
        class: CrossingClass::Memory,
        scope: vec!["read".to_owned()],
        per_day: 5,
        not_before: now - 1_000,
        expires_at: now + 60_000,
        nonce: canon::ids::ProposalId::from_bytes([9; 16]),
    };
    let path = dir.join("grants.json");
    write_private(&path, &GrantSet::default().with_grant(grant).unwrap().canonical_bytes().unwrap());
    let standing = open_standing(&dir, Some(path), Some(policy_file(&dir, SliderSetting::Trusted)));
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Clear));
    // Past the expiry, nothing clears; stepping the clock back to before it changes nothing.
    assert!(matches!(standing.settle(&read_crossing(), now + 120_000, || Ok(())), Settled::Ask));
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_new_day_starts_the_log_afresh() {
    let dir = temp("newday");
    // Fixed times, so the day turn is certain: day 40 at one second past midnight, and a grant live for three days.
    let day = |n: i64| n * DAY_MS + 1_000;
    let grant = DoorGrant {
        class: CrossingClass::Memory,
        scope: vec!["read".to_owned()],
        per_day: 5,
        not_before: day(40) - 1_000,
        expires_at: day(40) + 3 * DAY_MS,
        nonce: canon::ids::ProposalId::from_bytes([9; 16]),
    };
    let path = dir.join("grants.json");
    write_private(&path, &GrantSet::default().with_grant(grant).unwrap().canonical_bytes().unwrap());
    let standing = open_standing(&dir, Some(path), Some(policy_file(&dir, SliderSetting::Trusted)));
    for _ in 0..3 {
        assert!(matches!(standing.settle(&read_crossing(), day(40), || Ok(())), Settled::Clear));
    }
    assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap().lines().count(), 3);
    // Tomorrow the grant is still live and the log holds only tomorrow's line.
    assert!(matches!(standing.settle(&read_crossing(), day(41), || Ok(())), Settled::Clear));
    let log = std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 1, "{log}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn on_the_node_the_grants_are_the_gate_targets_applied_bytes_and_nothing_else() {
    let dir = temp("source");
    // A grants file is ignored once the gate is the source: only owner-applied bytes count.
    let (file, _) = grant_file(&dir, CrossingClass::Memory, &["read"], 5);
    let mut standing = open_standing(&dir, Some(file), None);
    let applied: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let source = applied.clone();
    standing.grants_from(Box::new(move || source.lock().unwrap().clone()));
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask), "nothing applied yet");
    let other = temp("source-bytes");
    let (bytes, _) = grant_file(&other, CrossingClass::Memory, &["read"], 5);
    *applied.lock().unwrap() = Some(std::fs::read(bytes).unwrap());
    *standing.from_source.lock().unwrap() = None;
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Clear));
    // Bytes that are not a grant set are no grants.
    *applied.lock().unwrap() = Some(b"{}".to_vec());
    *standing.from_source.lock().unwrap() = None;
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(other);
}

#[test]
fn a_slow_preflight_holds_no_lock_and_the_grant_is_judged_again_after_it() {
    use std::sync::mpsc::{channel, RecvTimeoutError};
    use std::time::Duration;
    let dir = temp("slow-preflight");
    let (file, _) = grant_file(&dir, CrossingClass::Memory, &["read"], 1);
    let standing = std::sync::Arc::new(open_standing(&dir, Some(file), None));
    let (in_preflight, entered) = channel::<()>();
    let (release, released) = channel::<()>();
    let slow = {
        let standing = standing.clone();
        std::thread::spawn(move || {
            standing.settle(&read_crossing(), now_ms(), || {
                in_preflight.send(()).unwrap();
                // A lock held across this wait would stall the other call below for the whole of it.
                match released.recv_timeout(Duration::from_secs(10)) {
                    Ok(()) => Ok(()),
                    Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Err("preflight-never-released".into()),
                }
            })
        })
    };
    entered.recv_timeout(Duration::from_secs(10)).unwrap();
    // While the first call is inside its check, another call settles at once and spends the grant's one use.
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Clear), "not stalled by the slow check");
    release.send(()).unwrap();
    // The slow call then finds the grant spent: it asks, and nothing is cleared twice.
    assert!(matches!(slow.join().unwrap(), Settled::Ask));
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_revoke_takes_effect_on_the_next_call() {
    let dir = temp("revoke");
    let (grants, id) = grant_file(&dir, CrossingClass::Memory, &["read"], 5);
    let standing = open_standing(&dir, Some(grants.clone()), None);
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Clear));
    let mut set = GrantSet::parse(&std::fs::read(&grants).unwrap()).unwrap();
    assert!(set.revoke(id).is_ok());
    std::fs::remove_file(&grants).unwrap();
    write_private(&grants, &set.canonical_bytes().unwrap());
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_call_the_door_would_refuse_spends_nothing_and_is_not_asked_about() {
    let dir = temp("preflight");
    let (grants, _) = grant_file(&dir, CrossingClass::Memory, &["read"], 5);
    let standing = open_standing(&dir, Some(grants), None);
    let refused = standing.settle(&read_crossing(), now_ms(), || Err("lane-closed".to_owned()));
    assert!(matches!(refused, Settled::Refuse(code) if code == "lane-closed"));
    assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap(), "");
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Clear));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unreadable_or_loose_grants_file_fails_closed() {
    let dir = temp("loose");
    let (grants, _) = grant_file(&dir, CrossingClass::Memory, &["read"], 5);
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&grants, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    let standing = open_standing(&dir, Some(grants), None);
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_policy_file_that_asks_for_everything_wins_over_a_perfect_grant() {
    let dir = temp("ask");
    let (grants, _) = grant_file(&dir, CrossingClass::Memory, &["read"], 5);
    let mut policy = slider::starter().unwrap();
    policy.setting = SliderSetting::AskEverything;
    let path = dir.join("slider.json");
    write_private(&path, &policy.canonical_bytes().unwrap());
    let standing = open_standing(&dir, Some(grants), Some(path.clone()));
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    // A broken policy file is "ask for everything", never the looser starter.
    write_private(&path, b"{}");
    let broken = temp("ask-broken");
    let (grants, _) = grant_file(&broken, CrossingClass::Memory, &["read"], 5);
    let standing = open_standing(&broken, Some(grants), Some(path));
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(broken);
}

fn count_line(at: i64, grant: &canon::digest::Digest32) -> String {
    format!("{}\n", serde_json::json!({"at_ms": at, "class": "memory", "grant": grant.to_string()}))
}

#[test]
fn old_days_are_dropped_when_the_log_is_opened() {
    let dir = temp("compact");
    let id = canon::digest::Digest32::sha256(b"g");
    let old = now_ms() - 3 * DAY_MS;
    let today = now_ms();
    write_private(&dir.join("autoclear.jsonl"), format!("{}{}", count_line(old, &id), count_line(today, &id)).as_bytes());
    let _standing = open_standing(&dir, None, None);
    assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap(), count_line(today, &id));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_line_that_cannot_be_read_is_never_skipped_it_spends_the_day() {
    // The review's scenario: a torn append, then a good one glued onto it. The glued line parses as nothing, and the
    // count it carried was an executed clear. Opening must not shrug it off: nothing auto-clears for the rest of the
    // day, however many the grant still allows, and a second restart does not forget.
    let dir = temp("unreadable");
    let (grants, id) = grant_file(&dir, CrossingClass::Memory, &["read"], 5);
    let now = now_ms();
    let glued = format!("{{\"at_ms\":{now},\"class\":\"mem{}", count_line(now, &id));
    write_private(&dir.join("autoclear.jsonl"), format!("{}{glued}", count_line(now, &id)).as_bytes());
    let standing = open_standing(&dir, Some(grants.clone()), None);
    assert!(matches!(standing.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    // The unreadable line is gone from the file, replaced by a line that says so, and the readable count stays.
    let log = std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 2, "{log}");
    assert_eq!(log.lines().next().unwrap(), count_line(now, &id).trim_end());
    assert!(log.lines().nth(1).unwrap().contains("\"void\""), "{log}");
    drop(standing);
    let again = open_standing(&dir, Some(grants.clone()), None);
    assert!(matches!(again.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap(), log, "a second restart rewrites nothing");
    // A torn last line (a crash mid-append) is the same: it may have been a count.
    let torn = temp("unreadable-torn");
    let (grants, id) = grant_file(&torn, CrossingClass::Memory, &["read"], 5);
    write_private(&torn.join("autoclear.jsonl"), format!("{}{{\"at_ms\":", count_line(now, &id)).as_bytes());
    let after_crash = open_standing(&torn, Some(grants), None);
    assert!(matches!(after_crash.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let log = std::fs::read_to_string(torn.join("autoclear.jsonl")).unwrap();
    assert!(log.lines().all(|line| parse_event(line).is_some()), "{log}");
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(torn);
}

#[test]
fn a_void_day_ends_with_the_day() {
    let dir = temp("void-day");
    let day = |n: i64| n * DAY_MS + 1_000;
    let grant = DoorGrant {
        class: CrossingClass::Memory,
        scope: vec!["read".to_owned()],
        per_day: 5,
        not_before: day(40) - 1_000,
        expires_at: day(40) + 3 * DAY_MS,
        nonce: canon::ids::ProposalId::from_bytes([9; 16]),
    };
    let path = dir.join("grants.json");
    write_private(&path, &GrantSet::default().with_grant(grant).unwrap().canonical_bytes().unwrap());
    let standing = open_standing(&dir, Some(path), None);
    // Force a void through "day 40" as an unreadable log would have.
    {
        let mut counts = standing.counts.lock().unwrap();
        counts.void_through = Some(40);
    }
    assert!(matches!(standing.settle(&read_crossing(), day(40), || Ok(())), Settled::Ask));
    assert!(matches!(standing.settle(&read_crossing(), day(41), || Ok(())), Settled::Clear));
    let _ = std::fs::remove_dir_all(dir);
}

fn fault(standing: &Standing, set: impl FnOnce(&mut Fault)) {
    set(&mut standing.counts.lock().unwrap().log.fault);
}

#[test]
fn a_failed_append_that_cannot_be_cut_back_stops_every_clear_until_it_can() {
    // The review's scenario: an append writes part of a line and fails (disk full), and cutting the log back fails
    // too. The old code carried on, so the next good line glued onto the torn one and a restart lost its count.
    let dir = temp("torn");
    let (grants, id) = grant_file(&dir, CrossingClass::Memory, &["read"], 2);
    let standing = open_standing(&dir, Some(grants.clone()), None);
    let now = now_ms();
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Clear));
    fault(&standing, |f| *f = Fault { tear_append: true, refuse_cut: true });
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    let torn = std::fs::read(dir.join("autoclear.jsonl")).unwrap();
    assert!(!torn.ends_with(b"\n"), "the disk holds a torn line");
    // Space is back (nothing tears any more) but the log still cannot be cut back: everything asks, nothing is written.
    fault(&standing, |f| f.tear_append = false);
    for _ in 0..3 {
        assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    }
    assert_eq!(std::fs::read(dir.join("autoclear.jsonl")).unwrap(), torn);
    // The cut works again: the torn line goes, the log is clean, and the one count left clears.
    fault(&standing, |f| f.refuse_cut = false);
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Clear));
    let log = std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap();
    assert_eq!(log, format!("{0}{0}", count_line(now, &id)));
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    // Both executed clears are counted after a restart: the allowance of two is spent, not given back.
    drop(standing);
    let again = open_standing(&dir, Some(grants), None);
    assert!(matches!(again.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_torn_line_left_on_disk_by_a_failed_cut_makes_the_next_start_ask_for_the_day() {
    let dir = temp("torn-restart");
    let (grants, _) = grant_file(&dir, CrossingClass::Memory, &["read"], 5);
    let standing = open_standing(&dir, Some(grants.clone()), None);
    let now = now_ms();
    fault(&standing, |f| *f = Fault { tear_append: true, refuse_cut: true });
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    drop(standing);
    let again = open_standing(&dir, Some(grants), None);
    assert!(matches!(again.settle(&read_crossing(), now_ms(), || Ok(())), Settled::Ask));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_failed_append_that_is_cut_back_at_once_costs_one_ask_and_nothing_else() {
    let dir = temp("torn-cut");
    let (grants, id) = grant_file(&dir, CrossingClass::Memory, &["read"], 5);
    let standing = open_standing(&dir, Some(grants), None);
    let now = now_ms();
    fault(&standing, |f| f.tear_append = true);
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Ask));
    assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap(), "");
    assert!(matches!(standing.settle(&read_crossing(), now, || Ok(())), Settled::Clear));
    assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap(), count_line(now, &id));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_state_folder_is_synced_and_a_folder_that_cannot_be_is_refused() {
    let dir = temp("sync");
    assert!(sync_dir(&dir).is_ok());
    assert!(sync_dir(&dir.join("missing")).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

/// A door whose memory executor is a one-shot stand-in for the Kira service, with the slider configured.
fn memory_door(dir: &Path, grants: Option<&Path>) -> (Door, std::thread::JoinHandle<usize>) {
    use std::io::BufRead;
    use std::os::unix::net::UnixListener;
    let socket = dir.join("kira.sock");
    let token = dir.join("door.token");
    write_private(&token, b"door-token\n");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(false).unwrap();
    let service = std::thread::spawn(move || {
        let mut served = 0;
        // The door asks `whoami` before its first memory call, then at most one `recall` follows; the test ends the
        // stand-in by connecting once more when no call was expected.
        while let Ok((stream, _)) = listener.accept() {
            let mut text = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap()).read_line(&mut text).unwrap();
            let mut stream = stream;
            if text.contains("whoami") {
                writeln!(stream, "{}", serde_json::json!({"ok": true, "result": {"owner": false}})).unwrap();
            } else if text.contains("recall") || text.contains("\"get\"") {
                served = 1;
                writeln!(stream, "{}", serde_json::json!({"ok": true, "result": {"status": "found", "items": []}})).unwrap();
                break;
            } else {
                break;
            }
        }
        served
    });
    let standing = grants.map_or_else(|| "\"standing\":{}".to_owned(), |g| format!("\"standing\":{{\"grants_file\":\"{}\"}}", g.display()));
    let text = format!(
        "{{\"v\":1,\"peers\":{{\"mode\":\"peercred\",\"uids\":[1001]}},\"workspace_roots\":[\"/sandbox\"],\"state_dir\":\"{}\",\"classes\":{{\"memory\":\"allow\"}},\"memory\":{{\"socket\":\"{}\",\"token_file\":\"{}\"}},{standing}}}",
        dir.join("state").display(),
        socket.display(),
        token.display()
    );
    (Door::open(super::super::policy::Policy::parse(&text).unwrap()).unwrap(), service)
}

#[test]
fn the_door_asks_where_the_policy_said_allow_until_a_grant_clears_the_call() {
    use super::super::peer::Peer;
    use super::super::wire::test_line as line;
    let recall = |id: &str| line(id, "kira_recall", "{\"query\":\"figurine\"}", "memory");

    // No grant: the slider turns the policy's allow into an ask, and nothing reaches the service.
    let bare = temp("door-bare");
    let (door, service) = memory_door(&bare, None);
    let (_, decision) = door.judge(Peer::Uid(1001), &recall("c-1"));
    assert!(matches!(&decision, super::super::wire::Decision::Ask(code) if code == "ask-memory"), "{decision:?}");
    drop(std::os::unix::net::UnixStream::connect(bare.join("kira.sock")));
    assert_eq!(service.join().unwrap(), 0);

    // A live grant for reads: the same call runs, once per count.
    let granted = temp("door-granted");
    let (grants, _) = grant_file(&granted, CrossingClass::Memory, &["read"], 1);
    let (door, service) = memory_door(&granted, Some(&grants));
    let (_, decision) = door.judge(Peer::Uid(1001), &recall("c-2"));
    assert!(matches!(decision, super::super::wire::Decision::Allow { .. }), "{decision:?}");
    assert_eq!(service.join().unwrap(), 1);
    let (_, decision) = door.judge(Peer::Uid(1001), &recall("c-3"));
    assert!(matches!(&decision, super::super::wire::Decision::Ask(code) if code == "ask-memory"), "{decision:?}");
    let _ = std::fs::remove_dir_all(bare);
    let _ = std::fs::remove_dir_all(granted);
}

#[test]
fn auma_s_own_slot_is_read_at_session_start_without_a_card_and_nothing_else_is() {
    use super::super::peer::Peer;
    use super::super::wire::test_line as line;
    // No grant at all (the starter): reading aukora:self runs at once (O14) ...
    let dir = temp("door-own-slot");
    let (door, service) = memory_door(&dir, None);
    let (_, decision) = door.judge(Peer::Uid(1001), &line("s-1", "kira_get", "{\"id\":\"aukora:self\"}", "memory"));
    assert!(matches!(decision, super::super::wire::Decision::Allow { .. }), "{decision:?}");
    assert_eq!(service.join().unwrap(), 1);
    let _ = std::fs::remove_dir_all(&dir);
    // ... while reading any other slot, or recalling, still asks the owner.
    let dir = temp("door-other-slot");
    let (door, service) = memory_door(&dir, None);
    let (_, decision) = door.judge(Peer::Uid(1001), &line("s-2", "kira_get", "{\"id\":\"resume:grok\"}", "memory"));
    assert!(matches!(&decision, super::super::wire::Decision::Ask(code) if code == "ask-memory"), "{decision:?}");
    drop(std::os::unix::net::UnixStream::connect(dir.join("kira.sock")));
    assert_eq!(service.join().unwrap(), 0);
    let _ = std::fs::remove_dir_all(dir);
}
