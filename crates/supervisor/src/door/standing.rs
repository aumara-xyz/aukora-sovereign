// SPDX-License-Identifier: AGPL-3.0-or-later
//! The slider and standing grants at the door: Laya's floor, applied by Rust.
//!
//! With a `standing` section in the door policy, a class the policy would `allow` or `ask` about is decided per
//! call: the owner's slider setting, the live standing grants and today's counts give a floor
//! (`laya::slider::judge`: Rust's floor, raised by Laya's escalation, never lowered), and only a floor of "clear"
//! lets the call run without an owner request. Everything else becomes an `ask`. A policy `deny` stays a deny, a class
//! without an executor can never run, and the door's own checks (host allowlist, memory ceilings) still apply first.
//!
//! The slider policy and the grants are owner-approved data the installer places as root-owned files, read like the
//! door policy (`files::open_trusted`) and re-read when they change, so a revoked grant stops clearing on the next
//! call. A missing slider policy file means the shipped starter ("only risky things"); a missing grants file means no
//! grants (so nothing clears); an unreadable one fails closed to the same. Counts are durable: a clear is written to
//! `autoclear.jsonl` and synced before the call runs, so a crash can lose a run and never gives back a count.
//! A policy without a `standing` section behaves exactly as before.

use super::classify::Class;
use super::files;
use super::ledger::open_append;
use super::policy::{Action, StandingFiles};
use super::wire::Request;
use super::{memory, refuse, Door};
use canon::json::{Value, ValueView};
use canon::Result;
use laya::{slider, Crossing, CrossingClass, Floor, GrantSet, SliderPolicy, SliderSetting, Usage};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FILE: u64 = 128 << 10;
/// The counts log stops clearing past this size (calls ask instead) until a restart compacts it to today's lines.
const LOG_MAX: u64 = 4 << 20;
const DAY_MS: i64 = 86_400_000;

/// What a file looked like when it was read: a change in any of it means read it again.
type Stamp = Option<(u64, i64, i64, u64)>;

fn stamp(path: &Path) -> Stamp {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some((meta.len(), meta.mtime(), meta.mtime_nsec(), meta.ino()))
}

struct Loaded {
    policy_stamp: Stamp,
    grants_stamp: Stamp,
    policy: SliderPolicy,
    grants: GrantSet,
}

struct Counts {
    usage: Usage,
    log: File,
    bytes: u64,
    /// The latest instant the slider has seen, so a clock that steps back (or a call that sampled the time before it
    /// waited for the lock) cannot revive an expired grant or move today's counts back a day.
    last_ms: i64,
}

pub struct Standing {
    files: StandingFiles,
    loaded: Mutex<Option<Loaded>>,
    counts: Mutex<Counts>,
}

/// The slider's answer for one call, after the door's own checks.
pub enum Settled {
    /// Run it: the count is spent, durably.
    Clear,
    /// An owner request is needed.
    Ask,
    /// The door would refuse the call anyway (the token the engine sees).
    Refuse(String),
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn read_text(path: &Path) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    files::open_trusted(path, MAX_FILE, 0o022, "door-standing").ok()?.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

impl Standing {
    pub fn open(files: &StandingFiles, state_dir: &Path) -> Result<Self> {
        let path = state_dir.join("autoclear.jsonl");
        let mut log = open_append(&path)?;
        let mut text = String::new();
        log.read_to_string(&mut text).map_err(|_| refuse("door-state"))?;
        let today = slider::day_of(now_ms());
        let mut usage = Usage::default();
        let mut last_ms = 0;
        let mut kept = String::new();
        for line in text.lines() {
            // A line that does not parse is dropped: it can only lose a count, which makes the door ask less often at
            // worst by the lines of a torn write, never grant anything.
            let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let (Some(at), Some(class), Some(grant)) = (event["at_ms"].as_i64(), event["class"].as_str(), event["grant"].as_str()) else { continue };
            let (Some(class), Ok(grant)) = (CrossingClass::from_wire(class), canon::digest::Digest32::from_hex(grant)) else { continue };
            if slider::day_of(at) == today {
                last_ms = last_ms.max(at);
                usage.record(class, grant, at);
                kept.push_str(line);
                kept.push('\n');
            }
        }
        // Compact to today's lines (atomically) so the log stays small and a restart gives back nothing.
        if kept.len() != text.len() {
            let tmp = state_dir.join("autoclear.jsonl.tmp");
            let mut file = File::create(&tmp).map_err(|_| refuse("door-state"))?;
            file.write_all(kept.as_bytes()).and_then(|()| file.sync_all()).map_err(|_| refuse("door-state"))?;
            std::fs::rename(&tmp, &path).map_err(|_| refuse("door-state"))?;
            log = open_append(&path)?;
        }
        Ok(Self { files: files.clone(), loaded: Mutex::new(None), counts: Mutex::new(Counts { usage, log, bytes: kept.len() as u64, last_ms }) })
    }

    fn load(&self, policy_stamp: Stamp, grants_stamp: Stamp) -> Loaded {
        let policy = match &self.files.policy {
            None => slider::starter(),
            Some(path) => read_text(path).ok_or_else(|| refuse("door-standing")).and_then(|bytes| SliderPolicy::parse(&bytes)),
        }
        .unwrap_or_else(|_| SliderPolicy { setting: SliderSetting::AskEverything, classes: Vec::new() });
        let grants = self.files.grants.as_ref().and_then(|path| read_text(path)).and_then(|bytes| GrantSet::parse(&bytes).ok()).unwrap_or_default();
        Loaded { policy_stamp, grants_stamp, policy, grants }
    }

    /// Read the slider policy and the grants again when either file changed. Anything unreadable or invalid fails
    /// closed: no policy file means the starter, a bad one means "ask for everything", a bad grants file means none.
    fn current(&self) -> (SliderPolicy, GrantSet) {
        let mut guard = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        let stamps = (self.files.policy.as_deref().and_then(stamp), self.files.grants.as_deref().and_then(stamp));
        let loaded = guard.get_or_insert_with(|| self.load(stamps.0, stamps.1));
        if (loaded.policy_stamp, loaded.grants_stamp) != stamps {
            *loaded = self.load(stamps.0, stamps.1);
        }
        (loaded.policy.clone(), loaded.grants.clone())
    }

    /// Decide one crossing. On a clear the count is appended and synced before this returns; `preflight` (the door's
    /// own checks) runs first so a call the door would refuse spends nothing.
    pub fn settle(&self, crossing: &Crossing, now: i64, preflight: impl FnOnce() -> std::result::Result<(), String>) -> Settled {
        let (policy, grants) = self.current();
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let now = now.max(counts.last_ms);
        counts.last_ms = now;
        // A new day starts the log afresh: yesterday's lines are not needed and, under `trusted` (no count to run out),
        // would only grow toward the size at which nothing clears any more.
        if slider::day_of(now) > counts.usage.day() && counts.log.set_len(0).is_ok() {
            counts.bytes = 0;
        }
        let decision = slider::judge(&policy, &grants, &counts.usage, crossing, now);
        let (Floor::AutoClear, Some(grant)) = (decision.floor, decision.grant) else { return Settled::Ask };
        if let Err(code) = preflight() {
            return Settled::Refuse(code);
        }
        let line = format!("{}\n", serde_json::json!({"at_ms": now, "class": crossing.class.wire_name(), "grant": grant.to_string()}));
        if counts.bytes + line.len() as u64 > LOG_MAX {
            return Settled::Ask;
        }
        if counts.log.write_all(line.as_bytes()).and_then(|()| counts.log.sync_data()).is_err() {
            // Take back a torn line so the next one does not glue onto it (and a restart does not read it as a count).
            let length = counts.bytes;
            let _ = counts.log.set_len(length);
            return Settled::Ask;
        }
        counts.bytes += line.len() as u64;
        counts.usage.record(crossing.class, grant, now);
        Settled::Clear
    }
}

/// The one path a file-outside call names. The door classifies a call by seven argument names (`classify::PATH_KEYS`,
/// arrays included); the slider's grant covers a prefix, so a call that names more than one distinct path, or one it
/// cannot read as text, has no single token and asks.
fn one_path(request: &Request) -> Option<String> {
    let mut seen: Vec<String> = Vec::new();
    for key in super::classify::PATH_KEYS {
        match request.args.get(key).map(Value::view) {
            None => {}
            Some(ValueView::Text(path)) => seen.push(path.to_owned()),
            Some(ValueView::Array(items)) => {
                for item in items {
                    match item.view() {
                        ValueView::Text(path) => seen.push(path.to_owned()),
                        _ => return None,
                    }
                }
            }
            Some(_) => return None,
        }
    }
    seen.sort();
    seen.dedup();
    if seen.len() == 1 { seen.pop() } else { None }
}

/// What a call crosses, as the slider's rules see it: a class and one target token, never the body.
pub fn crossing_of(class: Class, request: &Request) -> Option<Crossing> {
    let crossing_class = CrossingClass::from_wire(class.name())?;
    let text = |key: &str| match request.args.get(key).map(Value::view) {
        Some(ValueView::Text(text)) => Some(text.to_owned()),
        _ => None,
    };
    let token = match class {
        Class::Net if request.tool == "web_fetch" => reqwest::Url::parse(&text("url")?).ok()?.host_str()?.to_ascii_lowercase(),
        Class::Net => return None,
        Class::Memory => match memory::method(&request.tool).ok()? {
            "recall" | "get" | "list_recent" => "read".to_owned(),
            _ => format!("write:{}", text("lane")?),
        },
        Class::Mcp => request.tool.strip_prefix("mcp__")?.split("__").next()?.to_owned(),
        Class::Delegate => text("provider")?,
        Class::FsOutside => one_path(request)?,
        _ => request.tool.clone(),
    };
    Some(Crossing::new(crossing_class, token))
}

impl Door {
    /// With a slider configured, what a policy `allow` or `ask` becomes for this call; without one, the policy's own
    /// action. `Err` is a refusal the door would give anyway.
    pub(super) fn settle(&self, class: Class, request: &Request, action: Action) -> std::result::Result<Action, String> {
        let (Some(standing), true) = (&self.standing, action != Action::Deny) else { return Ok(action) };
        let Some(crossing) = crossing_of(class, request) else { return Ok(Action::Ask) };
        match standing.settle(&crossing, now_ms(), || self.preflight_for_clear(class, request)) {
            Settled::Clear => Ok(Action::Allow),
            Settled::Ask => Ok(Action::Ask),
            Settled::Refuse(code) => Err(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use laya::grant::{DoorGrant, DAY_MS as GRANT_DAY};
    use std::path::PathBuf;

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

    #[test]
    fn old_days_are_dropped_when_the_log_is_opened() {
        let dir = temp("compact");
        let id = canon::digest::Digest32::sha256(b"g");
        let old = now_ms() - 3 * DAY_MS;
        let today = now_ms();
        let line = |at: i64| format!("{}\n", serde_json::json!({"at_ms": at, "class": "memory", "grant": id.to_string()}));
        write_private(&dir.join("autoclear.jsonl"), format!("{}{}torn", line(old), line(today)).as_bytes());
        let _standing = open_standing(&dir, None, None);
        assert_eq!(std::fs::read_to_string(dir.join("autoclear.jsonl")).unwrap(), line(today));
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
                } else if text.contains("recall") {
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
}
