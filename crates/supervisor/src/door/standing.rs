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
//!
//! The log fails closed. A failed append or sync that cannot be taken back (the log cut back to the last acknowledged
//! length and synced) stops every auto-clear until a later call manages that; a line at open that does not parse is
//! never skipped: it is replaced by a durable "void" line, and nothing auto-clears for the rest of that UTC day (the
//! allowance is treated as spent), because a lost count could otherwise let more clear than the owner allowed. The
//! state folder is synced after the log is created and after a compaction renames it into place, before any crossing.
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
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FILE: u64 = 128 << 10;
/// The counts log stops clearing past this size (calls ask instead) until a restart compacts it to today's lines.
const LOG_MAX: u64 = 4 << 20;
const DAY_MS: i64 = 86_400_000;
/// The `void` member of a log line that says the log was unreadable on its day: that day's allowance is spent.
const VOID: &str = "unreadable-log";

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

/// The counts log file. In tests it can be made to tear an append or refuse to be cut back, as a failing disk would.
struct Log {
    file: File,
    #[cfg(test)]
    fault: Fault,
}

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct Fault {
    /// The next append writes half its bytes and fails.
    tear_append: bool,
    /// Cutting the log back fails.
    refuse_cut: bool,
}

impl Log {
    fn new(file: File) -> Self {
        Self {
            file,
            #[cfg(test)]
            fault: Fault::default(),
        }
    }

    /// Append one line and sync it.
    fn append(&mut self, line: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fault.tear_append) {
            self.file.write_all(&line[..line.len() / 2])?;
            return Err(std::io::Error::other("torn append"));
        }
        self.file.write_all(line).and_then(|()| self.file.sync_data())
    }

    /// Cut the log back to `length` bytes, sync it and check it is that long: the one way a failed append is undone.
    fn cut_to(&mut self, length: u64) -> bool {
        #[cfg(test)]
        if self.fault.refuse_cut {
            return false;
        }
        self.file.set_len(length).and_then(|()| self.file.sync_all()).is_ok() && self.file.metadata().is_ok_and(|meta| meta.len() == length)
    }
}

struct Counts {
    usage: Usage,
    log: Log,
    bytes: u64,
    /// The UTC day of the newest line in the log (0 when empty): a later day starts the log afresh.
    log_day: i64,
    /// An append or sync failed and the log could not be cut back to `bytes` (the last acknowledged length) and synced,
    /// so it may end in a torn line. Nothing auto-clears until a later call manages the cut.
    dirty: bool,
    /// The log held something that could not be read on this UTC day (or a day ahead of the clock): the allowance is
    /// treated as spent through that day.
    void_through: Option<i64>,
    /// The latest instant the slider has seen, so a clock that steps back (or a call that sampled the time before it
    /// waited for the lock) cannot revive an expired grant or move today's counts back a day.
    last_ms: i64,
}

/// Where the grants come from on the node: the bytes the owner's passkey applied to `door/standing-grants.json`.
pub type GrantSource = Box<dyn Fn() -> Option<Vec<u8>> + Send + Sync>;

/// How long the gate's grants are trusted before the gate is asked again (a revoke or a new card lands within it).
const SOURCE_FRESH: std::time::Duration = std::time::Duration::from_secs(2);

pub struct Standing {
    files: StandingFiles,
    loaded: Mutex<Option<Loaded>>,
    counts: Mutex<Counts>,
    /// When set, the grants are the gate target's applied bytes, not `files.grants`.
    source: Option<GrantSource>,
    from_source: Mutex<Option<(std::time::Instant, GrantSet)>>,
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

pub(super) fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// One line of the counts log.
enum Event {
    /// A clear, spent against a grant.
    Count { at: i64, class: CrossingClass, grant: canon::digest::Digest32 },
    /// The log was unreadable on this line's day.
    Void { at: i64 },
}

fn parse_event(line: &str) -> Option<Event> {
    let event: serde_json::Value = serde_json::from_str(line).ok()?;
    let at = event["at_ms"].as_i64()?;
    if !event["void"].is_null() {
        return (event["void"].as_str() == Some(VOID)).then_some(Event::Void { at });
    }
    let class = CrossingClass::from_wire(event["class"].as_str()?)?;
    let grant = canon::digest::Digest32::from_hex(event["grant"].as_str()?).ok()?;
    Some(Event::Count { at, class, grant })
}

/// Make a directory's entries durable (a created or renamed file survives a crash).
fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir).and_then(|handle| handle.sync_all()).map_err(|_| refuse("door-state"))
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
        let mut raw = Vec::new();
        log.read_to_end(&mut raw).map_err(|_| refuse("door-state"))?;
        // Bytes that are not text cannot parse as a line either, so they end up in the "unreadable" branch below.
        let text = String::from_utf8_lossy(&raw);
        let now = now_ms();
        let today = slider::day_of(now);
        let mut usage = Usage::default();
        let mut last_ms = 0;
        let mut kept = String::new();
        // A line that does not parse (a torn write, a glued one, an edit) may have been an executed count, so it is
        // never skipped: it makes today's allowance spent, and is replaced by a durable void line.
        let mut ambiguous = false;
        let mut void_today = false;
        for line in text.lines() {
            match parse_event(line) {
                None => ambiguous = true,
                Some(Event::Count { at, class, grant }) => {
                    let day = slider::day_of(at);
                    if day == today {
                        last_ms = last_ms.max(at);
                        usage.record(class, grant, at);
                    } else if day > today {
                        // Ahead of the clock: keep the line, and do not trust today.
                        ambiguous = true;
                    }
                    if day >= today {
                        kept.push_str(line);
                        kept.push('\n');
                    }
                }
                Some(Event::Void { at }) => {
                    let day = slider::day_of(at);
                    void_today |= day == today;
                    ambiguous |= day > today;
                    if day >= today {
                        last_ms = last_ms.max(at);
                        kept.push_str(line);
                        kept.push('\n');
                    }
                }
            }
        }
        if ambiguous && !void_today {
            let at = now.max(last_ms);
            last_ms = at;
            kept.push_str(&format!("{}\n", serde_json::json!({"at_ms": at, "void": VOID})));
        }
        // Compact to today's lines (atomically) so the log stays small and a restart gives back nothing.
        if kept.len() != text.len() {
            let tmp = state_dir.join("autoclear.jsonl.tmp");
            let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|_| refuse("door-state"))?;
            file.write_all(kept.as_bytes()).and_then(|()| file.sync_all()).map_err(|_| refuse("door-state"))?;
            std::fs::rename(&tmp, &path).map_err(|_| refuse("door-state"))?;
            log = open_append(&path)?;
        }
        // The log's directory entry (new, or just renamed over the old one) is durable before any crossing is accepted.
        sync_dir(state_dir)?;
        let void_through = (ambiguous || void_today).then_some(today.max(slider::day_of(last_ms)));
        let counts = Counts { usage, log: Log::new(log), bytes: kept.len() as u64, log_day: slider::day_of(last_ms), dirty: false, void_through, last_ms };
        Ok(Self { files: files.clone(), loaded: Mutex::new(None), counts: Mutex::new(counts), source: None, from_source: Mutex::new(None) })
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

    /// Take the grants from the gate (the in-node door): only owner-applied bytes; anything unreadable is no grants.
    pub fn grants_from(&mut self, source: GrantSource) {
        self.source = Some(source);
    }

    fn source_grants(&self, source: &GrantSource) -> GrantSet {
        let mut cached = self.from_source.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((at, grants)) = cached.as_ref() {
            if at.elapsed() < SOURCE_FRESH {
                return grants.clone();
            }
        }
        let grants = source().and_then(|bytes| GrantSet::parse(&bytes).ok()).unwrap_or_default();
        *cached = Some((std::time::Instant::now(), grants.clone()));
        grants
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
        let policy = loaded.policy.clone();
        let grants = match &self.source {
            Some(source) => {
                drop(guard);
                self.source_grants(source)
            }
            None => loaded.grants.clone(),
        };
        (policy, grants)
    }

    /// Cut the log back to its last acknowledged length. Only when that is done and checked is it trusted again.
    fn recover(counts: &mut Counts) -> bool {
        let length = counts.bytes;
        counts.dirty = !counts.log.cut_to(length);
        !counts.dirty
    }

    /// The clock never runs back inside the log, and a new day starts the log afresh: yesterday's lines are not needed
    /// and, under `trusted` (no count to run out), would only grow toward the size at which nothing clears any more.
    fn advance(counts: &mut Counts, now: i64) -> i64 {
        let now = now.max(counts.last_ms);
        counts.last_ms = now;
        if slider::day_of(now) > counts.log_day && counts.log.file.set_len(0).is_ok() {
            counts.bytes = 0;
            counts.log_day = slider::day_of(now);
        }
        now
    }

    /// Decide one crossing. On a clear the count is appended and synced before this returns; `preflight` (the door's
    /// own checks) runs first so a call the door would refuse spends nothing.
    pub fn settle(&self, crossing: &Crossing, now: i64, preflight: impl FnOnce() -> std::result::Result<(), String>) -> Settled {
        // First look, under the lock: does a grant cover this call at all? Nothing is spent here.
        let (policy, grants) = self.current();
        let (now, covered) = {
            let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Self::advance(&mut counts, now);
            let decision = slider::judge(&policy, &grants, &counts.usage, crossing, now);
            (now, matches!((decision.floor, decision.grant), (Floor::AutoClear, Some(_))))
        };
        if !covered {
            return Settled::Ask;
        }
        // The door's own checks run with no lock held: the memory check asks Kira (a read timeout of seconds), and a slow
        // Kira must not stall every other slider-settled call, net included (SCOUT M13).
        if let Err(code) = preflight() {
            return Settled::Refuse(code);
        }
        // Second look, under the lock again: another call may have spent the grant, or a revoke landed, while the check
        // ran. The count is judged afresh and the line appended in the same hold, so a grant never clears twice over.
        let (policy, grants) = self.current();
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Self::advance(&mut counts, now);
        let decision = slider::judge(&policy, &grants, &counts.usage, crossing, now);
        let (Floor::AutoClear, Some(grant)) = (decision.floor, decision.grant) else { return Settled::Ask };
        // Everything asks while the log cannot be trusted: it held a line nobody could read today, or an append left it
        // possibly torn and it has not been cut back yet.
        if counts.void_through.is_some_and(|day| slider::day_of(now) <= day) {
            return Settled::Ask;
        }
        if counts.dirty && !Self::recover(&mut counts) {
            return Settled::Ask;
        }
        let line = format!("{}\n", serde_json::json!({"at_ms": now, "class": crossing.class.wire_name(), "grant": grant.to_string()}));
        if counts.bytes + line.len() as u64 > LOG_MAX {
            return Settled::Ask;
        }
        if counts.log.append(line.as_bytes()).is_err() {
            // The line may be on disk in part or whole. Whatever it is, this call asks; and until the log is cut back to
            // the last acknowledged length the next line would glue onto the torn one and a restart could not read it.
            counts.dirty = true;
            Self::recover(&mut counts);
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

/// Auma's own slots, which the `@aukora/kira` plugin reads at the start of every session (`aukora:self` and
/// `aukora:resume`, by name through `kira_get`).
const OWN_SLOTS: [&str; 2] = ["aukora:self", "aukora:resume"];

/// A read of one of Auma's own slots and nothing else: `kira_get` whose only argument is `id`, naming the slot. It
/// writes nothing, crosses to nobody, and its result is the identity the owner already gave her; asking the owner
/// for it on every new session teaches the owner to approve memory cards unread (NODE.md O14). Every other memory
/// call (any recall, any other id or slot, any write) is still the slider's.
pub fn own_slot_read(class: Class, request: &Request) -> bool {
    if class != Class::Memory || request.tool != "kira_get" {
        return false;
    }
    match request.args.view() {
        ValueView::Object(fields) if fields.len() == 1 => {
            matches!(request.args.get("id").map(Value::view), Some(ValueView::Text(id)) if OWN_SLOTS.contains(&id))
        }
        _ => false,
    }
}

impl Door {
    /// With a slider configured, what a policy `allow` or `ask` becomes for this call; without one, the policy's own
    /// action. `Err` is a refusal the door would give anyway. A policy `allow` of a read of Auma's own slot clears
    /// without the slider (`own_slot_read`); a policy `ask` still asks.
    pub(super) fn settle(&self, class: Class, request: &Request, action: Action) -> std::result::Result<Action, String> {
        let (Some(standing), true) = (&self.standing, action != Action::Deny) else { return Ok(action) };
        if action == Action::Allow && own_slot_read(class, request) {
            return Ok(Action::Allow);
        }
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
}
