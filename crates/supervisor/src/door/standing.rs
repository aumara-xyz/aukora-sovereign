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
/// The in-node policy comes from the same verified Aura view as owner actions.
pub type PolicySource = Box<dyn Fn() -> Option<SliderPolicy> + Send + Sync>;

/// How long the gate's grants are trusted before the gate is asked again (a revoke or a new card lands within it).
const SOURCE_FRESH: std::time::Duration = std::time::Duration::from_secs(2);

pub struct Standing {
    files: StandingFiles,
    loaded: Mutex<Option<Loaded>>,
    counts: Mutex<Counts>,
    /// When set, the grants are the gate target's applied bytes, not `files.grants`.
    source: Option<GrantSource>,
    policy_source: Option<PolicySource>,
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

pub(super) fn configured_policy(files: Option<&StandingFiles>) -> SliderPolicy {
    match files.and_then(|files| files.policy.as_ref()) {
        None => slider::starter(),
        Some(path) => read_text(path).ok_or_else(|| refuse("door-standing")).and_then(|bytes| SliderPolicy::parse(&bytes)),
    }
    .unwrap_or(SliderPolicy { setting: SliderSetting::AskEverything, classes: Vec::new() })
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
        Ok(Self { files: files.clone(), loaded: Mutex::new(None), counts: Mutex::new(counts), source: None, policy_source: None, from_source: Mutex::new(None) })
    }

    fn load(&self, policy_stamp: Stamp, grants_stamp: Stamp) -> Loaded {
        let policy = configured_policy(Some(&self.files));
        let grants = self.files.grants.as_ref().and_then(|path| read_text(path)).and_then(|bytes| GrantSet::parse(&bytes).ok()).unwrap_or_default();
        Loaded { policy_stamp, grants_stamp, policy, grants }
    }

    /// Take the grants from the gate (the in-node door): only owner-applied bytes; anything unreadable is no grants.
    pub fn grants_from(&mut self, source: GrantSource) {
        self.source = Some(source);
    }

    pub fn policy_from(&mut self, source: PolicySource) {
        self.policy_source = Some(source);
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
        // No policy cache: a tightening applies to the next crossing, including
        // the second judgment after a slow preflight.
        let policy = match &self.policy_source {
            Some(source) => source().unwrap_or(SliderPolicy { setting: SliderSetting::AskEverything, classes: Vec::new() }),
            None => loaded.policy.clone(),
        };
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
mod tests;
