// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner approval for the door's asks, through the node's own gate.
//!
//! An `ask` class turns into a normal gate proposal: the call (tool, class, canonical arguments, call digest) is written
//! as a record (`gate::door`) into one of a few fixed content targets, `door/ask-00.json`.., and the owner approves it on
//! the existing owner origin with a passkey assertion, exactly as for any other critical change. When the model repeats
//! the identical call (a fresh call id, the same call digest) and the proposal was applied, the door spends the approval
//! (durably, before anything runs) and executes the call itself. One approval lets one call through.
//!
//! The `Approver` trait is the only thing the door sees; `GateApprover` is the node's implementation.

use super::ledger::open_append;
use super::refuse;
use crate::adapters::{GateAdapter, HostLedger};
use canon::json::Value;
use canon::Result;
use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use supervisor::ingress::BindingState;
use supervisor::services::GateService;

/// The approvals log stops accepting after this many bytes; an ask is then refused until the owner rotates it.
pub const APPROVALS_MAX_BYTES: u64 = 16 << 20;
/// What one event line takes at most (an `open` line is about 170 bytes), kept free before a card is raised.
const EVENT_BYTES: u64 = 256;
/// Open asks the door remembers at once. A request beyond this is refused, not forgotten.
const MAX_OPEN: usize = 4_096;
/// How many `door/ask-NN.json` targets the installer ships (the most asks open at once).
pub const TARGET_POOL: usize = 8;
/// An approval is good for the repeat of its call for this long after the request was raised (the gate's own proposal
/// lasts five minutes); an ask nobody settled in that time is raised afresh.
pub const APPROVAL_TTL_SECS: u64 = 3_600;

/// The call the door is asking about, as the door itself parsed and recomputed it.
pub struct AskRecord<'a> {
    pub call_id: &'a str,
    pub class: &'a str,
    pub tool: &'a str,
    pub digest_sha256: &'a str,
    pub args: &'a Value,
}

/// What the owner has done with one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Approval {
    /// Raised, not answered yet.
    Pending,
    /// The owner approved it.
    Approved,
    /// Refused, retired, expired or lost: a new request is needed.
    Gone,
}

/// Raises owner requests and reports on them. A handle is opaque to the door; it is stored durably.
pub trait Approver: Send + Sync {
    /// Raise one request. `Err` carries the refusal token the engine sees; nothing was raised.
    fn request(&self, ask: &AskRecord<'_>) -> std::result::Result<String, &'static str>;
    /// Where a request stands.
    fn state(&self, handle: &str) -> Approval;
    /// Housekeeping, called about once a minute (the node settles expired proposals here).
    fn sweep(&self) {}
}

/// The door's own memory of its open asks, durable across a restart: one JSON line per event,
/// `{"at":secs,"digest":..,"e":"open"|"used"|"gone","handle":..}`; the last event for a digest decides.
pub struct ApprovalLog {
    inner: Mutex<Inner>,
    max_bytes: u64,
    max_open: usize,
}

struct Inner {
    file: File,
    bytes: u64,
    /// Call digest to (request handle, when it was raised).
    open: HashMap<String, (String, u64)>,
}

impl ApprovalLog {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with(path, APPROVALS_MAX_BYTES)
    }

    pub(super) fn open_with(path: &Path, max_bytes: u64) -> Result<Self> {
        Self::open_with_limits(path, max_bytes, MAX_OPEN)
    }

    pub(super) fn open_with_limits(path: &Path, max_bytes: u64, max_open: usize) -> Result<Self> {
        let mut file = open_append(path)?;
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(|_| refuse("door-state"))?;
        let mut bytes = text.len() as u64;
        if !text.is_empty() && !text.ends_with('\n') {
            file.write_all(b"\n").and_then(|()| file.sync_data()).map_err(|_| refuse("door-state"))?;
            bytes += 1;
        }
        let mut open: HashMap<String, (String, u64)> = HashMap::new();
        for line in text.lines().filter(|line| !line.is_empty()) {
            // A line that does not parse is skipped: it can only lose an open ask, never grant one.
            let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let (Some(kind), Some(digest), Some(handle)) = (event["e"].as_str(), event["digest"].as_str(), event["handle"].as_str()) else { continue };
            match kind {
                "open" => {
                    open.insert(digest.to_owned(), (handle.to_owned(), event["at"].as_u64().unwrap_or(0)));
                }
                "used" | "gone" => {
                    if open.get(digest).is_some_and(|(current, _)| current == handle) {
                        open.remove(digest);
                    }
                }
                _ => {}
            }
        }
        Ok(Self { inner: Mutex::new(Inner { file, bytes, open }), max_bytes, max_open })
    }

    /// The open request for this call digest, if any: its handle and when it was raised.
    pub fn get(&self, digest: &str) -> Option<(String, u64)> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).open.get(digest).cloned()
    }

    /// Make room for one more open ask before one is raised: when the table is full, asks older than the approval time
    /// limit are ended (`gone`, durably) since nothing can spend them any more. `Err` if it is still full, so the
    /// caller refuses before it puts a card in front of the owner that could never be honoured.
    pub fn reserve(&self, digest: &str, now: u64) -> std::result::Result<(), &'static str> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        self.make_room(&mut inner, digest, now)
    }

    fn make_room(&self, inner: &mut Inner, digest: &str, now: u64) -> std::result::Result<(), &'static str> {
        // Room in the file as well as in the table: at the byte cap `begin` would refuse after the card went up.
        let room_in_file = inner.bytes + EVENT_BYTES <= self.max_bytes;
        if room_in_file && (inner.open.len() < self.max_open || inner.open.contains_key(digest)) {
            return Ok(());
        }
        let stale: Vec<(String, String)> = inner
            .open
            .iter()
            .filter(|(_, (_, raised))| now.saturating_sub(*raised) > APPROVAL_TTL_SECS)
            .map(|(digest, (handle, _))| (digest.clone(), handle.clone()))
            .collect();
        for (old_digest, old_handle) in stale {
            self.append(inner, "gone", &old_digest, &old_handle, 0)?;
            inner.open.remove(&old_digest);
        }
        if room_in_file && inner.open.len() < self.max_open {
            Ok(())
        } else {
            Err("approvals-full")
        }
    }

    /// Remember a newly raised request for this call digest (replacing a lost one), raised at `at` (unix seconds).
    pub fn begin(&self, digest: &str, handle: &str, at: u64) -> std::result::Result<(), &'static str> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        self.make_room(&mut inner, digest, at)?;
        self.append(&mut inner, "open", digest, handle, at)?;
        inner.open.insert(digest.to_owned(), (handle.to_owned(), at));
        Ok(())
    }

    /// End the open request (`"used"` when its approval was spent, `"gone"` when it was lost). Durable before it returns.
    pub fn finish(&self, digest: &str, handle: &str, kind: &'static str) -> std::result::Result<(), &'static str> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.open.get(digest).is_none_or(|(current, _)| current != handle) {
            return Err("approval-spent");
        }
        self.append(&mut inner, kind, digest, handle, 0)?;
        inner.open.remove(digest);
        Ok(())
    }

    fn append(&self, inner: &mut Inner, kind: &str, digest: &str, handle: &str, at: u64) -> std::result::Result<(), &'static str> {
        let line = format!("{{\"at\":{at},\"digest\":\"{digest}\",\"e\":\"{kind}\",\"handle\":\"{handle}\"}}\n");
        let needed = line.len() as u64;
        if inner.bytes + needed > self.max_bytes {
            return Err("approvals-full");
        }
        if inner.file.write_all(line.as_bytes()).and_then(|()| inner.file.sync_data()).is_err() {
            let _ = inner.file.set_len(inner.bytes);
            return Err("door-state");
        }
        inner.bytes += needed;
        Ok(())
    }

    #[cfg(test)]
    pub fn open_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).open.len()
    }
}

/// The note under the owner card: ASCII, short, never the engine's own words.
fn note(ask: &AskRecord<'_>) -> String {
    let mut text = format!("The engine asks to run {} ({}). Digest {}.", ask.tool, ask.class, &ask.digest_sha256[..16.min(ask.digest_sha256.len())]);
    text.retain(|c| c.is_ascii_graphic() || c == ' ');
    text.truncate(120);
    text
}

/// Run a future to completion on this thread (the door's own threads are plain threads, so no runtime is entered).
pub(super) fn block_on<T>(future: impl Future<Output = T>) -> T {
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// The node's approver: proposals in the gate, answered on the owner origin.
pub struct GateApprover {
    gate: Arc<GateAdapter>,
    ledger: Arc<HostLedger>,
}

impl GateApprover {
    pub fn new(gate: Arc<GateAdapter>, ledger: Arc<HostLedger>) -> Self {
        Self { gate, ledger }
    }

    fn scope(&self) -> std::result::Result<supervisor::ingress::PrincipalScope, &'static str> {
        match self.ledger.binding() {
            Ok(BindingState::Bound(scope)) => Ok(scope),
            Ok(BindingState::Unbound) => Err("approvals-unbound"),
            Err(_) => Err("door-state"),
        }
    }
}

impl Approver for GateApprover {
    fn request(&self, ask: &AskRecord<'_>) -> std::result::Result<String, &'static str> {
        let scope = self.scope()?;
        let bytes = gate::door::record(&gate::door::Ask {
            call_id: ask.call_id,
            class: ask.class,
            tool: ask.tool,
            digest_sha256: ask.digest_sha256,
            args: ask.args,
        })
        .map_err(|refusal| if refusal.reason == "door-record-too-large" { "ask-too-large" } else { "ask-record" })?;
        let note = note(ask);
        for attempt in 0..2 {
            for slot in 0..TARGET_POOL {
                let target = format!("{}{slot:02}.json", gate::door::ASK_PREFIX);
                match block_on(self.gate.propose_door(scope, target, note.clone(), bytes.clone())) {
                    Ok(id) => return Ok(id.to_string()),
                    // Not in the inventory: the node was installed without the door's targets.
                    Err(refusal) if refusal.reason == "target-not-allowed" => return Err("approvals-not-installed"),
                    // Busy (one open proposal per target) or already holding these bytes: try the next.
                    Err(_) => {}
                }
            }
            // Every target busy: an unanswered proposal may only be waiting to be settled as expired.
            if attempt == 0 {
                self.sweep();
            }
        }
        Err("approvals-busy")
    }

    fn state(&self, handle: &str) -> Approval {
        let scope = match self.ledger.binding() {
            Ok(BindingState::Bound(scope)) => scope,
            // The owner binding is gone: whatever was open belonged to the old one.
            Ok(BindingState::Unbound) => return Approval::Gone,
            // A ledger we cannot read right now says nothing about the owner's answer.
            Err(_) => return Approval::Pending,
        };
        let Ok(id) = canon::ids::ProposalId::from_hex(handle) else { return Approval::Gone };
        match block_on(self.gate.outcome(scope, id)) {
            Ok(None) => Approval::Pending,
            Ok(Some(outcome)) if outcome.state == canon::fd3_payloads::OutcomeState::Applied => Approval::Approved,
            Ok(Some(_)) => Approval::Gone,
            // Owner re-bound since the request was raised.
            Err(refusal) if refusal.reason == "binding-required" => Approval::Gone,
            // A busy gate or a read that failed: the owner's answer is unknown, not "no". An answer that never becomes
            // readable ends with the approval's time limit, not with a second request the owner would have to approve.
            Err(_) => Approval::Pending,
        }
    }

    fn sweep(&self) {
        match block_on(self.gate.sweep_expired()) {
            Ok(0) => {}
            Ok(blocked) => eprintln!("door: {blocked} gate proposals could not be settled"),
            Err(refusal) => eprintln!("door: expiry sweep failed: {}:{}", refusal.organ, refusal.reason),
        }
    }
}

#[cfg(test)]
pub mod fake {
    //! A scripted approver for the door's ask-flow tests.
    use super::*;

    #[derive(Default)]
    pub struct Fake {
        pub raised: Mutex<Vec<String>>,
        pub states: Mutex<HashMap<String, Approval>>,
        pub fail: Mutex<Option<&'static str>>,
        pub swept: Mutex<u32>,
    }

    impl Fake {
        pub fn answer(&self, handle: &str, approval: Approval) {
            self.states.lock().unwrap().insert(handle.to_owned(), approval);
        }
    }

    impl Approver for Fake {
        fn request(&self, ask: &AskRecord<'_>) -> std::result::Result<String, &'static str> {
            if let Some(code) = *self.fail.lock().unwrap() {
                return Err(code);
            }
            let mut raised = self.raised.lock().unwrap();
            let handle = format!("{:032x}", raised.len() + 1);
            raised.push(format!("{}|{}|{}", ask.tool, ask.class, ask.digest_sha256));
            self.states.lock().unwrap().insert(handle.clone(), Approval::Pending);
            Ok(handle)
        }

        fn state(&self, handle: &str) -> Approval {
            self.states.lock().unwrap().get(handle).copied().unwrap_or(Approval::Gone)
        }

        fn sweep(&self) {
            *self.swept.lock().unwrap() += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-door-approvals-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_open_ask_survives_a_restart_and_a_spent_one_does_not() {
        let dir = temp("replay");
        let path = dir.join("approvals.jsonl");
        {
            let log = ApprovalLog::open(&path).unwrap();
            log.begin("d1", "h1", 10).unwrap();
            log.begin("d2", "h2", 10).unwrap();
            log.begin("d3", "h3", 10).unwrap();
            log.finish("d2", "h2", "used").unwrap();
            log.finish("d3", "h3", "gone").unwrap();
        }
        let log = ApprovalLog::open(&path).unwrap();
        assert_eq!(log.get("d1"), Some(("h1".to_owned(), 10)));
        assert_eq!((log.get("d2"), log.get("d3")), (None, None));
        assert_eq!(log.open_count(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_approval_can_be_spent_only_once_and_only_by_its_own_handle() {
        let dir = temp("spend");
        let log = ApprovalLog::open(&dir.join("approvals.jsonl")).unwrap();
        log.begin("d1", "h1", 10).unwrap();
        assert!(log.finish("d1", "other", "used").is_err());
        assert!(log.finish("d1", "h1", "used").is_ok());
        assert!(log.finish("d1", "h1", "used").is_err());
        // A later request for the same call is a new one.
        log.begin("d1", "h4", 20).unwrap();
        assert_eq!(log.get("d1"), Some(("h4".to_owned(), 20)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_torn_or_unreadable_line_can_lose_an_ask_but_never_grant_one() {
        let dir = temp("torn");
        let path = dir.join("approvals.jsonl");
        std::fs::write(&path, "{\"digest\":\"d1\",\"e\":\"open\",\"handle\":\"h1\"}\nnot json\n{\"digest\":\"d2\",\"e\":\"open\",\"han").unwrap();
        let log = ApprovalLog::open(&path).unwrap();
        assert_eq!(log.get("d1"), Some(("h1".to_owned(), 0)));
        assert_eq!(log.get("d2"), None);
        log.begin("d5", "h5", 5).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().ends_with("\"handle\":\"h5\"}\n"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_full_table_ends_the_asks_nothing_can_spend_any_more_and_keeps_the_rest() {
        let dir = temp("prune");
        let path = dir.join("approvals.jsonl");
        let log = ApprovalLog::open_with_limits(&path, APPROVALS_MAX_BYTES, 3).unwrap();
        log.begin("d1", "h1", 100).unwrap();
        log.begin("d2", "h2", 200).unwrap();
        log.begin("d3", "h3", 100 + APPROVAL_TTL_SECS + 50).unwrap();
        // Full, and nothing is old enough to end yet.
        assert_eq!(log.reserve("d4", 100 + APPROVAL_TTL_SECS), Err("approvals-full"));
        assert_eq!(log.begin("d4", "h4", 100 + APPROVAL_TTL_SECS), Err("approvals-full"));
        // A digest that is already open never needs room.
        assert_eq!(log.reserve("d2", 100 + APPROVAL_TTL_SECS), Ok(()));
        // Later, d1 and d2 are older than the time limit: they go, d3 stays.
        let now = 200 + APPROVAL_TTL_SECS + 1;
        assert_eq!(log.reserve("d4", now), Ok(()));
        assert_eq!((log.get("d1"), log.get("d2")), (None, None));
        assert_eq!(log.get("d3"), Some(("h3".to_owned(), 100 + APPROVAL_TTL_SECS + 50)));
        log.begin("d4", "h4", now).unwrap();
        drop(log);
        // What was ended stays ended after a restart.
        let log = ApprovalLog::open_with_limits(&path, APPROVALS_MAX_BYTES, 3).unwrap();
        assert_eq!((log.get("d1"), log.get("d2")), (None, None));
        assert_eq!(log.open_count(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_log_with_no_room_left_in_the_file_refuses_before_a_card_goes_up() {
        let dir = temp("bytes");
        // Room for one event of the real size and a little more, but not for the 256 bytes kept free.
        let log = ApprovalLog::open_with(&dir.join("approvals.jsonl"), 300).unwrap();
        log.begin("d1", "h1", 10).unwrap();
        assert_eq!(log.reserve("d2", 10), Err("approvals-full"));
        // An ask that is already open needs no new line, but the file is still too full to promise one.
        assert_eq!(log.reserve("d1", 10), Err("approvals-full"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_full_log_refuses_rather_than_forgets() {
        let dir = temp("full");
        let log = ApprovalLog::open_with(&dir.join("approvals.jsonl"), 300).unwrap();
        log.begin("d1", "h1", 10).unwrap();
        assert!(log.begin("d2", "h2", 10).is_err());
        assert_eq!(log.get("d2"), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_note_is_short_ascii() {
        let args = canon::json::parse_strict(b"{}").unwrap();
        let digest = "ab".repeat(32);
        let text = note(&AskRecord { call_id: "c", class: "net", tool: "web_fetch", digest_sha256: &digest, args: &args });
        assert!(text.len() <= 120 && text.is_ascii() && text.contains("web_fetch") && text.contains("abababababababab"));
    }

    #[test]
    fn block_on_finishes_a_future_woken_from_another_thread() {
        let (send, receive) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let _ = send.send(7);
        });
        assert_eq!(block_on(receive).unwrap(), 7);
    }
}
