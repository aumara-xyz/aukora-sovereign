// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sovereign door serve --socket PATH --policy FILE`: the Rust door for the engine's crossings.
//!
//! The DSH door plugin (engine/plugins/aukora-door) sends every call that is not workspace-local here, one request
//! line per connection. The door believes nothing in the request: it checks the peer first, rate-limits, parses
//! strictly, re-derives the class by channel, recomputes the digest over the bytes it will act on, applies the policy,
//! consumes the call id durably and, only if the policy says allow, executes the crossing itself. Every error is a
//! refusal.
//!
//! What it is not: a wall. The OS confines the engine; this process is where authority and keys live.

mod approver;
mod classify;
mod cutback;
mod fetch;
mod files;
mod ledger;
mod memory;
mod peer;
mod policy;
mod standing;
mod starter;
mod taint;
mod wire;

use approver::{Approval, ApprovalLog, Approver, AskRecord, GateApprover};
use canon::{Refusal, Result};
use classify::Class;
use ledger::{AskLog, Ledger};
use peer::Peer;
use policy::{Action, PeerRule, Policy};
use serde_json::json;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wire::{Decision, Request};

const MAX_CONNECTIONS: usize = 32;
const READ_DEADLINE: Duration = Duration::from_secs(5);
const WRITE_DEADLINE: Duration = Duration::from_secs(10);
/// How long a `whoami` that said "not the owner" holds before the door asks the Kira service again.
const TOKEN_CHECK_EVERY: Duration = Duration::from_secs(30);
/// How often an approver settles what the owner left unanswered.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

fn refuse(reason: &'static str) -> Refusal {
    Refusal { organ: "supervisor", reason }
}

/// A token bucket: `rate` requests per second sustained, `burst` at once.
struct Bucket {
    state: Mutex<(f64, Instant)>,
    rate: f64,
    burst: f64,
}

impl Bucket {
    fn new(rate: u32, burst: u32) -> Self {
        Self { state: Mutex::new((f64::from(burst), Instant::now())), rate: f64::from(rate), burst: f64::from(burst) }
    }

    fn take(&self) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        let (tokens, last) = &mut *guard;
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * self.rate).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Releases a connection slot when its thread ends, however it ends.
struct Slot(Arc<Door>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The door: policy, the durable ledgers, the rate limit and the runtime the net executor uses.
pub struct Door {
    policy: Policy,
    ledger: Ledger,
    asks: AskLog,
    /// The owner path for `ask` classes, when the node supplies one; without it an ask is only recorded.
    owner: Option<Owner>,
    bucket: Bucket,
    runtime: tokio::runtime::Runtime,
    active: AtomicUsize,
    /// When the Kira token was last confirmed not to be the owner's, and how long that confirmation holds.
    memory_checked: Mutex<Option<Instant>>,
    token_check_every: Duration,
    /// The slider and standing grants, when the policy has a `standing` section (`standing.rs`).
    standing: Option<standing::Standing>,
    /// Fetched content reached the engine: its next net calls and memory writes ask (`taint.rs`).
    taint: taint::Taint,
}

/// The approver, the door's durable memory of what it has asked, and the lock that keeps one ask at a time.
struct Owner {
    approver: Arc<dyn Approver>,
    log: ApprovalLog,
    turn: Mutex<()>,
}

impl Door {
    /// Open the state folder (a real directory of ours, 0700), lock and load the consumed ids, open the asks log.
    #[cfg(test)]
    pub fn open(policy: Policy) -> Result<Door> {
        Door::open_with(policy, None)
    }

    /// As `open`, with an approver that raises owner requests for `ask` classes.
    pub fn open_with(policy: Policy, approver: Option<Arc<dyn Approver>>) -> Result<Door> {
        files::private_dir(&policy.state_dir, "door-state")?;
        let ledger = Ledger::open(&policy.state_dir)?;
        let asks = AskLog::open(&policy.state_dir.join("asks.jsonl"))?;
        let owner = match approver {
            Some(approver) => Some(Owner { approver, log: ApprovalLog::open(&policy.state_dir.join("approvals.jsonl"))?, turn: Mutex::new(()) }),
            None => None,
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| refuse("door-state"))?;
        let bucket = Bucket::new(policy.rate_per_second, policy.rate_burst);
        let standing = policy.standing.as_ref().map(|files| standing::Standing::open(files, &policy.state_dir)).transpose()?;
        let taint = taint::Taint::new(&policy.state_dir);
        Ok(Door { policy, ledger, asks, owner, bucket, runtime, active: AtomicUsize::new(0), memory_checked: Mutex::new(None), token_check_every: TOKEN_CHECK_EVERY, standing, taint })
    }

    fn peer_allowed(&self, peer: Peer) -> bool {
        match (&self.policy.peers, peer) {
            (PeerRule::SocketPermissions, _) => true,
            (PeerRule::Uids(allowed), Peer::Uid(uid)) => allowed.contains(&uid),
            (PeerRule::Uids(_), Peer::Unknown) => false,
        }
    }

    /// Decide one request line. Returns the call id to echo and the decision. Never panics on input.
    pub fn judge(&self, peer: Peer, line: &[u8]) -> (String, Decision) {
        if !self.peer_allowed(peer) {
            return ("unknown".to_owned(), Decision::Deny("peer".into()));
        }
        let guess = wire::salvage_call_id(line);
        let request = match wire::parse_request(line) {
            Ok(request) => request,
            Err(code) => return (guess, Decision::Deny(code.into())),
        };
        let id = request.call_id.clone();
        let derived = classify::derive(&request.tool, &request.args, &self.policy.workspace_roots);
        let class = match classify::settle(&request.claimed_class, derived) {
            Ok(class) => class,
            Err(code) => return (id, Decision::Deny(code.into())),
        };
        let action = self.policy.action(class);
        if action == Action::Deny && request.tool != "kira_taint" {
            // A refusal costs the engine nothing to repeat and burns no id.
            return (id, Decision::Deny(format!("{}-denied", class.name())));
        }
        match self.ledger.consume(&id) {
            Ok(true) => {}
            Ok(false) => return (id, Decision::Deny("replay".into())),
            Err(_) => return (id, Decision::Deny("door-state".into())),
        }
        if request.tool == "kira_taint" {
            return (id, self.taint_control(&request));
        }
        // A tainted engine's net calls and memory writes, and every web-derived write, ask whatever the slider says
        // (taint.rs); they never spend a grant's count. Otherwise, with a slider, a policy allow or ask is decided per
        // call; a call the door would refuse anyway is refused here.
        let action = if self.taint_asks(class, &request) {
            // Never an ask about a call the door would refuse anyway (a host off the allowlist stays a refusal).
            if let Err(code) = self.preflight(class, &request) {
                return (id, Decision::Deny(code));
            }
            Action::Ask
        } else {
            match self.settle(class, &request, action) {
                Ok(action) => action,
                Err(code) => return (id, Decision::Deny(code)),
            }
        };
        let decision = match action {
            Action::Ask => self.ask(class, &request),
            Action::Allow => self.execute(class, &request),
            Action::Deny => Decision::Deny(format!("{}-denied", class.name())),
        };
        (id, decision)
    }

    fn ask(&self, class: Class, request: &Request) -> Decision {
        match &self.owner {
            Some(owner) => self.ask_owner(owner, class, request),
            None => self.ask_recorded(class, request),
        }
    }

    /// Without an approver an ask is written down for whatever picks it up, and nothing runs.
    fn ask_recorded(&self, class: Class, request: &Request) -> Decision {
        match self.asks.record(&self.ask_line(class, request)) {
            Ok(()) => Decision::Ask(format!("ask-{}", class.name())),
            Err(_) => Decision::Deny("asks-full".into()),
        }
    }

    fn ask_line(&self, class: Class, request: &Request) -> String {
        let at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        json!({
            "at": at,
            "call_id": request.call_id,
            "class": class.name(),
            "tool": request.tool,
            "digest_sha256": wire::call_digest(&request.tool, &request.args_bytes),
        })
        .to_string()
    }

    /// What the door would refuse anyway, found before the owner is asked: a class with no executor, bad arguments, a
    /// host off the allowlist, a memory call above the engine's ceilings.
    fn preflight(&self, class: Class, request: &Request) -> std::result::Result<(), String> {
        match class {
            Class::Net => {
                let net = self.policy.net.as_ref().filter(|_| request.tool == "web_fetch").ok_or("no-executor")?;
                fetch::check_url(net, net_url(request)?).map(|_| ()).map_err(str::to_owned)
            }
            Class::Memory => {
                self.policy.memory.as_ref().ok_or("no-executor")?;
                memory::preflight(&request.tool, &request.args).map(|_| ())
            }
            _ => Err("no-executor".into()),
        }
    }

    /// An ask with an owner behind it. The approval belongs to the call digest, not to the call id: the model repeats
    /// the identical call (a fresh id) once the owner has approved, and that one call then runs. The approval is spent,
    /// durably, before the call executes; a crash in between costs the run, never repeats it.
    fn ask_owner(&self, owner: &Owner, class: Class, request: &Request) -> Decision {
        if let Err(code) = self.preflight(class, request) {
            return Decision::Deny(code);
        }
        // The owner reads the URL as the model wrote it and the door requests the parsed one (`%2e%2e` and `\` resolve,
        // tabs and newlines drop out): no card goes up for a URL whose two readings differ.
        if class == Class::Net && net_url(request).is_ok_and(|url| !fetch::reads_as_written(url)) {
            return Decision::Deny("url-not-canonical".into());
        }
        // One ask at a time: two concurrent repeats of an approved call cannot both spend it, and one call is
        // never raised twice.
        let _turn = owner.turn.lock().unwrap_or_else(PoisonError::into_inner);
        let digest = wire::call_digest(&request.tool, &request.args_bytes);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        if let Some((handle, raised)) = owner.log.get(&digest) {
            // An answer is good for a limited time; an older request is raised again, whatever the approver says.
            let state = if now.saturating_sub(raised) > approver::APPROVAL_TTL_SECS { Approval::Gone } else { owner.approver.state(&handle) };
            match state {
                Approval::Approved => {
                    // What the door can know will fail is found before the approval is spent: a Kira that is down, or a
                    // token that is the owner's now, must not cost the owner a passkey approval for a call that never ran.
                    if let Err(code) = self.preflight_for_clear(class, request) {
                        return Decision::Deny(code);
                    }
                    return match owner.log.finish(&digest, &handle, "used") {
                        Ok(()) => self.execute(class, request),
                        Err(code) => Decision::Deny(code.into()),
                    };
                }
                Approval::Pending => return Decision::Ask(format!("ask-{}:pending", class.name())),
                Approval::Gone => {
                    if let Err(code) = owner.log.finish(&digest, &handle, "gone") {
                        return Decision::Deny(code.into());
                    }
                }
            }
        }
        // Room first: no card goes up for an ask that could not be remembered.
        if let Err(code) = owner.log.reserve(&digest, now) {
            return Decision::Deny(code.into());
        }
        let ask = AskRecord { call_id: &request.call_id, class: class.name(), tool: &request.tool, digest_sha256: &digest, args: &request.args };
        let handle = match owner.approver.request(&ask) {
            Ok(handle) => handle,
            Err(code) => return Decision::Deny(code.into()),
        };
        if let Err(code) = owner.log.begin(&digest, &handle, now) {
            return Decision::Deny(code.into());
        }
        // The audit trail of what was asked; the approval itself lives in the gate and the approvals log.
        let _ = self.asks.record(&self.ask_line(class, request));
        Decision::Ask(format!("ask-{}", class.name()))
    }

    fn execute(&self, class: Class, request: &Request) -> Decision {
        match class {
            Class::Net => self.execute_net(request),
            Class::Memory => match &self.policy.memory {
                Some(memory) => match memory::preflight(&request.tool, &request.args)
                    .and_then(|_| self.memory_token_ok(memory))
                    .and_then(|()| memory::forward(memory, &request.tool, &request.args))
                    .and_then(|value| self.taint_after(Class::Memory, request, &value).map(|()| value))
                {
                    // The whole reply line must fit what the plugin accepts (as for a fetch): a list the plugin would reject as
                    // too large is refused here, with a reason the model can act on (ask for fewer).
                    Ok(value) if value.to_string().len() > self.policy.max_frame_bytes.saturating_sub(2048) => Decision::Deny("reply-too-large".into()),
                    Ok(value) => Decision::Allow { value, text: None },
                    Err(code) => Decision::Deny(code),
                },
                None => Decision::Deny("no-executor".into()),
            },
            _ => Decision::Deny("no-executor".into()),
        }
    }

    /// The Kira token is not the owner's, as the service itself says, within the last `token_check_every`. A token that
    /// was re-issued as the owner's, or a service that does not answer, stops the memory crossings at the next call.
    fn memory_token_ok(&self, memory: &policy::MemoryPolicy) -> std::result::Result<(), String> {
        if self.memory_checked.lock().unwrap_or_else(PoisonError::into_inner).is_some_and(|at| at.elapsed() < self.token_check_every) {
            return Ok(());
        }
        // Asked outside the lock: a service that is slow to answer must not stall every other call behind this one.
        let verdict = memory::check_token(memory);
        let mut checked = self.memory_checked.lock().unwrap_or_else(PoisonError::into_inner);
        *checked = verdict.is_ok().then(Instant::now);
        verdict
    }

    /// The door's own checks, plus (for memory) that the Kira token is not the owner's: what a call must pass before
    /// the slider may spend a count on it, so a service that is down or an owner token burns no grant.
    fn preflight_for_clear(&self, class: Class, request: &Request) -> std::result::Result<(), String> {
        self.preflight(class, request)?;
        match (&self.policy.memory, class) {
            (Some(memory), Class::Memory) => self.memory_token_ok(memory),
            _ => Ok(()),
        }
    }

    fn execute_net(&self, request: &Request) -> Decision {
        let (Some(net), "web_fetch") = (&self.policy.net, request.tool.as_str()) else { return Decision::Deny("no-executor".into()) };
        let url = match net_url(request) {
            Ok(url) => url,
            Err(code) => return Decision::Deny(code),
        };
        // The whole reply line must fit what the plugin accepts, so a full-size page is cut here, not refused after it ran.
        let reply_limit = self.policy.max_frame_bytes.saturating_sub(2048);
        // The page reaches the engine only once the taint it brings is durable.
        match self.runtime.block_on(fetch::fetch(net, url, reply_limit)).and_then(|value| self.taint_after(Class::Net, request, &value).map(|()| value)) {
            Ok(value) => Decision::Allow { value, text: None },
            Err(code) => Decision::Deny(code),
        }
    }

    /// Serve one accepted connection: the caller is whoever the kernel says it is (tests; `serve` knows the peer already).
    #[cfg(test)]
    pub fn connection(&self, stream: UnixStream) {
        let peer = peer::of(&stream);
        self.serve_stream(stream, peer);
    }

    /// Check the peer and the rate first, then read one line, decide, write one reply, close.
    pub fn serve_stream(&self, mut stream: UnixStream, peer: Peer) {
        if !self.peer_allowed(peer) {
            write_reply(&mut stream, &wire::reply_line("unknown", &Decision::Deny("peer".into())));
            return;
        }
        if !self.bucket.take() {
            write_reply(&mut stream, &wire::reply_line("unknown", &Decision::Deny("rate-limited".into())));
            return;
        }
        let reply = match read_line(&mut stream, self.policy.max_frame_bytes) {
            Read1::Gone => return,
            Read1::TooLarge => wire::reply_line("unknown", &Decision::Deny("too-large".into())),
            Read1::TrailingBytes => wire::reply_line("unknown", &Decision::Deny("bad-request".into())),
            Read1::Line(line) => {
                let (id, decision) = self.judge(peer, &line);
                wire::reply_line(&id, &decision)
            }
        };
        write_reply(&mut stream, &reply);
    }
}

/// The one argument `web_fetch` takes.
fn net_url(request: &Request) -> std::result::Result<&str, String> {
    use canon::json::ValueView;
    match (request.args.view(), request.args.get("url").map(canon::json::Value::view)) {
        (ValueView::Object(members), Some(ValueView::Text(url))) if members.len() == 1 => Ok(url),
        _ => Err("bad-args".into()),
    }
}

/// Write the whole reply within one overall deadline (a reader that never reads cannot hold the slot).
fn write_reply(stream: &mut UnixStream, reply: &str) {
    let started = Instant::now();
    let bytes = reply.as_bytes();
    let mut sent = 0;
    while sent < bytes.len() {
        let Some(left) = WRITE_DEADLINE.checked_sub(started.elapsed()) else { return };
        if stream.set_write_timeout(Some(left.max(Duration::from_millis(1)))).is_err() {
            return;
        }
        match stream.write(&bytes[sent..]) {
            Ok(0) | Err(_) => return,
            Ok(n) => sent += n,
        }
    }
    let _ = stream.flush();
}

enum Read1 {
    Line(Vec<u8>),
    TooLarge,
    TrailingBytes,
    Gone,
}

/// Read up to the first newline within a size cap and an overall deadline (a trickling client gets nothing).
fn read_line(stream: &mut UnixStream, limit: usize) -> Read1 {
    let started = Instant::now();
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let Some(left) = READ_DEADLINE.checked_sub(started.elapsed()) else { return Read1::Gone };
        if stream.set_read_timeout(Some(left.max(Duration::from_millis(1)))).is_err() {
            return Read1::Gone;
        }
        let read = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Read1::Gone,
            Ok(n) => n,
        };
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(newline) = buffer.iter().position(|b| *b == b'\n') {
            return if newline + 1 > limit {
                Read1::TooLarge
            } else if newline + 1 == buffer.len() {
                Read1::Line(buffer)
            } else {
                Read1::TrailingBytes
            };
        }
        if buffer.len() > limit {
            return Read1::TooLarge;
        }
    }
}

fn bind(socket: &Path, world_connectable: bool) -> Result<UnixListener> {
    if let Ok(meta) = std::fs::symlink_metadata(socket) {
        if !meta.file_type().is_socket() || UnixStream::connect(socket).is_ok() {
            return Err(refuse("door-socket"));
        }
        std::fs::remove_file(socket).map_err(|_| refuse("door-socket"))?;
    }
    let listener = UnixListener::bind(socket).map_err(|_| refuse("door-socket"))?;
    // Created with the umask's (stricter) mode; opened up only after the bind, and only when peers are checked by uid.
    let mode = if world_connectable { 0o666 } else { 0o600 };
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(mode)).map_err(|_| refuse("door-socket"))?;
    Ok(listener)
}

/// Check the policy against this platform and user, open the state, bind the socket.
fn start(
    policy: Policy,
    socket: &Path,
    approver: Option<Arc<dyn Approver>>,
    grants: Option<standing::GrantSource>,
) -> Result<(Arc<Door>, UnixListener)> {
    let by_uid = matches!(policy.peers, PeerRule::Uids(_));
    if by_uid && !peer::peercred_supported() {
        // Without kernel peer credentials a uid allowlist would silently allow everyone.
        return Err(refuse("door-policy"));
    }
    policy.check_peer_uids(files::euid())?;
    files::parent_not_writable_by_others(socket, "door-socket")?;
    let mut door = Door::open_with(policy, approver)?;
    if let (Some(grants), Some(standing)) = (grants, door.standing.as_mut()) {
        standing.grants_from(grants);
    }
    let door = Arc::new(door);
    // A door whose Kira token is the owner's would hand the engine owner powers: it does not start. A service that is
    // not up yet is not a reason to stay down; the first memory call checks again.
    if let Some(memory) = &door.policy.memory {
        match memory::check_token(memory) {
            Ok(()) => *door.memory_checked.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now()),
            Err(code) if code == "kira-token-owner" => return Err(refuse("door-policy")),
            Err(code) => eprintln!("door: the Kira token was not checked at start ({code}); memory calls check it first"),
        }
    }
    let listener = bind(socket, by_uid)?;
    if door.owner.is_some() {
        let door = Arc::clone(&door);
        std::thread::Builder::new()
            .name("door-sweep".into())
            .spawn(move || loop {
                std::thread::sleep(SWEEP_EVERY);
                if let Some(owner) = &door.owner {
                    owner.approver.sweep();
                }
            })
            .map_err(|_| refuse("door-state"))?;
    }
    Ok((door, listener))
}

/// Accept connections until the listener fails for good.
fn accept_loop(door: &Arc<Door>, listener: &UnixListener) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            // Out of descriptors, say: do not spin on the same error.
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let peer = peer::of(&stream);
        if !door.peer_allowed(peer) {
            // Turned away before it costs a slot or a thread.
            write_reply(&mut stream, &wire::reply_line("unknown", &Decision::Deny("peer".into())));
            continue;
        }
        if door.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            door.active.fetch_sub(1, Ordering::SeqCst);
            write_reply(&mut stream, &wire::reply_line("unknown", &Decision::Deny("busy".into())));
            continue;
        }
        let slot = Slot(Arc::clone(door));
        let _ = std::thread::Builder::new().spawn(move || {
            let slot = slot;
            slot.0.serve_stream(stream, peer);
        });
    }
}

/// Serve until killed.
pub fn serve(policy: Policy, socket: &Path) -> Result<()> {
    let (door, listener) = start(policy, socket, None, None)?;
    eprintln!("door: serving on {}", socket.display());
    accept_loop(&door, &listener);
    Ok(())
}

/// Run the door inside the node when the config directory holds `door-policy-v1.json` (absent: no door). The door's
/// `ask` classes then raise real owner requests in this node's gate. A door that cannot start is logged and the node
/// carries on without it; the engine's crossings are refused while it is down. Everything past reading the file runs
/// on the door's own thread: the door owns a tokio runtime, which must never be dropped inside the node's.
pub fn start_in_node(config: &crate::config::NodeConfig, ledger: Arc<crate::adapters::HostLedger>, gate: Arc<crate::adapters::GateAdapter>) {
    let log = |refusal: Refusal| eprintln!("door: not started: {}:{}", refusal.organ, refusal.reason);
    let text = match config.door_policy_text() {
        Ok(Some(text)) => text,
        Ok(None) => return,
        Err(refusal) => return log(refusal),
    };
    let spawned = std::thread::Builder::new().name("door".into()).spawn(move || {
        let started = Policy::parse(&text).and_then(|policy| {
            let socket = policy.socket.clone().ok_or_else(|| refuse("door-policy"))?;
            let approver: Arc<dyn Approver> = Arc::new(GateApprover::new(gate.clone(), ledger.clone()));
            // In the node the slider's grants are the owner-applied `door/standing-grants.json`, nothing else.
            let source_gate = gate.clone();
            let grants: standing::GrantSource =
                Box::new(move || approver::block_on(source_gate.approved_target(laya::grant::GRANT_TARGET)).ok().flatten());
            let terms = policy.starter.clone();
            start(policy, &socket, Some(approver), Some(grants)).map(|(door, listener)| (door, listener, socket, terms))
        });
        match started {
            Ok((door, listener, socket, terms)) => {
                // The starter card is raised only for a door that is actually serving.
                if let Some(terms) = terms {
                    let spawned = std::thread::Builder::new()
                        .name("door-starter".into())
                        .spawn(move || starter::keep(gate, ledger, terms));
                    if spawned.is_err() {
                        eprintln!("door: the starter grants keeper did not start; nothing clears without grants");
                    }
                }
                eprintln!("door: serving on {} (owner approvals through the gate)", socket.display());
                accept_loop(&door, &listener);
            }
            Err(refusal) => eprintln!("door: not started: {}:{}", refusal.organ, refusal.reason),
        }
    });
    if spawned.is_err() {
        log(refuse("door-state"));
    }
}

/// Where the in-node door keeps its taint (`taint.rs`), for the owner's page: `None` when the node has no door.
fn node_taint(config: &crate::config::NodeConfig) -> Result<Option<taint::Taint>> {
    let Some(text) = config.door_policy_text()? else { return Ok(None) };
    Ok(Some(taint::Taint::new(&Policy::parse(&text)?.state_dir)))
}

/// The engine's taint as the owner sees it: `Some((since_ms, cause))` while fetched content holds its net calls and
/// memory writes to a card each, `None` when clean. `Err` when the node has no door.
pub fn taint_status(config: &crate::config::NodeConfig) -> Result<Option<(i64, String)>> {
    match node_taint(config)?.ok_or_else(|| refuse("door-not-configured"))?.state() {
        taint::State::Clean => Ok(None),
        taint::State::Tainted { since_ms, cause } => Ok(Some((since_ms, cause))),
    }
}

/// The owner's action that ends the taint (`POST /api/engine/door/clear-taint`). Returns whether it was tainted.
pub fn clear_taint(config: &crate::config::NodeConfig) -> Result<bool> {
    let cleared = node_taint(config)?.ok_or_else(|| refuse("door-not-configured"))?.clear()?;
    eprintln!("door: the owner cleared the engine's taint (was tainted: {cleared})");
    Ok(cleared)
}

/// Whether the door would start on this policy text (the engine controller treats anything else as no door).
pub fn policy_parses(text: &str) -> bool {
    Policy::parse(text).is_ok_and(|policy| policy.socket.is_some())
}

/// `sovereign door serve --socket PATH --policy FILE`.
pub fn run(arguments: &[OsString]) -> Result<()> {
    let [command, socket_flag, socket, policy_flag, policy] = arguments else { return Err(refuse("usage")) };
    if command != "serve" || socket_flag != "--socket" || policy_flag != "--policy" {
        return Err(refuse("usage"));
    }
    serve(Policy::load(Path::new(policy))?, Path::new(socket))
}

#[cfg(test)]
mod tests;
