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

mod classify;
mod fetch;
mod files;
mod ledger;
mod memory;
mod peer;
mod policy;
mod wire;

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
    bucket: Bucket,
    runtime: tokio::runtime::Runtime,
    active: AtomicUsize,
}

impl Door {
    /// Open the state folder (a real directory of ours, 0700), lock and load the consumed ids, open the asks log.
    pub fn open(policy: Policy) -> Result<Door> {
        files::private_dir(&policy.state_dir, "door-state")?;
        let ledger = Ledger::open(&policy.state_dir)?;
        let asks = AskLog::open(&policy.state_dir.join("asks.jsonl"))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| refuse("door-state"))?;
        let bucket = Bucket::new(policy.rate_per_second, policy.rate_burst);
        Ok(Door { policy, ledger, asks, bucket, runtime, active: AtomicUsize::new(0) })
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
        if action == Action::Deny {
            // A refusal costs the engine nothing to repeat and burns no id.
            return (id, Decision::Deny(format!("{}-denied", class.name())));
        }
        match self.ledger.consume(&id) {
            Ok(true) => {}
            Ok(false) => return (id, Decision::Deny("replay".into())),
            Err(_) => return (id, Decision::Deny("door-state".into())),
        }
        let decision = match action {
            Action::Ask => self.ask(class, &request),
            Action::Allow => self.execute(class, &request),
            Action::Deny => Decision::Deny(format!("{}-denied", class.name())),
        };
        (id, decision)
    }

    fn ask(&self, class: Class, request: &Request) -> Decision {
        let at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let line = json!({
            "at": at,
            "call_id": request.call_id,
            "class": class.name(),
            "tool": request.tool,
            "digest_sha256": wire::call_digest(&request.tool, &request.args_bytes),
        })
        .to_string();
        match self.asks.record(&line) {
            Ok(()) => Decision::Ask(format!("ask-{}", class.name())),
            Err(_) => Decision::Deny("asks-full".into()),
        }
    }

    fn execute(&self, class: Class, request: &Request) -> Decision {
        match class {
            Class::Net => self.execute_net(request),
            Class::Memory => match &self.policy.memory {
                Some(memory) => match memory::forward(memory, &request.tool, &request.args) {
                    Ok(value) => Decision::Allow { value, text: None },
                    Err(code) => Decision::Deny(code),
                },
                None => Decision::Deny("no-executor".into()),
            },
            _ => Decision::Deny("no-executor".into()),
        }
    }

    fn execute_net(&self, request: &Request) -> Decision {
        use canon::json::ValueView;
        let (Some(net), "web_fetch") = (&self.policy.net, request.tool.as_str()) else { return Decision::Deny("no-executor".into()) };
        let url = match (request.args.view(), request.args.get("url").map(canon::json::Value::view)) {
            (ValueView::Object(members), Some(ValueView::Text(url))) if members.len() == 1 => url,
            _ => return Decision::Deny("bad-args".into()),
        };
        // The whole reply line must fit what the plugin accepts, so a full-size page is cut here, not refused after it ran.
        let reply_limit = self.policy.max_frame_bytes.saturating_sub(2048);
        match self.runtime.block_on(fetch::fetch(net, url, reply_limit)) {
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

/// Serve until killed.
pub fn serve(policy: Policy, socket: &Path) -> Result<()> {
    let by_uid = matches!(policy.peers, PeerRule::Uids(_));
    if by_uid && !peer::peercred_supported() {
        // Without kernel peer credentials a uid allowlist would silently allow everyone.
        return Err(refuse("door-policy"));
    }
    policy.check_peer_uids(files::euid())?;
    files::parent_not_writable_by_others(socket, "door-socket")?;
    let door = Arc::new(Door::open(policy)?);
    let listener = bind(socket, by_uid)?;
    eprintln!("door: serving on {}", socket.display());
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
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
        let slot = Slot(Arc::clone(&door));
        let _ = std::thread::Builder::new().spawn(move || {
            let slot = slot;
            slot.0.serve_stream(stream, peer);
        });
    }
    Ok(())
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
mod tests {
    use super::wire::test_line as line;
    use super::*;
    use std::io::BufRead;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-door-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn policy_text(state: &Path, mode: &str, classes: &str, extra: &str) -> String {
        format!(
            "{{\"v\":1,\"peers\":{mode},\"workspace_roots\":[\"/sandbox\"],\"state_dir\":\"{}\",\"classes\":{{{classes}}}{extra}}}",
            state.display()
        )
    }

    fn door(name: &str, classes: &str, extra: &str) -> (Door, std::path::PathBuf) {
        let dir = temp(name);
        let text = policy_text(&dir.join("state"), "{\"mode\":\"peercred\",\"uids\":[1001]}", classes, extra);
        (Door::open(Policy::parse(&text).unwrap()).unwrap(), dir)
    }

    const FETCH: &str = "{\"url\":\"https://example.org/\"}";

    fn denied(decision: &Decision) -> &str {
        match decision {
            Decision::Deny(code) => code,
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn a_digest_that_does_not_match_is_refused_and_consumes_nothing() {
        let (door, dir) = door("digest", "\"net\":\"deny\"", "");
        let good = String::from_utf8(line("call-1", "web_fetch", FETCH, "net")).unwrap();
        let forged = good.replace(&wire::call_digest("web_fetch", FETCH.as_bytes()), &"0".repeat(64));
        let (id, decision) = door.judge(Peer::Uid(1001), forged.as_bytes());
        assert_eq!((id.as_str(), denied(&decision)), ("call-1", "digest-mismatch"));
        assert_eq!(door.ledger.len(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_replayed_call_id_is_refused_even_after_a_restart() {
        let dir = temp("replay");
        let text = policy_text(&dir.join("state"), "{\"mode\":\"peercred\",\"uids\":[1001]}", "\"plugin\":\"ask\"", "");
        let request = line("call-7", "plugin_manager", "{\"action\":\"install\"}", "plugin");
        {
            let door = Door::open(Policy::parse(&text).unwrap()).unwrap();
            let (_, first) = door.judge(Peer::Uid(1001), &request);
            assert!(matches!(first, Decision::Ask(_)), "{first:?}");
            let (_, second) = door.judge(Peer::Uid(1001), &request);
            assert_eq!(denied(&second), "replay");
        }
        let door = Door::open(Policy::parse(&text).unwrap()).unwrap();
        let (_, third) = door.judge(Peer::Uid(1001), &request);
        assert_eq!(denied(&third), "replay");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_peer_that_is_not_on_the_allowlist_is_refused_before_anything_is_read() {
        let (door, dir) = door("peer", "\"plugin\":\"ask\"", "");
        let request = line("call-1", "plugin_manager", "{}", "plugin");
        for peer in [Peer::Uid(0), Peer::Uid(1002), Peer::Unknown] {
            let (_, decision) = door.judge(peer, &request);
            assert_eq!(denied(&decision), "peer", "{peer:?}");
        }
        assert_eq!(door.ledger.len(), 0);
        let (_, allowed) = door.judge(Peer::Uid(1001), &request);
        assert!(matches!(allowed, Decision::Ask(_)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unknown_or_dishonest_class_is_refused() {
        let (door, dir) = door("class", "\"net\":\"deny\",\"memory\":\"deny\"", "");
        let judge = |id: &str, tool: &str, args: &str, class: &str| {
            let (_, decision) = door.judge(Peer::Uid(1001), &line(id, tool, args, class));
            decision
        };
        assert_eq!(denied(&judge("a1", "web_fetch", FETCH, "quantum")), "bad-class");
        assert_eq!(denied(&judge("a2", "web_fetch", FETCH, "local")), "bad-class");
        assert_eq!(denied(&judge("a3", "web_fetch", FETCH, "memory")), "class-mismatch");
        assert_eq!(denied(&judge("a4", "kira_recall", "{\"query\":\"x\"}", "net")), "class-mismatch");
        // A tool the door knows that the plugin calls unknown is served under the door's class.
        assert_eq!(denied(&judge("a5", "kira_recall", "{\"query\":\"x\"}", "unknown")), "memory-denied");
        // A tool nobody knows is a crossing nobody allowed.
        assert_eq!(denied(&judge("a6", "totally_new_tool", "{}", "unknown")), "unknown-denied");
        // A call the door considers local never needed the door.
        assert_eq!(denied(&judge("a7", "read", "{\"file_path\":\"a.txt\"}", "fs-outside")), "class-mismatch");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn float_arguments_are_refused() {
        let (door, dir) = door("float", "\"net\":\"deny\"", "");
        let (_, decision) = door.judge(Peer::Uid(1001), &line("call-1", "write", "{\"ratio\":1.5}", "unknown"));
        assert_eq!(denied(&decision), "args-not-canonical");
        assert_eq!(door.ledger.len(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn outside_the_workspace_is_denied_and_a_policy_cannot_allow_it() {
        let (door, dir) = door("fs", "\"fs-outside\":\"deny\"", "");
        let (_, decision) = door.judge(Peer::Uid(1001), &line("call-1", "read", "{\"file_path\":\"/etc/passwd\"}", "fs-outside"));
        assert_eq!(denied(&decision), "fs-outside-denied");
        let text = policy_text(&dir.join("state2"), "{\"mode\":\"peercred\",\"uids\":[1001]}", "\"fs-outside\":\"allow\"", "");
        assert!(Policy::parse(&text).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_ask_is_recorded_for_the_approval_path() {
        let (door, dir) = door("ask", "\"plugin\":\"ask\"", "");
        let (_, decision) = door.judge(Peer::Uid(1001), &line("call-1", "plugin_manager", "{\"action\":\"install\"}", "plugin"));
        assert!(matches!(&decision, Decision::Ask(code) if code == "ask-plugin"));
        let log = std::fs::read_to_string(dir.join("state").join("asks.jsonl")).unwrap();
        let entry: serde_json::Value = serde_json::from_str(log.trim()).unwrap();
        assert_eq!(entry["call_id"], "call-1");
        assert_eq!(entry["class"], "plugin");
        assert_eq!(entry["tool"], "plugin_manager");
        assert_eq!(entry["digest_sha256"], wire::call_digest("plugin_manager", b"{\"action\":\"install\"}"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_net_executor_refuses_hosts_off_the_allowlist_without_touching_the_network() {
        let (door, dir) = door("net", "\"net\":\"allow\"", ",\"net\":{\"hosts\":[\"docs.rs\"]}");
        let judge = |id: &str, tool: &str, args: &str| door.judge(Peer::Uid(1001), &line(id, tool, args, "net")).1;
        assert_eq!(denied(&judge("n1", "web_fetch", "{\"url\":\"https://evil.example/x\"}")), "host-not-allowed");
        assert_eq!(denied(&judge("n2", "web_fetch", "{\"url\":\"http://docs.rs/x\"}")), "url-scheme");
        assert_eq!(denied(&judge("n3", "web_fetch", "{\"url\":\"https://127.0.0.1/\"}")), "host-not-allowed");
        assert_eq!(denied(&judge("n4", "web_fetch", "{\"extra\":1,\"url\":\"https://docs.rs/\"}")), "bad-args");
        assert_eq!(denied(&judge("n5", "web_fetch", "{\"url\":7}")), "bad-args");
        assert_eq!(denied(&judge("n6", "web_search", "{\"query\":\"x\"}")), "no-executor");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn memory_calls_reach_the_service_with_the_doors_token_and_the_engines_ceilings() {
        let dir = temp("memory");
        let socket = dir.join("kira.sock");
        let token = dir.join("door.token");
        std::fs::write(&token, "door-token\n").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let service = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut text = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap()).read_line(&mut text).unwrap();
            let mut stream = stream;
            writeln!(stream, "{}", json!({"ok": true, "result": {"status": "found", "items": []}})).unwrap();
            text
        });
        let extra = format!(",\"memory\":{{\"socket\":\"{}\",\"token_file\":\"{}\"}}", socket.display(), token.display());
        let text = policy_text(&dir.join("state"), "{\"mode\":\"peercred\",\"uids\":[1001]}", "\"memory\":\"allow\"", &extra);
        let door = Door::open(Policy::parse(&text).unwrap()).unwrap();
        // Above the engine's ceiling: refused, and the service is never contacted.
        let owner = "{\"capture\":\"model-generated\",\"form\":\"fact\",\"lane\":\"decision\",\"privacy\":\"builders\",\"scope\":\"auma\",\"subject\":\"s\",\"text\":\"x\"}";
        let (_, refused) = door.judge(Peer::Uid(1001), &line("m1", "kira_remember", owner, "memory"));
        assert_eq!(denied(&refused), "lane-closed");
        let (_, quarantine) = door.judge(Peer::Uid(1001), &line("m2", "kira_quarantine_source", "{\"pubkey\":\"00\"}", "memory"));
        assert_eq!(denied(&quarantine), "owner-only");
        // A read goes through, carrying the door's token.
        let (_, allowed) = door.judge(Peer::Uid(1001), &line("m3", "kira_recall", "{\"query\":\"figurine\"}", "memory"));
        let Decision::Allow { value, .. } = allowed else { panic!("expected allow") };
        assert_eq!(value["status"], "found");
        let seen: serde_json::Value = serde_json::from_str(&service.join().unwrap()).unwrap();
        assert_eq!(seen["token"], "door-token");
        assert_eq!(seen["method"], "recall");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn exchange(door: &Arc<Door>, bytes: &[u8]) -> serde_json::Value {
        let (client, server) = UnixStream::pair().unwrap();
        let door = Arc::clone(door);
        let handle = std::thread::spawn(move || door.connection(server));
        let mut client = client;
        // The door may answer and close before it reads (a refused peer or rate): a failed write is then expected.
        let _ = client.write_all(bytes);
        let mut reply = String::new();
        std::io::BufReader::new(client).read_line(&mut reply).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&reply).unwrap()
    }

    #[test]
    fn over_a_real_socket_pair_one_line_in_one_line_out() {
        let dir = temp("socket");
        let text = policy_text(&dir.join("state"), "{\"mode\":\"socket-permissions\"}", "\"fs-outside\":\"deny\"", ",\"max_frame_bytes\":2048");
        let door = Arc::new(Door::open(Policy::parse(&text).unwrap()).unwrap());
        let reply = exchange(&door, &line("call-1", "read", "{\"file_path\":\"/etc/passwd\"}", "fs-outside"));
        assert_eq!(reply["call_id"], "call-1");
        assert_eq!(reply["decision"], "deny");
        assert_eq!(reply["refusal"], "fs-outside-denied");
        // A line over the cap, and bytes after the newline, are refusals too.
        let big = format!("{}\n", "x".repeat(4096));
        assert_eq!(exchange(&door, big.as_bytes())["refusal"], "too-large");
        let two = [line("c-2", "read", "{}", "fs-outside"), line("c-3", "read", "{}", "fs-outside")].concat();
        assert_eq!(exchange(&door, &two)["refusal"], "bad-request");
        // A request that is JSON but not the protocol is answered under its own call id; unreadable bytes are not.
        let wrong = exchange(&door, b"{\"call_id\":\"c-4\",\"junk\":1}\n");
        assert_eq!((wrong["call_id"].as_str(), wrong["refusal"].as_str()), (Some("c-4"), Some("bad-request")));
        let junk = exchange(&door, b"{\"call_id\":\"c-5\",\"junk\":}\n");
        assert_eq!((junk["call_id"].as_str(), junk["refusal"].as_str()), (Some("unknown"), Some("bad-request")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_uid_allowlist_cannot_start_where_the_kernel_cannot_say_who_called() {
        if peer::peercred_supported() {
            return;
        }
        let dir = temp("platform");
        let text = policy_text(&dir.join("state"), "{\"mode\":\"peercred\",\"uids\":[1001]}", "", "");
        assert!(serve(Policy::parse(&text).unwrap(), &dir.join("door.sock")).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_denied_request_burns_no_id() {
        let (door, dir) = door("noburn", "\"net\":\"deny\"", "");
        let request = line("call-1", "web_fetch", FETCH, "net");
        for _ in 0..3 {
            let (_, decision) = door.judge(Peer::Uid(1001), &request);
            assert_eq!(denied(&decision), "net-denied");
        }
        assert_eq!(door.ledger.len(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_peer_off_the_allowlist_is_answered_without_being_read() {
        let (door, dir) = door("unread", "\"plugin\":\"ask\"", "");
        let door = Arc::new(door);
        let (client, server) = UnixStream::pair().unwrap();
        let worker = Arc::clone(&door);
        let handle = std::thread::spawn(move || worker.serve_stream(server, Peer::Uid(0)));
        // The client never writes; the reply must still come.
        let mut reply = String::new();
        std::io::BufReader::new(client).read_line(&mut reply).unwrap();
        handle.join().unwrap();
        let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(value["refusal"], "peer");
        assert_eq!(door.ledger.len(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn requests_beyond_the_rate_are_refused_before_they_are_read() {
        let dir = temp("rate");
        let text = policy_text(&dir.join("state"), "{\"mode\":\"socket-permissions\"}", "\"fs-outside\":\"deny\"", ",\"rate_per_second\":1,\"rate_burst\":2");
        let door = Arc::new(Door::open(Policy::parse(&text).unwrap()).unwrap());
        let ask = |id: &str| exchange(&door, &line(id, "read", "{\"file_path\":\"/etc/passwd\"}", "fs-outside"));
        assert_eq!(ask("r-1")["refusal"], "fs-outside-denied");
        assert_eq!(ask("r-2")["refusal"], "fs-outside-denied");
        assert_eq!(ask("r-3")["refusal"], "rate-limited");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_bucket_refills_over_time() {
        let bucket = Bucket::new(100, 2);
        assert!(bucket.take() && bucket.take());
        assert!(!bucket.take());
        std::thread::sleep(Duration::from_millis(40));
        assert!(bucket.take());
    }

    #[test]
    fn the_socket_is_bound_once_and_a_stale_one_is_replaced() {
        let dir = temp("bind");
        let path = dir.join("door.sock");
        let first = bind(&path, false).unwrap();
        assert!(bind(&path, false).is_err());
        drop(first);
        let again = bind(&path, false);
        assert!(again.is_ok());
        std::fs::write(dir.join("not-a-socket"), "x").unwrap();
        assert!(bind(&dir.join("not-a-socket"), false).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_state_folder_that_is_a_symlink_is_refused() {
        let dir = temp("symlink-state");
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.join("state");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let text = policy_text(&link, "{\"mode\":\"socket-permissions\"}", "", "");
        assert!(Door::open(Policy::parse(&text).unwrap()).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
