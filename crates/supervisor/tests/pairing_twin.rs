// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local stand-in node for the two-browser co-presence rehearsal (tests/copresence/twin.mjs).
//!
//! Real: `supervisor::pairing` (store, context, copresence::v1 verifier, single spend, device
//! list) and the phone page's CSP and permissions from frontdoor. Stood in: TLS, the owner
//! session check (one fixed bound owner), and the Aura ledger (facts are kept in memory and
//! served at /__facts). Run only by the driver: `cargo test -p supervisor --test pairing_twin
//! -- --ignored --nocapture` with PAIRING_TWIN_ROOT set to the compiled portal folder.

use canon::{
    digest::Digest32,
    ids::{NodeId, SubjectId},
    json::Value,
    Result,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use supervisor::pairing::{FactRecorder, Owner, Pairing, Recorded};

#[derive(Default)]
struct Facts(Mutex<Vec<Value>>);

impl FactRecorder for Facts {
    fn record(&self, _: &SubjectId, body: &Value) -> Result<Recorded> {
        let mut rows = self.0.lock().expect("facts");
        rows.push(body.clone());
        Ok(Recorded {
            sequence: 41 + rows.len() as u64,
            entry: Digest32::sha256(&body.canonical_bytes()),
        })
    }
}

struct Node {
    root: PathBuf,
    pairing: Pairing,
    facts: Facts,
    owner: Owner,
    origin: String,
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let head_end = loop {
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if bytes.len() > 65_536 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&bytes[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_owned(), first.next()?.to_owned());
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = bytes[head_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&buffer[..read]);
    }
    Some(Request { method, path, body })
}

fn respond(stream: &mut TcpStream, status: u16, kind: &str, headers: &[(&str, &str)], body: &[u8]) {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\ncache-control: no-store\r\nx-content-type-options: nosniff\r\nconnection: close\r\n",
        if status == 200 { "OK" } else { "Refused" },
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

fn field(body: &Value, key: &str) -> Result<String> {
    match body.get(key).map(Value::view) {
        Some(canon::json::ValueView::Text(text)) => Ok(text.to_owned()),
        _ => Err(canon::codes::FRONTDOOR_BODY_INVALID),
    }
}

impl Node {
    fn api(&self, request: &Request) -> Result<Value> {
        let body = if request.method == "POST" {
            canon::json::parse_strict(&request.body)?
        } else {
            Value::object(Vec::new())?
        };
        let at = now();
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/api/pairing/start") => self.pairing.start(&self.owner, &field(&body, "deviceKey")?, at),
            ("POST", "/api/pairing/status") => {
                self.pairing.owner_status(&self.owner, &field(&body, "pairing")?, at, &self.facts)
            }
            ("POST", "/api/pairing/receipt") => {
                use base64::Engine;
                let receipt = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(field(&body, "receipt")?)
                    .map_err(|_| canon::codes::FRONTDOOR_BODY_INVALID)?;
                self.pairing.submit(&self.owner, &field(&body, "pairing")?, &receipt, at, &self.facts)
            }
            ("GET", "/api/pairing/devices") => self.pairing.devices(&self.owner.subject),
            ("POST", "/api/pairing/join") => {
                self.pairing.join(&field(&body, "join")?, &field(&body, "deviceKey")?, at)
            }
            ("POST", "/api/pairing/phone") => self.pairing.phone_status(&field(&body, "phone")?, at),
            ("GET", "/__facts") => Value::array(self.facts.0.lock().expect("facts").clone()),
            _ => Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE),
        }
    }

    fn file(&self, path: &str) -> Option<(Vec<u8>, &'static str)> {
        let relative = path.trim_start_matches('/');
        if relative.split('/').any(|part| part.is_empty() || part == "..") {
            return None;
        }
        let kind = match Path::new(relative).extension()?.to_str()? {
            "html" => "text/html; charset=utf-8",
            "js" => "text/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "json" => "application/json",
            "wasm" => "application/wasm",
            _ => return None,
        };
        Some((std::fs::read(self.root.join(relative)).ok()?, kind))
    }

    fn serve(&self, mut stream: TcpStream) -> bool {
        let Some(request) = read_request(&mut stream) else {
            return false;
        };
        if request.path == "/__stop" {
            respond(&mut stream, 200, "application/json", &[], b"{}");
            return true;
        }
        if request.path.starts_with("/api/") || request.path.starts_with("/__") {
            match self.api(&request) {
                Ok(value) => respond(&mut stream, 200, "application/json", &[], &value.canonical_bytes()),
                Err(refusal) => {
                    let body = format!("{{\"error\":\"{}:{}\"}}", refusal.organ, refusal.reason);
                    respond(&mut stream, 400, "application/json", &[], body.as_bytes());
                }
            }
            return false;
        }
        let (asset, headers): (&str, Vec<(&str, String)>) = match request.path.as_str() {
            "/pair" => (
                "/portal/phone/index.html",
                vec![
                    ("content-security-policy", frontdoor::shell::PHONE_CSP.to_owned()),
                    ("permissions-policy", frontdoor::shell::PHONE_PERMISSIONS.to_owned()),
                    ("referrer-policy", "no-referrer".to_owned()),
                    ("x-frame-options", "DENY".to_owned()),
                ],
            ),
            "/owner" => (
                "/owner.html",
                vec![(
                    "content-security-policy",
                    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'".to_owned(),
                )],
            ),
            path if path.ends_with(".html") => {
                respond(&mut stream, 404, "text/plain", &[], b"");
                return false;
            }
            path => (path, Vec::new()),
        };
        let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        match self.file(asset) {
            Some((bytes, kind)) => respond(&mut stream, 200, kind, &headers, &bytes),
            None => respond(&mut stream, 404, "text/plain", &[], b""),
        }
        false
    }
}

#[test]
#[ignore = "run by tests/copresence/twin.mjs"]
fn pairing_twin_node() {
    let root = PathBuf::from(std::env::var("PAIRING_TWIN_ROOT").expect("PAIRING_TWIN_ROOT"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let origin = format!("http://127.0.0.1:{port}");
    let node = NodeId::from_bytes([0x5a; 16]);
    let store = root.join("pairing-v1.sqlite3");
    let node = Arc::new(Node {
        pairing: Pairing::open(&store, node, &origin).expect("store"),
        facts: Facts::default(),
        owner: Owner {
            subject: SubjectId::from_digest(Digest32::sha256(b"twin owner")),
            epoch: 1,
            session: Digest32::sha256(b"twin owner session"),
        },
        origin,
        root,
    });
    println!("PAIRING_TWIN_PORT={port} ORIGIN={}", node.origin);
    std::io::stdout().flush().expect("stdout");
    let deadline = Instant::now() + Duration::from_secs(
        std::env::var("PAIRING_TWIN_SECONDS").ok().and_then(|v| v.parse().ok()).unwrap_or(180),
    );
    listener.set_nonblocking(true).expect("nonblocking");
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    while Instant::now() < deadline && !stopped.load(std::sync::atomic::Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).expect("blocking");
                let node = node.clone();
                let stopped = stopped.clone();
                std::thread::spawn(move || {
                    if node.serve(stream) {
                        stopped.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}
