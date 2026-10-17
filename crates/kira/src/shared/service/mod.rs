// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Kira 2 service: one local memory for every agent on the Mac.
//!
//! The service holds every agent's signing key and signs for the authenticated caller, so no agent ever holds another
//! agent's key. A caller authenticates with a bearer token; only its sha256 is kept. Requests are one JSON object per
//! line on a Unix socket (mode 0600, inside the 0700 state folder); `mcp` is a stdio Model Context Protocol shim that
//! forwards to it. Every note a response carries is read back from the store, which re-verifies it, and a caller
//! that is not the owner never receives a note whose privacy is `local`.

use super::llama::{HttpEmbedder, HttpReranker};
use super::note::{Capture, Form, Lane, NoteDraft, Privacy, Review, NOTE_KIND, QUARANTINE_KIND, SUPERSEDE_KIND};
use super::recall::{Embedder, RecallQuery, RecallStatus, Reranker};
use super::store::{SharedStore, StoredNote};
use canon::{Refusal, Result};
use nostr::{Event, PublicKey, SecretKey};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use zeroize::Zeroizing;

const DB: &str = "kira.sqlite3";
const KEYS: &str = "keys";
const TOKENS: &str = "tokens.json";
const SOCKET: &str = "kira.sock";
/// The agent that signs the epoch-1 archive import. It never receives a token.
pub const IMPORT_AGENT: &str = "epoch1-import";
/// 2026-10-17T00:00:00Z, the archive date; a fixed time makes a re-import produce the same ids, so it adds nothing.
const IMPORT_AT: u64 = 1_792_195_200;
/// Signing-oracle limits (spec v0.3 §5, from Kira's notes.rs): statement size and per-agent signatures per window.
const MAX_STATEMENT: usize = 4_096;
const RATE_WRITES: usize = 32;
const RATE_WINDOW: u64 = 60;
const DEFAULT_BUDGET: usize = 4_800;
const MAX_BUDGET: usize = 48_000;
const DEFAULT_LIMIT: usize = 20;
const MAX_REQUEST: usize = 1 << 20;
const MAX_REPLY: usize = 64 << 20;
/// Batch size for embedding notes that have no vector yet, before a recall and after a remember.
const INDEX_BATCH: usize = 256;
const PROTOCOLS: [&str; 4] = ["2025-06-18", "2025-11-25", "2025-03-26", "2024-11-05"];
const TOOLS: [&str; 6] = ["remember", "recall", "get", "list_recent", "supersede", "quarantine_source"];

fn refuse(code: &'static str) -> Refusal {
    Refusal { organ: "kira", reason: code }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn random32() -> Result<Zeroizing<[u8; 32]>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| refuse("random-unavailable"))?;
    Ok(bytes)
}

fn token_hash(token: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    hex(&digest)
}

/// `~/aukora-memory/kira`.
pub fn default_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| refuse("home-unset"))?;
    Ok(PathBuf::from(home).join("aukora-memory").join("kira"))
}

/// `~/aukora-memory/archive/epoch1-2026-10-17/notes.jsonl`.
pub fn default_epoch1() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| refuse("home-unset"))?;
    Ok(PathBuf::from(home).join("aukora-memory").join("archive").join("epoch1-2026-10-17").join("notes.jsonl"))
}

fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|_| refuse("state-dir"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| refuse("state-dir"))
}

/// Writes a file only its owner can read. `create_new` never replaces an existing file.
fn write_private(path: &Path, bytes: &[u8], create_new: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).mode(0o600);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    let mut file = options.open(path).map_err(|_| refuse("state-write"))?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|_| refuse("state-write"))
}

/// Reads a secret file, refusing one that group or others could read.
fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = fs::File::open(path).map_err(|_| refuse("private-file-missing"))?;
    let mode = file.metadata().map_err(|_| refuse("private-file-missing"))?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(refuse("private-file-mode"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| refuse("private-file-missing"))?;
    if bytes.len() > limit {
        return Err(refuse("private-file-shape"));
    }
    Ok(bytes)
}

fn agent_name(name: &str) -> Result<()> {
    let ok = (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(refuse("agent-name"))
    }
}

fn key_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(KEYS).join(format!("{name}.key"))
}

fn load_key(dir: &Path, name: &str) -> Result<SecretKey> {
    agent_name(name)?;
    let bytes = read_private(&key_path(dir, name), 32)?;
    let material: [u8; 32] = bytes.as_slice().try_into().map_err(|_| refuse("private-file-shape"))?;
    SecretKey::import(Zeroizing::new(material))
}

fn load_tokens(dir: &Path) -> Result<BTreeMap<String, String>> {
    match fs::read(dir.join(TOKENS)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| refuse("tokens-malformed")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(_) => Err(refuse("tokens-unreadable")),
    }
}

fn save_tokens(dir: &Path, tokens: &BTreeMap<String, String>) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(tokens).map_err(|_| refuse("tokens-malformed"))?;
    let temp = dir.join("tokens.json.new");
    let _ = fs::remove_file(&temp);
    write_private(&temp, &bytes, true)?;
    fs::rename(&temp, dir.join(TOKENS)).map_err(|_| refuse("state-write"))
}

/// Generates a key (file mode 0600) and registers its public key. Refuses a name that already has a key.
fn create_agent(dir: &Path, store: &SharedStore, name: &str, scopes: &[String], owner: bool) -> Result<()> {
    agent_name(name)?;
    if scopes.is_empty() || scopes.iter().any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control)) {
        return Err(refuse("agent-scopes"));
    }
    let path = key_path(dir, name);
    if fs::symlink_metadata(&path).is_ok() {
        return Err(refuse("agent-exists"));
    }
    let material = loop {
        let candidate = random32()?;
        if SecretKey::import(Zeroizing::new(*candidate)).is_ok() {
            break candidate;
        }
    };
    let key = SecretKey::import(Zeroizing::new(*material))?;
    let pubkey = hex(key.public_key()?.as_bytes());
    write_private(&path, material.as_ref(), true)?;
    if let Err(refusal) = store.register_agent(name, &pubkey, scopes, owner) {
        let _ = fs::remove_file(&path);
        return Err(refusal);
    }
    Ok(())
}

fn issue_token(dir: &Path, name: &str) -> Result<String> {
    let token = hex(random32()?.as_ref());
    let mut tokens = load_tokens(dir)?;
    tokens.insert(token_hash(&token), name.to_owned());
    save_tokens(dir, &tokens)?;
    Ok(token)
}

/// Registers an agent: a fresh key in `keys/<name>.key`, its public key in the store, and a token returned ONCE.
pub fn register(dir: &Path, name: &str, scopes: &[String], owner: bool) -> Result<String> {
    let state = State::open(dir)?;
    create_agent(dir, &state.store, name, scopes, owner)?;
    issue_token(dir, name)
}

/// Issues one more token for an agent that already has a key (a lost token). Earlier tokens stay valid.
pub fn reissue(dir: &Path, name: &str) -> Result<String> {
    let mut state = State::open(dir)?;
    if name == IMPORT_AGENT {
        return Err(refuse("agent-takes-no-token"));
    }
    state.key(name)?;
    issue_token(dir, name)
}

/// An authenticated caller.
struct Caller {
    name: String,
    pubkey: String,
    owner: bool,
}

type BoxedEmbedder = Box<dyn Embedder + Send>;
type BoxedReranker = Box<dyn Reranker + Send>;

/// The service state: the store, the token hashes, the agents' keys and the optional model servers.
pub struct State {
    dir: PathBuf,
    store: SharedStore,
    tokens: BTreeMap<String, String>,
    keys: BTreeMap<String, SecretKey>,
    embedder: Option<BoxedEmbedder>,
    reranker: Option<BoxedReranker>,
    /// Signing times per agent name, for the rate limit.
    writes: BTreeMap<String, Vec<u64>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    token: String,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberParams {
    text: String,
    subject: String,
    scope: String,
    lane: String,
    form: String,
    privacy: String,
    capture: String,
    #[serde(default)]
    sources: Vec<String>,
    slot: Option<String>,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
    #[serde(default)]
    owner_signed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecallParams {
    query: String,
    epoch: Option<u32>,
    #[serde(default)]
    scopes: Vec<String>,
    author: Option<String>,
    budget_chars: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetParams {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    limit: Option<usize>,
    before: Option<i64>,
    epoch: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupersedeParams {
    target: String,
    replacement: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantineParams {
    pubkey: String,
}

fn parse<T: DeserializeOwned>(params: Value) -> Result<T> {
    let params = if params.is_null() { json!({}) } else { params };
    serde_json::from_value(params).map_err(|_| refuse("params-invalid"))
}

fn visible(caller: &Caller, note: &StoredNote) -> bool {
    caller.owner || note.meta.privacy != Privacy::Local
}

/// A note as the wire shows it, built from a store read (which re-verified it).
fn note_json(note: &StoredNote) -> Value {
    let m = &note.meta;
    json!({
        "id": hex(note.event.id.as_bytes()), "seq": note.seq, "author": hex(note.event.pubkey.as_bytes()),
        "author_name": note.author_name, "created_at": note.event.created_at, "text": note.event.content,
        "subject": m.subject, "lane": m.lane.wire(), "form": m.form.wire(), "review": m.review.wire(),
        "privacy": m.privacy.wire(), "capture": m.capture.wire(), "scope": m.scope, "epoch": m.epoch,
        "sources": m.sources, "slot": m.slot, "valid_from": m.valid_from, "valid_to": m.valid_to,
        "roots": note.roots, "superseded_by": note.superseded_by, "quarantined": note.quarantined,
    })
}

/// The note, or for a `local` note and a caller who is not the owner, only a receipt that it exists.
fn view(caller: &Caller, note: &StoredNote) -> Value {
    if visible(caller, note) {
        note_json(note)
    } else {
        json!({"id": hex(note.event.id.as_bytes()), "privacy": "local", "withheld": true})
    }
}

impl State {
    /// Opens (creating if needed) the state folder at mode 0700 and the store inside it. No model servers.
    pub fn open(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        private_dir(&dir.join(KEYS))?;
        let store = SharedStore::open(&dir.join(DB))?;
        fs::set_permissions(dir.join(DB), fs::Permissions::from_mode(0o600)).map_err(|_| refuse("state-dir"))?;
        Ok(Self {
            dir: dir.to_owned(),
            store,
            tokens: load_tokens(dir)?,
            keys: BTreeMap::new(),
            embedder: None,
            reranker: None,
            writes: BTreeMap::new(),
        })
    }

    pub fn with_models(mut self, embedder: Option<BoxedEmbedder>, reranker: Option<BoxedReranker>) -> Self {
        self.embedder = embedder;
        self.reranker = reranker;
        self
    }

    fn key(&mut self, name: &str) -> Result<&SecretKey> {
        if !self.keys.contains_key(name) {
            let key = load_key(&self.dir, name)?;
            self.keys.insert(name.to_owned(), key);
        }
        self.keys.get(name).ok_or_else(|| refuse("private-file-missing"))
    }

    fn pubkey_of(&mut self, name: &str) -> Result<String> {
        let key = self.key(name).map_err(|_| refuse("author-unknown"))?;
        Ok(hex(key.public_key()?.as_bytes()))
    }

    fn caller(&mut self, token: &str) -> Result<Caller> {
        let hash = token_hash(token);
        if !self.tokens.contains_key(&hash) {
            self.tokens = load_tokens(&self.dir)?;
        }
        let name = self.tokens.get(&hash).cloned().ok_or_else(|| refuse("token-refused"))?;
        let pubkey = self.pubkey_of(&name).map_err(|_| refuse("token-refused"))?;
        let agent = self.store.agent(&pubkey)?.ok_or_else(|| refuse("token-refused"))?;
        if agent.revoked_at.is_some() {
            return Err(refuse("agent-revoked"));
        }
        Ok(Caller { name, pubkey, owner: agent.owner })
    }

    /// Embeds notes that have no vector yet. Best effort: a model that is down leaves recall to report coverage.
    fn index_new(&self) {
        if let Some(embedder) = &self.embedder {
            if let Err(r) = self.store.index_missing(embedder.as_ref(), INDEX_BATCH) {
                eprintln!("kira: indexing paused: {}:{}", r.organ, r.reason);
            }
        }
    }

    fn dispatch(&mut self, line: &str) -> Result<Value> {
        let request: Request = serde_json::from_str(line).map_err(|_| refuse("request-malformed"))?;
        let caller = self.caller(&request.token)?;
        match request.method.as_str() {
            "remember" => self.remember(&caller, parse(request.params)?),
            "recall" => self.recall(&caller, parse(request.params)?),
            "get" => self.get(&caller, parse(request.params)?),
            "list_recent" => self.list_recent(&caller, parse(request.params)?),
            "supersede" => self.supersede(&caller, parse(request.params)?),
            "quarantine_source" => self.quarantine(&caller, parse(request.params)?),
            _ => Err(refuse("method-unknown")),
        }
    }

    /// The signing-oracle rate (spec v0.3 §5): at most RATE_WRITES signatures per agent per RATE_WINDOW seconds.
    fn rate(&mut self, caller: &Caller) -> Result<()> {
        let at = now();
        let recent = self.writes.entry(caller.name.clone()).or_default();
        recent.retain(|t| at.saturating_sub(*t) < RATE_WINDOW);
        if recent.len() >= RATE_WRITES {
            return Err(refuse("rate-limited"));
        }
        recent.push(at);
        Ok(())
    }

    fn remember(&mut self, caller: &Caller, p: RememberParams) -> Result<Value> {
        let capture = Capture::parse(&p.capture)?;
        if capture == Capture::Import {
            return Err(refuse("capture-import-reserved"));
        }
        // Spec v0.3 §5: only the owner channel claims owner review or an owner-class capture; refused, never downgraded.
        if !caller.owner && (p.owner_signed || matches!(capture, Capture::OwnerSigned | Capture::OwnerTyped)) {
            return Err(refuse("review-claim-refused"));
        }
        if p.text.len() > MAX_STATEMENT {
            return Err(refuse("statement-too-long"));
        }
        self.rate(caller)?;
        let review = if p.owner_signed { Review::OwnerSigned } else { Review::Remembered };
        let draft = NoteDraft {
            text: p.text,
            subject: p.subject,
            scope: p.scope,
            lane: Lane::parse(&p.lane)?,
            form: Form::parse(&p.form)?,
            privacy: Privacy::parse(&p.privacy)?,
            capture,
            sources: p.sources,
            slot: p.slot,
            valid_from: p.valid_from,
            valid_to: p.valid_to,
            epoch: 2,
        };
        let tags = draft.tags(review)?;
        let event = Event::sign(self.key(&caller.name)?, now(), NOTE_KIND, tags, draft.text)?;
        let note = self.store.append(event)?;
        self.index_new();
        Ok(view(caller, &note))
    }

    fn recall(&mut self, caller: &Caller, p: RecallParams) -> Result<Value> {
        let author = match p.author {
            None => None,
            Some(author) if is_hex64(&author) => Some(author),
            Some(name) => Some(self.pubkey_of(&name)?),
        };
        let query = RecallQuery {
            text: p.query,
            caller: caller.pubkey.clone(),
            epoch: p.epoch.unwrap_or(2),
            scopes: p.scopes,
            author,
            budget_chars: p.budget_chars.unwrap_or(DEFAULT_BUDGET).min(MAX_BUDGET),
        };
        self.index_new();
        let embedder = self.embedder.as_deref().map(|e| e as &dyn Embedder);
        let reranker = self.reranker.as_deref().map(|r| r as &dyn Reranker);
        let outcome = self.store.recall(&query, embedder, reranker)?;
        let mut status = outcome.status.clone();
        let mut items = Vec::new();
        for item in &outcome.items {
            match self.store.get(&item.id) {
                Ok(Some(note)) if visible(caller, &note) => {
                    let mut shown = note_json(&note);
                    shown["score"] = json!(item.score);
                    shown["also_by"] = json!(item.also_by);
                    shown["correction"] = json!(item.correction);
                    items.push(shown);
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => status = RecallStatus::Undetermined("note-integrity"),
            }
        }
        // Only withheld notes matched: from this caller's view nothing was found.
        if status == RecallStatus::Found && items.is_empty() {
            status = RecallStatus::Empty;
        }
        let (status, reason) = match status {
            RecallStatus::Found => ("found", None),
            RecallStatus::Empty => ("empty", None),
            RecallStatus::Undetermined(why) => ("undetermined", Some(why)),
        };
        Ok(json!({
            "status": status, "reason": reason, "items": items, "indexed": outcome.indexed, "total": outcome.total,
            "query_digest": outcome.query_digest,
        }))
    }

    fn get(&mut self, caller: &Caller, p: GetParams) -> Result<Value> {
        if !is_hex64(&p.id) {
            return Err(refuse("id-invalid"));
        }
        match self.store.get(&p.id)? {
            Some(note) if visible(caller, &note) => Ok(note_json(&note)),
            _ => Err(refuse("not-found")),
        }
    }

    fn list_recent(&mut self, caller: &Caller, p: ListParams) -> Result<Value> {
        let limit = p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, 500);
        let notes = self.store.list_recent(limit, p.before, Some(p.epoch.unwrap_or(2)))?;
        let next_before = if notes.len() == limit { notes.last().map(|n| n.seq) } else { None };
        let shown: Vec<Value> = notes.iter().filter(|n| visible(caller, n)).map(note_json).collect();
        Ok(json!({"notes": shown, "next_before": next_before}))
    }

    fn supersede(&mut self, caller: &Caller, p: SupersedeParams) -> Result<Value> {
        if !is_hex64(&p.target) || p.replacement.as_deref().is_some_and(|r| !is_hex64(r)) {
            return Err(refuse("id-invalid"));
        }
        self.rate(caller)?;
        let mut tags = vec![vec!["supersedes".to_owned(), p.target.clone()]];
        if let Some(replacement) = &p.replacement {
            tags.push(vec!["replacement".to_owned(), replacement.clone()]);
        }
        let event = Event::sign(self.key(&caller.name)?, now(), SUPERSEDE_KIND, tags, String::new())?;
        let id = self.store.record(event)?;
        let target = self.store.get(&p.target)?.ok_or_else(|| refuse("not-found"))?;
        Ok(json!({"event": id, "target": view(caller, &target)}))
    }

    fn quarantine(&mut self, caller: &Caller, p: QuarantineParams) -> Result<Value> {
        if !caller.owner {
            return Err(refuse("quarantine-owner-only"));
        }
        PublicKey::from_hex(&p.pubkey)?;
        if p.pubkey == caller.pubkey {
            return Err(refuse("quarantine-self"));
        }
        self.rate(caller)?;
        let tags = vec![vec!["source".to_owned(), p.pubkey.clone()]];
        let event = Event::sign(self.key(&caller.name)?, now(), QUARANTINE_KIND, tags, String::new())?;
        let id = self.store.record(event)?;
        Ok(json!({"event": id, "source": p.pubkey}))
    }
}

/// One request line in, one reply line out: `{"ok":true,"result":...}` or `{"ok":false,"error":"kira:<reason>"}`.
pub fn handle(state: &mut State, line: &str) -> String {
    match state.dispatch(line) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(refusal) => json!({"ok": false, "error": refusal.to_string()}),
    }
    .to_string()
}

fn socket_addr(text: &str) -> Result<std::net::SocketAddr> {
    text.parse().map_err(|_| refuse("model-addr"))
}

fn env_models() -> Result<(Option<BoxedEmbedder>, Option<BoxedReranker>)> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let embedder: Option<BoxedEmbedder> = match (var("KIRA_EMBED_ADDR"), var("KIRA_EMBED_MODEL")) {
        (Some(addr), Some(model)) => Some(Box::new(HttpEmbedder::new(socket_addr(&addr)?, &model)?)),
        (None, None) => None,
        _ => return Err(refuse("embed-config-partial")),
    };
    let reranker: Option<BoxedReranker> = match (var("KIRA_RERANK_ADDR"), var("KIRA_RERANK_MODEL")) {
        (Some(addr), Some(model)) => Some(Box::new(HttpReranker::new(socket_addr(&addr)?, &model)?)),
        (None, None) => None,
        _ => return Err(refuse("rerank-config-partial")),
    };
    Ok((embedder, reranker))
}

/// Binds the socket at mode 0600. A stale socket file is replaced; a live service is never displaced.
fn bind(socket: &Path) -> Result<UnixListener> {
    if let Ok(meta) = fs::symlink_metadata(socket) {
        if !meta.file_type().is_socket() {
            return Err(refuse("socket-path-taken"));
        }
        if UnixStream::connect(socket).is_ok() {
            return Err(refuse("service-running"));
        }
        fs::remove_file(socket).map_err(|_| refuse("socket-bind"))?;
    }
    let listener = UnixListener::bind(socket).map_err(|_| refuse("socket-bind"))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|_| refuse("socket-bind"))?;
    Ok(listener)
}

fn read_line(reader: &mut impl BufRead, limit: usize) -> Option<String> {
    let mut buf = Vec::new();
    let n = reader.by_ref().take(limit as u64 + 1).read_until(b'\n', &mut buf).ok()?;
    if n == 0 || buf.len() > limit {
        return None;
    }
    String::from_utf8(buf).ok()
}

fn connection(state: &Mutex<State>, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
    let Ok(mut writer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(stream);
    while let Some(line) = read_line(&mut reader, MAX_REQUEST) {
        if line.trim().is_empty() {
            continue;
        }
        let reply = handle(&mut state.lock().unwrap_or_else(PoisonError::into_inner), &line);
        if writeln!(writer, "{reply}").and_then(|()| writer.flush()).is_err() {
            return;
        }
    }
}

/// Serves the store on a Unix socket until killed. Model servers come from KIRA_EMBED_ADDR/KIRA_EMBED_MODEL and
/// KIRA_RERANK_ADDR/KIRA_RERANK_MODEL; without them recall runs on keywords and reports its coverage.
pub fn serve(dir: &Path, socket: &Path) -> Result<()> {
    let (embedder, reranker) = env_models()?;
    let state = State::open(dir)?.with_models(embedder, reranker);
    let listener = bind(socket)?;
    eprintln!("kira: serving {} on {}", dir.display(), socket.display());
    let state = Arc::new(Mutex::new(state));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let state = Arc::clone(&state);
        std::thread::spawn(move || connection(&state, stream));
    }
    Ok(())
}

mod cli;
mod import;
mod mcp;

pub use cli::cli;
pub use import::{import_epoch1, ImportReport};
pub use mcp::{mcp, mcp_reply};

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        dir: PathBuf,
        state: State,
        owner: String,
        claude: String,
        grok: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture() -> Fixture {
        let tag = hex(random32().unwrap().as_ref());
        let dir = std::env::temp_dir().join(format!("kira-service-{}", &tag[..16]));
        let owner = register(&dir, "peter", &["*".to_owned()], true).unwrap();
        let claude = register(&dir, "claude", &["builders".to_owned()], false).unwrap();
        let grok = register(&dir, "grok", &["builders".to_owned()], false).unwrap();
        let state = State::open(&dir).unwrap();
        Fixture { dir, state, owner, claude, grok }
    }

    fn call(state: &mut State, token: &str, method: &str, params: Value) -> Value {
        let line = json!({"token": token, "method": method, "params": params}).to_string();
        serde_json::from_str(&handle(state, &line)).unwrap()
    }

    fn note(text: &str, privacy: &str) -> Value {
        json!({"text": text, "subject": "test", "scope": "builders", "lane": "evidence", "form": "fact",
               "privacy": privacy, "capture": "tool-observed"})
    }

    #[test]
    fn register_gives_a_token_and_keeps_only_its_hash() {
        let f = fixture();
        assert!(is_hex64(&f.claude));
        let tokens = fs::read_to_string(f.dir.join(TOKENS)).unwrap();
        assert!(tokens.contains(&token_hash(&f.claude)) && !tokens.contains(&f.claude));
        let mode = fs::metadata(key_path(&f.dir, "claude")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(fs::metadata(f.dir.join(KEYS)).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(register(&f.dir, "claude", &["builders".to_owned()], false).is_err());
        assert!(register(&f.dir, "../evil", &["builders".to_owned()], false).is_err());
    }

    #[test]
    fn a_wrong_token_is_refused() {
        let mut f = fixture();
        let reply = call(&mut f.state, &"0".repeat(64), "list_recent", json!({}));
        assert_eq!(reply["error"], "kira:token-refused");
        let reply = call(&mut f.state, "", "remember", note("anything", "builders"));
        assert_eq!(reply["error"], "kira:token-refused");
        assert_eq!(call(&mut f.state, &f.grok, "list_recent", json!({}))["ok"], true);
    }

    #[test]
    fn a_remembers_b_finds_it_with_a_as_author() {
        let mut f = fixture();
        let claude = f.claude.clone();
        let written = call(&mut f.state, &claude, "remember", note("The figurine is on the left shelf", "builders"));
        assert_eq!(written["ok"], true, "{written}");
        let id = written["result"]["id"].as_str().unwrap().to_owned();
        assert_eq!(written["result"]["review"], "remembered");
        let grok = f.grok.clone();
        let got = call(&mut f.state, &grok, "get", json!({"id": id}));
        assert_eq!(got["result"]["author_name"], "claude");
        assert_eq!(got["result"]["text"], "The figurine is on the left shelf");
        let recalled = call(&mut f.state, &grok, "recall", json!({"query": "where is the figurine"}));
        assert_eq!(recalled["ok"], true, "{recalled}");
        let items = recalled["result"]["items"].as_array().unwrap();
        assert!(items.iter().all(|i| i["author_name"] == "claude"));
        assert_eq!(recalled["result"]["status"], "found", "{recalled}");
        assert!(items.iter().any(|i| i["id"] == id.as_str()));
        let listed = call(&mut f.state, &grok, "list_recent", json!({"limit": 5}));
        assert_eq!(listed["result"]["notes"][0]["author_name"], "claude");
    }

    #[test]
    fn only_the_owner_signs_reviews_and_quarantines() {
        let mut f = fixture();
        let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
        let mut claim = note("Peter approved this", "builders");
        claim["owner_signed"] = json!(true);
        assert_eq!(call(&mut f.state, &claude, "remember", claim.clone())["error"], "kira:review-claim-refused");
        let signed = call(&mut f.state, &owner, "remember", claim);
        assert_eq!(signed["result"]["review"], "owner_signed", "{signed}");
        let mut typed = note("Peter said so", "builders");
        typed["capture"] = json!("owner-typed");
        assert_eq!(call(&mut f.state, &claude, "remember", typed)["error"], "kira:review-claim-refused");
        let long = note(&"x".repeat(MAX_STATEMENT + 1), "builders");
        assert_eq!(call(&mut f.state, &claude, "remember", long)["error"], "kira:statement-too-long");
        for i in 0..RATE_WRITES {
            assert_eq!(call(&mut f.state, &claude, "remember", note(&format!("note {i}"), "builders"))["ok"], true);
        }
        assert_eq!(call(&mut f.state, &claude, "remember", note("one too many", "builders"))["error"], "kira:rate-limited");
        let grok_key = f.state.pubkey_of("grok").unwrap();
        let reply = call(&mut f.state, &claude, "quarantine_source", json!({"pubkey": grok_key}));
        assert_eq!(reply["error"], "kira:quarantine-owner-only");
        assert_eq!(call(&mut f.state, &owner, "quarantine_source", json!({"pubkey": grok_key}))["ok"], true);
        assert_eq!(call(&mut f.state, &grok, "remember", note("after quarantine", "builders"))["error"], "kira:author-quarantined");
    }

    #[test]
    fn local_notes_are_withheld_from_non_owners() {
        let mut f = fixture();
        let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
        let private = call(&mut f.state, &owner, "remember", note("Peter's door code lives in the drawer", "local"));
        let id = private["result"]["id"].as_str().unwrap().to_owned();
        assert_eq!(private["result"]["text"], "Peter's door code lives in the drawer");
        assert_eq!(call(&mut f.state, &grok, "get", json!({"id": id}))["error"], "kira:not-found");
        assert_eq!(call(&mut f.state, &grok, "list_recent", json!({}))["result"]["notes"], json!([]));
        let recalled = call(&mut f.state, &grok, "recall", json!({"query": "door code drawer"}));
        assert_eq!(recalled["result"]["items"], json!([]), "{recalled}");
        assert_ne!(recalled["result"]["status"], "found");
        let own = call(&mut f.state, &claude, "remember", note("my own local observation", "local"));
        assert_eq!(own["result"]["withheld"], true);
        assert!(own["result"].get("text").is_none());
        assert_eq!(call(&mut f.state, &owner, "list_recent", json!({}))["result"]["notes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn supersede_is_signed_by_the_caller() {
        let mut f = fixture();
        let (claude, grok) = (f.claude.clone(), f.grok.clone());
        let old = call(&mut f.state, &claude, "remember", note("plan uses the tiny harness", "builders"));
        let id = old["result"]["id"].as_str().unwrap().to_owned();
        assert_eq!(call(&mut f.state, &grok, "supersede", json!({"target": id}))["error"], "kira:supersede-not-author");
        let done = call(&mut f.state, &claude, "supersede", json!({"target": id}));
        assert!(done["result"]["target"]["superseded_by"].is_string(), "{done}");
    }

    #[test]
    fn import_skips_secrets_and_is_idempotent() {
        let f = fixture();
        let file = f.dir.join("archive.jsonl");
        let lines = [
            json!({"from": "AUKORA-BUILD", "text": "[conductor ruling] Kira holds no root keys."}),
            json!({"from": "AUKORA-BUILD", "text": "[aukora-sovereign plan, NORTH-STAR row 7] | 7 | Memory app |"}),
            json!({"from": "AUKORA-BUILD", "text": "the relay nsec1qqqqqqqq was pasted here"}),
            json!({"from": "AUKORA-BUILD", "text": format!("signing key {}", "ab".repeat(32))}),
            json!({"from": "AUKORA-BUILD", "kind": "finding", "id": "a4c1c86c567b", "text": "risk-free task-runner note"}),
        ];
        let body: String = lines.iter().map(|l| format!("{l}\nnot json\n")).collect();
        fs::write(&file, body).unwrap();
        let report = import_epoch1(&f.dir, &file).unwrap();
        assert_eq!(report, ImportReport { imported: 3, duplicates: 0, secrets: 2, invalid: 5 });
        assert_eq!(import_epoch1(&f.dir, &file).unwrap().duplicates, 3);
        let notes = f.state.store.list_recent(10, None, Some(1)).unwrap();
        let lanes: Vec<&str> = notes.iter().map(|n| n.meta.lane.wire()).collect();
        assert_eq!(lanes, ["finding", "evidence", "evidence"]);
        assert!(notes.iter().all(|n| n.author_name == IMPORT_AGENT && n.meta.capture == Capture::Import));
        assert!(notes[0].meta.subject.starts_with("epoch1:finding") && notes[0].meta.subject.contains("a4c1c86c567b"));
        assert!(notes[1].meta.subject.starts_with("epoch1:row") && notes[2].meta.subject.starts_with("epoch1:ruling"));
        assert!(reissue(&f.dir, IMPORT_AGENT).is_err());
    }
}
