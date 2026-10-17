// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Kira 2 service: one local memory for every agent on the Mac.
//!
//! The service holds every agent's signing key and signs for the authenticated caller, so no agent ever holds another
//! agent's key. A caller authenticates with a bearer token; only its sha256 is kept, and `tokens.json` is re-read
//! whenever it changes, so a revoked or rotated token stops working on the next request. Requests are one JSON object
//! per line on a Unix socket (mode 0600, inside the 0700 state folder); `mcp` is a stdio Model Context Protocol shim
//! that forwards to it. Every note a response carries is read back from the store, which re-verifies it; a caller that
//! is not the owner never receives a note whose privacy is `local` or whose scope it is not registered for, and a
//! quarantined note is only ever shown as a stub without its text.
//!
//! Trust boundary (Phase M): same-uid trust: agents running as the owner's user can read token and key files; Phase N
//! moves keys behind a separate service uid and SO_PEERCRED. The 0600/0700 modes keep out other users, not other
//! processes of the same user.

use super::hybrid::query_vector;
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
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};
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

/// What identifies one version of `tokens.json`: modification time, length and inode (a save renames a new file in).
type TokensStamp = Option<(Option<SystemTime>, u64, u64)>;

fn tokens_stamp(dir: &Path) -> Result<TokensStamp> {
    match fs::metadata(dir.join(TOKENS)) {
        Ok(meta) => Ok(Some((meta.modified().ok(), meta.len(), meta.ino()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
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

/// A fresh token for `name`; with `rotate`, every earlier token of that agent is removed in the same save.
fn issue_token(dir: &Path, name: &str, rotate: bool) -> Result<String> {
    let token = hex(random32()?.as_ref());
    let mut tokens = load_tokens(dir)?;
    if rotate {
        tokens.retain(|_, holder| holder != name);
    }
    tokens.insert(token_hash(&token), name.to_owned());
    save_tokens(dir, &tokens)?;
    Ok(token)
}

/// Registers an agent: a fresh key in `keys/<name>.key`, its public key in the store, and a token returned ONCE.
pub fn register(dir: &Path, name: &str, scopes: &[String], owner: bool) -> Result<String> {
    let state = State::open(dir)?;
    create_agent(dir, &state.store, name, scopes, owner)?;
    issue_token(dir, name, false)
}

/// Issues one more token for an agent that already has a key (a lost token). Earlier tokens stay valid unless
/// `rotate` is set, which replaces them. A revoked agent gets no token.
pub fn reissue(dir: &Path, name: &str, rotate: bool) -> Result<String> {
    let mut state = State::open(dir)?;
    if name == IMPORT_AGENT {
        return Err(refuse("agent-takes-no-token"));
    }
    let pubkey = state.pubkey_of(name)?;
    if state.store.agent(&pubkey)?.is_none_or(|a| a.revoked_at.is_some()) {
        return Err(refuse("agent-revoked"));
    }
    issue_token(dir, name, rotate)
}

/// Revokes an agent: `revoked_at` is set in the store (it can no longer write or authenticate) and every token hash
/// it holds is removed from `tokens.json`. Its notes stay readable; quarantine is the separate act that withdraws them.
pub fn revoke(dir: &Path, name: &str) -> Result<()> {
    agent_name(name)?;
    let state = State::open(dir)?;
    state.store.revoke_agent(name, now())?;
    let mut tokens = load_tokens(dir)?;
    tokens.retain(|_, holder| holder != name);
    save_tokens(dir, &tokens)
}

/// An authenticated caller.
struct Caller {
    name: String,
    pubkey: String,
    owner: bool,
    /// Registered scopes; `*` reads every scope.
    scopes: Vec<String>,
}

impl Caller {
    fn reads_scope(&self, scope: &str) -> bool {
        self.owner || self.scopes.iter().any(|s| s == "*" || s == scope)
    }

    /// The scopes a recall searches: the requested ones this caller may read (all of its own when none are asked).
    fn read_scopes(&self, requested: Vec<String>) -> Result<Vec<String>> {
        if self.owner || self.scopes.iter().any(|s| s == "*") {
            return Ok(requested);
        }
        if requested.is_empty() {
            return Ok(self.scopes.clone());
        }
        let allowed: Vec<String> = requested.into_iter().filter(|s| self.scopes.contains(s)).collect();
        if allowed.is_empty() {
            return Err(refuse("scope-refused"));
        }
        Ok(allowed)
    }
}

type SharedEmbedder = Arc<dyn Embedder + Send + Sync>;
type SharedReranker = Arc<dyn Reranker + Send + Sync>;

/// The service state: the store, the token hashes, the agents' keys and the optional model servers.
pub struct State {
    dir: PathBuf,
    store: SharedStore,
    tokens: BTreeMap<String, String>,
    tokens_stamp: TokensStamp,
    keys: BTreeMap<String, SecretKey>,
    embedder: Option<SharedEmbedder>,
    reranker: Option<SharedReranker>,
    /// Wakes the background indexer after a write.
    wake: Option<Sender<()>>,
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
    (caller.owner || note.meta.privacy != Privacy::Local) && caller.reads_scope(&note.meta.scope)
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

/// A quarantined note: that it existed, who signed it and its statement hash, never its text.
fn stub(note: &StoredNote) -> Value {
    json!({
        "id": hex(note.event.id.as_bytes()), "author": hex(note.event.pubkey.as_bytes()),
        "created_at": note.event.created_at, "statement_hash": hex(&note.meta.statement_hash), "correction": "quarantined",
    })
}

/// The note; a stub if it is quarantined; for a note this caller may not read, only a receipt that it exists.
fn view(caller: &Caller, note: &StoredNote) -> Value {
    if !visible(caller, note) {
        json!({"id": hex(note.event.id.as_bytes()), "privacy": note.meta.privacy.wire(), "withheld": true})
    } else if note.quarantined {
        stub(note)
    } else {
        note_json(note)
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl State {
    /// Opens (creating if needed) the state folder at mode 0700 and the store inside it. No model servers.
    pub fn open(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        private_dir(&dir.join(KEYS))?;
        let store = SharedStore::open(&dir.join(DB))?;
        fs::set_permissions(dir.join(DB), fs::Permissions::from_mode(0o600)).map_err(|_| refuse("state-dir"))?;
        let tokens_stamp = tokens_stamp(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
            store,
            tokens: load_tokens(dir)?,
            tokens_stamp,
            keys: BTreeMap::new(),
            embedder: None,
            reranker: None,
            wake: None,
            writes: BTreeMap::new(),
        })
    }

    pub fn with_models(mut self, embedder: Option<SharedEmbedder>, reranker: Option<SharedReranker>) -> Self {
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

    /// Every request sees the current `tokens.json`: it is re-read whenever its stamp changes.
    fn caller(&mut self, token: &str) -> Result<Caller> {
        let stamp = tokens_stamp(&self.dir)?;
        if stamp != self.tokens_stamp {
            self.tokens = load_tokens(&self.dir)?;
            self.tokens_stamp = stamp;
        }
        let name = self.tokens.get(&token_hash(token)).cloned().ok_or_else(|| refuse("token-refused"))?;
        let pubkey = self.pubkey_of(&name).map_err(|_| refuse("token-refused"))?;
        let agent = self.store.agent(&pubkey)?.ok_or_else(|| refuse("token-refused"))?;
        if agent.revoked_at.is_some() {
            return Err(refuse("agent-revoked"));
        }
        Ok(Caller { name, pubkey, owner: agent.owner, scopes: agent.scopes })
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

    fn whoami(caller: &Caller) -> Value {
        json!({"name": caller.name, "pubkey": caller.pubkey, "owner": caller.owner, "scopes": caller.scopes})
    }

    fn remember(&mut self, caller: &Caller, p: RememberParams) -> Result<Value> {
        let claimed = Capture::parse(&p.capture)?;
        if claimed == Capture::Import {
            return Err(refuse("capture-import-reserved"));
        }
        // Spec v0.3 §5: only the owner channel claims owner review or an owner-class capture; refused, never downgraded.
        // `owner_signed` means signed with the owner's passkey over these exact bytes. That path (Phase N) is not
        // built, so no token, not even the owner's, can claim it; the owner's own notes are owner-typed.
        if p.owner_signed {
            return Err(refuse("review-needs-passkey"));
        }
        if !caller.owner && claimed.owner_class() {
            return Err(refuse("review-claim-refused"));
        }
        // Any other caller's claim stands only as tool-observed with at least one source note behind it; everything
        // else it writes is filed as model-generated.
        let capture = if caller.owner || (claimed == Capture::ToolObserved && !p.sources.is_empty()) {
            claimed
        } else {
            Capture::ModelGenerated
        };
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
        if let Some(wake) = &self.wake {
            let _ = wake.send(());
        }
        Ok(view(caller, &note))
    }

    fn get(&mut self, caller: &Caller, p: GetParams) -> Result<Value> {
        if !is_hex64(&p.id) {
            return Err(refuse("id-invalid"));
        }
        match self.store.get(&p.id)? {
            Some(note) if visible(caller, &note) => Ok(view(caller, &note)),
            _ => Err(refuse("not-found")),
        }
    }

    fn list_recent(&mut self, caller: &Caller, p: ListParams) -> Result<Value> {
        let limit = p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, 500);
        let notes = self.store.list_recent(limit, p.before, Some(p.epoch.unwrap_or(2)))?;
        let next_before = if notes.len() == limit { notes.last().map(|n| n.seq) } else { None };
        let shown: Vec<Value> = notes.iter().filter(|n| visible(caller, n)).map(|n| view(caller, n)).collect();
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

/// Recall in three steps so no model call runs under the state lock: read the query's settings and model handles,
/// embed the query unlocked, gather candidates locked, rerank unlocked, then re-read the returned notes locked.
fn recall(state: &Mutex<State>, caller: &Caller, p: RecallParams) -> Result<Value> {
    let (query, embedder, reranker) = {
        let mut s = lock(state);
        let author = match p.author {
            None => None,
            Some(author) if is_hex64(&author) => Some(author),
            Some(name) => Some(s.pubkey_of(&name)?),
        };
        let query = RecallQuery {
            text: p.query,
            caller: caller.pubkey.clone(),
            epoch: p.epoch.unwrap_or(2),
            scopes: caller.read_scopes(p.scopes)?,
            author,
            budget_chars: p.budget_chars.unwrap_or(DEFAULT_BUDGET).min(MAX_BUDGET),
            include_local: caller.owner,
        };
        (query, s.embedder.clone(), s.reranker.clone())
    };
    let model = embedder.as_ref().map(|e| e.model_id().to_owned());
    let vector = embedder.as_deref().and_then(|e| query_vector(&query, e));
    let prepared = lock(state).store.recall_prepare(&query, model.as_deref().map(|m| (m, vector)))?;
    let outcome = prepared.finish(reranker.as_deref().map(|r| r as &dyn Reranker));
    let s = lock(state);
    let mut status = outcome.status.clone();
    let mut items = Vec::new();
    for item in &outcome.items {
        match s.store.get(&item.id) {
            Ok(Some(note)) if visible(caller, &note) => {
                let mut shown = if note.quarantined { stub(&note) } else { note_json(&note) };
                shown["score"] = json!(item.score);
                shown["also_by"] = json!(item.also_by);
                shown["also_by_ids"] = json!(item.also_by_ids);
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
        "status": status, "reason": reason, "items": items, "omitted": outcome.omitted, "indexed": outcome.indexed,
        "total": outcome.total, "query_digest": outcome.query_digest,
    }))
}

fn dispatch(state: &Mutex<State>, line: &str) -> Result<Value> {
    let request: Request = serde_json::from_str(line).map_err(|_| refuse("request-malformed"))?;
    let mut s = lock(state);
    let caller = s.caller(&request.token)?;
    match request.method.as_str() {
        "recall" => {
            drop(s);
            recall(state, &caller, parse(request.params)?)
        }
        "whoami" => Ok(State::whoami(&caller)),
        "remember" => s.remember(&caller, parse(request.params)?),
        "get" => s.get(&caller, parse(request.params)?),
        "list_recent" => s.list_recent(&caller, parse(request.params)?),
        "supersede" => s.supersede(&caller, parse(request.params)?),
        "quarantine_source" => s.quarantine(&caller, parse(request.params)?),
        _ => Err(refuse("method-unknown")),
    }
}

/// One request line in, one reply line out: `{"ok":true,"result":...}` or `{"ok":false,"error":"kira:<reason>"}`.
pub fn handle(state: &Mutex<State>, line: &str) -> String {
    match dispatch(state, line) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(refusal) => json!({"ok": false, "error": refusal.to_string()}),
    }
    .to_string()
}

fn read_line(reader: &mut impl BufRead, limit: usize) -> Option<String> {
    let mut buf = Vec::new();
    let n = reader.by_ref().take(limit as u64 + 1).read_until(b'\n', &mut buf).ok()?;
    if n == 0 || buf.len() > limit {
        return None;
    }
    String::from_utf8(buf).ok()
}

mod cli;
mod import;
mod mcp;
mod server;

pub use cli::cli;
pub use import::{import_epoch1, ImportReport};
pub use mcp::{mcp, mcp_reply};
pub use server::serve;

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        dir: PathBuf,
        state: Mutex<State>,
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
        let state = Mutex::new(State::open(&dir).unwrap());
        Fixture { dir, state, owner, claude, grok }
    }

    fn call(state: &Mutex<State>, token: &str, method: &str, params: Value) -> Value {
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
        let f = fixture();
        let reply = call(&f.state, &"0".repeat(64), "list_recent", json!({}));
        assert_eq!(reply["error"], "kira:token-refused");
        let reply = call(&f.state, "", "remember", note("anything", "builders"));
        assert_eq!(reply["error"], "kira:token-refused");
        assert_eq!(call(&f.state, &f.grok, "list_recent", json!({}))["ok"], true);
    }

    #[test]
    fn a_remembers_b_finds_it_with_a_as_author() {
        let f = fixture();
        let claude = f.claude.clone();
        let written = call(&f.state, &claude, "remember", note("The figurine is on the left shelf", "builders"));
        assert_eq!(written["ok"], true, "{written}");
        let id = written["result"]["id"].as_str().unwrap().to_owned();
        assert_eq!(written["result"]["review"], "remembered");
        let grok = f.grok.clone();
        let got = call(&f.state, &grok, "get", json!({"id": id}));
        assert_eq!(got["result"]["author_name"], "claude");
        assert_eq!(got["result"]["text"], "The figurine is on the left shelf");
        let recalled = call(&f.state, &grok, "recall", json!({"query": "where is the figurine"}));
        assert_eq!(recalled["ok"], true, "{recalled}");
        let items = recalled["result"]["items"].as_array().unwrap();
        assert!(items.iter().all(|i| i["author_name"] == "claude"));
        assert_eq!(recalled["result"]["status"], "found", "{recalled}");
        assert!(items.iter().any(|i| i["id"] == id.as_str()));
        let listed = call(&f.state, &grok, "list_recent", json!({"limit": 5}));
        assert_eq!(listed["result"]["notes"][0]["author_name"], "claude");
    }

    #[test]
    fn only_the_owner_signs_reviews_and_quarantines() {
        let f = fixture();
        let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
        let mut claim = note("Peter approved this", "builders");
        claim["owner_signed"] = json!(true);
        assert_eq!(call(&f.state, &claude, "remember", claim.clone())["error"], "kira:review-needs-passkey");
        assert_eq!(call(&f.state, &owner, "remember", claim)["error"], "kira:review-needs-passkey");
        let mut typed = note("Peter said so", "builders");
        typed["capture"] = json!("owner-typed");
        assert_eq!(call(&f.state, &claude, "remember", typed)["error"], "kira:review-claim-refused");
        let long = note(&"x".repeat(MAX_STATEMENT + 1), "builders");
        assert_eq!(call(&f.state, &claude, "remember", long)["error"], "kira:statement-too-long");
        for i in 0..RATE_WRITES {
            assert_eq!(call(&f.state, &claude, "remember", note(&format!("note {i}"), "builders"))["ok"], true);
        }
        assert_eq!(call(&f.state, &claude, "remember", note("one too many", "builders"))["error"], "kira:rate-limited");
        let grok_key = lock(&f.state).pubkey_of("grok").unwrap();
        let reply = call(&f.state, &claude, "quarantine_source", json!({"pubkey": grok_key}));
        assert_eq!(reply["error"], "kira:quarantine-owner-only");
        assert_eq!(call(&f.state, &owner, "quarantine_source", json!({"pubkey": grok_key}))["ok"], true);
        assert_eq!(call(&f.state, &grok, "remember", note("after quarantine", "builders"))["error"], "kira:author-quarantined");
    }

    #[test]
    fn local_notes_are_withheld_from_non_owners() {
        let f = fixture();
        let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
        let private = call(&f.state, &owner, "remember", note("Peter's door code lives in the drawer", "local"));
        let id = private["result"]["id"].as_str().unwrap().to_owned();
        assert_eq!(private["result"]["text"], "Peter's door code lives in the drawer");
        assert_eq!(call(&f.state, &grok, "get", json!({"id": id}))["error"], "kira:not-found");
        assert_eq!(call(&f.state, &grok, "list_recent", json!({}))["result"]["notes"], json!([]));
        let recalled = call(&f.state, &grok, "recall", json!({"query": "door code drawer"}));
        assert_eq!(recalled["result"]["items"], json!([]), "{recalled}");
        assert_ne!(recalled["result"]["status"], "found");
        let own = call(&f.state, &claude, "remember", note("my own local observation", "local"));
        assert_eq!(own["result"]["withheld"], true);
        assert!(own["result"].get("text").is_none());
        assert_eq!(call(&f.state, &owner, "list_recent", json!({}))["result"]["notes"].as_array().unwrap().len(), 2);
        // Scopes: an agent reads only the scopes it is registered for, whatever it asks for.
        let mut owner_scope = note("the figurine insurance is in the owner folder", "builders");
        owner_scope["scope"] = json!("owner");
        let id = call(&f.state, &owner, "remember", owner_scope)["result"]["id"].as_str().unwrap().to_owned();
        assert_eq!(call(&f.state, &grok, "get", json!({"id": id}))["error"], "kira:not-found");
        let asked = call(&f.state, &grok, "recall", json!({"query": "figurine insurance", "scopes": ["owner"]}));
        assert_eq!(asked["error"], "kira:scope-refused");
        let wide = call(&f.state, &grok, "recall", json!({"query": "figurine insurance"}));
        assert_eq!(wide["result"]["status"], "empty", "{wide}");
        assert_eq!(call(&f.state, &owner, "recall", json!({"query": "figurine insurance"}))["result"]["status"], "found");
    }

    #[test]
    fn agent_captures_are_clamped_and_commitments_are_the_owners() {
        let f = fixture();
        let (owner, claude) = (f.owner.clone(), f.claude.clone());
        let plain = call(&f.state, &claude, "remember", note("the kettle was descaled", "builders"));
        assert_eq!(plain["result"]["capture"], "model-generated", "{plain}");
        let mut sourced = note("the kettle was descaled on Sunday", "builders");
        sourced["sources"] = json!([plain["result"]["id"]]);
        assert_eq!(call(&f.state, &claude, "remember", sourced)["result"]["capture"], "tool-observed");
        let mut web = note("the kettle manual says monthly", "builders");
        web["capture"] = json!("web-derived");
        assert_eq!(call(&f.state, &claude, "remember", web)["result"]["capture"], "model-generated");
        let mut decision = note("we descale the kettle monthly", "builders");
        decision["lane"] = json!("decision");
        assert_eq!(call(&f.state, &claude, "remember", decision.clone())["error"], "kira:note-capture-lane");
        assert_eq!(call(&f.state, &owner, "remember", decision.clone())["error"], "kira:note-capture-lane");
        decision["capture"] = json!("owner-typed");
        assert_eq!(call(&f.state, &owner, "remember", decision)["result"]["lane"], "decision");
        assert_eq!(call(&f.state, &owner, "whoami", json!({}))["result"]["owner"], true);
    }

    #[test]
    fn quarantined_notes_are_stubs_everywhere() {
        let f = fixture();
        let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
        call(&f.state, &claude, "remember", note("The harness is the deepseek one.", "builders"));
        let bad = call(&f.state, &grok, "remember", note("The harness is secretly broken.", "builders"));
        let id = bad["result"]["id"].as_str().unwrap().to_owned();
        let grok_key = bad["result"]["author"].clone();
        assert_eq!(call(&f.state, &owner, "quarantine_source", json!({"pubkey": grok_key}))["ok"], true);
        let got = call(&f.state, &claude, "get", json!({"id": id}));
        assert_eq!(got["result"]["correction"], "quarantined", "{got}");
        assert!(got["result"].get("text").is_none() && got["result"]["statement_hash"].is_string());
        let listed = call(&f.state, &claude, "list_recent", json!({}));
        assert!(listed["result"]["notes"].as_array().unwrap().iter().any(|n| n["id"] == id.as_str() && n.get("text").is_none()));
        let recalled = call(&f.state, &claude, "recall", json!({"query": "which harness"}));
        let items = recalled["result"]["items"].as_array().unwrap();
        let stub = items.iter().find(|i| i["id"] == id.as_str()).expect("the quarantined note shows as a correction");
        assert!(stub.get("text").is_none() && stub["correction"] == "quarantined", "{stub}");
    }

    #[test]
    fn revoke_and_rotate_take_effect_on_the_next_request() {
        let f = fixture();
        let (old, grok) = (f.claude.clone(), f.grok.clone());
        assert_eq!(call(&f.state, &old, "whoami", json!({}))["result"]["name"], "claude");
        let new = reissue(&f.dir, "claude", true).unwrap();
        assert_eq!(call(&f.state, &old, "whoami", json!({}))["error"], "kira:token-refused");
        assert_eq!(call(&f.state, &new, "whoami", json!({}))["result"]["scopes"], json!(["builders"]));
        revoke(&f.dir, "claude").unwrap();
        assert_eq!(call(&f.state, &new, "whoami", json!({}))["error"], "kira:token-refused");
        assert_eq!(reissue(&f.dir, "claude", false).err(), Some(refuse("agent-revoked")));
        assert!(revoke(&f.dir, "nobody").is_err());
        assert_eq!(call(&f.state, &grok, "whoami", json!({}))["result"]["owner"], false);
    }

    #[test]
    fn supersede_is_signed_by_the_caller() {
        let f = fixture();
        let (claude, grok) = (f.claude.clone(), f.grok.clone());
        let old = call(&f.state, &claude, "remember", note("plan uses the tiny harness", "builders"));
        let id = old["result"]["id"].as_str().unwrap().to_owned();
        assert_eq!(call(&f.state, &grok, "supersede", json!({"target": id}))["error"], "kira:supersede-not-author");
        let done = call(&f.state, &claude, "supersede", json!({"target": id}));
        assert!(done["result"]["target"]["superseded_by"].is_string(), "{done}");
    }

    #[test]
    fn import_skips_secrets_and_is_idempotent() {
        let f = fixture();
        let file = f.dir.join("archive.jsonl");
        let lines = [
            json!({"from": "AUKORA-BUILD", "text": "a stray bell \u{7} and escape \u{1b}[0m, then\ta tab"}),
            json!({"from": "AUKORA-BUILD", "text": "the bearer token never enters the engine; password rules: see the spec"}),
            json!({"from": "AUKORA-BUILD", "text": format!("pushed with ghp_{}", "a1".repeat(18))}),
            json!({"from": "AUKORA-BUILD", "text": "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwx'"}),
            json!({"from": "AUKORA-BUILD", "text": "export API_KEY=\"live1234abcd\""}),
            json!({"from": "AUKORA-BUILD", "text": "[conductor ruling] Kira holds no root keys."}),
            json!({"from": "AUKORA-BUILD", "text": "[aukora-sovereign plan, NORTH-STAR row 7] | 7 | Memory app |"}),
            json!({"from": "AUKORA-BUILD", "text": "the relay nsec1qqqqqqqq was pasted here"}),
            json!({"from": "AUKORA-BUILD", "text": format!("signing key {}", "ab".repeat(32))}),
            json!({"from": "AUKORA-BUILD", "kind": "finding", "id": "a4c1c86c567b", "text": "risk-free task-runner note"}),
        ];
        let body: String = lines.iter().map(|l| format!("{l}\nnot json\n")).collect();
        fs::write(&file, body).unwrap();
        let report = import_epoch1(&f.dir, &file).unwrap();
        let secret = [5, 7, 9, 15, 17].map(|n| (n, "secret"));
        let mut skipped: Vec<(usize, &str)> = (1..=10).map(|n| (n * 2, "invalid")).chain(secret).collect();
        skipped.sort_unstable();
        let mut got = report.skipped.clone();
        got.sort_unstable();
        assert_eq!((report.imported, report.duplicates, report.secrets, report.invalid), (5, 0, 5, 10));
        assert_eq!(got, skipped);
        assert_eq!(import_epoch1(&f.dir, &file).unwrap().duplicates, 5);
        let notes = lock(&f.state).store.list_recent(10, None, Some(1)).unwrap();
        let lanes: Vec<&str> = notes.iter().map(|n| n.meta.lane.wire()).collect();
        assert_eq!(lanes, ["finding", "evidence", "evidence", "evidence", "evidence"]);
        assert_eq!(notes[4].event.content, "a stray bell  and escape [0m, then\ta tab");
        let source = hex(&Sha256::digest(fs::read(&file).unwrap()));
        assert!(notes.iter().all(|n| n.event.tags.contains(&vec!["import_source".to_owned(), source.clone()])));
        assert!(notes.iter().all(|n| n.author_name == IMPORT_AGENT && n.meta.capture == Capture::Import));
        assert!(notes[0].meta.subject.starts_with("epoch1:finding") && notes[0].meta.subject.contains("a4c1c86c567b"));
        assert!(notes[1].meta.subject.starts_with("epoch1:row") && notes[2].meta.subject.starts_with("epoch1:ruling"));
        assert!(reissue(&f.dir, IMPORT_AGENT, false).is_err());
    }
}
