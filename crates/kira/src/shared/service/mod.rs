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
//! moves keys behind a separate service uid. The 0600/0700 modes keep out other users, not other processes of the same
//! user. On Linux `serve --peer-uids/--peer-gids` admits only the listed peers by SO_PEERCRED (peer.rs); macOS has no
//! peer credentials, so there it stays same-uid trust.

use super::hybrid::query_vector;
use super::llama::{HttpEmbedder, HttpReranker};
use super::note::{
    may_write_slot, readable_slot, slot_readable_by, valid_agent_name, Capture, Form, Lane, NoteDraft, Privacy, Review, ACCEPT_KIND, NOTE_KIND, QUARANTINE_KIND,
    SUPERSEDE_KIND,
};
use super::hybrid::Prepared;
use super::recall::{Embedder, RecallOutcome, RecallQuery, RecallStatus, Reranker};
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
/// The most notes one `list_recent` reads while looking for `limit` the caller may see.
const MAX_LIST_SCAN: usize = 5_000;
const MAX_REQUEST: usize = 1 << 20;
const MAX_REPLY: usize = 64 << 20;
const PROTOCOLS: [&str; 4] = ["2025-06-18", "2025-11-25", "2025-03-26", "2024-11-05"];
const TOOLS: [&str; 7] = ["remember", "recall", "get", "list_recent", "supersede", "accept_correction", "quarantine_source"];

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

/// `~/aukora-memory/kira`, the live store on the Mac. Never a default inside a test (see `under_test`): every test names
/// its own state folder, and one that forgets is refused (`kira:state-dir-required`) instead of reaching the live store.
pub fn default_dir() -> Result<PathBuf> {
    if under_test() {
        return Err(refuse("state-dir-required"));
    }
    live_dir().ok_or_else(|| refuse("home-unset"))
}

/// `~/aukora-memory/archive/epoch1-2026-10-17/notes.jsonl`. Refused inside a test, like `default_dir`.
pub fn default_epoch1() -> Result<PathBuf> {
    if under_test() {
        return Err(refuse("state-dir-required"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| refuse("home-unset"))?;
    Ok(PathBuf::from(home).join("aukora-memory").join("archive").join("epoch1-2026-10-17").join("notes.jsonl"))
}

/// The marker a test harness that runs the built binary (not through cargo) sets so this process counts as a test.
pub const TEST_MARKER: &str = "KIRA_STATE_REQUIRED";

/// Whether this process is a test: this crate built for `cargo test` (`cfg(test)`); any binary cargo itself launched
/// (`cargo test`, `cargo run` and `cargo bench` set `CARGO_MANIFEST_DIR` in the child's environment, so the tests of
/// every other crate count too); or a process started with `KIRA_STATE_REQUIRED` set. The live service is started
/// from its own binary (`start.sh`), never by cargo, so it is none of these.
pub fn under_test() -> bool {
    cfg!(test) || std::env::var_os("CARGO_MANIFEST_DIR").is_some() || std::env::var_os(TEST_MARKER).is_some()
}

fn live_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join("aukora-memory").join("kira"))
}

/// A path as the file system resolves it: the longest existing ancestor canonicalized, the rest appended as written.
fn resolved(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() { path.to_owned() } else { std::env::current_dir().unwrap_or_default().join(path) };
    let mut tail = Vec::new();
    let mut cursor = absolute.as_path();
    loop {
        if let Ok(real) = cursor.canonicalize() {
            return tail.iter().rev().fold(real, |acc: PathBuf, part| acc.join(part));
        }
        match (cursor.parent(), cursor.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_owned());
                cursor = parent;
            }
            _ => return absolute,
        }
    }
}

/// Inside a test, a state folder in the live namespace is refused even when it is named explicitly
/// (`kira:live-state-in-test`), so no test can open, create or serve the live store.
fn refuse_live_in_test(dir: &Path) -> Result<()> {
    match live_dir() {
        Some(live) if under_test() => refuse_inside(dir, &live),
        _ => Ok(()),
    }
}

/// `kira:live-state-in-test` when `dir` resolves to `live` or anything under it (a symlink or `..` does not hide it).
fn refuse_inside(dir: &Path, live: &Path) -> Result<()> {
    if resolved(dir).starts_with(resolved(live)) {
        return Err(refuse("live-state-in-test"));
    }
    Ok(())
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
    if valid_agent_name(name) {
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

/// The gate on minting credentials (`register`, `token`): once the store has an owner, the caller must hold the
/// owner's token file. A store with no owner yet is open, so the first owner can be created. Not isolation: a same-uid
/// process that can read the file passes (see the trust boundary above).
pub fn require_owner(dir: &Path, owner_token_file: Option<&Path>) -> Result<()> {
    let mut state = State::open(dir)?;
    if !state.store.has_owner()? {
        return Ok(());
    }
    let file = owner_token_file.ok_or_else(|| refuse("owner-token-required"))?;
    let bytes = read_private(file, 256).map_err(|_| refuse("owner-token-refused"))?;
    let token = std::str::from_utf8(&bytes).map_err(|_| refuse("owner-token-refused"))?.trim();
    match state.caller(token) {
        Ok(caller) if caller.owner => Ok(()),
        _ => Err(refuse("owner-token-refused")),
    }
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
    /// For a slot write: the head the writer last read (a note id), or `none` for a slot it saw empty. A slot whose
    /// live head is anything else is refused as `kira:resume-stale`, so a session that went stale cannot silently
    /// replace a newer handoff. Without it the write goes through, as it always did.
    expected_head: Option<String>,
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
    /// Also search `web-derived` notes (left out by default).
    #[serde(default)]
    include_web: bool,
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
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptParams {
    proposal: String,
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

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl State {
    /// Opens (creating if needed) the state folder at mode 0700 and the store inside it. No model servers.
    pub fn open(dir: &Path) -> Result<Self> {
        refuse_live_in_test(dir)?;
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
        // Spec v0.3 §4: an agent's tool-observed stands only with a receipt the service itself can verify. The service
        // verifies no execution receipt today (the door's ledger is not readable here, and a source id is a citation of
        // another note, not a receipt), so an agent cannot claim it: refused, never silently filed as something else.
        if !caller.owner && claimed == Capture::ToolObserved {
            return Err(refuse("capture-unverified"));
        }
        // Taint inheritance (spec v0.3 §2): citing a web-derived note makes this one web-derived, for every caller, the
        // owner included (provenance is a fact, not a trust level). Citations only ever lower a claim, never raise it;
        // so a commitment lane, which takes only the owner's own words, refuses a note that cites the web.
        self.sources_readable(caller, &p.sources)?;
        let capture = if self.cites_web(&p.sources)? { Capture::WebDerived } else { claimed };
        self.check_head(caller, &p)?;
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
        view(&self.store, caller, &note)
    }

    /// One note by id, or the head of a slot (`aukora:self`, `aukora:resume`, `resume:<agent>`): the newest live note
    /// in it by an author allowed to write it. The same read checks either way.
    /// Whether any cited note is web-derived. An unknown source is left to the store, which refuses it.
    fn cites_web(&self, sources: &[String]) -> Result<bool> {
        for source in sources.iter().filter(|s| is_hex64(s)) {
            if self.store.get(source)?.is_some_and(|n| n.meta.capture == Capture::WebDerived) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Every cited note must be one this caller may read. One it may not read is refused exactly as a note that does not
    /// exist (`note-source-unknown`), so a citation reveals neither the note (its root, its capture) nor that it exists.
    fn sources_readable(&self, caller: &Caller, sources: &[String]) -> Result<()> {
        for source in sources.iter().filter(|s| is_hex64(s)) {
            if !self.store.get(source)?.is_some_and(|n| visible(caller, &n)) {
                return Err(refuse("note-source-unknown"));
            }
        }
        Ok(())
    }

    /// Every slot write names the head it replaces (`expected_head`: the head's note id, or `none` for a slot the writer saw
    /// empty), checked against the slot's live head under the same lock the append runs under. A write that omits it
    /// is refused (`expected-head-required`), so a session that went stale can never replace a newer handoff by
    /// simply not saying what it read. A caller who may not write the slot is refused before the head is looked at
    /// (`slot-refused`), and a head the caller may not read counts as no head: neither the refusals nor any id tell it
    /// that a note it cannot read is there.
    fn check_head(&self, caller: &Caller, p: &RememberParams) -> Result<()> {
        let Some(slot) = p.slot.as_deref() else {
            return if p.expected_head.is_some() { Err(refuse("expected-head-needs-slot")) } else { Ok(()) };
        };
        if !may_write_slot(slot, &caller.name, caller.owner) {
            return Err(refuse("slot-refused"));
        }
        let expected = p.expected_head.as_deref().ok_or_else(|| refuse("expected-head-required"))?;
        if expected != "none" && !is_hex64(expected) {
            return Err(refuse("id-invalid"));
        }
        let head = self.store.slot(slot)?.filter(|n| visible(caller, n)).map(|n| hex(n.event.id.as_bytes()));
        match head.as_deref() {
            None if expected == "none" => Ok(()),
            Some(head) if head == expected => Ok(()),
            _ => Err(refuse("resume-stale")),
        }
    }

    fn get(&mut self, caller: &Caller, p: GetParams) -> Result<Value> {
        let mut from_event = None;
        let note = if is_hex64(&p.id) {
            match self.store.get(&p.id)? {
                Some(note) => Some(note),
                // The id of a supersede event (`superseded_by` on the retired note) names the note that replaced it.
                None => match self.store.current_for_event(&p.id)? {
                    Some(current) => {
                        from_event = Some(p.id.clone());
                        self.store.get(&current)?
                    }
                    None => None,
                },
            }
        } else if readable_slot(&p.id) {
            self.store.slot(&p.id)?
        } else {
            return Err(refuse("id-invalid"));
        };
        match note {
            Some(note) if visible(caller, &note) => {
                let mut shown = view(&self.store, caller, &note)?;
                if let Some(event) = from_event {
                    shown["resolved_from"] = json!(event);
                }
                Ok(shown)
            }
            _ => Err(refuse("not-found")),
        }
    }

    /// Newest first, only notes this caller may see, so neither the page contents nor `next_before` reveal how many
    /// it cannot (a page used to be cut from all notes and then filtered; the cursor was the last unfiltered seq).
    fn list_recent(&mut self, caller: &Caller, p: ListParams) -> Result<Value> {
        let limit = p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, 500);
        let epoch = Some(p.epoch.unwrap_or(2));
        let (mut shown, mut cursor, mut scanned) = (Vec::new(), p.before, 0usize);
        'pages: loop {
            let page = self.store.list_recent(limit, cursor, epoch)?;
            let more = page.len() == limit;
            for note in &page {
                scanned += 1;
                cursor = Some(note.seq);
                if visible(caller, note) {
                    shown.push(view(&self.store, caller, note)?);
                    if shown.len() == limit {
                        break 'pages;
                    }
                }
            }
            if !more || scanned >= MAX_LIST_SCAN {
                cursor = None;
                break;
            }
        }
        let next_before = if shown.len() == limit { cursor } else { None };
        Ok(json!({"notes": shown, "next_before": next_before}))
    }

    /// Supersede a note. By its author or the owner this is in force at once. By any other agent (which must offer a
    /// replacement note of its own) it is only a proposal, listed on the note until its author or the owner accepts
    /// it with `accept_correction`. The latest correction in force wins.
    fn supersede(&mut self, caller: &Caller, p: SupersedeParams) -> Result<Value> {
        if !is_hex64(&p.target) || p.replacement.as_deref().is_some_and(|r| !is_hex64(r)) {
            return Err(refuse("id-invalid"));
        }
        // A note the caller may not read is refused as one that does not exist: neither the target nor the
        // replacement can be probed for existence through the refusal code.
        if !self.store.get(&p.target)?.is_some_and(|n| visible(caller, &n)) {
            return Err(refuse("supersede-target-unknown"));
        }
        if let Some(replacement) = &p.replacement {
            if !self.store.get(replacement)?.is_some_and(|n| visible(caller, &n)) {
                return Err(refuse("supersede-replacement-unknown"));
            }
        }
        self.rate(caller)?;
        let mut tags = vec![vec!["supersedes".to_owned(), p.target.clone()]];
        if let Some(replacement) = &p.replacement {
            tags.push(vec!["replacement".to_owned(), replacement.clone()]);
        }
        if let Some(reason) = &p.reason {
            tags.push(vec!["reason".to_owned(), reason.clone()]);
        }
        let event = Event::sign(self.key(&caller.name)?, now(), SUPERSEDE_KIND, tags, String::new())?;
        let id = self.store.record(event)?;
        let target = self.store.get(&p.target)?.ok_or_else(|| refuse("not-found"))?;
        let proposed = target.superseded_by.as_deref() != Some(id.as_str()) && target.author_name != caller.name && !caller.owner;
        Ok(json!({"event": id, "proposed": proposed, "target": view(&self.store, caller, &target)?}))
    }

    /// Accept a proposed correction of a note: signed by the note's author or the owner. From then on the proposal is
    /// in force, and it wins over any correction that came before it.
    fn accept_correction(&mut self, caller: &Caller, p: AcceptParams) -> Result<Value> {
        if !is_hex64(&p.proposal) {
            return Err(refuse("id-invalid"));
        }
        // Only a note the caller may read can be reached through its proposal: anything else is not found.
        let target = self.store.correction_target(&p.proposal)?.and_then(|id| self.store.get(&id).ok().flatten());
        if !target.as_ref().is_some_and(|t| visible(caller, t)) {
            return Err(refuse("not-found"));
        }
        self.rate(caller)?;
        let event = Event::sign(self.key(&caller.name)?, now(), ACCEPT_KIND, vec![vec!["accepts".to_owned(), p.proposal.clone()]], String::new())?;
        let id = self.store.record(event)?;
        let target = self.store.get(&target.map(|t| hex(t.event.id.as_bytes())).unwrap_or_default())?.ok_or_else(|| refuse("not-found"))?;
        Ok(json!({"event": id, "target": view(&self.store, caller, &target)?}))
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
/// embed the query unlocked, gather candidates locked (`recall_gather`); rerank unlocked (`Prepared::finish`); then
/// re-read the returned notes locked (`recall_answer`).
fn recall(state: &Mutex<State>, caller: &Caller, p: RecallParams) -> Result<Value> {
    let (prepared, reranker) = recall_gather(state, caller, p)?;
    let outcome = prepared.finish(reranker.as_deref().map(|r| r as &dyn Reranker));
    recall_answer(state, caller, &outcome)
}

fn recall_gather(state: &Mutex<State>, caller: &Caller, p: RecallParams) -> Result<(Prepared, Option<SharedReranker>)> {
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
            include_web: p.include_web,
            now: now(),
        };
        (query, s.embedder.clone(), s.reranker.clone())
    };
    let model = embedder.as_ref().map(|e| e.model_id().to_owned());
    let vector = embedder.as_deref().and_then(|e| query_vector(&query, e));
    let prepared = lock(state).store.recall_prepare(&query, model.as_deref().map(|m| (m, vector)))?;
    Ok((prepared, reranker))
}

/// The last step, under the lock again. Anything may have happened while the models ran, so nothing from the first
/// read is trusted: the caller is looked up again (revoked: refused; its scopes and owner flag as they are now), and
/// every note is re-read and re-verified. A note chosen as live memory that is no longer live (superseded, or its
/// author quarantined) is dropped; when that leaves no live note the answer is undetermined, never found. A note that
/// was already a correction keeps its label, and a quarantined one is only ever a stub.
fn recall_answer(state: &Mutex<State>, caller: &Caller, outcome: &RecallOutcome) -> Result<Value> {
    let s = lock(state);
    let record = s.store.agent(&caller.pubkey)?.ok_or_else(|| refuse("token-refused"))?;
    if record.revoked_at.is_some() {
        return Err(refuse("agent-revoked"));
    }
    let caller = Caller { name: caller.name.clone(), pubkey: caller.pubkey.clone(), owner: record.owner, scopes: record.scopes };
    let mut status = outcome.status.clone();
    let (mut items, mut live, mut changed, mut justified) = (Vec::new(), 0usize, false, false);
    let mut states: BTreeMap<String, usize> = BTreeMap::new();
    for item in &outcome.items {
        match s.store.get(&item.id) {
            Ok(Some(note)) if visible(&caller, &note) => {
                let dead = note.quarantined || note.superseded_by.is_some() || validity(&note.meta, now()) != "current";
                if item.correction.is_none() && dead {
                    changed = true;
                    continue;
                }
                live += usize::from(item.correction.is_none());
                // What the statement stands on is worked out again from the notes as they are now (the kept note and the
                // repeaters that still read as visible and live): the label recall gathered before the models ran may rest
                // on a root that has since been quarantined.
                let mut evidence = item.evidence;
                if item.correction.is_none() && !note.quarantined {
                    let mut holders = vec![note.clone()];
                    let mut failed = false;
                    for other in &item.also_by_ids {
                        match s.store.get(other) {
                            Ok(Some(n)) if visible(&caller, &n) && !n.quarantined && n.superseded_by.is_none() && validity(&n.meta, now()) == "current" => holders.push(n),
                            Ok(_) => {}
                            Err(_) => failed = true,
                        }
                    }
                    let fresh = if failed {
                        None
                    } else {
                        let refs: Vec<&StoredNote> = holders.iter().collect();
                        crate::shared::hybrid::group_evidence(&s.store, &refs, &|n| visible(&caller, n)).ok()
                    };
                    match fresh {
                        Some(fresh) => evidence = fresh,
                        None => {
                            status = RecallStatus::Undetermined("note-integrity");
                            continue;
                        }
                    }
                }
                // `found` stands on a note that cleared the relevance floor AND stands on something, as of now.
                justified |= item.correction.is_none() && item.relevant && evidence != "unverified";
                let correction = if note.quarantined { Some("quarantined") } else { item.correction.as_deref() };
                let mut shown = if note.quarantined {
                    stub(&note)
                } else {
                    match note_json(&s.store, &caller, &note, Some(evidence)) {
                        Ok(shown) => shown,
                        // A relation the store cannot read is not "no relation": the answer is not one.
                        Err(_) => {
                            status = RecallStatus::Undetermined("note-integrity");
                            continue;
                        }
                    }
                };
                shown["score"] = json!(item.score);
                // Others who stated the same words. Repetition is not support: see `evidence` and `roots`. `also_by`
                // is the old name of `repeated_by`.
                shown["repeated_by"] = json!(item.also_by);
                shown["repeated_by_ids"] = json!(item.also_by_ids);
                shown["capture"] = json!(item.capture);
                shown["kept_capture"] = json!(item.kept_capture);
                shown["also_by_captures"] = json!(item.also_by_captures);
                shown["also_by"] = json!(item.also_by);
                shown["also_by_ids"] = json!(item.also_by_ids);
                shown["correction"] = json!(correction);
                if let (None, Some(state)) = (item.correction.as_deref(), shown.get("state").and_then(Value::as_str)) {
                    *states.entry(state.to_owned()).or_default() += 1;
                }
                items.push(shown);
            }
            Ok(Some(_)) => changed |= item.correction.is_none(),
            Ok(None) | Err(_) => status = RecallStatus::Undetermined("note-integrity"),
        }
    }
    if status == RecallStatus::Found && changed && live == 0 {
        status = RecallStatus::Undetermined("note-changed");
    }
    // The note that justified `found` may be gone (superseded, expired or quarantined while the reranker ran): what is
    // left is a lead, not an answer.
    if status == RecallStatus::Found && live > 0 && !justified {
        status = RecallStatus::Undetermined("similar-note-unverified");
    }
    // Only withheld notes matched: from this caller's view nothing was found.
    if matches!(status, RecallStatus::Found | RecallStatus::Undetermined("similar-note-unverified")) && items.is_empty() {
        status = RecallStatus::Empty;
    }
    let (status, reason) = match status {
        RecallStatus::Found => ("found", None),
        RecallStatus::Empty => ("empty", None),
        RecallStatus::Undetermined(why) => ("undetermined", Some(why)),
    };
    Ok(json!({
        "status": status, "reason": reason, "items": items, "omitted": outcome.omitted, "indexed": outcome.indexed,
        "total": outcome.total, "query_digest": outcome.query_digest, "states": states,
        "judged": {
            "by": outcome.judged_by, "rerank_floor": outcome.rerank_floor, "cosine_floor": outcome.cosine_floor,
            "embed_model": outcome.embed_model, "rerank_model": outcome.rerank_model,
            "calibration_set": outcome.calibration_set,
        },
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
        "accept_correction" => s.accept_correction(&caller, parse(request.params)?),
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
mod peer;
mod server;
mod wire;

pub use cli::cli;
pub use import::{import_epoch1, ImportReport};
pub use mcp::{mcp, mcp_reply};
pub use peer::Admission;
pub use server::serve;
use wire::{note_json, stub, validity, view, visible};

#[cfg(test)]
mod tests;
