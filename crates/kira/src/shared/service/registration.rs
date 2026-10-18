// SPDX-License-Identifier: AGPL-3.0-or-later
//! Registration spans SQLite and private files: a durable intent makes interrupted steps resumable.

use super::*;

#[derive(Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Intent {
    scopes: Vec<String>,
    owner: bool,
}

impl Intent {
    fn new(scopes: &[String], owner: bool) -> Result<Self> {
        if scopes.is_empty() || scopes.iter().any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control)) {
            return Err(refuse("agent-scopes"));
        }
        Ok(Self { scopes: scopes.to_vec(), owner })
    }

    fn matches(&self, agent: &super::super::store::AgentRecord, name: &str) -> bool {
        agent.name == name && agent.scopes == self.scopes && agent.owner == self.owner && agent.revoked_at.is_none()
    }
}

fn intent_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("register-{name}.json"))
}

fn load_intent(dir: &Path, name: &str) -> Result<Option<Intent>> {
    let path = intent_path(dir, name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_private(&path, 1 << 20)?;
            serde_json::from_slice(&bytes).map(Some).map_err(|_| refuse("registration-state"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(refuse("registration-state")),
    }
}

/// Whether a path exists. Only "not found" means absent: any other stat error refuses rather than reading as "no key".
pub(super) fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(refuse("state-read")),
    }
}

/// Where a fresh token goes. The token is delivered before its hash is saved: a delivered token that was never saved is
/// only unusable, while a saved token that never arrived could lock its holder out (a rotated last owner, a first owner
/// whose retry then needs the token it never received).
pub(super) trait Delivery {
    fn send(&mut self, token: &str) -> Result<()>;
    /// Called when the delivered token's save was refused: remove what `send` left, so a retry is not blocked by it.
    fn withdraw(&mut self) {}
}

/// The library calls return the token to their caller once it is saved.
impl Delivery for () {
    fn send(&mut self, _token: &str) -> Result<()> {
        Ok(())
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir).and_then(|file| file.sync_all()).map_err(|_| refuse("state-write"))
}

/// A legacy interrupted registration has a matching key and row, but has never acquired a token. A key without a
/// row needs the durable intent: otherwise the original requested scopes/owner cannot be recovered safely.
fn unfinished(dir: &Path, store: &SharedStore, name: &str, intent: &Intent) -> Result<bool> {
    let key = load_key(dir, name)?;
    let pubkey = hex(key.public_key()?.as_bytes());
    let matches = store.agent(&pubkey)?.is_some_and(|agent| intent.matches(&agent, name));
    Ok(matches && !load_tokens(dir)?.values().any(|holder| holder == name))
}

/// Generates a key (file mode 0600) and registers its public key. Refuses a name that already has a key.
pub(super) fn create_agent(dir: &Path, store: &SharedStore, name: &str, scopes: &[String], owner: bool) -> Result<()> {
    agent_name(name)?;
    Intent::new(scopes, owner)?;
    let path = key_path(dir, name);
    if present(&path)? {
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
    // A crash during the private-file write leaves only a disposable staging file, never a partial signing key.
    let temp = path.with_extension("key.new");
    let _ = fs::remove_file(&temp);
    write_private(&temp, material.as_ref(), true)?;
    fs::rename(&temp, &path).map_err(|_| refuse("state-write"))?;
    sync_dir(&dir.join(KEYS))?;
    if let Err(refusal) = store.register_agent(name, &pubkey, scopes, owner) {
        let _ = fs::remove_file(&path);
        return Err(refusal);
    }
    Ok(())
}

/// A fresh token for `name`, delivered first and then saved; with `rotate`, every earlier token of that agent is removed
/// in the same save. A refused delivery changes nothing, so a failed `token --rotate` keeps the earlier tokens.
fn issue_token(dir: &Path, name: &str, rotate: bool, delivery: &mut impl Delivery) -> Result<String> {
    let token = hex(random32()?.as_ref());
    delivery.send(&token)?;
    authorization::probe("token-delivered");
    let saved = load_tokens(dir).and_then(|mut tokens| {
        if rotate {
            tokens.retain(|_, holder| holder != name);
        }
        tokens.insert(token_hash(&token), name.to_owned());
        save_tokens(dir, &tokens)
    });
    if let Err(refusal) = saved {
        delivery.withdraw();
        return Err(refusal);
    }
    authorization::probe("token-issued");
    Ok(token)
}

/// Registers an agent, or resumes the exact interrupted registration. A completed registration still refuses reuse.
pub fn register(dir: &Path, name: &str, scopes: &[String], owner: bool) -> Result<String> {
    register_with_delivery(dir, name, scopes, owner, &mut ())
}

/// CLI delivery stays inside the recoverable phase: a refused output or crash before the token is saved keeps the
/// intent and leaves no token, so the retry needs no owner token. Once saved, the token has been delivered.
pub(super) fn register_with_delivery(
    dir: &Path, name: &str, scopes: &[String], owner: bool, delivery: &mut impl Delivery,
) -> Result<String> {
    agent_name(name)?;
    if name == IMPORT_AGENT {
        return Err(refuse("agent-takes-no-token"));
    }
    let wanted = Intent::new(scopes, owner)?;
    let state = State::open(dir)?;
    // Registration and every token update share revoke's cross-process guard.
    let _authorization = request_guard(dir)?;
    match load_intent(dir, name)? {
        Some(intent) if intent != wanted => return Err(refuse("agent-exists")),
        Some(_) => (),
        None => {
            if present(&key_path(dir, name))? && !unfinished(dir, &state.store, name, &wanted)? {
                return Err(refuse("agent-exists"));
            }
            let bytes = serde_json::to_vec(&wanted).map_err(|_| refuse("registration-state"))?;
            let path = intent_path(dir, name);
            let temp = path.with_extension("json.new");
            let _ = fs::remove_file(&temp);
            write_private(&temp, &bytes, true)?;
            fs::rename(&temp, path).map_err(|_| refuse("state-write"))?;
            sync_dir(dir)?;
        }
    }
    if present(&key_path(dir, name))? {
        let key = load_key(dir, name)?;
        let pubkey = hex(key.public_key()?.as_bytes());
        match state.store.agent(&pubkey)? {
            Some(agent) if wanted.matches(&agent, name) => (),
            Some(_) => return Err(refuse("agent-exists")),
            None => state.store.register_agent(name, &pubkey, scopes, owner)?,
        }
    } else {
        create_agent(dir, &state.store, name, scopes, owner)?;
    }
    authorization::probe("registration-created");
    // A retry after a crash between the save and clearing the intent (the holder has that token) replaces it.
    let token = issue_token(dir, name, true, delivery)?;
    sync_dir(dir)?;
    fs::remove_file(intent_path(dir, name)).map_err(|_| refuse("state-write"))?;
    sync_dir(dir)?;
    Ok(token)
}

/// The first owner's interrupted row must not make its own retry require the token that it never received. A retry
/// can only finish that same live owner with the exact privileges, and only while no token of it is saved: a saved
/// token was delivered first, so a leftover intent beside it never lets anyone rotate the live owner without it.
/// Other credential operations retain their gate.
pub(super) fn require_registration_owner(
    dir: &Path, owner_token_file: Option<&Path>, name: &str, scopes: &[String], owner: bool,
) -> Result<()> {
    let gate = require_owner(dir, owner_token_file);
    if gate != Err(refuse("owner-token-required")) || !owner {
        return gate;
    }
    agent_name(name)?;
    let wanted = Intent::new(scopes, owner)?;
    let state = State::open(dir)?;
    let _authorization = request_guard(dir)?;
    if state.store.is_last_live_owner(name)? {
        let pending = load_intent(dir, name)?;
        let key = load_key(dir, name)?;
        let pubkey = hex(key.public_key()?.as_bytes());
        let matches = state.store.agent(&pubkey)?.is_some_and(|agent| wanted.matches(&agent, name));
        let undelivered = !load_tokens(dir)?.values().any(|holder| holder == name);
        if matches && undelivered && pending.as_ref().is_none_or(|intent| intent == &wanted) {
            return Ok(());
        }
    }
    gate
}

/// Issues one more token for an agent that already has a key (a lost token). Earlier tokens stay valid unless
/// `rotate` is set, which replaces them. A revoked agent gets no token.
pub fn reissue(dir: &Path, name: &str, rotate: bool) -> Result<String> {
    reissue_with_delivery(dir, name, rotate, &mut ())
}

/// `reissue`, delivering the token before it is saved (the CLI's `token NAME`).
pub(super) fn reissue_with_delivery(dir: &Path, name: &str, rotate: bool, delivery: &mut impl Delivery) -> Result<String> {
    let mut state = State::open(dir)?;
    let _authorization = request_guard(dir)?;
    if name == IMPORT_AGENT {
        return Err(refuse("agent-takes-no-token"));
    }
    let pubkey = state.pubkey_of(name)?;
    if state.store.agent(&pubkey)?.is_none_or(|a| a.revoked_at.is_some()) {
        return Err(refuse("agent-revoked"));
    }
    issue_token(dir, name, rotate, delivery)
}
