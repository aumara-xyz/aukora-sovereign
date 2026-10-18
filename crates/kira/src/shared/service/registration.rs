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

/// A fresh token for `name`; with `rotate`, every earlier token of that agent is removed in the same save.
fn issue_token(dir: &Path, name: &str, rotate: bool) -> Result<String> {
    let token = hex(random32()?.as_ref());
    let mut tokens = load_tokens(dir)?;
    if rotate {
        tokens.retain(|_, holder| holder != name);
    }
    tokens.insert(token_hash(&token), name.to_owned());
    save_tokens(dir, &tokens)?;
    authorization::probe("token-issued");
    Ok(token)
}

/// Registers an agent, or resumes the exact interrupted registration. A completed registration still refuses reuse.
pub fn register(dir: &Path, name: &str, scopes: &[String], owner: bool) -> Result<String> {
    register_with_delivery(dir, name, scopes, owner, |_| Ok(()))
}

/// CLI delivery stays inside the recoverable phase: a refused output or crash before delivery keeps the intent.
pub(super) fn register_with_delivery(
    dir: &Path, name: &str, scopes: &[String], owner: bool, deliver: impl FnOnce(&str) -> Result<()>,
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
            if fs::symlink_metadata(key_path(dir, name)).is_ok() && !unfinished(dir, &state.store, name, &wanted)? {
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
    if fs::symlink_metadata(key_path(dir, name)).is_ok() {
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
    // A crash after saving the token but before clearing the intent may leave an unreturned token; replace it.
    let token = issue_token(dir, name, true)?;
    sync_dir(dir)?;
    deliver(&token)?;
    fs::remove_file(intent_path(dir, name)).map_err(|_| refuse("state-write"))?;
    sync_dir(dir)?;
    Ok(token)
}

/// The first owner's interrupted row must not make its own retry require the token that it never received. A retry
/// can only finish that same live owner with the exact privileges; other credential operations retain their gate.
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
        if matches && (pending.as_ref() == Some(&wanted) || pending.is_none() && unfinished(dir, &state.store, name, &wanted)?) {
            return Ok(());
        }
    }
    gate
}

/// Issues one more token for an agent that already has a key (a lost token). Earlier tokens stay valid unless
/// `rotate` is set, which replaces them. A revoked agent gets no token.
pub fn reissue(dir: &Path, name: &str, rotate: bool) -> Result<String> {
    let mut state = State::open(dir)?;
    let _authorization = request_guard(dir)?;
    if name == IMPORT_AGENT {
        return Err(refuse("agent-takes-no-token"));
    }
    let pubkey = state.pubkey_of(name)?;
    if state.store.agent(&pubkey)?.is_none_or(|a| a.revoked_at.is_some()) {
        return Err(refuse("agent-revoked"));
    }
    issue_token(dir, name, rotate)
}
