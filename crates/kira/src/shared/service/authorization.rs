// SPDX-License-Identifier: AGPL-3.0-or-later
//! Serialize authorization with revocation, including a revoke run by a separate CLI process.

use super::*;
use rustix::fs::{flock, FlockOperation};

const REQUEST_LOCK: &str = "requests.lock";

/// A fresh file description for every guarded phase. Keep the returned file alive through both the caller check
/// and the request's store access. Closing it releases the OS lock, including on an error or a process crash.
/// Never rename or remove this file: external CLI revocations must lock the same inode as the running service.
/// The lock is taken on the inode that was opened (never through a symlink), and it is kept only if
/// `requests.lock` still names that inode afterwards: a file swapped in between the open and the lock is retried, so
/// two guards never lock different inodes for the same path. (A same-user process that unlinks the file while it is
/// held is outside the boundary: it could edit the store directly.)
pub(super) fn request_guard(dir: &Path) -> Result<fs::File> {
    let path = dir.join(REQUEST_LOCK);
    for _ in 0..8 {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|_| refuse("request-lock"))?;
        let held = file.metadata().map_err(|_| refuse("request-lock"))?;
        if !held.is_file() {
            return Err(refuse("request-lock"));
        }
        if held.permissions().mode() & 0o077 != 0 {
            return Err(refuse("request-lock-mode"));
        }
        probe("lock-opened");
        flock(&file, FlockOperation::LockExclusive).map_err(|_| refuse("request-lock"))?;
        match fs::symlink_metadata(&path) {
            Ok(named) if named.dev() == held.dev() && named.ino() == held.ino() => return Ok(file),
            _ => continue,
        }
    }
    Err(refuse("request-lock"))
}

/// A test's view into a guarded operation at a named stage (`lock-opened`, `store-updated`, `tokens-saved`); a no-op
/// outside tests.
pub(super) fn probe(_stage: &'static str) {
    #[cfg(test)]
    PROBE.with(|probe| {
        if let Some(seen) = probe.borrow_mut().as_mut() {
            seen(_stage);
        }
    });
}

#[cfg(test)]
thread_local! {
    pub(super) static PROBE: std::cell::RefCell<Option<Box<dyn FnMut(&'static str)>>> = const { std::cell::RefCell::new(None) };
}

impl State {
    /// Every request sees the current `tokens.json`: it is re-read whenever its stamp changes. The request's guard
    /// stays held while reading the agent row and serving the request, so a CLI revoke cannot split those reads.
    pub(super) fn caller(&mut self, token: &str) -> Result<Caller> {
        let stamp = tokens_stamp(&self.dir)?;
        if stamp != self.tokens_stamp {
            self.tokens = load_tokens(&self.dir)?;
            self.tokens_stamp = stamp;
        }
        let name = self.tokens.get(&token_hash(token)).cloned().ok_or_else(|| refuse("token-refused"))?;
        let pubkey = self.pubkey_of(&name).map_err(|_| refuse("token-refused"))?;
        self.refresh_caller(&name, &pubkey)
    }

    /// Refresh an admitted identity after an unlocked model call. Call only while the request guard is held;
    /// ownership and scopes are current along with the revocation status.
    pub(super) fn refresh_caller(&self, name: &str, pubkey: &str) -> Result<Caller> {
        let agent = self.store.agent(pubkey)?.ok_or_else(|| refuse("token-refused"))?;
        if agent.revoked_at.is_some() {
            return Err(refuse("agent-revoked"));
        }
        Ok(Caller { name: name.to_owned(), pubkey: pubkey.to_owned(), owner: agent.owner, scopes: agent.scopes })
    }
}
