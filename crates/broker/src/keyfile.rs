// SPDX-License-Identifier: AGPL-3.0-or-later
//! The provider key at rest (NODE.md O7). The owner types the key once; after the owner's passkey approves the card
//! naming its SHA-256, the supervisor keeps it in one file outside the wall, so a restart does not ask for it again.
//!
//! The file is the supervisor's alone: a regular file (never a symlink), owned by the running user, mode 0600, one link,
//! in a private (0700) folder, written beside itself, synced, renamed into place, the folder synced. It is loaded only
//! when its SHA-256 equals the key digest the owner currently has approved (`engine/model-key.json`); anything else
//! leaves the node without a key and says why, in words that never include the key. The key does not enter the engine,
//! Aura, logs or replies: this module hands it only to the `KeyInbox` and the file.

use crate::engine_link::budget::KeyApproval;
use crate::keystore::{validate_key, KeyInbox, MAX_KEY_BYTES};
use canon::{codes, Result};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use zeroize::Zeroizing;

const FILE: &str = "model-key";
const TEMP: &str = ".model-key.new";
/// How long the ticket that carries a stored key into the inbox lives.
const TICKET_MS: u64 = 60_000;

/// What reading the stored key found.
pub enum Loaded {
    /// No file.
    Absent,
    /// A well-formed key whose digest is the approved one.
    Key(Zeroizing<String>),
    /// A well-formed key that is not the approved one (the owner approved another since, or none matches).
    NotApproved,
    /// A file or folder that is not what this module writes; the word says which part.
    Unsafe(&'static str),
}

/// What one reconcile pass did. The words are for the journal and never hold key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing to do (no approval yet, nothing stored, or already in step).
    Idle,
    /// The stored key was loaded into the inbox.
    Loaded,
    /// The key the owner approved was written to the file.
    Persisted,
    /// The stored key was not the approved one and was removed.
    Discarded,
    /// The stored key was not used, or could not be written, for this reason.
    Refused(&'static str),
}

pub struct KeyFile {
    dir: PathBuf,
}

impl KeyFile {
    /// `dir` is the supervisor's private folder for the key; it must exist (the state root creates it 0700).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn check_dir(&self) -> std::result::Result<(), &'static str> {
        let meta = std::fs::symlink_metadata(&self.dir).map_err(|_| "key-folder-missing")?;
        let own = rustix::process::geteuid().as_raw();
        if !meta.is_dir() || meta.uid() != own || meta.mode() & 0o077 != 0 {
            return Err("key-folder-not-private");
        }
        Ok(())
    }

    /// Read the stored key, accepting it only when it is exactly what `save` writes and its digest is `approved_sha256`.
    pub fn load(&self, approved_sha256: &str) -> Loaded {
        if let Err(reason) = self.check_dir() {
            // A missing folder is just "nothing stored"; a folder anyone else can use is not safe to read from.
            return if reason == "key-folder-missing" { Loaded::Absent } else { Loaded::Unsafe(reason) };
        }
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(self.dir.join(FILE))
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Loaded::Absent,
            Err(_) => return Loaded::Unsafe("key-file-unreadable-or-symlink"),
        };
        let Ok(meta) = file.metadata() else { return Loaded::Unsafe("key-file-unreadable-or-symlink") };
        if !meta.is_file() {
            return Loaded::Unsafe("key-file-not-regular");
        }
        if meta.uid() != rustix::process::geteuid().as_raw() || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 {
            return Loaded::Unsafe("key-file-permissions");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        if Read::by_ref(&mut file).take(MAX_KEY_BYTES as u64 + 1).read_to_end(&mut bytes).is_err() {
            return Loaded::Unsafe("key-file-unreadable-or-symlink");
        }
        let Ok(text) = std::str::from_utf8(&bytes) else { return Loaded::Unsafe("key-file-malformed") };
        if validate_key(text).is_err() {
            return Loaded::Unsafe("key-file-malformed");
        }
        if KeyApproval::for_key(text).key_sha256 != approved_sha256 {
            return Loaded::NotApproved;
        }
        Loaded::Key(Zeroizing::new(text.to_owned()))
    }

    /// Write the key: a new 0600 file beside the target, synced, renamed over it, the folder synced.
    pub fn save(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        self.check_dir().map_err(|_| codes::BROKER_KEY_STORE)?;
        let fresh = self.dir.join(TEMP);
        let _ = std::fs::remove_file(&fresh);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&fresh)
            .map_err(|_| codes::BROKER_KEY_STORE)?;
        let written = file.write_all(key.as_bytes()).and_then(|()| file.sync_all());
        drop(file);
        if written.is_err() || std::fs::rename(&fresh, self.dir.join(FILE)).is_err() {
            let _ = std::fs::remove_file(&fresh);
            return Err(codes::BROKER_KEY_STORE);
        }
        self.sync_dir()
    }

    /// Remove the stored key, if any (replacing or clearing the key; a missing file is already done).
    pub fn remove(&self) -> Result<()> {
        match std::fs::remove_file(self.dir.join(FILE)) {
            Ok(()) => self.sync_dir(),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(codes::BROKER_KEY_STORE),
        }
    }

    fn sync_dir(&self) -> Result<()> {
        File::open(&self.dir).and_then(|folder| folder.sync_all()).map_err(|_| codes::BROKER_KEY_STORE)
    }
}

/// Bring the file and the inbox in step with the key digest the owner has approved (`approved`: the `key_sha256` of
/// the approved `engine/model-key.json`, or `None` when no card has been approved or it could not be read):
/// - the inbox holds no key and the file holds the approved one: load it;
/// - the file holds some other key: remove it (the owner has since approved another);
/// - the inbox holds the approved key and the file does not: write it.
///
/// With no approval known nothing is loaded and nothing is written, and the file is left as it is.
pub fn reconcile(keys: &KeyInbox, file: &KeyFile, approved: Option<&str>, now_ms: u64) -> Step {
    let Some(approved) = approved else { return Step::Idle };
    let Ok(held) = keys.key_sha256() else { return Step::Refused("key-inbox") };
    match held {
        None => match file.load(approved) {
            Loaded::Absent => Step::Idle,
            Loaded::Unsafe(reason) => Step::Refused(reason),
            Loaded::NotApproved => match file.remove() {
                Ok(()) => Step::Discarded,
                Err(_) => Step::Refused("key-file-not-removed"),
            },
            Loaded::Key(key) => {
                let admitted = keys
                    .issue(now_ms, TICKET_MS)
                    .and_then(|ticket| keys.redeem(ticket.token(), key.to_string(), now_ms));
                if admitted.is_ok() {
                    Step::Loaded
                } else {
                    Step::Refused("key-inbox")
                }
            }
        },
        Some(held) if held == approved => {
            if matches!(file.load(approved), Loaded::Key(_)) {
                return Step::Idle;
            }
            match keys.key_to_persist(approved) {
                Ok(Some(key)) => match file.save(&key) {
                    Ok(()) => Step::Persisted,
                    Err(_) => Step::Refused("key-file-not-written"),
                },
                _ => Step::Refused("key-inbox"),
            }
        }
        // The owner typed a key the card does not name yet: nothing is stored for it until the card is approved.
        Some(_) => Step::Idle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU32, Ordering};

    const KEY: &str = "sk-0123456789abcdef0123456789abcdef";
    const OTHER: &str = "sk-fedcba9876543210fedcba9876543210";

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!("aukora-keyfile-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn file(&self) -> KeyFile {
            KeyFile::new(&self.0)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn digest(key: &str) -> String {
        KeyApproval::for_key(key).key_sha256
    }

    fn held(keys: &KeyInbox, key: &str) {
        let ticket = keys.issue(1, 1000).unwrap();
        keys.redeem(ticket.token(), key.to_owned(), 2).unwrap();
    }

    fn mode(dir: &Dir) -> u32 {
        std::fs::metadata(dir.0.join(FILE)).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn an_approved_key_is_written_0600_and_survives_a_restart() {
        let dir = Dir::new();
        let keys = KeyInbox::new();
        held(&keys, KEY);
        assert_eq!(reconcile(&keys, &dir.file(), Some(&digest(KEY)), 10), Step::Persisted);
        assert_eq!(mode(&dir), 0o600);
        assert_eq!(std::fs::read(dir.0.join(FILE)).unwrap(), KEY.as_bytes());
        assert!(!dir.0.join(TEMP).exists(), "the temporary file is renamed away");
        assert_eq!(reconcile(&keys, &dir.file(), Some(&digest(KEY)), 11), Step::Idle, "already in step: not rewritten");
        // A new process: an empty inbox, the same file, the same approval.
        let fresh = KeyInbox::new();
        assert_eq!(fresh.key_sha256().unwrap(), None);
        assert_eq!(reconcile(&fresh, &dir.file(), Some(&digest(KEY)), 20), Step::Loaded);
        assert_eq!(fresh.key_sha256().unwrap().as_deref(), Some(digest(KEY).as_str()));
        assert!(fresh.key_for_generation(fresh.state().unwrap().generation).is_ok());
    }

    #[test]
    fn a_key_the_owner_has_not_approved_is_not_written_and_a_missing_approval_loads_nothing() {
        let dir = Dir::new();
        let keys = KeyInbox::new();
        held(&keys, KEY);
        assert_eq!(reconcile(&keys, &dir.file(), None, 10), Step::Idle);
        assert_eq!(reconcile(&keys, &dir.file(), Some(&digest(OTHER)), 10), Step::Idle);
        assert!(!dir.0.join(FILE).exists());
        // A file already there is not loaded while no approval is known, and is left alone.
        dir.file().save(KEY).unwrap();
        let fresh = KeyInbox::new();
        assert_eq!(reconcile(&fresh, &dir.file(), None, 10), Step::Idle);
        assert_eq!(fresh.key_sha256().unwrap(), None);
        assert!(dir.0.join(FILE).exists());
    }

    #[test]
    fn a_stored_key_the_owner_did_not_approve_is_discarded_not_loaded() {
        let dir = Dir::new();
        dir.file().save(KEY).unwrap();
        let keys = KeyInbox::new();
        assert_eq!(reconcile(&keys, &dir.file(), Some(&digest(OTHER)), 10), Step::Discarded);
        assert_eq!(keys.key_sha256().unwrap(), None);
        assert!(!dir.0.join(FILE).exists());
    }

    #[test]
    fn a_file_that_is_not_ours_is_refused_with_a_reason_and_no_key() {
        let approved = digest(KEY);
        // Wrong mode.
        let dir = Dir::new();
        dir.file().save(KEY).unwrap();
        std::fs::set_permissions(dir.0.join(FILE), std::fs::Permissions::from_mode(0o640)).unwrap();
        let keys = KeyInbox::new();
        assert_eq!(reconcile(&keys, &dir.file(), Some(&approved), 10), Step::Refused("key-file-permissions"));
        assert_eq!(keys.key_sha256().unwrap(), None);
        // A symlink, even to a good file.
        let dir = Dir::new();
        std::fs::write(dir.0.join("real"), KEY).unwrap();
        std::fs::set_permissions(dir.0.join("real"), std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(dir.0.join("real"), dir.0.join(FILE)).unwrap();
        let keys = KeyInbox::new();
        assert_eq!(reconcile(&keys, &dir.file(), Some(&approved), 10), Step::Refused("key-file-unreadable-or-symlink"));
        assert_eq!(keys.key_sha256().unwrap(), None);
        // Not a regular file.
        let dir = Dir::new();
        std::fs::create_dir(dir.0.join(FILE)).unwrap();
        let keys = KeyInbox::new();
        assert!(matches!(reconcile(&keys, &dir.file(), Some(&approved), 10), Step::Refused(_)));
        assert_eq!(keys.key_sha256().unwrap(), None);
        // A second hard link.
        let dir = Dir::new();
        dir.file().save(KEY).unwrap();
        std::fs::hard_link(dir.0.join(FILE), dir.0.join("copy")).unwrap();
        let keys = KeyInbox::new();
        assert_eq!(reconcile(&keys, &dir.file(), Some(&approved), 10), Step::Refused("key-file-permissions"));
        // Not a key.
        let dir = Dir::new();
        std::fs::write(dir.0.join(FILE), "hello\n").unwrap();
        std::fs::set_permissions(dir.0.join(FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
        let keys = KeyInbox::new();
        assert_eq!(reconcile(&keys, &dir.file(), Some(&approved), 10), Step::Refused("key-file-malformed"));
        // A folder others can enter.
        let dir = Dir::new();
        dir.file().save(KEY).unwrap();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        let keys = KeyInbox::new();
        assert_eq!(reconcile(&keys, &dir.file(), Some(&approved), 10), Step::Refused("key-folder-not-private"));
        assert_eq!(keys.key_sha256().unwrap(), None);
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn replacing_or_clearing_the_key_removes_the_file() {
        let dir = Dir::new();
        dir.file().save(KEY).unwrap();
        assert!(dir.0.join(FILE).exists());
        dir.file().remove().unwrap();
        assert!(!dir.0.join(FILE).exists());
        dir.file().remove().unwrap();
        // A save over an unsafe leftover replaces it with a proper file.
        std::fs::write(dir.0.join(FILE), "junk").unwrap();
        std::fs::set_permissions(dir.0.join(FILE), std::fs::Permissions::from_mode(0o666)).unwrap();
        dir.file().save(OTHER).unwrap();
        assert_eq!(mode(&dir), 0o600);
        assert_eq!(std::fs::read(dir.0.join(FILE)).unwrap(), OTHER.as_bytes());
        assert!(dir.file().save("not-a-key").is_err());
    }

    #[test]
    fn the_key_digest_and_key_never_leak_through_the_steps() {
        // The step words are fixed text: none can carry the key.
        let dir = Dir::new();
        let keys = KeyInbox::new();
        held(&keys, KEY);
        let step = reconcile(&keys, &dir.file(), Some(&digest(KEY)), 10);
        assert!(!format!("{step:?}").contains("sk-"));
    }
}
