// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::{bail, Result};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub fn now_ms() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
pub fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}
pub fn prepare(dir: &Path) -> Result<File> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let meta = fs::symlink_metadata(dir)?;
    // SAFETY: geteuid has no pointers or memory side effects.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
        bail!("supervisor:state-not-private");
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join("supervisor.lock"))?;
    // SAFETY: lock is an owned live descriptor and remains held by Node.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("supervisor:already-running");
    }
    Ok(lock)
}
pub fn connection(path: &Path) -> Result<Connection> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => {
            file.sync_all()?;
            File::open(
                path.parent()
                    .ok_or_else(|| anyhow::anyhow!("supervisor:database-path"))?,
            )?
            .sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    private_file(path)?;
    let db = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.pragma_update(None, "recursive_triggers", true)?;
    aura::initialize(&db)?;
    Ok(db)
}
pub fn node_key(dir: &Path) -> Result<SigningKey> {
    let path = dir.join("node.ed25519");
    let mut key = Zeroizing::new([0; 32]);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(mut file) => {
            getrandom::fill(&mut *key)?;
            file.write_all(&*key)?;
            file.sync_all()?;
            File::open(dir)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            private_file(&path)?;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            if file.metadata()?.len() != 32 {
                bail!("supervisor:key-invalid");
            }
            file.read_exact(&mut *key)?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(SigningKey::from_bytes(&key))
}
pub(crate) fn private_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    // SAFETY: geteuid takes no arguments.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_file() || meta.nlink() != 1 || meta.uid() != uid || meta.mode() & 0o777 != 0o600 {
        bail!("supervisor:file-not-private");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_is_private_stable_and_links_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state");
        let _lock = prepare(&path).unwrap();
        let a = node_key(&path).unwrap();
        let b = node_key(&path).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_ne!(a.to_bytes(), [0u8; 32]);
        assert_eq!(
            fs::metadata(path.join("node.ed25519")).unwrap().mode() & 0o777,
            0o600
        );
        fs::set_permissions(path.join("node.ed25519"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(node_key(&path).is_err());
        fs::set_permissions(path.join("node.ed25519"), fs::Permissions::from_mode(0o600)).unwrap();
        let linked = tmp.path().join("linked");
        fs::hard_link(path.join("node.ed25519"), &linked).unwrap();
        assert!(node_key(&path).is_err());
        fs::remove_file(linked).unwrap();
        fs::remove_file(path.join("node.ed25519")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("outside"), path.join("node.ed25519")).unwrap();
        assert!(node_key(&path).is_err());
    }
    #[test]
    fn every_connection_is_wal_and_writer_is_exclusive() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state");
        let _lock = prepare(&path).unwrap();
        assert!(prepare(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let insecure = tmp.path().join("insecure");
        fs::create_dir(&insecure).unwrap();
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare(&insecure).is_err());
        let db = connection(&path.join("node.sqlite3")).unwrap();
        let second = connection(&path.join("node.sqlite3")).unwrap();
        for db in [db, second] {
            assert_eq!(
                db.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
                    .unwrap(),
                "wal"
            );
            assert_eq!(
                db.query_row("PRAGMA synchronous", [], |r| r.get::<_, u32>(0))
                    .unwrap(),
                2
            );
            assert_eq!(
                db.query_row("PRAGMA recursive_triggers", [], |r| r.get::<_, u32>(0))
                    .unwrap(),
                1
            );
        }
    }
}
