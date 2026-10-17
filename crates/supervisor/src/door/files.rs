// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opening the files the door trusts (its policy, its Kira token) and the folders it writes into.
//!
//! The checks run on the OPEN file (`fstat` on the descriptor, never a second look at the path), the open refuses a
//! final symlink, and the owner must be the door's own user or root, so a file the engine could replace or write is
//! not accepted however its mode bits look.

use canon::{Refusal, Result};
use rustix::fs::OFlags;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// The effective uid of this process.
pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Whether a file owned by `owner` may be trusted by a process running as `effective`.
pub const fn owner_ok(owner: u32, effective: u32) -> bool {
    owner == effective || owner == 0
}

/// Open a regular file for reading with the final symlink refused, and check it on the descriptor: a regular file,
/// at most `max` bytes, owned by this user or root, with none of the `forbidden` mode bits set.
pub fn open_trusted(path: &Path, max: u64, forbidden: u32, reason: &'static str) -> Result<File> {
    let refuse = || Refusal { organ: "supervisor", reason };
    let file = OpenOptions::new()
        .read(true)
        // NONBLOCK so a FIFO swapped in for a file cannot hold the open; the check below refuses anything not a regular file.
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| refuse())?;
    let meta = file.metadata().map_err(|_| refuse())?;
    if !meta.is_file() || meta.len() > max || meta.permissions().mode() & forbidden != 0 || !owner_ok(meta.uid(), euid()) {
        return Err(refuse());
    }
    Ok(file)
}

/// A folder the door owns: a real directory (not a symlink) owned by this user, created 0700 when missing and
/// tightened to 0700 when present.
pub fn private_dir(path: &Path, reason: &'static str) -> Result<()> {
    let refuse = || Refusal { organ: "supervisor", reason };
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != euid() {
                return Err(refuse());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|_| refuse())?;
        }
        Err(_) => return Err(refuse()),
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|_| refuse())
}

/// A directory the engine could write into (group or others have write permission) cannot hold the socket or the
/// state: whoever can add or rename entries there can wedge or replace them.
pub fn parent_not_writable_by_others(path: &Path, reason: &'static str) -> Result<()> {
    let refuse = || Refusal { organ: "supervisor", reason };
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let meta = std::fs::metadata(parent).map_err(|_| refuse())?;
    if !meta.is_dir() || meta.permissions().mode() & 0o022 != 0 || !owner_ok(meta.uid(), euid()) {
        return Err(refuse());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-door-files-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn write(path: &Path, mode: u32) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(b"x").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_trusted_file_is_a_small_regular_file_of_ours_with_no_forbidden_bits() {
        let dir = temp("trusted");
        let ok = dir.join("ok");
        write(&ok, 0o600);
        assert!(open_trusted(&ok, 16, 0o077, "x").is_ok());
        let loose = dir.join("loose");
        write(&loose, 0o644);
        assert!(open_trusted(&loose, 16, 0o077, "x").is_err());
        assert!(open_trusted(&ok, 0, 0o077, "x").is_err());
        assert!(open_trusted(&dir.join("missing"), 16, 0o077, "x").is_err());
        assert!(open_trusted(&dir, 16, 0o077, "x").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_fifo_in_place_of_a_file_is_refused_without_waiting_for_a_writer() {
        let dir = temp("fifo");
        let fifo = dir.join("policy");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        assert!(open_trusted(&fifo, 16, 0o077, "x").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_symlink_is_never_followed() {
        let dir = temp("link");
        let real = dir.join("real");
        write(&real, 0o600);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_trusted(&link, 16, 0o077, "x").is_err());
        let state = dir.join("state-link");
        std::os::unix::fs::symlink(&dir, &state).unwrap();
        assert!(private_dir(&state, "x").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ownership_is_ours_or_root() {
        assert!(owner_ok(1001, 1001));
        assert!(owner_ok(0, 1001));
        assert!(!owner_ok(1002, 1001));
    }

    #[test]
    fn a_private_dir_is_created_and_tightened() {
        let dir = temp("private");
        let state = dir.join("state");
        private_dir(&state, "x").unwrap();
        assert_eq!(std::fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o700);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&state, "x").unwrap();
        assert_eq!(std::fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o700);
        let file = dir.join("not-a-dir");
        write(&file, 0o600);
        assert!(private_dir(&file, "x").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_socket_folder_others_can_write_is_refused() {
        let dir = temp("parent");
        assert!(parent_not_writable_by_others(&dir.join("door.sock"), "x").is_ok());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(parent_not_writable_by_others(&dir.join("door.sock"), "x").is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(parent_not_writable_by_others(&dir.join("door.sock"), "x").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
