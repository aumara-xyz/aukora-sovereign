// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{Refusal, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ProtectedStore {
    path: PathBuf,
    root_uid: u32,
    anchor: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub len: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

impl From<&Metadata> for FileIdentity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LockInfo {
    pub dev: u64,
    pub ino: u64,
    pub token: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    Locked,
    BeforeOpen,
    AfterOpen,
    TempSynced,
    DirectorySynced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncPoint {
    Lock,
    Temp,
    Directory,
}

#[cfg(test)]
thread_local! {
    static SYNC_FAILURE: std::cell::Cell<Option<SyncPoint>> = const { std::cell::Cell::new(None) };
}

impl ProtectedStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            root_uid: 0,
            anchor: PathBuf::from("/"),
        }
    }

    #[cfg(test)]
    pub(crate) fn test(path: impl Into<PathBuf>, root_uid: u32, anchor: PathBuf) -> Self {
        Self {
            path: path.into(),
            root_uid,
            anchor,
        }
    }

    #[cfg(test)]
    pub(crate) fn path_for_test(&self) -> &Path {
        &self.path
    }

    pub fn identity(&self) -> Result<Option<FileIdentity>> {
        self.check_path()?;
        let before = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_refusal(error)),
        };
        self.protected_node(&before, false)?;
        let file = open_read(&self.path)?;
        let opened = file.metadata().map_err(io_refusal)?;
        let same_file = |left: &Metadata, right: &Metadata| self.open_identity(left, right, false);
        same_file(&before, &opened)?;
        let after = fs::symlink_metadata(&self.path).map_err(io_refusal)?;
        same_file(&opened, &after)?;
        self.check_path()?;
        Ok(Some(FileIdentity::from(&after)))
    }

    pub fn read(&self, max: usize) -> Result<Option<Vec<u8>>> {
        self.read_inner(max, &mut |_| Ok(()))
    }

    #[cfg(test)]
    pub(crate) fn read_hook(
        &self,
        max: usize,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<Option<Vec<u8>>> {
        self.read_inner(max, hook)
    }

    pub fn transact<F>(&self, max: usize, replace: F) -> Result<()>
    where
        F: FnOnce(Option<Vec<u8>>) -> Result<Vec<u8>>,
    {
        self.transact_inner(max, replace, &mut |_| Ok(()))
    }

    #[cfg(test)]
    pub(crate) fn transact_hook<F>(
        &self,
        max: usize,
        replace: F,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<()>
    where
        F: FnOnce(Option<Vec<u8>>) -> Result<Vec<u8>>,
    {
        self.transact_inner(max, replace, hook)
    }

    pub fn lock_info(&self) -> Result<Option<LockInfo>> {
        self.check_path()?;
        let lock = self.lock_path();
        let Some((metadata, bytes)) = self.read_leaf(&lock, 4096, &mut |_| Ok(()))? else {
            return Ok(None);
        };
        let token = String::from_utf8(bytes).map_err(|_| Refusal("floor:lock-identity"))?;
        Ok(Some(LockInfo {
            dev: metadata.dev(),
            ino: metadata.ino(),
            token,
        }))
    }

    pub fn reconcile_lock(&self, expected: &LockInfo) -> Result<()> {
        self.require_operator()?;
        self.check_path()?;
        self.remove_lock(expected)
    }

    fn require_operator(&self) -> Result<()> {
        // SAFETY: geteuid takes no arguments and only reads the process credential.
        let uid = unsafe { libc::geteuid() };
        if uid != self.root_uid {
            return Err(Refusal("floor:root-required"));
        }
        Ok(())
    }

    fn lock_path(&self) -> PathBuf {
        let mut path = self.path.as_os_str().to_owned();
        path.push(".lock");
        PathBuf::from(path)
    }

    fn parent(&self) -> Result<&Path> {
        self.path.parent().ok_or(Refusal("floor:path"))
    }

    fn check_path(&self) -> Result<()> {
        let path = &self.path;
        let mut canonical = PathBuf::new();
        if !path.is_absolute() || path.to_str().is_none() {
            return Err(Refusal("floor:path"));
        }
        for component in path.components() {
            match component {
                Component::RootDir | Component::Normal(_) => canonical.push(component.as_os_str()),
                _ => return Err(Refusal("floor:path")),
            }
        }
        if canonical.as_os_str() != path.as_os_str()
            || path.file_name().is_none()
            || !path.starts_with(&self.anchor)
        {
            return Err(Refusal("floor:path"));
        }
        let mut ancestors = Vec::new();
        let mut parent = self.parent()?;
        loop {
            ancestors.push(parent);
            if parent == self.anchor {
                break;
            }
            parent = parent.parent().ok_or(Refusal("floor:path"))?;
        }
        for ancestor in ancestors.into_iter().rev() {
            let before = fs::symlink_metadata(ancestor).map_err(io_refusal)?;
            self.protected_node(&before, true)?;
            let directory = open_directory(ancestor)?;
            let opened = directory.metadata().map_err(io_refusal)?;
            self.open_identity(&before, &opened, true)?;
            let after = fs::symlink_metadata(ancestor).map_err(io_refusal)?;
            self.open_identity(&opened, &after, true)?;
        }
        Ok(())
    }

    fn protected_node(&self, metadata: &Metadata, directory: bool) -> Result<()> {
        if metadata.file_type().is_symlink() {
            return Err(Refusal("floor:symlink"));
        }
        if metadata.uid() != self.root_uid || metadata.mode() & 0o022 != 0 {
            return Err(Refusal("floor:protection"));
        }
        if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
            return Err(Refusal("floor:type"));
        }
        if !directory && metadata.nlink() != 1 {
            return Err(Refusal("floor:hardlink"));
        }
        Ok(())
    }

    fn open_identity(&self, before: &Metadata, opened: &Metadata, directory: bool) -> Result<()> {
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(Refusal("floor:open-identity"));
        }
        self.protected_node(opened, directory)
            .map_err(|_| Refusal("floor:open-identity"))
    }

    fn read_inner(
        &self,
        max: usize,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<Option<Vec<u8>>> {
        self.check_path()?;
        let bytes = self
            .read_leaf(&self.path, max, hook)?
            .map(|(_, bytes)| bytes);
        self.check_path()?;
        Ok(bytes)
    }

    fn read_leaf(
        &self,
        path: &Path,
        max: usize,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<Option<(Metadata, Vec<u8>)>> {
        let before = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_refusal(error)),
        };
        self.protected_node(&before, false)?;
        if before.len() > max as u64 {
            return Err(Refusal("floor:size"));
        }
        hook(Stage::BeforeOpen)?;
        let mut opened_file = open_read(path)?;
        let opened = opened_file.metadata().map_err(io_refusal)?;
        self.open_identity(&before, &opened, false)?;
        if opened.len() > max as u64 {
            return Err(Refusal("floor:size"));
        }
        hook(Stage::AfterOpen)?;
        let mut bytes = Vec::new();
        (&mut opened_file)
            .take(max.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(io_refusal)?;
        let after_opened = opened_file.metadata().map_err(io_refusal)?;
        self.open_identity(&opened, &after_opened, false)?;
        let after_path = fs::symlink_metadata(path).map_err(io_refusal)?;
        self.open_identity(&opened, &after_path, false)?;
        if bytes.len() > max
            || bytes.len() as u64 != opened.len()
            || after_opened.len() != opened.len()
            || after_path.len() != opened.len()
        {
            return Err(Refusal("floor:size"));
        }
        Ok(Some((opened, bytes)))
    }

    fn transact_inner<F>(
        &self,
        max: usize,
        replace: F,
        hook: &mut impl FnMut(Stage) -> Result<()>,
    ) -> Result<()>
    where
        F: FnOnce(Option<Vec<u8>>) -> Result<Vec<u8>>,
    {
        self.require_operator()?;
        self.check_path()?;
        let lock = self.lock_path();
        let mut lock_file = create_exclusive(&lock, 0o600)?;
        let metadata = lock_file.metadata().map_err(io_refusal)?;
        self.protected_node(&metadata, false)?;
        let token = fresh_token()?;
        lock_file.write_all(token.as_bytes()).map_err(io_refusal)?;
        sync_file(&lock_file, SyncPoint::Lock)?;
        let identity = LockInfo {
            dev: metadata.dev(),
            ino: metadata.ino(),
            token,
        };
        hook(Stage::Locked)?;
        // Authority is recomputed from the current bytes while this lock is held.
        let replacement = match self.read_inner(max, hook).and_then(replace) {
            Ok(bytes) => bytes,
            Err(error) => {
                drop(lock_file);
                self.remove_lock(&identity)?;
                return Err(error);
            }
        };
        if replacement.len() > max {
            drop(lock_file);
            self.remove_lock(&identity)?;
            return Err(Refusal("floor:size"));
        }
        let mut crashed = false;
        let outcome = (|| {
            let temporary = self.parent()?.join(format!(
                ".floor.tmp-{}-{}",
                std::process::id(),
                fresh_token()?.trim().replace(':', "-")
            ));
            let mut temp_file = create_exclusive(&temporary, 0o644)?;
            // The service user must read the floor. Set the mode on the handle: a caller's umask (the
            // installer runs under 077) would otherwise leave a root-only 0600 floor that reads as floor:io.
            temp_file
                .set_permissions(fs::Permissions::from_mode(0o644))
                .map_err(io_refusal)?;
            let temp_identity = temp_file.metadata().map_err(io_refusal)?;
            self.protected_node(&temp_identity, false)?;
            temp_file.write_all(&replacement).map_err(io_refusal)?;
            sync_file(&temp_file, SyncPoint::Temp)?;
            if let Err(error) = hook(Stage::TempSynced) {
                crashed = true;
                return Err(error);
            }
            self.check_path()?;
            let current_temp = fs::symlink_metadata(&temporary).map_err(io_refusal)?;
            self.open_identity(&temp_identity, &current_temp, false)?;
            fs::rename(&temporary, &self.path).map_err(io_refusal)?;
            let renamed = fs::symlink_metadata(&self.path).map_err(io_refusal)?;
            self.open_identity(&temp_identity, &renamed, false)?;
            self.sync_parent()?;
            hook(Stage::DirectorySynced)
        })();
        drop(lock_file);
        if !crashed {
            self.remove_lock(&identity)?;
        }
        outcome
    }

    fn remove_lock(&self, expected: &LockInfo) -> Result<()> {
        let current = self.lock_info()?.ok_or(Refusal("floor:lock-identity"))?;
        if current != *expected {
            return Err(Refusal("floor:lock-identity"));
        }
        fs::remove_file(self.lock_path()).map_err(io_refusal)?;
        self.sync_parent()
    }

    fn sync_parent(&self) -> Result<()> {
        let path = self.parent()?;
        let before = fs::symlink_metadata(path).map_err(io_refusal)?;
        self.protected_node(&before, true)?;
        let directory = open_directory(path)?;
        let opened = directory.metadata().map_err(io_refusal)?;
        self.open_identity(&before, &opened, true)?;
        sync_file(&directory, SyncPoint::Directory)?;
        let after = fs::symlink_metadata(path).map_err(io_refusal)?;
        self.open_identity(&opened, &after, true)
    }
}

fn open_read(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_refusal)
}

fn create_exclusive(path: &Path, mode: u32) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Refusal("floor:locked")
            } else {
                io_refusal(error)
            }
        })
}

fn open_directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_refusal)
}

fn fresh_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(io_refusal)?;
    let mut token = format!("{}:", std::process::id());
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut token, "{byte:02x}").map_err(|_| Refusal("floor:io"))?;
    }
    token.push('\n');
    Ok(token)
}

fn sync_file(file: &File, point: SyncPoint) -> Result<()> {
    #[cfg(test)]
    if SYNC_FAILURE.with(|failure| {
        if failure.get() == Some(point) {
            failure.set(None);
            true
        } else {
            false
        }
    }) {
        return Err(Refusal("floor:io"));
    }
    #[cfg(not(test))]
    let _ = point;
    file.sync_all().map_err(io_refusal)
}

fn io_refusal(_: std::io::Error) -> Refusal {
    Refusal("floor:io")
}

#[cfg(test)]
#[path = "protected_tests.rs"]
mod tests;
