// SPDX-License-Identifier: AGPL-3.0-or-later
//! Descriptor-relative protected storage with a retained, non-stealable lock.
//! Unpublished scratch bytes may be discarded only while that lock is held.

use crate::{refuse, Result};
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use std::fs::{File, Metadata, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const LOCK: &str = "floor.lock";
const TEMPORARY: &str = "floor.pending-write";
const STORE_MAX_BYTES: usize = 2 * crate::state::STATE_MAX_BYTES + 65_536;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

pub(crate) struct Store {
    path: PathBuf,
    directory: File,
    directory_identity: Identity,
    lock: File,
    lock_identity: Identity,
}

impl Store {
    pub(crate) fn open(directory: &Path) -> Result<Self> {
        let handle = directory_handle(directory)?;
        let directory_identity = Identity::of(&metadata(&handle)?);
        let lock = leaf(&handle, LOCK, true)?.ok_or_else(|| refuse("lock-absent"))?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| refuse("locked"))?;
        let lock_identity = Identity::of(&metadata(&lock)?);
        let store = Self {
            path: directory.to_path_buf(),
            directory: handle,
            directory_identity,
            lock,
            lock_identity,
        };
        store.revalidate()?;
        store.discard_unpublished()?;
        Ok(store)
    }

    pub(crate) fn read(&self, name: &str, max: usize) -> Result<Option<Vec<u8>>> {
        valid_name(name)?;
        if max > STORE_MAX_BYTES {
            return Err(refuse("size"));
        }
        self.revalidate()?;
        let Some(mut file) = leaf(&self.directory, name, false)? else {
            return Ok(None);
        };
        let before = metadata(&file)?;
        if before.len() > max as u64 {
            return Err(refuse("size"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refuse("io"))?;
        let after = metadata(&file)?;
        if bytes.len() > max || !same_read(&before, &after) {
            return Err(refuse("read-conflict"));
        }
        self.revalidate()?;
        let current = leaf(&self.directory, name, false)?.ok_or_else(|| refuse("read-conflict"))?;
        if Identity::of(&metadata(&current)?) != Identity::of(&before) {
            return Err(refuse("read-conflict"));
        }
        Ok(Some(bytes))
    }

    pub(crate) fn write_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.write(name, bytes, true)
    }

    pub(crate) fn replace(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.write(name, bytes, false)
    }

    pub(super) fn discard_stage(&self, expected: &[u8]) -> Result<()> {
        if let Some(bytes) = self.read(super::PENDING_FILE, super::STAGE_MAX)? {
            if bytes != expected {
                return Err(refuse("stage-conflict"));
            }
            self.remove(super::PENDING_FILE)?;
        }
        self.discard_unpublished()
    }

    pub(crate) fn remove(&self, name: &str) -> Result<()> {
        writable_name(name)?;
        self.revalidate()?;
        let file = leaf(&self.directory, name, false)?.ok_or_else(|| refuse("absent"))?;
        let identity = Identity::of(&metadata(&file)?);
        self.revalidate()?;
        let current =
            leaf(&self.directory, name, false)?.ok_or_else(|| refuse("write-conflict"))?;
        if Identity::of(&metadata(&current)?) != identity {
            return Err(refuse("write-conflict"));
        }
        fs::unlinkat(&self.directory, name, AtFlags::empty()).map_err(|_| refuse("io"))?;
        self.sync_directory()
    }

    fn write(&self, name: &str, bytes: &[u8], new: bool) -> Result<()> {
        writable_name(name)?;
        if bytes.len() > STORE_MAX_BYTES {
            return Err(refuse("size"));
        }
        self.revalidate()?;
        let prior = leaf(&self.directory, name, false)?;
        if new && prior.is_some() {
            return Err(refuse("already-exists"));
        }
        if !new && prior.is_none() {
            return Err(refuse("absent"));
        }
        let prior_identity = prior
            .as_ref()
            .map(metadata)
            .transpose()?
            .as_ref()
            .map(Identity::of);
        let temporary = fs::openat(
            &self.directory,
            TEMPORARY,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                refuse("interrupted-write")
            } else {
                refuse("io")
            }
        })?;
        let mut temporary = File::from(temporary);
        temporary
            .set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| refuse("io"))?;
        protected_file(&metadata(&temporary)?)?;
        let temporary_identity = Identity::of(&metadata(&temporary)?);
        temporary.write_all(bytes).map_err(|_| refuse("io"))?;
        temporary.sync_all().map_err(|_| refuse("io"))?;
        self.revalidate()?;
        let named =
            leaf(&self.directory, TEMPORARY, false)?.ok_or_else(|| refuse("write-conflict"))?;
        if Identity::of(&metadata(&named)?) != temporary_identity {
            return Err(refuse("write-conflict"));
        }
        let current = leaf(&self.directory, name, false)?;
        let current_identity = current
            .as_ref()
            .map(metadata)
            .transpose()?
            .as_ref()
            .map(Identity::of);
        if current_identity != prior_identity {
            return Err(refuse("write-conflict"));
        }
        if new {
            fs::renameat_with(
                &self.directory,
                TEMPORARY,
                &self.directory,
                name,
                RenameFlags::NOREPLACE,
            )
            .map_err(|_| refuse("write-conflict"))?;
        } else {
            fs::renameat(&self.directory, TEMPORARY, &self.directory, name)
                .map_err(|_| refuse("io"))?;
        }
        self.sync_directory()?;
        let published =
            leaf(&self.directory, name, false)?.ok_or_else(|| refuse("write-conflict"))?;
        if Identity::of(&metadata(&published)?) != temporary_identity {
            return Err(refuse("write-conflict"));
        }
        self.revalidate()
    }

    fn revalidate(&self) -> Result<()> {
        let current = directory_handle(&self.path)?;
        if Identity::of(&metadata(&current)?) != self.directory_identity
            || Identity::of(&metadata(&self.directory)?) != self.directory_identity
        {
            return Err(refuse("directory-identity"));
        }
        let named_lock = leaf(&current, LOCK, true)?.ok_or_else(|| refuse("lock-absent"))?;
        let held = metadata(&self.lock)?;
        protected_file(&held)?;
        if Identity::of(&metadata(&named_lock)?) != self.lock_identity
            || Identity::of(&held) != self.lock_identity
        {
            return Err(refuse("lock-identity"));
        }
        Ok(())
    }

    /// Only the fixed unpublished scratch name can be removed by open recovery.
    /// The persistent lock, installed state and staged release use distinct names.
    fn discard_unpublished(&self) -> Result<()> {
        let Some(temporary) = leaf(&self.directory, TEMPORARY, false)? else {
            return Ok(());
        };
        let observed = metadata(&temporary)?;
        if observed.len() > STORE_MAX_BYTES as u64 {
            return Err(refuse("size"));
        }
        let identity = Identity::of(&observed);
        self.revalidate()?;
        let current =
            leaf(&self.directory, TEMPORARY, false)?.ok_or_else(|| refuse("write-conflict"))?;
        if Identity::of(&metadata(&current)?) != identity {
            return Err(refuse("write-conflict"));
        }
        fs::unlinkat(&self.directory, TEMPORARY, AtFlags::empty()).map_err(|_| refuse("io"))?;
        self.sync_directory()?;
        self.revalidate()
    }

    fn sync_directory(&self) -> Result<()> {
        self.directory.sync_all().map_err(|_| refuse("io"))
    }
}

fn directory_handle(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(refuse("path"));
    }
    let mut components = path.components();
    let root = components.next().ok_or_else(|| refuse("path"))?;
    if root != Component::RootDir {
        return Err(refuse("path"));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(fs::open(root.as_os_str(), flags, Mode::empty()).map_err(|_| refuse("path"))?);
    protected_directory(&metadata(&directory)?, false)?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(refuse("path"));
        };
        directory = File::from(
            fs::openat(&directory, name, flags, Mode::empty()).map_err(|_| refuse("path"))?,
        );
        protected_directory(&metadata(&directory)?, false)?;
    }
    protected_directory(&metadata(&directory)?, true)?;
    Ok(directory)
}

fn leaf(directory: &File, name: &str, writable: bool) -> Result<Option<File>> {
    valid_name(name)?;
    let access = if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    };
    let descriptor = match fs::openat(
        directory,
        name,
        access | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(refuse("protected-file")),
    };
    let file = File::from(descriptor);
    protected_file(&metadata(&file)?)?;
    Ok(Some(file))
}

fn valid_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(refuse("path"));
    }
    Ok(())
}

fn writable_name(name: &str) -> Result<()> {
    valid_name(name)?;
    if matches!(name, LOCK | TEMPORARY) {
        return Err(refuse("reserved-path"));
    }
    Ok(())
}

fn metadata(file: &File) -> Result<Metadata> {
    file.metadata().map_err(|_| refuse("io"))
}

fn protected_directory(metadata: &Metadata, private: bool) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_dir()
        || (metadata.uid() != uid && (private || metadata.uid() != 0))
        || metadata.mode() & 0o022 != 0
        || private && metadata.mode() & 0o7777 != 0o700
    {
        return Err(refuse("protection"));
    }
    Ok(())
}

fn protected_file(metadata: &Metadata) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(refuse("protection"));
    }
    Ok(())
}

fn same_read(before: &Metadata, after: &Metadata) -> bool {
    Identity::of(before) == Identity::of(after)
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && protected_file(after).is_ok()
}
