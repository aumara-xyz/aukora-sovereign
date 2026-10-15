// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writing an export to a private directory: every file is created new, never through a symlink,
//! and synced before the whole folder is renamed into place.

use super::ExportFiles;
use canon::{codes, Result};
use rustix::fs::{self, AtFlags, Dir, FlockOperation, Mode, OFlags, RenameFlags};
use std::{
    fs::{File, Metadata},
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn private_dir(metadata: &Metadata) -> Result<()> {
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(codes::SUPERVISOR_STATE);
    }
    Ok(())
}

fn open_dir(parent: &File, name: &str) -> Result<File> {
    let dir = File::from(
        fs::openat(parent, name, dir_flags(), Mode::empty())
            .map_err(|_| codes::SUPERVISOR_STATE)?,
    );
    private_dir(&dir.metadata().map_err(|_| codes::SUPERVISOR_STATE)?)?;
    Ok(dir)
}

fn make_dir(parent: &File, name: &str) -> Result<File> {
    match fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(codes::SUPERVISOR_STATE),
    }
    open_dir(parent, name)
}

/// The directory that holds exports must already exist and be private to the supervisor's user.
/// Every component is opened without following a symlink, and `..` is refused.
fn open_parent(parent: &Path) -> Result<File> {
    let mut current = File::from(
        fs::openat(fs::CWD, ".", dir_flags(), Mode::empty())
            .map_err(|_| codes::SUPERVISOR_STATE)?,
    );
    let mut named = false;
    for part in parent.components() {
        match part {
            Component::Normal(name) => {
                current = File::from(
                    fs::openat(&current, name, dir_flags(), Mode::empty())
                        .map_err(|_| codes::SUPERVISOR_STATE)?,
                );
                named = true;
            }
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(codes::SUPERVISOR_STATE)
            }
        }
    }
    if !named {
        return Err(codes::SUPERVISOR_STATE);
    }
    private_dir(&current.metadata().map_err(|_| codes::SUPERVISOR_STATE)?)?;
    Ok(current)
}

fn create_file(dir: &File, leaf: &str, bytes: &[u8]) -> Result<()> {
    let fd = fs::openat(
        dir,
        leaf,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| codes::SUPERVISOR_STATE)?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|_| codes::SUPERVISOR_STATE)?;
    file.sync_all().map_err(|_| codes::SUPERVISOR_STATE)
}

/// Write each file under a fresh pending folder, sync every file and folder, then rename the
/// folder to its random 32-hex-digit name and sync the parent. Returns that name. Nothing is
/// ever overwritten. A failure before the rename leaves no folder under the final name. If only the
/// last sync of the parent fails, the finished folder stays, complete and synced file by file, but
/// the error reports that its entry may not survive a crash.
pub(super) fn write(parent: &Path, files: &ExportFiles) -> Result<String> {
    let root = open_parent(parent)?;
    fs::flock(&root, FlockOperation::LockExclusive).map_err(|_| codes::SUPERVISOR_STATE)?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| codes::SUPERVISOR_STATE)?;
    let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let pending = format!("{name}.pending");
    fs::mkdirat(
        &root,
        pending.as_str(),
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|_| codes::SUPERVISOR_STATE)?;
    let folder = open_dir(&root, &pending)?;
    let mut created: Vec<(Option<&str>, &str)> = Vec::new();
    let mut renamed = false;
    let result = (|| {
        for (path, bytes) in files.files() {
            match path.split_once('/') {
                None => {
                    create_file(&folder, path, bytes)?;
                    created.push((None, path));
                }
                Some((sub, leaf)) if !leaf.contains('/') => {
                    let inner = make_dir(&folder, sub)?;
                    create_file(&inner, leaf, bytes)?;
                    inner.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?;
                    created.push((Some(sub), leaf));
                }
                Some(_) => return Err(codes::SUPERVISOR_STATE),
            }
        }
        folder.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?;
        fs::renameat_with(
            &root,
            pending.as_str(),
            &root,
            name.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| codes::SUPERVISOR_STATE)?;
        renamed = true;
        root.sync_all().map_err(|_| codes::SUPERVISOR_STATE)
    })();
    if result.is_err() && !renamed {
        // Best effort: remove only what this call created, files first, then folders.
        for (sub, leaf) in &created {
            if let Some(sub) = sub {
                if let Ok(inner) = open_dir(&folder, sub) {
                    let _ = fs::unlinkat(&inner, *leaf, AtFlags::empty());
                }
            } else {
                let _ = fs::unlinkat(&folder, *leaf, AtFlags::empty());
            }
        }
        for (sub, _) in &created {
            if let Some(sub) = sub {
                let _ = fs::unlinkat(&folder, *sub, AtFlags::REMOVEDIR);
            }
        }
        let _ = fs::unlinkat(&root, pending.as_str(), AtFlags::REMOVEDIR);
    }
    result.map(|()| name)
}

fn names(dir: &File) -> Result<Vec<String>> {
    let mut reader = Dir::read_from(dir).map_err(|_| codes::SUPERVISOR_STATE)?;
    let mut names = Vec::new();
    while let Some(entry) = reader.read() {
        let entry = entry.map_err(|_| codes::SUPERVISOR_STATE)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        if !matches!(name, "." | "..") {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// Remove only `<32 hex digits>.pending` folders, two levels deep, that an interrupted `write`
/// left behind. A symlink or any other entry inside is unlinked itself, never followed.
/// Returns how many folders were removed.
pub(super) fn discard_unfinished(parent: &Path) -> Result<u32> {
    let root = open_parent(parent)?;
    fs::flock(&root, FlockOperation::LockExclusive).map_err(|_| codes::SUPERVISOR_STATE)?;
    let mut removed = 0;
    for name in names(&root)? {
        let Some(stem) = name.strip_suffix(".pending") else {
            continue;
        };
        if stem.len() != 32
            || !stem
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            continue;
        }
        let folder = open_dir(&root, &name)?;
        for inner in names(&folder)? {
            match open_dir(&folder, &inner) {
                Ok(sub) => {
                    for leaf in names(&sub)? {
                        fs::unlinkat(&sub, leaf.as_str(), AtFlags::empty())
                            .map_err(|_| codes::SUPERVISOR_STATE)?;
                    }
                    fs::unlinkat(&folder, inner.as_str(), AtFlags::REMOVEDIR)
                        .map_err(|_| codes::SUPERVISOR_STATE)?;
                }
                Err(_) => fs::unlinkat(&folder, inner.as_str(), AtFlags::empty())
                    .map_err(|_| codes::SUPERVISOR_STATE)?,
            }
        }
        fs::unlinkat(&root, name.as_str(), AtFlags::REMOVEDIR)
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        removed += 1;
    }
    root.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?;
    Ok(removed)
}
