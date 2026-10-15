// SPDX-License-Identifier: AGPL-3.0-or-later
//! Descriptor-relative host reads reject symlinks and writable configuration.

use super::{checked_path, refused};
use canon::Result;
use rustix::fs::{openat, Mode, OFlags, CWD};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

pub(super) fn open_host_directory(path: &Path) -> Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory: File = openat(CWD, std::path::MAIN_SEPARATOR_STR, flags, Mode::empty())
        .map_err(|_| refused("config-unreadable"))?
        .into();
    if !path.is_absolute() {
        return Err(refused("config-path"));
    }
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, flags, Mode::empty())
                    .map_err(|_| refused("config-unreadable"))?
                    .into();
                let metadata = directory
                    .metadata()
                    .map_err(|_| refused("config-unreadable"))?;
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return Err(refused("config-permissions"));
                }
            }
            _ => return Err(refused("config-path")),
        }
    }
    Ok(directory)
}

pub(super) fn read_host_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    checked_path(path)?;
    let parent = path.parent().ok_or(refused("config-path"))?;
    let name = path.file_name().ok_or(refused("config-path"))?;
    let directory = open_host_directory(parent)?;
    let file: File = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| refused("config-unreadable"))?
    .into();
    let metadata = file.metadata().map_err(|_| refused("config-unreadable"))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() > limit as u64
    {
        return Err(refused("config-permissions"));
    }
    let mut raw = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| refused("config-unreadable"))?;
    if raw.len() > limit || raw.len() as u64 != metadata.len() {
        return Err(refused("config-size"));
    }
    Ok(raw)
}
