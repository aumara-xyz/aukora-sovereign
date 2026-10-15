// SPDX-License-Identifier: AGPL-3.0-or-later
//! Confinement and compare-and-replace contracts for trusted target adapters.

use crate::{Result, RiskTier};
use canon::{authority::BaseDigest, digest::Digest32, ids::OperationId};
use rustix::fs::{self, FlockOperation, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};

const TEMP_PREFIX: &str = ".aukora-gate-";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetId(String);

impl TargetId {
    pub fn new(name: String) -> Result<Self> {
        if name.is_empty()
            || name.len() > 256
            || name.starts_with('/')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(crate::refuse("target-invalid"));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetClass {
    Content,
    Release,
    OwnerBinding,
    Permission,
    SpendGrant,
    Install,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSpec {
    pub id: TargetId,
    pub class: TargetClass,
    pub risk: RiskTier,
    pub max_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetObservation {
    pub digest: BaseDigest,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct EffectPermit {
    operation: OperationId,
    target: TargetId,
    base: BaseDigest,
    new_digest: Digest32,
    bytes: Vec<u8>,
}

impl EffectPermit {
    pub(crate) fn new(
        operation: OperationId,
        target: TargetId,
        base: BaseDigest,
        new_digest: Digest32,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            operation,
            target,
            base,
            new_digest,
            bytes,
        }
    }

    pub fn operation(&self) -> OperationId {
        self.operation
    }
    pub fn target(&self) -> &TargetId {
        &self.target
    }
    pub fn base(&self) -> BaseDigest {
        self.base
    }
    pub fn new_digest(&self) -> Digest32 {
        self.new_digest
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub trait TargetStore {
    fn observe(&self, target: &TargetId) -> Result<TargetObservation>;

    /// Consumes a permit. Implementations compare the base, replace once and sync
    /// bytes and directory; an error is ambiguous and must not be retried.
    fn replace_once(&mut self, permit: EffectPermit) -> Result<TargetObservation>;
}

#[derive(Debug)]
pub struct ConfinedStore {
    directory: std::fs::File,
    targets: BTreeMap<TargetId, TargetSpec>,
    attempted: BTreeSet<OperationId>,
}

impl ConfinedStore {
    pub fn open(directory: std::fs::File, targets: Vec<TargetSpec>) -> Result<Self> {
        if !directory
            .metadata()
            .map_err(|_| crate::refuse("store-root"))?
            .is_dir()
        {
            return Err(crate::refuse("store-root"));
        }
        let directory = open_directory(&directory, ".")?;
        fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| crate::refuse("writer-locked"))?;
        let mut configured = BTreeMap::new();
        for target in targets {
            if target
                .id
                .as_str()
                .split('/')
                .any(|part| part.starts_with(TEMP_PREFIX) || part.len() > 255)
                || target.max_bytes == usize::MAX
            {
                return Err(crate::refuse("target-invalid"));
            }
            if configured.insert(target.id.clone(), target).is_some() {
                return Err(crate::refuse("duplicate-target"));
            }
        }
        for name in configured.keys() {
            for (index, _) in name.as_str().match_indices('/') {
                if configured
                    .keys()
                    .any(|other| other.as_str() == &name.as_str()[..index])
                {
                    return Err(crate::refuse("duplicate-target"));
                }
            }
        }
        Ok(Self {
            directory,
            targets: configured,
            attempted: BTreeSet::new(),
        })
    }

    pub fn directory(&self) -> &std::fs::File {
        &self.directory
    }

    fn specification(&self, target: &TargetId) -> Result<&TargetSpec> {
        self.targets
            .get(target)
            .ok_or(crate::refuse("target-not-allowed"))
    }

    fn parent(&self, target: &TargetId, create: bool) -> Result<Option<(File, String)>> {
        let mut parts = target.as_str().split('/').peekable();
        let mut directory = self
            .directory
            .try_clone()
            .map_err(|_| crate::refuse("io"))?;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                return Ok(Some((directory, part.to_owned())));
            }
            match fs::openat(&directory, part, directory_flags(), Mode::empty()) {
                Ok(next) => directory = File::from(next),
                Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
                Err(rustix::io::Errno::NOENT) => {
                    match fs::mkdirat(&directory, part, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                        Ok(()) => directory.sync_all().map_err(|_| crate::refuse("io"))?,
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(_) => return Err(crate::refuse("io")),
                    }
                    directory = open_directory(&directory, part)?;
                }
                Err(_) => return Err(crate::refuse("store-root")),
            }
        }
        Err(crate::refuse("target-invalid"))
    }

    fn read_at(directory: &File, name: &str, max_bytes: usize) -> Result<TargetObservation> {
        let descriptor = match fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(absent()),
            Err(_) => return Err(crate::refuse("io")),
        };
        let file = File::from(descriptor);
        let before = file.metadata().map_err(|_| crate::refuse("io"))?;
        if !before.is_file() || before.nlink() != 1 {
            return Err(crate::refuse("store-not-regular"));
        }
        if before.len() > max_bytes as u64 {
            return Err(crate::refuse("target-limit"));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| crate::refuse("io"))?;
        if bytes.len() > max_bytes {
            return Err(crate::refuse("target-limit"));
        }
        let after = file.metadata().map_err(|_| crate::refuse("io"))?;
        if before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(crate::refuse("stale-base"));
        }
        Ok(TargetObservation {
            digest: BaseDigest::Present(hash(&bytes)),
            bytes: Some(bytes),
        })
    }
}

impl TargetStore for ConfinedStore {
    fn observe(&self, target: &TargetId) -> Result<TargetObservation> {
        let specification = self.specification(target)?;
        match self.parent(target, false)? {
            Some((directory, name)) => Self::read_at(&directory, &name, specification.max_bytes),
            None => Ok(absent()),
        }
    }

    fn replace_once(&mut self, permit: EffectPermit) -> Result<TargetObservation> {
        if !self.attempted.insert(permit.operation) {
            return Err(crate::refuse("write-already-claimed"));
        }
        let max_bytes = self.specification(&permit.target)?.max_bytes;
        if permit.bytes.len() > max_bytes {
            return Err(crate::refuse("target-limit"));
        }
        if hash(&permit.bytes) != permit.new_digest {
            return Err(crate::refuse("post-write-hash"));
        }
        if permit.base == BaseDigest::Present(permit.new_digest) {
            return Err(crate::refuse("identical"));
        }
        if self.observe(&permit.target)?.digest != permit.base {
            return Err(crate::refuse("stale-base"));
        }
        let (directory, name) = self
            .parent(&permit.target, true)?
            .ok_or(crate::refuse("store-root"))?;
        let temporary = format!("{TEMP_PREFIX}{}", permit.operation);
        let descriptor = fs::openat(
            &directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                crate::refuse("write-already-claimed")
            } else {
                crate::refuse("io")
            }
        })?;
        let mut file = File::from(descriptor);
        // Retained temporary names fence attempts that fail before replacement.
        directory.sync_all().map_err(|_| crate::refuse("io"))?;
        file.write_all(&permit.bytes)
            .map_err(|_| crate::refuse("io"))?;
        file.sync_all().map_err(|_| crate::refuse("io"))?;
        if Self::read_at(&directory, &name, max_bytes)?.digest != permit.base {
            return Err(crate::refuse("stale-base"));
        }
        let retained = fs::statat(
            &directory,
            temporary.as_str(),
            fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| crate::refuse("io"))?;
        let written = file.metadata().map_err(|_| crate::refuse("io"))?;
        if retained.st_dev as u64 != written.dev()
            || retained.st_ino as u64 != written.ino()
            || written.nlink() != 1
            || written.len() != permit.bytes.len() as u64
        {
            return Err(crate::refuse("store-not-regular"));
        }
        if permit.base == BaseDigest::Absent {
            fs::renameat_with(
                &directory,
                temporary.as_str(),
                &directory,
                name.as_str(),
                fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| crate::refuse("io"))?;
        } else {
            fs::renameat(&directory, temporary.as_str(), &directory, name.as_str())
                .map_err(|_| crate::refuse("io"))?;
        }
        directory.sync_all().map_err(|_| crate::refuse("io"))?;
        let observed = Self::read_at(&directory, &name, max_bytes)?;
        if observed.digest != BaseDigest::Present(permit.new_digest)
            || observed.bytes.as_deref() != Some(permit.bytes.as_slice())
        {
            return Err(crate::refuse("post-write-hash"));
        }
        Ok(observed)
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_directory(parent: &File, name: &str) -> Result<File> {
    fs::openat(parent, name, directory_flags(), Mode::empty())
        .map(File::from)
        .map_err(|_| crate::refuse("store-root"))
}

fn absent() -> TargetObservation {
    TargetObservation {
        digest: BaseDigest::Absent,
        bytes: None,
    }
}

fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}
