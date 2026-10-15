// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private host state and an observation signer, separate from owner authority.

use canon::{
    alg::{AlgorithmId, PublicKey, Signature, Signatures},
    digest::Digest32,
    ids::NodeId,
    Result,
};
use ed25519_dalek::{Signer, SigningKey};
use rustix::fs::{flock, mkdirat, open, openat, Dir, FlockOperation, Mode, OFlags};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};
use zeroize::Zeroizing;

pub struct HostState {
    directory: File,
    _lock: File,
    pub node: NodeId,
    pub signer: std::sync::Arc<NodeSigner>,
}

pub struct NodeSigner(SigningKey);

impl aura::RecordSigner for NodeSigner {
    fn public_keys(&self) -> Result<Vec<PublicKey>> {
        Ok(vec![PublicKey {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: self.0.verifying_key().to_bytes().to_vec(),
        }])
    }

    fn sign_entry_hash(&self, hash: Digest32) -> Result<Signatures> {
        Signatures::new(vec![Signature {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: self.0.sign(hash.as_bytes()).to_bytes().to_vec(),
        }])
    }
}

impl HostState {
    pub fn open(path: &Path, node_name: &str) -> Result<Self> {
        let directory = open_state_directory(path)?;
        private_directory(&directory)?;
        let lock: File = openat(
            &directory,
            "supervisor.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| refuse("state-lock"))?
        .into();
        private_file(&lock, 0)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| refuse("already-running"))?;
        let stored = match read_private(&directory, "node-identity-v1", 512) {
            Ok(bytes) => bytes,
            Err(error) if error == rustix::io::Errno::NOENT => {
                // Partial startup state never silently regenerates the signing identity.
                let mut entries =
                    Dir::read_from(&directory).map_err(|_| refuse("state-directory"))?;
                while let Some(entry) = entries.read() {
                    let entry = entry.map_err(|_| refuse("state-directory"))?;
                    let name = entry
                        .file_name()
                        .to_str()
                        .map_err(|_| refuse("state-directory"))?;
                    if !matches!(name, "." | ".." | "supervisor.lock") {
                        return Err(refuse("identity-missing"));
                    }
                }
                let mut seed = Zeroizing::new([0; 32]);
                let mut id = [0; 16];
                getrandom::fill(&mut seed[..]).map_err(|_| refuse("randomness"))?;
                getrandom::fill(&mut id).map_err(|_| refuse("randomness"))?;
                let node = NodeId::from_bytes(id);
                let metadata =
                    format!("aukora-node-identity-v1\n{node_name}\n{node}\n").into_bytes();
                write_new(&directory, "aura-signing-key", &seed[..])?;
                write_new(&directory, "node-identity-v1", &metadata)?;
                metadata
            }
            Err(_) => return Err(refuse("identity-read")),
        };
        let text = std::str::from_utf8(&stored).map_err(|_| refuse("identity-format"))?;
        let fields: Vec<_> = text.split('\n').collect();
        let ["aukora-node-identity-v1", name, id, ""] = fields.as_slice() else {
            return Err(refuse("identity-format"));
        };
        if *name != node_name {
            return Err(refuse("identity-node"));
        }
        let node = NodeId::from_hex(id)?;
        let seed = Zeroizing::new(
            read_private(&directory, "aura-signing-key", 32).map_err(|_| refuse("signing-key"))?,
        );
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| refuse("signing-key"))?,
        );
        Ok(Self {
            directory,
            _lock: lock,
            node,
            signer: std::sync::Arc::new(NodeSigner(SigningKey::from_bytes(&key))),
        })
    }

    pub fn directory(&self) -> &File {
        &self.directory
    }

    pub fn subdirectory(&self, name: &str) -> Result<File> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(refuse("state-name"));
        }
        match mkdirat(&self.directory, name, Mode::from_raw_mode(0o700)) {
            Ok(()) => self
                .directory
                .sync_all()
                .map_err(|_| refuse("state-sync"))?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(refuse("state-directory")),
        }
        let directory: File = openat(&self.directory, name, directory_flags(), Mode::empty())
            .map_err(|_| refuse("state-directory"))?
            .into();
        private_directory(&directory)?;
        Ok(directory)
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_state_directory(path: &Path) -> Result<File> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(refuse("state-directory"));
    }
    let mut directory: File = open(
        std::path::MAIN_SEPARATOR_STR,
        directory_flags(),
        Mode::empty(),
    )
    .map_err(|_| refuse("state-directory"))?
    .into();
    let uid = rustix::process::geteuid().as_raw();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, name, directory_flags(), Mode::empty())
                    .map_err(|_| refuse("state-directory"))?
                    .into();
                let metadata = directory
                    .metadata()
                    .map_err(|_| refuse("state-directory"))?;
                if !metadata.is_dir()
                    || ![0, uid].contains(&metadata.uid())
                    || metadata.mode() & 0o022 != 0
                {
                    return Err(refuse("state-permissions"));
                }
            }
            _ => return Err(refuse("state-directory")),
        }
    }
    Ok(directory)
}

fn private_directory(file: &File) -> Result<()> {
    let meta = file.metadata().map_err(|_| refuse("state-directory"))?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(refuse("state-permissions"));
    }
    Ok(())
}

fn private_file(file: &File, maximum: u64) -> Result<()> {
    let meta = file.metadata().map_err(|_| refuse("state-file"))?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.nlink() != 1
        || meta.mode() & 0o7777 != 0o600
        || meta.len() > maximum
    {
        return Err(refuse("state-permissions"));
    }
    Ok(())
}

fn read_private(
    directory: &File,
    name: &str,
    maximum: usize,
) -> std::result::Result<Vec<u8>, rustix::io::Errno> {
    let file: File = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?
    .into();
    private_file(&file, maximum as u64).map_err(|_| rustix::io::Errno::INVAL)?;
    let expected = file.metadata().map_err(|_| rustix::io::Errno::IO)?;
    let mut bytes = Vec::new();
    (&file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| rustix::io::Errno::IO)?;
    let after = file.metadata().map_err(|_| rustix::io::Errno::IO)?;
    if bytes.len() > maximum
        || bytes.len() as u64 != expected.len()
        || expected.mtime() != after.mtime()
        || expected.mtime_nsec() != after.mtime_nsec()
        || expected.ctime() != after.ctime()
        || expected.ctime_nsec() != after.ctime_nsec()
        || expected.len() != after.len()
    {
        return Err(rustix::io::Errno::FBIG);
    }
    Ok(bytes)
}

fn write_new(directory: &File, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file: File = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| refuse("state-write"))?
    .into();
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| directory.sync_all())
        .map_err(|_| refuse("state-sync"))
}

fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "supervisor",
        reason,
    }
}
