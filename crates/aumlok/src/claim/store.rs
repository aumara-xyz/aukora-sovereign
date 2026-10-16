// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable single-use bootstrap claims; admission does not establish an owner.

use super::HostClaimCommitment;
use canon::{
    codes::{AUMLOK_CLAIM_SPENT, AUMLOK_CLAIM_UNKNOWN},
    digest::Digest32,
    ids::NodeId,
    Result,
};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, CWD};
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
use subtle::ConstantTimeEq;

const MAX_TIME: u64 = canon::json::MAX_SAFE_INTEGER as u64;
const MAX_LIFETIME_MS: u64 = 86_400_000;
const SCHEMA: &[(&str, &str, &str)] = &[
    (
        "table",
        "aumlok_claim_v1",
        "CREATE TABLE aumlok_claim_v1(id INTEGER PRIMARY KEY CHECK(id=1),node BLOB NOT NULL CHECK(length(node)=16),commitment BLOB NOT NULL CHECK(length(commitment)=32),spent INTEGER NOT NULL CHECK(spent IN (0,1)))",
    ),
    (
        "trigger",
        "aumlok_claim_retain_v1",
        "CREATE TRIGGER aumlok_claim_retain_v1 BEFORE DELETE ON aumlok_claim_v1 BEGIN SELECT RAISE(ABORT,'aumlok:claim-spent'); END",
    ),
    (
        "trigger",
        "aumlok_claim_singleton_v1",
        "CREATE TRIGGER aumlok_claim_singleton_v1 BEFORE INSERT ON aumlok_claim_v1 WHEN EXISTS(SELECT 1 FROM aumlok_claim_v1) BEGIN SELECT RAISE(ABORT,'aumlok:claim-spent'); END",
    ),
    (
        "trigger",
        "aumlok_claim_forward_v1",
        "CREATE TRIGGER aumlok_claim_forward_v1 BEFORE UPDATE ON aumlok_claim_v1 WHEN NEW.id IS NOT OLD.id OR NEW.node IS NOT OLD.node OR NEW.commitment IS NOT OLD.commitment OR OLD.spent!=0 OR NEW.spent!=1 BEGIN SELECT RAISE(ABORT,'aumlok:claim-spent'); END",
    ),
];

/// Produced only after the host claim's spending transaction commits.
pub struct ClaimAdmission {
    node: NodeId,
    session_digest: Digest32,
    origin: String,
    expires_at_ms: u64,
    directory_device: u64,
    directory_inode: u64,
}

impl ClaimAdmission {
    pub fn matches_directory(&self, directory: &File) -> Result<bool> {
        let metadata = directory.metadata().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        Ok(metadata.is_dir()
            && metadata.dev() == self.directory_device
            && metadata.ino() == self.directory_inode)
    }

    pub fn into_parts(self) -> (NodeId, Digest32, String, u64) {
        (
            self.node,
            self.session_digest,
            self.origin,
            self.expires_at_ms,
        )
    }
}

pub trait ClaimStore {
    /// Commit the one-use claim before frontdoor may insert a bootstrap session.
    #[allow(clippy::too_many_arguments)]
    fn claim(
        &mut self,
        commitment: &HostClaimCommitment,
        token: &[u8],
        node: NodeId,
        session_digest: Digest32,
        origin: &str,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<ClaimAdmission>;
}

pub struct SqliteClaimStore {
    connection: Connection,
    node: NodeId,
    commitment: Digest32,
    directory: File,
    file_identity: (u64, u64),
    path: PathBuf,
}

impl SqliteClaimStore {
    /// A missing database may be created only for an unclaimed session store.
    pub fn open(
        path: &Path,
        directory: &File,
        node: NodeId,
        commitment: &HostClaimCommitment,
        bootstrap_allowed: bool,
    ) -> Result<Self> {
        validate_directory(path, directory)?;
        let name = path.file_name().ok_or(AUMLOK_CLAIM_UNKNOWN)?;
        if name != std::ffi::OsStr::new("claim-v1.sqlite3") {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let expected = directory.metadata().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        validate_sidecars(path, directory, expected.uid())?;
        let (metadata, fresh) = match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => (metadata, false),
            Err(rustix::io::Errno::NOENT) if bootstrap_allowed => {
                let file = File::from(
                    openat(
                        directory,
                        name,
                        OFlags::RDWR
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC
                            | OFlags::NONBLOCK
                            | OFlags::CREATE
                            | OFlags::EXCL,
                        Mode::RUSR | Mode::WUSR,
                    )
                    .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?,
                );
                let metadata = fstat(&file).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
                file.sync_all().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
                drop(file);
                directory.sync_all().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
                (metadata, true)
            }
            Err(rustix::io::Errno::NOENT) => return Err(AUMLOK_CLAIM_SPENT),
            Err(_) => return Err(AUMLOK_CLAIM_UNKNOWN),
        };
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_nlink != 1
            || metadata.st_uid != expected.uid()
            || (!fresh && metadata.st_size == 0)
        {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let file_identity = (metadata.st_dev as u64, metadata.st_ino as u64);
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        validate_file(path, directory, file_identity)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        connection
            .execute_batch("PRAGMA trusted_schema=OFF; PRAGMA synchronous=EXTRA;")
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        let journal: String = connection
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        let sync: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        if journal != "delete" || sync != 3 {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        if fresh {
            for (_, _, statement) in SCHEMA {
                transaction
                    .execute_batch(statement)
                    .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
            }
            transaction
                .execute(
                    "INSERT INTO aumlok_claim_v1(id,node,commitment,spent) VALUES(1,?1,?2,0)",
                    params![
                        node.as_bytes().as_slice(),
                        commitment.0.as_bytes().as_slice()
                    ],
                )
                .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        }
        validate_schema(&transaction)?;
        if !retained_spent(&transaction, node, commitment.0)? && !bootstrap_allowed {
            return Err(AUMLOK_CLAIM_SPENT);
        }
        transaction.commit().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        directory.sync_all().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        validate_file(path, directory, file_identity)?;
        Ok(Self {
            connection,
            node,
            commitment: commitment.0,
            directory: directory.try_clone().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?,
            file_identity,
            path: path.to_owned(),
        })
    }
}

impl ClaimStore for SqliteClaimStore {
    fn claim(
        &mut self,
        commitment: &HostClaimCommitment,
        token: &[u8],
        node: NodeId,
        session_digest: Digest32,
        origin: &str,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<ClaimAdmission> {
        validate_file(&self.path, &self.directory, self.file_identity)?;
        if node != self.node
            || !bool::from(commitment.0.as_bytes().ct_eq(self.commitment.as_bytes()))
            || now_ms > MAX_TIME
            || expires_at_ms > MAX_TIME
            || !expires_at_ms
                .checked_sub(now_ms)
                .is_some_and(|lifetime| (1..=MAX_LIFETIME_MS).contains(&lifetime))
            || origin.is_empty()
            || origin.len() > 2048
            || origin.chars().any(char::is_control)
        {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        validate_schema(&transaction)?;
        if retained_spent(&transaction, node, self.commitment)? {
            return Err(AUMLOK_CLAIM_SPENT);
        }
        commitment.verify(token)?;
        let changed = transaction
            .execute(
                "UPDATE aumlok_claim_v1 SET spent=1 WHERE id=1 AND spent=0",
                [],
            )
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        if changed != 1 {
            return Err(AUMLOK_CLAIM_SPENT);
        }
        transaction.commit().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        self.directory
            .sync_all()
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        validate_file(&self.path, &self.directory, self.file_identity)?;
        let directory = self
            .directory
            .metadata()
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        Ok(ClaimAdmission {
            node,
            session_digest,
            origin: origin.to_owned(),
            expires_at_ms,
            directory_device: directory.dev(),
            directory_inode: directory.ino(),
        })
    }
}

fn validate_directory(path: &Path, directory: &File) -> Result<()> {
    let parent = path.parent().ok_or(AUMLOK_CLAIM_UNKNOWN)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut opened: Option<File> = None;
    for component in parent.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let descriptor = match &opened {
            Some(previous) => openat(previous, component.as_os_str(), flags, Mode::empty()),
            None => openat(CWD, component.as_os_str(), flags, Mode::empty()),
        }
        .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        opened = Some(File::from(descriptor));
    }
    let actual = opened
        .ok_or(AUMLOK_CLAIM_UNKNOWN)?
        .metadata()
        .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
    let expected = directory.metadata().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
    if !expected.is_dir()
        || expected.mode() & 0o077 != 0
        || actual.dev() != expected.dev()
        || actual.ino() != expected.ino()
    {
        return Err(AUMLOK_CLAIM_UNKNOWN);
    }
    Ok(())
}

fn validate_file(path: &Path, directory: &File, expected: (u64, u64)) -> Result<()> {
    validate_directory(path, directory)?;
    let actual = std::fs::symlink_metadata(path).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
    let parent = directory.metadata().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
    if !actual.is_file()
        || actual.mode() & 0o7777 != 0o600
        || actual.nlink() != 1
        || actual.uid() != parent.uid()
        || actual.dev() != expected.0
        || actual.ino() != expected.1
    {
        return Err(AUMLOK_CLAIM_UNKNOWN);
    }
    validate_sidecars(path, directory, parent.uid())
}

fn validate_sidecars(path: &Path, directory: &File, owner: u32) -> Result<()> {
    let name = path.file_name().ok_or(AUMLOK_CLAIM_UNKNOWN)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = name.to_os_string();
        sidecar.push(suffix);
        let metadata = match statat(directory, sidecar.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(_) => return Err(AUMLOK_CLAIM_UNKNOWN),
        };
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != owner
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_nlink != 1
        {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
    }
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<()> {
    let mut statement = connection
        .prepare("SELECT type,name,sql FROM sqlite_schema")
        .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
    let mut rows = statement.query([]).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(|_| AUMLOK_CLAIM_UNKNOWN)? {
        let kind: String = row.get(0).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        let name: String = row.get(1).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        let sql: String = row.get(2).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        if !SCHEMA
            .iter()
            .any(|expected| expected.0 == kind && expected.1 == name && expected.2 == sql)
        {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        count += 1;
    }
    if count != SCHEMA.len() {
        return Err(AUMLOK_CLAIM_UNKNOWN);
    }
    Ok(())
}

fn retained_spent(connection: &Connection, node: NodeId, commitment: Digest32) -> Result<bool> {
    let count: i64 = connection
        .query_row("SELECT count(*) FROM aumlok_claim_v1", [], |row| row.get(0))
        .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
    if count != 1 {
        return Err(AUMLOK_CLAIM_UNKNOWN);
    }
    let (stored_node, stored_commitment, spent): (Vec<u8>, Vec<u8>, i64) = connection
        .query_row(
            "SELECT node,commitment,spent FROM aumlok_claim_v1 WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
    if stored_node != node.as_bytes()
        || !bool::from(stored_commitment.as_slice().ct_eq(commitment.as_bytes()))
        || !matches!(spent, 0 | 1)
    {
        return Err(AUMLOK_CLAIM_UNKNOWN);
    }
    Ok(spent == 1)
}
