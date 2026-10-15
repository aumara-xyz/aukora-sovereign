// SPDX-License-Identifier: AGPL-3.0-or-later
//! One locked directory contains principal-scoped append logs and durable cursors.

use super::{codec, PrincipalScope, SessionLimits, SessionStoreConfig, TailRecovery};
use canon::{
    alg::AlgorithmId,
    codes,
    digest::Digest32,
    fd3::Reply,
    ids::SessionId,
    json::MAX_SAFE_INTEGER,
    provenance::{Provenance, Source},
    session::*,
    Result,
};
use rustix::fs::{self, AtFlags, Dir, FlockOperation, Mode, OFlags};
use std::{
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};

const RESERVE: u64 = 1024;
const MAX: u64 = MAX_SAFE_INTEGER as u64;

pub(super) struct Disk {
    root: File,
    limits: SessionLimits,
}

struct Loaded {
    file: File,
    metadata: Metadata,
    summary: SessionSummary,
    entries: Vec<SessionEntry>,
    bytes: Vec<u8>,
    ends: Vec<usize>,
    discarded: u64,
}

impl Disk {
    pub(super) fn open(config: &SessionStoreConfig) -> Result<Self> {
        let limits = config.limits;
        if limits.max_sessions_per_principal == 0
            || limits.max_entries_per_session == 0
            || limits.max_entries_per_session > MAX
            || limits.max_bytes_per_principal < RESERVE
            || limits.max_bytes_per_principal >= usize::MAX as u64
        {
            return Err(codes::SUPERVISOR_STATE);
        }
        let root = root(&config.root)?;
        fs::flock(&root, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        let disk = Self { root, limits };
        for name in names(&disk.root)? {
            Digest32::from_hex(&name).map_err(|_| codes::SUPERVISOR_STATE)?;
            let dir = directory(&disk.root, &name, false)?;
            clean_pending(&dir)?;
            disk.recover_creating(&dir)?;
            for id in session_ids(&dir)? {
                disk.load(&dir, id, limits)?;
            }
            disk.usage(&dir, limits)?;
        }
        Ok(disk)
    }

    fn principal(&self, scope: PrincipalScope, create: bool) -> Result<File> {
        let dir =
            directory(&self.root, &scope.subject.digest().to_string(), create).map_err(|e| {
                if e == codes::SESSION_NOT_FOUND {
                    codes::SESSION_NOT_FOUND
                } else {
                    codes::SUPERVISOR_STATE
                }
            })?;
        clean_pending(&dir)?;
        self.recover_creating(&dir)?;
        Ok(dir)
    }

    pub(super) fn create(
        &mut self,
        scope: PrincipalScope,
        request: SessionCreate,
        limits: SessionLimits,
    ) -> Result<SessionSummary> {
        let dir = self.principal(scope, true)?;
        let ids = session_ids(&dir)?;
        if ids.len() >= limits.max_sessions_per_principal as usize {
            return Err(codes::SUPERVISOR_STATE);
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| codes::SUPERVISOR_STATE)?;
        let session_id = SessionId::from_bytes(random);
        let at = now()?;
        let summary = SessionSummary {
            v: RECORD_VERSION,
            algorithm: AlgorithmId::Sha256,
            session_id,
            thread_id: request.thread_id,
            title: request.title,
            mode: request.mode,
            archived: false,
            sequence: 0,
            created_at_ms: at,
            updated_at_ms: at,
        };
        let payload = codec::record(Reply::SessionCreated(summary.clone()))?;
        let bytes = framed(&payload)?;
        if self
            .usage(&dir, limits)?
            .checked_add(RESERVE + 2 * bytes.len() as u64)
            .is_none_or(|total| total > limits.max_bytes_per_principal)
        {
            return Err(codes::SUPERVISOR_STATE);
        }
        let name = format!("{session_id}.session");
        if leaf(&dir, &name, false)?.is_some()
            || leaf(&dir, &format!("{session_id}.commit"), false)?.is_some()
            || leaf(&dir, &format!("{session_id}.creating"), false)?.is_some()
        {
            return Err(codes::SUPERVISOR_STATE);
        }
        atomic(
            &dir,
            &format!("{session_id}.creating"),
            &format!("{session_id}.pending"),
            &payload,
        )?;
        self.recover_creating(&dir)?;
        Ok(summary)
    }

    pub(super) fn open_session(
        &mut self,
        scope: PrincipalScope,
        request: SessionOpen,
        limits: SessionLimits,
    ) -> Result<SessionOpened> {
        page_limit(request.limit)?;
        let dir = self.principal(scope, false)?;
        let loaded = self.load(&dir, request.session_id, limits)?;
        if request.after_sequence > loaded.summary.sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        let mut page = SessionOpened {
            summary: loaded.summary,
            entries: Items::new(Vec::new())?,
            next_sequence: None,
        };
        let mut chosen = Vec::new();
        for entry in loaded
            .entries
            .into_iter()
            .skip(request.after_sequence as usize)
        {
            if chosen.len() == request.limit as usize {
                break;
            }
            chosen.push(entry);
            let last = chosen.last().ok_or(codes::SUPERVISOR_STATE)?.sequence;
            page.entries = Items::new(chosen.clone())?;
            page.next_sequence = (last < page.summary.sequence).then_some(last);
            if codec::frame(Reply::SessionOpened(page.clone())).is_err() {
                chosen.pop();
                break;
            }
        }
        if chosen.is_empty() && request.after_sequence < page.summary.sequence {
            return Err(codes::FRAME_TOO_LARGE);
        }
        page.next_sequence = chosen
            .last()
            .and_then(|e| (e.sequence < page.summary.sequence).then_some(e.sequence));
        page.entries = Items::new(chosen)?;
        codec::frame(Reply::SessionOpened(page.clone()))?;
        Ok(page)
    }

    pub(super) fn list(
        &mut self,
        scope: PrincipalScope,
        request: SessionList,
        limits: SessionLimits,
    ) -> Result<SessionPage> {
        page_limit(request.limit)?;
        let dir = match self.principal(scope, false) {
            Ok(dir) => dir,
            Err(e) if e == codes::SESSION_NOT_FOUND => {
                return Ok(SessionPage {
                    items: Items::new(Vec::new())?,
                    next: None,
                })
            }
            Err(e) => return Err(e),
        };
        let mut candidates = Vec::new();
        for id in session_ids(&dir)?.into_iter().rev() {
            if request.before.is_some_and(|before| id >= before) {
                continue;
            }
            let summary = self.load(&dir, id, limits)?.summary;
            if (!request.include_archived && summary.archived)
                || request
                    .thread_id
                    .is_some_and(|thread| summary.thread_id != thread)
            {
                continue;
            }
            candidates.push(summary);
        }
        let total = candidates.len();
        let mut chosen = Vec::new();
        for summary in candidates.into_iter().take(request.limit as usize) {
            chosen.push(summary);
            let next = (chosen.len() < total).then(|| chosen[chosen.len() - 1].session_id);
            let page = SessionPage {
                items: Items::new(chosen.clone())?,
                next,
            };
            if codec::frame(Reply::SessionList(page)).is_err() {
                chosen.pop();
                break;
            }
        }
        if chosen.is_empty() && total > 0 {
            return Err(codes::FRAME_TOO_LARGE);
        }
        let next = (chosen.len() < total).then(|| chosen[chosen.len() - 1].session_id);
        Ok(SessionPage {
            items: Items::new(chosen)?,
            next,
        })
    }

    pub(super) fn append(
        &mut self,
        scope: PrincipalScope,
        origin: Provenance,
        request: SessionAppend,
        limits: SessionLimits,
    ) -> Result<SessionAppended> {
        if request.entry.provenance != origin || origin.source == Source::Stranger {
            return Err(codes::FRAME_PROVENANCE);
        }
        let payload = codec::record(Reply::SessionAppended(SessionAppended {
            entry: request.entry.clone(),
        }))?;
        if request.entry.commitment != codec::entry_commitment(&request.entry)? {
            return Err(codes::SUPERVISOR_STATE);
        }
        if request.expected_sequence >= MAX
            || request.entry.sequence != request.expected_sequence + 1
            || request.entry.session_id != request.session_id
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        let dir = self.principal(scope, false)?;
        let loaded = self.load(&dir, request.session_id, limits)?;
        if loaded.summary.sequence != request.expected_sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        let mut summary = loaded.summary.clone();
        summary.sequence = request.entry.sequence;
        summary.updated_at_ms = request.entry.at_ms;
        codec::frame(Reply::SessionOpened(SessionOpened {
            summary,
            entries: Items::new(vec![request.entry.clone()])?,
            next_sequence: None,
        }))?;
        let bytes = framed(&payload)?;
        if loaded.summary.sequence >= limits.max_entries_per_session
            || self
                .usage(&dir, limits)?
                .checked_add(bytes.len() as u64)
                .is_none_or(|total| total > limits.max_bytes_per_principal)
        {
            return Err(codes::SUPERVISOR_STATE);
        }
        current_log(&dir, request.session_id, &loaded)?;
        let mut file = &loaded.file;
        file.seek(SeekFrom::End(0))
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        file.write_all(&bytes)
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        Ok(SessionAppended {
            entry: request.entry,
        })
    }

    pub(super) fn flush(
        &mut self,
        scope: PrincipalScope,
        request: SessionFlush,
        limits: SessionLimits,
    ) -> Result<SessionFlushed> {
        let dir = self.principal(scope, false)?;
        let loaded = self.load(&dir, request.session_id, limits)?;
        self.flush_loaded(&dir, request.session_id, request.through_sequence, &loaded)
    }

    fn flush_loaded(
        &self,
        dir: &File,
        id: SessionId,
        through: u64,
        loaded: &Loaded,
    ) -> Result<SessionFlushed> {
        if through > loaded.summary.sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        current_log(dir, id, loaded)?;
        loaded
            .file
            .sync_all()
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        current_log(dir, id, loaded)?;
        let durable = receipt(id, loaded.summary.sequence, &loaded.bytes);
        checkpoint(dir, &durable)?;
        let end = *loaded
            .ends
            .get(through as usize)
            .ok_or(codes::SESSION_SEQUENCE)?;
        Ok(receipt(id, through, &loaded.bytes[..end]))
    }

    pub(super) fn before_dispatch(
        &mut self,
        scope: PrincipalScope,
        session_id: SessionId,
        sequence: u64,
        limits: SessionLimits,
    ) -> Result<SessionFlushed> {
        let dir = self.principal(scope, false)?;
        let loaded = self.load(&dir, session_id, limits)?;
        if loaded.summary.sequence != sequence {
            return Err(codes::SESSION_SEQUENCE);
        }
        self.flush_loaded(&dir, session_id, sequence, &loaded)
    }

    pub(super) fn recover(
        &mut self,
        scope: PrincipalScope,
        session_id: SessionId,
        limits: SessionLimits,
    ) -> Result<TailRecovery> {
        let dir = self.principal(scope, false)?;
        let loaded = self.load(&dir, session_id, limits)?;
        Ok(TailRecovery {
            session_id,
            last_complete_sequence: loaded.summary.sequence,
            discarded_tail_bytes: loaded.discarded,
            committed_prefix: Digest32::sha256(&loaded.bytes),
        })
    }

    fn usage(&self, dir: &File, limits: SessionLimits) -> Result<u64> {
        let ids = session_ids(dir)?;
        let mut staged = Vec::new();
        for name in names(dir)? {
            if let Some(id) = name.strip_suffix(".creating") {
                staged.push(SessionId::from_hex(id).map_err(|_| codes::SUPERVISOR_STATE)?);
            }
        }
        let new_staged = staged.iter().filter(|id| !ids.contains(id)).count();
        if ids.len() + new_staged > limits.max_sessions_per_principal as usize {
            return Err(codes::SUPERVISOR_STATE);
        }
        let mut used = 0u64;
        for id in ids {
            let size = required(dir, &format!("{id}.session"))?
                .metadata()
                .map_err(|_| codes::SUPERVISOR_STATE)?
                .len();
            used = used
                .checked_add(size)
                .and_then(|n| n.checked_add(RESERVE))
                .ok_or(codes::SUPERVISOR_STATE)?;
        }
        for id in staged {
            let size = required(dir, &format!("{id}.creating"))?
                .metadata()
                .map_err(|_| codes::SUPERVISOR_STATE)?
                .len();
            used = used.checked_add(size).ok_or(codes::SUPERVISOR_STATE)?;
            if leaf(dir, &format!("{id}.session"), false)?.is_none() {
                used = used
                    .checked_add(size)
                    .and_then(|n| n.checked_add(4 + RESERVE))
                    .ok_or(codes::SUPERVISOR_STATE)?;
            }
        }
        if used > limits.max_bytes_per_principal {
            return Err(codes::SUPERVISOR_STATE);
        }
        Ok(used)
    }

    fn recover_creating(&self, dir: &File) -> Result<()> {
        self.usage(dir, self.limits)?;
        for name in names(dir)? {
            let Some(id) = name.strip_suffix(".creating") else {
                continue;
            };
            let id = SessionId::from_hex(id).map_err(|_| codes::SUPERVISOR_STATE)?;
            let mut marker = required(dir, &name)?;
            let payload = read_bounded(&mut marker, canon::frame::MAX_FRAME_BYTES as u64)?;
            drop(marker);
            let Reply::SessionCreated(summary) = codec::decode(&payload, "session.create")? else {
                return Err(codes::SUPERVISOR_STATE);
            };
            if summary.session_id != id
                || summary.sequence != 0
                || summary.archived
                || summary.created_at_ms != summary.updated_at_ms
            {
                return Err(codes::SUPERVISOR_STATE);
            }
            let initial = framed(&payload)?;
            let cursor = codec::record(Reply::SessionFlushed(receipt(id, 0, &initial)))?;
            let files = [
                ("commit", cursor.as_slice()),
                ("session", initial.as_slice()),
            ];
            let mut missing = Vec::new();
            for (extension, expected) in files {
                let target = format!("{id}.{extension}");
                match leaf(dir, &target, false)? {
                    Some(mut existing) => {
                        if read_bounded(&mut existing, self.limits.max_bytes_per_principal)?
                            != expected
                        {
                            return Err(codes::SUPERVISOR_STATE);
                        }
                        existing.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?;
                    }
                    None => missing.push((target, expected)),
                }
            }
            for (target, expected) in missing {
                atomic(dir, &target, &format!("{id}.pending"), expected)?;
            }
            dir.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?;
            fs::unlinkat(dir, &name, AtFlags::empty()).map_err(|_| codes::SUPERVISOR_STATE)?;
            if dir.sync_all().is_err() {
                let _ = atomic(dir, &name, &format!("{id}.pending"), &payload);
                return Err(codes::SUPERVISOR_STATE);
            }
        }
        dir.sync_all().map_err(|_| codes::SUPERVISOR_STATE)
    }

    fn load(&self, dir: &File, id: SessionId, limits: SessionLimits) -> Result<Loaded> {
        let mut file = required(dir, &format!("{id}.session"))?;
        let original = file.metadata().map_err(|_| codes::SUPERVISOR_STATE)?;
        let mut bytes = read_bounded(&mut file, limits.max_bytes_per_principal)?;
        let mut position = 0usize;
        let mut ends = Vec::new();
        let mut entries = Vec::new();
        let mut summary = None;
        while position < bytes.len() {
            if bytes.len() - position < 4 {
                break;
            }
            let size = u32::from_be_bytes(
                bytes[position..position + 4]
                    .try_into()
                    .map_err(|_| codes::SUPERVISOR_STATE)?,
            ) as usize;
            if size == 0 || size > canon::frame::MAX_FRAME_BYTES {
                return Err(codes::SUPERVISOR_STATE);
            }
            let end = position
                .checked_add(4 + size)
                .ok_or(codes::SUPERVISOR_STATE)?;
            if end > bytes.len() {
                break;
            }
            if summary.is_none() {
                let Reply::SessionCreated(value) =
                    codec::decode(&bytes[position + 4..end], "session.create")?
                else {
                    return Err(codes::SUPERVISOR_STATE);
                };
                if value.session_id != id
                    || value.sequence != 0
                    || value.created_at_ms != value.updated_at_ms
                {
                    return Err(codes::SUPERVISOR_STATE);
                }
                summary = Some(value);
            } else {
                let Reply::SessionAppended(value) =
                    codec::decode(&bytes[position + 4..end], "session.append")?
                else {
                    return Err(codes::SUPERVISOR_STATE);
                };
                if value.entry.session_id != id
                    || value.entry.sequence != entries.len() as u64 + 1
                    || value.entry.commitment != codec::entry_commitment(&value.entry)?
                    || entries.len() as u64 >= limits.max_entries_per_session
                {
                    return Err(codes::SUPERVISOR_STATE);
                }
                entries.push(value.entry);
            }
            ends.push(end);
            position = end;
        }
        let mut summary = summary.ok_or(codes::SUPERVISOR_STATE)?;
        summary.sequence = entries.len() as u64;
        if let Some(last) = entries.last() {
            summary.updated_at_ms = last.at_ms;
        }
        match leaf(dir, &format!("{id}.commit"), false)? {
            Some(mut cursor) => {
                let data = read_bounded(&mut cursor, RESERVE / 2)?;
                let Reply::SessionFlushed(receipt) = codec::decode(&data, "session.flush")? else {
                    return Err(codes::SUPERVISOR_STATE);
                };
                let end = *ends
                    .get(receipt.sequence as usize)
                    .ok_or(codes::SUPERVISOR_STATE)?;
                if receipt.session_id != id || receipt.commitment != Digest32::sha256(&bytes[..end])
                {
                    return Err(codes::SUPERVISOR_STATE);
                }
            }
            None => return Err(codes::SUPERVISOR_STATE),
        }
        let discarded = (bytes.len() - position) as u64;
        if !same_snapshot(
            &original,
            &file.metadata().map_err(|_| codes::SUPERVISOR_STATE)?,
        ) {
            return Err(codes::SUPERVISOR_STATE);
        }
        if discarded > 0 {
            file.set_len(position as u64)
                .map_err(|_| codes::SUPERVISOR_STATE)?;
            file.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?;
            bytes.truncate(position);
        }
        let metadata = file.metadata().map_err(|_| codes::SUPERVISOR_STATE)?;
        Ok(Loaded {
            file,
            metadata,
            summary,
            entries,
            bytes,
            ends,
            discarded,
        })
    }
}

fn receipt(session_id: SessionId, sequence: u64, bytes: &[u8]) -> SessionFlushed {
    SessionFlushed {
        v: RECORD_VERSION,
        algorithm: AlgorithmId::Sha256,
        session_id,
        sequence,
        commitment: Digest32::sha256(bytes),
    }
}

fn checkpoint(dir: &File, receipt: &SessionFlushed) -> Result<()> {
    let bytes = codec::record(Reply::SessionFlushed(receipt.clone()))?;
    if bytes.len() as u64 > RESERVE / 2 {
        return Err(codes::SUPERVISOR_STATE);
    }
    atomic(
        dir,
        &format!("{}.commit", receipt.session_id),
        &format!("{}.pending", receipt.session_id),
        &bytes,
    )
}

fn atomic(dir: &File, name: &str, pending: &str, bytes: &[u8]) -> Result<()> {
    let mut file = leaf(dir, pending, true)?.ok_or(codes::SUPERVISOR_STATE)?;
    file.set_len(0).map_err(|_| codes::SUPERVISOR_STATE)?;
    file.write_all(bytes).map_err(|_| codes::SUPERVISOR_STATE)?;
    file.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?;
    fs::renameat(dir, pending, dir, name).map_err(|_| codes::SUPERVISOR_STATE)?;
    let published = required(dir, name)?
        .metadata()
        .map_err(|_| codes::SUPERVISOR_STATE)?;
    if !same_snapshot(
        &file.metadata().map_err(|_| codes::SUPERVISOR_STATE)?,
        &published,
    ) {
        return Err(codes::SUPERVISOR_STATE);
    }
    dir.sync_all().map_err(|_| codes::SUPERVISOR_STATE)
}

fn framed(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > canon::frame::MAX_FRAME_BYTES {
        return Err(codes::FRAME_TOO_LARGE);
    }
    let mut bytes = Vec::with_capacity(payload.len() + 4);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn read_bounded(file: &mut File, limit: u64) -> Result<Vec<u8>> {
    let before = file.metadata().map_err(|_| codes::SUPERVISOR_STATE)?;
    if before.len() > limit {
        return Err(codes::SUPERVISOR_STATE);
    }
    let mut data = Vec::new();
    Read::by_ref(file)
        .take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| codes::SUPERVISOR_STATE)?;
    let after = file.metadata().map_err(|_| codes::SUPERVISOR_STATE)?;
    if data.len() as u64 > limit || !same_snapshot(&before, &after) {
        return Err(codes::SUPERVISOR_STATE);
    }
    Ok(data)
}

fn current_log(dir: &File, id: SessionId, loaded: &Loaded) -> Result<()> {
    let linked = required(dir, &format!("{id}.session"))?;
    let metadata = linked.metadata().map_err(|_| codes::SUPERVISOR_STATE)?;
    if !same_snapshot(&loaded.metadata, &metadata) {
        return Err(codes::SUPERVISOR_STATE);
    }
    Ok(())
}

fn same_snapshot(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && private(b, false).is_ok()
}

fn page_limit(limit: u16) -> Result<()> {
    if limit == 0 || limit as usize > MAX_SESSION_PAGE {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    Ok(())
}

fn now() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| codes::SUPERVISOR_STATE)?
        .as_millis();
    u64::try_from(millis)
        .ok()
        .filter(|n| *n <= MAX)
        .ok_or(codes::SUPERVISOR_STATE)
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn root(path: &Path) -> Result<File> {
    let mut current = File::from(
        fs::openat(fs::CWD, ".", dir_flags(), Mode::empty())
            .map_err(|_| codes::SUPERVISOR_STATE)?,
    );
    let mut saw_name = false;
    for part in path.components() {
        match part {
            Component::RootDir => {
                current = File::from(
                    fs::openat(fs::CWD, part.as_os_str(), dir_flags(), Mode::empty())
                        .map_err(|_| codes::SUPERVISOR_STATE)?,
                )
            }
            Component::Normal(name) => {
                match fs::mkdirat(&current, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                    Ok(()) => current.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(codes::SUPERVISOR_STATE),
                }
                current = File::from(
                    fs::openat(&current, name, dir_flags(), Mode::empty())
                        .map_err(|_| codes::SUPERVISOR_STATE)?,
                );
                saw_name = true;
            }
            Component::CurDir => {}
            _ => return Err(codes::SUPERVISOR_STATE),
        }
    }
    if !saw_name {
        return Err(codes::SUPERVISOR_STATE);
    }
    private(
        &current.metadata().map_err(|_| codes::SUPERVISOR_STATE)?,
        true,
    )?;
    Ok(current)
}

fn directory(parent: &File, name: &str, create: bool) -> Result<File> {
    if create {
        match fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => parent.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(codes::SUPERVISOR_STATE),
        }
    }
    let fd = fs::openat(parent, name, dir_flags(), Mode::empty()).map_err(|e| {
        if e == rustix::io::Errno::NOENT {
            codes::SESSION_NOT_FOUND
        } else {
            codes::SUPERVISOR_STATE
        }
    })?;
    let file = File::from(fd);
    private(&file.metadata().map_err(|_| codes::SUPERVISOR_STATE)?, true)?;
    Ok(file)
}

fn leaf(dir: &File, name: &str, create: bool) -> Result<Option<File>> {
    let flags = OFlags::RDWR
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC
        | if create {
            OFlags::CREATE
        } else {
            OFlags::empty()
        };
    match fs::openat(dir, name, flags, Mode::RUSR | Mode::WUSR) {
        Ok(fd) => {
            let file = File::from(fd);
            private(
                &file.metadata().map_err(|_| codes::SUPERVISOR_STATE)?,
                false,
            )?;
            Ok(Some(file))
        }
        Err(rustix::io::Errno::NOENT) if !create => Ok(None),
        Err(_) => Err(codes::SUPERVISOR_STATE),
    }
}

fn required(dir: &File, name: &str) -> Result<File> {
    leaf(dir, name, false)?.ok_or(codes::SESSION_NOT_FOUND)
}

fn private(metadata: &Metadata, dir: bool) -> Result<()> {
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != if dir { 0o700 } else { 0o600 }
        || if dir {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(codes::SUPERVISOR_STATE);
    }
    Ok(())
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
            names.push(name.into());
        }
    }
    names.sort();
    Ok(names)
}

fn session_ids(dir: &File) -> Result<Vec<SessionId>> {
    let names = names(dir)?;
    let mut sessions = Vec::new();
    for name in &names {
        let (id, extension) = name.rsplit_once('.').ok_or(codes::SUPERVISOR_STATE)?;
        let id = SessionId::from_hex(id).map_err(|_| codes::SUPERVISOR_STATE)?;
        if !matches!(extension, "session" | "commit" | "pending" | "creating") {
            return Err(codes::SUPERVISOR_STATE);
        }
        required(dir, name)?;
        if extension == "session" {
            sessions.push(id);
        } else if extension == "commit"
            && !names.contains(&format!("{id}.session"))
            && !names.contains(&format!("{id}.creating"))
        {
            return Err(codes::SUPERVISOR_STATE);
        }
    }
    Ok(sessions)
}

fn clean_pending(dir: &File) -> Result<()> {
    for name in names(dir)? {
        if let Some(id) = name.strip_suffix(".pending") {
            SessionId::from_hex(id).map_err(|_| codes::SUPERVISOR_STATE)?;
            required(dir, &name)?;
            fs::unlinkat(dir, &name, AtFlags::empty()).map_err(|_| codes::SUPERVISOR_STATE)?;
            dir.sync_all().map_err(|_| codes::SUPERVISOR_STATE)?;
        }
    }
    Ok(())
}
