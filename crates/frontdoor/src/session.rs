// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable browser admission. Session possession never authorizes an effect.

use crate::{owner_origin::OwnerRoute, tls::Origin};
use canon::{
    codes::{
        AUMLOK_BINDING_REQUIRED, AUMLOK_ENROLMENT_REQUIRED, FRONTDOOR_COOKIE_HOST_REFUSED,
        FRONTDOOR_SESSION_REQUIRED,
    },
    digest::Digest32,
    ids::{NodeId, SubjectId},
    Result,
};
use rustix::fs::{flock, openat, renameat, unlinkat, AtFlags, FlockOperation, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};
use zeroize::{Zeroize, Zeroizing};

pub const OWNER_COOKIE: &str = "__Host-aukora-owner";
pub const SHELL_COOKIE: &str = "__Host-aukora-chat";
pub const COOKIE_ATTRIBUTES: &str = "Path=/; Secure; HttpOnly; SameSite=Strict";
pub const MAX_LIFETIME_MS: u64 = 86_400_000;
const MAX_SESSIONS: usize = 4096;
const MAX_STORE_BYTES: u64 = 2_097_152;
const MAX_COUNTER: u64 = canon::json::MAX_SAFE_INTEGER as u64;
const STATE_FILE: &str = "sessions-v1.json";
const LOCK_FILE: &str = "sessions.lock";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingState {
    Unclaimed,
    Claimed,
    Enrolled,
    Bound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionScope {
    BindingOnly,
    OwnerFrame,
    Shell,
}

/// Persist only the digest and admission metadata, never the bearer.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub token_digest: Digest32,
    pub node: NodeId,
    pub origin: Origin,
    pub subject: Option<SubjectId>,
    pub owner_epoch: u64,
    pub scope: SessionScope,
    pub expires_at_ms: u64,
    pub revoked: bool,
}

/// Stores keep the live epoch and revocation guard throughout each callback.
pub trait SessionStore {
    fn lookup(&mut self, digest: Digest32) -> Result<Option<SessionRecord>>;
    fn revoke(&mut self, digest: Digest32) -> Result<()>;
    /// The live parent must be bound, and insertion shares its revocation transaction.
    fn derive_shell(&mut self, parent: Digest32, child: SessionRecord, now_ms: u64) -> Result<()>;
    fn with_live_session<T>(
        &mut self,
        digest: Digest32,
        now_ms: u64,
        operation: impl FnOnce(&SessionRecord) -> Result<T>,
    ) -> Result<T>;
}

/// Exists only while its store's live-session transaction is held.
pub struct BoundSession<'a> {
    record: &'a SessionRecord,
}
impl BoundSession<'_> {
    pub fn record(&self) -> &SessionRecord {
        self.record
    }
}

/// A bootstrap session cannot be passed to agent, documents or approval APIs.
pub struct BindingSession<'a> {
    record: &'a SessionRecord,
}
impl BindingSession<'_> {
    pub fn record(&self) -> &SessionRecord {
        self.record
    }
}

pub enum OwnerSession<'a> {
    Binding(BindingSession<'a>),
    Bound(BoundSession<'a>),
}

/// Parse the single cookie value, never a header, and hash its exact ASCII bytes.
pub fn session_digest(cookie: &[u8]) -> Result<Digest32> {
    if cookie.len() != 64
        || !cookie
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(FRONTDOOR_SESSION_REQUIRED);
    }
    Ok(Digest32::sha256(cookie))
}

/// Generated bearer bytes are erased when this value drops.
pub struct SessionBearer {
    token: Zeroizing<String>,
}
impl SessionBearer {
    pub fn generate() -> Result<Self> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        let mut token = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in entropy.iter() {
            token.push(HEX[(byte >> 4) as usize] as char);
            token.push(HEX[(byte & 15) as usize] as char);
        }
        Ok(Self {
            token: Zeroizing::new(token),
        })
    }
    pub fn digest(&self) -> Digest32 {
        Digest32::sha256(self.token.as_bytes())
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.token.as_bytes()
    }
    /// Issue this only after the corresponding record's durable insertion succeeded.
    pub fn cookie_header(
        &self,
        scope: SessionScope,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<String> {
        if expires_at_ms > MAX_COUNTER || now_ms > MAX_COUNTER {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        let lifetime = expires_at_ms
            .checked_sub(now_ms)
            .filter(|v| (1000..=MAX_LIFETIME_MS).contains(v))
            .ok_or(FRONTDOOR_SESSION_REQUIRED)?;
        let name = if scope == SessionScope::Shell {
            SHELL_COOKIE
        } else {
            OWNER_COOKIE
        };
        Ok(format!(
            "{name}={}; {COOKIE_ATTRIBUTES}; Max-Age={}",
            self.token.as_str(),
            lifetime / 1000
        ))
    }
}

pub fn with_bound_session<S: SessionStore, T>(
    store: &mut S,
    cookie: &[u8],
    node: NodeId,
    origin: &Origin,
    now_ms: u64,
    operation: impl for<'a> FnOnce(BoundSession<'a>) -> Result<T>,
) -> Result<T> {
    store.with_live_session(session_digest(cookie)?, now_ms, |record| {
        check_audience(record, node, origin, now_ms)?;
        if record.scope == SessionScope::BindingOnly || record.subject.is_none() {
            return Err(AUMLOK_BINDING_REQUIRED);
        }
        operation(BoundSession { record })
    })
}

/// Only enrolment and initial binding can receive bootstrap admission.
pub fn with_owner_session<S: SessionStore, T>(
    store: &mut S,
    cookie: &[u8],
    node: NodeId,
    origin: &Origin,
    route: OwnerRoute,
    now_ms: u64,
    operation: impl for<'a> FnOnce(OwnerSession<'a>) -> Result<T>,
) -> Result<T> {
    store.with_live_session(session_digest(cookie)?, now_ms, |record| {
        check_audience(record, node, origin, now_ms)?;
        match record.scope {
            SessionScope::Shell => Err(FRONTDOOR_COOKIE_HOST_REFUSED),
            SessionScope::BindingOnly => {
                if !matches!(
                    route,
                    OwnerRoute::EnrolStart
                        | OwnerRoute::EnrolFinish
                        | OwnerRoute::BindingPrepare
                        | OwnerRoute::BindingConfirm
                ) {
                    return Err(AUMLOK_BINDING_REQUIRED);
                }
                if matches!(
                    route,
                    OwnerRoute::BindingPrepare | OwnerRoute::BindingConfirm
                ) && record.subject.is_none()
                {
                    return Err(AUMLOK_ENROLMENT_REQUIRED);
                }
                operation(OwnerSession::Binding(BindingSession { record }))
            }
            SessionScope::OwnerFrame if record.subject.is_some() => {
                operation(OwnerSession::Bound(BoundSession { record }))
            }
            _ => Err(FRONTDOOR_SESSION_REQUIRED),
        }
    })
}

fn check_audience(
    record: &SessionRecord,
    node: NodeId,
    origin: &Origin,
    now_ms: u64,
) -> Result<()> {
    if record.revoked
        || record.expires_at_ms <= now_ms
        || record.node != node
        || record.expires_at_ms > MAX_COUNTER
        || record.owner_epoch > MAX_COUNTER
        || now_ms > MAX_COUNTER
    {
        return Err(FRONTDOOR_SESSION_REQUIRED);
    }
    if &record.origin != origin {
        return Err(FRONTDOOR_COOKIE_HOST_REFUSED);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SessionFacts {
    pub durable_sessions: u64,
    pub binding_only_sessions: u64,
    pub revoked_sessions: u64,
    pub failed_durable_writes: u64,
}

/// Uses a private directory capability validated on construction.
/// Every read reloads the durable state under a process-shared lock; no memory fallback exists.
pub struct DurableSessions {
    directory: File,
    node: NodeId,
    shell: Origin,
    owner: Origin,
    failed_writes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    format: String,
    node: String,
    shell: String,
    owner: String,
    epoch: u64,
    binding: String,
    subject: Option<String>,
    records: Vec<StoredRecord>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    digest: String,
    origin: String,
    subject: Option<String>,
    epoch: u64,
    scope: String,
    expires_at_ms: u64,
    revoked: bool,
    parent: Option<String>,
}

impl DurableSessions {
    /// Open existing state; missing or malformed storage refuses startup.
    pub fn open(directory: File, node: NodeId, shell: Origin, owner: Origin) -> Result<Self> {
        let store = Self::capability(directory, node, shell, owner)?;
        let _lock = store.lock()?;
        store.load()?;
        Ok(store)
    }
    /// Explicit first boot, separate from open; existing state is never overwritten.
    pub fn initialize(directory: File, node: NodeId, shell: Origin, owner: Origin) -> Result<Self> {
        let mut store = Self::capability(directory, node, shell, owner)?;
        let _lock = store.lock()?;
        match store.read_file(STATE_FILE) {
            Err(error) if error == rustix::io::Errno::NOENT => {}
            _ => return Err(FRONTDOOR_SESSION_REQUIRED),
        }
        let state = StoredState {
            format: "frontdoor-sessions-v1".to_owned(),
            node: node.to_string(),
            shell: store.shell.as_str().to_owned(),
            owner: store.owner.as_str().to_owned(),
            epoch: 0,
            binding: "unclaimed".to_owned(),
            subject: None,
            records: Vec::new(),
        };
        store.save(&state)?;
        Ok(store)
    }
    fn capability(directory: File, node: NodeId, shell: Origin, owner: Origin) -> Result<Self> {
        let meta = directory
            .metadata()
            .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        if !meta.is_dir() || meta.mode() & 0o077 != 0 || shell == owner {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        Ok(Self {
            directory,
            node,
            shell,
            owner,
            failed_writes: 0,
        })
    }
    fn lock(&self) -> Result<File> {
        let file: File = openat(
            &self.directory,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?
        .into();
        private_file(&file)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        Ok(file)
    }
    fn read_file(&self, name: &str) -> rustix::io::Result<File> {
        openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
    }
    fn load(&self) -> Result<StoredState> {
        let file = self
            .read_file(STATE_FILE)
            .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        private_file(&file)?;
        let mut bytes = Vec::new();
        file.take(MAX_STORE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        let state: StoredState =
            serde_json::from_slice(&bytes).map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        self.validate_state(&state)?;
        Ok(state)
    }
    fn validate_state(&self, state: &StoredState) -> Result<()> {
        if state.format != "frontdoor-sessions-v1"
            || state.node != self.node.to_string()
            || state.shell != self.shell.as_str()
            || state.owner != self.owner.as_str()
            || state.records.len() > MAX_SESSIONS
            || state.epoch > MAX_COUNTER
        {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        let binding = parse_binding(&state.binding)?;
        let subject = parse_subject(state.subject.as_deref())?;
        if matches!(binding, BindingState::Enrolled | BindingState::Bound) != subject.is_some() {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        let mut seen = std::collections::BTreeSet::new();
        for stored in &state.records {
            let record = self.decode_record(stored)?;
            if !seen.insert(record.token_digest)
                || record.owner_epoch > state.epoch
                || record.expires_at_ms == 0
                || record.expires_at_ms > MAX_COUNTER
                || (record.scope == SessionScope::Shell) != stored.parent.is_some()
            {
                return Err(FRONTDOOR_SESSION_REQUIRED);
            }
            if let Some(parent) = &stored.parent {
                Digest32::from_hex(parent).map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
            }
        }
        Ok(())
    }
    fn decode_record(&self, stored: &StoredRecord) -> Result<SessionRecord> {
        let scope = parse_scope(&stored.scope)?;
        let origin = Origin::parse(&stored.origin).map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        if origin
            != *if scope == SessionScope::Shell {
                &self.shell
            } else {
                &self.owner
            }
        {
            return Err(FRONTDOOR_COOKIE_HOST_REFUSED);
        }
        let subject = parse_subject(stored.subject.as_deref())?;
        if scope != SessionScope::BindingOnly && subject.is_none() {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        Ok(SessionRecord {
            token_digest: Digest32::from_hex(&stored.digest)
                .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?,
            node: self.node,
            origin,
            subject,
            owner_epoch: stored.epoch,
            scope,
            expires_at_ms: stored.expires_at_ms,
            revoked: stored.revoked,
        })
    }
    fn save(&mut self, state: &StoredState) -> Result<()> {
        let result = self.save_inner(state);
        if result.is_err() {
            self.failed_writes = self.failed_writes.saturating_add(1);
        }
        result
    }
    fn save_inner(&self, state: &StoredState) -> Result<()> {
        self.validate_state(state)?;
        let bytes = serde_json::to_vec(state).map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
        let temporary = format!(".sessions-{}", Digest32::sha256(&nonce));
        nonce.zeroize();
        let mut file: File = openat(
            &self.directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?
        .into();
        let result = (|| {
            file.write_all(&bytes)
                .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
            file.sync_all().map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
            renameat(
                &self.directory,
                temporary.as_str(),
                &self.directory,
                STATE_FILE,
            )
            .map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
            self.directory
                .sync_all()
                .map_err(|_| FRONTDOOR_SESSION_REQUIRED)
        })();
        if result.is_err() {
            let _ = unlinkat(&self.directory, temporary.as_str(), AtFlags::empty());
        }
        result
    }
    /// Store admission metadata; verification and authority consumption remain external.
    pub fn insert_after_ceremony(&mut self, record: SessionRecord, now_ms: u64) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        if record.scope == SessionScope::Shell {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        self.insert_record(&mut state, record, None, now_ms)?;
        self.save(&state)
    }
    /// Epoch changes revoke every existing session in the same durable write.
    pub fn synchronize_binding(
        &mut self,
        epoch: u64,
        binding: BindingState,
        subject: Option<SubjectId>,
    ) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        apply_binding(&mut state, epoch, binding, subject)?;
        self.save(&state)
    }
    /// Persist binding metadata and promote only its exact live browser session.
    /// This changes admission metadata; it does not verify or consume owner authority.
    pub fn advance_after_ceremony(
        &mut self,
        digest: Digest32,
        epoch: u64,
        binding: BindingState,
        subject: Option<SubjectId>,
        now_ms: u64,
    ) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        let current = self.live_record(&state, digest, now_ms)?;
        if current.scope == SessionScope::Shell || binding == BindingState::Unclaimed {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        if binding == BindingState::Bound && parse_binding(&state.binding)? == BindingState::Claimed
        {
            return Err(AUMLOK_ENROLMENT_REQUIRED);
        }
        apply_binding(&mut state, epoch, binding, subject)?;
        let record = state
            .records
            .iter_mut()
            .find(|r| r.digest == digest.to_string())
            .ok_or(FRONTDOOR_SESSION_REQUIRED)?;
        record.subject = state.subject.clone();
        record.epoch = epoch;
        record.scope = if binding == BindingState::Bound {
            "owner"
        } else {
            "binding"
        }
        .to_owned();
        record.revoked = false;
        self.save(&state)
    }
    fn insert_record(
        &self,
        state: &mut StoredState,
        record: SessionRecord,
        parent: Option<Digest32>,
        now_ms: u64,
    ) -> Result<()> {
        check_audience(
            &record,
            self.node,
            if record.scope == SessionScope::Shell {
                &self.shell
            } else {
                &self.owner
            },
            now_ms,
        )?;
        let lifetime = record
            .expires_at_ms
            .checked_sub(now_ms)
            .ok_or(FRONTDOOR_SESSION_REQUIRED)?;
        state
            .records
            .retain(|record| !record.revoked && record.expires_at_ms > now_ms);
        if lifetime > MAX_LIFETIME_MS
            || record.owner_epoch != state.epoch
            || state.records.len() >= MAX_SESSIONS
            || state
                .records
                .iter()
                .any(|old| old.digest == record.token_digest.to_string())
        {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        let binding = parse_binding(&state.binding)?;
        if record.scope != SessionScope::BindingOnly
            && (binding != BindingState::Bound
                || record.subject.as_ref().map(ToString::to_string) != state.subject)
        {
            return Err(AUMLOK_BINDING_REQUIRED);
        }
        if record.scope == SessionScope::BindingOnly
            && (!matches!(binding, BindingState::Claimed | BindingState::Enrolled)
                || record.subject.as_ref().map(ToString::to_string) != state.subject)
        {
            return Err(AUMLOK_BINDING_REQUIRED);
        }
        state.records.push(StoredRecord {
            digest: record.token_digest.to_string(),
            origin: record.origin.as_str().to_owned(),
            subject: record.subject.map(|id| id.to_string()),
            epoch: record.owner_epoch,
            scope: scope_name(record.scope).to_owned(),
            expires_at_ms: record.expires_at_ms,
            revoked: false,
            parent: parent.map(|digest| digest.to_string()),
        });
        Ok(())
    }
    fn live_record(
        &self,
        state: &StoredState,
        digest: Digest32,
        now_ms: u64,
    ) -> Result<SessionRecord> {
        let stored = state
            .records
            .iter()
            .find(|r| r.digest == digest.to_string())
            .ok_or(FRONTDOOR_SESSION_REQUIRED)?;
        let record = self.decode_record(stored)?;
        if record.revoked || record.expires_at_ms <= now_ms || record.owner_epoch != state.epoch {
            return Err(FRONTDOOR_SESSION_REQUIRED);
        }
        if record.scope != SessionScope::BindingOnly
            && (parse_binding(&state.binding)? != BindingState::Bound
                || record.subject.as_ref().map(ToString::to_string) != state.subject)
        {
            return Err(AUMLOK_BINDING_REQUIRED);
        }
        if record.scope == SessionScope::BindingOnly
            && (!matches!(
                parse_binding(&state.binding)?,
                BindingState::Claimed | BindingState::Enrolled
            ) || record.subject.as_ref().map(ToString::to_string) != state.subject)
        {
            return Err(AUMLOK_BINDING_REQUIRED);
        }
        if let Some(parent) = &stored.parent {
            let parent = state
                .records
                .iter()
                .find(|r| &r.digest == parent)
                .ok_or(FRONTDOOR_SESSION_REQUIRED)?;
            if parent.revoked
                || parent.expires_at_ms <= now_ms
                || parent.epoch != state.epoch
                || parent.scope != "owner"
                || parent.subject != stored.subject
            {
                return Err(FRONTDOOR_SESSION_REQUIRED);
            }
        }
        Ok(record)
    }
    pub fn facts(&mut self) -> Result<SessionFacts> {
        let _lock = self.lock()?;
        let state = self.load()?;
        Ok(SessionFacts {
            durable_sessions: state.records.len() as u64,
            binding_only_sessions: state
                .records
                .iter()
                .filter(|r| r.scope == "binding")
                .count() as u64,
            revoked_sessions: state.records.iter().filter(|r| r.revoked).count() as u64,
            failed_durable_writes: self.failed_writes,
        })
    }
}

impl SessionStore for DurableSessions {
    fn lookup(&mut self, digest: Digest32) -> Result<Option<SessionRecord>> {
        let _lock = self.lock()?;
        let state = self.load()?;
        state
            .records
            .iter()
            .find(|r| r.digest == digest.to_string())
            .map(|r| self.decode_record(r))
            .transpose()
    }
    fn revoke(&mut self, digest: Digest32) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        let name = digest.to_string();
        for record in &mut state.records {
            if record.digest == name || record.parent.as_ref() == Some(&name) {
                record.revoked = true;
            }
        }
        self.save(&state)
    }
    fn derive_shell(&mut self, parent: Digest32, child: SessionRecord, now_ms: u64) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        let live_parent = self.live_record(&state, parent, now_ms)?;
        if live_parent.scope != SessionScope::OwnerFrame
            || live_parent.subject.is_none()
            || child.scope != SessionScope::Shell
            || child.subject != live_parent.subject
            || child.owner_epoch != live_parent.owner_epoch
            || child.expires_at_ms > live_parent.expires_at_ms
        {
            return Err(AUMLOK_BINDING_REQUIRED);
        }
        self.insert_record(&mut state, child, Some(parent), now_ms)?;
        self.save(&state)
    }
    fn with_live_session<T>(
        &mut self,
        digest: Digest32,
        now_ms: u64,
        operation: impl FnOnce(&SessionRecord) -> Result<T>,
    ) -> Result<T> {
        let _lock = self.lock()?;
        let state = self.load()?;
        let record = self.live_record(&state, digest, now_ms)?;
        operation(&record)
    }
}

fn private_file(file: &File) -> Result<()> {
    let meta = file.metadata().map_err(|_| FRONTDOOR_SESSION_REQUIRED)?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(FRONTDOOR_SESSION_REQUIRED);
    }
    Ok(())
}
fn parse_subject(text: Option<&str>) -> Result<Option<SubjectId>> {
    text.map(|text| SubjectId::parse(text).map_err(|_| FRONTDOOR_SESSION_REQUIRED))
        .transpose()
}
fn parse_binding(text: &str) -> Result<BindingState> {
    match text {
        "unclaimed" => Ok(BindingState::Unclaimed),
        "claimed" => Ok(BindingState::Claimed),
        "enrolled" => Ok(BindingState::Enrolled),
        "bound" => Ok(BindingState::Bound),
        _ => Err(FRONTDOOR_SESSION_REQUIRED),
    }
}
fn binding_name(binding: BindingState) -> &'static str {
    match binding {
        BindingState::Unclaimed => "unclaimed",
        BindingState::Claimed => "claimed",
        BindingState::Enrolled => "enrolled",
        BindingState::Bound => "bound",
    }
}
fn parse_scope(text: &str) -> Result<SessionScope> {
    match text {
        "binding" => Ok(SessionScope::BindingOnly),
        "owner" => Ok(SessionScope::OwnerFrame),
        "shell" => Ok(SessionScope::Shell),
        _ => Err(FRONTDOOR_SESSION_REQUIRED),
    }
}
fn scope_name(scope: SessionScope) -> &'static str {
    match scope {
        SessionScope::BindingOnly => "binding",
        SessionScope::OwnerFrame => "owner",
        SessionScope::Shell => "shell",
    }
}

fn binding_rank(binding: BindingState) -> u8 {
    match binding {
        BindingState::Unclaimed => 0,
        BindingState::Claimed => 1,
        BindingState::Enrolled => 2,
        BindingState::Bound => 3,
    }
}

fn apply_binding(
    state: &mut StoredState,
    epoch: u64,
    binding: BindingState,
    subject: Option<SubjectId>,
) -> Result<()> {
    if epoch < state.epoch
        || (epoch == state.epoch
            && (binding_rank(binding) < binding_rank(parse_binding(&state.binding)?)
                || (subject.as_ref().map(ToString::to_string) != state.subject
                    && state.subject.is_some())))
        || matches!(binding, BindingState::Enrolled | BindingState::Bound) != subject.is_some()
    {
        return Err(FRONTDOOR_SESSION_REQUIRED);
    }
    if epoch > state.epoch {
        for record in &mut state.records {
            record.revoked = true;
        }
    }
    state.epoch = epoch;
    state.binding = binding_name(binding).to_owned();
    state.subject = subject.map(|id| id.to_string());
    Ok(())
}
