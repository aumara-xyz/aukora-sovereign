// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read spawn's host commitment and connect it to durable browser admission.

use aumlok::claim::{ClaimStore, HostClaimCommitment, SqliteClaimStore};
use canon::{codes, json, json::ValueView, Result};
use frontdoor::{
    claim::{ClaimRequest, ClaimService},
    session::{DurableSessions, SessionRecord},
};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub trait ClaimAuthority: Send + Sync {
    fn transaction(
        &self,
        operation: &mut dyn FnMut(&mut aura::LedgerTxn<'_>) -> Result<SessionRecord>,
    ) -> Result<SessionRecord>;
}

pub struct HostClaimService {
    directory: File,
    ledger: Arc<dyn ClaimAuthority>,
    claims: SqliteClaimStore,
    sessions: DurableSessions,
}

impl HostClaimService {
    /// The supervisor supplies the node's configuration directory and session store.
    pub fn from_host(
        directory: &File,
        mut sessions: DurableSessions,
        ledger: Arc<dyn ClaimAuthority>,
    ) -> Result<Self> {
        let commitment = HostClaimCommitment::from_host(directory)?;
        let path = session_directory(directory)?;
        let claims = sessions.open_claim_store(&path, &commitment)?;
        Ok(Self {
            directory: directory
                .try_clone()
                .map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?,
            ledger,
            claims,
            sessions,
        })
    }

    pub fn sessions_mut(&mut self) -> &mut DurableSessions {
        &mut self.sessions
    }
}

impl ClaimService for HostClaimService {
    fn consume_and_create_session(&mut self, request: ClaimRequest) -> Result<SessionRecord> {
        let token = Zeroizing::new(request.token);
        let commitment = HostClaimCommitment::from_host(&self.directory)?;
        commitment.verify(token.as_slice())?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?
            .as_millis();
        let now_ms = u64::try_from(now_ms).map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?;
        self.ledger.transaction(&mut |authority| {
            if authority.active_owner_passkeys()? != 0 {
                return Err(codes::AUMLOK_CLAIM_SPENT);
            }
            let admission = self.claims.claim(
                &commitment,
                token.as_slice(),
                request.node,
                request.session_digest,
                request.session_origin.as_str(),
                request.expires_at_ms,
                now_ms,
                authority,
            )?;
            self.sessions.admit_host_claim(admission, now_ms)
        })
    }
}

fn session_directory(directory: &File) -> Result<PathBuf> {
    use rustix::fs::{openat, Mode, OFlags};

    let file = File::from(
        openat(
            directory,
            "node.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?,
    );
    let metadata = file.metadata().map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() > 16_384
    {
        return Err(codes::AUMLOK_CLAIM_UNKNOWN);
    }
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
    if bytes.len() > 16_384 || bytes.len() as u64 != metadata.len() {
        return Err(codes::AUMLOK_CLAIM_UNKNOWN);
    }
    let config = json::parse_strict(&bytes).map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
    if config.canonical_bytes() != bytes
        || !matches!(config.get("v").map(|v| v.view()), Some(ValueView::Integer(v)) if v.get() == 1)
    {
        return Err(codes::AUMLOK_CLAIM_UNKNOWN);
    }
    if !matches!(
        config.get("kind").map(|v| v.view()),
        Some(ValueView::Text("aukora-node-config-v1"))
    ) {
        return Err(codes::AUMLOK_CLAIM_UNKNOWN);
    }
    let Some(ValueView::Text(root)) = config.get("state_root").map(|v| v.view()) else {
        return Err(codes::AUMLOK_CLAIM_UNKNOWN);
    };
    let path = PathBuf::from(root);
    if !path.is_absolute()
        || root.len() > 4096
        || root.as_bytes().contains(&0)
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(codes::AUMLOK_CLAIM_UNKNOWN);
    }
    Ok(path.join("browser-sessions"))
}
