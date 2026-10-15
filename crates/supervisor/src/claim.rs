// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read spawn's host commitment and connect it to durable browser admission.

use aumlok::claim::HostClaimCommitment;
use canon::{codes, digest::Digest32, Result};
use frontdoor::{
    claim::{ClaimRequest, ClaimService},
    session::{DurableSessions, SessionRecord},
};
use rustix::fs::{openat, Mode, OFlags};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct HostClaimService {
    commitment: HostClaimCommitment,
    sessions: DurableSessions,
}

impl HostClaimService {
    /// The supervisor supplies the node's configuration directory and session store.
    pub fn from_host(directory: &File, sessions: DurableSessions) -> Result<Self> {
        let meta = directory
            .metadata()
            .map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(codes::AUMLOK_CLAIM_UNKNOWN);
        }
        let file: File = openat(
            directory,
            "claim.sha256",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?
        .into();
        let meta = file.metadata().map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
        if !meta.is_file()
            || meta.uid() != 0
            || meta.mode() & 0o7777 != 0o440
            || meta.nlink() != 1
            || meta.len() != 65
        {
            return Err(codes::AUMLOK_CLAIM_UNKNOWN);
        }
        let mut bytes = Vec::new();
        file.take(66)
            .read_to_end(&mut bytes)
            .map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
        if bytes.len() != 65 || bytes[64] != b'\n' {
            return Err(codes::AUMLOK_CLAIM_UNKNOWN);
        }
        let text = std::str::from_utf8(&bytes[..64]).map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
        let digest = Digest32::from_hex(text).map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
        Ok(Self {
            commitment: HostClaimCommitment::from_host_digest(digest),
            sessions,
        })
    }

    pub fn sessions_mut(&mut self) -> &mut DurableSessions {
        &mut self.sessions
    }
}

impl ClaimService for HostClaimService {
    fn consume_and_create_session(&mut self, request: ClaimRequest) -> Result<SessionRecord> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?
            .as_millis();
        let now_ms = u64::try_from(now_ms).map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?;
        self.sessions
            .consume_host_claim(request, &self.commitment, now_ms)
    }
}
