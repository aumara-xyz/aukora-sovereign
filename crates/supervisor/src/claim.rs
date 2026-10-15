// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read spawn's host commitment and connect it to durable browser admission.

use aumlok::claim::HostClaimCommitment;
use canon::{codes, Result};
use frontdoor::{
    claim::{ClaimRequest, ClaimService},
    session::{DurableSessions, SessionRecord},
};
use std::{
    fs::File,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct HostClaimService {
    commitment: HostClaimCommitment,
    sessions: DurableSessions,
}

impl HostClaimService {
    /// The supervisor supplies the node's configuration directory and session store.
    pub fn from_host(directory: &File, sessions: DurableSessions) -> Result<Self> {
        Ok(Self {
            commitment: HostClaimCommitment::from_host(directory)?,
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
