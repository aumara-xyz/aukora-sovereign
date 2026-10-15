// SPDX-License-Identifier: AGPL-3.0-or-later
//! Approval notifications have no dependency on the guest process or its readiness.

use crate::session::BoundSession;
use canon::{ids::ProposalId, session::Items, Result};

pub const MAX_PENDING: usize = 100;
pub const POLL_INTERVAL_MS: u64 = 1_000;

#[derive(Clone, Debug)]
pub struct PendingApproval {
    pub proposal: ProposalId,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug)]
pub struct PendingPage {
    pub sequence: u64,
    pub proposals: Items<PendingApproval, MAX_PENDING>,
    pub next: Option<ProposalId>,
}

/// Gate-backed reads continue while Auma is stopped. A notification cannot apply a proposal.
pub trait ApprovalService {
    fn pending(
        &mut self,
        session: &BoundSession<'_>,
        after: Option<ProposalId>,
    ) -> Result<PendingPage>;
}

#[derive(Clone, Copy, Debug)]
pub struct ApprovalFacts {
    pub last_poll_at_ms: Option<u64>,
    pub last_gate_sequence: Option<u64>,
    pub pending_count: u64,
    pub poll_failures: u64,
}
