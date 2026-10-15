// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared storage data for gate callers; constructing a value grants no authority.

use canon::{
    authority::{AuthorityVersion, BaseDigest, Card, CardRisk, CellCommitment, OwnerAuthorization},
    digest::Digest32,
    ids::{OperationDigest, OperationId, ProposalId},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Consumed,
    Applied,
    Refused,
    Expired,
    Retired,
    Incomplete,
    Failed,
    Conflict,
    Unknown,
}

impl ProposalStatus {
    /// Consumed is recoverable work; every other completed outcome releases a target.
    pub const fn holds_reservation(self) -> bool {
        matches!(self, Self::Pending | Self::Consumed)
    }
}

/// Exact immutable proposal input. State changes are only transaction methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalState {
    pub proposal: ProposalId,
    pub operation: OperationId,
    pub operation_digest: OperationDigest,
    pub authority: AuthorityVersion,
    pub target: String,
    pub base_sha256: BaseDigest,
    pub new_bytes: Vec<u8>,
    pub cell: Option<CellCommitment>,
    pub risk: CardRisk,
    pub evidence_digest: Digest32,
    pub evidence_source: Option<AuthorityVersion>,
    pub prior_reviewed_batch: Option<OperationId>,
    pub actor: String,
    pub model_note: String,
    pub status: ProposalStatus,
}

/// The gate-rendered card and rebuilt C5 authorization are stored together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedAuthorization {
    pub authorization: OwnerAuthorization,
    pub card: Card,
}

/// Declines survive retirement; only different evidence permits reconsideration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclinedProposal {
    pub proposal: ProposalId,
    pub operation_digest: OperationDigest,
    pub evidence_digest: Digest32,
    pub target: String,
    pub authority: AuthorityVersion,
}

/// Recovery resolves the consumed authorization from locked storage before appending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryWork {
    pub proposal: ProposalId,
    pub operation: OperationId,
    pub target: String,
    pub consumed_approval: Digest32,
    pub consumed_at: AuthorityVersion,
    pub base_sha256: BaseDigest,
    pub new_sha256: Digest32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationCoverage {
    pub intents: u64,
    pub settlements: u64,
    pub terminals: u64,
}
