// SPDX-License-Identifier: AGPL-3.0-or-later
//! Proposed bytes and stored lifecycle snapshots are data, never effect permits.

use crate::{target::TargetId, RiskTier};
use canon::{
    authority::{AuthorityVersion, BaseDigest, CellCommitment},
    digest::Digest32,
    ids::{OperationDigest, OperationId, ProposalId},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalRequest {
    pub target: TargetId,
    pub base: BaseDigest,
    pub new_bytes: Vec<u8>,
    pub model_note: String,
    pub cell: Option<CellCommitment>,
    pub new_evidence: Option<EvidenceReference>,
    pub suggestion: SuggestionOrder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalState {
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

impl ProposalState {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Consumed)
    }

    pub const fn reserves_target(self) -> bool {
        matches!(self, Self::Pending | Self::Consumed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub id: ProposalId,
    pub operation_id: OperationId,
    pub operation_digest: OperationDigest,
    pub authority: AuthorityVersion,
    pub request: ProposalRequest,
    pub new_digest: Digest32,
    pub risk: RiskTier,
    pub state: ProposalState,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclinedProposal {
    pub proposal: ProposalId,
    pub operation: OperationDigest,
    pub target: TargetId,
    pub evidence: Option<Digest32>,
    pub terminal: AuthorityVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceChange {
    pub previous: Option<Digest32>,
    pub current: Digest32,
    pub source_record: AuthorityVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceReference {
    pub digest: Digest32,
    pub source_record: AuthorityVersion,
}

pub fn validate_new_evidence(
    _transaction: &mut aura::LedgerTxn<'_>,
    _declined: &DeclinedProposal,
    _change: &EvidenceChange,
) -> crate::Result<()> {
    crate::unavailable()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuggestionOrder {
    Single,
    Batch,
    RuleAfterReviewedBatch { batch: OperationId },
}
