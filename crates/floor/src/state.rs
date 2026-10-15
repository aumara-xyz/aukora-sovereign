// SPDX-License-Identifier: AGPL-3.0-or-later
//! Anti-replay metadata is separate from the frozen floor object.

use crate::{refuse, Floor, Result};
use canon::{
    alg::AlgorithmId,
    authority::AuthorityVersion,
    digest::Digest32,
    ids::{CredentialId, OperationId, ProposalId},
};

pub const STATE_SCHEMA: &str = "aukora-floor-state-v2";
pub const STATE_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialHighWater {
    pub credential: CredentialId,
    pub algorithm: AlgorithmId,
    pub key_sha256: Digest32,
    pub epoch: u64,
    pub counter: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentApproval {
    pub algorithm: AlgorithmId,
    pub authority: AuthorityVersion,
    pub operation: OperationId,
    pub proposal: ProposalId,
    pub authorization_sha256: Digest32,
}

/// A snapshot cannot be used to unspend an approval or advance protected storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HighWater {
    pub highest_epoch: u64,
    pub highest_sequence: u64,
    pub head: Digest32,
    pub credentials: Vec<CredentialHighWater>,
    /// Full retained spent identities; unlike display history, these are never pruned.
    pub spent: Vec<SpentApproval>,
}

impl HighWater {
    /// Row 65/110: check epoch/sequence/predecessor, credential uniqueness, counters and
    /// every spent identity. Refuse snapshot rollback or unspending, including after crash.
    pub fn validate_successor(&self, _next: &Self) -> Result<()> {
        Err(refuse("high-water-unwritten"))
    }
}

/// New outer wrapper; its `floor` member remains the seven-key pinned object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedState {
    pub schema: String,
    pub algorithm: AlgorithmId,
    pub authority: AuthorityVersion,
    pub floor: Floor,
    pub high_water: HighWater,
}

impl ProtectedState {
    /// Row 65/110 protected-state codec. Old records never acquire new authority.
    pub fn parse(_bytes: &[u8]) -> Result<Self> {
        Err(refuse("state-codec-unwritten"))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Err(refuse("state-codec-unwritten"))
    }
}

/// Reserved row 111 interface. No implementation or clone-resistance claim is shipped.
pub trait CloneGuard {
    type Challenge;
    type Proof;
    fn challenge(&mut self, authority: AuthorityVersion) -> Result<Self::Challenge>;
    fn verify(&mut self, challenge: &Self::Challenge, proof: &Self::Proof) -> Result<()>;
}
