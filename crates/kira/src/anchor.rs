// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-side Aura anchors. This module exposes no ledger append capability.

use canon::{authority::AuthorityTxn, digest::Digest32, ids::SubjectId, Refusal, Result};

/// The latest kira.save/demote/permission row in the complete verified Aura chain.
/// Sequence is its global Aura sequence; intervening non-Kira rows are verified too.
/// Empty memory history has no fabricated hash. This is not a second ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryHead {
    pub version: u16,
    pub sequence: u64,
    pub hash: Option<Digest32>,
}

impl MemoryHead {
    pub const EMPTY: Self = Self {
        version: 1,
        sequence: 0,
        hash: None,
    };

    pub fn validate(self) -> Result<Self> {
        if self.version != 1
            || self.sequence > canon::json::MAX_SAFE_INTEGER as u64
            || (self.sequence == 0) != self.hash.is_none()
        {
            return Err(Refusal {
                organ: "kira",
                reason: "head-invalid",
            });
        }
        Ok(self)
    }
}

/// Counts committed with the head, not inferred from a mutable index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCounts {
    pub saved: u64,
    pub demoted: u64,
    pub quarantined: u64,
}

impl MemoryCounts {
    pub fn validate(self) -> Result<Self> {
        if self.saved > canon::json::MAX_SAFE_INTEGER as u64
            || self.demoted > self.saved
            || self.quarantined > self.saved
        {
            return Err(Refusal {
                organ: "kira",
                reason: "counts-invalid",
            });
        }
        Ok(self)
    }
}

/// Non-authorizing data for a commitment in a C3 body; never extra C3 row keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorClaim {
    pub owner: SubjectId,
    pub head: MemoryHead,
    pub counts: MemoryCounts,
    pub aura_sequence: u64,
    pub aura_hash: Digest32,
}

/// Read verification stays in the Aura snapshot used by the memory operation.
/// Implementors verify the complete signed Aura chain against its retained head,
/// then compare Kira commitments, head and counts. Missing or partial coverage
/// refuses; a row or signature supplied by the caller alone is not verification.
pub trait AuraAnchors {
    fn verify<T: AuthorityTxn + ?Sized>(
        &self,
        transaction: &mut T,
        expected: &AnchorClaim,
    ) -> Result<()>;
}
