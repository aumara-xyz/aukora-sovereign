// SPDX-License-Identifier: AGPL-3.0-or-later
//! Transaction-bound use of a previously owner-signed routine permission.

use super::{AuthorityTxn, CardRisk, OwnerOperation};
use crate::{
    codes,
    digest::Digest32,
    ids::{OperationDigest, ProposalId},
    Result,
};

/// Locked standing-use metadata; constructing this data grants no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandingUseContext {
    /// Current binding epoch, equal to the owner-signed permission's epoch.
    pub epoch: u64,
    /// Operation-content digest rebuilt from the locked proposal's exact bytes.
    pub operation: OperationDigest,
    /// Locked consumed count plus one, within the signed cap.
    pub use_number: u64,
    /// Risk from the locked gate proposal; only `Routine` permits standing use.
    pub risk: CardRisk,
}

/// One non-Clone use capability, tied to one active authority transaction.
/// The transaction checks the retained grant-time proof; this holds no fresh proof.
#[derive(Debug)]
pub struct VerifiedStandingUse {
    permission_id: ProposalId,
    permission_digest: Digest32,
    proposal: ProposalId,
    context: StandingUseContext,
    transaction_id: Digest32,
}

impl VerifiedStandingUse {
    /// Check a routine `Apply` against the permission in locked storage.
    /// Storage checks the grant proof, epoch, revocation, expiry, scope and cap.
    /// This neither consumes a use nor persists a passkey counter.
    pub fn check<T: AuthorityTxn + ?Sized>(
        txn: &mut T,
        permission_id: &ProposalId,
        permission_digest: Digest32,
        proposal: &ProposalId,
        action: OwnerOperation,
    ) -> Result<Self> {
        if action != OwnerOperation::Apply {
            return Err(codes::GATE_STANDING_ACTION);
        }
        let transaction_id = txn.transaction_id();
        let context = txn.check_standing_use(permission_id, permission_digest, proposal, action)?;
        if txn.transaction_id() != transaction_id {
            return Err(codes::AURA_TRANSACTION);
        }
        if context.risk != CardRisk::Routine {
            return Err(codes::GATE_STANDING_CRITICAL);
        }
        if context.use_number == 0 {
            return Err(codes::GATE_CONSUMPTION_CONFLICT);
        }
        Ok(Self {
            permission_id: *permission_id,
            permission_digest,
            proposal: *proposal,
            context,
            transaction_id,
        })
    }

    /// Compatibility name for `check`; this performs no fresh signature verification.
    pub fn verify<T: AuthorityTxn + ?Sized>(
        txn: &mut T,
        permission_id: &ProposalId,
        permission_digest: Digest32,
        proposal: &ProposalId,
        action: OwnerOperation,
    ) -> Result<Self> {
        Self::check(txn, permission_id, permission_digest, proposal, action)
    }

    /// The proposal that granted the permission, distinct from the proposed use.
    pub const fn permission_id(&self) -> &ProposalId {
        &self.permission_id
    }

    /// Commitment to the exact stored owner-signed permission bytes.
    pub const fn permission_digest(&self) -> Digest32 {
        self.permission_digest
    }

    /// Locked proposal checked against the signed scope.
    pub const fn proposal(&self) -> &ProposalId {
        &self.proposal
    }

    /// Standing use carries only `Apply`; other owner actions require fresh proofs.
    pub const fn action(&self) -> OwnerOperation {
        OwnerOperation::Apply
    }

    /// Checked metadata, never a standalone capability.
    pub const fn context(&self) -> &StandingUseContext {
        &self.context
    }

    /// The single active transaction allowed to consume and append this use.
    pub const fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }
}
