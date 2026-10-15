// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed standing-permission requests and transaction-bound verification.

use canon::{
    authority::{AuthorityTxn, OwnerAssertion, OwnerOperation, VerifiedProof, VerifiedStandingUse},
    digest::Digest32,
    ids::ProposalId,
};

use crate::Result;

/// Commitment to the exact stored owner-signed permission, never authority by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionFingerprint(Digest32);

impl PermissionFingerprint {
    /// Wrap the existing permission digest without hashing or verifying its source.
    pub const fn from_digest(digest: Digest32) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest32 {
        self.0
    }
}

/// Untrusted reference that must be resolved against locked permission storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandingPermissionRef {
    pub granting_proposal: ProposalId,
    pub fingerprint: PermissionFingerprint,
}

impl StandingPermissionRef {
    pub const fn new(granting_proposal: ProposalId, fingerprint: PermissionFingerprint) -> Self {
        Self {
            granting_proposal,
            fingerprint,
        }
    }
}

/// Check a routine Apply using the retained grant proof and exact fingerprint.
/// The transaction checks current owner, epoch, revocation, expiry, scope and cap.
/// No use is consumed, and no grant or widening is authorized by this check.
pub fn check_use<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    proposal: &ProposalId,
    permission: StandingPermissionRef,
) -> Result<VerifiedStandingUse> {
    VerifiedStandingUse::check(
        txn,
        &permission.granting_proposal,
        permission.fingerprint.digest(),
        proposal,
        OwnerOperation::Apply,
    )
}

/// Request idempotent revocation of the exact grant without a passkey assertion.
/// The transaction can only narrow authority; unavailable adapters refuse.
pub fn revoke<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    permission: StandingPermissionRef,
) -> Result<()> {
    txn.revoke_standing(
        &permission.granting_proposal,
        permission.fingerprint.digest(),
    )
}

/// A grant, renewal or widening request carries its own unverified owner assertion.
#[derive(Debug)]
pub struct StandingChange {
    pub proposal: ProposalId,
    pub assertion: OwnerAssertion,
}

/// Verify a fresh Permission assertion for gate/permission over exact C5 bytes.
/// Counter persistence, consumption and append remain in the same transaction.
pub fn verify_change<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    change: StandingChange,
) -> Result<VerifiedProof> {
    let authorization = txn.rebuild_authorization(&change.proposal, OwnerOperation::Permission)?;
    if authorization.proposal != change.proposal
        || authorization.op != OwnerOperation::Permission
        || authorization.target != "gate/permission"
    {
        return Err(crate::refuse("standing-action"));
    }
    aumlok::webauthn::verify_owner_assertion(
        txn,
        &change.proposal,
        OwnerOperation::Permission,
        change.assertion,
    )
}
