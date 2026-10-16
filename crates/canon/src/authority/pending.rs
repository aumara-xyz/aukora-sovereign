// SPDX-License-Identifier: AGPL-3.0-or-later
//! Subject-less enrolment and the atomic transition to a bound owner.

use super::{AuthorityVersion, OwnerBinding};
use crate::{
    alg::PublicKey,
    digest::Digest32,
    ids::{RequestId, SessionId, SubjectId},
    json::Value,
};

/// Data read from a verified enrolment anchor; it is not an authorization capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOwnerCredential {
    /// Passkey verification data; epoch zero before binding.
    pub binding: OwnerBinding,
    /// Owner account label from trusted node configuration.
    pub owner_id: String,
    /// Opaque WebAuthn handle retained from registration.
    pub user_handle: Vec<u8>,
    /// Authenticator backup eligibility fixed by registration.
    pub backup_eligible: bool,
    /// Signed subject-less enrolment coordinates.
    pub enrolment: AuthorityVersion,
    /// Hash of the signed subject-less enrolment record.
    pub enrolment_hash: Digest32,
    /// Session bound to the stored ceremony.
    pub session: SessionId,
}

/// Original possession bytes; the authority transaction reloads their ceremony.
pub struct PendingEnrolmentFinish<'a> {
    /// Identity of the active Aura authority transaction.
    pub transaction_id: Digest32,
    /// Durable single-use ceremony identifier.
    pub id: RequestId,
    /// Session bound to the stored ceremony.
    pub session: SessionId,
    /// Original pinned assertion fields, including encoded clientDataJSON.
    pub assertion_json: &'a [u8],
    /// Observed supervisor time, rechecked against the transaction clock.
    pub now_ms: i64,
}

/// Public identity and ciphertext, committed by the pending credential's assertion.
pub struct BindingFinish<'a> {
    /// Identity of the active Aura authority transaction.
    pub transaction_id: Digest32,
    /// Durable single-use ceremony identifier.
    pub id: RequestId,
    /// Session bound to the stored ceremony.
    pub session: SessionId,
    /// Subject derived from the random identity root.
    pub subject: SubjectId,
    /// Public identity key derived from the random root.
    pub identity_public_key: &'a PublicKey,
    /// Unchanged envelope-v1 ciphertext and KDF metadata.
    pub envelope: &'a Value,
    /// Original pinned assertion fields, including encoded clientDataJSON.
    pub assertion_json: &'a [u8],
    /// Observed supervisor time, rechecked against the transaction clock.
    pub now_ms: i64,
}

/// Original assertion for a stored sign-in or envelope-refresh ceremony.
pub struct BoundCeremonyFinish<'a> {
    /// Identity of the active Aura authority transaction.
    pub transaction_id: Digest32,
    /// Durable single-use ceremony identifier.
    pub id: RequestId,
    /// Session bound to the stored ceremony.
    pub session: SessionId,
    /// Original pinned assertion fields, including encoded clientDataJSON.
    pub assertion_json: &'a [u8],
    /// Observed supervisor time, rechecked against the transaction clock.
    pub now_ms: i64,
}

/// Current bound identity reconstructed from signed authority records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundOwnerIdentity {
    /// Subject derived from the random identity root.
    pub subject: SubjectId,
    /// Public identity key derived from the random root.
    pub identity_public_key: PublicKey,
    /// Unchanged envelope-v1 ciphertext and KDF metadata.
    pub envelope: Value,
    /// Monotone encrypted-envelope revision.
    pub revision: u64,
    /// Verified passkey and original enrolment anchor.
    pub credential: PendingOwnerCredential,
}
