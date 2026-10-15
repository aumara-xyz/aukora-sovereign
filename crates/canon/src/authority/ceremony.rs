// SPDX-License-Identifier: AGPL-3.0-or-later
//! Standalone passkey ceremony inputs; these values are not owner proof capabilities.

use super::{AuthorityVersion, OwnerBinding};
use crate::{
    digest::Digest32,
    ids::{RequestId, SessionId, SubjectId},
};

/// The two standalone passkey finishes, separate from C5 owner operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyKind {
    /// First credential possession after registration.
    Enrolment,
    /// Possession of an already bound owner credential.
    SignIn,
}

/// Untrusted inputs to the authority adapter, not a verified counter-write token.
/// The adapter must reload the ceremony, candidate or binding, session and epoch
/// under its write lock and verify the original assertion against those values.
/// Enrolment requires bootstrap admission and the absence of an existing owner.
/// On success, the same transaction must persist the counter, consume the nonce,
/// install the credential or session and append the signed enrol/sign-in record.
/// Consumption advances registered (enrolment) or fresh (sign-in) through spent
/// to finished. Any failure must roll back every authority change; no fact row
/// or separately committed ceremony write can complete this interface.
pub struct CeremonyFinish<'a> {
    /// Identity of the active transaction that inspected the assertion.
    pub transaction_id: Digest32,
    /// Stored ceremony handle.
    pub id: RequestId,
    /// Expected operation; never inferred from browser input.
    pub kind: CeremonyKind,
    /// Session resolved by the trusted host.
    pub session: SessionId,
    /// Expected subject from locked ceremony state.
    pub subject: SubjectId,
    /// Epoch and retained Aura context at ceremony creation.
    pub authority: AuthorityVersion,
    /// Stored single-use ceremony nonce.
    pub nonce: [u8; 32],
    /// Stored expiry, checked against the transaction's trusted clock.
    pub expires_at_ms: i64,
    /// Registration candidate commitment; absent for sign-in.
    pub candidate_digest: Option<Digest32>,
    /// Expected binding after verification, including the presented counter.
    pub binding: &'a OwnerBinding,
    /// Expected owner metadata from trusted configuration.
    pub owner_id: &'a str,
    /// Expected user handle from stored credential metadata.
    pub user_handle: &'a [u8],
    /// Credential backup eligibility, independent of its counter.
    pub backup_eligible: bool,
    /// Pinned v1 assertion fields; clientDataJSON remains encoded original bytes.
    /// This JSON wrapper is data and must never be used as the signed message.
    pub assertion_json: &'a [u8],
    /// Observed time; the adapter also checks its own trusted clock.
    pub now_ms: i64,
}
