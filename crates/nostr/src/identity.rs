// SPDX-License-Identifier: AGPL-3.0-or-later
//! Delegated node and agent identities anchored in the closed nostr.bind kind.

use crate::{PublicKey, Refusal, Result, SecretKey, VerifiedEvent};
use canon::{
    authority::{AuthorityRecord, AuthorityTxn, AuthorityVersion, VerifiedProof},
    digest::Digest32,
    ids::{NodeId, SubjectId},
};

pub const BINDING_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityRole {
    Node,
    Agent,
}

/// Metadata inside the Aura body, never additional C3 row fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingRequest {
    pub v: u16,
    pub node: NodeId,
    pub owner: SubjectId,
    pub authority: AuthorityVersion,
    pub node_key: PublicKey,
    pub agent_key: PublicKey,
    pub delegation_commitment: Digest32,
}

/// Private construction distinguishes a checked binding from caller-made data.
/// The retained receipt is evidence; each signing use rechecks current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundIdentities {
    binding: BindingRequest,
    receipt: AuthorityRecord,
}

impl BoundIdentities {
    pub const fn binding(&self) -> &BindingRequest {
        &self.binding
    }

    pub const fn receipt(&self) -> &AuthorityRecord {
        &self.receipt
    }
}

/// Wave 1 compares both keys to the current owner-approved AUMLOK delegation,
/// checks distinct roles/keys and rollback guards, and uses the same AuthorityTxn
/// to persist the passkey counter, consume the exact proof and append nostr.bind.
/// The proof's transaction, authorization bytes, target and epoch must match.
/// This function never commits the surrounding transaction.
pub fn bind<T: IdentityTxn + ?Sized>(
    _txn: &mut T,
    _proof: VerifiedProof,
    _request: BindingRequest,
) -> Result<BoundIdentities> {
    Err(Refusal {
        organ: "nostr",
        reason: "unimplemented-binding",
    })
}

/// The host supplies AUMLOK's delegation view under the same authority lock.
/// A commitment or request supplied by the caller is not a delegation lookup.
pub trait IdentityTxn: AuthorityTxn {
    /// Compare node, subject, both role keys, epoch and delegation commitment to
    /// current owner-approved state; refuse revoked, stale or scope-mismatched
    /// bindings. No independent read snapshot may authorize the later append.
    fn check_delegation_request(&mut self, request: &BindingRequest) -> Result<()>;
}

/// Trusted supervisor/AUMLOK lookup, not a value supplied by an incoming event.
pub trait DelegationState {
    /// Wave 1 implementations check the live epoch, revocation and exact scope.
    fn check_current(
        &mut self,
        binding: &BoundIdentities,
        role: IdentityRole,
        kind: u16,
    ) -> Result<()>;
}

/// Wave 1 checks current delegation, role/key equality and permitted event scope
/// before signing. The agent role identifies data; Auma never receives this key.
pub fn sign_delegated<D: DelegationState + ?Sized>(
    _delegations: &mut D,
    _binding: &BoundIdentities,
    _role: IdentityRole,
    _secret: &SecretKey,
    _event: EventDraft,
) -> Result<VerifiedEvent> {
    Err(Refusal {
        organ: "nostr",
        reason: "unimplemented-binding",
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDraft {
    pub created_at_seconds: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}
