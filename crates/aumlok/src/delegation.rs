// SPDX-License-Identifier: AGPL-3.0-or-later
//! Delegation contracts; no accepted lineage or usable grant is constructed yet.

use crate::keys::{KeyId, KeyReadTxn, KeyScope, KeyUse};
use canon::alg::{AlgorithmId, Signatures};
use canon::authority::{AuthorityRecord, AuthorityTxn, AuthorityVersion, VerifiedProof};
use canon::digest::Digest32;
use canon::ids::OperationId;
use canon::{Refusal, Result};

/// Version of the delegation body, without changing the C3 outer field set.
pub const DELEGATION_VERSION: u16 = 1;
/// Domain of newly versioned delegation records.
pub const DELEGATION_DOMAIN: &str = "aukora:aumlok-delegation:v1";
/// Root, device, session and agent form exactly three signed edges.
pub const DELEGATION_EDGE_COUNT: usize = 3;

/// Closed lineage positions; a descendant cannot name a new root position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationLevel {
    /// Owner passkey authority at the start of the lineage.
    Root,
    /// Owner-approved device.
    Device,
    /// Session narrowed from the device.
    Session,
    /// Agent narrowed from the session.
    Agent,
}

/// Unverified signed edge; signatures are data until checked against stored bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationRecord {
    /// Exactly DELEGATION_VERSION.
    pub v: u16,
    /// Commitment primitive for this body, SHA-256 for this version.
    pub algorithm: AlgorithmId,
    /// SHA-256 of signing_bytes(); excluded from those bytes with the signatures.
    pub id: Digest32,
    /// Parent edge, absent only for the root-to-device edge.
    pub parent: Option<Digest32>,
    /// Key signing the edge; bound-key algorithm tags are retained in storage.
    pub issuer: KeyId,
    /// Exact delegated key, never inferred from a supplied display name.
    pub delegate: KeyId,
    /// Issuer's position in the lineage.
    pub from: DelegationLevel,
    /// Descendant position; validation requires the immediate next position.
    pub to: DelegationLevel,
    /// Requested attenuated scope, including its expiry.
    pub scope: KeyScope,
    /// Epoch and append-only record context.
    pub version: AuthorityVersion,
    /// All required components over signing_bytes(); hybrids require all components.
    pub signatures: Signatures,
}

impl DelegationRecord {
    /// Refuses until the codec lands. The frozen preimage is the ASCII bytes of
    /// DELEGATION_DOMAIN, one NUL, then C1 canonical bytes of exactly
    /// {v, algorithm, parent, issuer, delegate, from, to, scope, version}.
    /// Both id and signatures are excluded; algorithm uses its frozen wire name,
    /// key ids and parent digests use lowercase hex, and an absent parent is null.
    /// Levels are root, device, session and agent; version contains exactly epoch,
    /// sequence and previous_hash, with a null predecessor only at sequence one.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Err(Refusal {
            organ: "aumlok",
            reason: "delegation-unimplemented",
        })
    }

    /// Refuses until hashing lands. The commitment is SHA-256 of signing_bytes(),
    /// excluding the claimed id and signatures; validation must compare it with id.
    pub fn commitment(&self) -> Result<Digest32> {
        Err(Refusal {
            organ: "aumlok",
            reason: "delegation-unimplemented",
        })
    }
}

/// The exact root-to-device-to-session-to-agent lineage supplied for inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationLineage {
    /// Ordered root-to-device, device-to-session and session-to-agent edges.
    pub edges: [DelegationRecord; DELEGATION_EDGE_COUNT],
}

/// A single requested use; validating it cannot replace gate owner authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedUse {
    /// Exact agent key at the leaf of the lineage.
    pub leaf: KeyId,
    /// Closed use within the parent's scope.
    pub purpose: KeyUse,
    /// Exact resource identifier, with no prefix or wildcard implication.
    pub resource: String,
    /// Digest of the exact bytes for this one use.
    pub content_sha256: Digest32,
    /// Current supervisor clock for expiry checks, not ordering authority.
    pub now_ms: u64,
}

/// Current edge revocation read from authoritative storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationRevocation {
    /// Revoked edge identifier.
    pub delegation_id: Digest32,
    /// Epoch and append-only position of revocation.
    pub version: AuthorityVersion,
    /// Aura record containing the owner-approved revocation.
    pub record_hash: Digest32,
}

/// Locked reads for every lineage use; there is no cached-validity capability.
pub trait DelegationReadTxn: KeyReadTxn {
    /// Read exact stored edge bytes and their Aura anchor by id.
    fn delegation_record(&mut self, id: Digest32) -> Result<DelegationRecord>;
    /// Read current edge revocation; all ancestors must be re-read for each use.
    fn delegation_revocation(&mut self, id: Digest32) -> Result<Option<DelegationRevocation>>;
}

/// An observation, deliberately not VerifiedProof, Clone or a grant capability.
#[derive(Debug)]
pub struct LineageObservation {
    transaction_id: Digest32,
    content_sha256: Digest32,
}

impl LineageObservation {
    /// Identify the transaction in which the observation was made.
    pub const fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }

    /// Identify the one inspected message; this digest authorizes no effect.
    pub const fn content_sha256(&self) -> Digest32 {
        self.content_sha256
    }
}

/// Refuses every use. Wave 1 must reload every edge, key binding, epoch and
/// revocation under this transaction, verify every signature, require immediate
/// lineage order and scope attenuation, require empty owner_actions on every
/// delegated scope, and refuse reserved mesh uses.
pub fn inspect_use<T: DelegationReadTxn + ?Sized>(
    _txn: &mut T,
    _lineage: &DelegationLineage,
    _requested: &DelegatedUse,
) -> Result<LineageObservation> {
    Err(Refusal {
        organ: "aumlok",
        reason: "delegation-unimplemented",
    })
}

/// Refuses without mutation. Creating an Aura delegation requires the owner's
/// proof over these exact bytes; descendant signatures never substitute for it.
pub fn record_delegation<T: AuthorityTxn + ?Sized>(
    _txn: &mut T,
    _approval: VerifiedProof,
    _record: DelegationRecord,
    _operation_id: OperationId,
) -> Result<AuthorityRecord> {
    Err(Refusal {
        organ: "aumlok",
        reason: "delegation-unimplemented",
    })
}

/// Refuses without mutation. Revocation follows the same atomic owner-proof path.
pub fn revoke_delegation<T: AuthorityTxn + ?Sized>(
    _txn: &mut T,
    _approval: VerifiedProof,
    _delegation_id: Digest32,
    _expected_epoch: u64,
) -> Result<AuthorityRecord> {
    Err(Refusal {
        organ: "aumlok",
        reason: "delegation-unimplemented",
    })
}
