// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device-pairing contracts. Co-presence is evidence, separate from owner approval.

use crate::keys::{KeyBindingRequest, KeyId, KeyScope};
use canon::alg::{AlgorithmId, Signatures};
use canon::authority::{AuthorityRecord, AuthorityTxn, AuthorityVersion, VerifiedProof};
use canon::digest::Digest32;
use canon::ids::{NodeId, OperationId, SubjectId};
use canon::{Refusal, Result};

/// Version of this device-binding body; the containing C3 row remains unchanged.
pub const DEVICE_BINDING_VERSION: u16 = 1;
/// Domain of the new device-binding body, separate from every co-presence format.
pub const DEVICE_BINDING_DOMAIN: &str = "aukora:aumlok-device-binding:v1";

/// Old and new membership travel together in the owner-approved body.
/// Lists are exact sets, never a quorum score or evidence of authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSetChange {
    pub previous: Vec<KeyId>,
    pub next: Vec<KeyId>,
    pub expected: AuthorityVersion,
    pub next_epoch: u64,
}

/// Co-presence formats stay distinct; a v0 receipt is never upgraded by relabelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopresenceFormat {
    /// The pinned v0 core signs t_B only.
    PinnedV0,
    /// The separately versioned intent protocol from row 76.
    IntentV1,
}

/// Exact exchange method, fixed before the exchange; it supplies no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingMethod {
    /// Locally captured camera exchange; this label does not prove physical presence.
    Camera,
    /// Relayed camera exchange, explicitly retained as relayed.
    RelayedCamera,
    /// Remote comparison over an independent owner-selected channel.
    RemoteComparison,
}

/// Original receipt bytes plus context claims, all unverified data at this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopresenceEvidence {
    /// Exact format to route to its own receipt reader, never canon's C1 reader.
    pub format: CopresenceFormat,
    /// Receipt commitment algorithm; SHA-256 is the v1 binding commitment.
    pub algorithm: AlgorithmId,
    /// Original bytes, including any decimals in the co-presence format.
    pub receipt_bytes: Vec<u8>,
    /// Claimed exact receipt commitment, recomputed before use.
    pub receipt_sha256: Digest32,
    /// Method recorded before the exchange; no fallback is inferred.
    pub method: PairingMethod,
    /// Exact contribution from the already bound owner side.
    pub owner_contribution: Digest32,
    /// Exact contribution from the candidate device side.
    pub device_contribution: Digest32,
    /// Informational exchange timestamps, preserved individually.
    pub t_a_ms: u64,
    /// Other side's exchange timestamp.
    pub t_b_ms: u64,
    /// Exclusive expiry bound from the ceremony state.
    pub expires_at_ms: u64,
}

/// Unsigned candidate device body; possession signatures cannot enter this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevicePairingBody {
    /// Exactly DEVICE_BINDING_VERSION.
    pub v: u16,
    /// Commitment primitive for the body, SHA-256 for this version.
    pub algorithm: AlgorithmId,
    /// Owner identity; a copied value is never owner authority.
    pub subject: SubjectId,
    /// Node recording the device.
    pub node: NodeId,
    /// Requested owner epoch.
    pub epoch: u64,
    /// Joint old/new membership; wave 1 compares the old set to locked storage.
    pub membership: DeviceSetChange,
    /// Exact candidate key binding, including algorithm and role.
    pub device_key: KeyBindingRequest,
    /// Exact device scope, bound to both the receipt context and owner card.
    pub scope: KeyScope,
    /// Evidence in addition to, never instead of, the separate owner proof.
    pub copresence: CopresenceEvidence,
    /// Gate operation consumed by the owner's approval.
    pub operation_id: OperationId,
}

impl DevicePairingBody {
    /// Refuses until the codec lands. The frozen preimage is the ASCII bytes of
    /// DEVICE_BINDING_DOMAIN, one NUL, then C1 canonical bytes of exactly
    /// {v, algorithm, subject, node, epoch, device_key, scope, copresence, operation_id}.
    /// It contains every field of this body and no possession signature or wrapper.
    /// Receipt bytes are encoded as standard padded base64; their decimal-bearing
    /// content is never reparsed or canonicalized by the C1 body codec.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Err(Refusal {
            organ: "aumlok",
            reason: "devices-unimplemented",
        })
    }
}

/// Pairing body and its separate possession proof, displayed for owner approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevicePairingRequest {
    /// Complete body whose domain-separated bytes the device signs.
    pub body: DevicePairingBody,
    /// All required components over body.signing_bytes(), excluding this field.
    pub possession: Signatures,
}

/// Stored device state; epoch and sequence are ordering data, not a cached approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceBinding {
    /// Original versioned owner-approved body.
    pub request: DevicePairingRequest,
    /// Aura ordering and predecessor of the device binding.
    pub version: AuthorityVersion,
    /// Exact signed record hash.
    pub record_hash: Digest32,
}

/// Adapter implemented by the supervisor using the co-presence organ's own reader.
/// Its result is evidence only; add_device still requires a separate VerifiedProof.
pub trait CopresenceReader {
    /// Inspect the original receipt and requested context; invalid evidence refuses.
    fn inspect(&mut self, request: &DevicePairingRequest) -> Result<()>;
}

/// Refuses without mutation. Wave 1 must check co-presence and device possession,
/// then bind this exact body to the owner proof within AuthorityTxn; neither the
/// receipt nor the candidate device signature can create owner authority.
pub fn add_device<T: AuthorityTxn + ?Sized, C: CopresenceReader + ?Sized>(
    _txn: &mut T,
    _copresence: &mut C,
    _approval: VerifiedProof,
    _request: DevicePairingRequest,
) -> Result<AuthorityRecord> {
    Err(Refusal {
        organ: "aumlok",
        reason: "devices-unimplemented",
    })
}

/// Refuses without mutation. Device revocation requires a current exact-byte owner
/// proof and invalidates descendants when their next use reloads the lineage.
pub fn revoke_device<T: AuthorityTxn + ?Sized>(
    _txn: &mut T,
    _approval: VerifiedProof,
    _device: KeyId,
    _membership: DeviceSetChange,
) -> Result<AuthorityRecord> {
    Err(Refusal {
        organ: "aumlok",
        reason: "devices-unimplemented",
    })
}
