// SPDX-License-Identifier: AGPL-3.0-or-later
//! Device pairing with distinct receipt, possession and owner-approval checks.

use crate::keys::{self, KeyBindingRequest, KeyId, KeyRole, KeyScope, KeyUse};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::alg::{AlgorithmId, Signatures};
use canon::authority::{
    AuthorityAppendContext, AuthorityRecord, AuthorityTxn, AuthorityVersion, VerifiedProof,
};
use canon::digest::Digest32;
use canon::ids::{NodeId, OperationId, SubjectId};
use canon::json::{Value, ValueView};
use canon::{Refusal, Result};

/// Version of this device-binding body; the containing C3 row remains unchanged.
pub const DEVICE_BINDING_VERSION: u16 = 1;
/// Domain of the new device-binding body, separate from every co-presence format.
pub const DEVICE_BINDING_DOMAIN: &str = "aukora:aumlok-device-binding:v1";
/// Separate preimage for removing a device from the current membership.
pub const DEVICE_REVOCATION_DOMAIN: &str = "aukora:aumlok-device-revocation:v1";
/// Owner approval commits the receipt body and its separate possession proof.
pub const DEVICE_APPROVAL_DOMAIN: &str = "aukora:aumlok-device-approval:v1";
/// Bounded original receipt bytes, before padded-base64 expansion.
pub const MAX_DEVICE_RECEIPT_BYTES: usize = 65_536;
/// Bound on each exact membership set.
pub const MAX_PAIRED_DEVICES: usize = 128;

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
    /// New owner epoch, exactly membership.next_epoch.
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
    /// The preimage is the ASCII bytes of
    /// DEVICE_BINDING_DOMAIN, one NUL, then C1 canonical bytes of exactly
    /// {v, algorithm, subject, node, epoch, membership, device_key, scope, copresence, operation_id}.
    /// It contains every field of this body and no possession signature or wrapper.
    /// Receipt bytes are encoded as standard padded base64; their decimal-bearing
    /// content is never reparsed or canonicalized by the C1 body codec.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        validate_pairing(self)?;
        keys::domain_bytes(DEVICE_BINDING_DOMAIN, &pairing_value(self)?)
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

impl DevicePairingRequest {
    /// Bytes approved through C5, retaining every possession component for replay.
    pub fn approval_bytes(&self) -> Result<Vec<u8>> {
        validate_pairing(&self.body)?;
        keys::domain_bytes(DEVICE_APPROVAL_DOMAIN, &request_value(self)?)
    }
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

/// Check the locked joint membership, receipt and possession before consuming the
/// separate exact-byte owner proof. The Aura transaction owns the atomic append.
pub fn add_device<T: AuthorityTxn + ?Sized, C: CopresenceReader + ?Sized>(
    txn: &mut T,
    copresence: &mut C,
    approval: VerifiedProof,
    request: DevicePairingRequest,
) -> Result<AuthorityRecord> {
    validate_pairing(&request.body)?;
    let context = txn.authority_append_context(&approval)?;
    let body = &request.body;
    check_membership(txn, &context, &body.subject, &body.membership)?;
    if context.operation_id != body.operation_id
        || context.authority.epoch != body.membership.expected.epoch
        || approval.authorization().node != body.node
        || approval.authorization().subject != body.subject
    {
        return Err(refuse("device-context"));
    }
    let now = u64::try_from(context.at).map_err(|_| refuse("device-clock"))?;
    if now < body.scope.not_before_ms
        || now >= body.scope.expires_at_ms
        || now < body.copresence.t_b_ms
        || now >= body.copresence.expires_at_ms
    {
        return Err(refuse("device-expired"));
    }
    if txn
        .authority_state("aumlok.key-binding", &body.device_key.key_id.0.to_string())?
        .is_some()
        || txn
            .authority_state(
                "aumlok.key-revocation",
                &body.device_key.key_id.0.to_string(),
            )?
            .is_some()
    {
        return Err(refuse("device-already-bound"));
    }
    verify_pairing(txn, &request)?;
    copresence.inspect(&request)?;
    let target = device_target(&body.subject);
    let epoch = body.membership.next_epoch;
    keys::append_change(
        txn,
        approval,
        context,
        request_value(&request)?,
        DEVICE_APPROVAL_DOMAIN,
        &target,
        epoch,
    )
}

/// Remove exactly one current device under the same locked owner-proof append.
pub fn revoke_device<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    approval: VerifiedProof,
    device: KeyId,
    membership: DeviceSetChange,
) -> Result<AuthorityRecord> {
    validate_membership(&membership)?;
    check_delta(&membership, device, false)?;
    let context = txn.authority_append_context(&approval)?;
    let subject = approval.authorization().subject;
    let node = approval.authorization().node;
    check_membership(txn, &context, &subject, &membership)?;
    let bound = keys::load_binding(txn, device)?;
    if bound.request.role != KeyRole::Device
        || bound.request.scope.subject != subject
        || bound.request.scope.node != node
        || bound.request.epoch > context.authority.epoch
    {
        return Err(refuse("device-binding"));
    }
    if txn
        .authority_state("aumlok.key-revocation", &device.0.to_string())?
        .is_some()
    {
        return Err(refuse("device-revoked"));
    }
    let body = revocation_value(device, &membership, subject, node, context.operation_id)?;
    let epoch = membership.next_epoch;
    keys::append_change(
        txn,
        approval,
        context,
        body,
        DEVICE_REVOCATION_DOMAIN,
        &device_target(&subject),
        epoch,
    )
}

/// Exact bytes the owner must approve for removing one device.
pub fn revocation_bytes(
    device: KeyId,
    membership: &DeviceSetChange,
    subject: SubjectId,
    node: NodeId,
    operation_id: OperationId,
) -> Result<Vec<u8>> {
    validate_membership(membership)?;
    check_delta(membership, device, false)?;
    keys::domain_bytes(
        DEVICE_REVOCATION_DOMAIN,
        &revocation_value(device, membership, subject, node, operation_id)?,
    )
}

/// Exact C5 target identifier used for pairing and device membership changes.
pub fn device_target(subject: &SubjectId) -> String {
    format!("aumlok.devices:{subject}")
}

pub(crate) fn validate_pairing(body: &DevicePairingBody) -> Result<()> {
    if body.v != DEVICE_BINDING_VERSION || body.algorithm != AlgorithmId::Sha256 {
        return Err(refuse("device-format"));
    }
    keys::validate_request(&body.device_key)?;
    validate_membership(&body.membership)?;
    check_delta(&body.membership, body.device_key.key_id, true)?;
    if body.device_key.role != KeyRole::Device
        || body.device_key.scope != body.scope
        || body.scope.subject != body.subject
        || body.scope.node != body.node
        || body.device_key.epoch != body.epoch
        || body.device_key.operation_id != body.operation_id
        || body.membership.next_epoch != body.epoch
        || !body.scope.owner_actions.is_empty()
        || !body.scope.uses.contains(&KeyUse::DevicePossession)
    {
        return Err(refuse("device-context"));
    }
    let receipt = &body.copresence;
    if receipt.algorithm != AlgorithmId::Sha256
        || receipt.receipt_bytes.is_empty()
        || receipt.receipt_bytes.len() > MAX_DEVICE_RECEIPT_BYTES
        || keys::hash_bytes(&receipt.receipt_bytes) != receipt.receipt_sha256
    {
        return Err(refuse("device-receipt"));
    }
    let elapsed = receipt
        .t_b_ms
        .checked_sub(receipt.t_a_ms)
        .ok_or_else(|| refuse("device-receipt-time"))?;
    if elapsed > 10_000
        || receipt.t_b_ms >= receipt.expires_at_ms
        || receipt.expires_at_ms > canon::json::MAX_SAFE_INTEGER as u64
        || receipt.owner_contribution == receipt.device_contribution
        || receipt.owner_contribution.as_bytes() == &[0; 32]
        || receipt.device_contribution.as_bytes() == &[0; 32]
    {
        return Err(refuse("device-receipt-context"));
    }
    Ok(())
}

pub(crate) fn verify_pairing<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    request: &DevicePairingRequest,
) -> Result<()> {
    let signed = request.body.signing_bytes()?;
    keys::verify_material_signatures(
        txn,
        &request.body.device_key.material,
        &signed,
        &request.possession,
    )
}

fn validate_membership(change: &DeviceSetChange) -> Result<()> {
    validate_set(&change.previous)?;
    validate_set(&change.next)?;
    let expected = &change.expected;
    if expected.sequence == 0
        || expected.sequence > canon::json::MAX_SAFE_INTEGER as u64
        || (expected.sequence == 1) != expected.previous_hash.is_none()
        || expected.epoch.checked_add(1) != Some(change.next_epoch)
        || change.next_epoch > canon::json::MAX_SAFE_INTEGER as u64
    {
        return Err(refuse("device-membership-version"));
    }
    Ok(())
}

fn validate_set(members: &[KeyId]) -> Result<()> {
    if members.len() > MAX_PAIRED_DEVICES {
        return Err(refuse("device-membership-limit"));
    }
    let mut sorted = members.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(refuse("device-membership-duplicate"));
    }
    Ok(())
}

fn check_delta(change: &DeviceSetChange, device: KeyId, adding: bool) -> Result<()> {
    let mut expected = change.previous.clone();
    if adding {
        if expected.contains(&device) {
            return Err(refuse("device-already-member"));
        }
        expected.push(device);
    } else {
        let position = expected
            .iter()
            .position(|member| *member == device)
            .ok_or_else(|| refuse("device-not-member"))?;
        expected.remove(position);
    }
    expected.sort_unstable();
    let mut next = change.next.clone();
    next.sort_unstable();
    if next != expected {
        return Err(refuse("device-membership-change"));
    }
    Ok(())
}

fn check_membership<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    context: &AuthorityAppendContext,
    subject: &SubjectId,
    change: &DeviceSetChange,
) -> Result<()> {
    let stored = txn
        .authority_state("aumlok.devices", &subject.to_string())?
        .ok_or_else(|| refuse("device-membership-missing"))?;
    keys::exact_fields(&stored, &["members", "version"])?;
    let version = keys::parse_version(keys::field(&stored, "version")?)?;
    let members = keys::field(&stored, "members")?;
    let ValueView::Array(members) = members.view() else {
        return Err(refuse("device-membership-state"));
    };
    let mut members = members
        .iter()
        .map(keys::parse_key_id)
        .collect::<Result<Vec<_>>>()?;
    validate_set(&members)?;
    members.sort_unstable();
    let mut previous = change.previous.clone();
    previous.sort_unstable();
    if version != change.expected
        || members != previous
        || version.epoch != context.authority.epoch
        || version.sequence >= context.authority.sequence
    {
        return Err(refuse("device-membership-conflict"));
    }
    Ok(())
}

fn pairing_value(body: &DevicePairingBody) -> Result<Value> {
    keys::object([
        ("v", keys::number(u64::from(body.v))?),
        ("algorithm", keys::text(body.algorithm.wire_name())?),
        ("subject", keys::text(body.subject)?),
        ("node", keys::text(body.node)?),
        ("epoch", keys::number(body.epoch)?),
        ("membership", membership_value(&body.membership)?),
        ("device_key", keys::request_value(&body.device_key)?),
        ("scope", keys::scope_json(&body.scope)?),
        ("copresence", evidence_value(&body.copresence)?),
        ("operation_id", keys::text(body.operation_id)?),
    ])
}

fn membership_value(change: &DeviceSetChange) -> Result<Value> {
    let list = |members: &[KeyId]| {
        Value::checked_array(
            members
                .iter()
                .map(|key| keys::text(key.0))
                .collect::<Result<Vec<_>>>()?,
        )
    };
    keys::object([
        ("previous", list(&change.previous)?),
        ("next", list(&change.next)?),
        ("expected", keys::version_json(&change.expected)?),
        ("next_epoch", keys::number(change.next_epoch)?),
    ])
}

fn evidence_value(evidence: &CopresenceEvidence) -> Result<Value> {
    let format = match evidence.format {
        CopresenceFormat::PinnedV0 => "copresence.v0",
        CopresenceFormat::IntentV1 => "copresence.intent.v1",
    };
    let method = match evidence.method {
        PairingMethod::Camera => "camera",
        PairingMethod::RelayedCamera => "relayed-camera",
        PairingMethod::RemoteComparison => "remote-comparison",
    };
    keys::object([
        ("format", keys::text(format)?),
        ("algorithm", keys::text(evidence.algorithm.wire_name())?),
        (
            "receipt_bytes",
            keys::text(STANDARD.encode(&evidence.receipt_bytes))?,
        ),
        ("receipt_sha256", keys::text(evidence.receipt_sha256)?),
        ("method", keys::text(method)?),
        (
            "owner_contribution",
            keys::text(evidence.owner_contribution)?,
        ),
        (
            "device_contribution",
            keys::text(evidence.device_contribution)?,
        ),
        ("t_a_ms", keys::number(evidence.t_a_ms)?),
        ("t_b_ms", keys::number(evidence.t_b_ms)?),
        ("expires_at_ms", keys::number(evidence.expires_at_ms)?),
    ])
}

fn signatures_value(signatures: &Signatures) -> Result<Value> {
    if signatures.version() != 1
        || signatures.components().len() != 1
        || signatures.components().iter().any(|signature| {
            signature.v != 1
                || signature.algorithm != AlgorithmId::Ed25519
                || signature.bytes.len() != 64
        })
    {
        return Err(refuse("device-possession-format"));
    }
    let components = signatures
        .components()
        .iter()
        .map(|signature| {
            keys::object([
                ("v", keys::number(u64::from(signature.v))?),
                ("algorithm", keys::text(signature.algorithm.wire_name())?),
                ("bytes", keys::text(STANDARD.encode(&signature.bytes))?),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    keys::object([
        ("v", keys::number(u64::from(signatures.version()))?),
        ("components", Value::checked_array(components)?),
    ])
}

pub(crate) fn request_value(request: &DevicePairingRequest) -> Result<Value> {
    keys::object([
        ("v", keys::number(1)?),
        ("body", pairing_value(&request.body)?),
        ("possession", signatures_value(&request.possession)?),
    ])
}

fn revocation_value(
    device: KeyId,
    membership: &DeviceSetChange,
    subject: SubjectId,
    node: NodeId,
    operation: OperationId,
) -> Result<Value> {
    keys::object([
        ("v", keys::number(1)?),
        ("algorithm", keys::text(AlgorithmId::Sha256.wire_name())?),
        ("subject", keys::text(subject)?),
        ("node", keys::text(node)?),
        ("device", keys::text(device.0)?),
        ("membership", membership_value(membership)?),
        ("operation_id", keys::text(operation)?),
    ])
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}
