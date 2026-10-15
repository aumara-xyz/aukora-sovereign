// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scoped key bindings and exact-byte owner transitions in a single transaction.

use base64::{engine::general_purpose::STANDARD, Engine};
use canon::alg::{AlgorithmId, PublicKey, Signature, Signatures};
use canon::authority::{AuthorityAppendContext, BaseDigest, Kind, PendingAuthorityRecord, Phase};
use canon::authority::{
    AuthorityRecord, AuthorityTxn, AuthorityVersion, OwnerOperation, VerifiedProof,
};
use canon::digest::Digest32;
use canon::ids::{NodeId, OperationId, SubjectId};
use canon::json::{SafeInteger, Value, ValueView, MAX_SAFE_INTEGER};
use canon::{Refusal, Result};
use sha2::{Digest, Sha256};

/// Version of the key-binding body; C3's outer field set is unchanged.
pub const KEY_BINDING_VERSION: u16 = 1;
/// Domain for canonical key-binding bodies, distinct from identity-root derivation.
pub const KEY_BINDING_DOMAIN: &str = "aukora:aumlok-key-binding:v1";
/// Maximum number of explicitly named uses in one key scope.
pub const MAX_KEY_USES: usize = 16;
/// Maximum number of exact resource identifiers in one key scope.
pub const MAX_SCOPE_RESOURCES: usize = 32;

/// Claimed key identifier; retaining a digest proves neither possession nor binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct KeyId(pub Digest32);

/// Closed key-role vocabulary; roles are data, never an approval capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum KeyRole {
    /// The approving credential; uses bound delegation, owner actions are descriptive.
    OwnerPasskey,
    /// Identity-root commitment or public identity key; never an owner proof.
    IdentityRoot,
    /// Scoped identity, session and agent statements.
    Operational,
    /// A paired device with its own bounded possession and identity scope.
    Device,
    /// Session authentication and identity within a device delegation.
    Session,
    /// Agent identity within a session delegation; no owner actions.
    Agent,
    /// Node identity statements.
    Node,
    /// Node Nostr events using its separate Schnorr key.
    NodeNostr,
    /// Agent Nostr events using its separate Schnorr key.
    AgentNostr,
    /// Shard receipts only; never owner replacement.
    GuardianShardHolder,
    /// Recovery statements only; never owner replacement.
    GuardianRecovery,
    /// Veto acknowledgements only; never owner replacement.
    GuardianVeto,
    /// Sealed backup encryption commitment; no signing authority.
    BackupEncryption,
    /// Aura record signatures; never owner approval.
    AuraSigning,
    /// Reserved mesh signing role; every use refuses until mesh activation.
    DeviceMeshIdentity,
    /// Reserved mesh agreement role; every use refuses until mesh activation.
    DeviceMeshAgreement,
}

/// Closed non-owner uses; none represents approval, release, or credential mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum KeyUse {
    /// An identity statement, not owner authorization.
    IdentityStatement,
    /// An Aura record signature, not an approval.
    AuraRecord,
    /// An event under the node's Nostr identity.
    NodeNostrEvent,
    /// An event under the agent's Nostr identity.
    AgentNostrEvent,
    /// Possession evidence in addition to separate owner approval.
    DevicePossession,
    /// Authentication within the session's exact scope.
    SessionAuthentication,
    /// A delegated agent identity statement.
    AgentIdentity,
    /// Backup encryption only, without owner actions.
    BackupEncrypt,
    /// Backup decryption only, without owner actions.
    BackupDecrypt,
    /// A shard receipt, never owner replacement.
    GuardianShardReceipt,
    /// A recovery statement, never owner replacement.
    GuardianRecoveryStatement,
    /// A veto acknowledgement, never owner replacement.
    GuardianVetoAcknowledgement,
    /// Reserved mesh signing use; currently refused.
    MeshIdentity,
    /// Reserved mesh agreement use; currently refused.
    MeshAgreement,
}

/// Exact subject, node, resources and uses requested for a binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyScope {
    /// Identity whose resources the key names.
    pub subject: SubjectId,
    /// Node on which the binding applies.
    pub node: NodeId,
    /// Closed uses; for owner bindings these also bound root delegation scope.
    pub uses: Vec<KeyUse>,
    /// Descriptive owner operations, never approval capabilities. Only OwnerPasskey
    /// bindings may carry entries; every delegated scope must carry an empty list.
    pub owner_actions: Vec<OwnerOperation>,
    /// Exact resource names; an empty list denotes no resources, never a wildcard.
    pub resources: Vec<String>,
    /// Inclusive lower time bound in supervisor milliseconds.
    pub not_before_ms: u64,
    /// Exclusive upper time bound; ordering remains epoch and Aura sequence.
    pub expires_at_ms: u64,
}

/// Public key material or a commitment; secret bytes do not enter this contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyMaterial {
    /// Public verification or agreement key with its own algorithm tag.
    Public(PublicKey),
    /// SHA-256 commitment to a sealed secret; it is not a public verification key.
    SealedCommitment(Digest32),
}

/// Proposed binding data, retained inside a versioned Aura body after approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyBindingRequest {
    /// Exactly KEY_BINDING_VERSION.
    pub v: u16,
    /// Key primitive; each public key component repeats its exact algorithm.
    pub algorithm: AlgorithmId,
    /// Binding identifier named in approved bytes.
    pub key_id: KeyId,
    /// Role whose scope must be checked independently.
    pub role: KeyRole,
    /// Non-secret representation of key material.
    pub material: KeyMaterial,
    /// Exact scope displayed for owner approval.
    pub scope: KeyScope,
    /// Current owner epoch expected by the caller.
    pub epoch: u64,
    /// Owning operation whose exact bytes bind this request.
    pub operation_id: OperationId,
}

/// Stored binding data; reading it alone supplies no authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyBinding {
    /// Original approved request, including algorithm, epoch and scope.
    pub request: KeyBindingRequest,
    /// Aura ordering and predecessor at the binding's append.
    pub version: AuthorityVersion,
    /// Exact signed Aura record hash anchoring the binding.
    pub record_hash: Digest32,
}

/// Current revocation state read under the same authority transaction as a use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRevocation {
    /// Key named by the revocation record.
    pub key_id: KeyId,
    /// Epoch and sequence at which revocation took effect.
    pub version: AuthorityVersion,
    /// Signed Aura record hash; absence must come from storage, never a caller boolean.
    pub record_hash: Digest32,
}

/// Read interface implemented by the Aura transaction owner, not by guest input.
pub trait KeyReadTxn: AuthorityTxn {
    /// Supervisor clock captured under the same lock as these reads.
    fn key_time_ms(&mut self) -> Result<u64> {
        Err(refuse("key-clock-unavailable"))
    }
    /// Read the active owner epoch and rollback guard from locked state.
    fn key_epoch(&mut self) -> Result<AuthorityVersion>;
    /// Read an Aura-anchored binding by exact id under this transaction.
    fn key_binding(&mut self, key: KeyId) -> Result<KeyBinding>;
    /// Read the latest revocation under this transaction on every use.
    fn key_revocation(&mut self, key: KeyId) -> Result<Option<KeyRevocation>>;
}

/// Bind exact public material and scope through the transaction's owner approval.
pub fn bind_key<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    approval: VerifiedProof,
    request: KeyBindingRequest,
) -> Result<AuthorityRecord> {
    validate_request(&request)?;
    let context = txn.authority_append_context(&approval)?;
    if request.epoch != context.authority.epoch || request.operation_id != context.operation_id {
        return Err(refuse("key-context"));
    }
    if txn
        .authority_state("aumlok.key-revocation", &request.key_id.0.to_string())?
        .is_some()
    {
        return Err(refuse("key-revoked"));
    }
    let existing = txn.authority_state("aumlok.key-binding", &request.key_id.0.to_string())?;
    if existing.is_some() {
        let previous = load_binding(txn, request.key_id)?;
        if previous.version.sequence >= context.authority.sequence
            || previous.request.epoch >= request.epoch
            || previous.request.role != request.role
            || previous.request.material != request.material
            || previous.request.scope.subject != request.scope.subject
            || previous.request.scope.node != request.scope.node
        {
            return Err(refuse("key-exists"));
        }
    }
    if request.role == KeyRole::Device {
        if existing.is_none() {
            return Err(refuse("device-pairing-required"));
        }
        let membership = txn
            .authority_state("aumlok.devices", &request.scope.subject.to_string())?
            .ok_or(refuse("device-membership-missing"))?;
        exact_fields(&membership, &["members", "version"])?;
        let version = parse_version(field(&membership, "version")?)?;
        let members = array(field(&membership, "members")?)?
            .iter()
            .map(parse_key_id)
            .collect::<Result<Vec<_>>>()?;
        if version.epoch != request.epoch
            || version.sequence >= context.authority.sequence
            || !members.contains(&request.key_id)
            || !unique(&members)
        {
            return Err(refuse("device-not-member"));
        }
    }
    let now = checked_time(context.at)?;
    if now < request.scope.not_before_ms || now >= request.scope.expires_at_ms {
        return Err(refuse("key-expired"));
    }
    if request.scope.subject != approval.authorization().subject
        || request.scope.node != approval.authorization().node
    {
        return Err(refuse("key-owner-context"));
    }
    if request.role == KeyRole::OwnerPasskey
        && request.material != KeyMaterial::Public(approval.public_key().clone())
    {
        return Err(refuse("owner-key-mismatch"));
    }
    let body = request_value(&request)?;
    let target = format!("aumlok:key:{}", request.key_id.0);
    append_change(
        txn,
        approval,
        context,
        body,
        KEY_BINDING_DOMAIN,
        &target,
        request.epoch,
    )
}

/// Revoke an existing binding under a fresh exact-byte owner approval.
pub fn revoke_key<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    approval: VerifiedProof,
    key: KeyId,
    expected_epoch: u64,
) -> Result<AuthorityRecord> {
    let context = txn.authority_append_context(&approval)?;
    if context.authority.epoch != expected_epoch {
        return Err(refuse("key-epoch"));
    }
    let binding = load_binding(txn, key)?;
    if binding.version.sequence >= context.authority.sequence
        || binding.request.epoch > expected_epoch
        || txn
            .authority_state("aumlok.key-revocation", &key.0.to_string())?
            .is_some()
    {
        return Err(refuse("key-revoked-or-future"));
    }
    if matches!(
        binding.request.role,
        KeyRole::OwnerPasskey | KeyRole::Device
    ) {
        return Err(refuse("membership-transition-required"));
    }
    if binding.request.scope.subject != approval.authorization().subject
        || binding.request.scope.node != approval.authorization().node
    {
        return Err(refuse("key-owner-context"));
    }
    let body = object([
        ("v", number(1)?),
        ("algorithm", text("sha256")?),
        ("key_id", text(key.0)?),
        ("epoch", number(expected_epoch)?),
        ("operation_id", text(context.operation_id)?),
    ])?;
    append_change(
        txn,
        approval,
        context,
        body,
        "aukora:aumlok-key-revocation:v1",
        &format!("aumlok:key:{}", key.0),
        expected_epoch,
    )
}
pub(crate) fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}
pub(crate) fn hash_bytes(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}
pub(crate) fn text(value: impl ToString) -> Result<Value> {
    Value::checked_text(value.to_string())
}
pub(crate) fn number(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| refuse("integer-range"))?;
    Ok(Value::integer(SafeInteger::new(value)?))
}
pub(crate) fn object<const N: usize>(fields: [(&str, Value); N]) -> Result<Value> {
    Value::checked_object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
pub(crate) fn domain_bytes(domain: &str, value: &Value) -> Result<Vec<u8>> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(value.canonical_bytes());
    if bytes.len() > 65_536 {
        return Err(refuse("body-size"));
    }
    Ok(bytes)
}
pub(crate) fn checked_time(at: i64) -> Result<u64> {
    if !(0..=MAX_SAFE_INTEGER).contains(&at) {
        return Err(refuse("clock"));
    }
    Ok(at as u64)
}
pub(crate) fn validate_version(version: &AuthorityVersion) -> Result<()> {
    if version.epoch > MAX_SAFE_INTEGER as u64
        || version.sequence == 0
        || version.sequence > MAX_SAFE_INTEGER as u64
        || (version.sequence == 1) != version.previous_hash.is_none()
    {
        return Err(refuse("authority-version"));
    }
    Ok(())
}
pub(crate) fn version_json(version: &AuthorityVersion) -> Result<Value> {
    validate_version(version)?;
    object([
        ("epoch", number(version.epoch)?),
        ("sequence", number(version.sequence)?),
        (
            "previous_hash",
            match version.previous_hash {
                Some(hash) => text(hash)?,
                None => Value::null(),
            },
        ),
    ])
}
const ROLES: &[(KeyRole, &str)] = &[
    (KeyRole::OwnerPasskey, "owner-passkey"),
    (KeyRole::IdentityRoot, "identity-root"),
    (KeyRole::Operational, "operational"),
    (KeyRole::Device, "device"),
    (KeyRole::Session, "session"),
    (KeyRole::Agent, "agent"),
    (KeyRole::Node, "node"),
    (KeyRole::NodeNostr, "node-nostr"),
    (KeyRole::AgentNostr, "agent-nostr"),
    (KeyRole::GuardianShardHolder, "guardian-shard-holder"),
    (KeyRole::GuardianRecovery, "guardian-recovery"),
    (KeyRole::GuardianVeto, "guardian-veto"),
    (KeyRole::BackupEncryption, "backup-encryption"),
    (KeyRole::AuraSigning, "aura-signing"),
    (KeyRole::DeviceMeshIdentity, "device-mesh-identity"),
    (KeyRole::DeviceMeshAgreement, "device-mesh-agreement"),
];
const USES: &[(KeyUse, &str)] = &[
    (KeyUse::IdentityStatement, "identity-statement"),
    (KeyUse::AuraRecord, "aura-record"),
    (KeyUse::NodeNostrEvent, "node-nostr-event"),
    (KeyUse::AgentNostrEvent, "agent-nostr-event"),
    (KeyUse::DevicePossession, "device-possession"),
    (KeyUse::SessionAuthentication, "session-authentication"),
    (KeyUse::AgentIdentity, "agent-identity"),
    (KeyUse::BackupEncrypt, "backup-encrypt"),
    (KeyUse::BackupDecrypt, "backup-decrypt"),
    (KeyUse::GuardianShardReceipt, "guardian-shard-receipt"),
    (KeyUse::GuardianRecoveryStatement, "guardian-recovery-statement"),
    (KeyUse::GuardianVetoAcknowledgement, "guardian-veto-acknowledgement"),
    (KeyUse::MeshIdentity, "mesh-identity"),
    (KeyUse::MeshAgreement, "mesh-agreement"),
];
fn role_name(role: KeyRole) -> Result<&'static str> {
    ROLES
        .iter()
        .find(|(r, _)| *r == role)
        .map(|(_, n)| *n)
        .ok_or(refuse("key-role"))
}
fn use_name(purpose: KeyUse) -> Result<&'static str> {
    USES.iter()
        .find(|(u, _)| *u == purpose)
        .map(|(_, n)| *n)
        .ok_or(refuse("key-use"))
}
fn unique<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .all(|(i, v)| !items[..i].contains(v))
}
pub(crate) fn validate_scope(scope: &KeyScope) -> Result<()> {
    if scope.uses.len() > MAX_KEY_USES
        || !unique(&scope.uses)
        || scope.owner_actions.len() > 5
        || !unique(&scope.owner_actions)
        || scope.resources.len() > MAX_SCOPE_RESOURCES
        || !unique(&scope.resources)
        || scope
            .resources
            .iter()
            .any(|r| r.is_empty() || r.len() > 1024 || r.chars().any(char::is_control))
        || scope.not_before_ms >= scope.expires_at_ms
        || scope.expires_at_ms > MAX_SAFE_INTEGER as u64
    {
        return Err(refuse("key-scope"));
    }
    Ok(())
}
pub(crate) fn scope_attenuates(child: &KeyScope, parent: &KeyScope) -> Result<()> {
    validate_scope(child)?;
    validate_scope(parent)?;
    if !child.owner_actions.is_empty()
        || child.subject != parent.subject
        || child.node != parent.node
        || child.not_before_ms < parent.not_before_ms
        || child.expires_at_ms > parent.expires_at_ms
        || child.uses.iter().any(|v| !parent.uses.contains(v))
        || child
            .resources
            .iter()
            .any(|v| !parent.resources.contains(v))
    {
        return Err(refuse("scope-amplification"));
    }
    Ok(())
}
pub(crate) fn scope_json(scope: &KeyScope) -> Result<Value> {
    validate_scope(scope)?;
    let uses = scope.uses.iter().map(|value| text(use_name(*value)?));
    let actions = scope.owner_actions.iter().map(|value| text(value.wire_name()));
    object([
        ("subject", text(scope.subject)?),
        ("node", text(scope.node)?),
        ("uses", Value::checked_array(uses.collect::<Result<_>>()?)?),
        (
            "owner_actions",
            Value::checked_array(actions.collect::<Result<_>>()?)?,
        ),
        (
            "resources",
            Value::checked_array(scope.resources.iter().map(text).collect::<Result<_>>()?)?,
        ),
        ("not_before_ms", number(scope.not_before_ms)?),
        ("expires_at_ms", number(scope.expires_at_ms)?),
    ])
}
fn role_use(role: KeyRole, purpose: KeyUse) -> bool {
    use KeyRole as R;
    use KeyUse as U;
    match role {
        R::IdentityRoot | R::Node => purpose == U::IdentityStatement,
        R::Operational => matches!(
            purpose,
            U::IdentityStatement | U::SessionAuthentication | U::AgentIdentity
        ),
        R::OwnerPasskey | R::Device => matches!(
            purpose,
            U::DevicePossession
                | U::SessionAuthentication
                | U::AgentIdentity
                | U::IdentityStatement
        ),
        R::Session => matches!(
            purpose,
            U::SessionAuthentication | U::AgentIdentity | U::IdentityStatement
        ),
        R::Agent => matches!(purpose, U::AgentIdentity | U::IdentityStatement),
        R::NodeNostr => purpose == U::NodeNostrEvent,
        R::AgentNostr => purpose == U::AgentNostrEvent,
        R::GuardianShardHolder => purpose == U::GuardianShardReceipt,
        R::GuardianRecovery => purpose == U::GuardianRecoveryStatement,
        R::GuardianVeto => purpose == U::GuardianVetoAcknowledgement,
        R::BackupEncryption => matches!(purpose, U::BackupEncrypt | U::BackupDecrypt),
        R::AuraSigning => purpose == U::AuraRecord,
        R::DeviceMeshIdentity => purpose == U::MeshIdentity,
        R::DeviceMeshAgreement => purpose == U::MeshAgreement,
    }
}
pub(crate) fn validate_request(request: &KeyBindingRequest) -> Result<()> {
    validate_scope(&request.scope)?;
    if request.v != KEY_BINDING_VERSION
        || request.epoch > MAX_SAFE_INTEGER as u64
        || (request.role != KeyRole::OwnerPasskey && !request.scope.owner_actions.is_empty())
        || request
            .scope
            .uses
            .iter()
            .any(|u| !role_use(request.role, *u))
    {
        return Err(refuse("key-role-scope"));
    }
    use AlgorithmId as A;
    use KeyRole as R;
    match (&request.material, request.role, request.algorithm) {
        (KeyMaterial::SealedCommitment(_), R::BackupEncryption, A::XChaCha20Poly1305)
        | (KeyMaterial::SealedCommitment(_), R::IdentityRoot, A::Sha256) => Ok(()),
        (KeyMaterial::Public(key), role, algorithm) => {
            if key.v != 1 || key.algorithm != algorithm {
                return Err(refuse("key-algorithm"));
            }
            let permitted = match role {
                R::OwnerPasskey => matches!(algorithm, A::Ed25519 | A::EcdsaP256Sha256),
                R::NodeNostr | R::AgentNostr => algorithm == A::Secp256k1Schnorr,
                R::DeviceMeshAgreement => algorithm == A::X25519,
                R::BackupEncryption => false,
                _ => algorithm == A::Ed25519,
            };
            if !permitted {
                return Err(refuse("key-algorithm"));
            }
            validate_public_key(key)
        }
        _ => Err(refuse("key-material")),
    }
}
fn validate_public_key(key: &PublicKey) -> Result<()> {
    if key.v != 1 {
        return Err(refuse("key-version"));
    }
    match key.algorithm {
        AlgorithmId::Ed25519 => {
            let bytes: &[u8; 32] = key
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| refuse("public-key"))?;
            let key =
                ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| refuse("public-key"))?;
            if key.is_weak() {
                return Err(refuse("public-key"));
            }
        }
        AlgorithmId::EcdsaP256Sha256 => {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.bytes)
                .map_err(|_| refuse("public-key"))?;
        }
        AlgorithmId::Secp256k1Schnorr => {
            k256::schnorr::VerifyingKey::from_bytes(
                &k256::FieldBytes::try_from(key.bytes.as_slice())
                    .map_err(|_| refuse("public-key"))?,
            )
            .map_err(|_| refuse("public-key"))?;
        }
        AlgorithmId::X25519 if key.bytes.len() == 32 && key.bytes.iter().any(|v| *v != 0) => {}
        _ => return Err(refuse("key-algorithm")),
    }
    Ok(())
}
pub(crate) fn validate_binding(binding: &KeyBinding) -> Result<()> {
    validate_request(&binding.request)?;
    validate_version(&binding.version)?;
    if binding.version.epoch != binding.request.epoch {
        return Err(refuse("key-epoch"));
    }
    Ok(())
}
pub(crate) fn request_value(request: &KeyBindingRequest) -> Result<Value> {
    validate_request(request)?;
    let material = match &request.material {
        KeyMaterial::Public(key) => object([(
            "public",
            object([
                ("v", number(key.v.into())?),
                ("algorithm", text(key.algorithm.wire_name())?),
                ("bytes", text(STANDARD.encode(&key.bytes))?),
            ])?,
        )])?,
        KeyMaterial::SealedCommitment(hash) => object([("sealed_commitment", text(hash)?)])?,
    };
    object([
        ("v", number(request.v.into())?),
        ("algorithm", text(request.algorithm.wire_name())?),
        ("key_id", text(request.key_id.0)?),
        ("role", text(role_name(request.role)?)?),
        ("material", material),
        ("scope", scope_json(&request.scope)?),
        ("epoch", number(request.epoch)?),
        ("operation_id", text(request.operation_id)?),
    ])
}
pub(crate) fn verify_material_signatures<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    material: &KeyMaterial,
    bytes: &[u8],
    signatures: &Signatures,
) -> Result<()> {
    let KeyMaterial::Public(key) = material else {
        return Err(refuse("signing-key-required"));
    };
    if signatures.version() != 1 || signatures.components().len() != 1 {
        return Err(refuse("signature-components"));
    }
    verify_signature_component(txn, key, bytes, &signatures.components()[0])
}
pub(crate) fn verify_signature_component<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    key: &PublicKey,
    bytes: &[u8],
    signature: &Signature,
) -> Result<()> {
    validate_public_key(key)?;
    if signature.v != 1 || signature.algorithm != key.algorithm {
        return Err(refuse("signature-algorithm"));
    }
    // The primitive check happens here as well as at the transaction boundary.
    use signature::Verifier;
    match key.algorithm {
        AlgorithmId::Ed25519 => {
            let raw: &[u8; 32] = key
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| refuse("public-key"))?;
            let verifier =
                ed25519_dalek::VerifyingKey::from_bytes(raw).map_err(|_| refuse("public-key"))?;
            let sig = ed25519_dalek::Signature::from_slice(&signature.bytes)
                .map_err(|_| refuse("signature"))?;
            verifier
                .verify_strict(bytes, &sig)
                .map_err(|_| refuse("signature"))?;
        }
        AlgorithmId::EcdsaP256Sha256 => {
            let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.bytes)
                .map_err(|_| refuse("public-key"))?;
            let sig = p256::ecdsa::Signature::from_der(&signature.bytes)
                .map_err(|_| refuse("signature"))?;
            verifier
                .verify(bytes, &sig)
                .map_err(|_| refuse("signature"))?;
        }
        AlgorithmId::Secp256k1Schnorr => {
            let verifier = k256::schnorr::VerifyingKey::from_bytes(
                &k256::FieldBytes::try_from(key.bytes.as_slice())
                    .map_err(|_| refuse("public-key"))?,
            )
            .map_err(|_| refuse("public-key"))?;
            let sig = k256::schnorr::Signature::try_from(signature.bytes.as_slice())
                .map_err(|_| refuse("signature"))?;
            verifier
                .verify(bytes, &sig)
                .map_err(|_| refuse("signature"))?;
        }
        _ => return Err(refuse("signature-algorithm")),
    }
    txn.verify_signature(key, bytes, signature)
}
pub(crate) fn verify_key_signatures<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    binding: &KeyBinding,
    bytes: &[u8],
    signatures: &Signatures,
) -> Result<()> {
    validate_binding(binding)?;
    if matches!(
        binding.request.role,
        KeyRole::DeviceMeshIdentity | KeyRole::DeviceMeshAgreement
    ) {
        return Err(refuse("mesh-reserved"));
    }
    verify_material_signatures(txn, &binding.request.material, bytes, signatures)
}
pub(crate) fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(refuse("stored-field"))
}
pub(crate) fn value_text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(refuse("stored-text")),
    }
}
pub(crate) fn value_u64(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(value) if value.get() >= 0 => Ok(value.get() as u64),
        _ => Err(refuse("stored-integer")),
    }
}
pub(crate) fn exact_fields(value: &Value, names: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == names.len()
                && fields.iter().all(|(key, _)| names.contains(&key.as_str())) =>
        {
            Ok(())
        }
        _ => Err(refuse("stored-fields")),
    }
}
pub(crate) fn array(value: &Value) -> Result<&[Value]> {
    match value.view() {
        ValueView::Array(values) => Ok(values),
        _ => Err(refuse("stored-array")),
    }
}
pub(crate) fn parse_key_id(value: &Value) -> Result<KeyId> {
    Ok(KeyId(Digest32::from_hex(value_text(value)?)?))
}
pub(crate) fn parse_version(value: &Value) -> Result<AuthorityVersion> {
    exact_fields(value, &["epoch", "sequence", "previous_hash"])?;
    let version = AuthorityVersion {
        epoch: value_u64(field(value, "epoch")?)?,
        sequence: value_u64(field(value, "sequence")?)?,
        previous_hash: match field(value, "previous_hash")?.view() {
            ValueView::Null => None,
            _ => Some(Digest32::from_hex(value_text(field(
                value,
                "previous_hash",
            )?)?)?),
        },
    };
    validate_version(&version)?;
    Ok(version)
}
pub(crate) fn parse_scope(value: &Value) -> Result<KeyScope> {
    exact_fields(
        value,
        &[
            "subject",
            "node",
            "uses",
            "owner_actions",
            "resources",
            "not_before_ms",
            "expires_at_ms",
        ],
    )?;
    let uses = array(field(value, "uses")?)?
        .iter()
        .map(|v| {
            let name = value_text(v)?;
            USES.iter()
                .find(|(_, n)| *n == name)
                .map(|(u, _)| *u)
                .ok_or(refuse("key-use"))
        })
        .collect::<Result<_>>()?;
    let owner_actions = array(field(value, "owner_actions")?)?
        .iter()
        .map(|v| match value_text(v)? {
            "apply" => Ok(OwnerOperation::Apply),
            "retire" => Ok(OwnerOperation::Retire),
            "release" => Ok(OwnerOperation::Release),
            "grant" => Ok(OwnerOperation::Grant),
            "permission" => Ok(OwnerOperation::Permission),
            _ => Err(refuse("owner-operation")),
        })
        .collect::<Result<_>>()?;
    let scope = KeyScope {
        subject: SubjectId::from_digest(Digest32::from_hex(
            value_text(field(value, "subject")?)?
                .strip_prefix("aukora:1:")
                .ok_or(refuse("subject"))?,
        )?),
        node: NodeId::from_hex(value_text(field(value, "node")?)?)?,
        uses,
        owner_actions,
        resources: array(field(value, "resources")?)?
            .iter()
            .map(|v| Ok(value_text(v)?.to_owned()))
            .collect::<Result<_>>()?,
        not_before_ms: value_u64(field(value, "not_before_ms")?)?,
        expires_at_ms: value_u64(field(value, "expires_at_ms")?)?,
    };
    validate_scope(&scope)?;
    Ok(scope)
}
fn parse_request(value: &Value) -> Result<KeyBindingRequest> {
    exact_fields(
        value,
        &[
            "v",
            "algorithm",
            "key_id",
            "role",
            "material",
            "scope",
            "epoch",
            "operation_id",
        ],
    )?;
    let role_name = value_text(field(value, "role")?)?;
    let role = ROLES
        .iter()
        .find(|(_, n)| *n == role_name)
        .map(|(r, _)| *r)
        .ok_or(refuse("key-role"))?;
    let material = field(value, "material")?;
    let material = if let Some(key) = material.get("public") {
        exact_fields(material, &["public"])?;
        exact_fields(key, &["v", "algorithm", "bytes"])?;
        let encoded = value_text(field(key, "bytes")?)?;
        let bytes = STANDARD.decode(encoded).map_err(|_| refuse("public-key"))?;
        if STANDARD.encode(&bytes) != encoded {
            return Err(refuse("public-key"));
        }
        KeyMaterial::Public(PublicKey {
            v: u16::try_from(value_u64(field(key, "v")?)?).map_err(|_| refuse("key-version"))?,
            algorithm: AlgorithmId::from_wire(value_text(field(key, "algorithm")?)?)?,
            bytes,
        })
    } else {
        exact_fields(material, &["sealed_commitment"])?;
        KeyMaterial::SealedCommitment(Digest32::from_hex(value_text(field(
            material,
            "sealed_commitment",
        )?)?)?)
    };
    let request = KeyBindingRequest {
        v: u16::try_from(value_u64(field(value, "v")?)?).map_err(|_| refuse("key-version"))?,
        algorithm: AlgorithmId::from_wire(value_text(field(value, "algorithm")?)?)?,
        key_id: parse_key_id(field(value, "key_id")?)?,
        role,
        material,
        scope: parse_scope(field(value, "scope")?)?,
        epoch: value_u64(field(value, "epoch")?)?,
        operation_id: OperationId::from_hex(value_text(field(value, "operation_id")?)?)?,
    };
    validate_request(&request)?;
    Ok(request)
}
pub(crate) fn load_binding<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    key: KeyId,
) -> Result<KeyBinding> {
    let value = txn
        .authority_state("aumlok.key-binding", &key.0.to_string())?
        .ok_or(refuse("key-missing"))?;
    exact_fields(&value, &["request", "version", "record_hash"])?;
    let binding = KeyBinding {
        request: parse_request(field(&value, "request")?)?,
        version: parse_version(field(&value, "version")?)?,
        record_hash: Digest32::from_hex(value_text(field(&value, "record_hash")?)?)?,
    };
    validate_binding(&binding)?;
    if binding.request.key_id != key {
        return Err(refuse("key-id"));
    }
    Ok(binding)
}
pub(crate) fn require_active_key<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    key: KeyId,
    epoch: u64,
    now: u64,
) -> Result<KeyBinding> {
    let binding = load_binding(txn, key)?;
    if txn
        .authority_state("aumlok.key-revocation", &key.0.to_string())?
        .is_some()
    {
        return Err(refuse("key-revoked"));
    }
    if binding.request.epoch != epoch || binding.version.epoch != epoch {
        return Err(refuse("key-epoch"));
    }
    if now < binding.request.scope.not_before_ms || now >= binding.request.scope.expires_at_ms {
        return Err(refuse("key-expired"));
    }
    if matches!(
        binding.request.role,
        KeyRole::DeviceMeshIdentity | KeyRole::DeviceMeshAgreement
    ) {
        return Err(refuse("mesh-reserved"));
    }
    Ok(binding)
}

/// Re-read exact gate state before persisting a counter, consuming, and appending.
/// Failure leaves rollback to the transaction owner; this function never commits.
pub(crate) fn append_change<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    approval: VerifiedProof,
    context: AuthorityAppendContext,
    body: Value,
    domain: &str,
    target: &str,
    epoch: u64,
) -> Result<AuthorityRecord> {
    validate_version(&context.authority)?;
    let current = txn.authority_append_context(&approval)?;
    if current.authority != context.authority
        || current.operation_id != context.operation_id
        || current.at < context.at
    {
        return Err(refuse("owner-approval-context"));
    }
    let context = current;
    let now = checked_time(context.at)?;
    let bounded = if domain == crate::devices::DEVICE_APPROVAL_DOMAIN {
        field(&body, "body")?
    } else {
        &body
    };
    if let Some(scope) = bounded.get("scope") {
        let scope = parse_scope(scope)?;
        if now < scope.not_before_ms || now >= scope.expires_at_ms {
            return Err(refuse("key-expired"));
        }
    }
    if let Some(receipt) = bounded.get("copresence") {
        if now >= value_u64(field(receipt, "expires_at_ms")?)? {
            return Err(refuse("device-expired"));
        }
    }
    let auth = approval.authorization();
    if approval.transaction_id() != txn.transaction_id()
        || auth.v != 1
        || auth.algorithm != AlgorithmId::Sha256
        || auth.op != OwnerOperation::Permission
        || auth.epoch != context.authority.epoch
        || auth.target != target
        || auth.cell.is_some()
        || auth.expires_at < 0
        || now >= auth.expires_at as u64
        || auth.new_sha256 != hash_bytes(&domain_bytes(domain, &body)?)
        || epoch < context.authority.epoch
        || epoch > context.authority.epoch.saturating_add(1)
    {
        return Err(refuse("owner-approval-context"));
    }
    if txn.rebuild_authorization(&auth.proposal, auth.op)? != *auth {
        return Err(refuse("owner-approval-changed"));
    }
    let owner = txn.owner_binding(approval.credential_id())?;
    if owner.v != 1
        || owner.epoch != auth.epoch
        || owner.public_key != *approval.public_key()
        || owner.credential_id != *approval.credential_id()
        || owner.algorithm != approval.algorithm()
        || owner.top_origin != approval.top_origin()
    {
        return Err(refuse("owner-binding-changed"));
    }
    let base = txn.authority_state("aumlok.target", target)?;
    match (&auth.base_sha256, base) {
        (BaseDigest::Absent, None) => {}
        (BaseDigest::Present(expected), Some(value))
            if *expected == Digest32::from_hex(value_text(&value)?)? => {}
        _ => return Err(refuse("owner-approval-base")),
    }
    let pending = PendingAuthorityRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: AuthorityVersion {
            epoch,
            ..context.authority
        },
        at: context.at,
        kind: Kind::AumlokBind,
        actor: auth.subject.to_string(),
        operation: Some(context.operation_id),
        phase: Phase::Terminal,
        body,
    };
    txn.persist_counter(&approval)?;
    txn.consume(&approval)?;
    if epoch == context.authority.epoch {
        txn.append(approval, pending)
    } else {
        txn.append_epoch_change(approval, pending)
    }
}

impl KeyBindingRequest {
    /// Exact domain-separated bytes hashed into the owner's C5 new_sha256.
    pub fn approval_bytes(&self) -> Result<Vec<u8>> {
        domain_bytes(KEY_BINDING_DOMAIN, &request_value(self)?)
    }
}
