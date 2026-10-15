// SPDX-License-Identifier: AGPL-3.0-or-later
//! Key-binding contracts. Mutation entry points refuse until their implementation lands.

use canon::alg::{AlgorithmId, PublicKey};
use canon::authority::{
    AuthorityRecord, AuthorityTxn, AuthorityVersion, OwnerOperation, VerifiedProof,
};
use canon::digest::Digest32;
use canon::ids::{NodeId, OperationId, SubjectId};
use canon::{Refusal, Result};

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
    /// Hardware passkey authority, separate from the phrase-sealed identity secret.
    OwnerPasskey,
    /// Public commitment to the random phrase-sealed identity secret.
    IdentityRoot,
    /// Scoped day-to-day signing.
    Operational,
    /// Identity belonging to one paired device.
    Device,
    /// Short-lived descendant of one device delegation.
    Session,
    /// Agent descendant of one session delegation.
    Agent,
    /// Node identity for peer relationships.
    Node,
    /// secp256k1 node identity for Nostr.
    NodeNostr,
    /// secp256k1 agent identity for Nostr.
    AgentNostr,
    /// Holder of encrypted backup shards, without decryption authority.
    GuardianShardHolder,
    /// Operational-recovery statements, never owner replacement.
    GuardianRecovery,
    /// Recovery veto acknowledgements, never owner authorization.
    GuardianVeto,
    /// Backup encryption material, represented only by a public commitment here.
    BackupEncryption,
    /// Aura node signing, scoped to record signatures.
    AuraSigning,
    /// Reserved device signing identity for Bluetooth mesh.
    DeviceMeshIdentity,
    /// Reserved X25519 device agreement role for Bluetooth mesh.
    DeviceMeshAgreement,
}

/// Closed non-owner uses; none represents approval, release, or credential mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum KeyUse {
    /// Sign identity statements bounded by the recorded scope.
    IdentityStatement,
    /// Sign append-only records under already established authority.
    AuraRecord,
    /// Sign events as the node identity.
    NodeNostrEvent,
    /// Sign events as the agent identity.
    AgentNostrEvent,
    /// Sign a device possession statement.
    DevicePossession,
    /// Authenticate a bounded session.
    SessionAuthentication,
    /// Identify an agent inside its delegation.
    AgentIdentity,
    /// Wrap backup material.
    BackupEncrypt,
    /// Unwrap backups with surviving decryption material.
    BackupDecrypt,
    /// Acknowledge custody of ciphertext shards.
    GuardianShardReceipt,
    /// Attest operational recovery evidence.
    GuardianRecoveryStatement,
    /// Acknowledge a recovery veto.
    GuardianVetoAcknowledgement,
    /// Reserved mesh signing; no mesh operation is enabled by this enum.
    MeshIdentity,
    /// Reserved mesh key agreement; no transport is opened by this enum.
    MeshAgreement,
}

/// Exact subject, node, resources and uses requested for a binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyScope {
    /// Identity whose resources the key names.
    pub subject: SubjectId,
    /// Node on which the binding applies.
    pub node: NodeId,
    /// Closed uses; unknown wire operations have no variant.
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
    /// Read the active owner epoch and rollback guard from locked state.
    fn key_epoch(&mut self) -> Result<AuthorityVersion>;
    /// Read an Aura-anchored binding by exact id under this transaction.
    fn key_binding(&mut self, key: KeyId) -> Result<KeyBinding>;
    /// Read the latest revocation under this transaction on every use.
    fn key_revocation(&mut self, key: KeyId) -> Result<Option<KeyRevocation>>;
}

/// Refuses without mutating. Wave 1 must bind the exact body to the proof and use
/// only AuthorityTxn's counter, consumption and append path, in one transaction.
/// Any non-OwnerPasskey role with nonempty scope.owner_actions must refuse.
pub fn bind_key<T: AuthorityTxn + ?Sized>(
    _txn: &mut T,
    _approval: VerifiedProof,
    _request: KeyBindingRequest,
) -> Result<AuthorityRecord> {
    Err(Refusal {
        organ: "aumlok",
        reason: "keys-unimplemented",
    })
}

/// Refuses without mutating. Revocation requires a fresh owner proof over the exact
/// key, epoch and change; a stored binding or recovery statement is insufficient.
pub fn revoke_key<T: AuthorityTxn + ?Sized>(
    _txn: &mut T,
    _approval: VerifiedProof,
    _key: KeyId,
    _expected_epoch: u64,
) -> Result<AuthorityRecord> {
    Err(Refusal {
        organ: "aumlok",
        reason: "keys-unimplemented",
    })
}
