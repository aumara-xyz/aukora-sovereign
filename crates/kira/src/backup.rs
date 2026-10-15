// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 60 transfer contracts. No backup transport or plaintext restoration is implemented here.

use canon::{
    alg::AlgorithmId,
    authority::AuthorityTxn,
    codes,
    digest::Digest32,
    ids::{NodeId, SubjectId},
    Result,
};

use crate::{
    anchor::MemoryHead,
    permissions::{
        MemoryPermissions, Permission, PermissionContext, PermissionRequest, PermissionScope,
    },
};

/// Bounded ciphertext size for one backup chunk, including its authentication tag.
pub const MAX_BACKUP_CHUNK_BYTES: usize = 65_536;

/// The v1 backup chunk AAD domain, distinct from the note encryption domain.
pub const BACKUP_AEAD_DOMAIN: &str = "aukora:kira-backup-aead:v1";

fn validate_metadata(key_epoch: u64, head: MemoryHead, index: u32, count: u32) -> Result<()> {
    if key_epoch == 0
        || key_epoch > canon::json::MAX_SAFE_INTEGER as u64
        || head.version != 1
        || head.sequence > canon::json::MAX_SAFE_INTEGER as u64
        || (head.sequence == 0) != head.hash.is_none()
        || count == 0
        || index >= count
    {
        return Err(codes::KIRA_INVALID_FIELD);
    }
    Ok(())
}

/// Exact v1 chunk AAD: domain, NUL, then seven u32be-length-prefixed UTF-8 fields.
/// Order is archive id, owner subject, key epoch, head sequence, head hash, index,
/// count. Digests use lowercase hex, integers use unsigned decimal without padding,
/// and an empty head has sequence `0` and a zero-length hash field. The version and
/// XChaCha20Poly1305 algorithm are fixed by the v1 domain and wrapper validation.
/// This checks metadata shape only; it supplies no ownership or transport authority.
pub fn chunk_associated_data(
    archive_id: &Digest32,
    owner_subject: &SubjectId,
    key_epoch: u64,
    head: MemoryHead,
    index: u32,
    count: u32,
) -> Result<Vec<u8>> {
    validate_metadata(key_epoch, head, index, count)?;
    let fields = [
        archive_id.to_string(),
        owner_subject.to_string(),
        key_epoch.to_string(),
        head.sequence.to_string(),
        head.hash.map(|hash| hash.to_string()).unwrap_or_default(),
        index.to_string(),
        count.to_string(),
    ];
    let mut encoded = BACKUP_AEAD_DOMAIN.as_bytes().to_vec();
    encoded.push(0);
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| codes::KIRA_INVALID_FIELD)?;
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(field.as_bytes());
    }
    Ok(encoded)
}

/// A selected transport destination. The identifier alone proves no approval or ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupDestination {
    /// A relay identity from the owner's approved relay set; not an arbitrary URL.
    Relay(Digest32),
    /// Another node with a current binding to the same owner subject.
    OwnerNode(NodeId),
}

impl BackupDestination {
    /// Exact Export scope checked again immediately before transfer.
    pub fn permission_request(self) -> Result<PermissionRequest> {
        let scope = match self {
            Self::Relay(id) => format!("backup:relay:{id}"),
            Self::OwnerNode(id) => format!("backup:node:{id}"),
        };
        Ok(PermissionRequest {
            permission: Permission::Export,
            scope: PermissionScope::new(scope)?,
        })
    }
}

/// Opaque authenticated ciphertext. The constructor checks bounds, not cryptography.
#[derive(Clone, PartialEq, Eq)]
pub struct BackupCiphertext(Vec<u8>);

impl BackupCiphertext {
    /// Retain 16..=65,536 encrypted bytes, including the 16-byte AEAD tag.
    /// A producer must encrypt before construction; this value never marks plaintext safe.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < 16 || bytes.len() > MAX_BACKUP_CHUNK_BYTES {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(Self(bytes))
    }

    /// Borrow transport ciphertext only; no decryption or key access is provided.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One encrypted chunk of a head-pinned lossless backup, never an activation request.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedBackupChunk {
    /// Outer chunk wrapper version, exactly 1.
    pub version: u16,
    /// Exactly XChaCha20Poly1305 for this wrapper version.
    pub algorithm: AlgorithmId,
    /// Owner whose authenticated encrypted archive this chunk belongs to.
    pub owner_subject: SubjectId,
    /// Current root wrapping epoch; a secret key is never a field in this contract.
    pub key_epoch: u64,
    /// Exact Kira head covered by the complete archive.
    pub head: MemoryHead,
    /// Opaque archive identifier shared by its chunks.
    pub archive_id: Digest32,
    /// Zero-based chunk position, authenticated with the archive identifier.
    pub index: u32,
    /// Fixed total chunk count, authenticated to detect missing tails.
    pub count: u32,
    /// Unique XChaCha20 nonce supplied by the authenticated archive producer.
    pub nonce: [u8; 24],
    /// Encrypted chunk and authentication tag; includes no plaintext note or raw key.
    pub ciphertext: BackupCiphertext,
}

impl EncryptedBackupChunk {
    /// Validate wrapper shape, current owner/epoch and complete head metadata.
    /// This does not authenticate ciphertext, establish ownership or approve transport.
    pub fn validate(&self, context: &PermissionContext) -> Result<()> {
        context.validate()?;
        if self.version != 1
            || self.algorithm != AlgorithmId::XChaCha20Poly1305
            || self.owner_subject != context.owner_subject
            || self.key_epoch != context.owner_epoch
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        validate_metadata(self.key_epoch, self.head, self.index, self.count)
    }
}

/// Transport evidence, never proof of complete durable backup or permission to activate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupReceipt {
    /// Destination that acknowledged this particular chunk.
    pub destination: BackupDestination,
    /// Archive identifier from the encrypted chunk.
    pub archive_id: Digest32,
    /// Acknowledged chunk position.
    pub index: u32,
    /// Exact ciphertext commitment acknowledged by the destination.
    pub ciphertext_sha256: Digest32,
    /// Head the archive claims to cover; full restore verifies it against Aura.
    pub head: MemoryHead,
}

/// Future encrypted transfer hook; neither method stores notes or activates restored state.
pub trait MemoryBackup {
    /// Validate the chunk and compare its head to Kira's currently verified Aura anchor.
    /// In the supplied authority transaction, call `permissions.require` for
    /// `destination.permission_request()` and this exact context before sending each
    /// chunk. Check the relay is approved or the peer is a currently owner-bound node.
    /// Refuse stale, revoked or wrong-owner destinations and permission epochs.
    /// Transfer only ciphertext, nonce and content-free metadata; never keys or notes.
    /// Use `chunk_associated_data` with this chunk's exact archive id, owner,
    /// key epoch, head, index and count as the AEAD associated data.
    fn send<T: AuthorityTxn + ?Sized, P: MemoryPermissions + ?Sized>(
        &mut self,
        txn: &mut T,
        permissions: &P,
        context: &PermissionContext,
        destination: BackupDestination,
        chunk: &EncryptedBackupChunk,
    ) -> Result<BackupReceipt>;

    /// Recheck the same exact Export grant and approved destination as `send`.
    /// Return bounded ciphertext only, matching owner, epoch, archive and requested index.
    /// A later local restore must authenticate all chunks, verify Aura continuity and
    /// retain demotions, permission revocations and original note ids. This method
    /// cannot replace a newer head, revive permission or activate a memory artifact.
    fn receive<T: AuthorityTxn + ?Sized, P: MemoryPermissions + ?Sized>(
        &mut self,
        txn: &mut T,
        permissions: &P,
        context: &PermissionContext,
        source: BackupDestination,
        archive_id: Digest32,
        index: u32,
    ) -> Result<EncryptedBackupChunk>;
}
