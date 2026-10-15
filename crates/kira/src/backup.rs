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
            || self.count == 0
            || self.index >= self.count
            || self.head.version != 1
            || (self.head.sequence == 0) != self.head.hash.is_none()
            || self.head.sequence > canon::json::MAX_SAFE_INTEGER as u64
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(())
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
    /// Authenticate archive id, owner, epoch, head, index and count as chunk AAD.
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
