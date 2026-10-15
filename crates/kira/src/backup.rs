// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 60: authenticated memory archives, guarded ciphertext transfer and original-id restore.

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

/// Encrypted transfer hook; neither method stores notes or activates restored state.
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

use crate::{
    anchor::{AnchorClaim, MemoryLedger, SqliteMemory},
    health::{
        CheckObservation, HealthContext, HealthObserver, ObservationVerdict, ObservedCheck,
        BACKUP_HEAD_CORNER,
    },
    notes::{self, MemoryKey},
    permissions::{self, PermissionAction},
};
use canon::{health::CheckSpec, json::Value, Refusal};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

mod archive;
mod restore;

use archive::{head_value, obj};
pub use archive::{
    ArchivedDemotion, ArchivedNote, MemoryArchive, ARCHIVE_SCHEMA, MAX_ARCHIVE_BYTES,
};

/// Tag of the chunk associated data, followed by one NUL and length-prefixed fields.
pub const CHUNK_AEAD_DOMAIN: &str = BACKUP_AEAD_DOMAIN;
/// HKDF-SHA256 salt tag for the per-archive key, followed by one NUL.
pub const ARCHIVE_HKDF_DOMAIN: &str = "aukora:kira-backup-hkdf:v1";
/// HKDF-SHA256 info tag for the per-archive key, followed by one NUL and length-prefixed fields.
pub const ARCHIVE_KEY_DOMAIN: &str = "aukora:kira-backup-key:v1";
/// The `schema` of the content-free commitment object.
pub const COMMITMENT_SCHEMA: &str = "aukora-kira-backup-commitment-v1";
/// Smallest sealed chunk (ciphertext including its tag) a producer may choose.
pub const MIN_CHUNK_BYTES: usize = 1_024;
/// Default sealed chunk size; transport adapters enforce their own encoded-envelope limits.
pub const DEFAULT_CHUNK_BYTES: usize = 12_288;
/// Largest chunk count an archive may declare.
pub const MAX_ARCHIVE_CHUNKS: u32 = 16_384;
const TAG_BYTES: usize = 16;
const LENGTH_BYTES: usize = 8;

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "kira",
        reason,
    }
}

/// A destination that is not in the owner's approved relay set or not an owner-bound node.
pub const BACKUP_DESTINATION: Refusal = refusal("backup-destination");
/// A chunk's head differs from Kira's currently verified head.
pub const BACKUP_HEAD: Refusal = refusal("backup-head");
/// An archive is older than the head the caller already knows.
pub const BACKUP_ROLLBACK: Refusal = refusal("backup-rollback");
/// Archive bytes violate the closed archive format.
pub const BACKUP_ARCHIVE: Refusal = refusal("backup-archive");
/// A chunk set is incomplete, duplicated, mixed or inconsistent.
pub const BACKUP_CHUNKS: Refusal = refusal("backup-chunks");
/// A destination acknowledged other bytes than the ones sent.
pub const BACKUP_ACKNOWLEDGEMENT: Refusal = refusal("backup-acknowledgement");
/// Restore was attempted into a store that already holds notes or demotions.
pub const BACKUP_RESTORE_TARGET: Refusal = refusal("backup-restore-target");

/// Injected owner backup-root access for one epoch. Derived keys remain in zeroizing memory;
/// this module never serializes or sends the root.
pub trait BackupKeys {
    fn backup_root(&self, owner: &SubjectId, key_epoch: u64) -> Result<MemoryKey>;
}

fn push_field(out: &mut Vec<u8>, field: &str) -> Result<()> {
    let length = u32::try_from(field.len()).map_err(|_| codes::KIRA_INVALID_FIELD)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(field.as_bytes());
    Ok(())
}

fn archive_key<K: BackupKeys + ?Sized>(
    keys: &K,
    owner: &SubjectId,
    key_epoch: u64,
    archive_id: &Digest32,
) -> Result<MemoryKey> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let root = keys.backup_root(owner, key_epoch)?;
    let mut salt = ARCHIVE_HKDF_DOMAIN.as_bytes().to_vec();
    salt.push(0);
    let mut info = ARCHIVE_KEY_DOMAIN.as_bytes().to_vec();
    info.push(0);
    for field in [
        owner.to_string(),
        key_epoch.to_string(),
        archive_id.to_string(),
    ] {
        push_field(&mut info, &field)?;
    }
    let mut derived = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), root.bytes())
        .expand(&info, derived.as_mut())
        .map_err(|_| codes::KIRA_INVALID_FIELD)?;
    Ok(MemoryKey::from_unwrapped(derived))
}

// ---- sealing and opening ---------------------------------------------------------------------

/// Sealed chunks of one archive, in index order.
pub struct SealedArchive {
    /// The random id shared by every chunk.
    pub archive_id: Digest32,
    /// Chunks `0..count`, all of one size.
    pub chunks: Vec<EncryptedBackupChunk>,
}

/// Chunk and seal an archive for the owner at the context's epoch.
///
/// The stream that is sealed is `u64be(archive length) || archive || zero padding` up to a whole
/// number of chunks, so every chunk is exactly `chunk_bytes` of ciphertext and a holder learns
/// only a coarse size. Each chunk gets a fresh random nonce, and a repeated nonce refuses.
pub fn seal_archive<K: BackupKeys + ?Sized>(
    keys: &K,
    context: &PermissionContext,
    archive: &MemoryArchive,
    chunk_bytes: usize,
) -> Result<SealedArchive> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    context.validate()?;
    if archive.owner != context.owner_subject
        || archive.key_epoch != context.owner_epoch
        || !(MIN_CHUNK_BYTES..=MAX_BACKUP_CHUNK_BYTES).contains(&chunk_bytes)
    {
        return Err(codes::KIRA_INVALID_FIELD);
    }
    let plain = chunk_bytes - TAG_BYTES;
    let body = archive.to_bytes()?;
    let count = (LENGTH_BYTES + body.len()).div_ceil(plain);
    if count > MAX_ARCHIVE_CHUNKS as usize {
        return Err(BACKUP_ARCHIVE);
    }
    let mut stream = Zeroizing::new(Vec::with_capacity(count * plain));
    stream.extend_from_slice(&(body.len() as u64).to_be_bytes());
    stream.extend_from_slice(&body);
    stream.resize(count * plain, 0);
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| codes::KIRA_RANDOM_UNAVAILABLE)?;
    let archive_id = Digest32::from_bytes(random);
    let key = archive_key(keys, &archive.owner, archive.key_epoch, &archive_id)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| codes::KIRA_INVALID_FIELD)?;
    let mut nonces = BTreeSet::new();
    let mut chunks = Vec::with_capacity(count);
    for (index, piece) in stream.chunks_exact(plain).enumerate() {
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| codes::KIRA_RANDOM_UNAVAILABLE)?;
        if !nonces.insert(nonce) {
            return Err(codes::KIRA_RANDOM_UNAVAILABLE);
        }
        let aad = chunk_associated_data(
            &archive_id,
            &archive.owner,
            archive.key_epoch,
            archive.head,
            index as u32,
            count as u32,
        )?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: piece,
                    aad: &aad,
                },
            )
            .map_err(|_| codes::KIRA_AUTHENTICATION_FAILED)?;
        let chunk = EncryptedBackupChunk {
            version: 1,
            algorithm: AlgorithmId::XChaCha20Poly1305,
            owner_subject: archive.owner,
            key_epoch: archive.key_epoch,
            head: archive.head,
            archive_id,
            index: index as u32,
            count: count as u32,
            nonce,
            ciphertext: BackupCiphertext::new(ciphertext)?,
        };
        chunk.validate(context)?;
        chunks.push(chunk);
    }
    Ok(SealedArchive { archive_id, chunks })
}

/// The shape every chunk of one archive must share.
fn same_archive(first: &EncryptedBackupChunk, other: &EncryptedBackupChunk) -> bool {
    first.version == other.version
        && first.algorithm == other.algorithm
        && first.owner_subject == other.owner_subject
        && first.key_epoch == other.key_epoch
        && first.head == other.head
        && first.archive_id == other.archive_id
        && first.count == other.count
        && first.ciphertext.as_bytes().len() == other.ciphertext.as_bytes().len()
}

/// Authenticate every chunk, then rebuild and parse the archive.
///
/// All chunks `0..count` must be present exactly once and agree on archive, owner, epoch, head
/// and count; changed indices, foreign chunks, changed heads and truncated tails refuse.
/// Input order is immaterial: authenticated indices determine the output order.
pub fn open_archive<K: BackupKeys + ?Sized>(
    keys: &K,
    context: &PermissionContext,
    chunks: &[EncryptedBackupChunk],
) -> Result<MemoryArchive> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    context.validate()?;
    let first = chunks.first().ok_or(BACKUP_CHUNKS)?;
    let count = first.count as usize;
    if count == 0 || count > MAX_ARCHIVE_CHUNKS as usize || chunks.len() != count {
        return Err(BACKUP_CHUNKS);
    }
    let chunk_bytes = first.ciphertext.as_bytes().len();
    if !(MIN_CHUNK_BYTES..=MAX_BACKUP_CHUNK_BYTES).contains(&chunk_bytes) {
        return Err(BACKUP_CHUNKS);
    }
    let plain = chunk_bytes - TAG_BYTES;
    let stream_bytes = count.checked_mul(plain).ok_or(BACKUP_CHUNKS)?;
    if stream_bytes > MAX_ARCHIVE_BYTES + LENGTH_BYTES + plain - 1 {
        return Err(BACKUP_ARCHIVE);
    }
    let mut ordered: Vec<Option<&EncryptedBackupChunk>> = vec![None; count];
    let mut nonces = BTreeSet::new();
    for chunk in chunks {
        chunk.validate(context)?;
        let slot = ordered.get_mut(chunk.index as usize).ok_or(BACKUP_CHUNKS)?;
        if slot.is_some() || !same_archive(first, chunk) || !nonces.insert(chunk.nonce) {
            return Err(BACKUP_CHUNKS);
        }
        *slot = Some(chunk);
    }
    let key = archive_key(
        keys,
        &first.owner_subject,
        first.key_epoch,
        &first.archive_id,
    )?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| codes::KIRA_INVALID_FIELD)?;
    let mut stream = Zeroizing::new(Vec::with_capacity(stream_bytes));
    for chunk in ordered.into_iter().flatten() {
        let aad = chunk_associated_data(
            &chunk.archive_id,
            &chunk.owner_subject,
            chunk.key_epoch,
            chunk.head,
            chunk.index,
            chunk.count,
        )?;
        let clear = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(chunk.nonce),
                    Payload {
                        msg: chunk.ciphertext.as_bytes(),
                        aad: &aad,
                    },
                )
                .map_err(|_| codes::KIRA_AUTHENTICATION_FAILED)?,
        );
        stream.extend_from_slice(&clear);
    }
    let length = stream
        .get(..LENGTH_BYTES)
        .and_then(|prefix| <[u8; LENGTH_BYTES]>::try_from(prefix).ok())
        .map(u64::from_be_bytes)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(BACKUP_ARCHIVE)?;
    let end = LENGTH_BYTES.checked_add(length).ok_or(BACKUP_ARCHIVE)?;
    // A producer pads to the next whole chunk and no further, with zeros.
    if end > stream.len() || stream.len() - end >= plain || stream[end..].iter().any(|b| *b != 0) {
        return Err(BACKUP_ARCHIVE);
    }
    let archive = MemoryArchive::parse(&stream[LENGTH_BYTES..end])?;
    if archive.owner != first.owner_subject
        || archive.key_epoch != first.key_epoch
        || archive.head != first.head
    {
        return Err(BACKUP_ARCHIVE);
    }
    Ok(archive)
}

// ---- the content-free commitment -------------------------------------------------------------

/// The ids, head and SHA-256 of each sealed chunk. This value alone proves no remote possession.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupCommitment {
    pub owner: SubjectId,
    pub key_epoch: u64,
    pub archive_id: Digest32,
    pub head: MemoryHead,
    /// SHA-256 of each chunk's ciphertext, in index order.
    pub chunks: Vec<Digest32>,
}

impl BackupCommitment {
    pub fn validate(&self) -> Result<()> {
        let count = u32::try_from(self.chunks.len()).map_err(|_| BACKUP_CHUNKS)?;
        validate_metadata(self.key_epoch, self.head, 0, count)?;
        if count > MAX_ARCHIVE_CHUNKS {
            return Err(BACKUP_CHUNKS);
        }
        Ok(())
    }

    /// The commitment of chunks that were just sealed.
    pub fn from_sealed(sealed: &SealedArchive) -> Result<Self> {
        let first = sealed.chunks.first().ok_or(BACKUP_CHUNKS)?;
        let context = PermissionContext {
            owner_subject: first.owner_subject,
            current_principal: first.owner_subject,
            owner_epoch: first.key_epoch,
        };
        first.validate(&context)?;
        if sealed.chunks.len() != first.count as usize
            || first.archive_id != sealed.archive_id
            || first.count > MAX_ARCHIVE_CHUNKS
            || first.ciphertext.as_bytes().len() < MIN_CHUNK_BYTES
        {
            return Err(BACKUP_CHUNKS);
        }
        let mut digests = Vec::with_capacity(sealed.chunks.len());
        let mut nonces = BTreeSet::new();
        for (index, chunk) in sealed.chunks.iter().enumerate() {
            if chunk.index as usize != index
                || !same_archive(first, chunk)
                || !nonces.insert(chunk.nonce)
            {
                return Err(BACKUP_CHUNKS);
            }
            digests.push(Digest32::sha256(chunk.ciphertext.as_bytes()));
        }
        Ok(Self {
            owner: first.owner_subject,
            key_epoch: first.key_epoch,
            archive_id: first.archive_id,
            head: first.head,
            chunks: digests,
        })
    }

    /// The commitment that one destination's receipts support. It exists only when every chunk
    /// has exactly one receipt from that destination and every acknowledged digest matches.
    pub fn from_receipts(
        destination: BackupDestination,
        sealed: &SealedArchive,
        receipts: &[BackupReceipt],
    ) -> Result<Self> {
        let commitment = Self::from_sealed(sealed)?;
        if receipts.len() != commitment.chunks.len() {
            return Err(BACKUP_CHUNKS);
        }
        let mut seen = BTreeSet::new();
        for receipt in receipts {
            let expected = commitment
                .chunks
                .get(receipt.index as usize)
                .ok_or(BACKUP_CHUNKS)?;
            if receipt.destination != destination
                || receipt.archive_id != commitment.archive_id
                || receipt.head != commitment.head
                || receipt.ciphertext_sha256 != *expected
                || !seen.insert(receipt.index)
            {
                return Err(BACKUP_ACKNOWLEDGEMENT);
            }
        }
        Ok(commitment)
    }

    /// SHA-256 of the canonical commitment object; this is the value to witness.
    pub fn digest(&self) -> Result<Digest32> {
        self.validate()?;
        let chunks = self
            .chunks
            .iter()
            .map(|d| notes::text(d.to_string()))
            .collect::<Result<Vec<_>>>()?;
        let value = obj(vec![
            ("schema", notes::text(COMMITMENT_SCHEMA)?),
            (
                "body",
                obj(vec![
                    ("owner", notes::text(self.owner.to_string())?),
                    ("epoch", notes::integer(self.key_epoch)?),
                    ("archive_id", notes::text(self.archive_id.to_string())?),
                    ("head", head_value(self.head)?),
                    ("count", notes::integer(self.chunks.len() as u64)?),
                    ("chunks", Value::checked_array(chunks)?),
                ])?,
            ),
        ])?;
        Ok(Digest32::sha256(&value.canonical_bytes()))
    }
}

// ---- Kira's side of the backup health corner -------------------------------------------------

/// Measures corner 15 (`BACKUP_HEAD_CORNER`) from a commitment and the verified anchor; every
/// other check is left to its own observer and reports unwritten here.
///
/// A local commitment alone remains NotChecked. The receipts path additionally compares one
/// destination's complete acknowledgements; neither path claims permanent remote durability.
pub struct BackupChecks {
    context: HealthContext,
    verdict: Option<ObservationVerdict>,
}

impl BackupChecks {
    pub fn measure(
        principal: &PermissionContext,
        anchor: &AnchorClaim,
        latest: Option<&BackupCommitment>,
        observed_at_ms: u64,
    ) -> Self {
        let verdict = match latest {
            _ if principal.validate().is_err()
                || anchor.validate().is_err()
                || anchor.owner != principal.owner_subject =>
            {
                Some(ObservationVerdict::InvariantFailed)
            }
            None => None,
            Some(c) if c.validate().is_err() => Some(ObservationVerdict::InvariantFailed),
            Some(c) if c.owner != anchor.owner || c.key_epoch != principal.owner_epoch => {
                Some(ObservationVerdict::Disagreement)
            }
            Some(c) if c.head == anchor.head => None,
            Some(c) if c.head.sequence < anchor.head.sequence => None,
            Some(_) => Some(ObservationVerdict::Disagreement),
        };
        Self {
            context: HealthContext {
                epoch: principal.owner_epoch,
                sequence: anchor.aura_sequence,
                observed_at_ms,
                commitment: anchor.aura_hash,
            },
            verdict,
        }
    }

    /// Compare a complete set of transport acknowledgements from one observed relay transfer.
    pub fn measure_receipts(
        principal: &PermissionContext,
        anchor: &AnchorClaim,
        destination: BackupDestination,
        sealed: &SealedArchive,
        receipts: &[BackupReceipt],
        observed_at_ms: u64,
    ) -> Result<Self> {
        let commitment = BackupCommitment::from_receipts(destination, sealed, receipts)?;
        let mut check = Self::measure(principal, anchor, Some(&commitment), observed_at_ms);
        if check.verdict.is_none()
            && commitment.head == anchor.head
            && matches!(destination, BackupDestination::Relay(_))
        {
            check.verdict = Some(ObservationVerdict::Satisfied);
        }
        Ok(check)
    }
}

impl HealthObserver for BackupChecks {
    fn observe(&mut self, spec: CheckSpec, _requested: HealthContext) -> CheckObservation {
        if spec != BACKUP_HEAD_CORNER {
            return CheckObservation::Unwritten;
        }
        match self.verdict {
            None => CheckObservation::NotChecked,
            Some(verdict) => CheckObservation::Measured(ObservedCheck {
                check: spec.check,
                context: self.context,
                expires_at_ms: self
                    .context
                    .observed_at_ms
                    .saturating_add(spec.freshness_ms),
                verdict,
            }),
        }
    }
}

// ---- the guarded transfer --------------------------------------------------------------------

/// A holder's dumb side. It stores and returns sealed chunks and nothing else: it holds no
/// permission, no key and no policy, and a relay or node adapter implements it.
pub trait BackupStore {
    /// Keep the chunk. Return the SHA-256 of the ciphertext the destination now holds.
    fn put(
        &mut self,
        destination: BackupDestination,
        chunk: &EncryptedBackupChunk,
    ) -> Result<Digest32>;

    /// Fetch one chunk of one archive. The caller rechecks everything it returns.
    fn get(
        &mut self,
        source: BackupDestination,
        owner: &SubjectId,
        archive_id: &Digest32,
        index: u32,
    ) -> Result<EncryptedBackupChunk>;
}

/// Which destinations the owner currently stands behind. Supervisor wiring answers from the
/// approved relay set and from AUMLOK's node bindings; an identifier alone proves neither.
pub trait BackupDirectory {
    fn relay_approved<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        owner: &SubjectId,
        relay: &Digest32,
    ) -> Result<bool>;

    fn node_bound<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        owner: &SubjectId,
        node: &NodeId,
    ) -> Result<bool>;
}

/// Kira's currently verified anchor, read again in the caller's transaction.
pub trait VerifiedHead {
    fn verified<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
    ) -> Result<AnchorClaim>;
}

impl<L: MemoryLedger> VerifiedHead for SqliteMemory<'_, L> {
    fn verified<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
    ) -> Result<AnchorClaim> {
        self.verified_anchor(txn, context)
    }
}

/// The one `MemoryBackup`. Every call, for every chunk, repeats the same checks in the supplied
/// transaction: the owner context, the verified head, an approved destination and the exact
/// `Export` grant for that destination. No result is cached. `receive` makes the same checks as
/// `send`, so a node restoring from a destination needs the owner's `Export` grant for that
/// destination in its own Aura first; nothing here creates one.
pub struct GuardedBackup<'a, S, D, H> {
    store: S,
    directory: &'a D,
    head: &'a H,
    keys: &'a dyn BackupKeys,
}

impl<'a, S: BackupStore, D: BackupDirectory, H: VerifiedHead> GuardedBackup<'a, S, D, H> {
    pub fn new(store: S, directory: &'a D, head: &'a H, keys: &'a dyn BackupKeys) -> Self {
        Self {
            store,
            directory,
            head,
            keys,
        }
    }

    fn authenticate(&self, chunk: &EncryptedBackupChunk) -> Result<()> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            XChaCha20Poly1305, XNonce,
        };
        if chunk.ciphertext.as_bytes().len() < MIN_CHUNK_BYTES {
            return Err(BACKUP_CHUNKS);
        }
        let key = archive_key(
            self.keys,
            &chunk.owner_subject,
            chunk.key_epoch,
            &chunk.archive_id,
        )?;
        let aad = chunk_associated_data(
            &chunk.archive_id,
            &chunk.owner_subject,
            chunk.key_epoch,
            chunk.head,
            chunk.index,
            chunk.count,
        )?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.bytes())
            .map_err(|_| codes::KIRA_INVALID_FIELD)?;
        let _clear = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(chunk.nonce),
                    Payload {
                        msg: chunk.ciphertext.as_bytes(),
                        aad: &aad,
                    },
                )
                .map_err(|_| codes::KIRA_AUTHENTICATION_FAILED)?,
        );
        Ok(())
    }

    fn authorize<T: AuthorityTxn + ?Sized, P: MemoryPermissions + ?Sized>(
        &self,
        txn: &mut T,
        permissions: &P,
        context: &PermissionContext,
        destination: BackupDestination,
    ) -> Result<AnchorClaim> {
        context.validate()?;
        permissions::verify_context(txn, context)?;
        let anchor = self.head.verified(txn, context)?;
        anchor.validate()?;
        if anchor.owner != context.owner_subject {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        let approved = match destination {
            BackupDestination::Relay(id) => {
                self.directory
                    .relay_approved(txn, &context.owner_subject, &id)?
            }
            BackupDestination::OwnerNode(id) => {
                self.directory
                    .node_bound(txn, &context.owner_subject, &id)?
            }
        };
        if !approved {
            return Err(BACKUP_DESTINATION);
        }
        let request = destination.permission_request()?;
        let grant = permissions.require(txn, context, &request)?;
        if grant.change.context != *context
            || grant.change.action != PermissionAction::Grant
            || grant.change.request != request
            || grant.record.authority.epoch != context.owner_epoch
            || grant.record.authority.sequence == 0
            || grant.record.authority.sequence > anchor.aura_sequence
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(anchor)
    }
}

impl<S: BackupStore, D: BackupDirectory, H: VerifiedHead> MemoryBackup
    for GuardedBackup<'_, S, D, H>
{
    fn send<T: AuthorityTxn + ?Sized, P: MemoryPermissions + ?Sized>(
        &mut self,
        txn: &mut T,
        permissions: &P,
        context: &PermissionContext,
        destination: BackupDestination,
        chunk: &EncryptedBackupChunk,
    ) -> Result<BackupReceipt> {
        chunk.validate(context)?;
        if chunk.count > MAX_ARCHIVE_CHUNKS {
            return Err(BACKUP_CHUNKS);
        }
        let anchor = self.authorize(txn, permissions, context, destination)?;
        // A chunk of any other head, older or forged, never leaves the node.
        if chunk.head != anchor.head {
            return Err(BACKUP_HEAD);
        }
        self.authenticate(chunk)?;
        let committed = Digest32::sha256(chunk.ciphertext.as_bytes());
        if self.store.put(destination, chunk)? != committed {
            return Err(BACKUP_ACKNOWLEDGEMENT);
        }
        Ok(BackupReceipt {
            destination,
            archive_id: chunk.archive_id,
            index: chunk.index,
            ciphertext_sha256: committed,
            head: chunk.head,
        })
    }

    fn receive<T: AuthorityTxn + ?Sized, P: MemoryPermissions + ?Sized>(
        &mut self,
        txn: &mut T,
        permissions: &P,
        context: &PermissionContext,
        source: BackupDestination,
        archive_id: Digest32,
        index: u32,
    ) -> Result<EncryptedBackupChunk> {
        let anchor = self.authorize(txn, permissions, context, source)?;
        let chunk = self
            .store
            .get(source, &context.owner_subject, &archive_id, index)?;
        chunk.validate(context)?;
        // A holder cannot make the caller ask for more chunks than any archive may have.
        if chunk.archive_id != archive_id
            || chunk.index != index
            || chunk.count > MAX_ARCHIVE_CHUNKS
        {
            return Err(BACKUP_CHUNKS);
        }
        // Fetching can never lower the head this node already verified.
        if chunk.head.sequence < anchor.head.sequence {
            return Err(BACKUP_ROLLBACK);
        }
        if chunk.head.sequence == anchor.head.sequence && chunk.head != anchor.head {
            return Err(BACKUP_HEAD);
        }
        self.authenticate(&chunk)?;
        Ok(chunk)
    }
}
