// SPDX-License-Identifier: AGPL-3.0-or-later
//! Frozen domain-separation tags from C2 and the pinned interoperability vectors.
//!
//! Text constants exclude a trailing NUL; each contract below specifies whether
//! one is appended. These tags identify byte encodings, never authority or policy.

/// C2 Aura hash object `domain` value and sequence-1 `prev` sentinel; no NUL suffix.
pub const AURA_RECORD_DOMAIN: &str = "aukora:aura-record:v1";
/// C5 challenge prefix: UTF-8 tag, one NUL, then exact canonical authorization bytes.
pub const OWNER_AUTHORIZATION_DOMAIN: &str = "aukora:owner-authorization:v1";
/// C5 operation prefix: UTF-8 tag, one NUL, then the canonical operation-content object.
pub const OPERATION_CONTENT_DOMAIN: &str = "aukora:operation-content:v1";
/// C2 Kira associated-data tag, followed by NUL and u32be length-prefixed fields.
pub const KIRA_AEAD_DOMAIN: &str = "aukora:kira-aead:v1";
/// Fingerprint digest: SHA-256 of `"pentora.display.v1" || 0x00 || root32`.
/// `root32` is the 32 raw bytes of `AuraStatus::root`, the RFC 6962 root
/// used as the display snapshot head.
pub const PENTORA_DISPLAY_DOMAIN: &str = "pentora.display.v1";
/// C2 export convention name; its leaf prefix is the byte `0x00`, not this text.
pub const RFC6962_LEAF_CONVENTION: &str = "rfc6962-leaf-sha256-0x00-prefixed-v1";
/// RFC 6962 leaf hash prefix, followed by the raw 32-byte entry hash.
pub const RFC6962_LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 node hash prefix, followed by the raw left and right 32-byte hashes.
pub const RFC6962_NODE_PREFIX: u8 = 0x01;

/// Pinned subject vector's Ed25519 seed prefix: tag, one NUL, then the raw root key.
pub const AUMLOK_ROOT_KEY_DOMAIN: &str = "aukora:aumlok-root-key:v1";
/// Pinned subject vector's digest prefix: tag, one NUL, then the raw Ed25519 public key.
pub const AUMLOK_SUBJECT_DOMAIN: &str = "aukora:aumlok-subject:v1";
/// Envelope v1 associated-data prefix: tag, one NUL, then canonical header bytes.
/// The header contains exactly `kdf`, `nonce`, `salt` and `version`.
pub const AUMLOK_ENVELOPE_DOMAIN: &str = "aukora:aumlok-envelope:v1";
/// Refresh-phrase vector's key-derivation prefix: tag, one NUL, then the raw root key.
/// The derived key's AEAD associated data is the plain ASCII ceremony id alone.
pub const AUMLOK_REFRESH_PHRASE_KEY_DOMAIN: &str = "aukora:aumlok-refresh-phrase-key:v1";
/// Backup v2 PRF input is SHA-256 of this tag alone, without a NUL suffix.
pub const AUMLOK_BACKUP_PRF_DOMAIN: &str = "aukora:aumlok-backup-prf:v2";
/// Backup v2 HKDF-SHA256 extraction salt is this UTF-8 tag followed by one NUL.
pub const AUMLOK_BACKUP_HKDF_DOMAIN: &str = "aukora:aumlok-backup-hkdf:v2";
/// Backup v2 HKDF-SHA256 expansion info is this UTF-8 tag followed by one NUL.
pub const AUMLOK_BACKUP_KEY_DOMAIN: &str = "aukora:aumlok-backup-key:v2";
/// Backup v2 associated-data prefix: tag, one NUL, then its canonical header bytes.
/// The header contains every envelope field except `ciphertext`, including PRF metadata.
pub const AUMLOK_BACKUP_AEAD_DOMAIN: &str = "aukora:aumlok-backup-aead:v2";

/// Pinned co-presence v0 core prefix: tag, NUL, pk_A(65), pk_B(65), nonce_A(8),
/// nonce_B(8), then BE64(t_B), with keys and nonces decoded to raw bytes.
pub const COPRESENCE_CORE_DOMAIN: &str = "copresence.v0";
/// Pinned intent digest prefix: tag, one NUL, then the exact approved UTF-8 text.
pub const COPRESENCE_INTENT_DOMAIN: &str = "copresence.intent.v1";
/// Pinned intent nonce prefix: tag, NUL, digest(32), salt(16); use the first eight
/// bytes of the resulting SHA-256 digest as the asker's nonce.
pub const COPRESENCE_INTENT_NONCE_DOMAIN: &str = "copresence.intent-nonce.v1";
/// Pinned acknowledgement digest prefix: tag, NUL, intent digest(32), asker's
/// public key(65), then approver's nonce(8), all as raw bytes.
pub const COPRESENCE_INTENT_ACK_DOMAIN: &str = "copresence.intent-ack.v1";
