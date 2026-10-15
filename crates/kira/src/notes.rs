// SPDX-License-Identifier: AGPL-3.0-or-later
//! Encrypted note storage contracts. No disk store or alternate Aura writer is provided.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, CellCommitment, VerifiedProof},
    digest::Digest32,
    fd3_payloads::MemoryPut,
    ids::{NoteId, SubjectId},
    provenance::{Provenance, Source},
    Refusal, Result,
};
use zeroize::Zeroizing;

use crate::{
    anchor::{AnchorClaim, MemoryHead},
    permissions::{MemoryPermissions, PermissionContext},
};

pub const MAX_CATEGORY_BYTES: usize = 64;
pub const MAX_STATEMENT_BYTES: usize = 4096;
pub const MAX_QUOTE_BYTES: usize = 4096;
pub const MAX_NOTE_BYTES: usize = 65_536;
pub const MAX_SUMMARY_SOURCES: usize = 100;
pub const GUEST_WINDOW_MS: u64 = 60_000;
pub const GUEST_WINDOW_SAVES: u32 = 32;

pub(crate) const fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "kira",
        reason,
    }
}

/// Bounded immutable content; this type has no usage-driven confidence update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteContent {
    category: String,
    statement: String,
    quote: Option<String>,
}

impl NoteContent {
    pub fn new(category: String, statement: String, quote: Option<String>) -> Result<Self> {
        if category.is_empty()
            || category.len() > MAX_CATEGORY_BYTES
            || !category
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(refuse("category-invalid"));
        }
        if statement.trim().is_empty() || statement.len() > MAX_STATEMENT_BYTES {
            return Err(refuse("statement-invalid"));
        }
        if quote
            .as_ref()
            .is_some_and(|text| text.len() > MAX_QUOTE_BYTES)
        {
            return Err(refuse("quote-too-large"));
        }
        Ok(Self {
            category,
            statement,
            quote,
        })
    }

    pub fn category(&self) -> &str {
        &self.category
    }
    pub fn statement(&self) -> &str {
        &self.statement
    }
    pub fn quote(&self) -> Option<&str> {
        self.quote.as_deref()
    }

    /// C4's exact cell value, with absent quote distinct from an empty quote.
    pub fn canonical_value(&self) -> Result<Vec<u8>> {
        use canon::json::{to_canonical, Value};
        let mut fields = vec![
            ("category".into(), Value::text(self.category.clone())?),
            ("statement".into(), Value::text(self.statement.clone())?),
        ];
        if let Some(quote) = &self.quote {
            fields.push(("quote".into(), Value::text(quote.clone())?));
        }
        Ok(to_canonical(&Value::object(fields)?))
    }
}

/// Ingest provenance is supplied by the supervisor's channel, never parsed from text.
/// Recalled owner-session material remains memory data, not a current instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryOrigin(Provenance);

impl MemoryOrigin {
    pub fn from_ingress(provenance: Provenance) -> Result<Self> {
        if matches!(provenance.source, Source::Stranger) {
            return Err(refuse("unapproved-source"));
        }
        Ok(Self(provenance))
    }

    pub fn recorded_source(&self) -> &Provenance {
        &self.0
    }
    pub fn delivery_source(&self) -> Provenance {
        Provenance {
            source: Source::Memory,
        }
    }
    pub const fn grants_authority(&self) -> bool {
        false
    }
}

/// Deadline is a review reminder only; it has no expiry, demote or erase method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewBy(u64);

impl ReviewBy {
    pub fn new(at_ms: u64) -> Result<Self> {
        if at_ms > canon::json::MAX_SAFE_INTEGER as u64 {
            return Err(refuse("invalid-time"));
        }
        Ok(Self(at_ms))
    }
    pub const fn at_ms(self) -> u64 {
        self.0
    }
    pub const fn due(self, now_ms: u64) -> bool {
        now_ms >= self.0
    }
}

/// Derived usage is separate from the retained note and carries no confidence field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    recalls: u64,
}

impl Usage {
    pub const fn recalls(self) -> u64 {
        self.recalls
    }
    pub fn record_recall(&mut self) {
        self.recalls = self.recalls.saturating_add(1);
    }
}

/// A summary names retained originals; it cannot replace them through this API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoteForm {
    Original,
    Summary { originals: Vec<NoteId> },
}

impl NoteForm {
    pub fn validate(&self) -> Result<()> {
        if let Self::Summary { originals } = self {
            let distinct: std::collections::BTreeSet<_> = originals.iter().collect();
            if originals.is_empty()
                || originals.len() > MAX_SUMMARY_SOURCES
                || distinct.len() != originals.len()
            {
                return Err(refuse("summary-sources"));
            }
        }
        Ok(())
    }
}

/// Clear memory-key material has neither Debug nor Clone and is zeroized on drop.
pub struct MemoryKey(Zeroizing<[u8; 32]>);

impl MemoryKey {
    /// The supervisor supplies bytes unwrapped at the current AUMLOK root epoch.
    pub fn from_unwrapped(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Persistent wrapped material only; this is not a verified root binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedMemoryKey {
    pub version: u16,
    pub algorithm: AlgorithmId,
    pub key_id: NoteId,
    pub root_epoch: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl WrappedMemoryKey {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.algorithm != AlgorithmId::XChaCha20Poly1305 {
            return Err(refuse("unsupported-format"));
        }
        if self.root_epoch == 0
            || self.root_epoch > canon::json::MAX_SAFE_INTEGER as u64
            || self.ciphertext.len() != 48
        {
            return Err(refuse("key-envelope-invalid"));
        }
        Ok(())
    }
}

/// The v1 note AEAD binds owner_subject, note_id, key_id in that order.
/// Each UTF-8 field has a u32 big-endian byte length, following the C2 tag and NUL.
pub fn associated_data(owner: &SubjectId, note: &NoteId, key: &NoteId) -> Result<Vec<u8>> {
    let mut bytes = canon::domain::KIRA_AEAD_DOMAIN.as_bytes().to_vec();
    bytes.push(0);
    let subject = owner.to_string();
    for field in [subject.as_str(), note.as_str(), key.as_str()] {
        let len = u32::try_from(field.len()).map_err(|_| refuse("invalid-field"))?;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    Ok(bytes)
}

/// Ciphertext is the sealed canonical note payload including provenance and originals.
/// Algorithm and epoch belong to this new versioned storage envelope, never a C4 frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedNote {
    pub version: u16,
    pub algorithm: AlgorithmId,
    pub owner: SubjectId,
    pub note_id: NoteId,
    pub key_id: NoteId,
    pub root_epoch: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl EncryptedNote {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.algorithm != AlgorithmId::XChaCha20Poly1305 {
            return Err(refuse("unsupported-format"));
        }
        if self.root_epoch == 0
            || self.root_epoch > canon::json::MAX_SAFE_INTEGER as u64
            || !(16..=MAX_NOTE_BYTES + 16).contains(&self.ciphertext.len())
        {
            return Err(refuse("ciphertext-invalid"));
        }
        Ok(())
    }

    /// Exactly this new versioned storage wrapper is committed by SaveCommitment.
    /// Binary fields use lowercase hex; no plaintext or unwrapped key is included.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        use canon::json::{to_canonical, SafeInteger, Value};
        self.validate()?;
        let hex = |bytes: &[u8]| -> String {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(bytes.len() * 2);
            for &byte in bytes {
                out.push(DIGITS[(byte >> 4) as usize] as char);
                out.push(DIGITS[(byte & 15) as usize] as char);
            }
            out
        };
        let body = Value::object(vec![
            (
                "algorithm".into(),
                Value::text(self.algorithm.wire_name().into())?,
            ),
            ("owner".into(), Value::text(self.owner.to_string())?),
            ("note_id".into(), Value::text(self.note_id.to_string())?),
            ("key_id".into(), Value::text(self.key_id.to_string())?),
            (
                "root_epoch".into(),
                Value::integer(SafeInteger::new(self.root_epoch as i64)?),
            ),
            ("nonce".into(), Value::text(hex(&self.nonce))?),
            ("ciphertext".into(), Value::text(hex(&self.ciphertext))?),
        ])?;
        Ok(to_canonical(&Value::object(vec![
            ("schema".into(), Value::text("aukora-kira-note-v1".into())?),
            ("body".into(), body),
        ])?))
    }
}

/// Crypto implementation uses the allowlisted XChaCha20-Poly1305 primitive and a
/// fresh random nonce on every seal. Open rejects AEAD failure without plaintext.
pub trait NoteCipher {
    fn seal(
        &self,
        key: &MemoryKey,
        owner: &SubjectId,
        note: &NoteId,
        key_id: &NoteId,
        root_epoch: u64,
        canonical_payload: &[u8],
    ) -> Result<EncryptedNote>;
    fn open(&self, key: &MemoryKey, encrypted: &EncryptedNote) -> Result<Zeroizing<Vec<u8>>>;
}

/// Ledger body data cannot carry text, quotes, categories, origins or free-text reasons.
/// The ciphertext commitment covers the entire canonical encrypted envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaveCommitment {
    pub version: u16,
    pub algorithm: AlgorithmId,
    pub note_id: NoteId,
    pub encrypted_sha256: Digest32,
}

impl SaveCommitment {
    pub fn from_encrypted(note: &EncryptedNote) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(note.canonical_bytes()?);
        Ok(Self {
            version: 1,
            algorithm: AlgorithmId::Sha256,
            note_id: note.note_id.clone(),
            encrypted_sha256: Digest32::from_bytes(digest.into()),
        })
    }

    /// New versioned C3 body, with no text and no circular commitment to its own row hash.
    pub fn canonical_body(&self) -> Result<canon::json::Value> {
        use canon::json::Value;
        if self.version != 1 || self.algorithm != AlgorithmId::Sha256 {
            return Err(refuse("unsupported-format"));
        }
        Value::object(vec![
            ("schema".into(), Value::text("aukora-kira-save-v1".into())?),
            (
                "body".into(),
                Value::object(vec![
                    (
                        "algorithm".into(),
                        Value::text(self.algorithm.wire_name().into())?,
                    ),
                    ("note_id".into(), Value::text(self.note_id.to_string())?),
                    (
                        "encrypted_sha256".into(),
                        Value::text(self.encrypted_sha256.to_string())?,
                    ),
                ])?,
            ),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaveReceipt {
    pub commitment: SaveCommitment,
    pub cite_seq: u64,
    pub anchor: AnchorClaim,
}

/// A content-free demotion keeps both the original ciphertext and wrapped key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demotion {
    pub note_id: NoteId,
    pub save_sequence: u64,
    pub demoted_sequence: u64,
    pub demoted_at_ms: u64,
    pub head: MemoryHead,
}

pub struct SaveRequest {
    pub put: MemoryPut,
    pub origin: MemoryOrigin,
    pub form: NoteForm,
    pub at_ms: u64,
    pub review_by: Option<ReviewBy>,
}

/// Independent cell execution over memory:sha256(canon(value)), not guest digests.
pub trait SaveCell {
    /// Returns recomputed commitments over the canonical effect body plus one LF.
    fn replay(&self, content: &NoteContent) -> Result<CellCommitment>;
}

/// Storage implementation contract for worker 12. No operation removes a note or key.
/// Save requires a current store permission but never a per-note owner approval.
/// It replays the cell, compares all commitments, checks the per-principal budget,
/// preserves summary originals and commits ciphertext and content-free Aura anchor
/// atomically. An unavailable Aura append route refuses without a partial save.
/// This interface supplies no second ledger and no implementation of that route.
pub trait MemoryStore {
    fn save<T: AuthorityTxn + ?Sized, P: MemoryPermissions, C: SaveCell>(
        &mut self,
        transaction: &mut T,
        permissions: &mut P,
        context: &PermissionContext,
        cell: &C,
        request: SaveRequest,
    ) -> Result<SaveReceipt>;

    /// Verify exact demotion bytes against the consumed owner proof inside this
    /// transaction. Retain ciphertext, key, originals and save citation; invalidate
    /// the index pin before exposing success. Never store a clear-text reason.
    fn demote<T: AuthorityTxn + ?Sized>(
        &mut self,
        transaction: &mut T,
        context: &PermissionContext,
        proof: VerifiedProof,
        note_id: &NoteId,
        expected_head: MemoryHead,
        at_ms: u64,
    ) -> Result<Demotion>;
}
