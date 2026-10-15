// SPDX-License-Identifier: AGPL-3.0-or-later
//! Encrypted payloads and operations scoped to one Aura-owned storage transaction.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, CellCommitment, VerifiedProof},
    codes,
    digest::Digest32,
    fd3_payloads::MemoryPut,
    ids::{NoteId, SubjectId},
    provenance::{Provenance, Source},
    Result,
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
            return Err(codes::KIRA_INVALID_FIELD);
        }
        if statement.trim().is_empty() || statement.len() > MAX_STATEMENT_BYTES {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        if quote
            .as_ref()
            .is_some_and(|text| text.len() > MAX_QUOTE_BYTES)
        {
            return Err(codes::KIRA_INVALID_FIELD);
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
        use canon::json::Value;
        let mut fields = vec![
            (
                "category".into(),
                Value::checked_text(self.category.clone())?,
            ),
            (
                "statement".into(),
                Value::checked_text(self.statement.clone())?,
            ),
        ];
        if let Some(quote) = &self.quote {
            fields.push(("quote".into(), Value::checked_text(quote.clone())?));
        }
        Ok(Value::checked_object(fields)?.canonical_bytes())
    }
}

/// Ingest provenance is supplied by the supervisor's channel, never parsed from text.
/// Recalled owner-session material remains memory data, not a current instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryOrigin(Provenance);

impl MemoryOrigin {
    pub fn from_ingress(provenance: Provenance) -> Result<Self> {
        if matches!(provenance.source, Source::Stranger) {
            return Err(codes::KIRA_INVALID_FIELD);
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
            return Err(codes::KIRA_INVALID_FIELD);
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
                return Err(codes::KIRA_INVALID_FIELD);
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
            return Err(codes::KIRA_INVALID_FIELD);
        }
        if self.root_epoch == 0
            || self.root_epoch > canon::json::MAX_SAFE_INTEGER as u64
            || self.ciphertext.len() != 48
        {
            return Err(codes::KIRA_INVALID_FIELD);
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
        let len = u32::try_from(field.len()).map_err(|_| codes::KIRA_INVALID_FIELD)?;
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
            return Err(codes::KIRA_INVALID_FIELD);
        }
        if self.root_epoch == 0
            || self.root_epoch > canon::json::MAX_SAFE_INTEGER as u64
            || !(16..=MAX_NOTE_BYTES + 16).contains(&self.ciphertext.len())
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(())
    }

    /// Exactly this new versioned storage wrapper is committed by SaveCommitment.
    /// Binary fields use lowercase hex; no plaintext or unwrapped key is included.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        use canon::json::{SafeInteger, Value};
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
        let body = Value::checked_object(vec![
            (
                "algorithm".into(),
                Value::checked_text(self.algorithm.wire_name().into())?,
            ),
            ("owner".into(), Value::checked_text(self.owner.to_string())?),
            (
                "note_id".into(),
                Value::checked_text(self.note_id.to_string())?,
            ),
            (
                "key_id".into(),
                Value::checked_text(self.key_id.to_string())?,
            ),
            (
                "root_epoch".into(),
                Value::integer(SafeInteger::new(self.root_epoch as i64)?),
            ),
            ("nonce".into(), Value::checked_text(hex(&self.nonce))?),
            (
                "ciphertext".into(),
                Value::checked_text(hex(&self.ciphertext))?,
            ),
        ])?;
        Ok(Value::checked_object(vec![
            (
                "schema".into(),
                Value::checked_text("aukora-kira-note-v1".into())?,
            ),
            ("body".into(), body),
        ])?
        .canonical_bytes())
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
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Value::checked_object(vec![
            (
                "schema".into(),
                Value::checked_text("aukora-kira-save-v1".into())?,
            ),
            (
                "body".into(),
                Value::checked_object(vec![
                    (
                        "algorithm".into(),
                        Value::checked_text(self.algorithm.wire_name().into())?,
                    ),
                    (
                        "note_id".into(),
                        Value::checked_text(self.note_id.to_string())?,
                    ),
                    (
                        "encrypted_sha256".into(),
                        Value::checked_text(self.encrypted_sha256.to_string())?,
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

/// Independent execution of the pinned module, ignoring guest digests.
/// key = "memory:" || sha256(canon({category,statement,quote?})).
/// input_sha256 = sha256(canon({key,value})); effect_sha256 hashes the canonical
/// effect body followed by one LF; module_sha256 hashes the pinned module bytes.
pub trait SaveCell {
    /// Returns recomputed commitments over the canonical effect body plus one LF.
    fn replay(&self, content: &NoteContent) -> Result<CellCommitment>;
}

/// Storage implementation contract for worker 12. No operation removes a note or key.
/// Save requires a current store permission but never a per-note owner approval.
/// It replays the cell, compares all commitments, checks the per-principal budget,
/// preserves summary originals and commits ciphertext and content-free Aura anchor
/// atomically. An unavailable Aura append route refuses without a partial save.
/// The transaction adapter supplies that route; this interface owns no signer.
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

pub(crate) fn sha256(bytes: &[u8]) -> Digest32 {
    use sha2::{Digest, Sha256};
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

pub(crate) fn text(value: impl Into<String>) -> Result<canon::json::Value> {
    canon::json::Value::checked_text(value.into())
}

pub(crate) fn integer(n: u64) -> Result<canon::json::Value> {
    use canon::json::{SafeInteger, Value, MAX_SAFE_INTEGER};
    if n > MAX_SAFE_INTEGER as u64 {
        return Err(codes::KIRA_INVALID_FIELD);
    }
    Ok(Value::integer(SafeInteger::new(n as i64)?))
}

/// Storage decoding accepts only the byte-exact canonical representation.
pub(crate) fn parse_canonical(bytes: &[u8]) -> Result<canon::json::Value> {
    fn convert(value: serde_json::Value) -> Result<canon::json::Value> {
        use canon::json::{SafeInteger, Value};
        Ok(match value {
            serde_json::Value::Null => Value::null(),
            serde_json::Value::Bool(b) => Value::boolean(b),
            serde_json::Value::Number(n) => Value::integer(SafeInteger::new(
                n.as_i64().ok_or(codes::KIRA_STORE_CORRUPT)?,
            )?),
            serde_json::Value::String(s) => Value::checked_text(s)?,
            serde_json::Value::Array(a) => {
                Value::checked_array(a.into_iter().map(convert).collect::<Result<_>>()?)?
            }
            serde_json::Value::Object(o) => Value::checked_object(
                o.into_iter()
                    .map(|(k, v)| Ok((k, convert(v)?)))
                    .collect::<Result<_>>()?,
            )?,
        })
    }
    let parsed = convert(serde_json::from_slice(bytes).map_err(|_| codes::KIRA_STORE_CORRUPT)?)?;
    if parsed.canonical_bytes() != bytes {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    Ok(parsed)
}

pub(crate) fn field<'a>(
    value: &'a canon::json::Value,
    key: &str,
) -> Result<&'a canon::json::Value> {
    value.get(key).ok_or(codes::KIRA_STORE_CORRUPT)
}
pub(crate) fn string(value: &canon::json::Value) -> Result<&str> {
    match value.view() {
        canon::json::ValueView::Text(s) => Ok(s),
        _ => Err(codes::KIRA_STORE_CORRUPT),
    }
}
pub(crate) fn number(value: &canon::json::Value) -> Result<u64> {
    match value.view() {
        canon::json::ValueView::Integer(n) if n.get() >= 0 => Ok(n.get() as u64),
        _ => Err(codes::KIRA_STORE_CORRUPT),
    }
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let part = std::str::from_utf8(p).map_err(|_| codes::KIRA_STORE_CORRUPT)?;
            u8::from_str_radix(part, 16).map_err(|_| codes::KIRA_STORE_CORRUPT)
        })
        .collect()
}

/// The clear payload exists only while sealing or after authenticated decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePayload {
    pub content: NoteContent,
    pub origin: MemoryOrigin,
    pub form: NoteForm,
    pub at_ms: u64,
    pub review_by: Option<ReviewBy>,
    pub root_epoch: u64,
}

impl NotePayload {
    pub fn canonical_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        use canon::json::Value;
        self.form.validate()?;
        if self.root_epoch == 0 {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        let source = match &self.origin.recorded_source().source {
            Source::Owner => text("owner")?,
            Source::Auma => text("auma")?,
            Source::Document => text("document")?,
            Source::Memory => text("memory")?,
            Source::App(id) => Value::checked_object(vec![("app".into(), text(id.to_string())?)])?,
            Source::Contact(id) => {
                Value::checked_object(vec![("contact".into(), text(id.as_str())?)])?
            }
            Source::Stranger => return Err(codes::KIRA_INVALID_FIELD),
        };
        let originals = match &self.form {
            NoteForm::Original => Value::null(),
            NoteForm::Summary { originals } => Value::checked_array(
                originals
                    .iter()
                    .map(|id| text(id.to_string()))
                    .collect::<Result<_>>()?,
            )?,
        };
        let value = Value::checked_object(vec![
            ("schema".into(), text("aukora-kira-payload-v1")?),
            (
                "content".into(),
                parse_canonical(&self.content.canonical_value()?)?,
            ),
            ("origin".into(), source),
            ("originals".into(), originals),
            ("at".into(), integer(self.at_ms)?),
            ("epoch".into(), integer(self.root_epoch)?),
            (
                "review_by".into(),
                self.review_by
                    .map(|r| integer(r.at_ms()))
                    .transpose()?
                    .unwrap_or_else(Value::null),
            ),
        ])?;
        let bytes = Zeroizing::new(value.canonical_bytes());
        if bytes.len() > MAX_NOTE_BYTES {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        use canon::json::ValueView;
        if bytes.len() > MAX_NOTE_BYTES {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        let value = parse_canonical(bytes)?;
        if string(field(&value, "schema")?)? != "aukora-kira-payload-v1" {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        let c = field(&value, "content")?;
        let content = NoteContent::new(
            string(field(c, "category")?)?.into(),
            string(field(c, "statement")?)?.into(),
            c.get("quote").map(string).transpose()?.map(str::to_owned),
        )?;
        let source = field(&value, "origin")?;
        let source = match source.view() {
            ValueView::Text("owner") => Source::Owner,
            ValueView::Text("auma") => Source::Auma,
            ValueView::Text("document") => Source::Document,
            ValueView::Text("memory") => Source::Memory,
            ValueView::Object(m) if m.len() == 1 && m[0].0 == "app" => {
                Source::App(canon::ids::AppId::from_hex(string(&m[0].1)?)?)
            }
            ValueView::Object(m) if m.len() == 1 && m[0].0 == "contact" => Source::Contact(
                canon::provenance::Npub::from_memory_address(string(&m[0].1)?)?,
            ),
            _ => return Err(codes::KIRA_STORE_CORRUPT),
        };
        let form = match field(&value, "originals")?.view() {
            ValueView::Null => NoteForm::Original,
            ValueView::Array(a) => NoteForm::Summary {
                originals: a
                    .iter()
                    .map(|v| NoteId::new(string(v)?.into()))
                    .collect::<Result<_>>()?,
            },
            _ => return Err(codes::KIRA_STORE_CORRUPT),
        };
        let review_by = match field(&value, "review_by")?.view() {
            ValueView::Null => None,
            _ => Some(ReviewBy::new(number(field(&value, "review_by")?)?)?),
        };
        let payload = Self {
            content,
            origin: MemoryOrigin::from_ingress(Provenance { source })?,
            form,
            at_ms: number(field(&value, "at")?)?,
            review_by,
            root_epoch: number(field(&value, "epoch")?)?,
        };
        if payload.canonical_bytes()?.as_slice() != bytes {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        Ok(payload)
    }
}

#[derive(Default)]
pub struct XChaChaCipher;

impl NoteCipher for XChaChaCipher {
    fn seal(
        &self,
        key: &MemoryKey,
        owner: &SubjectId,
        note: &NoteId,
        key_id: &NoteId,
        root_epoch: u64,
        canonical_payload: &[u8],
    ) -> Result<EncryptedNote> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            XChaCha20Poly1305, XNonce,
        };
        if canonical_payload.len() > MAX_NOTE_BYTES
            || root_epoch == 0
            || root_epoch > canon::json::MAX_SAFE_INTEGER as u64
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        parse_canonical(canonical_payload)?;
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| codes::KIRA_RANDOM_UNAVAILABLE)?;
        let aad = associated_data(owner, note, key_id)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.bytes())
            .map_err(|_| codes::KIRA_INVALID_FIELD)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: canonical_payload,
                    aad: &aad,
                },
            )
            .map_err(|_| codes::KIRA_AUTHENTICATION_FAILED)?;
        Ok(EncryptedNote {
            version: 1,
            algorithm: AlgorithmId::XChaCha20Poly1305,
            owner: *owner,
            note_id: note.clone(),
            key_id: key_id.clone(),
            root_epoch,
            nonce,
            ciphertext,
        })
    }
    fn open(&self, key: &MemoryKey, encrypted: &EncryptedNote) -> Result<Zeroizing<Vec<u8>>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            XChaCha20Poly1305, XNonce,
        };
        encrypted.validate()?;
        let aad = associated_data(&encrypted.owner, &encrypted.note_id, &encrypted.key_id)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.bytes())
            .map_err(|_| codes::KIRA_INVALID_FIELD)?;
        let clear = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(encrypted.nonce),
                    Payload {
                        msg: &encrypted.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| codes::KIRA_AUTHENTICATION_FAILED)?,
        );
        parse_canonical(&clear)?;
        Ok(clear)
    }
}

impl SaveReceipt {
    pub fn validate(&self) -> Result<()> {
        self.anchor.validate()?;
        self.commitment.canonical_body()?;
        if self.cite_seq == 0 || self.cite_seq > self.anchor.head.sequence {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        Ok(())
    }
}
impl Demotion {
    pub fn validate(&self) -> Result<()> {
        self.head.validate()?;
        if self.save_sequence == 0
            || self.demoted_sequence <= self.save_sequence
            || self.demoted_sequence > self.head.sequence
            || self.demoted_at_ms > canon::json::MAX_SAFE_INTEGER as u64
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(())
    }
    /// Exact target bytes for the owner card; reasons and plaintext are excluded.
    pub fn target_bytes(note: &NoteId, saved: u64, head: MemoryHead) -> Result<Vec<u8>> {
        use canon::json::Value;
        head.validate()?;
        if saved == 0 || saved > head.sequence {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(Value::checked_object(vec![
            ("schema".into(), text("aukora-kira-demote-v1")?),
            (
                "body".into(),
                Value::checked_object(vec![
                    ("note_id".into(), text(note.to_string())?),
                    ("save_sequence".into(), integer(saved)?),
                    ("head_sequence".into(), integer(head.sequence)?),
                    (
                        "head_hash".into(),
                        head.hash
                            .map(|h| text(h.to_string()))
                            .transpose()?
                            .unwrap_or_else(Value::null),
                    ),
                ])?,
            ),
        ])?
        .canonical_bytes())
    }
}
