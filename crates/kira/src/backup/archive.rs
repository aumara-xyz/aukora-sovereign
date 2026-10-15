// SPDX-License-Identifier: AGPL-3.0-or-later
//! The lossless archive `aukora-kira-archive-v1`, shared by the sealed backup (row 60) and the
//! member exit (row 61). It is JSON Lines: one canonical C1 object per line, each ending in LF.

use super::BACKUP_ARCHIVE;
use crate::{
    anchor::{wrapped_bytes, AnchorClaim, MemoryCounts, MemoryHead, MemorySnapshot},
    notes::{self, NoteContent},
};
use canon::{
    authority::CellCommitment,
    digest::Digest32,
    ids::{NoteId, SubjectId},
    json::{self, Value, ValueView, MAX_SAFE_INTEGER},
    Result,
};
use zeroize::Zeroizing;

/// The `schema` of every line of an archive.
pub const ARCHIVE_SCHEMA: &str = "aukora-kira-archive-v1";
/// Largest archive, before sealing, that this module will build or accept.
pub const MAX_ARCHIVE_BYTES: usize = 268_435_456;

const MAX_ENVELOPE_BYTES: usize = 2 * notes::MAX_NOTE_BYTES + 4_096;
const MAX_WRAPPED_BYTES: usize = 1_024;
const COLD_PROOF_SCHEMA: &str = "aukora-aura-cold-proof-v1";

// ---- the archive -----------------------------------------------------------------------------

/// A demotion marker as the store keeps it. The reason is never stored, anywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedDemotion {
    /// Aura sequence of the `kira.demote` row.
    pub demoted_sequence: u64,
    /// Time of that row, milliseconds.
    pub demoted_at_ms: u64,
}

/// One retained note exactly as the store holds it: ciphertext and wrapped key, byte for byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedNote {
    /// The original note id; restore never mints another.
    pub note_id: NoteId,
    /// Canonical `aukora-kira-note-v1` bytes, whose SHA-256 the `kira.save` row commits to.
    pub envelope: Vec<u8>,
    /// Canonical `aukora-kira-wrapped-key-v1` bytes.
    pub wrapped_key: Vec<u8>,
    /// Retained category (the store keeps it in the clear).
    pub category: String,
    /// Save time, milliseconds.
    pub at_ms: u64,
    /// Cell commitments recorded with the save.
    pub cell: CellCommitment,
    /// Aura sequence of the `kira.save` row, the note's citation.
    pub cite_seq: u64,
    /// Present for a forgotten note; a forgotten note stays forgotten across restore.
    pub demotion: Option<ArchivedDemotion>,
    /// The ledger's quarantine state when the archive was cut.
    pub quarantined: bool,
}

/// Kira's retained metadata, encrypted note payloads and wrapped keys at one verified head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryArchive {
    /// The owner whose notes these are.
    pub owner: SubjectId,
    /// The root wrapping epoch the archive was cut under.
    pub key_epoch: u64,
    /// Kira's verified head.
    pub head: MemoryHead,
    /// Aura's tip when the archive was cut.
    pub aura_sequence: u64,
    /// Hash of that tip.
    pub aura_hash: Digest32,
    /// Committed counts at that head.
    pub counts: MemoryCounts,
    /// Notes in strictly increasing note-id order.
    pub notes: Vec<ArchivedNote>,
    /// Optional canonical `aukora-aura-cold-proof-v1` bytes covering the Aura tip, so one sealed
    /// backup carries the signed history that makes it verifiable.
    pub receipts: Option<Vec<u8>>,
}

pub(super) fn obj(members: Vec<(&str, Value)>) -> Result<Value> {
    Value::checked_object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

fn member<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(BACKUP_ARCHIVE)
}

fn exact_keys(value: &Value, keys: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(members)
            if members.len() == keys.len() && keys.iter().all(|k| value.get(k).is_some()) =>
        {
            Ok(())
        }
        _ => Err(BACKUP_ARCHIVE),
    }
}

fn text_of(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(s) => Ok(s),
        _ => Err(BACKUP_ARCHIVE),
    }
}

fn unsigned(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(n) if n.get() >= 0 => Ok(n.get() as u64),
        _ => Err(BACKUP_ARCHIVE),
    }
}

fn boolean_of(value: &Value) -> Result<bool> {
    match value.view() {
        ValueView::Boolean(b) => Ok(b),
        _ => Err(BACKUP_ARCHIVE),
    }
}

fn digest_of(value: &Value) -> Result<Digest32> {
    Digest32::from_hex(text_of(value)?).map_err(|_| BACKUP_ARCHIVE)
}

fn bytes_of(value: &Value, limit: usize) -> Result<Vec<u8>> {
    let hex = text_of(value)?;
    if hex.is_empty() || hex.len() > limit * 2 {
        return Err(BACKUP_ARCHIVE);
    }
    notes::unhex(hex).map_err(|_| BACKUP_ARCHIVE)
}

pub(super) fn head_value(head: MemoryHead) -> Result<Value> {
    obj(vec![
        ("sequence", notes::integer(head.sequence)?),
        (
            "hash",
            match head.hash {
                Some(hash) => notes::text(hash.to_string())?,
                None => Value::null(),
            },
        ),
    ])
}

fn head_of(value: &Value) -> Result<MemoryHead> {
    exact_keys(value, &["sequence", "hash"])?;
    let hash = match member(value, "hash")?.view() {
        ValueView::Null => None,
        _ => Some(digest_of(member(value, "hash")?)?),
    };
    MemoryHead {
        version: 1,
        sequence: unsigned(member(value, "sequence")?)?,
        hash,
    }
    .validate()
    .map_err(|_| BACKUP_ARCHIVE)
}

/// Strict C1 reading of one canonical line, byte for byte.
fn canonical_line(raw: &[u8]) -> Result<Value> {
    let value = json::parse_strict(raw).map_err(|_| BACKUP_ARCHIVE)?;
    if value.canonical_bytes() != raw {
        return Err(BACKUP_ARCHIVE);
    }
    Ok(value)
}

/// The body of a line that must carry exactly this kind.
fn line_body<'a>(line: &'a Value, kind: &str) -> Result<&'a Value> {
    exact_keys(line, &["schema", "kind", "body"])?;
    if text_of(member(line, "schema")?)? != ARCHIVE_SCHEMA
        || text_of(member(line, "kind")?)? != kind
    {
        return Err(BACKUP_ARCHIVE);
    }
    member(line, "body")
}

fn push_line(out: &mut Vec<u8>, kind: &str, body: Value) -> Result<()> {
    let line = obj(vec![
        ("schema", notes::text(ARCHIVE_SCHEMA)?),
        ("kind", notes::text(kind)?),
        ("body", body),
    ])?;
    out.extend_from_slice(&line.canonical_bytes());
    out.push(b'\n');
    if out.len() > MAX_ARCHIVE_BYTES {
        return Err(BACKUP_ARCHIVE);
    }
    Ok(())
}

/// Structural reading of a cold proof the archive carries. Signatures are not checked here:
/// Kira has no verifier. Aura's import and the stranger verifier do that.
fn cold_proof(bytes: &[u8], aura_sequence: u64, aura_hash: &Digest32) -> Result<Value> {
    let proof = canonical_line(bytes)?;
    exact_keys(&proof, &["schema", "publicKey", "head", "rows"])?;
    if text_of(member(&proof, "schema")?)? != COLD_PROOF_SCHEMA {
        return Err(BACKUP_ARCHIVE);
    }
    let ValueView::Array(rows) = member(&proof, "rows")?.view() else {
        return Err(BACKUP_ARCHIVE);
    };
    if rows.len() as u64 != aura_sequence {
        return Err(BACKUP_ARCHIVE);
    }
    if aura_sequence == 0 {
        return if rows.is_empty() {
            Ok(proof)
        } else {
            Err(BACKUP_ARCHIVE)
        };
    }
    let index = usize::try_from(aura_sequence - 1).map_err(|_| BACKUP_ARCHIVE)?;
    let row = rows.get(index).ok_or(BACKUP_ARCHIVE)?;
    if unsigned(member(row, "seq")?)? != aura_sequence
        || digest_of(member(row, "hash")?)? != *aura_hash
    {
        return Err(BACKUP_ARCHIVE);
    }
    Ok(proof)
}

fn check_envelope(owner: &SubjectId, id: &NoteId, bytes: &[u8]) -> Result<(NoteId, u64)> {
    let envelope = canonical_line(bytes)?;
    exact_keys(&envelope, &["schema", "body"])?;
    let body = member(&envelope, "body")?;
    exact_keys(
        body,
        &[
            "algorithm",
            "owner",
            "note_id",
            "key_id",
            "root_epoch",
            "nonce",
            "ciphertext",
        ],
    )?;
    if text_of(member(&envelope, "schema")?)? != "aukora-kira-note-v1"
        || text_of(member(body, "note_id")?)? != id.as_str()
        || text_of(member(body, "owner")?)? != owner.to_string()
        || text_of(member(body, "algorithm")?)? != "xchacha20-poly1305"
        || bytes_of(member(body, "nonce")?, 24)?.len() != 24
        || bytes_of(member(body, "ciphertext")?, notes::MAX_NOTE_BYTES + 16)?.len() < 16
    {
        return Err(BACKUP_ARCHIVE);
    }
    Ok((
        NoteId::new(text_of(member(body, "key_id")?)?.to_owned()).map_err(|_| BACKUP_ARCHIVE)?,
        unsigned(member(body, "root_epoch")?)?,
    ))
}

fn check_wrapped(bytes: &[u8]) -> Result<(NoteId, u64)> {
    let wrapped = canonical_line(bytes)?;
    exact_keys(
        &wrapped,
        &[
            "schema",
            "algorithm",
            "key_id",
            "epoch",
            "nonce",
            "ciphertext",
        ],
    )?;
    if text_of(member(&wrapped, "schema")?)? != "aukora-kira-wrapped-key-v1"
        || text_of(member(&wrapped, "algorithm")?)? != "xchacha20-poly1305"
        || bytes_of(member(&wrapped, "nonce")?, 24)?.len() != 24
        || bytes_of(member(&wrapped, "ciphertext")?, 48)?.len() != 48
    {
        return Err(BACKUP_ARCHIVE);
    }
    Ok((
        NoteId::new(text_of(member(&wrapped, "key_id")?)?.to_owned())
            .map_err(|_| BACKUP_ARCHIVE)?,
        unsigned(member(&wrapped, "epoch")?)?,
    ))
}

impl MemoryArchive {
    /// The anchor claim these fields describe.
    pub fn anchor(&self) -> AnchorClaim {
        AnchorClaim {
            owner: self.owner,
            head: self.head,
            counts: self.counts,
            aura_sequence: self.aura_sequence,
            aura_hash: self.aura_hash,
        }
    }

    /// Cut an archive from a snapshot that the ledger adapter verified against Aura in the
    /// caller's transaction. A snapshot assembled any other way must not reach this function.
    pub fn from_snapshot(
        snapshot: &MemorySnapshot,
        key_epoch: u64,
        receipts: Option<Vec<u8>>,
    ) -> Result<Self> {
        let mut records = Vec::with_capacity(snapshot.notes.len());
        for (id, note) in &snapshot.notes {
            let demotion = match &note.demotion {
                Some(d) => {
                    d.validate()?;
                    Some(ArchivedDemotion {
                        demoted_sequence: d.demoted_sequence,
                        demoted_at_ms: d.demoted_at_ms,
                    })
                }
                None => None,
            };
            records.push(ArchivedNote {
                note_id: id.clone(),
                envelope: note.encrypted.canonical_bytes()?,
                wrapped_key: wrapped_bytes(&note.wrapped_key)?,
                category: note.category.clone(),
                at_ms: note.at_ms,
                cell: note.cell,
                cite_seq: note.receipt.cite_seq,
                demotion,
                quarantined: note.quarantined,
            });
        }
        let archive = Self {
            owner: snapshot.anchor.owner,
            key_epoch,
            head: snapshot.anchor.head,
            aura_sequence: snapshot.anchor.aura_sequence,
            aura_hash: snapshot.anchor.aura_hash,
            counts: snapshot.anchor.counts,
            notes: records,
            receipts,
        };
        archive.validate()?;
        Ok(archive)
    }

    /// Every rule that does not need Aura: shape, counts, order and citation bounds.
    pub fn validate(&self) -> Result<()> {
        self.anchor().validate()?;
        if self.key_epoch == 0 || self.key_epoch > MAX_SAFE_INTEGER as u64 {
            return Err(BACKUP_ARCHIVE);
        }
        let (mut demoted, mut quarantined) = (0_u64, 0_u64);
        for (index, note) in self.notes.iter().enumerate() {
            if index > 0 && self.notes[index - 1].note_id >= note.note_id {
                return Err(BACKUP_ARCHIVE);
            }
            NoteContent::new(note.category.clone(), "metadata".into(), None)
                .map_err(|_| BACKUP_ARCHIVE)?;
            if note.at_ms > MAX_SAFE_INTEGER as u64
                || note.cite_seq == 0
                || note.cite_seq > self.head.sequence
            {
                return Err(BACKUP_ARCHIVE);
            }
            if note.envelope.len() > MAX_ENVELOPE_BYTES
                || note.wrapped_key.len() > MAX_WRAPPED_BYTES
            {
                return Err(BACKUP_ARCHIVE);
            }
            let key = check_envelope(&self.owner, &note.note_id, &note.envelope)?;
            if check_wrapped(&note.wrapped_key)? != key || key.1 == 0 || key.1 > self.key_epoch {
                return Err(BACKUP_ARCHIVE);
            }
            if let Some(d) = &note.demotion {
                demoted += 1;
                if d.demoted_sequence <= note.cite_seq
                    || d.demoted_sequence > self.head.sequence
                    || d.demoted_at_ms > MAX_SAFE_INTEGER as u64
                {
                    return Err(BACKUP_ARCHIVE);
                }
            }
            quarantined += u64::from(note.quarantined);
        }
        if self.notes.len() as u64 != self.counts.saved
            || demoted != self.counts.demoted
            || quarantined != self.counts.quarantined
        {
            return Err(BACKUP_ARCHIVE);
        }
        if let Some(receipts) = &self.receipts {
            cold_proof(receipts, self.aura_sequence, &self.aura_hash)?;
        }
        Ok(())
    }

    fn header(&self) -> Result<Value> {
        obj(vec![
            ("owner", notes::text(self.owner.to_string())?),
            ("epoch", notes::integer(self.key_epoch)?),
            ("head", head_value(self.head)?),
            (
                "aura",
                obj(vec![
                    ("sequence", notes::integer(self.aura_sequence)?),
                    ("hash", notes::text(self.aura_hash.to_string())?),
                ])?,
            ),
            (
                "counts",
                obj(vec![
                    ("saved", notes::integer(self.counts.saved)?),
                    ("demoted", notes::integer(self.counts.demoted)?),
                    ("quarantined", notes::integer(self.counts.quarantined)?),
                ])?,
            ),
            ("receipts", Value::boolean(self.receipts.is_some())),
        ])
    }

    /// The archive as JSON Lines: one header line, one line per note in note-id order and, when
    /// present, one receipts line, each a canonical C1 object ending in LF. Anyone with `jq`,
    /// `xxd` and `sha256sum` can read it.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::new());
        push_line(&mut out, "header", self.header()?)?;
        for note in &self.notes {
            let demotion = match &note.demotion {
                Some(d) => obj(vec![
                    ("sequence", notes::integer(d.demoted_sequence)?),
                    ("at", notes::integer(d.demoted_at_ms)?),
                ])?,
                None => Value::null(),
            };
            let body = obj(vec![
                ("note_id", notes::text(note.note_id.as_str())?),
                ("envelope", notes::text(notes::hex(&note.envelope))?),
                ("wrapped_key", notes::text(notes::hex(&note.wrapped_key))?),
                ("category", notes::text(note.category.as_str())?),
                ("at", notes::integer(note.at_ms)?),
                (
                    "cell",
                    obj(vec![
                        ("module", notes::text(note.cell.module_sha256.to_string())?),
                        ("input", notes::text(note.cell.input_sha256.to_string())?),
                        ("effect", notes::text(note.cell.effect_sha256.to_string())?),
                    ])?,
                ),
                ("cite_seq", notes::integer(note.cite_seq)?),
                ("demotion", demotion),
                ("quarantined", Value::boolean(note.quarantined)),
            ])?;
            push_line(&mut out, "note", body)?;
        }
        if let Some(receipts) = &self.receipts {
            let proof = cold_proof(receipts, self.aura_sequence, &self.aura_hash)?;
            push_line(&mut out, "receipts", proof)?;
        }
        Ok(out)
    }

    /// Read an archive. Anything outside the closed format, anything not canonical byte for byte,
    /// and any count that disagrees with the lines refuses.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ARCHIVE_BYTES || bytes.last() != Some(&b'\n') {
            return Err(BACKUP_ARCHIVE);
        }
        let mut lines = bytes[..bytes.len() - 1].split(|b| *b == b'\n');
        let first = canonical_line(lines.next().ok_or(BACKUP_ARCHIVE)?)?;
        let header = line_body(&first, "header")?;
        exact_keys(
            header,
            &["owner", "epoch", "head", "aura", "counts", "receipts"],
        )?;
        let owner =
            SubjectId::parse(text_of(member(header, "owner")?)?).map_err(|_| BACKUP_ARCHIVE)?;
        let aura = member(header, "aura")?;
        exact_keys(aura, &["sequence", "hash"])?;
        let counts = member(header, "counts")?;
        exact_keys(counts, &["saved", "demoted", "quarantined"])?;
        let counts = MemoryCounts {
            saved: unsigned(member(counts, "saved")?)?,
            demoted: unsigned(member(counts, "demoted")?)?,
            quarantined: unsigned(member(counts, "quarantined")?)?,
        };
        let mut records = Vec::new();
        for _ in 0..counts.saved {
            let line = canonical_line(lines.next().ok_or(BACKUP_ARCHIVE)?)?;
            records.push(note_of(line_body(&line, "note")?)?);
        }
        let receipts = if boolean_of(member(header, "receipts")?)? {
            let line = canonical_line(lines.next().ok_or(BACKUP_ARCHIVE)?)?;
            Some(line_body(&line, "receipts")?.canonical_bytes())
        } else {
            None
        };
        if lines.next().is_some() {
            return Err(BACKUP_ARCHIVE);
        }
        let archive = Self {
            owner,
            key_epoch: unsigned(member(header, "epoch")?)?,
            head: head_of(member(header, "head")?)?,
            aura_sequence: unsigned(member(aura, "sequence")?)?,
            aura_hash: digest_of(member(aura, "hash")?)?,
            counts,
            notes: records,
            receipts,
        };
        archive.validate()?;
        Ok(archive)
    }
}

fn note_of(body: &Value) -> Result<ArchivedNote> {
    exact_keys(
        body,
        &[
            "note_id",
            "envelope",
            "wrapped_key",
            "category",
            "at",
            "cell",
            "cite_seq",
            "demotion",
            "quarantined",
        ],
    )?;
    let cell = member(body, "cell")?;
    exact_keys(cell, &["module", "input", "effect"])?;
    let demotion = match member(body, "demotion")?.view() {
        ValueView::Null => None,
        _ => {
            let d = member(body, "demotion")?;
            exact_keys(d, &["sequence", "at"])?;
            Some(ArchivedDemotion {
                demoted_sequence: unsigned(member(d, "sequence")?)?,
                demoted_at_ms: unsigned(member(d, "at")?)?,
            })
        }
    };
    Ok(ArchivedNote {
        note_id: NoteId::new(text_of(member(body, "note_id")?)?.to_owned())
            .map_err(|_| BACKUP_ARCHIVE)?,
        envelope: bytes_of(member(body, "envelope")?, MAX_ENVELOPE_BYTES)?,
        wrapped_key: bytes_of(member(body, "wrapped_key")?, MAX_WRAPPED_BYTES)?,
        category: text_of(member(body, "category")?)?.to_owned(),
        at_ms: unsigned(member(body, "at")?)?,
        cell: CellCommitment {
            module_sha256: digest_of(member(cell, "module")?)?,
            input_sha256: digest_of(member(cell, "input")?)?,
            effect_sha256: digest_of(member(cell, "effect")?)?,
        },
        cite_seq: unsigned(member(body, "cite_seq")?)?,
        demotion,
        quarantined: boolean_of(member(body, "quarantined")?)?,
    })
}
