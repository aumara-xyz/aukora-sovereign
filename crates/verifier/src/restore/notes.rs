// SPDX-License-Identifier: AGPL-3.0-or-later
//! The memory file of an export, checked note by note against the signed history.

use super::{
    hex_any, history::Chain, shape, small, Manifest, PlannedDemotion, PlannedNote, ARCHIVE_SCHEMA,
    MAX_ENVELOPE_BYTES, MAX_MEMORY_BYTES, MAX_WRAPPED_BYTES,
};
use crate::{
    format::{canonical, digest, field, hex32, keys, object, refusal, string, text},
    report::{Verdict, VerificationReport},
};
use canon::{
    ids::NoteId,
    json::{SafeInteger, Value, ValueView},
    Result,
};
use std::collections::BTreeSet;

struct Cell {
    module: [u8; 32],
    input: [u8; 32],
    effect: [u8; 32],
}

fn line_body<'a>(line: &'a Value, kind: &str) -> Result<&'a Value> {
    shape(
        keys(line, &["schema", "kind", "body"]),
        "restore-memory-format",
    )?;
    if text(field(line, "schema")?)? != ARCHIVE_SCHEMA || text(field(line, "kind")?)? != kind {
        return Err(refusal("restore-memory-format"));
    }
    field(line, "body")
}

/// The closed shape of `aukora-kira-note-v1`; returns its `key_id` and `root_epoch`.
fn envelope(bytes: &[u8], owner: &str, id: &str) -> Result<(String, u64)> {
    let invalid = |_| refusal("restore-note-format");
    let value = canonical(bytes).map_err(invalid)?;
    shape(keys(&value, &["schema", "body"]), "restore-note-format")?;
    if text(field(&value, "schema")?)? != "aukora-kira-note-v1" {
        return Err(refusal("restore-note-format"));
    }
    let body = field(&value, "body")?;
    shape(
        keys(
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
        ),
        "restore-note-format",
    )?;
    let epoch = small(field(body, "root_epoch")?)?;
    if text(field(body, "algorithm")?)? != "xchacha20-poly1305"
        || text(field(body, "owner")?)? != owner
        || text(field(body, "note_id")?)? != id
        || epoch == 0
    {
        return Err(refusal("restore-note-format"));
    }
    hex_any(text(field(body, "nonce")?)?, 24, 24).map_err(invalid)?;
    hex_any(text(field(body, "ciphertext")?)?, 16, 65_552).map_err(invalid)?;
    let key_id = text(field(body, "key_id")?)?.to_owned();
    NoteId::new(key_id.clone()).map_err(invalid)?;
    Ok((key_id, epoch))
}

/// The closed shape of `aukora-kira-wrapped-key-v1`, bound to the same key id and epoch.
fn wrapped(bytes: &[u8], key_id: &str, epoch: u64) -> Result<()> {
    let invalid = |_| refusal("restore-note-format");
    let value = canonical(bytes).map_err(invalid)?;
    shape(
        keys(
            &value,
            &[
                "schema",
                "algorithm",
                "key_id",
                "epoch",
                "nonce",
                "ciphertext",
            ],
        ),
        "restore-note-format",
    )?;
    if text(field(&value, "schema")?)? != "aukora-kira-wrapped-key-v1"
        || text(field(&value, "algorithm")?)? != "xchacha20-poly1305"
        || text(field(&value, "key_id")?)? != key_id
        || small(field(&value, "epoch")?)? != epoch
    {
        return Err(refusal("restore-note-format"));
    }
    hex_any(text(field(&value, "nonce")?)?, 24, 24).map_err(invalid)?;
    hex_any(text(field(&value, "ciphertext")?)?, 48, 48).map_err(invalid)?;
    Ok(())
}

/// Kira's `aukora-kira-metadata-v1` digest, which the `kira.save` row commits to.
fn metadata(category: &str, at: u64, wrapped: &[u8], cell: &Cell) -> Result<[u8; 32]> {
    let value = object(vec![
        ("schema", string("aukora-kira-metadata-v1")?),
        ("category", string(category)?),
        ("at", Value::integer(SafeInteger::new(at as i64)?)),
        ("wrapped_key_sha256", string(&hex::encode(digest(wrapped)))?),
        ("module", string(&hex::encode(cell.module))?),
        ("input", string(&hex::encode(cell.input))?),
        ("effect", string(&hex::encode(cell.effect))?),
    ])?;
    Ok(digest(&value.canonical_bytes()))
}

fn head_pair(value: &Value) -> Result<(u64, Option<[u8; 32]>)> {
    shape(keys(value, &["sequence", "hash"]), "restore-memory-format")?;
    let hash = match field(value, "hash")?.view() {
        ValueView::Null => None,
        _ => Some(hex32(text(field(value, "hash")?)?)?),
    };
    let sequence = small(field(value, "sequence")?)?;
    if (sequence == 0) != hash.is_none() {
        return Err(refusal("restore-memory-format"));
    }
    Ok((sequence, hash))
}

/// Findings of the memory pass, grouped by the check they fail.
pub(super) struct Verdicts<'a> {
    pub(super) report: &'a mut VerificationReport,
    pub(super) commitments: bool,
    pub(super) complete: bool,
    pub(super) forgotten: bool,
    pub(super) heads: bool,
}

impl Verdicts<'_> {
    fn rewritten(&mut self, reason: &'static str, sequence: Option<u64>) {
        self.report.finding(
            Verdict::Rewritten,
            refusal(reason),
            sequence,
            sequence.is_some(),
        );
    }
}

pub(super) fn memory(
    bytes: &[u8],
    manifest: &Manifest,
    history: &Chain,
    verdicts: &mut Verdicts<'_>,
) -> Result<Vec<PlannedNote>> {
    let format = |_| refusal("restore-memory-format");
    if bytes.len() > MAX_MEMORY_BYTES || bytes.last() != Some(&b'\n') {
        return Err(refusal("restore-memory-format"));
    }
    let mut lines = bytes[..bytes.len() - 1].split(|b| *b == b'\n');
    let first = canonical(lines.next().ok_or(refusal("restore-memory-format"))?)?;
    let header = line_body(&first, "header")?;
    shape(
        keys(
            header,
            &["owner", "epoch", "head", "aura", "counts", "receipts"],
        ),
        "restore-memory-format",
    )?;
    let aura = field(header, "aura")?;
    shape(keys(aura, &["sequence", "hash"]), "restore-memory-format")?;
    let counts = field(header, "counts")?;
    shape(
        keys(counts, &["saved", "demoted", "quarantined"]),
        "restore-memory-format",
    )?;
    if !matches!(field(header, "receipts")?.view(), ValueView::Boolean(false)) {
        return Err(refusal("restore-memory-format"));
    }
    let head = head_pair(field(header, "head")?)?;
    let tip = (
        small(field(aura, "sequence")?).map_err(format)?,
        hex32(text(field(aura, "hash")?)?).map_err(format)?,
    );
    let (saved, demoted, quarantined) = (
        small(field(counts, "saved")?).map_err(format)?,
        small(field(counts, "demoted")?).map_err(format)?,
        small(field(counts, "quarantined")?).map_err(format)?,
    );
    if text(field(header, "owner")?)? != manifest.owner
        || small(field(header, "epoch")?)? != manifest.epoch
    {
        verdicts.heads = false;
        verdicts.rewritten("restore-header", None);
    }
    let chain_head = history.kira_head.map_or((0, None), |(s, h)| (s, Some(h)));
    if head != manifest.head || head != chain_head {
        verdicts.heads = false;
        verdicts.rewritten("restore-head", Some(head.0).filter(|s| *s > 0));
    }
    if Some(tip) != history.tip || tip != manifest.aura {
        verdicts.heads = false;
        verdicts.rewritten("restore-tip", Some(tip.0).filter(|s| *s > 0));
    }
    if (saved, demoted, quarantined) != (manifest.notes, manifest.demoted, manifest.quarantined)
        || saved != history.saves.len() as u64
        || demoted != history.demotes.len() as u64
    {
        verdicts.complete = false;
        verdicts.rewritten("restore-counts", None);
    }
    let mut plan = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut marked = 0_u64;
    let mut quarantined_seen = 0_u64;
    for _ in 0..saved {
        let Some(raw) = lines.next() else {
            verdicts.complete = false;
            verdicts.rewritten("restore-memory-truncated", None);
            break;
        };
        let line = canonical(raw)?;
        let body = line_body(&line, "note")?;
        shape(
            keys(
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
            ),
            "restore-memory-format",
        )?;
        let id = text(field(body, "note_id")?)?;
        if id.is_empty()
            || id.len() > 128
            || id.chars().any(char::is_control)
            || seen
                .iter()
                .next_back()
                .is_some_and(|last| last.as_str() >= id)
        {
            return Err(refusal("restore-memory-format"));
        }
        seen.insert(id.to_owned());
        let sealed =
            hex_any(text(field(body, "envelope")?)?, 1, MAX_ENVELOPE_BYTES).map_err(format)?;
        let wrap =
            hex_any(text(field(body, "wrapped_key")?)?, 1, MAX_WRAPPED_BYTES).map_err(format)?;
        let category = text(field(body, "category")?)?;
        let at = small(field(body, "at")?).map_err(format)?;
        let cell = field(body, "cell")?;
        shape(
            keys(cell, &["module", "input", "effect"]),
            "restore-memory-format",
        )?;
        let cell = Cell {
            module: hex32(text(field(cell, "module")?)?).map_err(format)?,
            input: hex32(text(field(cell, "input")?)?).map_err(format)?,
            effect: hex32(text(field(cell, "effect")?)?).map_err(format)?,
        };
        let cite = small(field(body, "cite_seq")?).map_err(format)?;
        let flagged = match field(body, "demotion")?.view() {
            ValueView::Null => None,
            _ => {
                let d = field(body, "demotion")?;
                shape(keys(d, &["sequence", "at"]), "restore-memory-format")?;
                Some(PlannedDemotion {
                    sequence: small(field(d, "sequence")?).map_err(format)?,
                    at_ms: small(field(d, "at")?).map_err(format)?,
                })
            }
        };
        let ValueView::Boolean(quarantine) = field(body, "quarantined")?.view() else {
            return Err(refusal("restore-memory-format"));
        };
        if category.is_empty()
            || category.len() > 64
            || !category
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(refusal("restore-memory-format"));
        }
        let (key_id, wrap_epoch) = envelope(&sealed, &manifest.owner, id)?;
        if wrap_epoch > manifest.epoch {
            return Err(refusal("restore-note-format"));
        }
        wrapped(&wrap, &key_id, wrap_epoch)?;
        match history.saves.get(id) {
            None => {
                verdicts.complete = false;
                verdicts.rewritten("restore-note-unsaved", None);
            }
            Some(save) => {
                if digest(&sealed) != save.encrypted {
                    verdicts.commitments = false;
                    verdicts.rewritten("restore-note-commitment", Some(save.seq));
                }
                if metadata(category, at, &wrap, &cell)? != save.metadata {
                    verdicts.commitments = false;
                    verdicts.rewritten("restore-note-metadata", Some(save.seq));
                }
                if cite != save.seq {
                    verdicts.commitments = false;
                    verdicts.rewritten("restore-note-citation", Some(save.seq));
                }
            }
        }
        match (history.demotes.get(id), &flagged) {
            (None, None) => {}
            (Some(d), Some(f))
                if d.seq == f.sequence && d.at == f.at_ms && d.saved == cite && d.seq > cite => {}
            (Some(d), None) => {
                // A forgotten note that came back as remembered.
                verdicts.forgotten = false;
                verdicts.rewritten("restore-forgotten", Some(d.seq));
            }
            (found, _) => {
                verdicts.forgotten = false;
                verdicts.rewritten("restore-demotion", found.map(|d| d.seq));
            }
        }
        marked += u64::from(flagged.is_some());
        quarantined_seen += u64::from(quarantine);
        plan.push(PlannedNote {
            note_id: id.to_owned(),
            key_id,
            wrap_epoch,
            cite_seq: cite,
            demoted: flagged,
            quarantined: quarantine,
        });
    }
    if lines.next().is_some() {
        return Err(refusal("restore-memory-format"));
    }
    for (id, save) in &history.saves {
        if !seen.contains(id) {
            verdicts.complete = false;
            verdicts.rewritten("restore-note-missing", Some(save.seq));
        }
    }
    for (id, demote) in &history.demotes {
        if !history.saves.contains_key(id) {
            verdicts.forgotten = false;
            verdicts.rewritten("restore-demotion", Some(demote.seq));
        }
    }
    if marked != demoted || quarantined_seen != quarantined {
        verdicts.complete = false;
        verdicts.rewritten("restore-counts", None);
    }
    Ok(plan)
}
