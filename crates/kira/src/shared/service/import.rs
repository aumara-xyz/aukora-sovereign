// SPDX-License-Identifier: AGPL-3.0-or-later
//! The epoch-1 archive import.

use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportReport {
    pub imported: u64,
    /// Already in the store (a re-import, or the same line twice).
    pub duplicates: u64,
    pub secrets: u64,
    pub invalid: u64,
}

/// Secret-looking material, matched without regexes: key headers, nsec, an `sk-` token, or a 64+ hex run within
/// 48 bytes of the word "key". Over-matching only skips a note.
fn looks_secret(text: &str) -> bool {
    if ["PRIVATE KEY", "nsec1", "BEGIN OPENSSH"].iter().any(|m| text.contains(m)) {
        return true;
    }
    let bytes = text.as_bytes();
    if text.match_indices("sk-").any(|(i, _)| i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    let lower = lower.as_bytes();
    let mut i = 0;
    while i < lower.len() {
        if !lower[i].is_ascii_hexdigit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < lower.len() && lower[i].is_ascii_hexdigit() {
            i += 1;
        }
        let window = &lower[start.saturating_sub(48)..(i + 48).min(lower.len())];
        if i - start >= 64 && window.windows(3).any(|w| w == b"key") {
            return true;
        }
    }
    false
}

fn clean_field(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().map(|c| if c.is_control() { ' ' } else { c }) {
        if out.len() + c.len_utf8() > 256 {
            break;
        }
        out.push(c);
    }
    out.trim().to_owned()
}

/// The archive's kind: its `kind` field when present (notes.enriched.jsonl), else read from the `[label]` prefix.
fn epoch1_kind(record: &Value, label: &str) -> String {
    if let Some(kind) = record.get("kind").and_then(Value::as_str) {
        return kind.to_owned();
    }
    let kind = if label.contains("NORTH-STAR row") {
        "row"
    } else if label.starts_with("conductor ruling") {
        "ruling"
    } else if label.contains("charter") {
        "charter"
    } else if label.contains("review") {
        "finding"
    } else {
        "note"
    };
    kind.to_owned()
}

fn epoch1_draft(record: &Value) -> Option<NoteDraft> {
    let text = record.get("text")?.as_str()?.to_owned();
    let label = text.strip_prefix('[').and_then(|t| t.split_once(']')).map_or("", |(l, _)| l);
    let kind = epoch1_kind(record, label);
    // An import is never a commitment: charters, rulings and plan rows stay evidence until an owner-signed manifest
    // promotes them. The original kind stays in the subject.
    let lane = if kind == "finding" { Lane::Finding } else { Lane::Evidence };
    let field = |name: &str| record.get(name).and_then(Value::as_str).unwrap_or("");
    let subject = clean_field(&format!("epoch1:{kind} {} {} [{label}]", field("from"), field("id")));
    Some(NoteDraft {
        text,
        subject,
        scope: "builders".into(),
        lane,
        form: Form::Fact,
        privacy: Privacy::Builders,
        capture: Capture::Import,
        sources: vec![],
        slot: None,
        valid_from: None,
        valid_to: None,
        epoch: 1,
    })
}

/// Imports the epoch-1 archive (JSON lines with a `text` field) as epoch-1 notes signed by `epoch1-import`:
/// capture import, review remembered, privacy builders, scope builders. Secret-looking lines are skipped.
pub fn import_epoch1(dir: &Path, path: &Path) -> Result<ImportReport> {
    let mut state = State::open(dir)?;
    if fs::symlink_metadata(key_path(dir, IMPORT_AGENT)).is_err() {
        create_agent(dir, &state.store, IMPORT_AGENT, &["*".to_owned()], false)?;
    }
    let text = fs::read_to_string(path).map_err(|_| refuse("import-unreadable"))?;
    let mut report = ImportReport::default();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some(draft) = serde_json::from_str::<Value>(line).ok().as_ref().and_then(epoch1_draft) else {
            report.invalid += 1;
            continue;
        };
        if looks_secret(line) || looks_secret(&draft.text) {
            report.secrets += 1;
            continue;
        }
        let Ok(tags) = draft.tags(Review::Remembered) else {
            report.invalid += 1;
            continue;
        };
        let Ok(event) = Event::sign(state.key(IMPORT_AGENT)?, IMPORT_AT, NOTE_KIND, tags, draft.text) else {
            report.invalid += 1;
            continue;
        };
        match state.store.append(event) {
            Ok(_) => report.imported += 1,
            Err(Refusal { reason: "note-duplicate", .. }) => report.duplicates += 1,
            Err(refusal) => return Err(refusal),
        }
    }
    Ok(report)
}
