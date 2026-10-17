// SPDX-License-Identifier: AGPL-3.0-or-later
//! The epoch-1 archive import.

use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportReport {
    pub imported: u64,
    /// Already in the store (a re-import, or the same line twice).
    pub duplicates: u64,
    pub secrets: u64,
    pub invalid: u64,
    /// Every skipped line: (1-based line number in the file, "secret" or "invalid").
    pub skipped: Vec<(usize, &'static str)>,
}

impl ImportReport {
    fn skip(&mut self, line: usize, why: &'static str) {
        if why == "secret" {
            self.secrets += 1;
        } else {
            self.invalid += 1;
        }
        self.skipped.push((line, why));
    }
}

fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b'+' | b'=')
}

/// `marker` (at a word start) followed by at least `tail` token bytes: a credential, not a mention of its name.
fn marked(text: &str, marker: &str, tail: usize) -> bool {
    let bytes = text.as_bytes();
    text.match_indices(marker).any(|(i, _)| {
        let starts_word = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let rest = &bytes[i + marker.len()..];
        starts_word && rest.iter().take_while(|b| token_byte(**b)).count() >= tail
    })
}

/// `name` followed (after optional quotes and spaces) by `=` or `:` and a value: an assignment, not prose.
fn assigned(lower: &str, name: &str) -> bool {
    lower.match_indices(name).any(|(i, _)| {
        let rest = lower[i + name.len()..].trim_start_matches(['"', '\'', ' ']);
        rest.strip_prefix(['=', ':']).is_some_and(|value| {
            value.trim_start_matches(['"', '\'', ' ']).bytes().take_while(|b| token_byte(*b)).count() >= 4
        })
    })
}

/// Secret-looking material, matched without regexes: PEM and key headers, nsec, `sk-`, GitHub (`ghp_`,
/// `github_pat_`), AWS (`AKIA`) and Slack (`xoxb-`) tokens, a `Bearer` credential, a `password=` or `api_key`
/// assignment, or a 64+ hex run within 48 bytes of the word "key". Over-matching only skips a note.
fn looks_secret(text: &str) -> bool {
    if ["PRIVATE KEY", "nsec1", "BEGIN OPENSSH", "-----BEGIN"].iter().any(|m| text.contains(m)) {
        return true;
    }
    let tokens = [("sk-", 1), ("ghp_", 20), ("github_pat_", 20), ("AKIA", 16), ("xoxb-", 10), ("Bearer ", 16)];
    if tokens.iter().any(|(marker, tail)| marked(text, marker, *tail)) {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    if ["password", "passwd", "api_key", "apikey"].iter().any(|name| assigned(&lower, name)) {
        return true;
    }
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

/// The text without C0 control characters other than tab, newline and carriage return (the event format refuses
/// them; the archive has a few stray escapes).
fn strip_controls(text: &str) -> String {
    text.chars().filter(|c| *c >= ' ' || matches!(c, '\t' | '\n' | '\r')).collect()
}

fn epoch1_draft(record: &Value) -> Option<NoteDraft> {
    let text = strip_controls(record.get("text")?.as_str()?);
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
/// capture import, review remembered, privacy builders, scope builders, and an `import_source` tag holding the
/// sha256 of the archive file. Secret-looking lines are skipped and every skipped line is reported by number.
pub fn import_epoch1(dir: &Path, path: &Path) -> Result<ImportReport> {
    let mut state = State::open(dir)?;
    state.store.verify_chain()?;
    if fs::symlink_metadata(key_path(dir, IMPORT_AGENT)).is_err() {
        create_agent(dir, &state.store, IMPORT_AGENT, &["*".to_owned()], false)?;
    }
    let bytes = fs::read(path).map_err(|_| refuse("import-unreadable"))?;
    let source: [u8; 32] = Sha256::digest(&bytes).into();
    let text = String::from_utf8(bytes).map_err(|_| refuse("import-unreadable"))?;
    let mut report = ImportReport::default();
    for (number, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)).filter(|(_, l)| !l.trim().is_empty()) {
        let Some(draft) = serde_json::from_str::<Value>(line).ok().as_ref().and_then(epoch1_draft) else {
            report.skip(number, "invalid");
            continue;
        };
        if looks_secret(line) || looks_secret(&draft.text) {
            report.skip(number, "secret");
            continue;
        }
        let Ok(mut tags) = draft.tags(Review::Remembered) else {
            report.skip(number, "invalid");
            continue;
        };
        tags.push(vec!["import_source".to_owned(), hex(&source)]);
        let Ok(event) = Event::sign(state.key(IMPORT_AGENT)?, IMPORT_AT, NOTE_KIND, tags, draft.text) else {
            report.skip(number, "invalid");
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
