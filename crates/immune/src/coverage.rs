// SPDX-License-Identifier: AGPL-3.0-or-later
//! Historical attack, issue and fingerprint inputs, separate from the route ratchet.

use canon::{
    digest::Digest32,
    json::{self, Value, ValueView},
    Refusal, Result,
};
use std::{collections::BTreeSet, sync::OnceLock};

pub const ARCHIVE_ATTACK_COUNT: usize = 815;
pub const AUMLOK_ISSUE_COUNT: usize = 81;
pub const PENTORA_VECTOR_COUNT: usize = 5_360;
pub const ATTACK_SHA256: &str = "6d0c66ff3fda1a3e66ff8a9af1862885647aafb47398e914310cad64c6674a90";
pub const ISSUE_EXPORT_SHA256: &str =
    "97fd71d7a7647a91deac76d048d7a3752014789404cfdf40d5b397412236b46d";

const ATTACK_BYTES: &[u8] = include_bytes!("../corpus/rt3-attacks.json");
const ISSUE_EXPORT_BYTES: usize = 797_919;
const PENTORA_INPUTS: [(&[u8], usize, &str); 2] = [
    (
        include_bytes!("../../pentora/vectors/expansion_vectors_4354.json"),
        4_354,
        "930bfbb5d8088de1c8aa94b99cdbc868505c79acde504c26b813b714c846e044",
    ),
    (
        include_bytes!("../../pentora/vectors/expansion_vectors_1006.json"),
        1_006,
        "02f5c5b9dee82b6eb36fbf02b430af50958165a6c07d7e652524183773e24529",
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttackExpectation {
    Pending {
        new_sha256: Digest32,
        after_apply: String,
        warning_count: u32,
        flags_sha256: Digest32,
    },
    Blocked {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalAttack {
    pub id: String,
    pub category: String,
    pub misleading: bool,
    pub content: String,
    pub note: String,
    pub expected: AttackExpectation,
}

/// Historical issue text is retained data, not a replay scenario or an instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalIssue<'a> {
    pub number: u16,
    pub title: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FingerprintVector {
    pub head: Digest32,
    pub expected_digest: Digest32,
    pub expected_wire: [u8; 110],
}

#[derive(Debug)]
pub struct HistoricalCorpora<'a> {
    attacks: Vec<HistoricalAttack>,
    issues: Vec<HistoricalIssue<'a>>,
    fingerprints: Vec<FingerprintVector>,
    attack_base: String,
    attack_target: String,
}

impl<'a> HistoricalCorpora<'a> {
    /// Validate supplied exact issue bytes, or decode the embedded export when absent.
    pub fn pinned(issue_export: Option<&'a [u8]>) -> Result<Self> {
        let issue_export = match issue_export {
            Some(bytes) => bytes,
            None => bundled_issue_bytes()?,
        };
        let issues = read_issues(issue_export)?;
        pin(ATTACK_BYTES, ATTACK_SHA256)?;
        let source = json::parse_strict(ATTACK_BYTES)?;
        fields(&source, 6)?;
        if text(&source, "corpus")? != "rt3-attacks"
            || integer(&source, "count")? != ARCHIVE_ATTACK_COUNT as i64
        {
            return Err(refuse("attack-corpus-schema"));
        }
        text(&source, "source")?;
        let cases = array(&source, "items")?;
        if cases.len() != ARCHIVE_ATTACK_COUNT {
            return Err(refuse("attack-corpus-count"));
        }
        let mut attacks = Vec::with_capacity(cases.len());
        let mut identifiers = BTreeSet::new();
        for case in cases {
            let attack = read_attack(case)?;
            if !identifiers.insert(attack.id.clone()) {
                return Err(refuse("attack-corpus-duplicate"));
            }
            attacks.push(attack);
        }
        let mut fingerprints = Vec::with_capacity(PENTORA_VECTOR_COUNT);
        for (bytes, count, digest) in PENTORA_INPUTS {
            pin(bytes, digest)?;
            let source = json::parse_strict(bytes)?;
            let ValueView::Array(rows) = source.view() else {
                return Err(refuse("fingerprint-corpus-schema"));
            };
            if rows.len() != count {
                return Err(refuse("fingerprint-corpus-count"));
            }
            for row in rows {
                fingerprints.push(read_fingerprint(row, count == 1_006)?);
            }
        }
        if fingerprints.len() != PENTORA_VECTOR_COUNT {
            return Err(refuse("fingerprint-corpus-count"));
        }
        Ok(Self {
            attacks,
            issues,
            fingerprints,
            attack_base: text(&source, "base")?.to_owned(),
            attack_target: text(&source, "target")?.to_owned(),
        })
    }

    pub fn attacks(&self) -> &[HistoricalAttack] {
        &self.attacks
    }

    pub fn issues(&self) -> &[HistoricalIssue<'a>] {
        &self.issues
    }

    pub fn fingerprints(&self) -> &[FingerprintVector] {
        &self.fingerprints
    }

    pub fn attack_base(&self) -> &str {
        &self.attack_base
    }

    pub fn attack_target(&self) -> &str {
        &self.attack_target
    }
}

impl HistoricalCorpora<'static> {
    /// Load all three embedded corpora once, retaining any pin or schema refusal.
    pub fn bundled() -> Result<&'static Self> {
        static CORPORA: OnceLock<Result<HistoricalCorpora<'static>>> = OnceLock::new();
        CORPORA
            .get_or_init(|| Self::pinned(None))
            .as_ref()
            .map_err(|error| *error)
    }
}

fn bundled_issue_bytes() -> Result<&'static [u8]> {
    static EXPORT: OnceLock<Result<Vec<u8>>> = OnceLock::new();
    EXPORT
        .get_or_init(bundled_issue_export)
        .as_deref()
        .map_err(|error| *error)
}

fn read_attack(row: &Value) -> Result<HistoricalAttack> {
    fields(row, 6)?;
    let expectation = row.get("expect").ok_or(refuse("attack-corpus-schema"))?;
    let expected = match text(expectation, "result")? {
        "pending" => {
            fields(expectation, 5)?;
            AttackExpectation::Pending {
                new_sha256: Digest32::from_hex(text(expectation, "new_sha")?)?,
                after_apply: text(expectation, "after_apply")?.to_owned(),
                warning_count: u32::try_from(integer(expectation, "warnings")?)
                    .map_err(|_| refuse("attack-corpus-schema"))?,
                flags_sha256: Digest32::from_hex(text(expectation, "flags_sha256")?)?,
            }
        }
        "blocked" => {
            fields(expectation, 2)?;
            let reason = text(expectation, "blocked_by")?;
            if !matches!(reason, "schema_canonical" | "identical_noop") {
                return Err(refuse("attack-corpus-schema"));
            }
            AttackExpectation::Blocked {
                reason: reason.to_owned(),
            }
        }
        _ => return Err(refuse("attack-corpus-schema")),
    };
    let misleading = match row.get("misleading").map(Value::view) {
        Some(ValueView::Boolean(value)) => value,
        _ => return Err(refuse("attack-corpus-schema")),
    };
    let id = text(row, "id")?;
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(refuse("attack-corpus-schema"));
    }
    Ok(HistoricalAttack {
        id: id.to_owned(),
        category: text(row, "category")?.to_owned(),
        misleading,
        content: text(row, "content")?.to_owned(),
        note: text(row, "note")?.to_owned(),
        expected,
    })
}

fn read_issues(bytes: &[u8]) -> Result<Vec<HistoricalIssue<'_>>> {
    if bytes.len() != ISSUE_EXPORT_BYTES {
        return Err(refuse("issue-corpus-size"));
    }
    pin(bytes, ISSUE_EXPORT_SHA256)?;
    let source = std::str::from_utf8(bytes).map_err(|_| refuse("issue-corpus-schema"))?;
    let mut issues: Vec<HistoricalIssue<'_>> = Vec::with_capacity(AUMLOK_ISSUE_COUNT);
    let mut offset = 0;
    let mut start = 0;
    for line in source.split_inclusive('\n') {
        if let Some(heading) = line.strip_prefix("## #") {
            let (number, caption) = heading
                .split_once(' ')
                .ok_or(refuse("issue-corpus-schema"))?;
            let number: u16 = number.parse().map_err(|_| refuse("issue-corpus-schema"))?;
            if usize::from(number) != issues.len() + 1 || issues.len() >= AUMLOK_ISSUE_COUNT {
                return Err(refuse("issue-corpus-order"));
            }
            let title = caption
                .strip_prefix("[OPEN] ")
                .or_else(|| caption.strip_prefix("[CLOSED] "))
                .ok_or(refuse("issue-corpus-schema"))?
                .strip_suffix('\n')
                .ok_or(refuse("issue-corpus-schema"))?;
            if title.is_empty() {
                return Err(refuse("issue-corpus-schema"));
            }
            if let Some(previous) = issues.last_mut() {
                previous.bytes = &bytes[start..offset];
            }
            start = offset;
            issues.push(HistoricalIssue {
                number,
                title,
                bytes: &[],
            });
        }
        offset += line.len();
    }
    if issues.len() != AUMLOK_ISSUE_COUNT {
        return Err(refuse("issue-corpus-count"));
    }
    issues.last_mut().ok_or(refuse("issue-corpus-count"))?.bytes = &bytes[start..];
    Ok(issues)
}

fn read_fingerprint(row: &Value, balanced: bool) -> Result<FingerprintVector> {
    fields(row, if balanced { 4 } else { 3 })?;
    let wire = text(row, "wire_hex")?.as_bytes();
    if wire.len() != 220 {
        return Err(refuse("fingerprint-corpus-schema"));
    }
    let mut expected_wire = [0_u8; 110];
    for (output, pair) in expected_wire.iter_mut().zip(wire.chunks_exact(2)) {
        if pair[0] != b'0' || !(b'0'..=b'2').contains(&pair[1]) {
            return Err(refuse("fingerprint-corpus-schema"));
        }
        *output = pair[1] - b'0';
    }
    if balanced {
        let values = array(row, "balanced")?;
        if values.len() != expected_wire.len()
            || values.iter().zip(expected_wire).any(|(value, digit)| {
                !matches!(value.view(), ValueView::Integer(number) if number.get() == i64::from(digit) - 1)
            })
        {
            return Err(refuse("fingerprint-corpus-schema"));
        }
    }
    Ok(FingerprintVector {
        head: Digest32::from_hex(text(row, "head")?)?,
        expected_digest: Digest32::from_hex(text(row, "sha256")?)?,
        expected_wire,
    })
}

fn pin(bytes: &[u8], expected: &str) -> Result<()> {
    if Digest32::sha256(bytes) == Digest32::from_hex(expected)? {
        Ok(())
    } else {
        Err(refuse("historical-corpus-pin"))
    }
}

fn fields(value: &Value, count: usize) -> Result<()> {
    match value.view() {
        ValueView::Object(fields) if fields.len() == count => Ok(()),
        _ => Err(refuse("historical-corpus-schema")),
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refuse("historical-corpus-schema")),
    }
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Array(values)) => Ok(values),
        _ => Err(refuse("historical-corpus-schema")),
    }
}

fn integer(value: &Value, key: &str) -> Result<i64> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Integer(number)) => Ok(number.get()),
        _ => Err(refuse("historical-corpus-schema")),
    }
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}

/// SHA-256 of the encoded issue export bundled for row 68.
pub const ISSUE_EXPORT_HEX_SHA256: &str =
    "4b67d465cf41c8329d38113c6f1848ef442d69208f3dcf554cdb6ba839c233c5";

/// SHA-256 of the row-68 file inventory, provenance and per-issue boundaries.
pub const HISTORICAL_MANIFEST_SHA256: &str =
    "82ac561202edaae4797b23de0c0fe29e8fd27b81095d70c2f8c30869e6511254";

/// Recover the exact pinned export as inert bytes for `HistoricalCorpora::pinned`.
/// The first hex line is the preamble; the next 81 lines are complete issue sections.
pub fn bundled_issue_export() -> Result<Vec<u8>> {
    const ENCODED: &[u8] = include_bytes!("../corpus/aumlok-id-issues-v1.hex");
    const CHUNKS: usize = AUMLOK_ISSUE_COUNT + 1;
    pin(
        include_bytes!("../corpus/pins-v1.json"),
        HISTORICAL_MANIFEST_SHA256,
    )?;
    if ENCODED.len() != ISSUE_EXPORT_BYTES * 2 + CHUNKS {
        return Err(refuse("issue-corpus-encoding-size"));
    }
    pin(ENCODED, ISSUE_EXPORT_HEX_SHA256)?;
    let text = std::str::from_utf8(ENCODED).map_err(|_| refuse("issue-corpus-encoding"))?;
    let mut decoded = Vec::with_capacity(ISSUE_EXPORT_BYTES);
    let mut chunks = 0;
    for line in text.split_terminator('\n') {
        chunks += 1;
        if chunks > CHUNKS
            || line.is_empty()
            || !line.len().is_multiple_of(2)
            || !line
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(refuse("issue-corpus-encoding"));
        }
        for pair in line.as_bytes().chunks_exact(2) {
            if decoded.len() == ISSUE_EXPORT_BYTES {
                return Err(refuse("issue-corpus-encoding-size"));
            }
            let pair = std::str::from_utf8(pair).map_err(|_| refuse("issue-corpus-encoding"))?;
            decoded
                .push(u8::from_str_radix(pair, 16).map_err(|_| refuse("issue-corpus-encoding"))?);
        }
    }
    if chunks != CHUNKS {
        return Err(refuse("issue-corpus-encoding"));
    }
    read_issues(&decoded)?;
    Ok(decoded)
}
