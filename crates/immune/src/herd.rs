// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retained replay data can grow; an import has no retirement or authority path.

use canon::{
    digest::Digest32,
    json::{self, Value, ValueView},
    Refusal, Result,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use crate::{
    hostile::{Limits, Usage},
    ratchet::PINNED_FILES,
};

pub const MAX_RETAINED_CASES: usize = 16_384;
pub const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_IMPORT_CASES: usize = 32;
pub const MAX_INPUT_BYTES: usize = 16_384;
const CASE_DOMAIN: &[u8] = b"aukora:antibody:v1\0";

/// Implemented by local wiring around a signature-verified Nostr announcement.
/// Neither the author nor its claimed corpus root selects the local inventory.
pub trait AuthenticatedAntibodies {
    fn source_event(&self) -> Digest32;
    fn author(&self) -> [u8; 32];
    fn canonical_cases(&self) -> Result<Vec<Vec<u8>>>;
}

/// Only locally installed, bounded replay engines may interpret imported data.
pub trait EngineRegistry {
    fn supports(&self, engine: &str, format_version: u16) -> bool;
    fn accepts_refusal(&self, refusal: &str) -> bool;
}

/// The installed engine supplies actual refusal observations and host resource
/// measurements. Its budget must interrupt blocked work at the configured deadline.
pub trait HerdReplay {
    fn configure_budget(&mut self, limits: Limits) -> Result<()>;
    fn check(&mut self, case: &RetainedCase) -> Result<String>;
    fn resource_usage(&mut self) -> Result<Usage>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayFacts {
    pub corpus_root: Digest32,
    pub attempted: u32,
    pub passed: u32,
    pub failures: Vec<Digest32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedCase {
    id: Digest32,
    engine: String,
    format_version: u16,
    expected_refusal: String,
    input_b64: String,
    bytes: Vec<u8>,
}

impl RetainedCase {
    pub const fn id(&self) -> Digest32 {
        self.id
    }
    pub fn engine(&self) -> &str {
        &self.engine
    }
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }
    pub fn expected_refusal(&self) -> &str {
        &self.expected_refusal
    }
    pub fn input_b64(&self) -> &str {
        &self.input_b64
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn read(bytes: Vec<u8>, registry: &impl EngineRegistry) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 24_000 {
            return Err(refuse("herd-case-limit"));
        }
        let value = json::parse_strict(&bytes)?;
        if value.canonical_bytes() != bytes {
            return Err(refuse("herd-not-canonical"));
        }
        match value.view() {
            ValueView::Object(fields)
                if fields.len() == 5
                    && fields.iter().all(|(key, _)| {
                        [
                            "id",
                            "engine",
                            "format_version",
                            "input_b64",
                            "expected_refusal",
                        ]
                        .contains(&key.as_str())
                    }) => {}
            _ => return Err(refuse("herd-case-schema")),
        }
        let id = Digest32::from_hex(text(&value, "id")?).map_err(|_| refuse("herd-case-id"))?;
        let version = match value.get("format_version").map(Value::view) {
            Some(ValueView::Integer(number)) => {
                u16::try_from(number.get()).map_err(|_| refuse("herd-engine"))?
            }
            _ => return Err(refuse("herd-engine")),
        };
        let engine = text(&value, "engine")?;
        if !token(engine, b"-_") || !registry.supports(engine, version) {
            return Err(refuse("herd-engine"));
        }
        let expected = text(&value, "expected_refusal")?;
        let (organ, reason) = expected.split_once(':').ok_or(refuse("herd-refusal"))?;
        if !token(organ, b"-_") || !token(reason, b"-_.") || !registry.accepts_refusal(expected) {
            return Err(refuse("herd-refusal"));
        }
        let input = text(&value, "input_b64")?;
        check_base64(input)?;
        let body = match value.view() {
            ValueView::Object(fields) => Value::object(
                fields
                    .iter()
                    .filter(|(key, _)| key != "id")
                    .cloned()
                    .collect(),
            )?,
            _ => return Err(refuse("herd-case-schema")),
        };
        let mut preimage = CASE_DOMAIN.to_vec();
        preimage.extend_from_slice(&body.canonical_bytes());
        if Digest32::sha256(&preimage) != id {
            return Err(refuse("herd-case-id"));
        }
        Ok(Self {
            id,
            engine: engine.into(),
            format_version: version,
            expected_refusal: expected.into(),
            input_b64: input.into(),
            bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportOutcome {
    pub source_event: Digest32,
    pub author: [u8; 32],
    pub previous_root: Digest32,
    pub retained_root: Digest32,
    pub inserted: Vec<Digest32>,
    pub already_present: Vec<Digest32>,
}

#[derive(Debug)]
pub struct HerdStore {
    floor: BTreeMap<String, &'static [u8]>,
    imported: BTreeMap<Digest32, RetainedCase>,
    bytes: usize,
    root: Digest32,
}

impl HerdStore {
    /// The floor is embedded locally; an announcement cannot supply its replacement.
    pub fn pinned() -> Result<Self> {
        let mut floor = BTreeMap::new();
        let mut total = 0_usize;
        for bytes in PINNED_FILES {
            let value = json::parse_strict(bytes)?;
            if value.canonical_bytes() != bytes {
                return Err(refuse("herd-floor"));
            }
            let id = text(&value, "id")?.to_owned();
            total = total.checked_add(bytes.len()).ok_or(refuse("herd-limit"))?;
            if floor.insert(id, bytes).is_some() {
                return Err(refuse("herd-floor"));
            }
        }
        let mut store = Self {
            floor,
            imported: BTreeMap::new(),
            bytes: total,
            root: Digest32::sha256(&[]),
        };
        store.root = store.calculate_root(&BTreeMap::new());
        Ok(store)
    }

    pub const fn root(&self) -> Digest32 {
        self.root
    }
    pub fn fixed_files(&self) -> impl Iterator<Item = &[u8]> {
        self.floor.values().copied()
    }
    pub fn imported_cases(&self) -> impl Iterator<Item = &RetainedCase> {
        self.imported.values()
    }

    /// Replays the imported additions alongside the fixed ratchet. Each retained
    /// case remains required, including cases that previously failed locally.
    pub fn replay(&self, limits: Limits, driver: &mut impl HerdReplay) -> Result<ReplayFacts> {
        limits.validate()?;
        let count = u32::try_from(self.imported.len()).map_err(|_| refuse("herd-limit"))?;
        if count > limits.cases {
            return Err(refuse("herd-replay-budget"));
        }
        driver.configure_budget(limits)?;
        let began = Instant::now();
        let mut facts = ReplayFacts {
            corpus_root: self.root,
            attempted: 0,
            passed: 0,
            failures: Vec::new(),
        };
        for case in self.imported.values() {
            if began.elapsed().as_millis() > u128::from(limits.wall_ms) {
                return Err(refuse("herd-replay-budget"));
            }
            let observed = driver.check(case)?;
            facts.attempted += 1;
            limits.permits(driver.resource_usage()?, facts.attempted)?;
            if began.elapsed().as_millis() > u128::from(limits.wall_ms) {
                return Err(refuse("herd-replay-budget"));
            }
            if observed == case.expected_refusal {
                facts.passed += 1;
            } else {
                facts.failures.push(case.id);
            }
        }
        limits.permits(driver.resource_usage()?, count)?;
        Ok(facts)
    }

    /// Preflight the complete batch before retaining anything. Repeats preserve
    /// the exact original bytes; changed verdicts for an existing input refuse.
    pub fn append_verified(
        &mut self,
        source: &impl AuthenticatedAntibodies,
        registry: &impl EngineRegistry,
    ) -> Result<ImportOutcome> {
        let files = source.canonical_cases()?;
        if files.is_empty() || files.len() > MAX_IMPORT_CASES {
            return Err(refuse("herd-import-limit"));
        }
        let mut batch = BTreeMap::new();
        let mut input_keys = BTreeSet::new();
        let mut inserted = Vec::new();
        let mut already_present = Vec::new();
        let mut total = self.bytes;
        for bytes in files {
            let case = RetainedCase::read(bytes, registry)?;
            let key = (
                case.engine.clone(),
                case.format_version,
                case.input_b64.clone(),
            );
            if !input_keys.insert(key) || batch.contains_key(&case.id) {
                return Err(refuse("herd-duplicate-case"));
            }
            if self.floor.contains_key(&case.id.to_string()) {
                return Err(refuse("herd-case-collision"));
            }
            if let Some(old) = self.imported.get(&case.id) {
                if old != &case {
                    return Err(refuse("herd-case-collision"));
                }
                already_present.push(case.id);
                // Retain it in the batch until duplicate checking has finished.
                batch.insert(case.id, case);
                continue;
            }
            if self.imported.values().any(|old| {
                old.engine == case.engine
                    && old.format_version == case.format_version
                    && old.input_b64 == case.input_b64
            }) {
                return Err(refuse("herd-verdict-conflict"));
            }
            total = total
                .checked_add(case.bytes.len())
                .filter(|bytes| *bytes <= MAX_RETAINED_BYTES)
                .ok_or(refuse("herd-limit"))?;
            inserted.push(case.id);
            batch.insert(case.id, case);
        }
        if self.floor.len() + self.imported.len() + inserted.len() > MAX_RETAINED_CASES {
            return Err(refuse("herd-limit"));
        }
        let retained_root = self.calculate_root(&batch);
        let result = ImportOutcome {
            source_event: source.source_event(),
            author: source.author(),
            previous_root: self.root,
            retained_root,
            inserted,
            already_present,
        };
        self.imported.extend(batch);
        self.bytes = total;
        self.root = retained_root;
        Ok(result)
    }

    fn calculate_root(&self, batch: &BTreeMap<Digest32, RetainedCase>) -> Digest32 {
        let mut files: BTreeMap<String, &[u8]> = self
            .floor
            .iter()
            .map(|(id, bytes)| (id.clone(), *bytes))
            .collect();
        for case in self.imported.values().chain(batch.values()) {
            files.insert(case.id.to_string(), &case.bytes);
        }
        let leaves: Vec<_> = files
            .values()
            .map(|bytes| Digest32::rfc6962_data_leaf(bytes))
            .collect();
        merkle(&leaves)
    }
}

fn merkle(leaves: &[Digest32]) -> Digest32 {
    match leaves {
        [] => Digest32::sha256(&[]),
        [leaf] => *leaf,
        many => {
            let split = many.len().next_power_of_two() / 2;
            Digest32::rfc6962_node(merkle(&many[..split]), merkle(&many[split..]))
        }
    }
}

fn token(value: &str, punctuation: &[u8]) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || punctuation.contains(&byte))
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    match value.get(name).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refuse("herd-case-schema")),
    }
}

/// Validate the standard padded spelling and its unused bits without decoding
/// or interpreting the replay input. The engine owns interpretation.
fn check_base64(text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_INPUT_BYTES.div_ceil(3) * 4 || bytes.len() % 4 != 0 {
        return Err(refuse("herd-input"));
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 || bytes.len() / 4 * 3 - padding > MAX_INPUT_BYTES {
        return Err(refuse("herd-input"));
    }
    let data = &bytes[..bytes.len() - padding];
    if data.iter().any(|byte| base64_digit(*byte).is_none()) {
        return Err(refuse("herd-input"));
    }
    let last = data.last().and_then(|byte| base64_digit(*byte));
    if (padding == 1 && !last.is_some_and(|value| value & 3 == 0))
        || (padding == 2 && !last.is_some_and(|value| value & 15 == 0))
    {
        return Err(refuse("herd-input"));
    }
    Ok(())
}

fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}
