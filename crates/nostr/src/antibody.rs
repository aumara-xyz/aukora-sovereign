// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 136: signed antibody data and an append-only import contract.

use crate::{Event, EventId, PublicKey, Refusal, Result, SecretKey, VerifiedEvent};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    digest::Digest32,
    json::{self, SafeInteger, Value, ValueView},
};
use std::collections::BTreeSet;

/// Regular stored event, not replaceable: a newer event cannot erase an older case.
pub const ANTIBODY_EVENT_KIND: u16 = 8777;
pub const ANTIBODY_SCHEMA: &str = "aukora-antibody-v1";
pub const ANTIBODY_DOMAIN: &str = "aukora:antibody:v1";
pub const MAX_CASES_PER_EVENT: usize = 32;
pub const MAX_CASE_BYTES: usize = 16_384;

/// Inert replay input for an existing local check engine; never source code.
/// Wire keys are id, engine, format_version, input_b64, expected_refusal.
/// id = SHA-256(ASCII ANTIBODY_DOMAIN || 00 || C1({engine,format_version,
/// input_b64,expected_refusal})); input_b64 is standard padded base64. An id
/// therefore commits to the expected verdict as well as the entire replay input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntibodyCase {
    pub id: Digest32,
    pub engine: String,
    pub format_version: u16,
    pub input: Vec<u8>,
    pub expected_refusal: String,
}

/// Exact versioned content within a signed NIP-01 event. No remote delete,
/// retire, exemption, replacement or executable instruction field exists.
/// The event has empty tags; content is the C1 object {schema,source_corpus_root,
/// cases}. The codec and case-id preimage are declared in vectors/antibody-v1.json.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntibodyAnnouncement {
    pub schema: String,
    pub source_corpus_root: Digest32,
    pub cases: Vec<AntibodyCase>,
}

/// Immune's local engine inventory, supplied by trusted wiring rather than by
/// the event author. Recognizing an engine does not execute an imported case.
pub trait AntibodyRegistry {
    fn supports(&self, engine: &str, format_version: u16) -> bool;
    fn accepts_refusal(&self, code: &str) -> bool;
}

/// Authenticated origin and immutable replay data; still evidence only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAntibodies {
    event_id: EventId,
    author: PublicKey,
    announcement: AntibodyAnnouncement,
}

impl VerifiedAntibodies {
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    pub const fn author(&self) -> &PublicKey {
        &self.author
    }

    pub const fn announcement(&self) -> &AntibodyAnnouncement {
        &self.announcement
    }
}

/// Wave 1 checks kind, schema, exact bounded C1 content, unique case ids and
/// content hashes, known local engines and organ:reason codes. Unknown engines
/// or actions refuse. Signature validity is not permission to execute content.
pub fn decode<R: AntibodyRegistry + ?Sized>(
    event: &VerifiedEvent,
    registry: &R,
) -> Result<VerifiedAntibodies> {
    let event = event.event();
    if event.kind != ANTIBODY_EVENT_KIND {
        return Err(refusal("antibody-kind"));
    }
    if !event.tags.is_empty() {
        return Err(refusal("antibody-tags"));
    }
    if event.content.is_empty() || event.content.len() > crate::event::MAX_EVENT_BYTES {
        return Err(refusal("antibody-bounds"));
    }
    let content = json::parse_strict(event.content.as_bytes())?;
    if content.canonical_bytes() != event.content.as_bytes() {
        return Err(refusal("antibody-content"));
    }
    exact(&content, &["schema", "source_corpus_root", "cases"])?;
    if text(&content, "schema")? != ANTIBODY_SCHEMA {
        return Err(refusal("antibody-version"));
    }
    let source_corpus_root = digest(&content, "source_corpus_root")?;
    let values = match field(&content, "cases")?.view() {
        ValueView::Array(values) if (1..=MAX_CASES_PER_EVENT).contains(&values.len()) => values,
        _ => return Err(refusal("antibody-bounds")),
    };
    let mut cases = Vec::with_capacity(values.len());
    for value in values {
        exact(
            value,
            &[
                "id",
                "engine",
                "format_version",
                "input_b64",
                "expected_refusal",
            ],
        )?;
        let format_version = match field(value, "format_version")?.view() {
            ValueView::Integer(number) => {
                u16::try_from(number.get()).map_err(|_| refusal("antibody-version"))?
            }
            _ => return Err(refusal("antibody-version")),
        };
        let encoded = text(value, "input_b64")?;
        if encoded.len() > MAX_CASE_BYTES.div_ceil(3) * 4 {
            return Err(refusal("antibody-bounds"));
        }
        let input = STANDARD
            .decode(encoded)
            .map_err(|_| refusal("antibody-input"))?;
        if STANDARD.encode(&input) != encoded {
            return Err(refusal("antibody-input"));
        }
        cases.push(AntibodyCase {
            id: digest(value, "id")?,
            engine: text(value, "engine")?.into(),
            format_version,
            input,
            expected_refusal: text(value, "expected_refusal")?.into(),
        });
    }
    let announcement = AntibodyAnnouncement {
        schema: ANTIBODY_SCHEMA.into(),
        source_corpus_root,
        cases,
    };
    validate(&announcement, registry)?;
    Ok(VerifiedAntibodies {
        event_id: event.id,
        author: event.pubkey,
        announcement,
    })
}

impl AntibodyCase {
    /// Commits to inert replay bytes and their expected refusal, without running them.
    pub fn new(
        engine: String,
        format_version: u16,
        input: Vec<u8>,
        expected_refusal: String,
    ) -> Result<Self> {
        let mut case = Self {
            id: Digest32::from_bytes([0; 32]),
            engine,
            format_version,
            input,
            expected_refusal,
        };
        case.check_fields()?;
        case.id = case.computed_id()?;
        Ok(case)
    }

    /// Exact retained corpus-file bytes, including the checked content identifier.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.check_fields()?;
        if self.computed_id()? != self.id {
            return Err(refusal("antibody-case-id"));
        }
        Ok(self.value()?.canonical_bytes())
    }

    fn check_fields(&self) -> Result<()> {
        if !token(&self.engine, 64, b"-_") {
            return Err(refusal("antibody-engine"));
        }
        if self.input.len() > MAX_CASE_BYTES {
            return Err(refusal("antibody-bounds"));
        }
        let Some((organ, reason)) = self.expected_refusal.split_once(':') else {
            return Err(refusal("antibody-refusal"));
        };
        if !token(organ, 64, b"-_") || !token(reason, 64, b"-_.") {
            return Err(refusal("antibody-refusal"));
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<(String, Value)>> {
        Ok(vec![
            ("engine".into(), Value::text(self.engine.clone())?),
            (
                "format_version".into(),
                Value::integer(SafeInteger::new(i64::from(self.format_version))?),
            ),
            (
                "input_b64".into(),
                Value::text(STANDARD.encode(&self.input))?,
            ),
            (
                "expected_refusal".into(),
                Value::text(self.expected_refusal.clone())?,
            ),
        ])
    }

    fn computed_id(&self) -> Result<Digest32> {
        let body = Value::object(self.body()?)?.canonical_bytes();
        let mut preimage = Vec::with_capacity(ANTIBODY_DOMAIN.len() + 1 + body.len());
        preimage.extend_from_slice(ANTIBODY_DOMAIN.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&body);
        Ok(Digest32::sha256(&preimage))
    }

    fn value(&self) -> Result<Value> {
        let mut fields = self.body()?;
        fields.push(("id".into(), Value::text(self.id.to_string())?));
        Value::object(fields)
    }
}

impl AntibodyAnnouncement {
    /// Encodes the frozen content object after validating every local replay contract.
    pub fn canonical_bytes<R: AntibodyRegistry + ?Sized>(&self, registry: &R) -> Result<Vec<u8>> {
        validate(self, registry)?;
        let content = Value::object(vec![
            ("schema".into(), Value::text(self.schema.clone())?),
            (
                "source_corpus_root".into(),
                Value::text(self.source_corpus_root.to_string())?,
            ),
            (
                "cases".into(),
                Value::array(
                    self.cases
                        .iter()
                        .map(AntibodyCase::value)
                        .collect::<Result<Vec<_>>>()?,
                )?,
            ),
        ])?
        .canonical_bytes();
        if content.len() > crate::event::MAX_EVENT_BYTES {
            return Err(refusal("antibody-bounds"));
        }
        Ok(content)
    }
}

/// Signs an announcement for the existing transport; this function performs no I/O.
pub fn announcement<R: AntibodyRegistry + ?Sized>(
    author: &SecretKey,
    created_at_seconds: u64,
    content: &AntibodyAnnouncement,
    registry: &R,
) -> Result<VerifiedEvent> {
    let bytes = content.canonical_bytes(registry)?;
    let content = String::from_utf8(bytes).map_err(|_| refusal("antibody-content"))?;
    Event::sign(
        author,
        created_at_seconds,
        ANTIBODY_EVENT_KIND,
        Vec::new(),
        content,
    )
}

fn validate<R: AntibodyRegistry + ?Sized>(
    announcement: &AntibodyAnnouncement,
    registry: &R,
) -> Result<()> {
    if announcement.schema != ANTIBODY_SCHEMA {
        return Err(refusal("antibody-version"));
    }
    if !(1..=MAX_CASES_PER_EVENT).contains(&announcement.cases.len()) {
        return Err(refusal("antibody-bounds"));
    }
    let mut identifiers = BTreeSet::new();
    let mut replays = BTreeSet::new();
    for case in &announcement.cases {
        case.canonical_bytes()?;
        if !registry.supports(&case.engine, case.format_version) {
            return Err(refusal("antibody-engine"));
        }
        if !registry.accepts_refusal(&case.expected_refusal) {
            return Err(refusal("antibody-refusal"));
        }
        if !identifiers.insert(case.id)
            || !replays.insert((
                &case.engine,
                case.format_version,
                Digest32::sha256(&case.input),
            ))
        {
            return Err(refusal("antibody-duplicate-case"));
        }
    }
    Ok(())
}

fn token(value: &str, limit: usize, punctuation: &[u8]) -> bool {
    (1..=limit).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || punctuation.contains(&byte))
}

fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == keys.len()
                && fields.iter().all(|(key, _)| keys.contains(&key.as_str())) =>
        {
            Ok(())
        }
        _ => Err(refusal("antibody-case")),
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(refusal("antibody-case"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match field(value, key)?.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(refusal("antibody-case")),
    }
}

fn digest(value: &Value, key: &str) -> Result<Digest32> {
    Digest32::from_hex(text(value, key)?).map_err(|_| refusal("antibody-case"))
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "nostr",
        reason,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportOutcome {
    pub source_event: EventId,
    pub previous_root: Digest32,
    pub retained_root: Digest32,
    pub inserted: Vec<Digest32>,
    pub already_present: Vec<Digest32>,
}

/// Immune owns the implementation. In one atomic operation it retains the fixed
/// floor and every imported case, accepts identical repeats idempotently, refuses
/// id collisions with changed bytes, and appends only new checks. RFC 6962 roots
/// commit to retained corpus files; a sender's claimed root never replaces them.
/// Imported cases may add refusals, but cannot retire a check or authorize effects.
pub trait AdditiveAntibodyStore {
    fn append_verified(&mut self, addition: &VerifiedAntibodies) -> Result<ImportOutcome>;
}
