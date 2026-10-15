// SPDX-License-Identifier: AGPL-3.0-or-later
//! Release observations replay the inventory and canonical route corpus (row 66).

use crate::{
    coverage::HistoricalCorpora,
    heldout::HeldOut,
    hostile::{Limits, Usage},
    registry::{Antibody, Registry, Status},
};
use canon::{
    digest::Digest32,
    json::{self, SafeInteger, Value, ValueView},
    Refusal, Result,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const MAX_CASE_BYTES: usize = 65_536;
pub const MAX_CASES: usize = 16_384;
pub const MAX_CORPUS_BYTES: usize = 16 * 1024 * 1024;
pub use crate::coverage::{ARCHIVE_ATTACK_COUNT, AUMLOK_ISSUE_COUNT, PENTORA_VECTOR_COUNT};
pub const RELEASE_FACT_SCHEMA: &str = "aukora-immune-release-facts-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttackVector {
    pub id: String,
    pub guarded_issue: String,
    pub organ: String,
    pub scenario: Value,
    pub expected_refusal: String,
    pub bytes_digest: Digest32,
    pub scenario_digest: Digest32,
}

#[derive(Debug)]
pub struct Corpus {
    vectors: Vec<AttackVector>,
    root: Digest32,
    historical: &'static HistoricalCorpora<'static>,
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}

fn text_field<'a>(object: &'a Value, name: &str) -> Result<&'a str> {
    match object.get(name).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refuse("vector-schema")),
    }
}

fn identifier(text: &str, maximum: usize, punctuation: &[u8]) -> bool {
    (1..=maximum).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
}

fn refusal_token(code: &str) -> bool {
    let mut fields = code.split(':');
    matches!((fields.next(), fields.next(), fields.next()), (Some(organ), Some(reason), None)
        if identifier(organ, 64, b"-") && identifier(reason, 64, b"-_."))
}

impl AttackVector {
    fn read(file: &[u8]) -> Result<Self> {
        if !(1..=MAX_CASE_BYTES).contains(&file.len()) {
            return Err(refuse("vector-limit"));
        }
        let object = json::parse_strict(file)?;
        if object.canonical_bytes() != file {
            return Err(refuse("vector-not-canonical"));
        }
        if !matches!(object.view(), ValueView::Object(fields) if fields.len() == 5) {
            return Err(refuse("vector-schema"));
        }
        let id = text_field(&object, "id")?;
        let organ = text_field(&object, "organ")?;
        let guarded = text_field(&object, "guarded_issue")?;
        let expected = text_field(&object, "expected_refusal")?;
        let scenario = object.get("scenario").ok_or(refuse("vector-schema"))?;
        if !identifier(id, 128, b"-_.")
            || !identifier(organ, 64, b"-")
            || guarded.is_empty()
            || guarded.len() > 128
            || !guarded.bytes().all(|b| (32..=126).contains(&b))
            || !matches!(scenario.view(), ValueView::Object(_))
            || !refusal_token(expected)
        {
            return Err(refuse("vector-schema"));
        }
        Ok(Self {
            bytes_digest: Digest32::sha256(file),
            scenario_digest: Digest32::sha256(&scenario.canonical_bytes()),
            scenario: scenario.clone(),
            expected_refusal: expected.into(),
            guarded_issue: guarded.into(),
            organ: organ.into(),
            id: id.into(),
        })
    }
}

impl Corpus {
    pub fn from_files<'a>(files: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let mut inventory = BTreeMap::new();
        let mut total_bytes = 0_usize;
        for file in files {
            if inventory.len() == MAX_CASES {
                return Err(refuse("corpus-limit"));
            }
            total_bytes = total_bytes
                .checked_add(file.len())
                .filter(|n| *n <= MAX_CORPUS_BYTES)
                .ok_or(refuse("corpus-limit"))?;
            let case = AttackVector::read(file)?;
            let slot = inventory.entry(case.id.clone());
            match slot {
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(refuse("duplicate-id"))
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert((case, Digest32::rfc6962_data_leaf(file)));
                }
            }
        }
        let mut frontier: Vec<Option<Digest32>> = Vec::new();
        let mut vectors = Vec::with_capacity(inventory.len());
        for (case, mut carry) in inventory.into_values() {
            let mut level = 0;
            loop {
                if level == frontier.len() {
                    frontier.push(Some(carry));
                    break;
                }
                match frontier[level].take() {
                    None => {
                        frontier[level] = Some(carry);
                        break;
                    }
                    Some(left) => {
                        carry = Digest32::rfc6962_node(left, carry);
                        level += 1;
                    }
                }
            }
            vectors.push(case);
        }
        let root = frontier
            .into_iter()
            .flatten()
            .reduce(|right, left| Digest32::rfc6962_node(left, right))
            .ok_or(refuse("corpus-empty"))?;
        Ok(Self {
            root,
            vectors,
            historical: HistoricalCorpora::bundled()?,
        })
    }

    pub fn pinned() -> Result<Self> {
        Self::from_files(PINNED_FILES.iter().copied())
    }
    pub fn vectors(&self) -> &[AttackVector] {
        &self.vectors
    }
    pub fn root(&self) -> Digest32 {
        self.root
    }

    /// Historical inputs remain separate from route scenarios and their RFC 6962 root.
    pub fn historical(&self) -> &'static HistoricalCorpora<'static> {
        self.historical
    }
}

pub const PINNED_FILES: [&[u8]; 20] = [
    include_bytes!("../corpus/binding-before-enrolment.json"),
    include_bytes!("../corpus/binding-wrong-word.json"),
    include_bytes!("../corpus/chat-owner-cookie.json"),
    include_bytes!("../corpus/chat-owner-route.json"),
    include_bytes!("../corpus/claim-single-use.json"),
    include_bytes!("../corpus/claim-unknown.json"),
    include_bytes!("../corpus/enrolment-second-key.json"),
    include_bytes!("../corpus/owner-before-binding.json"),
    include_bytes!("../corpus/refresh-without-passkey.json"),
    include_bytes!("../corpus/request-exact-host.json"),
    include_bytes!("../corpus/request-fetch-site.json"),
    include_bytes!("../corpus/request-origin.json"),
    include_bytes!("../corpus/request-path-alias.json"),
    include_bytes!("../corpus/request-proxy-https.json"),
    include_bytes!("../corpus/request-strict-json.json"),
    include_bytes!("../corpus/session-expired.json"),
    include_bytes!("../corpus/session-revoked.json"),
    include_bytes!("../corpus/signin-counter-regression.json"),
    include_bytes!("../corpus/signin-invalid-signature.json"),
    include_bytes!("../corpus/stranger-owner-action.json"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub passed: bool,
    pub refusal: Option<String>,
}

pub trait Replay {
    fn antibody(&mut self, antibody: &Antibody) -> Result<Observation>;
    /// Interpret only known scenario operations; unknown operations refuse.
    fn vector(&mut self, vector: &AttackVector) -> Result<Observation>;

    /// Install host-enforced resource ceilings before dispatching any case.
    /// The driver must interrupt a blocked case at the deadline.
    fn configure_budget(&mut self, _limits: Limits) -> Result<()> {
        Err(refuse("replay-budget-unavailable"))
    }

    /// Host-measured totals since configure_budget, including unsuccessful calls.
    fn resource_usage(&mut self) -> Result<Usage> {
        Err(refuse("replay-budget-unavailable"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseFacts {
    pub release: Digest32,
    pub registry_digest: Digest32,
    pub corpus_root: Digest32,
    pub registered: u32,
    pub active: u32,
    pub retired: u32,
    /// Inventory and fixed-corpus attempts; held-out attempts have separate counts.
    pub replayed: u32,
    pub heldout_root: Digest32,
    pub heldout_count: u32,
    pub heldout_passed: u32,
    pub failures: Vec<String>,
    pub budget_exhausted: bool,
}

/// A returned observation cannot approve a release or advance the floor.
pub fn release(
    registry: &Registry,
    fixed: &Corpus,
    heldout: &HeldOut,
    limits: Limits,
    replay: &mut impl Replay,
) -> Result<ReleaseFacts> {
    limits.validate()?;
    check_floor(registry, fixed)?;
    if heldout.vectors().iter().any(|fresh| {
        fixed
            .vectors()
            .iter()
            .any(|old| fresh.id == old.id || fresh.scenario_digest == old.scenario_digest)
    }) {
        return Err(refuse("heldout-reused"));
    }
    let mut facts = ReleaseFacts {
        release: heldout.release(),
        registry_digest: registry.pinned_digest(),
        corpus_root: fixed.root(),
        registered: count(registry.len())?,
        active: count(registry.active_count())?,
        retired: count(registry.len() - registry.active_count())?,
        replayed: 0,
        heldout_root: heldout.root(),
        heldout_count: count(heldout.vectors().len())?,
        heldout_passed: 0,
        failures: Vec::new(),
        budget_exhausted: false,
    };
    replay.configure_budget(limits)?;
    let started = Instant::now();
    let mut previous = replay.resource_usage()?;
    limits.permits(previous, 0)?;
    let mut attempted = 0;
    enum Case<'a> {
        Antibody(&'a Antibody),
        Fixed(&'a AttackVector),
        Fresh(&'a AttackVector),
    }
    let cases = registry
        .entries()
        .filter(|a| a.status == Status::Active)
        .map(Case::Antibody)
        .chain(fixed.vectors().iter().map(Case::Fixed))
        .chain(heldout.vectors().iter().map(Case::Fresh));
    for case in cases {
        if attempted == limits.cases || started.elapsed() >= Duration::from_millis(limits.wall_ms) {
            facts.budget_exhausted = true;
            break;
        }
        let (label, expected, fresh, observation) = match case {
            Case::Antibody(a) => (
                format!("antibody:{}", a.name),
                None,
                false,
                replay.antibody(a),
            ),
            Case::Fixed(v) => (
                format!("fixed:{}", v.id),
                Some(v.expected_refusal.as_str()),
                false,
                replay.vector(v),
            ),
            Case::Fresh(v) => (
                format!("heldout:{}", v.id),
                Some(v.expected_refusal.as_str()),
                true,
                replay.vector(v),
            ),
        };
        attempted += 1;
        if !fresh {
            facts.replayed += 1;
        }
        let usage = replay.resource_usage()?;
        if usage.wall_ms < previous.wall_ms
            || usage.cpu_us < previous.cpu_us
            || usage.memory_bytes < previous.memory_bytes
            || usage.io_bytes < previous.io_bytes
            || usage.output_bytes < previous.output_bytes
        {
            return Err(refuse("replay-usage-regressed"));
        }
        previous = usage;
        if limits.permits(usage, attempted).is_err()
            || started.elapsed() >= Duration::from_millis(limits.wall_ms)
        {
            facts.budget_exhausted = true;
            facts.failures.push(label);
            break;
        }
        let passed = match observation {
            Ok(observed) => {
                observed.passed
                    && match expected {
                        Some(code) => observed.refusal.as_deref() == Some(code),
                        None => observed.refusal.as_deref().is_none_or(refusal_token),
                    }
            }
            Err(_) => false,
        };
        if !passed {
            facts.failures.push(label);
        } else if fresh {
            facts.heldout_passed += 1;
        }
    }
    Ok(facts)
}

fn count(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| refuse("release-facts"))
}

fn check_floor(registry: &Registry, fixed: &Corpus) -> Result<()> {
    let pinned_registry = Registry::pinned()?;
    let intact_registry = pinned_registry.entries().all(|original| {
        registry.get(&original.name).is_some_and(|entry| {
            entry.name == original.name
                && entry.area == original.area
                && entry.source == original.source
                && (original.status == Status::Active || entry.status == original.status)
        })
    });
    let intact_corpus = Corpus::pinned()?.vectors().iter().all(|original| {
        fixed
            .vectors()
            .binary_search_by(|v| v.id.cmp(&original.id))
            .ok()
            .is_some_and(|index| fixed.vectors()[index].bytes_digest == original.bytes_digest)
    });
    if !intact_registry || !intact_corpus {
        return Err(refuse("ratchet-floor"));
    }
    Ok(())
}

/// Body's independent corpus-root and immutable-floor observations.
/// The supervisor supplies the release fact it read from the approved release.
pub fn health_observations(
    context: crate::health::Context,
    registry: &Registry,
    fixed: &Corpus,
    recorded: Option<&ReleaseFacts>,
) -> [crate::health::BodyObservation; 3] {
    use crate::health::{BodyObservation, Finding, CORNER_CHECKS, PRIVATE_CHECKS};
    let floor = if check_floor(registry, fixed).is_ok() {
        Finding::Satisfied
    } else {
        Finding::Failed
    };
    let root = match recorded {
        None => Finding::NotChecked,
        Some(facts)
            if facts.to_body().is_ok()
                && facts.corpus_root == fixed.root()
                && facts.registry_digest == registry.pinned_digest() =>
        {
            Finding::Satisfied
        }
        Some(_) => Finding::Failed,
    };
    [
        BodyObservation {
            check: PRIVATE_CHECKS[13].check,
            context,
            finding: root,
        },
        BodyObservation {
            check: PRIVATE_CHECKS[14].check,
            context,
            finding: floor,
        },
        BodyObservation {
            check: CORNER_CHECKS[3].check,
            context,
            finding: root,
        },
    ]
}

impl ReleaseFacts {
    /// Decode only the exact release-fact body schema and its count invariants.
    pub fn from_body(body: &Value) -> Result<Self> {
        if !matches!(body.view(), ValueView::Object(fields) if fields.len() == 13)
            || text_field(body, "schema")? != RELEASE_FACT_SCHEMA
        {
            return Err(refuse("release-facts"));
        }
        let digest =
            |key| Digest32::from_hex(text_field(body, key)?).map_err(|_| refuse("release-facts"));
        let number = |key| match body.get(key).map(Value::view) {
            Some(ValueView::Integer(n)) => {
                u32::try_from(n.get()).map_err(|_| refuse("release-facts"))
            }
            _ => Err(refuse("release-facts")),
        };
        let budget_exhausted = match body.get("budget_exhausted").map(Value::view) {
            Some(ValueView::Boolean(value)) => value,
            _ => return Err(refuse("release-facts")),
        };
        let failures = match body.get("failures").map(Value::view) {
            Some(ValueView::Array(entries)) => entries
                .iter()
                .map(|entry| match entry.view() {
                    ValueView::Text(text) => Ok(text.to_owned()),
                    _ => Err(refuse("release-facts")),
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(refuse("release-facts")),
        };
        let facts = Self {
            release: digest("release")?,
            registry_digest: digest("registry_digest")?,
            corpus_root: digest("corpus_root")?,
            heldout_root: digest("heldout_root")?,
            registered: number("registered")?,
            active: number("active")?,
            retired: number("retired")?,
            replayed: number("replayed")?,
            heldout_count: number("heldout_count")?,
            heldout_passed: number("heldout_passed")?,
            failures,
            budget_exhausted,
        };
        if facts.to_body()? != *body {
            return Err(refuse("release-facts"));
        }
        Ok(facts)
    }

    /// Evidence completeness only; this never authorizes installation.
    pub fn successful(&self) -> bool {
        self.to_body().is_ok()
            && !self.budget_exhausted
            && self.failures.is_empty()
            && self.heldout_passed == self.heldout_count
    }

    /// Encode evidence in a new body schema, leaving the frozen C3 row untouched.
    pub fn to_body(&self) -> Result<Value> {
        if self.registered < crate::registry::PINNED_REGISTERED as u32
            || self.registered > crate::registry::MAX_REGISTERED as u32
            || self.active.checked_add(self.retired) != Some(self.registered)
            || self.retired < crate::registry::PINNED_RETIRED as u32
            || !(1..=crate::heldout::MAX_HELDOUT_CASES as u32).contains(&self.heldout_count)
            || self.heldout_passed > self.heldout_count
            || !self.budget_exhausted && self.replayed < self.active + PINNED_FILES.len() as u32
            || self.replayed > self.active + MAX_CASES as u32
            || self.registry_digest.to_string() != crate::registry::REGISTRY_SHA256
            || self.failures.len()
                > MAX_CASES + crate::registry::MAX_REGISTERED + crate::heldout::MAX_HELDOUT_CASES
            || self
                .failures
                .iter()
                .any(|f| f.is_empty() || f.len() > 4200 || f.chars().any(char::is_control))
        {
            return Err(refuse("release-facts"));
        }
        let mut unique = std::collections::BTreeSet::new();
        let mut heldout_failures = 0;
        let mut fixed_failures = 0;
        for failure in &self.failures {
            let (group, id) = failure.split_once(':').ok_or(refuse("release-facts"))?;
            if id.is_empty() || !unique.insert(failure) {
                return Err(refuse("release-facts"));
            }
            match group {
                "heldout" => heldout_failures += 1,
                "antibody" | "fixed" => fixed_failures += 1,
                _ => return Err(refuse("release-facts")),
            }
        }
        if fixed_failures > self.replayed
            || heldout_failures > self.heldout_count - self.heldout_passed
            || !self.budget_exhausted
                && heldout_failures != self.heldout_count - self.heldout_passed
        {
            return Err(refuse("release-facts"));
        }
        let mut fields = vec![
            ("schema".into(), Value::text(RELEASE_FACT_SCHEMA.into())?),
            ("release".into(), Value::text(self.release.to_string())?),
            (
                "registry_digest".into(),
                Value::text(self.registry_digest.to_string())?,
            ),
            (
                "corpus_root".into(),
                Value::text(self.corpus_root.to_string())?,
            ),
            (
                "heldout_root".into(),
                Value::text(self.heldout_root.to_string())?,
            ),
            (
                "budget_exhausted".into(),
                Value::boolean(self.budget_exhausted),
            ),
            (
                "failures".into(),
                Value::array(
                    self.failures
                        .iter()
                        .cloned()
                        .map(Value::text)
                        .collect::<Result<Vec<_>>>()?,
                )?,
            ),
        ];
        for (key, n) in [
            ("registered", self.registered),
            ("active", self.active),
            ("retired", self.retired),
            ("replayed", self.replayed),
            ("heldout_count", self.heldout_count),
            ("heldout_passed", self.heldout_passed),
        ] {
            fields.push((key.into(), Value::integer(SafeInteger::new(i64::from(n))?)));
        }
        Value::object(fields)
    }
}

/// Recover the latest committed observation for the requested release.
pub fn committed_release_facts(
    transaction: &mut impl canon::authority::AuthorityTxn,
    release: Digest32,
) -> Result<Option<ReleaseFacts>> {
    use canon::{
        alg::AlgorithmId,
        authority::{Kind, Phase},
    };
    let mut latest = None;
    let mut previous_sequence = 0;
    for row in transaction.committed_immune_records()? {
        if row.authority.sequence <= previous_sequence {
            return Err(refuse("release-fact-context"));
        }
        previous_sequence = row.authority.sequence;
        let wrapper = aura::record::AuthorityBodyV1::parse(&row.body)?;
        if wrapper.authority != row.authority || wrapper.algorithm != row.algorithm {
            return Err(refuse("release-fact-context"));
        }
        match wrapper.payload.get("schema").map(Value::view) {
            Some(ValueView::Text(RELEASE_FACT_SCHEMA)) => {
                if row.v != 1
                    || row.algorithm != AlgorithmId::Sha256
                    || row.actor != "immune"
                    || row.kind != Kind::BootFacts
                    || row.phase != Phase::Fact
                    || row.operation.is_some()
                {
                    return Err(refuse("release-fact-context"));
                }
                let facts = ReleaseFacts::from_body(&wrapper.payload)?;
                if facts.release == release {
                    latest = Some(facts);
                }
            }
            Some(ValueView::Text(schema)) if schema.starts_with("aukora-immune-release-") => {
                return Err(refuse("release-facts"))
            }
            _ => {}
        }
    }
    Ok(latest)
}

/// Append nonauthorizing observations; the caller commits its fact transaction.
pub fn append_release_facts(
    transaction: &mut impl canon::authority::AuthorityTxn,
    authority: canon::authority::AuthorityVersion,
    at: i64,
    facts: &ReleaseFacts,
) -> Result<canon::authority::AuthorityRecord> {
    use canon::{
        alg::AlgorithmId,
        authority::{FactKind, FactRecord},
    };
    let context = transaction.observation_context()?;
    if context.authority != authority || at > context.at || at < 0 || at > json::MAX_SAFE_INTEGER {
        return Err(refuse("release-fact-context"));
    }
    transaction.append_fact(FactRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority,
        at,
        kind: FactKind::BootFacts,
        actor: "immune".into(),
        body: facts.to_body()?,
    })
}
