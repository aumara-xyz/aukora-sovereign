// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical attack data and release replay interfaces (rows 66 and 68).

use crate::{
    heldout::HeldOut,
    registry::{Antibody, Registry},
};
use canon::{
    digest::Digest32,
    json::{self, Value, ValueView},
    Refusal, Result,
};
use sha2::{Digest, Sha256};

pub const MAX_CASE_BYTES: usize = 65_536;
pub const MAX_CASES: usize = 16_384;
pub const ARCHIVE_ATTACK_COUNT: usize = 815;
pub const AUMLOK_ISSUE_COUNT: usize = 81;
pub const PENTORA_VECTOR_COUNT: usize = 5_360;

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
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}
fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

fn field(value: &Value, name: &str) -> Result<String> {
    match value.get(name).map(Value::view) {
        Some(ValueView::Text(text))
            if !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control) =>
        {
            Ok(text.to_owned())
        }
        _ => Err(refuse("vector-schema")),
    }
}

fn parse(bytes: &[u8]) -> Result<AttackVector> {
    if bytes.is_empty() || bytes.len() > MAX_CASE_BYTES {
        return Err(refuse("vector-limit"));
    }
    let value = json::parse_strict(bytes)?;
    if json::to_canonical(&value) != bytes {
        return Err(refuse("vector-not-canonical"));
    }
    let names = [
        "id",
        "guarded_issue",
        "organ",
        "scenario",
        "expected_refusal",
    ];
    match value.view() {
        ValueView::Object(members)
            if members.len() == names.len()
                && members.iter().all(|(key, _)| names.contains(&key.as_str())) => {}
        _ => return Err(refuse("vector-schema")),
    }
    let scenario = value.get("scenario").ok_or(refuse("vector-schema"))?;
    if !matches!(scenario.view(), ValueView::Object(_)) {
        return Err(refuse("vector-schema"));
    }
    let id = field(&value, "id")?;
    let organ = field(&value, "organ")?;
    let expected_refusal = field(&value, "expected_refusal")?;
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    };
    if !token(&id)
        || id.len() > 128
        || !token(&organ)
        || organ.len() > 64
        || !expected_refusal
            .split_once(':')
            .is_some_and(|(a, b)| token(a) && token(b))
    {
        return Err(refuse("vector-schema"));
    }
    Ok(AttackVector {
        id,
        guarded_issue: field(&value, "guarded_issue")?,
        organ,
        scenario: scenario.clone(),
        expected_refusal,
        bytes_digest: hash(bytes),
        scenario_digest: hash(&json::to_canonical(scenario)),
    })
}

fn root(leaves: &[Digest32]) -> Digest32 {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let split = leaves.len().next_power_of_two() / 2;
    let mut material = Vec::with_capacity(65);
    material.push(1);
    material.extend_from_slice(root(&leaves[..split]).as_bytes());
    material.extend_from_slice(root(&leaves[split..]).as_bytes());
    hash(&material)
}

impl Corpus {
    pub fn from_files<'a>(files: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let mut entries = Vec::new();
        for bytes in files {
            if entries.len() >= MAX_CASES {
                return Err(refuse("corpus-limit"));
            }
            let vector = parse(bytes)?;
            let mut leaf = Vec::with_capacity(bytes.len() + 1);
            leaf.push(0);
            leaf.extend_from_slice(bytes);
            entries.push((vector, hash(&leaf)));
        }
        if entries.is_empty() {
            return Err(refuse("corpus-empty"));
        }
        entries.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        if entries.windows(2).any(|p| p[0].0.id == p[1].0.id) {
            return Err(refuse("duplicate-id"));
        }
        let digest = root(&entries.iter().map(|(_, leaf)| *leaf).collect::<Vec<_>>());
        Ok(Self {
            vectors: entries.into_iter().map(|(v, _)| v).collect(),
            root: digest,
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
    fn vector(&mut self, vector: &AttackVector) -> Result<Observation>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseFacts {
    pub release: Digest32,
    pub registry_digest: Digest32,
    pub corpus_root: Digest32,
    pub registered: u32,
    pub active: u32,
    pub retired: u32,
    pub replayed: u32,
    pub heldout_root: Digest32,
    pub heldout_count: u32,
    pub heldout_passed: u32,
    pub failures: Vec<String>,
    pub budget_exhausted: bool,
}

/// Wave-1 replay entry point. A returned fact can never approve a release.
pub fn release(
    _registry: &Registry,
    _fixed: &Corpus,
    _heldout: &HeldOut,
    _limits: crate::hostile::Limits,
    _replay: &mut impl Replay,
) -> Result<ReleaseFacts> {
    todo!("row 66: release ratchet and held-out replay")
}

/// Appends release observations as a versioned body under C3 boot.facts.
pub fn append_release_facts(
    _transaction: &mut impl canon::authority::AuthorityTxn,
    _authority: canon::authority::AuthorityVersion,
    _at: i64,
    _facts: &ReleaseFacts,
) -> Result<canon::authority::AuthorityRecord> {
    todo!("row 66: release fact encoding")
}
