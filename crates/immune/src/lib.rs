// SPDX-License-Identifier: AGPL-3.0-or-later

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{Duration, Instant};

const MAX_VECTOR_BYTES: usize = 65_536;
const MAX_VECTORS: usize = 4096;

include!(concat!(env!("OUT_DIR"), "/corpus.rs"));

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vector {
    pub id: String,
    pub guarded_issue: String,
    pub organ: String,
    pub scenario: Value,
    pub expected_refusal: String,
}

#[derive(Clone, Debug)]
pub struct Corpus {
    vectors: Vec<Vector>,
    root: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for Error {}

fn refused(code: &'static str) -> Error {
    Error { code }
}

impl Corpus {
    pub fn embedded() -> Result<Self, Error> {
        Self::from_bytes(EMBEDDED.iter().copied())
    }

    pub fn from_bytes<I, B>(inputs: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut entries = Vec::new();
        for input in inputs {
            if entries.len() == MAX_VECTORS {
                return Err(refused("immune:corpus-too-large"));
            }
            let bytes = input.as_ref();
            let vector = parse_vector(bytes)?;
            entries.push((vector, bytes.to_vec()));
        }
        if entries.is_empty() {
            return Err(refused("immune:corpus-empty"));
        }
        entries.sort_by(|left, right| left.0.id.cmp(&right.0.id));
        if entries.windows(2).any(|pair| pair[0].0.id == pair[1].0.id) {
            return Err(refused("immune:duplicate-id"));
        }
        let leaves: Vec<_> = entries.iter().map(|(_, bytes)| leaf(bytes)).collect();
        let root = hex::encode(tree_hash(&leaves));
        Ok(Self {
            vectors: entries.into_iter().map(|(vector, _)| vector).collect(),
            root,
        })
    }

    pub fn vectors(&self) -> &[Vector] {
        &self.vectors
    }

    pub fn ids(&self) -> Vec<String> {
        self.vectors
            .iter()
            .map(|vector| vector.id.clone())
            .collect()
    }

    pub fn root(&self) -> &str {
        &self.root
    }
}

fn parse_vector(bytes: &[u8]) -> Result<Vector, Error> {
    if bytes.len() > MAX_VECTOR_BYTES {
        return Err(refused("immune:vector-too-large"));
    }
    let parsed = canon::parse(bytes).map_err(|_| refused("immune:vector-not-canonical"))?;
    if canon::canonical_json(&parsed).map_err(|_| refused("immune:vector-not-canonical"))? != bytes
    {
        return Err(refused("immune:vector-not-canonical"));
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| refused("immune:vector-schema"))?;
    let fields = value
        .as_object()
        .ok_or_else(|| refused("immune:vector-schema"))?;
    let names = [
        "id",
        "guarded_issue",
        "organ",
        "scenario",
        "expected_refusal",
    ];
    if fields.len() != names.len() || names.iter().any(|name| !fields.contains_key(*name)) {
        return Err(refused("immune:vector-schema"));
    }
    let string = |name: &str| {
        value[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| refused("immune:vector-schema"))
    };
    let id = string("id")?;
    let guarded_issue = string("guarded_issue")?;
    let organ = string("organ")?;
    let expected_refusal = string("expected_refusal")?;
    if !token(&id, 128, b"_.-")
        || guarded_issue.is_empty()
        || guarded_issue.len() > 128
        || !guarded_issue
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
        || !token(&organ, 64, b"-")
        || !value["scenario"].is_object()
        || !expected_refusal
            .split_once(':')
            .is_some_and(|(organ, reason)| token(organ, 64, b"-") && token(reason, 64, b"-_."))
    {
        return Err(refused("immune:vector-schema"));
    }
    Ok(Vector {
        id,
        guarded_issue,
        organ,
        scenario: value["scenario"].clone(),
        expected_refusal,
    })
}

fn token(value: &str, maximum: usize, extra: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
}

fn leaf(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([0]);
    hash.update(bytes);
    hash.finalize().into()
}

fn tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let split = leaves.len().next_power_of_two() / 2;
    let mut hash = Sha256::new();
    hash.update([1]);
    hash.update(tree_hash(&leaves[..split]));
    hash.update(tree_hash(&leaves[split..]));
    hash.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub id: String,
    pub expected: String,
    pub observed: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub root: String,
    pub ids: Vec<String>,
    pub passed: usize,
    pub total: usize,
    pub failures: Vec<Failure>,
    pub budget_exhausted: bool,
}

impl Report {
    pub fn successful(&self) -> bool {
        !self.budget_exhausted && self.failures.is_empty() && self.passed == self.total
    }

    pub fn refusal_code(&self) -> Option<&'static str> {
        if self.failures.iter().any(|failure| {
            matches!(
                failure.observed.as_str(),
                "immune:replay-unavailable" | "runner-error: immune:replay-unavailable"
            )
        }) {
            Some("immune:replay-unavailable")
        } else if self.budget_exhausted {
            Some("immune:budget-exhausted")
        } else if !self.successful() {
            Some("immune:antibody-failed")
        } else {
            None
        }
    }
}

pub fn run<F>(corpus: &Corpus, budget: Duration, mut replay: F) -> Report
where
    F: FnMut(&Vector) -> Result<String, String>,
{
    let start = Instant::now();
    let mut report = Report {
        root: corpus.root.clone(),
        ids: corpus.ids(),
        passed: 0,
        total: corpus.vectors.len(),
        failures: Vec::new(),
        budget_exhausted: false,
    };
    for vector in &corpus.vectors {
        if start.elapsed() >= budget {
            report.budget_exhausted = true;
            break;
        }
        let result = replay(vector);
        if start.elapsed() >= budget {
            report.budget_exhausted = true;
            break;
        }
        match result {
            Ok(observed) if observed == vector.expected_refusal => report.passed += 1,
            observed => report.failures.push(Failure {
                id: vector.id.clone(),
                expected: vector.expected_refusal.clone(),
                observed: observed.unwrap_or_else(|error| format!("runner-error: {error}")),
            }),
        }
    }
    report
}

#[cfg(test)]
mod tests;
