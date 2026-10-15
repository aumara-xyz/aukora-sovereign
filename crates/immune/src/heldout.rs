// SPDX-License-Identifier: AGPL-3.0-or-later
//! Admission reserves previously unseen scenario content and ids for one release.

use std::collections::BTreeSet;

use crate::ratchet::{AttackVector, Corpus};
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityRecord, AuthorityTxn, FactKind, FactRecord, Kind, Phase},
    digest::Digest32,
    json::{Value, ValueView},
    Refusal, Result,
};

pub const MAX_HELDOUT_CASES: usize = 1024;
const CLAIM_SCHEMA: &str = "aukora-immune-heldout-claim-v1";

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}

pub trait History {
    /// Reserve an unused release, every id and every scenario digest together.
    /// Reject empty, duplicate or previously claimed input without changing history.
    fn claim(&mut self, release: Digest32, cases: &[(String, Digest32)]) -> Result<()>;
}

#[derive(Debug, Default)]
struct ClaimInventory {
    releases: BTreeSet<Digest32>,
    ids: BTreeSet<String>,
    scenarios: BTreeSet<Digest32>,
}

fn batch(cases: &[(String, Digest32)]) -> Result<(BTreeSet<String>, BTreeSet<Digest32>)> {
    if cases.is_empty() || cases.len() > MAX_HELDOUT_CASES {
        return Err(refusal("heldout-count"));
    }
    let mut ids = BTreeSet::new();
    let mut scenarios = BTreeSet::new();
    for (id, digest) in cases {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(refusal("heldout-id"));
        }
        if !ids.insert(id.clone()) || !scenarios.insert(*digest) {
            return Err(refusal("heldout-reused"));
        }
    }
    Ok((ids, scenarios))
}

impl ClaimInventory {
    fn claim(&mut self, release: Digest32, cases: &[(String, Digest32)]) -> Result<()> {
        let (new_ids, new_scenarios) = batch(cases)?;
        if self.releases.contains(&release)
            || !self.ids.is_disjoint(&new_ids)
            || !self.scenarios.is_disjoint(&new_scenarios)
        {
            return Err(refusal("heldout-reused"));
        }
        self.releases.insert(release);
        self.ids.extend(new_ids);
        self.scenarios.extend(new_scenarios);
        Ok(())
    }
}

/// Freshness claims are committed as nonauthorizing facts under Aura's write lock.
pub struct LedgerHistory<'a, T: AuthorityTxn> {
    transaction: &'a mut T,
}

impl<'a, T: AuthorityTxn> LedgerHistory<'a, T> {
    pub fn new(transaction: &'a mut T) -> Self {
        Self { transaction }
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refusal("heldout-history")),
    }
}

fn fields(value: &Value, keys: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(members)
            if members.len() == keys.len()
                && members.iter().all(|(key, _)| keys.contains(&key.as_str())) =>
        {
            Ok(())
        }
        _ => Err(refusal("heldout-history")),
    }
}

fn payload(row: &AuthorityRecord) -> Result<Value> {
    let wrapper =
        aura::record::AuthorityBodyV1::parse(&row.body).map_err(|_| refusal("heldout-history"))?;
    if wrapper.authority != row.authority
        || wrapper.algorithm != row.algorithm
        || wrapper.algorithm != AlgorithmId::Sha256
    {
        return Err(refusal("heldout-history"));
    }
    Ok(wrapper.payload)
}

fn retained_claim(row: &AuthorityRecord) -> Result<(Digest32, Vec<(String, Digest32)>)> {
    if row.v != 1
        || row.algorithm != AlgorithmId::Sha256
        || row.kind != Kind::BootFacts
        || row.phase != Phase::Fact
        || row.operation.is_some()
        || row.actor != "immune"
    {
        return Err(refusal("heldout-history"));
    }
    let body = payload(row)?;
    fields(&body, &["schema", "release", "cases"])?;
    if text(&body, "schema")? != CLAIM_SCHEMA {
        return Err(refusal("heldout-history"));
    }
    let release =
        Digest32::from_hex(text(&body, "release")?).map_err(|_| refusal("heldout-history"))?;
    let members = match body.get("cases").map(Value::view) {
        Some(ValueView::Array(cases)) if !cases.is_empty() && cases.len() <= MAX_HELDOUT_CASES => {
            cases
        }
        _ => return Err(refusal("heldout-history")),
    };
    let mut cases = Vec::with_capacity(members.len());
    for case in members {
        fields(case, &["id", "scenario_sha256"])?;
        cases.push((
            text(case, "id")?.to_owned(),
            Digest32::from_hex(text(case, "scenario_sha256")?)
                .map_err(|_| refusal("heldout-history"))?,
        ));
    }
    batch(&cases).map_err(|_| refusal("heldout-history"))?;
    Ok((release, cases))
}

fn claim_body(release: Digest32, cases: &[(String, Digest32)]) -> Result<Value> {
    let mut ordered: Vec<_> = cases.iter().collect();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    let mut members = Vec::with_capacity(ordered.len());
    for (id, digest) in ordered {
        members.push(Value::object(vec![
            ("id".to_owned(), Value::text(id.clone())?),
            (
                "scenario_sha256".to_owned(),
                Value::text(digest.to_string())?,
            ),
        ])?);
    }
    Value::object(vec![
        ("schema".to_owned(), Value::text(CLAIM_SCHEMA.to_owned())?),
        ("release".to_owned(), Value::text(release.to_string())?),
        ("cases".to_owned(), Value::array(members)?),
    ])
}

impl<T: AuthorityTxn> History for LedgerHistory<'_, T> {
    fn claim(&mut self, release: Digest32, cases: &[(String, Digest32)]) -> Result<()> {
        batch(cases)?;
        let mut previous = ClaimInventory::default();
        for row in self.transaction.committed_immune_records()? {
            let body = payload(&row)?;
            let Some(ValueView::Text(schema)) = body.get("schema").map(Value::view) else {
                continue;
            };
            if schema == CLAIM_SCHEMA {
                let (old_release, old_cases) = retained_claim(&row)?;
                previous
                    .claim(old_release, &old_cases)
                    .map_err(|_| refusal("heldout-history"))?;
            } else if schema.starts_with("aukora-immune-heldout-") {
                return Err(refusal("heldout-history"));
            }
        }
        previous.claim(release, cases)?;
        let body = claim_body(release, cases)?;
        let context = self.transaction.observation_context()?;
        let appended = self.transaction.append_fact(FactRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: FactKind::BootFacts,
            actor: "immune".to_owned(),
            body: body.clone(),
        })?;
        retained_claim(&appended)?;
        if appended.authority != context.authority
            || appended.at != context.at
            || payload(&appended)? != body
        {
            return Err(refusal("heldout-history"));
        }
        self.transaction.commit_observations()
    }
}

#[derive(Debug)]
pub struct HeldOut {
    release: Digest32,
    corpus: Corpus,
}

impl HeldOut {
    pub fn admit(
        release: Digest32,
        fresh: Corpus,
        fixed: &Corpus,
        history: &mut impl History,
    ) -> Result<Self> {
        let identities: Vec<_> = fresh
            .vectors()
            .iter()
            .map(|vector| (vector.id.clone(), vector.scenario_digest))
            .collect();
        let (new_ids, new_scenarios) = batch(&identities)?;
        if fixed.vectors().iter().any(|vector| {
            new_ids.contains(&vector.id) || new_scenarios.contains(&vector.scenario_digest)
        }) {
            return Err(refusal("heldout-reused"));
        }
        history.claim(release, &identities)?;
        Ok(Self {
            release,
            corpus: fresh,
        })
    }

    pub fn release(&self) -> Digest32 {
        self.release
    }

    pub fn vectors(&self) -> &[AttackVector] {
        self.corpus.vectors()
    }

    pub fn root(&self) -> Digest32 {
        self.corpus.root()
    }
}
