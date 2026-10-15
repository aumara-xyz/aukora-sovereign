// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fresh release challenges have both identifier and content reuse checks.

use crate::ratchet::{AttackVector, Corpus};
use canon::{digest::Digest32, Refusal, Result};

pub const MAX_HELDOUT_CASES: usize = 1024;

pub trait History {
    /// Atomically retain every id and digest, or refuse the entire reused batch.
    fn claim(&mut self, release: Digest32, cases: &[(String, Digest32)]) -> Result<()>;
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
        if fresh.vectors().is_empty() || fresh.vectors().len() > MAX_HELDOUT_CASES {
            return Err(Refusal {
                organ: "immune",
                reason: "heldout-count",
            });
        }
        let mut scenarios = std::collections::BTreeSet::new();
        for candidate in fresh.vectors() {
            if !scenarios.insert(candidate.scenario_digest)
                || fixed.vectors().iter().any(|old| {
                    old.id == candidate.id || old.scenario_digest == candidate.scenario_digest
                })
            {
                return Err(Refusal {
                    organ: "immune",
                    reason: "heldout-reused",
                });
            }
        }
        let identities: Vec<_> = fresh
            .vectors()
            .iter()
            .map(|v| (v.id.clone(), v.scenario_digest))
            .collect();
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
