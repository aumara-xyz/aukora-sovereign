// SPDX-License-Identifier: AGPL-3.0-or-later
//! Seeded attack scheduling. The driver owns the isolated cgroup and process.

use crate::{hostile::Limits, mhc::Concern};
use canon::{digest::Digest32, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub v: u16,
    pub seed: [u8; 32],
    pub release: Digest32,
    pub corpus_root: Digest32,
    pub parent_cgroup: u64,
    pub limits: Limits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub seed: [u8; 32],
    pub release: Digest32,
    pub corpus_root: Digest32,
    pub attack_cgroup: u64,
    pub attempted: u32,
    pub new_findings: Vec<Concern>,
    pub budget_exhausted: bool,
}

pub trait Driver {
    fn run_isolated(&mut self, request: &Request) -> Result<Observation>;
}

pub fn run(request: &Request, driver: &mut impl Driver) -> Result<Observation> {
    request.limits.validate()?;
    if request.v != 1 || request.parent_cgroup == 0 {
        return Err(canon::Refusal {
            organ: "immune",
            reason: "hypermutation-input",
        });
    }
    let report = driver.run_isolated(request)?;
    if report.seed != request.seed
        || report.release != request.release
        || report.corpus_root != request.corpus_root
        || report.attack_cgroup == 0
        || report.attack_cgroup == request.parent_cgroup
        || report.attempted == 0
        || report.attempted > request.limits.cases
        || report.new_findings.len() > request.limits.cases as usize
        || report.budget_exhausted
    {
        return Err(canon::Refusal {
            organ: "immune",
            reason: "hypermutation-incomplete",
        });
    }
    Ok(report)
}
