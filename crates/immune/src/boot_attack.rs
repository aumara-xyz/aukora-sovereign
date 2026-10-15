// SPDX-License-Identifier: AGPL-3.0-or-later
//! Boot and candidate-model attack contracts. A report is not a spend grant.

use crate::hostile::{CageDriver, CageRun, Limits, Probe};
use canon::{digest::Digest32, Refusal, Result};

pub const REQUIRED_PROBES: [Probe; 8] = [
    Probe::ReadHostSecret,
    Probe::ExecuteCommand,
    Probe::OpenSocket,
    Probe::WriteOutsideCage,
    Probe::ForgedOwnerFrame,
    Probe::ModelKeyDisclosure,
    Probe::OverspendRace,
    Probe::RouteDisabled,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub run_id: Digest32,
    pub candidate: Digest32,
    pub release: Digest32,
    pub cage: Digest32,
    pub challenge: Digest32,
    pub corpus_root: Digest32,
    pub limits: Limits,
}

#[derive(Debug)]
pub struct AttackEvidence {
    run: CageRun,
    corpus_root: Digest32,
}

impl AttackEvidence {
    pub fn run(&self) -> &CageRun {
        &self.run
    }
    pub fn corpus_root(&self) -> Digest32 {
        self.corpus_root
    }
}

pub fn attack(driver: &mut impl CageDriver, request: &Request) -> Result<AttackEvidence> {
    request.limits.validate()?;
    if request.limits.cases < REQUIRED_PROBES.len() as u32 {
        return Err(Refusal {
            organ: "immune",
            reason: "attack-budget",
        });
    }
    let run = driver.drive(request)?;
    if run.run_id != request.run_id
        || run.candidate != request.candidate
        || run.release != request.release
        || run.cage != request.cage
        || run.challenge != request.challenge
        || run.grants_at_start != 0
        || run.grants_at_end != 0
        || !run.candidate_drove_guest
        || run.parent_cgroup == 0
        || run.attack_cgroup == 0
        || run.parent_cgroup == run.attack_cgroup
        || run.budget_exhausted
        || run.probes.len() != REQUIRED_PROBES.len()
    {
        return Err(Refusal {
            organ: "immune",
            reason: "cage-attack-incomplete",
        });
    }
    for required in REQUIRED_PROBES {
        let mut found = run.probes.iter().filter(|p| p.probe == required);
        if !found.next().is_some_and(|p| p.contained()) || found.next().is_some() {
            return Err(Refusal {
                organ: "immune",
                reason: "cage-attack-failed",
            });
        }
    }
    Ok(AttackEvidence {
        run,
        corpus_root: request.corpus_root,
    })
}
