// SPDX-License-Identifier: AGPL-3.0-or-later
//! Boot and candidate-model attack contracts. A report is not a spend grant.

use crate::hostile::{refusal, CageDriver, CageRun, Limits, Probe, Usage};
use canon::{digest::Digest32, Result};

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

impl Request {
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if self.limits.cases < REQUIRED_PROBES.len() as u32 * 2 {
            return Err(refusal("attack-budget"));
        }
        Ok(())
    }

    /// Commits to this attempt, the candidate, installed release, cage,
    /// supervisor challenge, corpus and every resource ceiling.
    pub fn commitment(&self) -> Digest32 {
        let mut bytes = b"aukora:boot-self-attack:v1\0".to_vec();
        for value in [
            self.run_id,
            self.candidate,
            self.release,
            self.cage,
            self.challenge,
            self.corpus_root,
        ] {
            bytes.extend_from_slice(value.as_bytes());
        }
        for value in [
            self.limits.wall_ms,
            self.limits.cpu_us,
            self.limits.memory_bytes,
            self.limits.io_bytes,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.limits.output_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.limits.cases.to_be_bytes());
        Digest32::sha256(&bytes)
    }

    /// Both sides of a pair must use these same exact request-bound inputs.
    pub fn input_digest(&self, probe: Probe) -> Digest32 {
        let mut bytes = b"aukora:boot-self-attack-input:v1\0".to_vec();
        bytes.extend_from_slice(self.commitment().as_bytes());
        bytes.extend_from_slice(&(probe.name().len() as u32).to_be_bytes());
        bytes.extend_from_slice(probe.name().as_bytes());
        Digest32::sha256(&bytes)
    }
}

#[derive(Debug)]
pub struct AttackEvidence {
    run: CageRun,
    corpus_root: Digest32,
    request_commitment: Digest32,
    usage: Usage,
}

impl AttackEvidence {
    pub fn run(&self) -> &CageRun {
        &self.run
    }
    pub fn corpus_root(&self) -> Digest32 {
        self.corpus_root
    }
    pub fn request_commitment(&self) -> Digest32 {
        self.request_commitment
    }
    pub fn usage(&self) -> Usage {
        self.usage
    }
}

pub fn attack(driver: &mut impl CageDriver, request: &Request) -> Result<AttackEvidence> {
    request.validate()?;
    let began = std::time::Instant::now();
    let run = driver.drive(request)?;
    let usage = driver.resource_usage()?;
    if began.elapsed().as_millis() > u128::from(request.limits.wall_ms) {
        return Err(refusal("attack-budget"));
    }
    request
        .limits
        .permits(usage, REQUIRED_PROBES.len() as u32 * 2)?;
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
        return Err(refusal("cage-attack-incomplete"));
    }
    for required in REQUIRED_PROBES {
        let mut found = run.probes.iter().filter(|p| p.probe == required);
        if !found
            .next()
            .is_some_and(|p| p.contained() && p.input_digest == request.input_digest(required))
            || found.next().is_some()
        {
            return Err(refusal("cage-attack-failed"));
        }
    }
    Ok(AttackEvidence {
        run,
        corpus_root: request.corpus_root,
        request_commitment: request.commitment(),
        usage,
    })
}

/// Runs a self-attack on every invocation before calling the supplied
/// start closure once. The host still checks owner/release authorization itself;
/// this evidence has no conversion into a passkey proof, release or spend grant.
/// A failed attack never calls start. Direct launcher entry points must arrange
/// to use this seam themselves; this function cannot intercept other callers.
pub fn before_start<T>(
    driver: &mut impl CageDriver,
    request: &Request,
    start: impl FnOnce(AttackEvidence) -> Result<T>,
) -> Result<T> {
    start(attack(driver, request)?)
}
