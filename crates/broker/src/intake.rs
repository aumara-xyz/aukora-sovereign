// SPDX-License-Identifier: AGPL-3.0-or-later
//! Intake observations never grant spending authority. The runner is supervisor supplied.

use crate::{identity::ModelName, provider::ModelSource};
use canon::{codes, digest::Digest32, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub model: ModelName,
    pub source: ModelSource,
    pub cage_digest: Digest32,
    pub release_digest: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntakeChallenge {
    pub candidate: Candidate,
    pub nonce: [u8; 32],
    pub generation: u64,
    pub policy: IntakePolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntakePolicy {
    pub corpus_root: Digest32,
    pub required_active: u32,
    pub required_heldout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CageAttackReport {
    pub challenge: IntakeChallenge,
    pub completed_active: u32,
    pub completed_heldout: u32,
    pub failures: u32,
    pub guest_grants_at_start: u32,
    pub guest_grants_at_end: u32,
    pub guest_was_driven_by_candidate: bool,
    pub isolated_cgroup: bool,
    pub report_commitment: Digest32,
}

pub trait IntakeRunner {
    fn attack_cage(&mut self, challenge: &IntakeChallenge) -> Result<CageAttackReport>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedModel {
    candidate: Candidate,
    generation: u64,
    intake_commitment: Digest32,
}

impl AdmittedModel {
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn intake_commitment(&self) -> Digest32 {
        self.intake_commitment
    }
}

#[derive(Debug, Default)]
pub struct ModelSlot {
    generation: u64,
    admitted: Option<AdmittedModel>,
}

impl ModelSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn admitted(&self) -> Option<&AdmittedModel> {
        self.admitted.as_ref()
    }

    pub fn disable(&mut self) -> Result<()> {
        self.admitted = None;
        self.generation = self
            .generation
            .checked_add(1)
            .filter(|v| *v <= crate::grant::MAX_SAFE)
            .ok_or(codes::BROKER_GENERATION_EXHAUSTED)?;
        Ok(())
    }

    pub fn attack_and_admit<R: IntakeRunner>(
        &mut self,
        candidate: Candidate,
        policy: IntakePolicy,
        runner: &mut R,
    ) -> Result<&AdmittedModel> {
        self.disable()?;
        if policy.required_active == 0 || policy.required_heldout == 0 {
            return Err(codes::BROKER_CONFIG);
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| codes::BROKER_STATE)?;
        let challenge = IntakeChallenge {
            candidate,
            nonce,
            generation: self.generation,
            policy,
        };
        let report = runner.attack_cage(&challenge)?;
        if report.challenge != challenge
            || report.completed_active != policy.required_active
            || report.completed_heldout != policy.required_heldout
            || report.failures != 0
            || report.guest_grants_at_start != 0
            || report.guest_grants_at_end != 0
            || !report.guest_was_driven_by_candidate
            || !report.isolated_cgroup
        {
            return Err(codes::BROKER_PROVIDER_UNAVAILABLE);
        }
        self.admitted = Some(AdmittedModel {
            candidate: challenge.candidate,
            generation: self.generation,
            intake_commitment: report.report_commitment,
        });
        self.admitted.as_ref().ok_or(codes::BROKER_STATE)
    }

    pub fn check_grant(&self, terms: &crate::grant::GrantTerms) -> Result<()> {
        let admitted = self
            .admitted
            .as_ref()
            .ok_or(codes::BROKER_PROVIDER_UNAVAILABLE)?;
        if terms.slot_generation != admitted.generation
            || terms.intake_commitment != admitted.intake_commitment
            || terms.source != admitted.candidate.source
            || terms.model != admitted.candidate.model
        {
            return Err(codes::BROKER_GRANT_MISMATCH);
        }
        Ok(())
    }
}
