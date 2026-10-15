// SPDX-License-Identifier: AGPL-3.0-or-later
//! The MHC reduction is data-only; scheduling and observations belong to the supervisor.

use crate::health::Context;
use canon::{
    digest::Digest32,
    health::{HealthEvidence, HealthSnapshot},
    Refusal, Result,
};

pub const CADENCE_MS: u64 = 5_000;
pub const CPU_BUDGET_US: u64 = 20_000;
pub const IO_BUDGET_BYTES: u64 = 262_144;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleBudget {
    pub cpu_us: u64,
    pub io_bytes: u64,
}

impl SampleBudget {
    pub fn check(self) -> Result<()> {
        if self.cpu_us > CPU_BUDGET_US || self.io_bytes > IO_BUDGET_BYTES {
            return Err(Refusal {
                organ: "immune",
                reason: "mhc-budget",
            });
        }
        Ok(())
    }
}

pub fn compute(context: Context, evidence: Vec<HealthEvidence>) -> Result<HealthSnapshot> {
    HealthSnapshot::reduce(
        context.epoch,
        context.sequence,
        context.observed_at_ms,
        context.commitment,
        evidence,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cadence {
    next_ms: u64,
}

impl Cadence {
    pub fn new(first_ms: u64) -> Self {
        Self { next_ms: first_ms }
    }
    pub fn due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_ms
    }
    pub fn sampled(&mut self, now_ms: u64) -> Result<()> {
        if !self.due(now_ms) {
            return Err(Refusal {
                organ: "immune",
                reason: "mhc-not-due",
            });
        }
        self.next_ms = now_ms.checked_add(CADENCE_MS).ok_or(Refusal {
            organ: "immune",
            reason: "mhc-clock-range",
        })?;
        Ok(())
    }
}

pub struct MhcLoop {
    cadence: Cadence,
}

impl MhcLoop {
    pub fn new(first_ms: u64) -> Self {
        Self {
            cadence: Cadence::new(first_ms),
        }
    }

    pub fn due(&self, now_ms: u64) -> bool {
        self.cadence.due(now_ms)
    }

    pub fn sample(
        &mut self,
        context: Context,
        evidence: Vec<HealthEvidence>,
        usage: SampleBudget,
    ) -> Result<HealthSnapshot> {
        self.cadence.sampled(context.observed_at_ms)?;
        usage.check()?;
        if evidence.len() > canon::health::MAX_EVIDENCE_COUNT {
            return Err(Refusal {
                organ: "immune",
                reason: "mhc-evidence-limit",
            });
        }
        compute(context, evidence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Concern {
    Drift {
        expected: Digest32,
        observed: Digest32,
    },
    ProvenTampering {
        verified_record: Digest32,
    },
    Unavailable,
}

/// Display data only. This module has no quarantine or recovery mutator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineView {
    pub resource: String,
    pub concern: Concern,
    pub owner_proposal: Option<canon::ids::ProposalId>,
    pub quarantined: bool,
    pub memory_note: Option<canon::ids::NoteId>,
}
