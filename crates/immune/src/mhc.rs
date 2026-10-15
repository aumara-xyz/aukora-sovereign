// SPDX-License-Identifier: AGPL-3.0-or-later
//! The MHC reduction is data-only; scheduling and observations belong to the supervisor.
//!
//! The loop samples on a fixed cadence under CPU and IO caps and reduces the five
//! organs' evidence through canon's single reduction. A failed cell is evidence
//! for quarantine or escalation, never authority: nothing here grants, approves,
//! quarantines or changes a gate decision.

use crate::health::Context;
use crate::organ_map::{self, OrganMap};
use canon::{
    digest::Digest32,
    health::{
        Cell, CheckId, CheckRef, CornerId, HealthEvidence, HealthReason, HealthSnapshot, OrganId,
        CHECKS, CORNERS,
    },
    Refusal, Result,
};
use pentora::geometry::Geometry;

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
            return Err(refusal("mhc-budget"));
        }
        Ok(())
    }

    /// Cadence periods this usage fills at the per-period caps; at least one.
    pub fn periods(self) -> u64 {
        self.cpu_us
            .div_ceil(CPU_BUDGET_US)
            .max(self.io_bytes.div_ceil(IO_BUDGET_BYTES))
            .max(1)
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

/// A fixed grid of `CADENCE_MS` slots anchored at the first slot.
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
    /// Spends the due slot; refuses before it. Slots missed while nothing sampled
    /// are skipped, so the next slot stays on the grid and lies after `now_ms`.
    pub fn sampled(&mut self, now_ms: u64) -> Result<()> {
        self.advance(now_ms, 1)
    }
    pub const fn next_ms(&self) -> u64 {
        self.next_ms
    }

    /// Spends the due slot and the `periods - 1` slots after it.
    fn advance(&mut self, now_ms: u64, periods: u64) -> Result<()> {
        if !self.due(now_ms) {
            return Err(refusal("mhc-not-due"));
        }
        let missed = (now_ms - self.next_ms) / CADENCE_MS;
        self.next_ms = missed
            .checked_add(periods.max(1))
            .and_then(|slots| slots.checked_mul(CADENCE_MS))
            .and_then(|step| self.next_ms.checked_add(step))
            .ok_or(refusal("mhc-clock-range"))?;
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

    pub const fn next_ms(&self) -> u64 {
        self.cadence.next_ms()
    }

    /// Reduces one sample taken at `context.observed_at_ms` with its measured usage.
    /// Refuses when no slot is due. The sample spends one slot per cadence period
    /// its usage filled at the caps, so an overrun delays the following samples and
    /// the reported usage averages at most the caps per period; an over-budget
    /// sample itself refuses. More than 130 reports refuse; canon's reduction
    /// validates the rest.
    pub fn sample(
        &mut self,
        context: Context,
        evidence: Vec<HealthEvidence>,
        usage: SampleBudget,
    ) -> Result<HealthSnapshot> {
        self.cadence
            .advance(context.observed_at_ms, usage.periods())?;
        usage.check()?;
        if evidence.len() > canon::health::MAX_EVIDENCE_COUNT {
            return Err(refusal("mhc-evidence-limit"));
        }
        compute(context, evidence)
    }

    /// `sample`, then the projection of its snapshot onto the geometry.
    pub fn attest(
        &mut self,
        context: Context,
        evidence: Vec<HealthEvidence>,
        usage: SampleBudget,
        geometry: &Geometry,
    ) -> Result<Attestation> {
        let snapshot = self.sample(context, evidence, usage)?;
        let map = organ_map::project(&snapshot, geometry)?;
        Ok(Attestation { snapshot, map })
    }
}

/// One MHC sample: the reduced snapshot and the organ map drawn from it. Both are
/// evidence only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attestation {
    pub snapshot: HealthSnapshot,
    pub map: OrganMap,
}

/// Where a failed cell sits. Evidence for escalation or a quarantine proposal; it
/// grants nothing and no gate decision reads it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// One organ's own check failed; the fault is that organ's.
    Private {
        check: CheckId,
        reason: HealthReason,
    },
    /// A shared corner failed; the fault is localised to its organ pair. `sides`
    /// holds each owner's report reason in the registered owner order.
    Corner {
        corner: CornerId,
        owners: [OrganId; 2],
        sides: [HealthReason; 2],
    },
}

/// Lists every failed cell of a snapshot, private checks first, in registry order.
/// A side with no report is `Missing`, repeated reports are `InvalidEvidence`, and
/// a report in another epoch, sequence or commitment is `ContextMismatch`. A failed
/// corner whose two reports are both satisfied in context is a `Disagreement`.
pub fn faults(snapshot: &HealthSnapshot) -> Vec<Fault> {
    let reason = |check: CheckRef| {
        let mut reports = snapshot.evidence.iter().filter(|e| e.check == check);
        match (reports.next(), reports.next()) {
            (None, _) => HealthReason::Missing,
            (Some(_), Some(_)) => HealthReason::InvalidEvidence,
            (Some(report), None)
                if report.epoch != snapshot.epoch
                    || report.sequence != snapshot.sequence
                    || report.commitment != snapshot.commitment =>
            {
                HealthReason::ContextMismatch
            }
            (Some(report), None) => report.reason,
        }
    };
    let private = CHECKS
        .iter()
        .zip(snapshot.private_cells.iter())
        .filter(|(_, cell)| **cell == Cell::Failed)
        .map(|(definition, _)| Fault::Private {
            check: definition.id,
            reason: reason(CheckRef::Private(definition.id)),
        });
    let corners = CORNERS
        .iter()
        .zip(snapshot.corner_cells.iter())
        .filter(|(_, cell)| **cell == Cell::Failed)
        .map(|(definition, _)| {
            let mut sides = definition.owners.map(|side| {
                reason(CheckRef::Corner {
                    corner: definition.id,
                    side,
                })
            });
            if sides.iter().all(|side| *side == HealthReason::Satisfied) {
                sides = [HealthReason::Disagreement; 2];
            }
            Fault::Corner {
                corner: definition.id,
                owners: definition.owners,
                sides,
            }
        });
    private.chain(corners).collect()
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

/// One target compared with the digest its receipt records. Plain data from the
/// supervisor's own reads; `resource` is a display name, never an instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetCheck {
    pub resource: String,
    /// The digest the receipt records for this target.
    pub expected: Digest32,
    /// The hash of the Aura record holding that receipt, present only when the
    /// record's chain and signature verified.
    pub verified_record: Option<Digest32>,
    /// The digest measured from the target now; `None` when it could not be read.
    pub observed: Option<Digest32>,
}

impl TargetCheck {
    /// `None` when the target matches its receipt. A mismatch against a verified
    /// record is proven tampering; a mismatch without one is drift, reported apart.
    pub fn concern(&self) -> Option<Concern> {
        match (self.observed, self.verified_record) {
            (None, _) => Some(Concern::Unavailable),
            (Some(observed), _) if observed == self.expected => None,
            (Some(_), Some(verified_record)) => Some(Concern::ProvenTampering { verified_record }),
            (Some(observed), None) => Some(Concern::Drift {
                expected: self.expected,
                observed,
            }),
        }
    }

    /// Owner-screen data for a concern. The view is never marked quarantined and
    /// carries no proposal; this module cannot quarantine anything.
    pub fn view(&self) -> Option<QuarantineView> {
        self.concern().map(|concern| QuarantineView {
            resource: self.resource.clone(),
            concern,
            owner_proposal: None,
            quarantined: false,
            memory_note: None,
        })
    }
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

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}
