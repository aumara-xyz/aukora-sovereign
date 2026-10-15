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
    alg::AlgorithmId,
    digest::Digest32,
    health::{
        Cell, CheckId, CheckRef, CheckSpec, CornerId, HealthEvidence, HealthReason, HealthSnapshot,
        OrganId, CHECKS, CORNERS, HEALTH_FORMAT_VERSION,
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
        self.sample_with_targets(context, evidence, &[], usage)
    }

    /// Includes digest mismatches measured by Body in this sample. Target count
    /// is bounded before inspection. Existing evidence is validated before any
    /// replacement, so a target failure cannot hide malformed or duplicate reports.
    pub fn sample_with_targets(
        &mut self,
        context: Context,
        evidence: Vec<HealthEvidence>,
        targets: &[TargetObservation<'_>],
        usage: SampleBudget,
    ) -> Result<HealthSnapshot> {
        self.cadence
            .advance(context.observed_at_ms, usage.periods())?;
        usage.check()?;
        if evidence.len() > canon::health::MAX_EVIDENCE_COUNT {
            return Err(refusal("mhc-evidence-limit"));
        }
        if targets.len() > canon::health::MAX_EVIDENCE_COUNT {
            return Err(refusal("mhc-target-limit"));
        }
        let mut snapshot = compute(context, evidence)?;
        let mut changed = false;
        for target in targets {
            for failure in target.failures() {
                // Validate each failure before merging, including its observation
                // time. A later target must not conceal an invalid earlier one.
                compute(context, vec![failure.clone()])?;
                if let Some(report) = snapshot
                    .evidence
                    .iter_mut()
                    .find(|report| report.check == failure.check)
                {
                    *report = failure;
                } else {
                    snapshot.evidence.push(failure);
                }
                changed = true;
            }
        }
        if changed {
            compute(context, snapshot.evidence)
        } else {
            Ok(snapshot)
        }
    }

    /// `sample`, then the projection of its snapshot onto the geometry.
    pub fn attest(
        &mut self,
        context: Context,
        evidence: Vec<HealthEvidence>,
        usage: SampleBudget,
        geometry: &Geometry,
    ) -> Result<Attestation> {
        self.attest_with_targets(context, evidence, &[], usage, geometry)
    }

    /// Samples Body target failures with the organ reports, then projects the
    /// reduced snapshot. Other organs must supply their own corner-side reports.
    pub fn attest_with_targets(
        &mut self,
        context: Context,
        evidence: Vec<HealthEvidence>,
        targets: &[TargetObservation<'_>],
        usage: SampleBudget,
        geometry: &Geometry,
    ) -> Result<Attestation> {
        let snapshot = self.sample_with_targets(context, evidence, targets, usage)?;
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

/// Body-owned targets with fixed registry mappings. Display names do not select
/// a check, and no variant can report for Gate, Kira or another organ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    RunningBinary,
    Shell,
    AntibodyCorpus,
    IndexPin,
}

impl Target {
    fn checks(self) -> &'static [CheckSpec] {
        const BINARY: &[CheckSpec] = &[CHECKS[76].spec(), CORNERS[12].specs()[1]];
        const SHELL: &[CheckSpec] = &[CHECKS[77].spec()];
        const CORPUS: &[CheckSpec] = &[CHECKS[85].spec(), CORNERS[13].specs()[1]];
        const INDEX: &[CheckSpec] = &[CORNERS[16].specs()[1]];
        match self {
            Self::RunningBinary => BINARY,
            Self::Shell => SHELL,
            Self::AntibodyCorpus => CORPUS,
            Self::IndexPin => INDEX,
        }
    }
}

/// A target read in its actual context by the supervisor, with its Body source
/// selected separately from the target's display name. No wire decoder exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetObservation<'a> {
    pub target: Target,
    pub context: Context,
    pub check: &'a TargetCheck,
}

impl TargetObservation<'_> {
    /// Both drift and proven tampering fail the registered Body checks. A match
    /// or an unavailable target adds no report: neither establishes the complete
    /// invariant, such as the shell's manifest together with its serving policy.
    pub fn failures(&self) -> Vec<HealthEvidence> {
        if !self
            .check
            .observed
            .is_some_and(|observed| observed != self.check.expected)
        {
            return Vec::new();
        }
        self.target
            .checks()
            .iter()
            .map(|spec| HealthEvidence {
                v: HEALTH_FORMAT_VERSION,
                algorithm: AlgorithmId::Sha256,
                check: spec.check,
                reporter: OrganId::Body,
                epoch: self.context.epoch,
                sequence: self.context.sequence,
                observed_at_ms: self.context.observed_at_ms,
                expires_at_ms: self
                    .context
                    .observed_at_ms
                    .saturating_add(spec.freshness_ms)
                    .min(canon::json::MAX_SAFE_INTEGER as u64),
                cell: Cell::Failed,
                reason: HealthReason::InvariantFailed,
                commitment: self.context.commitment,
            })
            .collect()
    }
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
