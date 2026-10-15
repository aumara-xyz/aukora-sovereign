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

// These obsolete authority declarations have no name outside this scope and
// cannot be called outside it. The constant evaluates no authority transition.
#[allow(dead_code)]
#[rustfmt::skip]
const _: () = {
/// Exact owner-approved state transition; concern labels do not select an action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineAction {
    Quarantine,
    Recover,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineRequest {
    pub resource: String,
    pub concern: Concern,
    pub memory_note: Option<canon::ids::NoteId>,
}

/// A new target format. None of these fields is added to a frozen C3 or C5 object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineTransition {
    pub action: QuarantineAction,
    pub request: QuarantineRequest,
    pub previous: Option<Digest32>,
}

impl QuarantineTransition {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        use canon::json::Value;
        quarantine_resource(&self.request.resource)?;
        if self.action == QuarantineAction::Recover && self.previous.is_none() {
            return Err(refusal("not-quarantined"));
        }
        let text = |value: &str| Value::checked_text(value.to_owned());
        let fields = match self.request.concern {
            Concern::Drift { expected, observed } => {
                if expected == observed {
                    return Err(refusal("quarantine-concern"));
                }
                vec![
                    ("kind".into(), text("drift")?),
                    ("expected".into(), text(&expected.to_string())?),
                    ("observed".into(), text(&observed.to_string())?),
                ]
            }
            Concern::ProvenTampering { verified_record } => vec![
                ("kind".into(), text("proven-tampering")?),
                (
                    "verified_record".into(),
                    text(&verified_record.to_string())?,
                ),
            ],
            Concern::Unavailable => vec![("kind".into(), text("unavailable")?)],
        };
        Ok(Value::checked_object(vec![
            ("schema".into(), text("aukora-immune-quarantine-v1")?),
            (
                "action".into(),
                text(match self.action {
                    QuarantineAction::Quarantine => "quarantine",
                    QuarantineAction::Recover => "recover",
                })?,
            ),
            ("resource".into(), text(&self.request.resource)?),
            ("concern".into(), Value::checked_object(fields)?),
            (
                "memory_note".into(),
                match &self.request.memory_note {
                    Some(note) => text(note.as_str())?,
                    None => Value::null(),
                },
            ),
            (
                "previous".into(),
                match self.previous {
                    Some(previous) => text(&previous.to_string())?,
                    None => Value::null(),
                },
            ),
        ])?
        .canonical_bytes())
    }
}

/// State read from verified committed owner-authorized rows, never from a finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineState {
    pub transition: QuarantineTransition,
    pub owner_proposal: canon::ids::ProposalId,
    pub authority: canon::authority::AuthorityVersion,
    pub record: Digest32,
}

impl QuarantineState {
    pub fn view(&self) -> Result<QuarantineView> {
        self.transition.canonical_bytes()?;
        let bound = canon::json::MAX_SAFE_INTEGER as u64;
        if self.authority.sequence == 0
            || self.authority.sequence > bound
            || self.authority.epoch > bound
        {
            return Err(refusal("quarantine-state"));
        }
        Ok(QuarantineView {
            resource: self.transition.request.resource.clone(),
            concern: self.transition.request.concern.clone(),
            owner_proposal: Some(self.owner_proposal),
            quarantined: self.transition.action == QuarantineAction::Quarantine,
            memory_note: self.transition.request.memory_note.clone(),
        })
    }
}

/// Host-only atomic quarantine port. A backend must re-read committed state under
/// its authority lock, compare the exact target/base/new bytes, persist the passkey
/// counter, consume its proof once, apply or remove the resource restriction, and
/// append and durably commit its receipt together. Memory restrictions must update
/// Kira's quarantine state and index before success. Every failure rolls back all
/// changes. Evidence and facts cannot implement any of these transitions.
pub trait ImmuneAuthorityTxn: canon::authority::AuthorityTxn {
    /// Read only committed owner state, verifying its covering authority records.
    fn quarantine_state(&mut self, _resource: &str) -> Result<Option<QuarantineState>> {
        Err(refusal("quarantine-backend-unavailable"))
    }

    /// Return only after durable commit. The ended authority transaction cannot
    /// append again; `quarantine_state` remains available for committed read-back.
    fn commit_quarantine(
        &mut self,
        _proof: canon::authority::VerifiedProof,
        _transition: &QuarantineTransition,
    ) -> Result<()> {
        Err(refusal("quarantine-backend-unavailable"))
    }
}

/// A failed health cell cannot call this without its own fresh owner proof.
pub fn quarantine(
    transaction: &mut impl ImmuneAuthorityTxn,
    proof: canon::authority::VerifiedProof,
    request: QuarantineRequest,
) -> Result<QuarantineView> {
    quarantine_resource(&request.resource)?;
    let current = transaction.quarantine_state(&request.resource)?;
    if current
        .as_ref()
        .is_some_and(|state| state.transition.action == QuarantineAction::Quarantine)
    {
        return Err(refusal("already-quarantined"));
    }
    owner_quarantine_change(
        transaction,
        proof,
        request,
        current,
        QuarantineAction::Quarantine,
    )
}

/// Recovery retains the recorded concern and note identity and needs a fresh proof.
pub fn recover(
    transaction: &mut impl ImmuneAuthorityTxn,
    proof: canon::authority::VerifiedProof,
    resource: &str,
) -> Result<QuarantineView> {
    quarantine_resource(resource)?;
    let current = transaction
        .quarantine_state(resource)?
        .ok_or(refusal("not-quarantined"))?;
    if current.transition.request.resource != resource {
        return Err(refusal("quarantine-state"));
    }
    if current.transition.action != QuarantineAction::Quarantine {
        return Err(refusal("not-quarantined"));
    }
    owner_quarantine_change(
        transaction,
        proof,
        current.transition.request.clone(),
        Some(current),
        QuarantineAction::Recover,
    )
}

fn owner_quarantine_change(
    transaction: &mut impl ImmuneAuthorityTxn,
    proof: canon::authority::VerifiedProof,
    request: QuarantineRequest,
    current: Option<QuarantineState>,
    action: QuarantineAction,
) -> Result<QuarantineView> {
    use canon::authority::{BaseDigest, OwnerOperation};
    let previous = current
        .as_ref()
        .map(|state| {
            state.view()?;
            if state.transition.request.resource != request.resource {
                return Err(refusal("quarantine-state"));
            }
            Ok(Digest32::sha256(&state.transition.canonical_bytes()?))
        })
        .transpose()?;
    let transition = QuarantineTransition {
        action,
        request,
        previous,
    };
    let bytes = transition.canonical_bytes()?;
    let auth = proof.authorization();
    let expected_base = previous.map_or(BaseDigest::Absent, BaseDigest::Present);
    let context = transaction.authority_append_context(&proof)?;
    let binding = transaction.owner_binding(proof.credential_id())?;
    if proof.transaction_id() != transaction.transaction_id()
        || auth.op != OwnerOperation::Apply
        || auth.target != format!("immune.quarantine:{}", transition.request.resource)
        || auth.cell.is_some()
        || auth.base_sha256 != expected_base
        || auth.new_sha256 != Digest32::sha256(&bytes)
        || binding.v != 1
        || binding.credential_id != *proof.credential_id()
        || binding.epoch != auth.epoch
        || binding.public_key != *proof.public_key()
        || binding.algorithm != proof.algorithm()
        || binding.top_origin != proof.top_origin()
        || context.authority.epoch != auth.epoch
        || context.at < 0
        || auth.expires_at <= context.at
        || current.as_ref().is_some_and(|state| {
            state.authority.epoch > auth.epoch
                || state.authority.sequence >= context.authority.sequence
        })
        || transaction.rebuild_authorization(&auth.proposal, OwnerOperation::Apply)? != *auth
        || auth.canonical_bytes()? != proof.authorization_bytes()
    {
        return Err(refusal("quarantine-authorization"));
    }
    transaction.check_authorization_live(auth)?;
    let proposal = auth.proposal;
    transaction.commit_quarantine(proof, &transition)?;
    let committed = transaction
        .quarantine_state(&transition.request.resource)?
        .ok_or(refusal("quarantine-not-committed"))?;
    if committed.transition != transition
        || committed.owner_proposal != proposal
        || committed.authority.epoch != context.authority.epoch
        || committed.authority.sequence < context.authority.sequence
    {
        return Err(refusal("quarantine-not-committed"));
    }
    committed.view()
}

fn quarantine_resource(resource: &str) -> Result<()> {
    if resource.is_empty()
        || resource.len() > 128
        || !resource
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(refusal("quarantine-resource"));
    }
    Ok(())
}
};
