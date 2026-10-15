// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kira's registered observation contracts; unwritten observers report failure.

use canon::alg::AlgorithmId;
use canon::digest::Digest32;
use canon::health::{
    Cell, CheckRef, CheckSpec, HealthEvidence, HealthReason, OrganId, CHECKS, CORNERS,
    HEALTH_FORMAT_VERSION,
};

/// Private 1: authentication of every retained note ciphertext, at most 30 s old.
pub const CIPHERTEXT_INTEGRITY: CheckSpec = CHECKS[36].spec();
/// Private 2: active memory key wrapping at the current root epoch, at most 30 s old.
pub const KEY_ENVELOPE: CheckSpec = CHECKS[37].spec();
/// Private 3: note identifiers commit to saved canonical content, at most 30 s old.
pub const NOTE_COMMITMENTS: CheckSpec = CHECKS[38].spec();
/// Private 4: contiguous verified memory sequence and previous hash, at most 5 s old.
pub const CHAIN_HEAD: CheckSpec = CHECKS[39].spec();
/// Private 5: the verified memory head has an Aura anchor, at most 5 s old.
pub const AURA_ANCHOR: CheckSpec = CHECKS[40].spec();
/// Private 6: recall and listing enforce the principal's permission, at most 5 s old.
pub const PRINCIPAL_PERMISSIONS: CheckSpec = CHECKS[41].spec();
/// Private 7: plaintext recalls retain note identifiers and save citations, at most 5 s old.
pub const RECALL_CITATIONS: CheckSpec = CHECKS[42].spec();
/// Private 8: forgotten listings expose metadata without cold plaintext, at most 5 s old.
pub const FORGOTTEN_LISTING: CheckSpec = CHECKS[43].spec();
/// Private 9: demotion retains the note with a later sequence, at most 5 s old.
pub const DEMOTION_RECORDS: CheckSpec = CHECKS[44].spec();
/// Private 10: permission changes have owner authorization and Aura citations, at most 5 s old.
pub const PERMISSION_RECORDS: CheckSpec = CHECKS[45].spec();
/// Private 11: quarantine changes require owner authorization, at most 5 s old.
pub const QUARANTINE_RECORDS: CheckSpec = CHECKS[46].spec();
/// Private 12: the recall index is pinned to the verified memory head, at most 5 s old.
pub const INDEX_PIN: CheckSpec = CHECKS[47].spec();
/// Private 13: memory cells are re-executed and effect digests compared, at most 5 s old.
pub const SAVE_CELL_EFFECTS: CheckSpec = CHECKS[48].spec();
/// Private 14: saved and recalled memory keeps non-owner provenance, at most 5 s old.
pub const MEMORY_PROVENANCE: CheckSpec = CHECKS[49].spec();
/// Private 15: memory permission epochs cannot roll back, at most 5 s old.
pub const PERMISSION_EPOCH: CheckSpec = CHECKS[50].spec();
/// Private 16: memory pages enforce item, cursor and frame bounds, at most 5 s old.
pub const PAGE_BOUNDS: CheckSpec = CHECKS[51].spec();
/// Private 17: disclosure receipts identify permission and cited note, at most 5 s old.
pub const DISCLOSURE_RECEIPTS: CheckSpec = CHECKS[52].spec();
/// Private 18: records and key envelopes name algorithms and versions, at most 30 s old.
pub const RECORD_FORMATS: CheckSpec = CHECKS[53].spec();

/// Kira's 18 private observations in canon's local-index order.
pub const PRIVATE_CHECKS: [CheckSpec; 18] = [
    CIPHERTEXT_INTEGRITY,
    KEY_ENVELOPE,
    NOTE_COMMITMENTS,
    CHAIN_HEAD,
    AURA_ANCHOR,
    PRINCIPAL_PERMISSIONS,
    RECALL_CITATIONS,
    FORGOTTEN_LISTING,
    DEMOTION_RECORDS,
    PERMISSION_RECORDS,
    QUARANTINE_RECORDS,
    INDEX_PIN,
    SAVE_CELL_EFFECTS,
    MEMORY_PROVENANCE,
    PERMISSION_EPOCH,
    PAGE_BOUNDS,
    DISCLOSURE_RECEIPTS,
    RECORD_FORMATS,
];

/// Corner 3: Kira's root-wrapping epoch agrees with AUMLOK, at most 30 s old.
pub const ROOT_EPOCH_CORNER: CheckSpec = CORNERS[2].specs()[1];
/// Corner 4: every permission change has an AUMLOK-verified owner signature, at most 5 s old.
pub const PERMISSION_SIGNATURE_CORNER: CheckSpec = CORNERS[3].specs()[1];
/// Corner 9: Kira's verified head agrees with its Aura anchor, at most 5 s old.
pub const AURA_HEAD_CORNER: CheckSpec = CORNERS[8].specs()[1];
/// Corner 10: demotion and quarantine counts agree with Aura, at most 5 s old.
pub const ACTION_COUNTS_CORNER: CheckSpec = CORNERS[9].specs()[1];
/// Corner 15: backup commitments agree with Kira's head, at most 60 s old.
pub const BACKUP_HEAD_CORNER: CheckSpec = CORNERS[14].specs()[0];
/// Corner 16: each disclosed memory has a Kira permission, at most 5 s old.
pub const DISCLOSURE_PERMISSION_CORNER: CheckSpec = CORNERS[15].specs()[0];
/// Corner 17: the OpenViking index pin agrees with Kira's head, at most 5 s old.
pub const INDEX_HEAD_CORNER: CheckSpec = CORNERS[16].specs()[0];
/// Corner 18: recall receipts agree with the guest's FD 3 memory calls, at most 5 s old.
pub const RECALL_RECEIPTS_CORNER: CheckSpec = CORNERS[17].specs()[0];

/// Kira's eight independent corner sides in canon's corner-index order.
pub const CORNER_CHECKS: [CheckSpec; 8] = [
    ROOT_EPOCH_CORNER,
    PERMISSION_SIGNATURE_CORNER,
    AURA_HEAD_CORNER,
    ACTION_COUNTS_CORNER,
    BACKUP_HEAD_CORNER,
    DISCLOSURE_PERMISSION_CORNER,
    INDEX_HEAD_CORNER,
    RECALL_RECEIPTS_CORNER,
];

/// The common supervisor snapshot context; these fields confer no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthContext {
    /// Owner-state epoch requested by the supervisor.
    pub epoch: u64,
    /// Aura sequence requested by the supervisor.
    pub sequence: u64,
    /// Supervisor observation time in milliseconds.
    pub observed_at_ms: u64,
    /// Commitment identifying the common context to be independently observed.
    pub commitment: Digest32,
}

/// A measured result; no variant grants an operation or permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationVerdict {
    /// The observer established its registered invariant in the measured context.
    Satisfied,
    /// The observer measured a violation of its registered invariant.
    InvariantFailed,
    /// The observer measured conflicting commitments or state.
    Disagreement,
}

/// One observer's measured context, kept separate from the requested snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedCheck {
    /// The private check or Kira corner side that was actually inspected.
    pub check: CheckRef,
    /// Independently observed epoch, sequence, time and context commitment.
    pub context: HealthContext,
    /// Maximum lifetime claimed by this observation, bounded again by its spec.
    pub expires_at_ms: u64,
    /// Result of inspecting the registered source in this context.
    pub verdict: ObservationVerdict,
}

/// An absent implementation is distinct from an implemented but unavailable check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckObservation {
    /// No observer exists for this check; this always reports failure.
    Unwritten,
    /// The implemented observer has not yet completed this check.
    NotChecked,
    /// The implemented observer cannot reach its registered source.
    Unreachable,
    /// An observation tied to its own check and inspected context.
    Measured(ObservedCheck),
}

/// Native Kira observer interface; callers supply an organ-owned implementation.
/// The default reports Unwritten for every check. No wire parser supplies observers.
pub trait HealthObserver {
    fn observe(&mut self, _spec: CheckSpec, _requested: HealthContext) -> CheckObservation {
        CheckObservation::Unwritten
    }
}

/// Reports the missing implementation of every observer without inspecting state.
#[derive(Default)]
pub struct UnwrittenChecks;

impl HealthObserver for UnwrittenChecks {}

fn registered_kira_spec(spec: CheckSpec) -> bool {
    if spec.owner != OrganId::Kira {
        return false;
    }
    match spec.check {
        CheckRef::Private(id) if id.organ() == OrganId::Kira => {
            CHECKS[36 + usize::from(id.index() - 1)].spec() == spec
        }
        CheckRef::Corner { corner, side } if side == OrganId::Kira => CORNERS
            [usize::from(corner.index() - 1)]
        .specs()
        .contains(&spec),
        _ => false,
    }
}

fn report(
    spec: CheckSpec,
    context: HealthContext,
    cell: Cell,
    reason: HealthReason,
) -> HealthEvidence {
    HealthEvidence {
        v: HEALTH_FORMAT_VERSION,
        algorithm: AlgorithmId::Sha256,
        check: spec.check,
        reporter: OrganId::Kira,
        epoch: context.epoch,
        sequence: context.sequence,
        observed_at_ms: context.observed_at_ms,
        expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
        cell,
        reason,
        commitment: context.commitment,
    }
}

fn measured_report(
    spec: CheckSpec,
    requested: HealthContext,
    measured: ObservedCheck,
) -> HealthEvidence {
    let context = measured.context;
    let mut evidence = report(spec, context, Cell::Failed, HealthReason::InvalidEvidence);
    evidence.expires_at_ms = measured.expires_at_ms.min(evidence.expires_at_ms);
    if measured.check != spec.check
        || measured.expires_at_ms < context.observed_at_ms
        || context.observed_at_ms > requested.observed_at_ms
    {
        return report(spec, requested, Cell::Failed, HealthReason::InvalidEvidence);
    }
    if context.epoch != requested.epoch
        || context.sequence != requested.sequence
        || context.commitment != requested.commitment
    {
        evidence.reason = HealthReason::ContextMismatch;
        return evidence;
    }
    match measured.verdict {
        ObservationVerdict::InvariantFailed => {
            evidence.reason = HealthReason::InvariantFailed;
        }
        ObservationVerdict::Disagreement => {
            evidence.reason = HealthReason::Disagreement;
        }
        ObservationVerdict::Satisfied if requested.observed_at_ms > evidence.expires_at_ms => {
            evidence.cell = Cell::Undetermined;
            evidence.reason = HealthReason::Stale;
        }
        ObservationVerdict::Satisfied => {
            evidence.cell = Cell::Verified;
            evidence.reason = HealthReason::Satisfied;
        }
    }
    evidence
}

/// Collects exactly Kira's 18 private checks and eight independent corner sides.
/// Unwritten checks fail. Wrong check, context or time cannot report success, and
/// freshness is bounded by canon. No other organ's corner side is reported.
pub fn health(
    context: HealthContext,
    observer: &mut (impl HealthObserver + ?Sized),
) -> Vec<HealthEvidence> {
    PRIVATE_CHECKS
        .into_iter()
        .chain(CORNER_CHECKS)
        .map(|spec| {
            if !registered_kira_spec(spec) {
                return report(spec, context, Cell::Failed, HealthReason::InvalidEvidence);
            }
            match observer.observe(spec, context) {
                CheckObservation::Unwritten => {
                    report(spec, context, Cell::Failed, HealthReason::Unwritten)
                }
                CheckObservation::NotChecked => {
                    report(spec, context, Cell::Undetermined, HealthReason::NotChecked)
                }
                CheckObservation::Unreachable => {
                    report(spec, context, Cell::Undetermined, HealthReason::Unreachable)
                }
                CheckObservation::Measured(observation) => {
                    measured_report(spec, context, observation)
                }
            }
        })
        .collect()
}
