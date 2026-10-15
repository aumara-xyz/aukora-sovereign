// SPDX-License-Identifier: AGPL-3.0-or-later
//! Body observers use canon's fixed ids, source names and freshness ceilings.
//!
//! Body owns 18 private checks and one side of 8 corners. Probes here turn raw
//! Body facts into findings; a check with no probe, or whose source is not
//! wired, reports Unwritten and its cell fails. Nothing here grants anything.

use crate::posture::Posture;
use canon::health::{
    Cell, CheckRef, CheckSpec, HealthEvidence, HealthReason, OrganId, CHECKS, CORNERS,
    HEALTH_FORMAT_VERSION,
};
use canon::{alg::AlgorithmId, digest::Digest32};

pub const PRIVATE_CHECKS: [CheckSpec; 18] = [
    CHECKS[72].spec(),
    CHECKS[73].spec(),
    CHECKS[74].spec(),
    CHECKS[75].spec(),
    CHECKS[76].spec(),
    CHECKS[77].spec(),
    CHECKS[78].spec(),
    CHECKS[79].spec(),
    CHECKS[80].spec(),
    CHECKS[81].spec(),
    CHECKS[82].spec(),
    CHECKS[83].spec(),
    CHECKS[84].spec(),
    CHECKS[85].spec(),
    CHECKS[86].spec(),
    CHECKS[87].spec(),
    CHECKS[88].spec(),
    CHECKS[89].spec(),
];

pub const CORNER_CHECKS: [CheckSpec; 8] = [
    CORNERS[6].specs()[1],
    CORNERS[7].specs()[1],
    CORNERS[12].specs()[1],
    CORNERS[13].specs()[1],
    CORNERS[16].specs()[1],
    CORNERS[17].specs()[1],
    CORNERS[18].specs()[1],
    CORNERS[19].specs()[1],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub commitment: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Finding {
    Satisfied,
    Failed,
    Unwritten,
    NotChecked,
    Unreachable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyObservation {
    pub check: CheckRef,
    pub context: Context,
    pub finding: Finding,
}

/// Supervisor-owned observations from the named Body sources; no wire decoder.
pub struct BodyFacts<'a> {
    pub context: Context,
    pub observations: &'a [BodyObservation],
}

/// One raw input as the Body code that owns it measured it. The supervisor fills
/// these from its own observations; nothing here is decoded from guest or wire text.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Measured<T> {
    /// No source is connected for this input; the checks it feeds report Unwritten.
    #[default]
    Unwired,
    /// The connected source has not completed a measurement.
    NotChecked,
    /// The connected source could not be reached.
    Unreachable,
    /// A value together with the context it was actually read in.
    At(Context, T),
}

/// A recorded value and the value Body measured from what is running or served.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Agreement<T> {
    /// What the approved record, or the other organ of a corner, holds as Body read it.
    pub recorded: T,
    /// What Body measured from the bytes or state actually in use.
    pub measured: T,
}

impl<T: Eq> Agreement<T> {
    /// True only when the two values are equal.
    pub fn holds(&self) -> bool {
        self.recorded == self.measured
    }
}

/// The shell's served asset manifest and serving policy, each against its approved value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShellAssets {
    pub manifest: Agreement<Digest32>,
    pub policy: Agreement<Digest32>,
}

impl ShellAssets {
    /// True only when both the manifest and the policy equal their approved digests.
    pub fn holds(&self) -> bool {
        self.manifest.holds() && self.policy.holds()
    }
}

/// Raw Body facts for one MHC sample. Every input defaults to `Unwired`, so a
/// check whose source the supervisor has not connected fails as unwritten.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BodyState {
    /// The live sandbox posture (private checks 1 to 4). A posture whose own
    /// observation time differs from the time of its context fails those checks.
    pub posture: Measured<Posture>,
    /// The approved release's binary digest against the measured running binary
    /// (private check 5 and Body's side of corner 13).
    pub running_release: Measured<Agreement<Digest32>>,
    /// The approved shell manifest and policy against what the shell serves (private check 6).
    pub shell_assets: Measured<ShellAssets>,
    /// The antibody corpus root in the release fact against the active corpus root
    /// (private check 14 and Body's side of corner 14).
    pub antibody_root: Measured<Agreement<Digest32>>,
    /// Kira's verified head as Body read it against the OpenViking index pin
    /// (Body's side of corner 17).
    pub index_pin: Measured<Agreement<Digest32>>,
}

/// Runs Body's probes over raw facts and returns one observation for each of its
/// 26 checks, in `PRIVATE_CHECKS` then `CORNER_CHECKS` order. Checks with no probe
/// here report Unwritten; their owning rows add the probe.
pub fn observe(context: Context, state: &BodyState) -> Vec<BodyObservation> {
    let unwritten = (context, Finding::Unwritten);
    let posture_in_context = match &state.posture {
        Measured::At(at, posture) => posture.observed_at_ms == at.observed_at_ms,
        _ => true,
    };
    let posture = |holds: fn(&Posture) -> bool| {
        probe(context, &state.posture, |p| posture_in_context && holds(p))
    };
    let release = probe(context, &state.running_release, Agreement::holds);
    let antibody = probe(context, &state.antibody_root, Agreement::holds);
    let private = [
        // 1. Only the trusted supervisor reads FD 3.
        posture(|p| p.fd3_supervisor_only),
        // 2. No exec or socket capability, inside a cage whose isolation was read back.
        posture(|p| {
            p.execve_denied && p.execveat_denied && p.sockets_denied && p.isolation_current
        }),
        // 3. The live filter denies execve and execveat.
        posture(|p| p.execve_denied && p.execveat_denied),
        // 4. FD 4 is in its bounded data-only mode.
        posture(|p| p.fd4_data_only),
        // 5. The running binary is the approved one.
        release,
        // 6. Shell assets and policy are the approved ones.
        probe(context, &state.shell_assets, ShellAssets::holds),
        unwritten, // 7. face sandboxes
        unwritten, // 8. owner ceremony origins
        unwritten, // 9. site isolation
        unwritten, // 10. WASM cell re-execution
        unwritten, // 11. model key boundary
        unwritten, // 12. broker reservations
        unwritten, // 13. broker settlements
        // 14. The active antibody corpus is the released one.
        antibody,
        unwritten, // 15. immune floor
        // 16. Invalid labels fail; no live display probe is connected.
        display_types(context),
        unwritten, // 17. app grant boundary
        unwritten, // 18. release pointer
    ];
    let corners = [
        unwritten, // 7. frontdoor origins
        unwritten, // 8. frontdoor unlock limits
        release,   // 13. running binary equals the approved release
        antibody,  // 14. antibody corpus root equals the release fact
        // 17. The OpenViking index pin matches Kira's head.
        probe(context, &state.index_pin, Agreement::holds),
        unwritten, // 18. FD 3 memory calls
        unwritten, // 19. egress allowlist
        unwritten, // 20. address and TLS identity
    ];
    PRIVATE_CHECKS
        .iter()
        .chain(CORNER_CHECKS.iter())
        .zip(private.into_iter().chain(corners))
        .map(|(spec, (context, finding))| BodyObservation {
            check: spec.check,
            context,
            finding,
        })
        .collect()
}

/// Turns Body observations into evidence for exactly Body's 26 registered checks.
/// A check with no observation reports Unwritten and a duplicated one reports
/// invalid evidence. An observation timed after the sample is invalid; one from
/// another epoch, sequence or commitment is a context mismatch; all of these fail.
/// A satisfied observation older than its freshness limit is stale (undetermined).
/// Observations of checks Body does not own produce no evidence.
pub fn health(facts: &BodyFacts<'_>) -> Vec<HealthEvidence> {
    PRIVATE_CHECKS
        .iter()
        .chain(CORNER_CHECKS.iter())
        .map(|spec| {
            let mut matching = facts.observations.iter().filter(|o| o.check == spec.check);
            match (matching.next(), matching.next()) {
                (None, _) => report(spec, facts.context, Cell::Failed, HealthReason::Unwritten),
                (Some(_), Some(_)) => report(
                    spec,
                    facts.context,
                    Cell::Failed,
                    HealthReason::InvalidEvidence,
                ),
                (Some(observation), None) => measured(spec, facts.context, observation),
            }
        })
        .collect()
}

/// Body's probes and their evidence for one MHC sample.
pub fn evidence(context: Context, state: &BodyState) -> Vec<HealthEvidence> {
    let observations = observe(context, state);
    health(&BodyFacts {
        context,
        observations: &observations,
    })
}

fn probe<T>(
    requested: Context,
    input: &Measured<T>,
    holds: impl Fn(&T) -> bool,
) -> (Context, Finding) {
    match input {
        Measured::Unwired => (requested, Finding::Unwritten),
        Measured::NotChecked => (requested, Finding::NotChecked),
        Measured::Unreachable => (requested, Finding::Unreachable),
        Measured::At(observed, value) if holds(value) => (*observed, Finding::Satisfied),
        Measured::At(observed, _) => (*observed, Finding::Failed),
    }
}

/// Private check 16 rejects empty or colliding display labels. Distinct static
/// labels do not observe live canvases, so this check remains unwritten.
fn display_types(context: Context) -> (Context, Finding) {
    let labels = [
        crate::organ_map::LABEL,
        pentora::motion::FINGERPRINT_LABEL,
        pentora::bloom::BLOOM_LABEL,
    ];
    let distinct = labels
        .iter()
        .enumerate()
        .all(|(i, label)| !label.is_empty() && labels[i + 1..].iter().all(|other| other != label));
    let finding = if distinct {
        Finding::Unwritten
    } else {
        Finding::Failed
    };
    (context, finding)
}

fn measured(spec: &CheckSpec, requested: Context, observation: &BodyObservation) -> HealthEvidence {
    let observed = observation.context;
    if observed.observed_at_ms > requested.observed_at_ms {
        return report(spec, requested, Cell::Failed, HealthReason::InvalidEvidence);
    }
    if observed.epoch != requested.epoch
        || observed.sequence != requested.sequence
        || observed.commitment != requested.commitment
    {
        return report(spec, observed, Cell::Failed, HealthReason::ContextMismatch);
    }
    let (cell, reason) = match observation.finding {
        Finding::Satisfied => (Cell::Verified, HealthReason::Satisfied),
        Finding::Failed => (Cell::Failed, HealthReason::InvariantFailed),
        Finding::Unwritten => (Cell::Failed, HealthReason::Unwritten),
        Finding::NotChecked => (Cell::Undetermined, HealthReason::NotChecked),
        Finding::Unreachable => (Cell::Undetermined, HealthReason::Unreachable),
    };
    let mut evidence = report(spec, observed, cell, reason);
    if cell == Cell::Verified && requested.observed_at_ms > evidence.expires_at_ms {
        evidence.cell = Cell::Undetermined;
        evidence.reason = HealthReason::Stale;
    }
    evidence
}

fn report(spec: &CheckSpec, context: Context, cell: Cell, reason: HealthReason) -> HealthEvidence {
    HealthEvidence {
        v: HEALTH_FORMAT_VERSION,
        algorithm: AlgorithmId::Sha256,
        check: spec.check,
        reporter: OrganId::Body,
        epoch: context.epoch,
        sequence: context.sequence,
        observed_at_ms: context.observed_at_ms,
        expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
        commitment: context.commitment,
        cell,
        reason,
    }
}
