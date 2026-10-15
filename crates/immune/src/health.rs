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
use canon::json::{self, Value, ValueView};
use canon::{alg::AlgorithmId, digest::Digest32};
use std::{fs::File, io::Read, path::Path};

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

/// Deployment's activation record. A pointer digest is not a verified signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveRelease {
    pub commit: String,
    pub release: Digest32,
    pub sequence: u64,
    pub pointer_sha256: Option<Digest32>,
    pub activated_at_ms: u64,
}

/// The supervisor's current owner-verified pointer and measured running release.
/// Populate only after verifying the owner's exact pointer bytes and reading the
/// running release; neither a deploy record nor health evidence supplies this fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasePointer {
    pub commit: String,
    pub release: Agreement<Digest32>,
    pub sequence: u64,
    pub pointer_sha256: Digest32,
}

/// Network's epoch and SHA-256 of the exact installed policy bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostPolicy {
    pub epoch: u64,
    pub sha256: Digest32,
}

/// Read-back written by the deploy egress verifier; it supplies no authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressStatus {
    pub policy: HostPolicy,
    pub loaded_policy_sha256: Digest32,
    pub loaded_ruleset_sha256: Digest32,
    pub live_ruleset_sha256: Digest32,
    pub ok: bool,
    pub observed_at_ms: u64,
}

/// Published endpoint and certificate digest, or an independent live measurement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressTlsIdentity {
    pub address: String,
    pub certificate_sha256: Digest32,
}

/// Raw Body facts for one MHC sample. Every input defaults to `Unwired`, so a
/// check whose required source the supervisor has not connected fails.
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
    /// Fresh read of active.json; None records an unavailable or invalid file.
    pub active_release: Measured<Option<ActiveRelease>>,
    /// Independently verified pointer and measured release for private check 18.
    pub release_pointer: Measured<ReleasePointer>,
    /// Egress verifier's status.json; None records an unavailable or invalid file.
    pub egress_status: Measured<Option<EgressStatus>>,
    /// Policy used by Network, compared to the deploy status for corner 19.
    pub relay_policy: Measured<HostPolicy>,
    /// Network's publication against the live endpoint for corner 20. The deploy
    /// files contain neither address nor certificate, so cannot fill this input.
    pub address_tls_identity: Measured<Agreement<AddressTlsIdentity>>,
}

impl BodyState {
    /// Read both deploy files without changing either. Every attempt replaces the
    /// previous values, including on failure. Paths and their parent directories
    /// come from trusted host config; deploy records must be owned by root.
    /// Activation time is not a heartbeat: active.json freshness starts at this
    /// read; egress freshness remains bounded by its producer's observation time.
    pub fn read_deploy(&mut self, context: Context, active: &Path, egress: &Path) {
        self.active_release = Measured::At(context, read_active(active, context.observed_at_ms));
        self.egress_status = match read_egress(egress) {
            Some(status)
                if context
                    .observed_at_ms
                    .checked_sub(status.observed_at_ms)
                    .is_some_and(|age| {
                        age <= CORNER_CHECKS[6]
                            .freshness_ms
                            .min(CORNER_CHECKS[7].freshness_ms)
                    }) =>
            {
                Measured::At(
                    Context {
                        observed_at_ms: status.observed_at_ms,
                        ..context
                    },
                    Some(status),
                )
            }
            _ => Measured::At(context, None),
        };
    }
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
        unwritten,                      // 17. app grant boundary
        deploy_release(context, state), // 18. release pointer
    ];
    let corners = [
        unwritten, // 7. frontdoor origins
        unwritten, // 8. frontdoor unlock limits
        release,   // 13. running binary equals the approved release
        antibody,  // 14. antibody corpus root equals the release fact
        // 17. The OpenViking index pin matches Kira's head.
        probe(context, &state.index_pin, Agreement::holds),
        unwritten,                      // 18. FD 3 memory calls
        deploy_egress(context, state),  // 19. egress allowlist
        deploy_address(context, state), // 20. address and TLS identity
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
/// A satisfied observation older than its freshness limit is stale. Deploy checks
/// fail on stale observations; the other checks become undetermined.
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

fn deploy_input<'a, T>(
    requested: Context,
    input: &'a Measured<T>,
    spec: &CheckSpec,
) -> Option<(Context, &'a T)> {
    match input {
        Measured::At(at, value)
            if at.epoch == requested.epoch
                && at.sequence == requested.sequence
                && at.commitment == requested.commitment
                && at.observed_at_ms > 0
                && requested.observed_at_ms.checked_sub(at.observed_at_ms)?
                    <= spec.freshness_ms =>
        {
            Some((*at, value))
        }
        _ => None,
    }
}

fn deploy_finding(context: Context, passed: Option<Context>) -> (Context, Finding) {
    match passed {
        Some(at) => (at, Finding::Satisfied),
        None => (context, Finding::Failed),
    }
}

fn oldest(left: Context, right: Context) -> Context {
    Context {
        observed_at_ms: left.observed_at_ms.min(right.observed_at_ms),
        ..left
    }
}

fn deploy_release(context: Context, state: &BodyState) -> (Context, Finding) {
    let passed = || {
        let spec = &PRIVATE_CHECKS[17];
        let (active_at, active) = deploy_input(context, &state.active_release, spec)?;
        let active = active.as_ref()?;
        let (pointer_at, pointer) = deploy_input(context, &state.release_pointer, spec)?;
        (hex(&active.commit, 40)
            && active.activated_at_ms > 0
            && active.activated_at_ms <= active_at.observed_at_ms
            && active.commit == pointer.commit
            && active.sequence > 0
            && active.sequence == pointer.sequence
            && active.pointer_sha256 == Some(pointer.pointer_sha256)
            && active.release == pointer.release.recorded
            && pointer.release.holds())
        .then_some(oldest(active_at, pointer_at))
    };
    deploy_finding(context, passed())
}

impl EgressStatus {
    fn holds(&self) -> bool {
        self.ok
            && self.policy.epoch > 0
            && self.policy.sha256 == self.loaded_policy_sha256
            && self.loaded_ruleset_sha256 == self.live_ruleset_sha256
    }
}

fn deploy_egress(context: Context, state: &BodyState) -> (Context, Finding) {
    let passed = || {
        let spec = &CORNER_CHECKS[6];
        let (status_at, status) = deploy_input(context, &state.egress_status, spec)?;
        let status = status.as_ref()?;
        let (policy_at, policy) = deploy_input(context, &state.relay_policy, spec)?;
        (status.observed_at_ms == status_at.observed_at_ms
            && status.holds()
            && status.policy == *policy)
            .then_some(oldest(status_at, policy_at))
    };
    deploy_finding(context, passed())
}

fn deploy_address(context: Context, state: &BodyState) -> (Context, Finding) {
    let passed = || {
        let spec = &CORNER_CHECKS[7];
        let (active_at, active) = deploy_input(context, &state.active_release, spec)?;
        let active = active.as_ref()?;
        let (status_at, status) = deploy_input(context, &state.egress_status, spec)?;
        let status = status.as_ref()?;
        let (identity_at, identity) = deploy_input(context, &state.address_tls_identity, spec)?;
        (active.activated_at_ms > 0
            && active.activated_at_ms <= active_at.observed_at_ms
            && status.observed_at_ms == status_at.observed_at_ms
            && status.holds()
            && !identity.measured.address.is_empty()
            && !identity
                .measured
                .address
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            && identity.holds())
        .then_some(oldest(oldest(active_at, status_at), identity_at))
    };
    deploy_finding(context, passed())
}

/// Bounded, nonblocking reads of root-owned regular files; a symlink at the final
/// component and any file writable by a group or by everyone are rejected.
fn deploy_json(path: &Path, keys: &[&str]) -> Option<Value> {
    use rustix::fs::{open, Mode, OFlags};
    use std::os::unix::fs::MetadataExt;

    const MAX_BYTES: u64 = 4096;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .ok()?;
    let file = File::from(fd);
    let before = file.metadata().ok()?;
    if !before.is_file()
        || before.uid() != 0
        || before.mode() & 0o022 != 0
        || before.len() > MAX_BYTES
    {
        return None;
    }
    let mut bytes = Vec::new();
    (&file).take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    let after = file.metadata().ok()?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.modified().ok()? != before.modified().ok()?
    {
        return None;
    }
    let value = json::parse_strict(&bytes).ok()?;
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == keys.len()
                && keys.iter().all(|key| value.get(key).is_some())
                && value.canonical_bytes() == bytes =>
        {
            Some(value)
        }
        _ => None,
    }
}

fn number(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)?.view() {
        ValueView::Integer(value) => u64::try_from(value.get()).ok(),
        _ => None,
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value.get(key)?.view() {
        ValueView::Text(value) => Some(value),
        _ => None,
    }
}

fn digest(value: &Value, key: &str) -> Option<Digest32> {
    Digest32::from_hex(text(value, key)?).ok()
}

fn hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_active(path: &Path, now_ms: u64) -> Option<ActiveRelease> {
    let value = deploy_json(
        path,
        &[
            "v",
            "id",
            "commit",
            "release",
            "seq",
            "pointer_sha256",
            "activated_at_ms",
        ],
    )?;
    let commit = text(&value, "commit")?;
    let release = digest(&value, "release")?;
    let sequence = number(&value, "seq")?;
    let activated_at_ms = number(&value, "activated_at_ms")?;
    let pointer_sha256 = match value.get("pointer_sha256")?.view() {
        ValueView::Null if sequence == 0 => None,
        ValueView::Text(value) if sequence > 0 => Some(Digest32::from_hex(value).ok()?),
        _ => return None,
    };
    if number(&value, "v")? != 1
        || !hex(commit, 40)
        || activated_at_ms == 0
        || activated_at_ms > now_ms
        || text(&value, "id")? != format!("{}-{}", &commit[..12], &release.to_string()[..12])
    {
        return None;
    }
    Some(ActiveRelease {
        commit: commit.into(),
        release,
        sequence,
        pointer_sha256,
        activated_at_ms,
    })
}

fn read_egress(path: &Path) -> Option<EgressStatus> {
    let value = deploy_json(
        path,
        &[
            "v",
            "epoch",
            "policy_sha256",
            "loaded_policy_sha256",
            "loaded_ruleset_sha256",
            "live_ruleset_sha256",
            "ok",
            "observed_at_ms",
        ],
    )?;
    let ok = match value.get("ok")?.view() {
        ValueView::Boolean(value) => value,
        _ => return None,
    };
    let epoch = number(&value, "epoch")?;
    let observed_at_ms = number(&value, "observed_at_ms")?;
    if number(&value, "v")? != 1 || epoch == 0 || observed_at_ms == 0 {
        return None;
    }
    Some(EgressStatus {
        policy: HostPolicy {
            epoch,
            sha256: digest(&value, "policy_sha256")?,
        },
        loaded_policy_sha256: digest(&value, "loaded_policy_sha256")?,
        loaded_ruleset_sha256: digest(&value, "loaded_ruleset_sha256")?,
        live_ruleset_sha256: digest(&value, "live_ruleset_sha256")?,
        ok,
        observed_at_ms,
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
        evidence.cell = if spec.check == PRIVATE_CHECKS[17].check
            || spec.check == CORNER_CHECKS[6].check
            || spec.check == CORNER_CHECKS[7].check
        {
            Cell::Failed
        } else {
            Cell::Undetermined
        };
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
