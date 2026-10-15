// SPDX-License-Identifier: AGPL-3.0-or-later
//! Seeded attack data and bounded execution through a supervisor-owned session.
//! A successful observation is evidence; it supplies no permission or owner proof.

use crate::{
    hostile::{Limits, Usage},
    mhc::Concern,
};
use canon::{digest::Digest32, Refusal, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

/// The pinned RNG dependency is part of this generator's replay identity.
pub const GENERATOR: &str = "immune-hypermutation-rand-0.10.3-v1";
pub const MAX_INPUT_BYTES: usize = 4096;
/// Reserved for generator state, its current case, digest input and one result.
pub const WORKING_MEMORY_BYTES: u64 = 4 * MAX_INPUT_BYTES as u64 + 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub v: u16,
    pub seed: [u8; 32],
    pub release: Digest32,
    pub corpus_root: Digest32,
    pub parent_cgroup: u64,
    pub limits: Limits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub seed: [u8; 32],
    pub release: Digest32,
    pub corpus_root: Digest32,
    pub attack_cgroup: u64,
    pub attempted: u32,
    pub new_findings: Vec<Concern>,
    pub budget_exhausted: bool,
}

pub trait Driver {
    /// Trusted host port. Execution, deadlines and reaping belong to its owner.
    fn run_isolated(&mut self, request: &Request) -> Result<Observation>;

    /// Independently verify the referenced record's hash, signature, chain and
    /// connection to the measured violation. A digest alone is insufficient.
    fn verify_tampering(&mut self, _request: &Request, _record: Digest32) -> Result<()> {
        Err(refusal("hypermutation-record-unverified"))
    }
}

pub fn run(request: &Request, driver: &mut impl Driver) -> Result<Observation> {
    validate_request(request)?;
    let started = Instant::now();
    let report = driver.run_isolated(request)?;
    check_wall(started, request.limits)?;
    validate_report(request, &report)?;
    for finding in &report.new_findings {
        if let Concern::ProvenTampering { verified_record } = finding {
            driver.verify_tampering(request, *verified_record)?;
        }
    }
    check_wall(started, request.limits)?;
    Ok(report)
}

fn validate_request(request: &Request) -> Result<()> {
    request.limits.validate()?;
    if request.v != 1 || request.parent_cgroup == 0 {
        return Err(refusal("hypermutation-input"));
    }
    Ok(())
}

fn validate_report(request: &Request, report: &Observation) -> Result<()> {
    if report.seed != request.seed
        || report.release != request.release
        || report.corpus_root != request.corpus_root
        || report.attack_cgroup == 0
        || report.attack_cgroup == request.parent_cgroup
        || report.attempted != request.limits.cases
        || report.new_findings.len() > request.limits.cases as usize
        || report.new_findings.capacity() as u64 * core::mem::size_of::<Concern>() as u64
            > request.limits.memory_bytes
        || report.budget_exhausted
    {
        return Err(refusal("hypermutation-incomplete"));
    }
    check_findings(&report.new_findings, request.limits)?;
    Ok(())
}

/// These choose input families, never commands or capabilities for the child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hazard {
    JsonBoundary,
    FrameBoundary,
    ReorderedMessages,
    ContextSubstitution,
    ResourceBoundary,
    ArbitraryBytes,
    CombinedPerturbations,
}

const HAZARDS: [Hazard; 7] = [
    Hazard::JsonBoundary,
    Hazard::FrameBoundary,
    Hazard::ReorderedMessages,
    Hazard::ContextSubstitution,
    Hazard::ResourceBoundary,
    Hazard::ArbitraryBytes,
    Hazard::CombinedPerturbations,
];

/// The host sends these bytes only to its preselected attack fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttackCase {
    pub ordinal: u32,
    pub hazard: Hazard,
    pub input: Vec<u8>,
    pub input_digest: Digest32,
}

/// Bounded streaming generation; it does not materialize a whole attack batch.
pub struct Schedule {
    rng: StdRng,
    binding: Digest32,
    next: u32,
    count: u32,
    input_limit: usize,
    phase: usize,
}

impl Schedule {
    pub fn new(request: &Request) -> Result<Self> {
        validate_request(request)?;
        if request.limits.memory_bytes < WORKING_MEMORY_BYTES {
            return Err(refusal("hypermutation-budget"));
        }
        let binding = request_binding(request);
        let mut rng = StdRng::from_seed(*binding.as_bytes());
        let phase = (rng.next_u32() as usize) % HAZARDS.len();
        Ok(Self {
            rng,
            binding,
            next: 0,
            count: request.limits.cases,
            input_limit: MAX_INPUT_BYTES.min(request.limits.io_bytes as usize),
            phase,
        })
    }

    /// Commitment to the seed, release, corpus, parent cgroup and all ceilings.
    pub const fn binding(&self) -> Digest32 {
        self.binding
    }
}

impl Iterator for Schedule {
    type Item = AttackCase;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.count {
            return None;
        }
        let ordinal = self.next;
        self.next += 1;
        let hazard = HAZARDS[(ordinal as usize + self.phase) % HAZARDS.len()];
        let mut input = generate(hazard, &mut self.rng, self.input_limit);
        input.truncate(self.input_limit);
        let mut identity = Vec::with_capacity(69 + input.len());
        identity.extend_from_slice(self.binding.as_bytes());
        identity.extend_from_slice(&ordinal.to_be_bytes());
        identity.push(hazard as u8);
        identity.extend_from_slice(&input);
        Some(AttackCase {
            ordinal,
            hazard,
            input,
            input_digest: Digest32::sha256(&identity),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.count - self.next) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Schedule {}

fn generate(hazard: Hazard, rng: &mut StdRng, limit: usize) -> Vec<u8> {
    match hazard {
        Hazard::JsonBoundary => {
            const SHAPES: [&[u8]; 8] = [
                b"{\"a\":0,\"\\u0061\":1}",
                b"[9007199254740992]",
                b"{\"v\":null}",
                b"[\"\\ud800a\"]",
                b"{\"a\":[]}",
                b"{\"a\":1}\r",
                b"[-0]",
                b"[\"\\ud800\\u00xz\"]",
            ];
            let selected = SHAPES[(rng.next_u32() as usize) % SHAPES.len()];
            let mut input = selected.to_vec();
            perturb(&mut input, rng, limit);
            input
        }
        Hazard::FrameBoundary => {
            let body = b"{\"body\":{},\"id\":\"m\",\"kind\":\"unknown\",\"v\":1}";
            let lengths = [0, 1, body.len() as u32, 65_536, u32::MAX];
            let length = lengths[(rng.next_u32() as usize) % lengths.len()];
            let mut input = length.to_be_bytes().to_vec();
            input.extend_from_slice(body);
            perturb(&mut input, rng, limit);
            input
        }
        Hazard::ReorderedMessages => {
            // Sequence numbers and repeated records are inert fixture input.
            let mut records = [0_u32, 1, 2, 2, u32::MAX];
            for index in (1..records.len()).rev() {
                let swap = (rng.next_u32() as usize) % (index + 1);
                records.swap(index, swap);
            }
            records.into_iter().flat_map(u32::to_be_bytes).collect()
        }
        Hazard::ContextSubstitution => {
            let mut input = vec![0; 96];
            rng.fill_bytes(&mut input);
            let source = (rng.next_u32() as usize) % 3;
            let duplicate = input[source * 32..(source + 1) * 32].to_vec();
            let target = (source + 1 + (rng.next_u32() as usize) % 2) % 3;
            input[target * 32..(target + 1) * 32].copy_from_slice(&duplicate);
            input
        }
        Hazard::ResourceBoundary => {
            let lengths = [0, 1, 63, 64, 65, 127, 128, 129, limit];
            let count = lengths[(rng.next_u32() as usize) % lengths.len()].min(limit);
            let mut input = vec![rng.next_u32() as u8; count];
            if count > 0 {
                input[count - 1] = 0;
            }
            input
        }
        Hazard::ArbitraryBytes => {
            let count = (rng.next_u32() as usize) % (limit + 1);
            let mut input = vec![0; count];
            rng.fill_bytes(&mut input);
            input
        }
        Hazard::CombinedPerturbations => {
            let count = 1 + (rng.next_u32() as usize) % 32;
            let mut input = Vec::new();
            for _ in 0..count {
                input.extend_from_slice(b"[\"\\u0000\",{}");
                input.extend_from_slice(&rng.next_u64().to_be_bytes());
            }
            for _ in 0..4 {
                perturb(&mut input, rng, limit);
            }
            input
        }
    }
}

fn perturb(input: &mut Vec<u8>, rng: &mut StdRng, limit: usize) {
    match rng.next_u32() % 4 {
        0 if !input.is_empty() => {
            let index = (rng.next_u32() as usize) % input.len();
            input[index] ^= 1 << (rng.next_u32() % 8);
        }
        1 if !input.is_empty() => {
            input.truncate((rng.next_u32() as usize) % input.len());
        }
        2 if input.len() < limit => {
            let index = (rng.next_u32() as usize) % (input.len() + 1);
            input.insert(index, rng.next_u32() as u8);
        }
        _ => input.reverse(),
    }
}

fn request_binding(request: &Request) -> Digest32 {
    let mut bytes = GENERATOR.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&request.v.to_be_bytes());
    bytes.extend_from_slice(&request.seed);
    bytes.extend_from_slice(request.release.as_bytes());
    bytes.extend_from_slice(request.corpus_root.as_bytes());
    bytes.extend_from_slice(&request.parent_cgroup.to_be_bytes());
    for value in [
        request.limits.wall_ms,
        request.limits.cpu_us,
        request.limits.memory_bytes,
        request.limits.io_bytes,
        u64::from(request.limits.output_bytes),
        u64::from(request.limits.cases),
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    Digest32::sha256(&bytes)
}

/// Trusted launcher observations, not a guest reply or a serialized proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Isolation {
    pub binding: Digest32,
    pub attack_cgroup: u64,
    pub loaded_release: Digest32,
    pub sample: launcher::boot::CageSample,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    pub ordinal: u32,
    pub input_digest: Digest32,
    pub completed: bool,
    pub findings: Vec<Concern>,
}

/// Aggregate resource counters and cleanup read back by the trusted host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finished {
    pub binding: Digest32,
    pub attack_cgroup: u64,
    pub usage: Usage,
    pub descendants_reaped: bool,
    pub cgroup_empty: bool,
}

/// The supervisor implements this around its launcher-owned child. Usage includes
/// every input byte sent and finding byte returned. Memory covers the child and
/// session; Executor adds its own buffers. CPU and wall counters include host work.
/// Implementations must interrupt an attempt at the cumulative CPU/IO ceilings
/// and deadline, then kill and reap; cgroup CPU rate and per-file limits alone
/// do not enforce those aggregate ceilings. `finish` also reaps failed attempts.
/// Case data cannot choose a command, path, process profile or destination.
pub trait AttackSession {
    fn isolation(&mut self) -> Result<Isolation>;
    fn attempt(&mut self, case: &AttackCase) -> Result<Attempt>;
    fn usage(&mut self) -> Result<Usage>;
    fn finish(&mut self) -> Result<Finished>;
}

pub trait AttackHost {
    type Session: AttackSession;

    /// Create the isolated child or refuse; a failed start cleans up its child.
    fn start(&mut self, request: &Request, binding: Digest32) -> Result<Self::Session>;

    /// Verify the signed record, its chain and the measured mismatch independently
    /// of the attack's output. Missing record verification refuses proven findings.
    fn verify_tampering(&mut self, _request: &Request, _record: Digest32) -> Result<()> {
        Err(refusal("hypermutation-record-unverified"))
    }
}

pub struct Executor<H> {
    host: H,
}

impl<H> Executor<H> {
    pub fn new(host: H) -> Self {
        Self { host }
    }

    pub fn into_host(self) -> H {
        self.host
    }
}

impl<H: AttackHost> Driver for Executor<H> {
    fn run_isolated(&mut self, request: &Request) -> Result<Observation> {
        let schedule = Schedule::new(request)?;
        let binding = schedule.binding();
        let started = Instant::now();
        let mut session = self.host.start(request, binding)?;
        let result = execute(request, binding, schedule, started, &mut session);
        // Always ask the host to terminate/reap, even after malformed observations.
        let finished = session.finish()?;
        check_wall(started, request.limits)?;
        if finished.binding != binding
            || finished.attack_cgroup == 0
            || finished.attack_cgroup == request.parent_cgroup
            || !finished.descendants_reaped
            || !finished.cgroup_empty
        {
            return Err(refusal("hypermutation-cleanup"));
        }
        let (report, previous_usage) = result?;
        if finished.attack_cgroup != report.attack_cgroup {
            return Err(refusal("hypermutation-cleanup"));
        }
        check_usage_progress(previous_usage, finished.usage)?;
        request.limits.permits(
            with_observer_memory(finished.usage, &report)?,
            report.attempted,
        )?;
        validate_report(request, &report)?;
        for finding in &report.new_findings {
            if let Concern::ProvenTampering { verified_record } = finding {
                self.host.verify_tampering(request, *verified_record)?;
            }
        }
        check_wall(started, request.limits)?;
        Ok(report)
    }

    fn verify_tampering(&mut self, request: &Request, record: Digest32) -> Result<()> {
        self.host.verify_tampering(request, record)
    }
}

fn execute(
    request: &Request,
    binding: Digest32,
    schedule: Schedule,
    started: Instant,
    session: &mut impl AttackSession,
) -> Result<(Observation, Usage)> {
    check_wall(started, request.limits)?;
    let isolation = session.isolation()?;
    check_isolation(request, binding, &isolation)?;
    let finding_capacity = (request.limits.cases as usize)
        .min(request.limits.output_bytes as usize / 33)
        .min(
            ((request.limits.memory_bytes - WORKING_MEMORY_BYTES)
                / core::mem::size_of::<Concern>() as u64) as usize,
        );
    let mut report = Observation {
        seed: request.seed,
        release: request.release,
        corpus_root: request.corpus_root,
        attack_cgroup: isolation.attack_cgroup,
        attempted: 0,
        new_findings: Vec::with_capacity(finding_capacity),
        budget_exhausted: false,
    };
    let mut usage = session.usage()?;
    request
        .limits
        .permits(with_observer_memory(usage, &report)?, 0)?;
    let mut input_bytes = 0_u64;
    let mut finding_bytes = 0_u64;
    for case in schedule {
        check_wall(started, request.limits)?;
        input_bytes += case.input.len() as u64;
        if input_bytes > request.limits.io_bytes {
            return Err(refusal("hypermutation-budget"));
        }
        let result = session.attempt(&case)?;
        report.attempted += 1;
        check_wall(started, request.limits)?;
        if !result.completed
            || result.ordinal != case.ordinal
            || result.input_digest != case.input_digest
            || result.findings.len() > 1
            || result.findings.capacity() as u64 * core::mem::size_of::<Concern>() as u64
                > WORKING_MEMORY_BYTES / 4
        {
            return Err(refusal("hypermutation-incomplete"));
        }
        check_findings(&result.findings, request.limits)?;
        for finding in result.findings {
            finding_bytes += finding_bytes_len(&finding)?;
            if finding_bytes > u64::from(request.limits.output_bytes) {
                return Err(refusal("hypermutation-budget"));
            }
            if !report.new_findings.contains(&finding) {
                if report.new_findings.len() == finding_capacity {
                    return Err(refusal("hypermutation-budget"));
                }
                report.new_findings.push(finding);
            }
        }
        if report.new_findings.capacity() as u64 * core::mem::size_of::<Concern>() as u64
            + WORKING_MEMORY_BYTES
            > request.limits.memory_bytes
        {
            return Err(refusal("hypermutation-budget"));
        }
        let measured = session.usage()?;
        check_usage_progress(usage, measured)?;
        request
            .limits
            .permits(with_observer_memory(measured, &report)?, report.attempted)?;
        if measured.io_bytes < input_bytes || u64::from(measured.output_bytes) < finding_bytes {
            return Err(refusal("hypermutation-usage"));
        }
        usage = measured;
    }
    // Re-read containment after the attacks, while the child is still inspectable.
    let final_isolation = session.isolation()?;
    check_isolation(request, binding, &final_isolation)?;
    if final_isolation.attack_cgroup != report.attack_cgroup
        || final_isolation.sample.observed_after_ms < isolation.sample.observed_after_ms
        || final_isolation.sample.landlock != isolation.sample.landlock
        || final_isolation.sample.seccomp != isolation.sample.seccomp
        || final_isolation.sample.namespaces != isolation.sample.namespaces
        || final_isolation.sample.cgroup != isolation.sample.cgroup
    {
        return Err(refusal("hypermutation-isolation"));
    }
    Ok((report, usage))
}

fn check_isolation(request: &Request, binding: Digest32, facts: &Isolation) -> Result<()> {
    let sample = &facts.sample;
    let valid = (|| {
        let landlock = sample.landlock.as_ref()?;
        let filter = sample.seccomp.as_ref()?;
        let namespaces = sample.namespaces.as_ref()?;
        let group = sample.cgroup.as_ref()?;
        let limits = &group.limits;
        Some(
            landlock.abi.get() >= 4
                && landlock.fully_enforced
                && landlock.network_denied
                && landlock.writable_subtrees == 0
                && filter.mode == 2
                && filter.no_new_privileges
                && filter.profile == launcher::profiles::ProfileKind::Auma
                && namespaces.user_isolated
                && namespaces.mounts_isolated
                && namespaces.pids_isolated
                && namespaces.ipc_isolated
                && namespaces.uts_isolated
                && namespaces.cgroup_isolated
                && namespaces.supervisor_network != namespaces.child_network
                && namespaces.active_interfaces == 0
                && namespaces.routes == 0
                && group.version == 2
                && group.swap_disabled
                && group.child_attached
                && limits.memory_bytes.get() <= request.limits.memory_bytes
                && limits.cpu_quota_us.get() <= request.limits.cpu_us
                && limits.file_bytes.get() <= request.limits.io_bytes
                && limits.tasks.get() == 1
                && limits.validate().is_ok(),
        )
    })();
    if facts.binding != binding
        || facts.loaded_release != request.release
        || facts.attack_cgroup == 0
        || facts.attack_cgroup == request.parent_cgroup
        || !sample.running
        || sample.observed_after_ms > request.limits.wall_ms
        || valid != Some(true)
    {
        return Err(refusal("hypermutation-isolation"));
    }
    Ok(())
}

fn check_findings(findings: &[Concern], limits: Limits) -> Result<()> {
    if findings.len() as u64 * core::mem::size_of::<Concern>() as u64 > limits.memory_bytes {
        return Err(refusal("hypermutation-finding"));
    }
    let mut bytes = 0_u64;
    for (index, finding) in findings.iter().enumerate() {
        bytes += finding_bytes_len(finding)?;
        if bytes > u64::from(limits.output_bytes) || findings[..index].contains(finding) {
            return Err(refusal("hypermutation-finding"));
        }
    }
    Ok(())
}

fn finding_bytes_len(finding: &Concern) -> Result<u64> {
    match finding {
        Concern::Drift { expected, observed } if expected != observed => Ok(65),
        Concern::ProvenTampering { .. } => Ok(33),
        _ => Err(refusal("hypermutation-finding")),
    }
}

fn check_usage_progress(before: Usage, after: Usage) -> Result<()> {
    if after.wall_ms < before.wall_ms
        || after.cpu_us < before.cpu_us
        || after.memory_bytes < before.memory_bytes
        || after.io_bytes < before.io_bytes
        || after.output_bytes < before.output_bytes
        || after.cases < before.cases
    {
        return Err(refusal("hypermutation-usage"));
    }
    Ok(())
}

fn with_observer_memory(mut usage: Usage, report: &Observation) -> Result<Usage> {
    let retained = WORKING_MEMORY_BYTES
        + report.new_findings.capacity() as u64 * core::mem::size_of::<Concern>() as u64;
    usage.memory_bytes = usage
        .memory_bytes
        .checked_add(retained)
        .ok_or(refusal("hypermutation-budget"))?;
    Ok(usage)
}

fn check_wall(started: Instant, limits: Limits) -> Result<()> {
    if started.elapsed() > Duration::from_millis(limits.wall_ms) {
        return Err(refusal("hypermutation-budget"));
    }
    Ok(())
}

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}
