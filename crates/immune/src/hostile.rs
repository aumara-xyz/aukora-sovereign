// SPDX-License-Identifier: AGPL-3.0-or-later
//! Attack descriptions and judgments. Execution belongs to the host driver.

use canon::{digest::Digest32, Refusal, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub wall_ms: u64,
    pub cpu_us: u64,
    pub memory_bytes: u64,
    pub io_bytes: u64,
    pub output_bytes: u32,
    pub cases: u32,
}

impl Limits {
    pub fn validate(self) -> Result<Self> {
        if self.wall_ms == 0
            || self.wall_ms > 60_000
            || self.cpu_us == 0
            || self.cpu_us > 10_000_000
            || self.memory_bytes == 0
            || self.memory_bytes > 256 * 1024 * 1024
            || self.io_bytes == 0
            || self.io_bytes > 16 * 1024 * 1024
            || self.output_bytes == 0
            || self.output_bytes > 65_536
            || self.cases == 0
            || self.cases > 16_384
        {
            return Err(Refusal {
                organ: "immune",
                reason: "attack-budget",
            });
        }
        Ok(self)
    }

    /// The ceiling applies to both sides of every attack, including controls.
    pub fn permits(self, usage: Usage, cases: u32) -> Result<()> {
        self.validate()?;
        if usage.wall_ms > self.wall_ms
            || usage.cpu_us > self.cpu_us
            || usage.memory_bytes > self.memory_bytes
            || usage.io_bytes > self.io_bytes
            || usage.output_bytes > self.output_bytes
            || usage.cases != cases
            || usage.cases > self.cases
        {
            return Err(refusal("attack-budget"));
        }
        Ok(())
    }
}

/// Measured aggregate work, counting both confined attempts and controls.
/// Memory is peak resident bytes; the other byte and CPU counters are totals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    pub wall_ms: u64,
    pub cpu_us: u64,
    pub memory_bytes: u64,
    pub io_bytes: u64,
    pub output_bytes: u32,
    pub cases: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    ReadHostSecret,
    ExecuteCommand,
    OpenSocket,
    WriteOutsideCage,
    ForgedOwnerFrame,
    ModelKeyDisclosure,
    OverspendRace,
    RouteDisabled,
}

impl Probe {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReadHostSecret => "read-host-secret",
            Self::ExecuteCommand => "execute-command",
            Self::OpenSocket => "open-socket",
            Self::WriteOutsideCage => "write-outside-cage",
            Self::ForgedOwnerFrame => "forged-owner-frame",
            Self::ModelKeyDisclosure => "model-key-disclosure",
            Self::OverspendRace => "overspend-race",
            Self::RouteDisabled => "route-disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Blocked,
    ReachedTarget,
    Unavailable,
    BudgetExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairedProbe {
    pub probe: Probe,
    pub confined: Outcome,
    pub unconfined_control: Outcome,
    pub input_digest: Digest32,
}

impl PairedProbe {
    pub fn contained(&self) -> bool {
        self.confined == Outcome::Blocked && self.unconfined_control == Outcome::ReachedTarget
    }

    /// Bridges only the four kernel operations. The other required probes need
    /// observations from their owning services and cannot be inferred here.
    pub fn from_kernel(
        request: &crate::boot_attack::Request,
        pair: &launcher::boot::KernelProbePair,
    ) -> Result<Self> {
        use launcher::boot::KernelProbe;
        let probe = match pair.confined.probe {
            KernelProbe::ReadHostSecret => Probe::ReadHostSecret,
            KernelProbe::ExecuteCommand => Probe::ExecuteCommand,
            KernelProbe::OpenSocket => Probe::OpenSocket,
            KernelProbe::WriteOutsideCage => Probe::WriteOutsideCage,
        };
        let expected = request.input_digest(probe);
        if pair.confined.probe != pair.unconfined_control.probe
            || pair.confined.input_digest != expected
            || pair.unconfined_control.input_digest != expected
        {
            return Err(refusal("cage-attack-failed"));
        }
        Ok(Self {
            probe,
            confined: kernel_outcome(&pair.confined)?,
            unconfined_control: kernel_outcome(&pair.unconfined_control)?,
            input_digest: expected,
        })
    }
}

fn kernel_outcome(observed: &launcher::boot::KernelProbeObservation) -> Result<Outcome> {
    use launcher::boot::{KernelProbe, KernelProbeOutcome};
    match observed.outcome {
        KernelProbeOutcome::Blocked => {
            let expected_errno = match observed.probe {
                KernelProbe::ExecuteCommand | KernelProbe::OpenSocket => observed.errno == Some(1),
                KernelProbe::ReadHostSecret | KernelProbe::WriteOutsideCage => {
                    matches!(observed.errno, Some(1 | 13))
                }
            };
            if expected_errno {
                Ok(Outcome::Blocked)
            } else {
                Err(refusal("cage-attack-failed"))
            }
        }
        KernelProbeOutcome::ReachedTarget if observed.errno.is_none() => Ok(Outcome::ReachedTarget),
        KernelProbeOutcome::Unavailable => Ok(Outcome::Unavailable),
        KernelProbeOutcome::BudgetExceeded if observed.errno.is_none() => {
            Ok(Outcome::BudgetExceeded)
        }
        _ => Err(refusal("cage-attack-failed")),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CageRun {
    pub run_id: Digest32,
    pub candidate: Digest32,
    pub release: Digest32,
    pub cage: Digest32,
    pub challenge: Digest32,
    pub grants_at_start: u32,
    pub grants_at_end: u32,
    pub candidate_drove_guest: bool,
    pub parent_cgroup: u64,
    pub attack_cgroup: u64,
    pub probes: Vec<PairedProbe>,
    pub budget_exhausted: bool,
}

pub trait CageDriver {
    fn drive(&mut self, request: &crate::boot_attack::Request) -> Result<CageRun>;

    /// Host measurements of the immediately preceding run, never guest counters.
    /// A driver that has not connected resource measurements cannot pass.
    fn resource_usage(&mut self) -> Result<Usage> {
        Err(refusal("cage-attack-incomplete"))
    }
}

/// Closed operations for the hostile guest. These values describe attempted
/// effects; no string is interpreted as a command or program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operation {
    ReadKey,
    ReadDatabase,
    ReadOtherProcess,
    ReadThroughSymlink,
    Execve,
    Execveat,
    InetStream,
    InetDatagram,
    Inet6,
    PacketSocket,
    NetlinkSocket,
    Vsock,
    UnixPathConnect,
    UnixAbstractConnect,
    HostLoopbackStream,
    HostLoopbackDatagram,
    WorkspaceSocket,
    WriteRepository,
    WriteReadOnlyProfile,
    WriteSharedMemory,
    WriteTemporaryDirectory,
    CreateOutsideDirectory,
    UnlinkHostFile,
    HardlinkOutside,
    RenameOutside,
    WriteBeyondFileLimit,
    Mount,
    UserNamespace,
    SetNamespace,
    NestedNamespace,
    NamespaceClone,
    Clone3,
    Ptrace,
    ProcessVmRead,
    ProcessVmWrite,
    IoUring,
    Bpf,
    PerfEvent,
    KernelKeyring,
    Userfaultfd,
    OpenByHandle,
    ChangeClock,
    ReadPhysicalMemory,
    ReadKernelMessages,
    SignalHostProcess,
    InjectTerminalInput,
    SetuidExecutable,
    ExhaustProcesses,
    ExhaustMemory,
    InheritedDescriptor,
    HostPidVisibility,
    HostNetworkVisibility,
    SupervisorDeath,
}

/// The host prepares disposable targets before either side. Missing fixtures
/// produce Unavailable, never successful containment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Fixture {
    File,
    Directory,
    Listener,
    Process,
    Terminal,
    PrivilegedHost,
    ResourceLimit,
    InheritedDescriptor,
    Namespace,
    Supervisor,
}

/// Exact observable denial class, kept separate from a generic failed attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Denial {
    Permission,
    Access,
    ReadOnly,
    Missing,
    BadDescriptor,
    FileTooLarge,
    NotImplemented,
    Isolated,
    ResourceLimited,
    ParentDeath,
}

impl Denial {
    /// Linux errno classes; isolation, resource and lifecycle checks require
    /// their host-observed postconditions instead of a syscall error.
    pub const fn errno(self) -> Option<i32> {
        match self {
            Self::Permission => Some(1),
            Self::Access => Some(13),
            Self::ReadOnly => Some(30),
            Self::Missing => Some(2),
            Self::BadDescriptor => Some(9),
            Self::FileTooLarge => Some(27),
            Self::NotImplemented => Some(38),
            Self::Isolated | Self::ResourceLimited | Self::ParentDeath => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttackCase {
    pub id: &'static str,
    pub operation: Operation,
    pub fixture: Fixture,
    pub denial: Denial,
}

impl AttackCase {
    fn accepts(self, observed: Observation) -> bool {
        let Observation::Denied { denial, errno } = observed else {
            return false;
        };
        if errno != denial.errno() {
            return false;
        }
        if denial == self.denial {
            return true;
        }
        // Auma's default-deny filter can stop these operations before their
        // filesystem, clone or resource checks run.
        denial == Denial::Permission
            && matches!(
                self.operation,
                Operation::ReadKey
                    | Operation::ReadDatabase
                    | Operation::ReadOtherProcess
                    | Operation::ReadThroughSymlink
                    | Operation::WriteRepository
                    | Operation::WriteReadOnlyProfile
                    | Operation::WriteSharedMemory
                    | Operation::WriteTemporaryDirectory
                    | Operation::CreateOutsideDirectory
                    | Operation::UnlinkHostFile
                    | Operation::HardlinkOutside
                    | Operation::RenameOutside
                    | Operation::WriteBeyondFileLimit
                    | Operation::Clone3
                    | Operation::ReadPhysicalMemory
                    | Operation::ReadKernelMessages
                    | Operation::ExhaustProcesses
            )
    }
}

/// Each row requires the same input and disposable target in an unconfined
/// control. There are no skipped rows and no success inferred from an errno
/// whose control could not reach the target.
pub const HOSTILE_CASES: &[AttackCase] = &[
    case(
        "host-key",
        Operation::ReadKey,
        Fixture::File,
        Denial::Access,
    ),
    case(
        "host-database",
        Operation::ReadDatabase,
        Fixture::File,
        Denial::Access,
    ),
    case(
        "other-process-memory",
        Operation::ReadOtherProcess,
        Fixture::Process,
        Denial::Missing,
    ),
    case(
        "symlink-escape",
        Operation::ReadThroughSymlink,
        Fixture::File,
        Denial::Access,
    ),
    case(
        "execve",
        Operation::Execve,
        Fixture::File,
        Denial::Permission,
    ),
    case(
        "execveat",
        Operation::Execveat,
        Fixture::File,
        Denial::Permission,
    ),
    case(
        "inet-stream",
        Operation::InetStream,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "inet-datagram",
        Operation::InetDatagram,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "inet6",
        Operation::Inet6,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "packet",
        Operation::PacketSocket,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "netlink",
        Operation::NetlinkSocket,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "vsock",
        Operation::Vsock,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "unix-path",
        Operation::UnixPathConnect,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "unix-abstract",
        Operation::UnixAbstractConnect,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "loopback-stream",
        Operation::HostLoopbackStream,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "loopback-datagram",
        Operation::HostLoopbackDatagram,
        Fixture::Listener,
        Denial::Permission,
    ),
    case(
        "workspace-socket",
        Operation::WorkspaceSocket,
        Fixture::Directory,
        Denial::Permission,
    ),
    case(
        "repository-write",
        Operation::WriteRepository,
        Fixture::File,
        Denial::ReadOnly,
    ),
    case(
        "profile-write",
        Operation::WriteReadOnlyProfile,
        Fixture::File,
        Denial::ReadOnly,
    ),
    case(
        "shared-memory-write",
        Operation::WriteSharedMemory,
        Fixture::Directory,
        Denial::Missing,
    ),
    case(
        "temporary-write",
        Operation::WriteTemporaryDirectory,
        Fixture::Directory,
        Denial::Missing,
    ),
    case(
        "outside-directory",
        Operation::CreateOutsideDirectory,
        Fixture::Directory,
        Denial::Access,
    ),
    case(
        "host-unlink",
        Operation::UnlinkHostFile,
        Fixture::File,
        Denial::Access,
    ),
    case(
        "outside-hardlink",
        Operation::HardlinkOutside,
        Fixture::File,
        Denial::Access,
    ),
    case(
        "outside-rename",
        Operation::RenameOutside,
        Fixture::Directory,
        Denial::Access,
    ),
    case(
        "file-limit",
        Operation::WriteBeyondFileLimit,
        Fixture::ResourceLimit,
        Denial::FileTooLarge,
    ),
    case(
        "mount",
        Operation::Mount,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "user-namespace",
        Operation::UserNamespace,
        Fixture::Namespace,
        Denial::Permission,
    ),
    case(
        "set-namespace",
        Operation::SetNamespace,
        Fixture::Namespace,
        Denial::Permission,
    ),
    case(
        "nested-namespace",
        Operation::NestedNamespace,
        Fixture::Namespace,
        Denial::Permission,
    ),
    case(
        "clone-namespace",
        Operation::NamespaceClone,
        Fixture::Namespace,
        Denial::Permission,
    ),
    case(
        "clone3",
        Operation::Clone3,
        Fixture::Process,
        Denial::NotImplemented,
    ),
    case(
        "ptrace",
        Operation::Ptrace,
        Fixture::Process,
        Denial::Permission,
    ),
    case(
        "process-read",
        Operation::ProcessVmRead,
        Fixture::Process,
        Denial::Permission,
    ),
    case(
        "process-write",
        Operation::ProcessVmWrite,
        Fixture::Process,
        Denial::Permission,
    ),
    case(
        "io-uring",
        Operation::IoUring,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "bpf",
        Operation::Bpf,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "perf-event",
        Operation::PerfEvent,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "kernel-keyring",
        Operation::KernelKeyring,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "userfaultfd",
        Operation::Userfaultfd,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "open-by-handle",
        Operation::OpenByHandle,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "change-clock",
        Operation::ChangeClock,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "physical-memory",
        Operation::ReadPhysicalMemory,
        Fixture::File,
        Denial::Missing,
    ),
    case(
        "kernel-messages",
        Operation::ReadKernelMessages,
        Fixture::File,
        Denial::Missing,
    ),
    case(
        "host-signal",
        Operation::SignalHostProcess,
        Fixture::Process,
        Denial::Permission,
    ),
    case(
        "terminal-input",
        Operation::InjectTerminalInput,
        Fixture::Terminal,
        Denial::Permission,
    ),
    case(
        "setuid",
        Operation::SetuidExecutable,
        Fixture::PrivilegedHost,
        Denial::Permission,
    ),
    case(
        "process-limit",
        Operation::ExhaustProcesses,
        Fixture::ResourceLimit,
        Denial::ResourceLimited,
    ),
    case(
        "memory-limit",
        Operation::ExhaustMemory,
        Fixture::ResourceLimit,
        Denial::ResourceLimited,
    ),
    case(
        "extra-descriptor",
        Operation::InheritedDescriptor,
        Fixture::InheritedDescriptor,
        Denial::BadDescriptor,
    ),
    case(
        "host-pid",
        Operation::HostPidVisibility,
        Fixture::Namespace,
        Denial::Isolated,
    ),
    case(
        "host-network",
        Operation::HostNetworkVisibility,
        Fixture::Namespace,
        Denial::Isolated,
    ),
    case(
        "supervisor-death",
        Operation::SupervisorDeath,
        Fixture::Supervisor,
        Denial::ParentDeath,
    ),
];

const fn case(
    id: &'static str,
    operation: Operation,
    fixture: Fixture,
    denial: Denial,
) -> AttackCase {
    AttackCase {
        id,
        operation,
        fixture,
        denial,
    }
}

/// Host-interpreted results. The unconfined side must produce ReachedTarget;
/// Unavailable and BudgetExceeded never count as a blocked confined operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Denied { denial: Denial, errno: Option<i32> },
    ReachedTarget,
    Unavailable,
    BudgetExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostilePair {
    pub case_id: String,
    pub confined_input: Digest32,
    pub control_input: Digest32,
    pub confined: Observation,
    pub control: Observation,
    pub confined_elapsed_ms: u64,
    pub control_elapsed_ms: u64,
}

/// Maximum time for the guest to die after its supervisor has died.
pub const PARENT_DEATH_DEADLINE_MS: u64 = 1_000;

/// Data-only request: the host chooses and creates fixtures; the guest cannot
/// provide a target path, executable, environment or listener address here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostileRequest {
    pub boot: crate::boot_attack::Request,
    pub fixture_commitment: Digest32,
}

impl HostileRequest {
    pub fn validate(&self) -> Result<()> {
        self.boot.validate()?;
        let attempts = (HOSTILE_CASES.len() as u32)
            .checked_mul(2)
            .ok_or(refusal("attack-budget"))?;
        if self.boot.limits.cases < attempts || self.boot.limits.wall_ms < PARENT_DEATH_DEADLINE_MS
        {
            return Err(refusal("attack-budget"));
        }
        Ok(())
    }

    /// Includes every frozen request field and the host-created fixture set.
    /// Fixed-width digest fields precede the length-prefixed ASCII case id.
    pub fn input_digest(&self, spec: &AttackCase) -> Digest32 {
        let mut bytes = b"aukora:hostile-case:v1\0".to_vec();
        bytes.extend_from_slice(self.boot.commitment().as_bytes());
        bytes.extend_from_slice(self.fixture_commitment.as_bytes());
        bytes.extend_from_slice(&(spec.id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(spec.id.as_bytes());
        bytes.extend_from_slice(&[spec.operation as u8, spec.fixture as u8, spec.denial as u8]);
        Digest32::sha256(&bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostileRun {
    pub request_commitment: Digest32,
    pub parent_cgroup: u64,
    pub confined_cgroup: u64,
    pub control_cgroup: u64,
    pub grants_at_start: u32,
    pub grants_at_end: u32,
    pub results: Vec<HostilePair>,
    pub usage: Usage,
    pub budget_exhausted: bool,
}

impl HostileRequest {
    pub fn commitment(&self) -> Digest32 {
        let mut bytes = b"aukora:hostile-request:v1\0".to_vec();
        bytes.extend_from_slice(self.boot.commitment().as_bytes());
        bytes.extend_from_slice(self.fixture_commitment.as_bytes());
        Digest32::sha256(&bytes)
    }
}

/// The host adapter runs both modes. Immune only reads its resulting data.
pub trait HostileDriver {
    fn drive_hostile(&mut self, request: &HostileRequest) -> Result<HostileRun>;
}

#[derive(Debug)]
pub struct HostileEvidence {
    run: HostileRun,
}

impl HostileEvidence {
    pub fn run(&self) -> &HostileRun {
        &self.run
    }
}

/// Judges every fixed attack and its positive control. Unknown, duplicate,
/// missing, differently bound, skipped or budget-exceeded cases all refuse.
pub fn judge(request: &HostileRequest, run: HostileRun) -> Result<HostileEvidence> {
    request.validate()?;
    let attempts = HOSTILE_CASES.len() as u32 * 2;
    request.boot.limits.permits(run.usage, attempts)?;
    if run.request_commitment != request.commitment()
        || run.parent_cgroup == 0
        || run.confined_cgroup == 0
        || run.control_cgroup == 0
        || run.parent_cgroup == run.confined_cgroup
        || run.parent_cgroup == run.control_cgroup
        || run.confined_cgroup == run.control_cgroup
        || run.grants_at_start != 0
        || run.grants_at_end != 0
        || run.budget_exhausted
        || run.results.len() != HOSTILE_CASES.len()
    {
        return Err(refusal("cage-attack-incomplete"));
    }
    for spec in HOSTILE_CASES {
        let mut matching = run.results.iter().filter(|row| row.case_id == spec.id);
        let Some(pair) = matching.next() else {
            return Err(refusal("cage-attack-incomplete"));
        };
        if matching.next().is_some()
            || pair.confined_input != request.input_digest(spec)
            || pair.control_input != pair.confined_input
            || pair.confined_elapsed_ms > run.usage.wall_ms
            || pair.control_elapsed_ms > run.usage.wall_ms
            || pair.control != Observation::ReachedTarget
            || !spec.accepts(pair.confined)
        {
            return Err(refusal("cage-attack-failed"));
        }
        if spec.operation == Operation::SupervisorDeath
            && (pair.confined_elapsed_ms > PARENT_DEATH_DEADLINE_MS
                || pair.control_elapsed_ms < PARENT_DEATH_DEADLINE_MS)
        {
            return Err(refusal("cage-attack-failed"));
        }
    }
    Ok(HostileEvidence { run })
}

/// Measures the wall deadline around the host driver as well as checking its
/// recorded resource counters. This function does not start the production guest.
pub fn hostile(
    driver: &mut impl HostileDriver,
    request: &HostileRequest,
) -> Result<HostileEvidence> {
    request.validate()?;
    let began = std::time::Instant::now();
    let report = driver.drive_hostile(request)?;
    if began.elapsed().as_millis() > u128::from(request.boot.limits.wall_ms) {
        return Err(refusal("attack-budget"));
    }
    judge(request, report)
}

pub(crate) const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}
