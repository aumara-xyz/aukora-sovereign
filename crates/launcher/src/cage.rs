// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ownership of launch resources and the stopped-child-to-running-child boundary.

use std::time::Duration;

use canon::{digest::Digest32, refusal::Refusal};

use crate::{
    boot::{BootFacts, BootReceipt, BootRecorder, CageSample},
    netns::UserMapping,
    profiles::{CageProfile, DisposableAuthority, DisposableSwitch},
};

/// Fallible launcher operations always carry a stable organ-prefixed refusal.
pub type Result<T> = core::result::Result<T, Refusal>;

pub(crate) const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "launcher",
        reason,
    }
}

/// The guest's two inherited data channels. Launcher remaps and transfers them;
/// it never reads the proposal stream or interprets a data frame.
#[cfg(unix)]
#[derive(Debug)]
pub struct GuestChannels {
    /// Connected STREAM endpoint mapped to FD 3; supervisor is the only host reader.
    pub proposals: std::os::fd::OwnedFd,
    /// Connected bounded data endpoint mapped to FD 4; never an HTTP listener.
    pub app_data: std::os::fd::OwnedFd,
    /// Explicitly owned standard input, output and error descriptors, in order.
    pub stdio: [std::os::fd::OwnedFd; 3],
}

/// An image that has been pinned and checked, not a path chosen by Auma.
#[cfg(unix)]
#[derive(Debug)]
pub struct StaticImage {
    _image: std::os::fd::OwnedFd,
    digest: Digest32,
}

#[cfg(unix)]
impl StaticImage {
    /// Row 25: check a sealed, regular executable image against the supervisor's
    /// approved release digest and reject dynamic interpreters. This check does
    /// not itself approve a release; its expected digest comes from the supervisor.
    pub fn pin(_image: std::os::fd::OwnedFd, _expected_sha256: Digest32) -> Result<Self> {
        todo!("row 25")
    }

    /// Commitment verified over the pinned executable bytes.
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }
}

/// Inputs owned by the supervisor; neither guest content nor a browser names paths.
#[cfg(unix)]
#[derive(Debug)]
pub struct LaunchRequest {
    /// Static executable pinned to the already approved release.
    pub executable: StaticImage,
    /// A closed Auma or user-app profile; disposable runs use a separate entry point.
    pub profile: CageProfile,
    /// Nonzero subordinate host identity for a fresh user namespace.
    pub identity: UserMapping,
    /// Existing delegated and verified cgroup-v2 leaf.
    pub cgroup: crate::cgroup::DelegatedCgroup,
    /// Inherited descriptors whose ownership transfers to the launcher.
    pub channels: GuestChannels,
    /// Positive deadline for the complete setup, record and ready handshake.
    pub setup_timeout: Duration,
}

/// Successfully started child and its durable boot receipt. No public constructor
/// can turn requested settings into this handle.
#[derive(Debug)]
pub struct RunningCage {
    pid: u32,
    facts: BootFacts,
    boot_receipt: BootReceipt,
}

impl RunningCage {
    /// Operating-system process id; not an owner or authority identity.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Observations collected before this specific child was released.
    pub const fn boot_facts(&self) -> &BootFacts {
        &self.facts
    }

    /// Aura append acknowledgement obtained before child release.
    pub const fn boot_receipt(&self) -> &BootReceipt {
        &self.boot_receipt
    }

    /// Row 26: read present kernel state rather than repeat launch configuration.
    pub fn sample(&self) -> Result<CageSample> {
        todo!("row 26")
    }

    /// Row 26: stop this child's cgroup, then reap every descendant within deadline.
    pub fn terminate(self, _deadline: Duration) -> Result<ExitStatus> {
        todo!("row 26")
    }

    /// Row 26: observe and reap exit; waiting does not manufacture successful exit.
    pub fn wait(self, _deadline: Duration) -> Result<ExitStatus> {
        todo!("row 26")
    }
}

/// A reaped child's observed termination, not a guest-supplied success message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// Normal exit with its exact code.
    Code(i32),
    /// Kernel-delivered terminating signal.
    Signal(i32),
}

/// Row 26: start a stopped child; install user/mount/PID/IPC/UTS/cgroup/network
/// namespaces, Landlock ABI >= 4, resource ceilings and the closed seccomp filter.
/// Close every descriptor except 0..4, clear capabilities, load only the pinned
/// static image, and deny execve/execveat/socket before any guest instruction.
/// Append boot facts on every boot through the supervisor; release only after its
/// durable acknowledgement. Failure kills and reaps the child, with no weaker mode.
#[cfg(unix)]
pub fn launch<R: BootRecorder + ?Sized>(
    _request: LaunchRequest,
    _recorder: &mut R,
) -> Result<RunningCage> {
    #[cfg(target_os = "linux")]
    {
        todo!("row 26")
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(refusal("unsupported-platform"))
    }
}

/// One inert, preselected command for the disposable profile; no shell evaluation.
#[cfg(unix)]
#[derive(Debug)]
pub struct DisposableCommand {
    /// Pinned executable whose exact digest falls under the signed standing policy.
    pub executable: StaticImage,
    /// Literal argument bytes, including argv[0]; bounded by the standing policy.
    pub arguments: Vec<std::ffi::OsString>,
}

/// A batch is separate from Auma's profile and contains exactly one work directory.
#[cfg(unix)]
#[derive(Debug)]
pub struct DisposableRequest {
    /// The only permitted writable subtree.
    pub directory: crate::landlock::WorkDirectory,
    /// A finite ordered batch; every command consumes the same signed budget.
    pub commands: Vec<DisposableCommand>,
    /// Fresh delegated cgroup leaf, separate from Auma and user applications.
    pub cgroup: crate::cgroup::DelegatedCgroup,
    /// Subordinate identity for the separate namespace set.
    pub identity: UserMapping,
    /// Deadline covering the entire disposable batch.
    pub deadline: Duration,
}

/// Row 39: a disabled switch refuses before process creation. After the owner's
/// exact policy is durably consumed, construct the exact run from the pinned inputs
/// and call authority.with_authorized_run before any process creation. Inside its
/// admission scope, restrict the sole WorkDirectory with Landlock and use
/// launcher-controlled launches into separate command cages.
/// The command payload cannot spawn or exec another command or open a socket.
#[cfg(unix)]
pub fn run_disposable<A: DisposableAuthority + ?Sized, R: BootRecorder + ?Sized>(
    switch: &mut DisposableSwitch,
    _request: DisposableRequest,
    _authority: &mut A,
    _recorder: &mut R,
) -> Result<Vec<ExitStatus>> {
    if !switch.enabled() {
        return Err(refusal("disposable-disabled"));
    }
    todo!("row 39")
}
