// SPDX-License-Identifier: AGPL-3.0-or-later
//! Boot observations and the supervisor-owned Aura append port.

use canon::{
    authority::FactKind,
    digest::Digest32,
    json::{SafeInteger, Value},
};

use crate::{
    cage::Result, cgroup::CgroupFacts, landlock::LandlockFacts, netns::NamespaceFacts,
    profiles::ProfileKind, seccomp::SeccompFacts,
};

/// Supervisor boot precedes binding, release admission and child setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCageState {
    /// No child has been launched: no installed guest filter or containment claim.
    NotStarted,
}

/// Host observations recorded even when no guest may start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostBootFacts {
    /// Kernel release sampled on this supervisor boot.
    pub kernel_release: String,
    /// Available kernel ABI; None means unavailable, never successful restriction.
    pub available_landlock_abi: Option<u32>,
    /// Initial state explicitly distinguished from installed child facts.
    pub cage_state: HostCageState,
}

impl HostBootFacts {
    /// Host observations use only the nonauthorizing boot-fact kind.
    pub const fn kind(&self) -> FactKind {
        FactKind::BootFacts
    }

    /// Row 27: encode a versioned body distinguishing available host support from
    /// absent child observations. The installed guest seccomp digest is null, never
    /// a planned filter digest or a copied receipt from an earlier boot.
    pub fn to_body(&self) -> Result<Value> {
        object([
            ("schema", text("aukora-host-boot-v1")?),
            ("kernel_release", kernel_text(&self.kernel_release)?),
            (
                "available_landlock_abi",
                self.available_landlock_abi
                    .map_or(Ok(Value::null()), |abi| number(abi.into()))?,
            ),
            ("cage_state", text("not-started")?),
            ("installed_seccomp_sha256", Value::null()),
        ])
    }
}

/// Supervisor boot must be recorded before unbound or unapproved startup refuses.
pub trait HostBootRecorder {
    /// Append and durably commit C3 boot.facts with the supervisor's own clock,
    /// epoch and next sequence. This does not enable a guest or approve a release.
    fn append_host_boot(&mut self, facts: &HostBootFacts) -> Result<BootReceipt>;
}

/// Row 27: sample this host without starting a child or pretending an absent cage
/// has installed restrictions. Unsupported/missing Landlock stays unavailable data.
pub fn inspect_host() -> Result<HostBootFacts> {
    #[cfg(target_os = "linux")]
    {
        let mut name = core::mem::MaybeUninit::<libc::utsname>::uninit();
        // SAFETY: uname initializes this correctly sized output on success only.
        if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
            return Err(crate::cage::refusal("boot-kernel"));
        }
        // SAFETY: the preceding successful uname initialized every field.
        let name = unsafe { name.assume_init() };
        let raw: Vec<u8> = name
            .release
            .iter()
            .map(|byte| *byte as u8)
            .take_while(|byte| *byte != 0)
            .collect();
        let kernel_release =
            String::from_utf8(raw).map_err(|_| crate::cage::refusal("boot-kernel"))?;
        kernel_text(&kernel_release)?;
        // SAFETY: VERSION accepts a null attribute pointer and a zero size. It
        // queries support without creating a ruleset or restricting this process.
        let queried = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                core::ptr::null::<u8>(),
                0usize,
                1u32,
            )
        };
        let available_landlock_abi = if queried > 0 {
            Some(u32::try_from(queried).map_err(|_| crate::cage::refusal("boot-landlock"))?)
        } else if queried == -1
            && matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM | libc::EACCES)
            )
        {
            None
        } else {
            return Err(crate::cage::refusal("boot-landlock"));
        };
        Ok(HostBootFacts {
            kernel_release,
            available_landlock_abi,
            cage_state: HostCageState::NotStarted,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(crate::cage::refusal("unsupported-platform"))
    }
}

/// Uninterpreted kernel observations from this launch, never permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootFacts {
    /// Kernel release obtained from the running kernel rather than release metadata.
    pub kernel_release: String,
    /// Executable digest checked from the pinned bytes actually loaded.
    pub executable_sha256: Digest32,
    /// Closed cage profile in effect for the child.
    pub profile: ProfileKind,
    /// Installed Landlock observations, including its ABI.
    pub landlock: LandlockFacts,
    /// Installed seccomp observations, including its exact filter commitment.
    pub seccomp: SeccompFacts,
    /// Namespace observations sampled during this launch.
    pub namespaces: NamespaceFacts,
    /// Resource settings read back after child attachment.
    pub cgroup: CgroupFacts,
    /// Number of inherited descriptors after closure; Auma retains exactly five.
    pub inherited_descriptors: u32,
    /// Whether child capability sets were read back as empty.
    pub capabilities_cleared: bool,
}

/// An acknowledgement from Aura's durable append path. It is never authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootReceipt {
    /// Aura's sequence for the committed `boot.facts` row.
    pub sequence: u64,
    /// C2 hash of the committed row.
    pub entry_sha256: Digest32,
}

/// The supervisor implements this port and supplies its clock and ledger context.
/// Launcher opens neither Aura's database nor any organ service socket.
pub trait BootRecorder {
    /// Row 28: the supervisor runs immune's request-bound self-attack for these
    /// measured child facts before release. Missing execution keeps the child
    /// stopped. This veto supplies no owner, release or spend authorization.
    fn before_agent_start(&mut self, _facts: &BootFacts) -> Result<()> {
        Err(crate::cage::refusal("boot-attack-required"))
    }

    /// Append C3 `boot.facts` with phase `fact`, canonical body, supervisor clock,
    /// epoch and next sequence. Return only after durable commit. An append failure
    /// leaves the child blocked and causes the launcher to terminate and reap it.
    fn append_boot(&mut self, facts: &BootFacts) -> Result<BootReceipt>;
}

impl BootFacts {
    /// Boot observations cannot select an authority-bearing ledger kind.
    pub const fn kind(&self) -> FactKind {
        FactKind::BootFacts
    }

    /// Row 27: encode bounded canonical facts in C3's body. Kernel release,
    /// Landlock ABI and the seccomp hash are mandatory; no new C3 row key is added.
    pub fn to_body(&self) -> Result<Value> {
        let namespace = &self.namespaces;
        let limits = &self.cgroup.limits;
        object([
            ("schema", text("aukora-cage-boot-v1")?),
            ("kernel_release", kernel_text(&self.kernel_release)?),
            (
                "executable_sha256",
                text(&self.executable_sha256.to_string())?,
            ),
            ("profile", text(profile_name(self.profile))?),
            (
                "landlock",
                object([
                    ("abi", number(self.landlock.abi.get().into())?),
                    (
                        "fully_enforced",
                        Value::boolean(self.landlock.fully_enforced),
                    ),
                    (
                        "network_denied",
                        Value::boolean(self.landlock.network_denied),
                    ),
                    (
                        "writable_subtrees",
                        number(self.landlock.writable_subtrees.into())?,
                    ),
                ])?,
            ),
            (
                "seccomp",
                object([
                    ("mode", number(self.seccomp.mode.into())?),
                    (
                        "no_new_privileges",
                        Value::boolean(self.seccomp.no_new_privileges),
                    ),
                    (
                        "filter_sha256",
                        text(&self.seccomp.filter_sha256.to_string())?,
                    ),
                    ("profile", text(profile_name(self.seccomp.profile))?),
                ])?,
            ),
            (
                "namespaces",
                object([
                    ("user_isolated", Value::boolean(namespace.user_isolated)),
                    ("mounts_isolated", Value::boolean(namespace.mounts_isolated)),
                    ("pids_isolated", Value::boolean(namespace.pids_isolated)),
                    ("ipc_isolated", Value::boolean(namespace.ipc_isolated)),
                    ("uts_isolated", Value::boolean(namespace.uts_isolated)),
                    ("cgroup_isolated", Value::boolean(namespace.cgroup_isolated)),
                    (
                        "supervisor_network",
                        namespace_body(namespace.supervisor_network)?,
                    ),
                    ("child_network", namespace_body(namespace.child_network)?),
                    (
                        "active_interfaces",
                        number(namespace.active_interfaces.into())?,
                    ),
                    ("routes", number(namespace.routes.into())?),
                ])?,
            ),
            (
                "cgroup",
                object([
                    ("version", number(self.cgroup.version.into())?),
                    ("swap_disabled", Value::boolean(self.cgroup.swap_disabled)),
                    ("child_attached", Value::boolean(self.cgroup.child_attached)),
                    (
                        "limits",
                        object([
                            ("memory_bytes", number(limits.memory_bytes.get())?),
                            ("tasks", number(limits.tasks.get().into())?),
                            ("cpu_quota_us", number(limits.cpu_quota_us.get())?),
                            ("cpu_period_us", number(limits.cpu_period_us.get())?),
                            ("open_files", number(limits.open_files.get().into())?),
                            ("file_bytes", number(limits.file_bytes.get())?),
                        ])?,
                    ),
                ])?,
            ),
            (
                "inherited_descriptors",
                number(self.inherited_descriptors.into())?,
            ),
            (
                "capabilities_cleared",
                Value::boolean(self.capabilities_cleared),
            ),
        ])
    }
}
fn profile_name(profile: ProfileKind) -> &'static str {
    match profile {
        ProfileKind::Auma => "auma",
        ProfileKind::UserApp => "user-app",
        ProfileKind::Disposable => "disposable",
    }
}
fn object<const N: usize>(fields: [(&str, Value); N]) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}
fn kernel_text(release: &str) -> Result<Value> {
    if release.is_empty()
        || release.len() > 255
        || release.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(crate::cage::refusal("boot-kernel"));
    }
    text(release)
}
fn number(value: u64) -> Result<Value> {
    let checked = i64::try_from(value)
        .ok()
        .and_then(|n| SafeInteger::new(n).ok())
        .ok_or_else(|| crate::cage::refusal("boot-number-range"))?;
    Ok(Value::integer(checked))
}
fn namespace_body(identity: crate::netns::NamespaceIdentity) -> Result<Value> {
    // Kernel dev_t and ino_t can exceed the C1 integer range; decimal text retains
    // all their bits in this versioned body.
    object([
        ("device", text(&identity.device.to_string())?),
        ("inode", text(&identity.inode.to_string())?),
    ])
}

/// Inspect and durably record this boot without launching or admitting an agent.
pub fn record_host_boot(
    recorder: &mut (impl HostBootRecorder + ?Sized),
) -> Result<(HostBootFacts, BootReceipt)> {
    let facts = inspect_host()?;
    let receipt = recorder.append_host_boot(&facts)?;
    if receipt.sequence == 0 {
        return Err(crate::cage::refusal("boot-receipt"));
    }
    Ok((facts, receipt))
}

/// A live sample is distinct from boot-time configuration and old observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CageSample {
    /// Monotonic elapsed time from the start of this cage, in milliseconds.
    pub observed_after_ms: u64,
    /// Whether the child is still present when sampled.
    pub running: bool,
    /// Landlock observation, absent when the process cannot be inspected.
    pub landlock: Option<LandlockFacts>,
    /// Seccomp observation, absent when the process cannot be inspected.
    pub seccomp: Option<SeccompFacts>,
    /// Namespace observation, absent when the process cannot be inspected.
    pub namespaces: Option<NamespaceFacts>,
    /// Resource observation, absent when the process cannot be inspected.
    pub cgroup: Option<CgroupFacts>,
}

/// The four kernel operations in the boot attack's closed operation set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelProbe {
    /// Open a supervisor-prepared file and read its complete marker.
    ReadHostSecret,
    /// Execute a sealed, digest-pinned fixture with fixed argv and empty environment.
    ExecuteCommand,
    /// Create an IPv4 stream socket without connecting to any address.
    OpenSocket,
    /// Exclusively create and write a marker in a supervisor-prepared directory.
    WriteOutsideCage,
}

/// A syscall observation; an unavailable fixture is never successful containment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelProbeOutcome {
    /// The attempted operation returned EACCES or EPERM.
    Blocked,
    /// The marker operation or the pinned executable completed successfully.
    ReachedTarget,
    /// Setup, fixture, protocol, exit or cleanup failed.
    Unavailable,
    /// The child exceeded the monotonic wall deadline and was killed and reaped.
    BudgetExceeded,
}

/// Host-observed result, without fixture contents or a permission to start Auma.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelProbeObservation {
    /// Operation selected by trusted code.
    pub probe: KernelProbe,
    /// Observed outcome of that operation.
    pub outcome: KernelProbeOutcome,
    /// Errno when the child reported a failed syscall.
    pub errno: Option<i32>,
    /// Supervisor's commitment to this run, challenge and exact fixture input.
    pub input_digest: Digest32,
}

/// Same-input observations; immune, not launcher, judges containment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelProbePair {
    /// Probe with the production confinement installed in its disposable child.
    pub confined: KernelProbeObservation,
    /// Probe with that confinement omitted in a different disposable child.
    pub unconfined_control: KernelProbeObservation,
}

/// Linux-only preparations and execution. No probe executes in the supervisor.
#[cfg(target_os = "linux")]
pub mod kernel_probes {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::CString,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        sync::Mutex,
        time::{Duration, Instant},
    };

    const MARKER_BYTES: usize = 32;
    const EXECUTABLE_MAX: u64 = 16 * 1024 * 1024;
    const SETUP_FAILED: i32 = 120;
    const OBSERVED: i32 = 121;

    /// Trusted prepared confinement for the separate probe child.
    ///
    /// # Safety
    /// `enter` runs between fork and exec. It must use only async-signal-safe
    /// operations, must not unwind, and may return true only after installing the
    /// production syscall/Landlock restrictions when confined, and resource
    /// ceilings on both sides. Fixture/report FDs are instrumentation: this does
    /// not measure production FD closure. Auma never implements this host port.
    pub unsafe trait ProbeConfinement {
        /// Prepare a fresh delegated cgroup and bounds before creating each child.
        fn prepare(&self) -> Result<()>;
        /// Attach this child to that cgroup and install the selected restrictions.
        ///
        /// # Safety
        /// Caller must be the just-forked disposable probe child.
        unsafe fn enter(&self, confined: bool, fixture_fd: i32, report_fd: i32) -> bool;
        /// Kill/reap every descendant and verify the cgroup empty; idempotent.
        fn cleanup(&self) -> Result<()>;
    }

    /// A prepared operation. Descriptor ownership lasts through both child reaps.
    pub struct KernelProbeSpec {
        probe: KernelProbe,
        descriptor: Option<OwnedFd>,
        name: CString,
        marker: [u8; MARKER_BYTES],
        input_digest: Digest32,
        active: Mutex<()>,
    }

    impl KernelProbeSpec {
        /// Prepare an exact 32-byte readable marker in a host-owned fixture directory.
        /// The input commitment is supplied by the supervisor's attack plan.
        pub fn read_file(
            directory: OwnedFd,
            leaf: &str,
            marker: [u8; 32],
            input_digest: Digest32,
        ) -> Result<Self> {
            Self::file(
                KernelProbe::ReadHostSecret,
                directory,
                leaf,
                marker,
                input_digest,
            )
        }

        /// Prepare a new, initially absent marker file. Both children use this same
        /// name; the parent removes its own created file after each reap.
        pub fn write_file(
            directory: OwnedFd,
            leaf: &str,
            marker: [u8; 32],
            input_digest: Digest32,
        ) -> Result<Self> {
            Self::file(
                KernelProbe::WriteOutsideCage,
                directory,
                leaf,
                marker,
                input_digest,
            )
        }

        fn file(
            probe: KernelProbe,
            directory: OwnedFd,
            leaf: &str,
            marker: [u8; 32],
            input_digest: Digest32,
        ) -> Result<Self> {
            if leaf.is_empty()
                || leaf.len() > 128
                || leaf == "."
                || leaf == ".."
                || !leaf
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(crate::cage::refusal("probe-fixture"));
            }
            let mut info = core::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: descriptor is owned; fstat writes only into this stat buffer.
            if unsafe { libc::fstat(directory.as_raw_fd(), info.as_mut_ptr()) } != 0 {
                return Err(crate::cage::refusal("probe-fixture"));
            }
            // SAFETY: successful fstat initialized the output.
            let info = unsafe { info.assume_init() };
            // SAFETY: geteuid has no memory arguments or side effects.
            if info.st_mode & libc::S_IFMT != libc::S_IFDIR
                || info.st_mode & 0o077 != 0
                || info.st_uid != unsafe { libc::geteuid() }
            {
                return Err(crate::cage::refusal("probe-fixture"));
            }
            Ok(Self {
                probe,
                descriptor: Some(directory),
                name: CString::new(leaf).map_err(|_| crate::cage::refusal("probe-fixture"))?,
                marker,
                input_digest,
                active: Mutex::new(()),
            })
        }

        /// Prepare a socket-creation probe; no listener or external address is used.
        pub fn socket(input_digest: Digest32) -> Self {
            Self {
                probe: KernelProbe::OpenSocket,
                descriptor: None,
                name: CString::default(),
                marker: [0; 32],
                input_digest,
                active: Mutex::new(()),
            }
        }

        /// Pin an immutable regular executable fixture. The trusted fixture must
        /// exit zero after entry; argv and environment cannot be supplied as data.
        pub fn executable(
            image: OwnedFd,
            expected_sha256: Digest32,
            input_digest: Digest32,
        ) -> Result<Self> {
            let fd = image.as_raw_fd();
            let mut info = core::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: image is owned and info is a writable stat output.
            if unsafe { libc::fstat(fd, info.as_mut_ptr()) } != 0 {
                return Err(crate::cage::refusal("probe-fixture"));
            }
            // SAFETY: successful fstat initialized info.
            let info = unsafe { info.assume_init() };
            // SAFETY: F_GET_SEALS has no pointer argument or side effect.
            let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
            let required =
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
            if seals < 0
                || seals & required != required
                || info.st_mode & libc::S_IFMT != libc::S_IFREG
                || info.st_size <= 0
                || info.st_size as u64 > EXECUTABLE_MAX
            {
                return Err(crate::cage::refusal("probe-fixture"));
            }
            let mut hash = Sha256::new();
            let mut offset = 0;
            let mut buffer = [0u8; 8192];
            while offset < info.st_size {
                // SAFETY: pread writes at most buffer.len() bytes without moving
                // the shared descriptor offset. Seals prevent concurrent changes.
                let read =
                    unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), buffer.len(), offset) };
                if read < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if read <= 0 {
                    return Err(crate::cage::refusal("probe-fixture"));
                }
                hash.update(&buffer[..read as usize]);
                offset += read as libc::off_t;
            }
            if Digest32::from_bytes(hash.finalize().into()) != expected_sha256 {
                return Err(crate::cage::refusal("probe-fixture"));
            }
            Ok(Self {
                probe: KernelProbe::ExecuteCommand,
                descriptor: Some(image),
                name: CString::default(),
                marker: [0; 32],
                input_digest,
                active: Mutex::new(()),
            })
        }
    }

    /// Run an unconfined control then a confined attempt under one wall budget.
    /// Both must be judged by immune; neither result admits an agent or release.
    pub fn run_kernel_pair(
        spec: &KernelProbeSpec,
        confinement: &impl ProbeConfinement,
        wall: Duration,
    ) -> Result<KernelProbePair> {
        let _active = spec
            .active
            .try_lock()
            .map_err(|_| crate::cage::refusal("probe-fixture"))?;
        if wall.is_zero() || wall > Duration::from_secs(60) {
            return Err(crate::cage::refusal("probe-budget"));
        }
        let deadline = Instant::now()
            .checked_add(wall)
            .ok_or_else(|| crate::cage::refusal("probe-budget"))?;
        let unconfined_control = run_one(spec, confinement, false, deadline)?;
        let confined = run_one(spec, confinement, true, deadline)?;
        Ok(KernelProbePair {
            confined,
            unconfined_control,
        })
    }

    struct ReapGuard {
        pidfd: OwnedFd,
        reaped: bool,
    }

    impl Drop for ReapGuard {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            // SAFETY: the atomic clone pidfd identifies this child even if a
            // supervisor reaper has consumed its numeric PID in the meantime.
            let signalled = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    core::ptr::null::<u8>(),
                    0u32,
                )
            };
            if signalled == 0 {
                let _ = reap(self.pidfd.as_raw_fd(), 0);
            }
        }
    }

    fn reap(pidfd: i32, options: i32) -> Result<Option<(bool, i32)>> {
        loop {
            let mut info = core::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: owned pidfd selects only this child; info is writable.
            if unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    pidfd as libc::id_t,
                    info.as_mut_ptr(),
                    libc::WEXITED | options,
                )
            } != 0
            {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(crate::cage::refusal("probe-wait"));
            }
            // SAFETY: waitid returned initialized siginfo or the zero no-event value.
            let info = unsafe { info.assume_init() };
            return Ok(if info.si_code == 0 {
                None
            } else {
                Some((info.si_code == libc::CLD_EXITED, unsafe {
                    info.si_status()
                }))
            });
        }
    }

    struct ProbeCleanup<'a, T: ProbeConfinement>(&'a T, bool);
    impl<T: ProbeConfinement> ProbeCleanup<'_, T> {
        fn finish(&mut self) -> Result<()> {
            self.0.cleanup()?;
            self.1 = true;
            Ok(())
        }
    }
    impl<T: ProbeConfinement> Drop for ProbeCleanup<'_, T> {
        fn drop(&mut self) {
            if !self.1 {
                let _ = self.0.cleanup();
            }
        }
    }

    fn run_one(
        spec: &KernelProbeSpec,
        confinement: &impl ProbeConfinement,
        confined: bool,
        deadline: Instant,
    ) -> Result<KernelProbeObservation> {
        let result = |outcome, errno| KernelProbeObservation {
            probe: spec.probe,
            outcome,
            errno,
            input_digest: spec.input_digest,
        };
        if Instant::now() >= deadline {
            return Ok(result(KernelProbeOutcome::BudgetExceeded, None));
        }
        if spec.probe == KernelProbe::WriteOutsideCage {
            let fd = spec
                .descriptor
                .as_ref()
                .ok_or_else(|| crate::cage::refusal("probe-fixture"))?
                .as_raw_fd();
            let mut info = core::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: single validated leaf under the pinned fixture directory.
            if unsafe {
                libc::fstatat(
                    fd,
                    spec.name.as_ptr(),
                    info.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
            {
                return Err(crate::cage::refusal("probe-fixture"));
            }
        }
        let _cleanup = WriteCleanup(spec);
        let mut cleanup = ProbeCleanup(confinement, false);
        confinement.prepare()?;
        let mut pipe = [-1; 2];
        // SAFETY: pipe points to two writable descriptor slots.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(crate::cage::refusal("probe-pipe"));
        }
        // SAFETY: successful pipe2 returned two distinct newly owned descriptors.
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        // SAFETY: the second pipe descriptor is separately newly owned.
        let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let mut pidfd = -1i32;
        // clone_args' eleven u64 fields have the same layout on Linux ABIs.
        let mut args = [0u64; 11];
        args[0] = libc::CLONE_PIDFD as u64;
        args[1] = (&mut pidfd as *mut i32) as u64;
        args[4] = libc::SIGCHLD as u64;
        // SAFETY: zero stack requests fork semantics. CLONE_PIDFD returns the
        // parent's owned process descriptor atomically; no PID-open race exists.
        let pid = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                args.as_ptr(),
                core::mem::size_of_val(&args),
            )
        };
        if pid < 0 {
            return Err(crate::cage::refusal("probe-fork"));
        }
        if pid == 0 {
            // SAFETY: this is the disposable child; no Rust destruction follows.
            unsafe {
                libc::close(reader.as_raw_fd());
                if !confinement.enter(
                    confined,
                    spec.descriptor.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    writer.as_raw_fd(),
                ) {
                    libc::_exit(SETUP_FAILED);
                }
                if spec.probe == KernelProbe::ExecuteCommand
                    && libc::write(writer.as_raw_fd(), [0xa5u8].as_ptr().cast(), 1) != 1
                {
                    libc::_exit(SETUP_FAILED);
                }
                let report = perform(spec);
                let written = libc::write(writer.as_raw_fd(), report.as_ptr().cast(), report.len());
                libc::_exit(if written == report.len() as isize {
                    OBSERVED
                } else {
                    SETUP_FAILED
                });
            }
        }
        // SAFETY: successful clone3 with CLONE_PIDFD returned this owned FD.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let mut child = ReapGuard {
            pidfd,
            reaped: false,
        };
        drop(writer);
        let mut report = [0u8; 9];
        let mut used = 0;
        let mut overflow = false;
        loop {
            if let Some((exited, status)) = reap(child.pidfd.as_raw_fd(), libc::WNOHANG)? {
                child.reaped = true;
                cleanup.finish()?;
                drain(reader.as_raw_fd(), &mut report, &mut used, &mut overflow)?;
                if !cleanup_write(spec)? {
                    return Ok(result(KernelProbeOutcome::Unavailable, None));
                }
                if Instant::now() > deadline {
                    return Ok(result(KernelProbeOutcome::BudgetExceeded, None));
                }
                if !overflow
                    && used == 1
                    && report[0] == 0xa5
                    && spec.probe == KernelProbe::ExecuteCommand
                    && exited
                    && status == 0
                {
                    return Ok(result(KernelProbeOutcome::ReachedTarget, None));
                }
                let prefix = usize::from(spec.probe == KernelProbe::ExecuteCommand);
                if overflow
                    || used != 8 + prefix
                    || (prefix == 1 && report[0] != 0xa5)
                    || !exited
                    || status != OBSERVED
                {
                    return Ok(result(KernelProbeOutcome::Unavailable, None));
                }
                let code = i32::from_be_bytes(
                    report[prefix..prefix + 4]
                        .try_into()
                        .map_err(|_| crate::cage::refusal("probe-report"))?,
                );
                let errno = i32::from_be_bytes(
                    report[prefix + 4..prefix + 8]
                        .try_into()
                        .map_err(|_| crate::cage::refusal("probe-report"))?,
                );
                return Ok(match (code, errno) {
                    (1, 0) => result(KernelProbeOutcome::ReachedTarget, None),
                    (0, libc::EACCES | libc::EPERM) => {
                        result(KernelProbeOutcome::Blocked, Some(errno))
                    }
                    _ => result(
                        KernelProbeOutcome::Unavailable,
                        (errno != 0).then_some(errno),
                    ),
                });
            }
            if Instant::now() >= deadline {
                drop(child);
                cleanup.finish()?;
                cleanup_write(spec)?;
                return Ok(result(KernelProbeOutcome::BudgetExceeded, None));
            }
            drain(reader.as_raw_fd(), &mut report, &mut used, &mut overflow)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            // poll without descriptors sleeps even after report EOF, avoiding a spin.
            let delay = remaining.as_millis().clamp(1, 5) as i32;
            // SAFETY: a null array and zero count form a bounded poll sleep.
            unsafe {
                libc::poll(core::ptr::null_mut(), 0, delay);
            }
        }
    }

    fn drain(fd: i32, report: &mut [u8; 9], used: &mut usize, overflow: &mut bool) -> Result<()> {
        let mut bytes = [0u8; 10];
        loop {
            // SAFETY: bytes is writable and read is bounded by its length.
            let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if read == 0 {
                return Ok(());
            }
            if read < 0 {
                return match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => Ok(()),
                    _ => Err(crate::cage::refusal("probe-report")),
                };
            }
            let count = read as usize;
            let room = report.len() - *used;
            let retained = count.min(room);
            report[*used..*used + retained].copy_from_slice(&bytes[..retained]);
            *used += retained;
            *overflow |= count > room;
            if *overflow {
                return Err(crate::cage::refusal("probe-output-limit"));
            }
        }
    }

    fn cleanup_write(spec: &KernelProbeSpec) -> Result<bool> {
        if spec.probe != KernelProbe::WriteOutsideCage {
            return Ok(true);
        }
        let directory = spec
            .descriptor
            .as_ref()
            .ok_or_else(|| crate::cage::refusal("probe-fixture"))?;
        let mut info = core::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: output stat is writable; symlinks are inspected, never followed.
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                spec.name.as_ptr(),
                info.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Ok(std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT));
        }
        // SAFETY: fstatat initialized info successfully.
        let info = unsafe { info.assume_init() };
        if info.st_mode & libc::S_IFMT != libc::S_IFREG || info.st_nlink != 1 {
            return Ok(false);
        }
        // SAFETY: the validated single leaf is beneath the pinned fixture directory.
        let removed = unsafe { libc::unlinkat(directory.as_raw_fd(), spec.name.as_ptr(), 0) };
        Ok(removed == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))
    }

    struct WriteCleanup<'a>(&'a KernelProbeSpec);
    impl Drop for WriteCleanup<'_> {
        fn drop(&mut self) {
            let _ = cleanup_write(self.0);
        }
    }

    // Only async-signal-safe libc operations and stack data are used in the child.
    unsafe fn perform(spec: &KernelProbeSpec) -> [u8; 8] {
        let fd = spec.descriptor.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let (reached, errno): (i32, i32) = match spec.probe {
            KernelProbe::OpenSocket => {
                // SAFETY: socket uses fixed kernel constants, and success is closed.
                let opened = unsafe {
                    libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
                };
                if opened >= 0 {
                    unsafe {
                        libc::close(opened);
                    }
                    (1, 0)
                } else {
                    (0, child_errno())
                }
            }
            KernelProbe::ExecuteCommand => {
                let argv = [c"aukora-boot-probe".as_ptr(), core::ptr::null()];
                let envp: [*const libc::c_char; 1] = [core::ptr::null()];
                // SAFETY: sealed owned fixture descriptor, fixed terminated argv
                // and empty environment; success replaces only this probe child.
                unsafe {
                    libc::syscall(
                        libc::SYS_execveat,
                        fd,
                        c"".as_ptr(),
                        argv.as_ptr(),
                        envp.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    );
                }
                (0, child_errno())
            }
            KernelProbe::ReadHostSecret | KernelProbe::WriteOutsideCage => {
                let writing = spec.probe == KernelProbe::WriteOutsideCage;
                let flags = libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | if writing {
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
                    } else {
                        libc::O_RDONLY
                    };
                // SAFETY: name is a single validated C leaf and fd pins its parent.
                let opened =
                    unsafe { libc::openat(fd, spec.name.as_ptr(), flags, 0o600 as libc::mode_t) };
                if opened < 0 {
                    (0, child_errno())
                } else {
                    let mut bytes = [0u8; MARKER_BYTES + 1];
                    // SAFETY: the selected buffers are valid for the stated lengths.
                    let count = if writing {
                        unsafe { libc::write(opened, spec.marker.as_ptr().cast(), MARKER_BYTES) }
                    } else {
                        unsafe { libc::read(opened, bytes.as_mut_ptr().cast(), bytes.len()) }
                    };
                    let errno = if count < 0 { child_errno() } else { 0 };
                    let matches = count == MARKER_BYTES as isize
                        && (writing || bytes[..MARKER_BYTES] == spec.marker);
                    // SAFETY: opened is a descriptor created above in this child.
                    unsafe {
                        libc::close(opened);
                    }
                    // A successful open already breached the filesystem boundary;
                    // only complete exact markers make the control effective.
                    if count < 0 {
                        (2, errno)
                    } else {
                        (if matches { 1 } else { 2 }, 0)
                    }
                }
            }
        };
        let mut report = [0; 8];
        report[..4].copy_from_slice(&reached.to_be_bytes());
        report[4..].copy_from_slice(&errno.to_be_bytes());
        report
    }

    fn child_errno() -> i32 {
        // SAFETY: Linux libc exposes thread-local errno storage for this thread.
        unsafe { *libc::__errno_location() }
    }
}
