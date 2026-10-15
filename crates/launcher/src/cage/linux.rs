// SPDX-License-Identifier: AGPL-3.0-or-later
//! Trusted fork setup and the stopped-payload release boundary.

use super::*;
use crate::{
    cgroup::{DelegatedCgroup, ResourceLimits},
    landlock::{self, LandlockAbi, LandlockFacts, WorkDirectory},
    netns::{self, NamespaceBaseline, NamespaceFacts},
    profiles::ProfileKind,
    seccomp::{Architecture, CompiledFilter, SeccompFacts},
};
use std::{
    cell::UnsafeCell,
    ffi::{CStr, OsString},
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicI32, AtomicU32, Ordering},
    time::Instant,
};

#[derive(Clone, Debug)]
struct SetupFacts {
    landlock: LandlockFacts,
    seccomp: SeccompFacts,
    namespaces: NamespaceFacts,
}
#[repr(C)]
struct Block {
    stage: AtomicU32,
    permit: AtomicU32,
    abort: AtomicU32,
    payload: AtomicI32,
    exit: AtomicI32,
    facts: UnsafeCell<MaybeUninit<SetupFacts>>,
    failure: UnsafeCell<MaybeUninit<Refusal>>,
}
#[derive(Debug)]
struct Shared(*mut Block);
// SAFETY: ownership of the mapping transfers with this handle; only atomics and release-published immutable slots are shared.
unsafe impl Send for Shared {}
// SAFETY: readers use acquire loads, and the unique owning handle controls unmapping after its Rust borrows end.
unsafe impl Sync for Shared {}
impl Shared {
    fn new() -> Result<Self> {
        // SAFETY: a shared anonymous mapping holds only this explicitly initialized block.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(refusal("setup-memory"));
        }
        let block = raw.cast::<Block>();
        // SAFETY: the fresh page is writable and larger than Block.
        unsafe {
            block.write(Block {
                stage: AtomicU32::new(0),
                permit: AtomicU32::new(0),
                abort: AtomicU32::new(0),
                payload: AtomicI32::new(0),
                exit: AtomicI32::new(i32::MIN),
                facts: UnsafeCell::new(MaybeUninit::uninit()),
                failure: UnsafeCell::new(MaybeUninit::uninit()),
            });
        }
        Ok(Self(block))
    }
    fn get(&self) -> &Block {
        // SAFETY: this mapping remains owned until every child has been stopped/reaped.
        unsafe { &*self.0 }
    }
    fn wait(&self, stage: u32, monitor: i32, until: Instant) -> Result<()> {
        loop {
            let current = self.get().stage.load(Ordering::Acquire);
            if current == 99 {
                // SAFETY: release-publishing 99 follows initialization of this immutable refusal.
                return Err(unsafe { *(*self.get().failure.get()).assume_init_ref() });
            }
            if current >= stage {
                return Ok(());
            }
            // SAFETY: signal zero checks an unreaped child; it changes no process state.
            if Instant::now() >= until || unsafe { libc::kill(monitor, 0) } != 0 {
                return Err(refusal("setup-timeout"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn permit(&self, n: u32) {
        self.get().permit.store(n, Ordering::Release);
    }
    fn child_wait(&self, n: u32) {
        while self.get().permit.load(Ordering::Acquire) < n {
            if self.get().abort.load(Ordering::Acquire) != 0 {
                // SAFETY: cancellation is handled by the trusted setup code before payload entry.
                unsafe { libc::_exit(125) }
            }
            std::hint::spin_loop();
        }
        if self.get().abort.load(Ordering::Acquire) != 0 {
            // SAFETY: a cancelled setup never enters the guest.
            unsafe { libc::_exit(125) }
        }
    }
    fn fail(&self, error: Refusal) -> ! {
        // SAFETY: only the trusted setup process writes this slot, before publishing failure.
        unsafe {
            (*self.get().failure.get()).write(error);
        }
        self.get().stage.store(99, Ordering::Release);
        // SAFETY: no Rust cleanup or inherited I/O runs in the failed fork child.
        unsafe { libc::_exit(125) }
    }
}
impl Drop for Shared {
    fn drop(&mut self) {
        // SAFETY: parent owns this page; children have distinct references to the shared mapping.
        unsafe {
            libc::munmap(self.0.cast(), 4096);
        }
    }
}

#[derive(Debug)]
pub(super) struct Runtime {
    monitor: i32,
    payload_fd: Option<OwnedFd>,
    cgroup: DelegatedCgroup,
    shared: Shared,
    started: Instant,
    limits: ResourceLimits,
    reaped: bool,
}
impl Runtime {
    pub(super) fn sample(&self, pid: u32) -> Result<CageSample> {
        let fd = self.payload_fd.as_ref().ok_or(refusal("pidfd"))?;
        let mut sample = CageSample {
            observed_after_ms: self.started.elapsed().as_millis().min(u64::MAX.into()) as u64,
            running: false,
            landlock: None,
            seccomp: None,
            namespaces: None,
            cgroup: None,
        };
        if !is_alive(fd)? {
            return Ok(sample);
        }
        let observed = self.cgroup.sample(pid, self.limits);
        if !is_alive(fd)? {
            return Ok(sample);
        }
        sample.cgroup = Some(observed?);
        sample.running = true;
        Ok(sample)
    }
    fn stop(&self) -> Result<()> {
        self.shared.get().abort.store(1, Ordering::Release);
        let group_result = self.cgroup.kill();
        let late = if self.payload_fd.is_none() {
            let pid = self.shared.get().payload.load(Ordering::Acquire);
            if pid > 1 {
                pidfd(pid).ok()
            } else {
                None
            }
        } else {
            None
        };
        if let Some(fd) = self.payload_fd.as_ref().or(late.as_ref()) {
            // SAFETY: a pidfd names this process instance even after its numeric PID is reused.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        if !self.reaped {
            // SAFETY: the unreaped direct child's PID cannot yet be reused.
            unsafe {
                libc::kill(self.monitor, libc::SIGCONT);
            }
        }
        group_result
    }
    pub(super) fn finish(mut self, deadline: Duration, terminate: bool) -> Result<ExitStatus> {
        let until = Instant::now()
            .checked_add(deadline)
            .ok_or(refusal("deadline"))?;
        if deadline.is_zero() {
            return Err(refusal("deadline"));
        }
        if terminate {
            self.stop()?;
        }
        loop {
            let mut status = 0;
            // SAFETY: status is writable and monitor is our direct child.
            let observed = unsafe { libc::waitpid(self.monitor, &mut status, libc::WNOHANG) };
            if observed == self.monitor {
                self.reaped = true;
                match self.cgroup.is_empty() {
                    Ok(true) => {}
                    result => {
                        let _ = self.cgroup.kill();
                        return Err(result.err().unwrap_or(refusal("cgroup-not-empty")));
                    }
                }
                let exit = self.shared.get().exit.load(Ordering::Acquire);
                if exit == i32::MIN {
                    return Err(refusal("child-status"));
                }
                return decode_exit(exit);
            }
            if observed < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(refusal("wait"));
            }
            if Instant::now() >= until {
                self.stop()?;
                return Err(refusal("deadline"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.stop();
        let monitor = self.monitor;
        let reaper = std::thread::Builder::new()
            .name("cage-reaper".into())
            .spawn(move || reap(monitor));
        if reaper.is_err() {
            reap(monitor);
        }
    }
}
fn reap(monitor: i32) {
    loop {
        // SAFETY: this helper owns reaping the direct child and ignores its nonauthorizing status.
        if unsafe { libc::waitpid(monitor, std::ptr::null_mut(), 0) } >= 0 {
            break;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break;
        }
    }
}
fn decode_exit(status: i32) -> Result<ExitStatus> {
    if libc::WIFEXITED(status) {
        Ok(ExitStatus::Code(libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        Ok(ExitStatus::Signal(libc::WTERMSIG(status)))
    } else {
        Err(refusal("child-status"))
    }
}
pub(super) fn pin(fd: &OwnedFd, expected: Digest32) -> Result<()> {
    let bytes = image::validate(fd)?;
    if Digest32::sha256(&bytes) != expected {
        return Err(refusal("image-digest"));
    }
    Ok(())
}
fn pidfd(pid: i32) -> Result<OwnedFd> {
    // SAFETY: pidfd_open returns a new owned descriptor or a negative error.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(refusal("pidfd"));
    }
    // SAFETY: the returned descriptor has not been wrapped or closed elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn is_alive(fd: &OwnedFd) -> Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the array has one initialized pollfd and timeout zero cannot block.
    let observed = unsafe { libc::poll(&mut p, 1, 0) };
    if observed < 0 || p.revents & libc::POLLNVAL != 0 {
        return Err(refusal("pidfd-observation"));
    }
    Ok(observed == 0)
}
fn alive(fd: &OwnedFd) -> Result<()> {
    if is_alive(fd)? {
        Ok(())
    } else {
        Err(refusal("parent-exited"))
    }
}
fn parent_death(parent: &OwnedFd) -> Result<()> {
    // SAFETY: the scalar setting affects only this trusted child.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(refusal("parent-death"));
    }
    alive(parent)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn start<R: BootRecorder + ?Sized>(
    executable: StaticImage,
    profile: ProfileKind,
    limits: ResourceLimits,
    mapping: UserMapping,
    cgroup: DelegatedCgroup,
    channels: GuestChannels,
    directory: Option<&WorkDirectory>,
    argv: Vec<OsString>,
    timeout: Duration,
    recorder: &mut R,
) -> Result<RunningCage> {
    limits.validate()?;
    if timeout.is_zero() {
        return Err(refusal("deadline"));
    }
    let started = Instant::now();
    let until = started.checked_add(timeout).ok_or(refusal("deadline"))?;
    let abi = LandlockAbi::query()?;
    let baseline = netns::baseline()?;
    validate_channels(&channels, profile)?;
    let bytes = image::validate(&executable._image)?;
    if Digest32::sha256(&bytes) != executable.digest() {
        return Err(refusal("image-digest"));
    }
    #[cfg(target_arch = "x86_64")]
    let architecture = Architecture::X86_64;
    #[cfg(target_arch = "aarch64")]
    let architecture = Architecture::Aarch64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(refusal("architecture"));
    let filter = CompiledFilter::compile(profile, architecture)?;
    let shared = Shared::new()?;
    let parent = pidfd(std::process::id() as i32)?;
    let mask = SignalMask::block()?;
    // SAFETY: libc's fork runs its allocator atfork hooks; inherited handlers remain blocked in the child.
    let monitor = unsafe { libc::fork() };
    if monitor == 0 {
        monitor_child(
            &shared, &baseline, &parent, &bytes, &argv, &channels, directory, abi, profile, limits,
            &filter,
        );
    }
    drop(mask);
    if monitor < 0 {
        return Err(refusal("fork"));
    }
    let mut runtime = Runtime {
        monitor,
        payload_fd: None,
        cgroup,
        shared,
        started,
        limits,
        reaped: false,
    };
    runtime.shared.wait(1, monitor, until)?;
    netns::map_child(monitor as u32, mapping)?;
    runtime.shared.permit(1);
    runtime.shared.wait(2, monitor, until)?;
    let pid = runtime.shared.get().payload.load(Ordering::Acquire);
    if pid <= 1 {
        return Err(refusal("child-pid"));
    }
    runtime.payload_fd = Some(pidfd(pid)?);
    runtime.cgroup.attach_setup(pid as u32, limits)?;
    runtime.shared.permit(2);
    runtime.shared.wait(3, monitor, until)?;
    let cgroup_facts = runtime.cgroup.finish_attach(pid as u32, limits)?;
    runtime.shared.permit(3);
    runtime.shared.wait(4, monitor, until)?;
    alive(runtime.payload_fd.as_ref().ok_or(refusal("pidfd"))?)?;
    // SAFETY: stage 4 is published only after the child initialized immutable setup facts.
    let observed = unsafe {
        (*runtime.shared.get().facts.get())
            .assume_init_ref()
            .clone()
    };
    let facts = BootFacts {
        kernel_release: kernel_release()?,
        executable_sha256: executable.digest(),
        profile,
        landlock: observed.landlock,
        seccomp: observed.seccomp,
        namespaces: observed.namespaces,
        cgroup: cgroup_facts,
        inherited_descriptors: 5,
        capabilities_cleared: true,
    };
    let remaining = until
        .checked_duration_since(Instant::now())
        .ok_or(refusal("setup-timeout"))?;
    let watchdog = BootDeadline::new(runtime.cgroup.duplicate()?, remaining)?;
    let boot_receipt = recorder.append_boot(&facts)?;
    drop(watchdog);
    if boot_receipt.sequence == 0 || Instant::now() >= until {
        return Err(refusal("boot-record"));
    }
    alive(runtime.payload_fd.as_ref().ok_or(refusal("pidfd"))?)?;
    runtime.shared.permit(4);
    Ok(RunningCage {
        pid: pid as u32,
        facts,
        boot_receipt,
        runtime,
    })
}

#[allow(clippy::too_many_arguments)]
fn monitor_child(
    shared: &Shared,
    baseline: &NamespaceBaseline,
    parent: &OwnedFd,
    bytes: &[u8],
    argv: &[OsString],
    channels: &GuestChannels,
    directory: Option<&WorkDirectory>,
    abi: LandlockAbi,
    profile: ProfileKind,
    limits: ResourceLimits,
    filter: &CompiledFilter,
) -> ! {
    if let Err(e) = parent_death(parent).and_then(|_| netns::prepare_namespaces(baseline)) {
        shared.fail(e);
    }
    shared.get().stage.store(1, Ordering::Release);
    shared.child_wait(1);
    if let Err(e) = parent_death(parent) {
        shared.fail(e);
    }
    let own = match pidfd(std::process::id() as i32) {
        Ok(fd) => fd,
        Err(e) => shared.fail(e),
    };
    // SAFETY: the intermediate is a trusted, single-threaded fork child with allocator state repaired by libc.
    let child = unsafe { libc::fork() };
    if child < 0 {
        shared.fail(refusal("fork"));
    }
    if child == 0 {
        if let Err(e) = parent_death(&own) {
            shared.fail(e);
        }
        shared.child_wait(2);
        match payload_setup(
            baseline, &own, bytes, argv, channels, directory, abi, profile, limits, filter, shared,
        ) {
            Ok(prepared) => {
                shared.child_wait(4);
                // SAFETY: preparation is finalized; all limits, restrictions and the boot receipt precede this release.
                unsafe { prepared.enter() }
            }
            Err(e) => shared.fail(e),
        }
    }
    shared.get().payload.store(child, Ordering::Release);
    shared.get().stage.store(2, Ordering::Release);
    let mut status = 0;
    loop {
        // SAFETY: child is this monitor's direct child and status is writable.
        let n = unsafe { libc::waitpid(child, &mut status, 0) };
        if n == child {
            shared.get().exit.store(status, Ordering::Release);
            break;
        }
        if n < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            shared.fail(refusal("wait"));
        }
    }
    // SAFETY: no inherited Rust cleanup runs in the intermediate process.
    unsafe { libc::_exit(0) }
}

#[allow(clippy::too_many_arguments)]
fn payload_setup(
    baseline: &NamespaceBaseline,
    parent: &OwnedFd,
    bytes: &[u8],
    argv: &[OsString],
    channels: &GuestChannels,
    directory: Option<&WorkDirectory>,
    abi: LandlockAbi,
    _profile: ProfileKind,
    limits: ResourceLimits,
    filter: &CompiledFilter,
    shared: &Shared,
) -> Result<image::Prepared> {
    let namespaces = netns::child_setup(baseline)?;
    parent_death(parent)?;
    // SAFETY: changing this child's personality clears READ_IMPLIES_EXEC before any mapping permissions are set.
    let personality = unsafe { libc::personality(!0u64 as libc::c_ulong) };
    if personality < 0
        || unsafe {
            libc::personality(
                (personality as libc::c_ulong) & !(libc::READ_IMPLIES_EXEC as libc::c_ulong),
            )
        } < 0
    {
        return Err(refusal("personality"));
    }
    crate::seccomp::clear_thread_bindings()?;
    let view = directory.map(WorkDirectory::isolated_view).transpose()?;
    let directory = view.as_ref();
    let mut prepared = image::prepare(bytes, argv)?;
    if let Some(dir) = directory {
        // SAFETY: this pinned descriptor names the only permitted work directory.
        if unsafe { libc::fchdir(dir.descriptor().as_raw_fd()) } != 0 {
            return Err(refusal("work-directory"));
        }
        // SAFETY: cwd is the private clone root; this child still holds only namespace-local setup capabilities.
        if unsafe { libc::chroot(c".".as_ptr()) } != 0 {
            return Err(refusal("work-directory"));
        }
    } else {
        // SAFETY: a terminated root path is valid, and no host-relative cwd is carried into guest entry.
        if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
            return Err(refusal("work-directory"));
        }
    }
    clear_capabilities()?;
    let landlock = match directory {
        Some(dir) => landlock::restrict_disposable(abi, dir)?,
        None => landlock::restrict(abi, &CageProfile::Auma { limits })?,
    };
    drop(view);
    prepared.finalize()?;
    remap_channels(channels)?;
    shared.get().stage.store(3, Ordering::Release);
    shared.child_wait(3);
    let seccomp = filter.install()?;
    // SAFETY: parent reads this slot only after the release-published ready stage.
    unsafe {
        (*shared.get().facts.get()).write(SetupFacts {
            landlock,
            seccomp,
            namespaces,
        });
    }
    shared.get().stage.store(4, Ordering::Release);
    Ok(prepared)
}
fn kernel_release() -> Result<String> {
    let mut name = MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uname initializes the complete output structure on success.
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return Err(refusal("kernel"));
    }
    // SAFETY: successful uname returns a terminated release string.
    Ok(unsafe { CStr::from_ptr((*name.as_ptr()).release.as_ptr()) }
        .to_str()
        .map_err(|_| refusal("kernel"))?
        .into())
}
fn validate_channels(c: &GuestChannels, profile: ProfileKind) -> Result<()> {
    for fd in &c.stdio {
        pipe_or_null(fd)?;
    }
    if profile == ProfileKind::Disposable {
        pipe_or_null(&c.proposals)?;
        pipe_or_null(&c.app_data)?;
        return Ok(());
    }
    for fd in [&c.proposals, &c.app_data] {
        for (option, expected) in [
            (libc::SO_TYPE, libc::SOCK_STREAM),
            (libc::SO_DOMAIN, libc::AF_UNIX),
            (libc::SO_ACCEPTCONN, 0),
        ] {
            let mut value: i32 = -1;
            let mut size = std::mem::size_of::<i32>() as libc::socklen_t;
            // SAFETY: value and size point to initialized buffers of the appropriate sizes.
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&mut value as *mut i32).cast(),
                    &mut size,
                )
            } != 0
                || value != expected
                || size as usize != std::mem::size_of::<i32>()
            {
                return Err(refusal("channels"));
            }
        }
        let mut address = MaybeUninit::<libc::sockaddr_un>::uninit();
        let mut size = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // SAFETY: address has sufficient writable space for an AF_UNIX peer address.
        if unsafe { libc::getpeername(fd.as_raw_fd(), address.as_mut_ptr().cast(), &mut size) } != 0
        {
            return Err(refusal("channels"));
        }
    }
    Ok(())
}
fn pipe_or_null(fd: &OwnedFd) -> Result<()> {
    let stat = rustix::fs::fstat(fd).map_err(|_| refusal("stdio"))?;
    if stat.st_mode & libc::S_IFMT == libc::S_IFIFO
        || (stat.st_mode & libc::S_IFMT == libc::S_IFCHR
            && stat.st_rdev == rustix::fs::makedev(1, 3))
    {
        Ok(())
    } else {
        Err(refusal("stdio"))
    }
}
pub(super) fn null_channels() -> Result<GuestChannels> {
    let open = || {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map(OwnedFd::from)
            .map_err(|_| refusal("stdio"))
    };
    Ok(GuestChannels {
        proposals: open()?,
        app_data: open()?,
        stdio: [open()?, open()?, open()?],
    })
}
fn remap_channels(c: &GuestChannels) -> Result<()> {
    let refs = [
        &c.stdio[0],
        &c.stdio[1],
        &c.stdio[2],
        &c.proposals,
        &c.app_data,
    ];
    let mut copies = [-1i32; 5];
    for (index, fd) in refs.into_iter().enumerate() {
        // SAFETY: duplication retains no inherited 0..4 collision.
        copies[index] = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
        if copies[index] < 0 {
            return Err(refusal("descriptors"));
        }
    }
    for (target, fd) in copies.iter().enumerate() {
        // SAFETY: duplicates avoid every 0..4 source collision and refer to validated channel descriptors.
        if unsafe { libc::dup2(*fd, target as i32) } != target as i32 {
            return Err(refusal("descriptors"));
        }
    }
    // SAFETY: the child retains exactly 0..4; no OwnedFd destructor executes after this closure.
    if unsafe { libc::syscall(libc::SYS_close_range, 5u32, u32::MAX, 0u32) } != 0 {
        return Err(refusal("descriptors"));
    }
    Ok(())
}
fn clear_capabilities() -> Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // SAFETY: these scalar controls remove privilege from this child only.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(refusal("capabilities"));
    }
    for cap in 0..64 {
        // SAFETY: dropping bounding capabilities never widens privilege.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
        {
            return Err(refusal("capabilities"));
        }
    }
    // NOROOT, NO_SETUID_FIXUP, KEEP_CAPS-off, NO_CAP_AMBIENT_RAISE, all locked.
    if unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0xef, 0, 0, 0) } != 0 {
        return Err(refusal("capabilities"));
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut caps = [Caps {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset/capget receive the version-three two-word capability layout.
    if unsafe { libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) } != 0
        || unsafe { libc::syscall(libc::SYS_capget, &header, caps.as_mut_ptr()) } != 0
        || caps
            .iter()
            .any(|c| c.effective != 0 || c.permitted != 0 || c.inheritable != 0)
    {
        return Err(refusal("capabilities"));
    }
    for cap in 0..64 {
        // SAFETY: PR_CAPBSET_READ queries one scalar capability bit.
        let bit = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if bit > 0
            || (bit < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL))
        {
            return Err(refusal("capabilities"));
        }
    }
    Ok(())
}

struct BootDeadline {
    cancel: std::sync::mpsc::Sender<()>,
    handle: Option<std::thread::JoinHandle<()>>,
}
impl BootDeadline {
    fn new(group: DelegatedCgroup, remaining: Duration) -> Result<Self> {
        let (cancel, receive) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("cage-boot-deadline".into())
            .spawn(move || {
                if receive.recv_timeout(remaining).is_err() {
                    let _ = group.kill();
                }
            })
            .map_err(|_| refusal("setup-watchdog"))?;
        Ok(Self {
            cancel,
            handle: Some(handle),
        })
    }
}
impl Drop for BootDeadline {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct SignalMask(u64);
impl SignalMask {
    fn block() -> Result<Self> {
        let all = u64::MAX;
        let mut previous = 0u64;
        // SAFETY: Linux's kernel signal set is eight bytes, including libc-reserved catchable signals.
        if unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &all,
                &mut previous,
                8usize,
            )
        } != 0
        {
            return Err(refusal("signal-mask"));
        }
        Ok(Self(previous))
    }
}
impl Drop for SignalMask {
    fn drop(&mut self) {
        // SAFETY: only the parent returns here; children retain the full block until the terminal handoff.
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &self.0,
                std::ptr::null_mut::<u64>(),
                8usize,
            );
        }
    }
}
