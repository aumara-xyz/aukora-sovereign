// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pinned cgroup-v2 leaves and kernel resource read-back.

use std::num::{NonZeroU32, NonZeroU64};

use crate::cage::{refusal, Result};

/// Positive cgroup-v2 and per-process resource ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Total bytes for the cage; the backend also disables swap.
    pub memory_bytes: NonZeroU64,
    /// Maximum tasks, including the cage's initial process.
    pub tasks: NonZeroU32,
    /// CPU time quota in microseconds.
    pub cpu_quota_us: NonZeroU64,
    /// CPU accounting period in microseconds.
    pub cpu_period_us: NonZeroU64,
    /// Per-process descriptor ceiling; FD 0 through FD 4 must fit.
    pub open_files: NonZeroU32,
    /// File-size ceiling; Auma has no writable file descriptors regardless of this.
    pub file_bytes: NonZeroU64,
}

impl ResourceLimits {
    /// Reject limits the kernel cannot install or that lose a fixed descriptor.
    pub fn validate(&self) -> Result<()> {
        if self.open_files.get() < 5
            || self.open_files.get() > i32::MAX as u32
            || self.cpu_quota_us.get() < 1_000
            || !(1_000..=1_000_000).contains(&self.cpu_period_us.get())
            || self.memory_bytes.get() > i64::MAX as u64
            || self.file_bytes.get() > i64::MAX as u64
        {
            return Err(refusal("limits"));
        }
        Ok(())
    }
}

/// Read-back after attachment, distinct from the requested limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CgroupFacts {
    /// Unified cgroup version observed from the mounted filesystem.
    pub version: u32,
    /// Installed and read-back resource ceilings.
    pub limits: ResourceLimits,
    /// Whether the kernel read-back reports a zero swap allowance.
    pub swap_disabled: bool,
    /// Whether the initial child is present in this cgroup.
    pub child_attached: bool,
}

/// A pinned delegated directory, never a path received from the guest.
#[cfg(unix)]
#[derive(Debug)]
pub struct DelegatedCgroup {
    _directory: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl DelegatedCgroup {
    /// Verify cgroup-v2, enabled resource controllers and an empty domain leaf.
    pub fn from_directory(directory: std::os::fd::OwnedFd) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let group = Self {
                _directory: directory,
            };
            group.verify_leaf(true)?;
            Ok(group)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            Err(refusal("unsupported-platform"))
        }
    }

    /// Install and read back every resource ceiling before attaching the child.
    pub(crate) fn attach(&mut self, pid: u32, limits: ResourceLimits) -> Result<CgroupFacts> {
        #[cfg(target_os = "linux")]
        {
            self.attach_setup(pid, limits)?;
            self.finish_attach(pid, limits)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (pid, limits);
            Err(refusal("unsupported-platform"))
        }
    }
}

#[cfg(target_os = "linux")]
impl DelegatedCgroup {
    /// Install cgroup limits and charge setup allocations to the payload leaf.
    /// Process descriptor limits are delayed until setup descriptors are closed.
    pub(crate) fn attach_setup(&mut self, pid: u32, limits: ResourceLimits) -> Result<()> {
        self.verify_leaf(true)?;
        limits.validate()?;
        if pid <= 1 || pid == std::process::id() {
            return Err(refusal("cgroup-child"));
        }
        self.write("memory.max", &limits.memory_bytes.to_string())?;
        self.write("memory.swap.max", "0")?;
        self.write("memory.oom.group", "1")?;
        self.write("pids.max", &limits.tasks.to_string())?;
        self.write(
            "cpu.max",
            &format!("{} {}", limits.cpu_quota_us, limits.cpu_period_us),
        )?;
        self.read_limits(limits)?;
        self.write("cgroup.procs", &pid.to_string())?;
        if !self.membership(pid)? {
            return Err(refusal("cgroup-membership"));
        }
        Ok(())
    }

    /// Install process ceilings only after the stopped child closes setup FDs.
    pub(crate) fn finish_attach(&self, pid: u32, limits: ResourceLimits) -> Result<CgroupFacts> {
        limits.validate()?;
        self.verify_leaf(false)?;
        self.read_limits(limits)?;
        if pid <= 1 || pid == std::process::id() || !self.membership(pid)? {
            return Err(refusal("cgroup-membership"));
        }
        install_child_limits(pid, limits)?;
        self.sample(pid, limits)
    }

    fn membership(&self, pid: u32) -> Result<bool> {
        let membership = self.read("cgroup.procs")?;
        let mut found = false;
        for entry in membership.split_ascii_whitespace() {
            let present: u32 = entry.parse().map_err(|_| refusal("cgroup-readback"))?;
            found |= present == pid;
        }
        Ok(found)
    }

    fn verify_leaf(&self, empty: bool) -> Result<()> {
        use rustix::fs::{fstat, fstatfs, Dir, FileType};
        let stat = fstat(&self._directory).map_err(|_| refusal("cgroup-stat"))?;
        let filesystem = fstatfs(&self._directory).map_err(|_| refusal("cgroup-stat"))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || filesystem.f_type as u64 != 0x6367_7270
            || self.read("cgroup.type")?.trim() != "domain"
            || !self.read("cgroup.subtree_control")?.trim().is_empty()
        {
            return Err(refusal("cgroup-not-v2-leaf"));
        }
        let controllers = self.read("cgroup.controllers")?;
        for required in ["memory", "pids", "cpu"] {
            if !controllers
                .split_ascii_whitespace()
                .any(|name| name == required)
            {
                return Err(refusal("cgroup-controller"));
            }
        }
        let mut entries = Dir::read_from(&self._directory).map_err(|_| refusal("cgroup-read"))?;
        for entry in &mut entries {
            let entry = entry.map_err(|_| refusal("cgroup-read"))?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." && entry.file_type() == FileType::Directory {
                return Err(refusal("cgroup-not-v2-leaf"));
            }
        }
        if empty && !self.read("cgroup.procs")?.trim().is_empty() {
            return Err(refusal("cgroup-not-empty"));
        }
        Ok(())
    }

    fn control(&self, name: &str, write: bool) -> Result<std::os::fd::OwnedFd> {
        use rustix::fs::{openat, Mode, OFlags};
        let access = if write {
            OFlags::WRONLY
        } else {
            OFlags::RDONLY
        };
        openat(
            &self._directory,
            name,
            access | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| refusal("cgroup-open"))
    }

    fn read(&self, name: &str) -> Result<String> {
        use std::io::Read;
        let mut bytes = String::new();
        std::fs::File::from(self.control(name, false)?)
            .take(65_537)
            .read_to_string(&mut bytes)
            .map_err(|_| refusal("cgroup-read"))?;
        if bytes.len() > 65_536 {
            return Err(refusal("cgroup-read"));
        }
        Ok(bytes)
    }

    fn write(&self, name: &str, value: &str) -> Result<()> {
        use std::io::Write;
        let bytes = value.as_bytes();
        let written = std::fs::File::from(self.control(name, true)?)
            .write(bytes)
            .map_err(|_| refusal("cgroup-write"))?;
        if written != bytes.len() {
            return Err(refusal("cgroup-write"));
        }
        Ok(())
    }

    fn number(&self, name: &str) -> Result<u64> {
        self.read(name)?
            .trim()
            .parse()
            .map_err(|_| refusal("cgroup-readback"))
    }

    fn read_limits(&self, requested: ResourceLimits) -> Result<ResourceLimits> {
        let cpu = self.read("cpu.max")?;
        let mut values = cpu.split_ascii_whitespace();
        let quota = values
            .next()
            .and_then(|v| v.parse().ok())
            .and_then(NonZeroU64::new);
        let period = values
            .next()
            .and_then(|v| v.parse().ok())
            .and_then(NonZeroU64::new);
        let observed = ResourceLimits {
            memory_bytes: NonZeroU64::new(self.number("memory.max")?)
                .ok_or(refusal("cgroup-readback"))?,
            tasks: u32::try_from(self.number("pids.max")?)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or(refusal("cgroup-readback"))?,
            cpu_quota_us: quota.ok_or(refusal("cgroup-readback"))?,
            cpu_period_us: period.ok_or(refusal("cgroup-readback"))?,
            open_files: requested.open_files,
            file_bytes: requested.file_bytes,
        };
        if observed != requested
            || values.next().is_some()
            || self.number("memory.swap.max")? != 0
            || self.number("memory.oom.group")? != 1
        {
            return Err(refusal("cgroup-readback"));
        }
        Ok(observed)
    }

    /// Read present controller values, child membership and its process limits.
    pub(crate) fn sample(&self, pid: u32, expected: ResourceLimits) -> Result<CgroupFacts> {
        self.verify_leaf(false)?;
        let mut limits = self.read_limits(expected)?;
        let observed = read_process_limits(pid)?;
        if observed
            != (
                u64::from(expected.open_files.get()),
                expected.file_bytes.get(),
                0,
            )
        {
            return Err(refusal("rlimits-readback"));
        }
        limits.open_files =
            NonZeroU32::new(u32::try_from(observed.0).map_err(|_| refusal("rlimits-readback"))?)
                .ok_or(refusal("rlimits-readback"))?;
        limits.file_bytes = NonZeroU64::new(observed.1).ok_or(refusal("rlimits-readback"))?;
        let child_attached = self.membership(pid)?;
        if !child_attached {
            return Err(refusal("cgroup-membership"));
        }
        Ok(CgroupFacts {
            version: 2,
            limits,
            swap_disabled: self.number("memory.swap.max")? == 0,
            child_attached,
        })
    }

    /// Duplicate the pinned group handle without resolving a path again.
    pub(crate) fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            _directory: rustix::io::fcntl_dupfd_cloexec(&self._directory, 5)
                .map_err(|_| refusal("cgroup-duplicate"))?,
        })
    }

    /// Kill all tasks in this leaf through cgroup-v2's atomic recursive operation.
    pub(crate) fn kill(&self) -> Result<()> {
        self.write("cgroup.kill", "1")
    }

    /// Read whether the kernel has removed every task from the leaf.
    pub(crate) fn is_empty(&self) -> Result<bool> {
        let events = self.read("cgroup.events")?;
        for line in events.lines() {
            let mut fields = line.split_ascii_whitespace();
            if fields.next() == Some("populated") {
                return match (fields.next(), fields.next()) {
                    (Some("0"), None) => Ok(true),
                    (Some("1"), None) => Ok(false),
                    _ => Err(refusal("cgroup-readback")),
                };
            }
        }
        Err(refusal("cgroup-readback"))
    }
}

/// Install per-process limits in the clone child before its descriptor closure.
#[cfg(target_os = "linux")]
pub(crate) fn apply_process_limits(limits: ResourceLimits) -> Result<()> {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    limits.validate()?;
    for (resource, ceiling) in [
        (Resource::Nofile, u64::from(limits.open_files.get())),
        (Resource::Fsize, limits.file_bytes.get()),
        (Resource::Core, 0),
    ] {
        let value = Rlimit {
            current: Some(ceiling),
            maximum: Some(ceiling),
        };
        setrlimit(resource, value).map_err(|_| refusal("rlimits"))?;
        if getrlimit(resource) != value {
            return Err(refusal("rlimits-readback"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_child_limits(pid: u32, limits: ResourceLimits) -> Result<()> {
    use rustix::process::{prlimit, Pid, Resource, Rlimit};
    let process = Pid::from_raw(i32::try_from(pid).map_err(|_| refusal("cgroup-child"))?)
        .ok_or(refusal("cgroup-child"))?;
    for (resource, value) in [
        (Resource::Nofile, u64::from(limits.open_files.get())),
        (Resource::Fsize, limits.file_bytes.get()),
        (Resource::Core, 0),
    ] {
        prlimit(
            Some(process),
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(|_| refusal("rlimits"))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_process_limits(pid: u32) -> Result<(u64, u64, u64)> {
    let mut values = [0; 3];
    let pid = i32::try_from(pid).map_err(|_| refusal("cgroup-child"))?;
    for (index, resource) in [libc::RLIMIT_NOFILE, libc::RLIMIT_FSIZE, libc::RLIMIT_CORE]
        .into_iter()
        .enumerate()
    {
        let mut current = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: null new_limit requests observation; old_limit is writable storage.
        if unsafe { libc::prlimit(pid, resource, std::ptr::null(), current.as_mut_ptr()) } != 0 {
            return Err(refusal("rlimits-readback"));
        }
        // SAFETY: a successful prlimit initialized both resource-limit fields.
        let current = unsafe { current.assume_init() };
        if current.rlim_cur != current.rlim_max {
            return Err(refusal("rlimits-readback"));
        }
        values[index] = current.rlim_cur;
    }
    Ok((values[0], values[1], values[2]))
}
