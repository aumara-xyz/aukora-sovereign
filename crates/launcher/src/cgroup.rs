// SPDX-License-Identifier: AGPL-3.0-or-later
//! Resource limit contracts. No requested limit is reported as a kernel observation.

use std::num::{NonZeroU32, NonZeroU64};

use crate::cage::Result;

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
    /// Reject limits that cannot retain the five fixed inherited descriptors.
    pub fn validate(&self) -> Result<()> {
        if self.open_files.get() < 5 {
            return Err(crate::cage::refusal("limits"));
        }
        Ok(())
    }
}

/// Kernel read-back after attachment, kept separately from requested limits.
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
    /// Row 26: verify a cgroup-v2 directory, no symlink traversal, required enabled
    /// controllers and an empty delegated leaf. Merely opening a folder is not enough.
    pub fn from_directory(_directory: std::os::fd::OwnedFd) -> Result<Self> {
        todo!("row 26")
    }

    /// Row 26: apply every limit before child release and read it back. A partial
    /// write, unavailable controller or failed membership check aborts the launch.
    pub(crate) fn attach(&mut self, _pid: u32, _limits: ResourceLimits) -> Result<CgroupFacts> {
        todo!("row 26")
    }
}
