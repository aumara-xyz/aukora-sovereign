//! Linux guest setup. A successful launch reports setup facts; `wait` observes guest exit.

use std::ffi::OsString;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(windows)]
use std::os::windows::io::OwnedHandle as OwnedFd;
#[cfg(not(any(unix, windows)))]
pub struct OwnedFd;
use std::path::PathBuf;

mod boot_probe;
#[cfg(target_os = "linux")]
mod linux;
pub use boot_probe::*;
mod requirements;
#[cfg(any(target_os = "linux", all(test, unix)))]
mod resources;
#[cfg(target_os = "linux")]
mod seccomp;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code} (errno {errno:?})")]
pub struct Refusal {
    pub code: &'static str,
    pub errno: Option<i32>,
}

impl Refusal {
    pub const fn new(code: &'static str) -> Self {
        Self { code, errno: None }
    }

    pub fn io(code: &'static str) -> Self {
        Self {
            code,
            errno: std::io::Error::last_os_error().raw_os_error(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdentityPolicy {
    pub subordinate_uid: u32,
    pub subordinate_gid: u32,
    pub allow_development_own_id: bool,
}

#[derive(Debug, Clone)]
pub struct CgroupPolicy {
    /// An existing, empty cgroup in the supervisor's delegated v2 subtree.
    pub path: PathBuf,
    pub pids_max: u64,
    pub memory_max: u64,
    /// Two positive decimal integers: quota and period, in microseconds.
    pub cpu_max: String,
}

#[derive(Debug, Clone)]
pub struct ReadonlyBind {
    /// Existing host directory whose path components contain no symlinks.
    pub host: PathBuf,
    /// Absolute normalized guest path strictly beneath `/opt`.
    pub guest: PathBuf,
}

pub const DEFAULT_FILE_SIZE_MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct LaunchPolicy {
    /// Existing directory accessible to the mapped guest uid; `.git` must be a directory.
    pub workspace: PathBuf,
    /// Existing empty directory owned by the caller, outside the workspace.
    pub root: PathBuf,
    pub cgroup: CgroupPolicy,
    pub identity: IdentityPolicy,
    /// Guest hard and soft RLIMIT_FSIZE; the supervisor is unaffected.
    pub file_size_max_bytes: u64,
    /// Absolute path as seen after pivot, beneath /usr or /workspace, or strictly inside a read-only bind.
    pub executable: PathBuf,
    /// Includes argv[0]. Environment entries are explicit NAME=value strings.
    pub argv: Vec<OsString>,
    pub env: Vec<OsString>,
    /// Read-only executable directory trees mounted beneath `/opt` in the guest.
    pub readonly_binds: Vec<ReadonlyBind>,
    /// Normalized workspace-relative regular files owned by the supervisor, mounted read-only.
    pub readonly_workspace_files: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct LaunchResult {
    pub pid: i32,
    pub kernel_release: String,
    pub landlock_abi: i32,
    pub seccomp_filter_hash: String,
    pub cgroup_path: PathBuf,
    pub development_own_id: bool,
}

impl LaunchResult {
    /// Returns the wait status. This must be called to reap the guest.
    pub fn wait(self) -> Result<i32, Refusal> {
        #[cfg(target_os = "linux")]
        {
            linux::wait(self.pid)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Refusal::new("launcher:unsupported-platform"))
        }
    }
}

/// Consumes a STREAM proposal socketpair end (length-prefixed frames, CONTRACTS C4), a STREAM listener, and three stdio descriptors.
/// Setup occurs in one child. Call from a supervisor thread that stays alive for its lifetime.
pub fn launch(
    policy: &LaunchPolicy,
    proposal: OwnedFd,
    ui: OwnedFd,
    stdio: [OwnedFd; 3],
) -> Result<LaunchResult, Refusal> {
    #[cfg(target_os = "linux")]
    {
        linux::launch(policy, proposal, ui, stdio)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy, proposal, ui, stdio);
        Err(Refusal::new("launcher:unsupported-platform"))
    }
}

/// Hash of the filter installed by both agent and boot probe launches.
pub fn seccomp_filter_hash() -> Result<String, Refusal> {
    #[cfg(target_os = "linux")]
    {
        seccomp::build().map(|filter| seccomp::hash(&filter))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Refusal::new("launcher:unsupported-platform"))
    }
}

#[cfg(all(test, unix, not(target_os = "linux")))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::net::UnixStream;

    #[test]
    fn unsupported_platform_fails_closed() {
        let (proposal, ui) = UnixStream::pair().unwrap();
        let policy = LaunchPolicy {
            workspace: "/workspace".into(),
            root: "/root".into(),
            cgroup: CgroupPolicy {
                path: "/sys/fs/cgroup/test".into(),
                pids_max: 1,
                memory_max: 1,
                cpu_max: "1 1".into(),
            },
            identity: IdentityPolicy {
                subordinate_uid: 1,
                subordinate_gid: 1,
                allow_development_own_id: false,
            },
            file_size_max_bytes: DEFAULT_FILE_SIZE_MAX_BYTES,
            executable: "/usr/bin/guest".into(),
            argv: vec!["guest".into()],
            env: vec![],
            readonly_binds: vec![],
            readonly_workspace_files: vec![],
        };
        let stdio = std::array::from_fn(|_| OwnedFd::from(File::open("/dev/null").unwrap()));
        let error = launch(&policy, proposal.into(), ui.into(), stdio).unwrap_err();
        assert_eq!(error.code, "launcher:unsupported-platform");
    }
}
