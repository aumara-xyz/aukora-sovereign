use crate::{LaunchPolicy, LaunchResult, OwnedFd, Refusal};
use std::path::Path;
use std::time::Duration;

pub const BOOT_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
pub const BOOT_PROBE_OUTPUT_MAX: usize = 64 * 1024;
pub const BOOT_PROBE_EXECUTABLE: &str = "/opt/sovereign/guest/probe";

#[cfg(any(target_os = "linux", test))]
pub(crate) fn probe_poll_budget(
    deadline: Option<std::time::Instant>,
    maximum_ms: i32,
) -> Result<i32, Refusal> {
    match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(Refusal::new("launcher:probe-timeout"));
            }
            Ok(remaining.as_millis().max(1).min(maximum_ms as u128) as i32)
        }
        None => Ok(maximum_ms),
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn append_probe_output(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Refusal> {
    if output.len().saturating_add(bytes.len()) > BOOT_PROBE_OUTPUT_MAX {
        return Err(Refusal::new("launcher:probe-output-limit"));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootProbeAttack {
    pub name: &'static str,
    pub skip_reason: Option<&'static str>,
}

const fn active(name: &'static str) -> BootProbeAttack {
    BootProbeAttack {
        name,
        skip_reason: None,
    }
}

const fn skipped(name: &'static str, reason: &'static str) -> BootProbeAttack {
    BootProbeAttack {
        name,
        skip_reason: Some(reason),
    }
}

// Only a reviewed source change can remove a skip.
pub const BOOT_PROBE_ATTACKS: [BootProbeAttack; 42] = [
    active("extra-descriptors"),
    active("landlock-root-mkdir"),
    active("landlock-workspace-socket"),
    active("pid-namespace"),
    active("network-namespace"),
    skipped("open-key", "requires-disposable-outside-key"),
    skipped("open-db", "requires-disposable-outside-database"),
    skipped(
        "connect-socket-path",
        "requires-outside-filesystem-listener",
    ),
    skipped("tcp-out", "requires-reachable-outside-listener"),
    skipped("udp-out", "requires-reachable-outside-listener"),
    skipped("tcp-loopback", "requires-host-loopback-listener"),
    skipped("udp-loopback", "requires-host-loopback-listener"),
    skipped("abstract-socket", "requires-host-abstract-listener"),
    skipped("proc-other-pid", "requires-disposable-outside-process"),
    skipped("ptrace", "requires-ptraceable-outside-process"),
    skipped(
        "process-vm-readv",
        "requires-readable-outside-process-address",
    ),
    active("mount"),
    active("unshare-user"),
    active("setns"),
    active("nested-userns"),
    active("io-uring-setup"),
    active("write-git"),
    active("write-past-fsize"),
    active("unlink-supervisor-file"),
    active("write-readonly-profile"),
    active("write-dev-shm"),
    active("write-var-tmp"),
    skipped("symlink-out", "requires-disposable-outside-readable-file"),
    skipped(
        "hardlink-out",
        "requires-disposable-outside-file-on-same-filesystem",
    ),
    skipped("rename-out", "requires-writable-outside-directory"),
    active("socket-inet6"),
    active("socket-packet"),
    active("socket-netlink"),
    active("socket-vsock"),
    skipped("tiocsti", "requires-disposable-controlling-tty"),
    skipped("signal-outside-pid", "requires-disposable-outside-process"),
    skipped(
        "fork-bomb",
        "production-pids-limit-may-exceed-bounded-corpus",
    ),
    skipped(
        "memory-balloon",
        "production-memory-limit-may-exceed-bounded-corpus",
    ),
    active("clock-set"),
    active("open-dev-mem"),
    active("open-dev-kmsg"),
    skipped("setuid-binary", "requires-root-owned-setuid-helper"),
];

pub fn boot_probe_expected_errno(attack: &str) -> Option<i32> {
    match attack {
        "extra-descriptors" => Some(libc::EBADF),
        "write-git" | "write-readonly-profile" => Some(libc::EROFS),
        "write-past-fsize" => Some(libc::EFBIG),
        "landlock-root-mkdir" | "landlock-workspace-socket" => Some(libc::EACCES),
        "write-dev-shm" | "write-var-tmp" | "open-dev-mem" | "open-dev-kmsg" => Some(libc::ENOENT),
        "mount"
        | "unshare-user"
        | "setns"
        | "nested-userns"
        | "io-uring-setup"
        | "unlink-supervisor-file"
        | "socket-inet6"
        | "socket-packet"
        | "socket-netlink"
        | "socket-vsock"
        | "clock-set" => Some(libc::EPERM),
        _ => None,
    }
}

pub fn boot_probe_outcome_refused(attack: &str, allowed: bool, errno: Option<i32>) -> bool {
    !allowed
        && match attack {
            "pid-namespace" | "network-namespace" => errno.is_none(),
            _ => errno.is_some() && errno == boot_probe_expected_errno(attack),
        }
}

/// Samples the supervisor's namespace before launch and preserves the sandbox policy fields.
pub fn boot_probe_policy(
    production: &LaunchPolicy,
    fixture_directory: &Path,
) -> Result<LaunchPolicy, Refusal> {
    boot_probe_policy_from_namespace(
        production,
        fixture_directory,
        Path::new("/proc/self/ns/net"),
    )
}

fn boot_probe_policy_from_namespace(
    production: &LaunchPolicy,
    fixture_directory: &Path,
    namespace: &Path,
) -> Result<LaunchPolicy, Refusal> {
    use std::os::unix::fs::MetadataExt;
    let namespace = std::fs::metadata(namespace)
        .map_err(|_| Refusal::io("launcher:probe-network-namespace"))?;
    if namespace.ino() == 0 {
        return Err(Refusal::new("launcher:probe-network-namespace"));
    }
    let mut policy = production.clone();
    policy.executable = BOOT_PROBE_EXECUTABLE.into();
    policy.argv = [BOOT_PROBE_EXECUTABLE, "--confined", "--boot"]
        .map(Into::into)
        .into();
    policy
        .env
        .retain(|value| !value.to_string_lossy().starts_with("AUKORA_PROBE_"));
    policy.env.extend([
        format!(
            "AUKORA_PROBE_SUPERVISOR_NET_NAMESPACE={}:{}",
            namespace.dev(),
            namespace.ino()
        )
        .into(),
        "AUKORA_PROBE_WORKSPACE=/workspace".into(),
        format!("AUKORA_PROBE_MOUNT_DIR={}", fixture_directory.display()).into(),
        format!(
            "AUKORA_PROBE_STICKY_FILE={}/supervisor-file",
            fixture_directory.display()
        )
        .into(),
        "AUKORA_PROBE_PROFILE_FILE=/workspace/dsh/profiles/web/package.json".into(),
        format!(
            "AUKORA_PROBE_FILE_SIZE_MAX_BYTES={}",
            policy.file_size_max_bytes
        )
        .into(),
    ]);
    Ok(policy)
}

#[derive(Debug)]
pub struct BootProbeExecution {
    pub output: Vec<u8>,
    pub setup: Option<LaunchResult>,
    pub wait_status: Option<i32>,
    pub refusal: Option<Refusal>,
}

/// Runs confined mode only, captures bounded output, and always terminates and reaps its child.
pub fn run_boot_probe(
    policy: &LaunchPolicy,
    fixture_directory: &Path,
    proposal: OwnedFd,
    ui: OwnedFd,
) -> BootProbeExecution {
    #[cfg(target_os = "linux")]
    {
        match boot_probe_policy(policy, fixture_directory) {
            Ok(policy) => crate::linux::run_boot_probe(&policy, fixture_directory, proposal, ui),
            Err(refusal) => BootProbeExecution {
                output: Vec::new(),
                setup: None,
                wait_status: None,
                refusal: Some(refusal),
            },
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy, fixture_directory, proposal, ui);
        BootProbeExecution {
            output: Vec::new(),
            setup: None,
            wait_status: None,
            refusal: Some(Refusal::new("launcher:unsupported-platform")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CgroupPolicy, IdentityPolicy, ReadonlyBind};

    fn production() -> LaunchPolicy {
        LaunchPolicy {
            workspace: "/srv/workspace".into(),
            root: "/srv/root".into(),
            cgroup: CgroupPolicy {
                path: "/sys/fs/cgroup/guest".into(),
                pids_max: 512,
                memory_max: 4_000_000_000,
                cpu_max: "90000 100000".into(),
            },
            identity: IdentityPolicy {
                subordinate_uid: 100001,
                subordinate_gid: 100002,
                allow_development_own_id: false,
            },
            file_size_max_bytes: 1024,
            executable: "/opt/node/bin/node".into(),
            argv: vec!["node".into()],
            env: vec![
                "HOME=/workspace/home".into(),
                "AUKORA_PROBE_DISPOSABLE=1".into(),
                "AUKORA_PROBE_PROFILE_FILE=/bad".into(),
                "AUKORA_PROBE_SUPERVISOR_NET_NAMESPACE=1:1".into(),
            ],
            readonly_binds: vec![ReadonlyBind {
                host: "/srv/bundle".into(),
                guest: "/opt/sovereign".into(),
            }],
            readonly_workspace_files: vec!["dsh/profiles/web/package.json".into()],
        }
    }

    #[test]
    fn antibody_boot_probe_uses_production_policy_without_control_mode() {
        let policy = production();
        let fixture = Path::new("/workspace/.aukora-boot-probe-fresh");
        let namespace = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let probe = boot_probe_policy_from_namespace(&policy, fixture, &namespace).unwrap();
        assert_eq!(probe.workspace, policy.workspace);
        assert_eq!(probe.root, policy.root);
        assert_eq!(probe.cgroup.path, policy.cgroup.path);
        assert_eq!(probe.cgroup.pids_max, policy.cgroup.pids_max);
        assert_eq!(probe.cgroup.memory_max, policy.cgroup.memory_max);
        assert_eq!(probe.cgroup.cpu_max, policy.cgroup.cpu_max);
        assert_eq!(
            probe.identity.subordinate_uid,
            policy.identity.subordinate_uid
        );
        assert_eq!(
            probe.identity.subordinate_gid,
            policy.identity.subordinate_gid
        );
        assert_eq!(
            probe.identity.allow_development_own_id,
            policy.identity.allow_development_own_id
        );
        assert_eq!(probe.file_size_max_bytes, policy.file_size_max_bytes);
        assert_eq!(
            probe.readonly_workspace_files,
            policy.readonly_workspace_files
        );
        assert_eq!(probe.readonly_binds.len(), policy.readonly_binds.len());
        assert_eq!(probe.readonly_binds[0].host, policy.readonly_binds[0].host);
        assert_eq!(
            probe.readonly_binds[0].guest,
            policy.readonly_binds[0].guest
        );
        assert_eq!(
            probe.argv,
            [BOOT_PROBE_EXECUTABLE, "--confined", "--boot"].map(std::ffi::OsString::from)
        );
        assert_eq!(
            probe.executable,
            std::path::Path::new(BOOT_PROBE_EXECUTABLE)
        );
        assert!(probe.env.contains(&"HOME=/workspace/home".into()));
        assert!(!probe.env.contains(&"AUKORA_PROBE_DISPOSABLE=1".into()));
        assert!(!probe.env.contains(&"AUKORA_PROBE_PROFILE_FILE=/bad".into()));
        assert!(probe
            .env
            .contains(&"AUKORA_PROBE_MOUNT_DIR=/workspace/.aukora-boot-probe-fresh".into()));
        assert!(probe.env.contains(
            &"AUKORA_PROBE_STICKY_FILE=/workspace/.aukora-boot-probe-fresh/supervisor-file".into()
        ));
    }

    #[test]
    fn antibody_boot_probe_samples_the_supervisor_namespace_and_replaces_inherited_identity() {
        use std::os::unix::fs::MetadataExt;
        let namespace = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let metadata = std::fs::metadata(&namespace).unwrap();
        let fixture = Path::new("/workspace/.aukora-boot-probe-fresh");
        let probe = boot_probe_policy_from_namespace(&production(), fixture, &namespace).unwrap();
        let identities: Vec<_> = probe
            .env
            .iter()
            .filter(|value| {
                value
                    .to_string_lossy()
                    .starts_with("AUKORA_PROBE_SUPERVISOR_NET_NAMESPACE=")
            })
            .collect();
        assert_eq!(
            identities,
            vec![&std::ffi::OsString::from(format!(
                "AUKORA_PROBE_SUPERVISOR_NET_NAMESPACE={}:{}",
                metadata.dev(),
                metadata.ino()
            ))]
        );
        assert_eq!(
            boot_probe_policy_from_namespace(&production(), fixture, &namespace.join("missing"))
                .unwrap_err()
                .code,
            "launcher:probe-network-namespace"
        );
    }

    #[test]
    fn antibody_boot_probe_skip_inventory_is_explicit_and_complete() {
        assert_eq!(BOOT_PROBE_ATTACKS.len(), 42);
        let mut names: Vec<_> = BOOT_PROBE_ATTACKS
            .iter()
            .map(|attack| attack.name)
            .collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 42);
        let skipped: Vec<_> = BOOT_PROBE_ATTACKS
            .iter()
            .filter_map(|attack| attack.skip_reason.map(|reason| (attack.name, reason)))
            .collect();
        assert_eq!(skipped.len(), 19);
        assert_eq!(skipped[0], ("open-key", "requires-disposable-outside-key"));
        assert_eq!(
            skipped[18],
            ("setuid-binary", "requires-root-owned-setuid-helper")
        );
        assert!(skipped.iter().all(|(_, reason)| !reason.is_empty()));
    }

    #[test]
    fn antibody_boot_probe_independently_checks_landlock_and_namespaces() {
        for attack in [
            "landlock-root-mkdir",
            "landlock-workspace-socket",
            "pid-namespace",
            "network-namespace",
        ] {
            assert!(BOOT_PROBE_ATTACKS
                .iter()
                .any(|entry| entry.name == attack && entry.skip_reason.is_none()));
            let expected = match attack {
                "landlock-root-mkdir" | "landlock-workspace-socket" => Some(libc::EACCES),
                _ => None,
            };
            assert_eq!(boot_probe_expected_errno(attack), expected);
            assert!(boot_probe_outcome_refused(attack, false, expected));
            assert!(!boot_probe_outcome_refused(attack, true, None));
            assert!(!boot_probe_outcome_refused(
                attack,
                false,
                Some(libc::EPERM)
            ));
        }
        assert!(!boot_probe_outcome_refused(
            "landlock-root-mkdir",
            false,
            None
        ));
        assert!(!boot_probe_outcome_refused("unknown", false, None));
    }

    #[test]
    fn antibody_boot_probe_budget_covers_setup_and_execution() {
        let expired = std::time::Instant::now() - Duration::from_millis(1);
        assert_eq!(
            probe_poll_budget(Some(expired), 15_000).unwrap_err().code,
            "launcher:probe-timeout"
        );
        let imminent = std::time::Instant::now() + Duration::from_millis(3);
        assert!((1..=3).contains(&probe_poll_budget(Some(imminent), 15_000).unwrap()));
        assert_eq!(probe_poll_budget(None, 15_000).unwrap(), 15_000);
    }

    #[test]
    fn antibody_boot_probe_output_cannot_exceed_cap() {
        let mut bytes = vec![0; BOOT_PROBE_OUTPUT_MAX - 1];
        append_probe_output(&mut bytes, &[1]).unwrap();
        assert_eq!(
            append_probe_output(&mut bytes, &[2]).unwrap_err().code,
            "launcher:probe-output-limit"
        );
        assert_eq!(bytes.len(), BOOT_PROBE_OUTPUT_MAX);
        assert_eq!(bytes.last(), Some(&1));
    }
}
