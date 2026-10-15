//! Bounded hostile-guest probes. Fixtures and control privileges are in PROBE.md.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Confined,
    Control,
}

const ATTACKS: &[&str] = &[
    "extra-descriptors",
    "landlock-root-mkdir",
    "landlock-workspace-socket",
    "pid-namespace",
    "network-namespace",
    "open-key",
    "open-db",
    "connect-socket-path",
    "tcp-out",
    "udp-out",
    "tcp-loopback",
    "udp-loopback",
    "abstract-socket",
    "proc-other-pid",
    "ptrace",
    "process-vm-readv",
    "mount",
    "unshare-user",
    "setns",
    "nested-userns",
    "io-uring-setup",
    "write-git",
    "write-past-fsize",
    "unlink-supervisor-file",
    "write-readonly-profile",
    "write-dev-shm",
    "write-var-tmp",
    "symlink-out",
    "hardlink-out",
    "rename-out",
    "socket-inet6",
    "socket-packet",
    "socket-netlink",
    "socket-vsock",
    "tiocsti",
    "signal-outside-pid",
    "fork-bomb",
    "memory-balloon",
    "clock-set",
    "open-dev-mem",
    "open-dev-kmsg",
    "setuid-binary",
];

fn boot_line(attack: &str, outcome: Option<Outcome>, reason: Option<&str>) -> String {
    let (result, reason) = if let Some(outcome) = outcome {
        if outcome.inconclusive {
            ("inconclusive", Some("launcher:probe-observation-invalid"))
        } else if outcome.allowed {
            ("allowed", None)
        } else if launcher::boot_probe_outcome_refused(attack, outcome.allowed, outcome.errno) {
            ("refused", None)
        } else {
            ("inconclusive", Some("launcher:probe-unexpected-errno"))
        }
    } else if reason.is_some_and(|value| value.starts_with("launcher:")) {
        ("inconclusive", reason)
    } else {
        ("skipped", reason)
    };
    let errno = outcome
        .and_then(|value| value.errno)
        .map_or_else(|| "null".to_owned(), |value| value.to_string());
    let reason = reason.map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""));
    format!(
        "{{\"attack\":\"{attack}\",\"errno\":{errno},\"reason\":{reason},\"result\":\"{result}\"}}"
    )
}

#[cfg(any(target_os = "linux", test))]
fn boot_fixture(
    attack: &str,
    workspace: &std::path::Path,
    mount_dir: &std::path::Path,
    sticky_file: &std::path::Path,
    profile_file: &std::path::Path,
) -> Result<(), &'static str> {
    let directory = |path: &std::path::Path| {
        std::fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.is_symlink())
    };
    let regular = |path: &std::path::Path| {
        std::fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.is_symlink())
    };
    let absent = |path: &std::path::Path| matches!(std::fs::symlink_metadata(path), Err(error) if error.raw_os_error() == Some(libc::ENOENT));
    let valid = match attack {
        "mount" => directory(mount_dir),
        "write-git" => directory(&workspace.join(".git")),
        "write-past-fsize" => directory(mount_dir),
        "unlink-supervisor-file" => regular(sticky_file),
        "write-readonly-profile" => regular(profile_file),
        _ => true,
    };
    if !valid {
        return Err("launcher:probe-fixture-missing");
    }
    let fresh = match attack {
        "write-git" => absent(&workspace.join(".git/.aukora-boot-probe-write")),
        "write-past-fsize" => absent(&mount_dir.join("file-size")),
        _ => true,
    };
    if !fresh {
        return Err("launcher:probe-fixture-collision");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Outcome {
    allowed: bool,
    errno: Option<i32>,
    inconclusive: bool,
}

impl Outcome {
    fn from_result(result: Result<(), i32>) -> Self {
        match result {
            Ok(()) => Self {
                allowed: true,
                errno: None,
                inconclusive: false,
            },
            Err(errno) => Self {
                allowed: false,
                errno: Some(errno),
                inconclusive: false,
            },
        }
    }

    fn line(self, attack: &str) -> String {
        let errno = self
            .errno
            .map_or_else(|| "null".to_owned(), |e| e.to_string());
        let result = if self.inconclusive {
            "inconclusive"
        } else if self.allowed {
            "allowed"
        } else {
            "refused"
        };
        format!("{{\"attack\":\"{attack}\",\"errno\":{errno},\"result\":\"{result}\"}}")
    }
}

#[cfg(any(target_os = "linux", test))]
fn pid_namespace_outcome(pid: u32) -> Outcome {
    Outcome {
        allowed: pid != 1,
        errno: None,
        inconclusive: false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn network_namespace_outcome(
    contents: &str,
    supervisor_namespace: Option<&str>,
    own_namespace: Option<(u64, u64)>,
) -> Outcome {
    let identity = |value: &str| {
        let (device, inode) = value.split_once(':')?;
        let number = |part: &str| {
            if part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return None;
            }
            part.parse::<u64>().ok()
        };
        let inode = number(inode)?;
        (inode != 0).then_some((number(device)?, inode))
    };
    let Some((supervisor, own)) = supervisor_namespace
        .and_then(identity)
        .zip(own_namespace.filter(|(_, inode)| *inode != 0))
    else {
        return Outcome {
            allowed: false,
            errno: None,
            inconclusive: true,
        };
    };
    if supervisor == own {
        return Outcome {
            allowed: true,
            errno: None,
            inconclusive: false,
        };
    }
    let mut lines = contents.lines();
    let headers = (lines.next(), lines.next());
    let mut interfaces = Vec::new();
    let valid_headers = headers
        .0
        .is_some_and(|line| line.trim_start().starts_with("Inter-|"))
        && headers
            .1
            .is_some_and(|line| line.trim_start().starts_with("face |"));
    let valid = valid_headers
        && lines.all(|line| {
            let Some((name, counters)) = line.split_once(':') else {
                return false;
            };
            let name = name.trim();
            let counters: Vec<_> = counters.split_ascii_whitespace().collect();
            if name.is_empty()
                || interfaces.contains(&name)
                || counters.len() != 16
                || counters.iter().any(|value| value.parse::<u64>().is_err())
            {
                return false;
            }
            interfaces.push(name);
            true
        });
    Outcome {
        allowed: interfaces.iter().any(|name| *name != "lo"),
        errno: None,
        inconclusive: !valid || !interfaces.contains(&"lo"),
    }
}

fn parse_args(args: &[String], disposable: bool) -> Result<(Mode, Option<&str>), &'static str> {
    let mode = match args.first().map(String::as_str) {
        Some("--confined") => Mode::Confined,
        Some("--control") if disposable => Mode::Control,
        Some("--control") => return Err("launcher:probe-control-not-disposable"),
        _ => return Err("launcher:probe-mode-required"),
    };
    let only = match args.get(1) {
        Some(value) if value == "--boot" && mode == Mode::Confined => None,
        Some(value) => {
            let attack = value
                .strip_prefix("--only=")
                .filter(|a| ATTACKS.contains(a))
                .ok_or("launcher:probe-unknown-attack")?;
            Some(attack)
        }
        None => None,
    };
    if args.len() > 2 {
        return Err("launcher:probe-unknown-argument");
    }
    Ok((mode, only))
}

fn resource_bound(value: usize, minimum: usize, maximum: usize) -> Result<usize, &'static str> {
    if value < minimum || value > maximum {
        return Err("launcher:probe-resource-bound");
    }
    Ok(value)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let _ = parse_args(&args, false);
    let _ = resource_bound(64, 2, 128);
    let _ = Outcome::from_result(Ok(())).line(ATTACKS[0]);
    let _ = boot_line(ATTACKS[0], None, Some("launcher:unsupported-platform"));
    eprintln!("launcher:unsupported-platform");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(code) = linux::run() {
        if code != "launcher:probe-confinement-failed"
            || !std::env::args().any(|arg| arg == "--boot")
        {
            eprintln!("{code}");
        }
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        boot_fixture, boot_line, network_namespace_outcome, parse_args, pid_namespace_outcome,
        resource_bound, Mode, Outcome, ATTACKS,
    };
    use std::ffi::CString;
    use std::io::Write;
    use std::net::Ipv4Addr;
    use std::path::{Path, PathBuf};

    type SysResult = Result<i64, i32>;

    struct Config {
        mode: Mode,
        boot: bool,
        workspace: PathBuf,
        outside_pid: i32,
        vm_address: usize,
        fork_limit: usize,
        memory_bytes: usize,
        file_size_max_bytes: usize,
    }

    pub(super) fn run() -> Result<(), String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let disposable = std::env::var("AUKORA_PROBE_DISPOSABLE").as_deref() == Ok("1");
        let (mode, only) = parse_args(&args, disposable)?;
        let boot = args.get(1).is_some_and(|value| value == "--boot");
        if mode == Mode::Control {
            validate_control(only)?;
        }
        if !boot {
            validate_network_fixtures(only)?;
        }
        let outside_pid = number("OUTSIDE_PID", 2_000_000)?;
        if outside_pid <= 1 || outside_pid > i32::MAX as usize {
            return Err("launcher:probe-outside-pid-invalid".to_owned());
        }
        let config = Config {
            mode,
            boot,
            workspace: path("WORKSPACE", "/workspace"),
            outside_pid: outside_pid as i32,
            vm_address: number("VM_ADDRESS", 1)?,
            fork_limit: resource_bound(number("FORK_LIMIT", 64)?, 2, 128)?,
            memory_bytes: resource_bound(number("MEMORY_MIB", 128)?, 1, 256)? * 1024 * 1024,
            file_size_max_bytes: resource_bound(
                number(
                    "FILE_SIZE_MAX_BYTES",
                    launcher::DEFAULT_FILE_SIZE_MAX_BYTES as usize,
                )?,
                1,
                i64::MAX as usize - 1,
            )?,
        };
        let mut mismatch = false;
        for &attack in ATTACKS {
            if boot {
                let entry = launcher::BOOT_PROBE_ATTACKS
                    .iter()
                    .find(|entry| entry.name == attack)
                    .ok_or("launcher:probe-inventory-mismatch")?;
                let line = if let Some(reason) = entry.skip_reason {
                    boot_line(attack, None, Some(reason))
                } else if let Err(reason) = boot_fixture(
                    attack,
                    &config.workspace,
                    &path("MOUNT_DIR", "/workspace/probe-mount"),
                    &path(
                        "STICKY_FILE",
                        "/workspace/.aukora-boot-probe/supervisor-file",
                    ),
                    &path("PROFILE_FILE", "/workspace/dsh/profiles/web/package.json"),
                ) {
                    mismatch = true;
                    boot_line(attack, None, Some(reason))
                } else {
                    let outcome = attempt(attack, &config);
                    mismatch |= outcome.inconclusive
                        || !launcher::boot_probe_outcome_refused(
                            attack,
                            outcome.allowed,
                            outcome.errno,
                        );
                    boot_line(attack, Some(outcome), None)
                };
                println!("{line}");
                std::io::stdout()
                    .flush()
                    .map_err(|_| "launcher:probe-output-failed")?;
                continue;
            }
            if only.is_none_or(|selected| selected == attack) {
                let outcome = attempt(attack, &config);
                mismatch |= outcome.inconclusive || outcome.allowed != (mode == Mode::Control);
                if mode == Mode::Confined {
                    mismatch |= match attack {
                        "write-past-fsize" => outcome.errno != Some(libc::EFBIG),
                        "unlink-supervisor-file" => outcome.errno != Some(libc::EPERM),
                        "write-readonly-profile" => outcome.errno != Some(libc::EROFS),
                        "landlock-root-mkdir" | "landlock-workspace-socket" => {
                            outcome.errno != Some(libc::EACCES)
                        }
                        _ => false,
                    };
                }
                println!("{}", outcome.line(attack));
                std::io::stdout()
                    .flush()
                    .map_err(|_| "launcher:probe-output-failed")?;
            }
        }
        if mismatch {
            return Err(match mode {
                Mode::Confined => "launcher:probe-confinement-failed",
                Mode::Control => "launcher:probe-control-inconclusive",
            }
            .to_owned());
        }
        Ok(())
    }

    fn validate_control(only: Option<&str>) -> Result<(), String> {
        let fixtures: &[(&str, &[&str])] = &[
            ("extra-descriptors", &["CONTROL_FD"]),
            ("open-key", &["KEY_PATH"]),
            ("open-db", &["DB_PATH"]),
            ("connect-socket-path", &["SOCKET_PATH"]),
            ("tcp-out", &["OUT_IPV4", "OUT_PORT"]),
            ("udp-out", &["OUT_IPV4", "OUT_PORT"]),
            ("tcp-loopback", &["LOOPBACK_PORT"]),
            ("udp-loopback", &["LOOPBACK_PORT"]),
            ("abstract-socket", &["ABSTRACT_NAME"]),
            ("proc-other-pid", &["OUTSIDE_PID"]),
            ("ptrace", &["OUTSIDE_PID"]),
            ("process-vm-readv", &["OUTSIDE_PID", "VM_ADDRESS"]),
            ("mount", &["MOUNT_DIR"]),
            ("write-git", &["WORKSPACE"]),
            ("landlock-workspace-socket", &["WORKSPACE"]),
            ("write-past-fsize", &["WORKSPACE", "FILE_SIZE_MAX_BYTES"]),
            ("unlink-supervisor-file", &["STICKY_FILE"]),
            ("write-readonly-profile", &["PROFILE_FILE"]),
            ("symlink-out", &["WORKSPACE", "KEY_PATH"]),
            ("hardlink-out", &["WORKSPACE", "KEY_PATH"]),
            ("rename-out", &["WORKSPACE", "ESCAPE_DIR"]),
            ("tiocsti", &["TTY_PATH"]),
            ("signal-outside-pid", &["OUTSIDE_PID"]),
            ("setuid-binary", &["SETUID_HELPER"]),
        ];
        for &(attack, names) in fixtures {
            if only.is_none_or(|selected| selected == attack) {
                for name in names {
                    if std::env::var(format!("AUKORA_PROBE_{name}")).is_err() {
                        return Err(format!("launcher:probe-fixture-missing:{name}"));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_network_fixtures(only: Option<&str>) -> Result<(), String> {
        let selected = |names: &[&str]| only.is_none_or(|attack| names.contains(&attack));
        if selected(&["tcp-out", "udp-out"]) {
            std::env::var("AUKORA_PROBE_OUT_IPV4")
                .unwrap_or_else(|_| "198.18.0.1".to_owned())
                .parse::<Ipv4Addr>()
                .map_err(|_| "launcher:probe-fixture-invalid:OUT_IPV4")?;
            let port = number("OUT_PORT", 9)?;
            if port == 0 || port > u16::MAX as usize {
                return Err("launcher:probe-fixture-invalid:OUT_PORT".to_owned());
            }
        }
        if selected(&["tcp-loopback", "udp-loopback"]) {
            let port = number("LOOPBACK_PORT", 9)?;
            if port == 0 || port > u16::MAX as usize {
                return Err("launcher:probe-fixture-invalid:LOOPBACK_PORT".to_owned());
            }
        }
        if selected(&["abstract-socket"]) {
            let name = std::env::var("AUKORA_PROBE_ABSTRACT_NAME")
                .unwrap_or_else(|_| "aukora-probe-control".to_owned());
            if name.is_empty() || name.len() >= 108 {
                return Err("launcher:probe-fixture-invalid:ABSTRACT_NAME".to_owned());
            }
        }
        if selected(&["connect-socket-path"]) {
            use std::os::unix::ffi::OsStrExt;
            let path = path("SOCKET_PATH", "/outside/probe.sock");
            if path.as_os_str().is_empty() || path.as_os_str().as_bytes().len() >= 108 {
                return Err("launcher:probe-fixture-invalid:SOCKET_PATH".to_owned());
            }
        }
        Ok(())
    }

    fn path(name: &str, default: &str) -> PathBuf {
        std::env::var_os(format!("AUKORA_PROBE_{name}"))
            .map_or_else(|| PathBuf::from(default), PathBuf::from)
    }

    fn number(name: &str, default: usize) -> Result<usize, String> {
        std::env::var(format!("AUKORA_PROBE_{name}")).map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|_| format!("launcher:probe-fixture-invalid:{name}"))
        })
    }

    fn cpath(path: &Path) -> Result<CString, i32> {
        use std::os::unix::ffi::OsStrExt;
        CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)
    }

    fn call(nr: libc::c_long, args: [usize; 6]) -> SysResult {
        // SAFETY: each caller supplies the syscall's initialized arguments and live buffers.
        let rc = unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
        if rc < 0 {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        } else {
            Ok(rc)
        }
    }

    fn close(fd: i64) {
        let _ = call(libc::SYS_close, [fd as usize, 0, 0, 0, 0, 0]);
    }

    fn open(path: &Path, flags: i32) -> SysResult {
        let value = cpath(path)?;
        call(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as usize,
                value.as_ptr() as usize,
                flags as usize,
                0o600,
                0,
                0,
            ],
        )
    }

    fn open_close(path: &Path, flags: i32) -> Result<(), i32> {
        let fd = open(path, flags)?;
        close(fd);
        Ok(())
    }

    fn socket(domain: i32, kind: i32, protocol: i32) -> SysResult {
        call(
            libc::SYS_socket,
            [domain as usize, kind as usize, protocol as usize, 0, 0, 0],
        )
    }

    fn socket_close(domain: i32, kind: i32, protocol: i32) -> Result<(), i32> {
        let fd = socket(domain, kind, protocol)?;
        close(fd);
        Ok(())
    }

    fn attempt(attack: &str, config: &Config) -> Outcome {
        let result = match attack {
            "extra-descriptors" => extra_descriptors(),
            "landlock-root-mkdir" => root_mkdir(),
            "landlock-workspace-socket" => workspace_socket(config),
            "pid-namespace" => return pid_namespace_outcome(std::process::id()),
            "network-namespace" => {
                use std::os::unix::fs::MetadataExt;
                let supervisor = std::env::var("AUKORA_PROBE_SUPERVISOR_NET_NAMESPACE").ok();
                let own = std::fs::metadata("/proc/self/ns/net")
                    .ok()
                    .map(|metadata| (metadata.dev(), metadata.ino()));
                let contents = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
                return network_namespace_outcome(&contents, supervisor.as_deref(), own);
            }
            "open-key" => open_close(&path("KEY_PATH", "/outside/probe-key"), libc::O_RDONLY),
            "open-db" => open_close(&path("DB_PATH", "/outside/probe.db"), libc::O_RDONLY),
            "connect-socket-path" => unix_connect(false),
            "tcp-out" => inet_send(false, false),
            "udp-out" => inet_send(false, true),
            "tcp-loopback" => inet_send(true, false),
            "udp-loopback" => inet_send(true, true),
            "abstract-socket" => unix_connect(true),
            "proc-other-pid" => open_close(
                &PathBuf::from(format!("/proc/{}/status", config.outside_pid)),
                libc::O_RDONLY,
            ),
            "ptrace" => ptrace(config.outside_pid),
            "process-vm-readv" => process_vm(config),
            "mount" => return isolated(mount),
            "unshare-user" => {
                return isolated(|| {
                    call(
                        libc::SYS_unshare,
                        [libc::CLONE_NEWUSER as usize, 0, 0, 0, 0, 0],
                    )
                    .map(|_| ())
                })
            }
            "setns" => return isolated(setns),
            "nested-userns" => return isolated(nested_userns),
            "io-uring-setup" => io_uring(),
            "write-git" => write_file(&config.workspace.join(if config.boot {
                ".git/.aukora-boot-probe-write"
            } else {
                ".git/probe-write"
            })),
            "write-past-fsize" => return isolated(|| write_past_file_size(config)),
            "unlink-supervisor-file" => {
                unlink_file(&path("STICKY_FILE", "/workspace/sticky/supervisor-file"))
            }
            "write-readonly-profile" if config.boot => truncate_profile(&path(
                "PROFILE_FILE",
                "/workspace/dsh/profiles/web/package.json",
            )),
            "write-readonly-profile" => open_close(
                &path("PROFILE_FILE", "/workspace/supervisor-profile"),
                libc::O_WRONLY,
            ),
            "write-dev-shm" => write_file(Path::new("/dev/shm/aukora-probe-write")),
            "write-var-tmp" => write_file(Path::new("/var/tmp/aukora-probe-write")),
            "symlink-out" => symlink_out(config),
            "hardlink-out" => hardlink_out(config),
            "rename-out" => rename_out(config),
            "socket-inet6" => socket_close(libc::AF_INET6, libc::SOCK_STREAM, 0),
            "socket-packet" => socket_close(libc::AF_PACKET, libc::SOCK_RAW, u16::to_be(3) as i32),
            "socket-netlink" => socket_close(libc::AF_NETLINK, libc::SOCK_RAW, 0),
            "socket-vsock" => socket_close(libc::AF_VSOCK, libc::SOCK_STREAM, 0),
            "tiocsti" => tiocsti(),
            "signal-outside-pid" => call(
                libc::SYS_kill,
                [
                    config.outside_pid as usize,
                    libc::SIGCONT as usize,
                    0,
                    0,
                    0,
                    0,
                ],
            )
            .map(|_| ()),
            "fork-bomb" => fork_bound(config.fork_limit),
            "memory-balloon" => return isolated(|| memory_bound(config.memory_bytes)),
            "clock-set" => clock_set(),
            "open-dev-mem" => open_close(Path::new("/dev/mem"), libc::O_RDONLY),
            "open-dev-kmsg" => open_close(Path::new("/dev/kmsg"), libc::O_RDONLY),
            "setuid-binary" => return setuid_binary(config.mode),
            _ => Err(libc::EINVAL),
        };
        Outcome::from_result(result)
    }

    fn extra_descriptors() -> Result<(), i32> {
        let entries = std::fs::read_dir("/proc/self/fd")
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let mut descriptors = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            if let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<usize>().ok())
            {
                if fd >= 5 {
                    descriptors.push(fd);
                }
            }
        }
        let mut missing = call(
            libc::SYS_fcntl,
            [usize::MAX, libc::F_GETFD as usize, 0, 0, 0, 0],
        )
        .map(|_| ());
        // The directory descriptor is closed before checking the enumerated numbers.
        for fd in descriptors {
            match call(libc::SYS_fcntl, [fd, libc::F_GETFD as usize, 0, 0, 0, 0]) {
                Ok(_) => return Ok(()),
                Err(errno) => missing = Err(errno),
            }
        }
        missing
    }

    fn root_mkdir() -> Result<(), i32> {
        let directory = c"/.aukora-probe-landlock";
        call(
            libc::SYS_mkdirat,
            [
                libc::AT_FDCWD as usize,
                directory.as_ptr() as usize,
                0o700,
                0,
                0,
                0,
            ],
        )?;
        let _ = call(
            libc::SYS_unlinkat,
            [
                libc::AT_FDCWD as usize,
                directory.as_ptr() as usize,
                libc::AT_REMOVEDIR as usize,
                0,
                0,
                0,
            ],
        );
        Ok(())
    }

    fn workspace_socket(config: &Config) -> Result<(), i32> {
        let directory = if config.boot {
            path("MOUNT_DIR", "/workspace/probe-mount")
        } else {
            config.workspace.clone()
        };
        let location = directory.join(format!(".aukora-probe-socket-{}", std::process::id()));
        let fd = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0)?;
        let result = (|| {
            use std::os::unix::ffi::OsStrExt;
            let name = location.as_os_str().as_bytes();
            let mut address = libc::sockaddr_un {
                sun_family: libc::AF_UNIX as u16,
                sun_path: [0; 108],
            };
            if name.is_empty() || name.len() >= address.sun_path.len() {
                return Err(libc::ENAMETOOLONG);
            }
            for (out, byte) in address.sun_path.iter_mut().zip(name) {
                *out = *byte as libc::c_char;
            }
            call(
                libc::SYS_bind,
                [
                    fd as usize,
                    &address as *const _ as usize,
                    std::mem::size_of::<libc::sa_family_t>() + name.len() + 1,
                    0,
                    0,
                    0,
                ],
            )
            .map(|_| ())
        })();
        close(fd);
        if result.is_ok() {
            unlink(&location);
        }
        result
    }

    fn inet_send(loopback: bool, udp: bool) -> Result<(), i32> {
        let fd = socket(
            libc::AF_INET,
            if udp {
                libc::SOCK_DGRAM
            } else {
                libc::SOCK_STREAM
            },
            0,
        )?;
        let result = (|| {
            let addr: Ipv4Addr = if loopback {
                Ipv4Addr::LOCALHOST
            } else {
                std::env::var("AUKORA_PROBE_OUT_IPV4")
                    .unwrap_or_else(|_| "198.18.0.1".to_owned())
                    .parse()
                    .map_err(|_| libc::EINVAL)?
            };
            let port = number(
                if loopback {
                    "LOOPBACK_PORT"
                } else {
                    "OUT_PORT"
                },
                9,
            )
            .map_err(|_| libc::EINVAL)?;
            if port == 0 || port > u16::MAX as usize {
                return Err(libc::EINVAL);
            }
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: (port as u16).to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.octets()),
                },
                sin_zero: [0; 8],
            };
            let timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 250_000,
            };
            call(
                libc::SYS_setsockopt,
                [
                    fd as usize,
                    libc::SOL_SOCKET as usize,
                    libc::SO_SNDTIMEO as usize,
                    &timeout as *const _ as usize,
                    std::mem::size_of_val(&timeout),
                    0,
                ],
            )?;
            if udp {
                let byte = [0u8];
                call(
                    libc::SYS_sendto,
                    [
                        fd as usize,
                        byte.as_ptr() as usize,
                        byte.len(),
                        0,
                        &address as *const _ as usize,
                        std::mem::size_of_val(&address),
                    ],
                )
                .map(|_| ())
            } else {
                call(
                    libc::SYS_connect,
                    [
                        fd as usize,
                        &address as *const _ as usize,
                        std::mem::size_of_val(&address),
                        0,
                        0,
                        0,
                    ],
                )
                .map(|_| ())
            }
        })();
        close(fd);
        result
    }

    fn unix_connect(abstract_name: bool) -> Result<(), i32> {
        let fd = socket(libc::AF_UNIX, libc::SOCK_STREAM, 0)?;
        let result = (|| {
            let name = if abstract_name {
                std::env::var("AUKORA_PROBE_ABSTRACT_NAME")
                    .unwrap_or_else(|_| "aukora-probe-control".to_owned())
                    .into_bytes()
            } else {
                use std::os::unix::ffi::OsStrExt;
                path("SOCKET_PATH", "/outside/probe.sock")
                    .as_os_str()
                    .as_bytes()
                    .to_vec()
            };
            let mut address = libc::sockaddr_un {
                sun_family: libc::AF_UNIX as u16,
                sun_path: [0; 108],
            };
            if name.is_empty() || name.len() >= address.sun_path.len() {
                return Err(libc::EINVAL);
            }
            let start = usize::from(abstract_name);
            for (out, byte) in address.sun_path[start..].iter_mut().zip(&name) {
                *out = *byte as libc::c_char;
            }
            let length = std::mem::size_of::<libc::sa_family_t>() + name.len() + 1;
            call(
                libc::SYS_connect,
                [fd as usize, &address as *const _ as usize, length, 0, 0, 0],
            )
            .map(|_| ())
        })();
        close(fd);
        result
    }

    fn ptrace(pid: i32) -> Result<(), i32> {
        call(
            libc::SYS_ptrace,
            [libc::PTRACE_ATTACH as usize, pid as usize, 0, 0, 0, 0],
        )?;
        let _ = wait(pid);
        let _ = call(
            libc::SYS_ptrace,
            [libc::PTRACE_DETACH as usize, pid as usize, 0, 0, 0, 0],
        );
        Ok(())
    }

    fn process_vm(config: &Config) -> Result<(), i32> {
        let mut byte = 0u8;
        let local = libc::iovec {
            iov_base: &mut byte as *mut _ as *mut libc::c_void,
            iov_len: 1,
        };
        let remote = libc::iovec {
            iov_base: config.vm_address as *mut libc::c_void,
            iov_len: 1,
        };
        call(
            libc::SYS_process_vm_readv,
            [
                config.outside_pid as usize,
                &local as *const _ as usize,
                1,
                &remote as *const _ as usize,
                1,
                0,
            ],
        )
        .map(|_| ())
    }

    fn mount() -> Result<(), i32> {
        let target = cpath(&path("MOUNT_DIR", "/workspace/probe-mount"))?;
        let source = c"none";
        let kind = c"tmpfs";
        call(
            libc::SYS_mount,
            [
                source.as_ptr() as usize,
                target.as_ptr() as usize,
                kind.as_ptr() as usize,
                (libc::MS_NOSUID | libc::MS_NODEV) as usize,
                0,
                0,
            ],
        )?;
        let _ = call(
            libc::SYS_umount2,
            [
                target.as_ptr() as usize,
                libc::MNT_DETACH as usize,
                0,
                0,
                0,
                0,
            ],
        );
        Ok(())
    }

    fn setns() -> Result<(), i32> {
        let fd = open(Path::new("/proc/self/ns/mnt"), libc::O_RDONLY)?;
        let result = call(
            libc::SYS_setns,
            [fd as usize, libc::CLONE_NEWNS as usize, 0, 0, 0, 0],
        )
        .map(|_| ());
        close(fd);
        result
    }

    fn nested_userns() -> Result<(), i32> {
        let pid = call(
            libc::SYS_clone,
            [
                (libc::CLONE_NEWUSER | libc::SIGCHLD) as usize,
                0,
                0,
                0,
                0,
                0,
            ],
        )?;
        if pid == 0 {
            exit_child(0);
        }
        wait(pid as i32).map(|_| ())
    }

    fn io_uring() -> Result<(), i32> {
        let mut params = [0u64; 15];
        let fd = call(
            libc::SYS_io_uring_setup,
            [1, params.as_mut_ptr() as usize, 0, 0, 0, 0],
        )?;
        close(fd);
        Ok(())
    }

    fn unlink(path: &Path) {
        if let Ok(path) = cpath(path) {
            let _ = call(
                libc::SYS_unlinkat,
                [libc::AT_FDCWD as usize, path.as_ptr() as usize, 0, 0, 0, 0],
            );
        }
    }

    fn unlink_file(path: &Path) -> Result<(), i32> {
        let path = cpath(path)?;
        call(
            libc::SYS_unlinkat,
            [libc::AT_FDCWD as usize, path.as_ptr() as usize, 0, 0, 0, 0],
        )
        .map(|_| ())
    }

    fn truncate_profile(path: &Path) -> Result<(), i32> {
        let length = std::fs::metadata(path)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?
            .len();
        let path = cpath(path)?;
        // mnt_want_write precedes DAC for truncate; preserve the bytes if a weakened mount allows it.
        call(
            libc::SYS_truncate,
            [path.as_ptr() as usize, length as usize, 0, 0, 0, 0],
        )
        .map(|_| ())
    }

    fn write_past_file_size(config: &Config) -> Result<(), i32> {
        // SAFETY: SIG_IGN permits observing EFBIG instead of SIGXFSZ terminating this isolated probe.
        unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        let path = if config.boot {
            path("MOUNT_DIR", "/workspace/probe-mount").join("file-size")
        } else {
            config.workspace.join("probe-file-size")
        };
        let fd = open(&path, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        let byte = b'x';
        let result = call(
            libc::SYS_pwrite64,
            [
                fd as usize,
                &byte as *const u8 as usize,
                1,
                config.file_size_max_bytes,
                0,
                0,
            ],
        )
        .map(|_| ());
        close(fd);
        unlink(&path);
        result
    }

    fn write_file(path: &Path) -> Result<(), i32> {
        let fd = open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        let byte = [0u8];
        let result = call(
            libc::SYS_write,
            [fd as usize, byte.as_ptr() as usize, byte.len(), 0, 0, 0],
        )
        .map(|_| ());
        close(fd);
        unlink(path);
        result
    }

    fn symlink_out(config: &Config) -> Result<(), i32> {
        let key = path("KEY_PATH", "/outside/probe-key");
        let link = config.workspace.join("probe-symlink");
        let target = cpath(&key)?;
        let location = cpath(&link)?;
        call(
            libc::SYS_symlinkat,
            [
                target.as_ptr() as usize,
                libc::AT_FDCWD as usize,
                location.as_ptr() as usize,
                0,
                0,
                0,
            ],
        )?;
        let result = open_close(&link, libc::O_RDONLY);
        unlink(&link);
        result
    }

    fn hardlink_out(config: &Config) -> Result<(), i32> {
        let key = cpath(&path("KEY_PATH", "/outside/probe-key"))?;
        let link = config.workspace.join("probe-hardlink");
        let location = cpath(&link)?;
        let result = call(
            libc::SYS_linkat,
            [
                libc::AT_FDCWD as usize,
                key.as_ptr() as usize,
                libc::AT_FDCWD as usize,
                location.as_ptr() as usize,
                0,
                0,
            ],
        )
        .map(|_| ());
        if result.is_ok() {
            unlink(&link);
        }
        result
    }

    fn rename_out(config: &Config) -> Result<(), i32> {
        let source = config.workspace.join("probe-rename-source");
        let fd = open(&source, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        close(fd);
        let target = path("ESCAPE_DIR", "/outside").join("probe-rename-target");
        let a = cpath(&source)?;
        let b = cpath(&target)?;
        let result = call(
            libc::SYS_renameat2,
            [
                libc::AT_FDCWD as usize,
                a.as_ptr() as usize,
                libc::AT_FDCWD as usize,
                b.as_ptr() as usize,
                libc::RENAME_NOREPLACE as usize,
                0,
            ],
        )
        .map(|_| ());
        unlink(&source);
        if result.is_ok() {
            unlink(&target);
        }
        result
    }

    fn tiocsti() -> Result<(), i32> {
        let fd = open(
            &path("TTY_PATH", "/dev/tty"),
            libc::O_RDWR | libc::O_NONBLOCK,
        )?;
        let newline = b'\n';
        let result = call(
            libc::SYS_ioctl,
            [
                fd as usize,
                libc::TIOCSTI as usize,
                &newline as *const _ as usize,
                0,
                0,
                0,
            ],
        )
        .map(|_| ());
        close(fd);
        result
    }

    fn clock_set() -> Result<(), i32> {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        call(
            libc::SYS_clock_gettime,
            [
                libc::CLOCK_REALTIME as usize,
                &mut time as *mut _ as usize,
                0,
                0,
                0,
                0,
            ],
        )?;
        call(
            libc::SYS_clock_settime,
            [
                libc::CLOCK_REALTIME as usize,
                &time as *const _ as usize,
                0,
                0,
                0,
                0,
            ],
        )
        .map(|_| ())
    }

    fn pipe() -> Result<[i32; 2], i32> {
        let mut fds = [-1; 2];
        call(
            libc::SYS_pipe2,
            [
                fds.as_mut_ptr() as usize,
                libc::O_CLOEXEC as usize,
                0,
                0,
                0,
                0,
            ],
        )?;
        Ok(fds)
    }

    fn wait(pid: i32) -> Result<i32, i32> {
        let mut status = 0;
        loop {
            match call(
                libc::SYS_wait4,
                [pid as usize, &mut status as *mut _ as usize, 0, 0, 0, 0],
            ) {
                Ok(_) => return Ok(status),
                Err(libc::EINTR) => continue,
                Err(errno) => return Err(errno),
            }
        }
    }

    fn exit_child(code: i32) -> ! {
        // SAFETY: this single-threaded probe child exits without running inherited Rust destructors.
        unsafe { libc::_exit(code) }
    }

    fn isolated(action: impl FnOnce() -> Result<(), i32>) -> Outcome {
        let fds = match pipe() {
            Ok(fds) => fds,
            Err(errno) => return Outcome::from_result(Err(errno)),
        };
        let pid = match call(libc::SYS_clone, [libc::SIGCHLD as usize, 0, 0, 0, 0, 0]) {
            Ok(pid) => pid,
            Err(errno) => {
                close(fds[0] as i64);
                close(fds[1] as i64);
                return Outcome::from_result(Err(errno));
            }
        };
        if pid == 0 {
            close(fds[0] as i64);
            let code = action().err().unwrap_or(0);
            let _ = call(
                libc::SYS_write,
                [
                    fds[1] as usize,
                    &code as *const _ as usize,
                    std::mem::size_of_val(&code),
                    0,
                    0,
                    0,
                ],
            );
            exit_child(0);
        }
        close(fds[1] as i64);
        let mut code = 0i32;
        let read = call(
            libc::SYS_read,
            [
                fds[0] as usize,
                &mut code as *mut _ as usize,
                std::mem::size_of_val(&code),
                0,
                0,
                0,
            ],
        );
        close(fds[0] as i64);
        let status = wait(pid as i32);
        if read == Ok(std::mem::size_of_val(&code) as i64) && status == Ok(0) {
            Outcome::from_result(if code == 0 { Ok(()) } else { Err(code) })
        } else {
            Outcome {
                allowed: false,
                errno: None,
                inconclusive: false,
            }
        }
    }

    fn fork_bound(limit: usize) -> Result<(), i32> {
        let fds = pipe()?;
        let mut children = Vec::new();
        let mut result = Ok(());
        for _ in 0..limit {
            match call(libc::SYS_clone, [libc::SIGCHLD as usize, 0, 0, 0, 0, 0]) {
                Ok(0) => {
                    close(fds[1] as i64);
                    let mut byte = 0u8;
                    let _ = call(
                        libc::SYS_read,
                        [fds[0] as usize, &mut byte as *mut _ as usize, 1, 0, 0, 0],
                    );
                    exit_child(0);
                }
                Ok(pid) => children.push(pid as i32),
                Err(errno) => {
                    result = Err(errno);
                    break;
                }
            }
        }
        close(fds[0] as i64);
        close(fds[1] as i64);
        for child in children {
            let _ = wait(child);
        }
        result
    }

    fn memory_bound(bytes: usize) -> Result<(), i32> {
        let address = call(
            libc::SYS_mmap,
            [
                0,
                bytes,
                (libc::PROT_READ | libc::PROT_WRITE) as usize,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize,
                usize::MAX,
                0,
            ],
        )?;
        for offset in (0..bytes).step_by(4096) {
            // SAFETY: mmap returned a writable mapping of bytes bytes, and offset is inside it.
            unsafe { (address as *mut u8).add(offset).write_volatile(1) };
        }
        call(libc::SYS_munmap, [address as usize, bytes, 0, 0, 0, 0]).map(|_| ())
    }

    fn setuid_binary(mode: Mode) -> Outcome {
        let helper = match cpath(&path("SETUID_HELPER", "/usr/libexec/aukora-probe-setuid")) {
            Ok(helper) => helper,
            Err(errno) => return Outcome::from_result(Err(errno)),
        };
        let fds = match pipe() {
            Ok(fds) => fds,
            Err(errno) => return Outcome::from_result(Err(errno)),
        };
        let pid = match call(libc::SYS_clone, [libc::SIGCHLD as usize, 0, 0, 0, 0, 0]) {
            Ok(pid) => pid,
            Err(errno) => {
                close(fds[0] as i64);
                close(fds[1] as i64);
                return Outcome::from_result(Err(errno));
            }
        };
        if pid == 0 {
            close(fds[0] as i64);
            if mode == Mode::Control && call(libc::SYS_geteuid, [0; 6]) == Ok(0) {
                let drop_identity = call(libc::SYS_setresgid, [65534, 65534, 65534, 0, 0, 0])
                    .and_then(|_| call(libc::SYS_setresuid, [65534, 65534, 65534, 0, 0, 0]));
                if let Err(errno) = drop_identity {
                    write_child_errno(fds[1], errno);
                }
            }
            let argv = [helper.as_ptr(), std::ptr::null()];
            let envp: [*const libc::c_char; 1] = [std::ptr::null()];
            if let Err(errno) = call(
                libc::SYS_execve,
                [
                    helper.as_ptr() as usize,
                    argv.as_ptr() as usize,
                    envp.as_ptr() as usize,
                    0,
                    0,
                    0,
                ],
            ) {
                write_child_errno(fds[1], errno);
            }
            exit_child(79);
        }
        close(fds[1] as i64);
        let mut errno = 0i32;
        let read = call(
            libc::SYS_read,
            [
                fds[0] as usize,
                &mut errno as *mut _ as usize,
                std::mem::size_of_val(&errno),
                0,
                0,
                0,
            ],
        );
        close(fds[0] as i64);
        match wait(pid as i32) {
            Ok(_) if read == Ok(std::mem::size_of_val(&errno) as i64) => {
                Outcome::from_result(Err(errno))
            }
            Ok(status) => Outcome {
                allowed: libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 77,
                errno: None,
                inconclusive: false,
            },
            Err(errno) => Outcome::from_result(Err(errno)),
        }
    }

    fn write_child_errno(fd: i32, errno: i32) -> ! {
        let _ = call(
            libc::SYS_write,
            [
                fd as usize,
                &errno as *const _ as usize,
                std::mem::size_of_val(&errno),
                0,
                0,
                0,
            ],
        );
        exit_child(79);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn child_errno_is_not_replaced_or_invented() {
            assert_eq!(
                isolated(|| Err(libc::EPERM)),
                Outcome::from_result(Err(libc::EPERM))
            );
            assert_eq!(isolated(|| Ok(())), Outcome::from_result(Ok(())));
        }

        #[test]
        fn socket_and_open_controls_exercise_real_syscalls() {
            assert_eq!(socket_close(libc::AF_UNIX, libc::SOCK_STREAM, 0), Ok(()));
            assert_eq!(open_close(Path::new("/dev/null"), libc::O_RDONLY), Ok(()));
            assert_eq!(
                open_close(Path::new("/proc/self/aukora-probe-missing"), libc::O_RDONLY),
                Err(libc::ENOENT)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_canonical_and_preserves_errno() {
        assert_eq!(
            Outcome::from_result(Err(1)).line("mount"),
            "{\"attack\":\"mount\",\"errno\":1,\"result\":\"refused\"}"
        );
        assert_eq!(
            Outcome::from_result(Ok(())).line("mount"),
            "{\"attack\":\"mount\",\"errno\":null,\"result\":\"allowed\"}"
        );
    }

    #[test]
    fn control_requires_an_explicit_disposable_environment() {
        let args = ["--control".to_owned()];
        assert_eq!(
            parse_args(&args, false),
            Err("launcher:probe-control-not-disposable")
        );
        assert_eq!(parse_args(&args, true), Ok((Mode::Control, None)));
    }

    #[test]
    fn resource_attacks_remain_bounded() {
        assert!(resource_bound(129, 2, 128).is_err());
        assert!(resource_bound(0, 2, 128).is_err());
        assert_eq!(resource_bound(64, 2, 128), Ok(64));
        assert!(resource_bound(257, 1, 256).is_err());
    }

    #[test]
    fn complete_attack_inventory_and_valid_selection() {
        assert_eq!(ATTACKS.len(), 42);
        let mut names = ATTACKS.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ATTACKS.len());
        for &attack in ATTACKS {
            let args = ["--confined".to_owned(), format!("--only={attack}")];
            assert_eq!(parse_args(&args, false), Ok((Mode::Confined, Some(attack))));
        }
        assert!(parse_args(
            &["--confined".to_owned(), "--only=missing".to_owned()],
            false
        )
        .is_err());
    }

    #[test]
    fn implicit_mode_and_extra_arguments_are_refused() {
        assert_eq!(parse_args(&[], true), Err("launcher:probe-mode-required"));
        assert_eq!(
            parse_args(&["--invalid".to_owned()], true),
            Err("launcher:probe-mode-required")
        );
        assert_eq!(
            parse_args(
                &[
                    "--confined".to_owned(),
                    "--only=mount".to_owned(),
                    "extra".to_owned()
                ],
                false
            ),
            Err("launcher:probe-unknown-argument")
        );
    }

    #[test]
    fn antibody_boot_probe_cannot_run_control_mode() {
        assert_eq!(
            parse_args(&["--confined".into(), "--boot".into()], false),
            Ok((Mode::Confined, None))
        );
        assert!(parse_args(&["--control".into(), "--boot".into()], true).is_err());
    }

    #[test]
    fn antibody_boot_probe_requires_exact_kernel_refusal() {
        assert_eq!(
            ATTACKS,
            launcher::BOOT_PROBE_ATTACKS.map(|entry| entry.name)
        );
        for attack in launcher::BOOT_PROBE_ATTACKS {
            if let Some(reason) = attack.skip_reason {
                assert!(
                    boot_line(attack.name, None, Some(reason)).ends_with("\"result\":\"skipped\"}")
                );
                continue;
            }
            let errno = launcher::boot_probe_expected_errno(attack.name);
            assert!(boot_line(
                attack.name,
                Some(Outcome {
                    allowed: false,
                    errno,
                    inconclusive: false
                }),
                None
            )
            .ends_with("\"result\":\"refused\"}"));
            assert!(
                boot_line(attack.name, Some(Outcome::from_result(Ok(()))), None)
                    .ends_with("\"result\":\"allowed\"}")
            );
            assert!(boot_line(
                attack.name,
                Some(Outcome::from_result(Err(libc::EINVAL))),
                None
            )
            .ends_with("\"result\":\"inconclusive\"}"));
            assert!(boot_line(
                attack.name,
                Some(Outcome {
                    allowed: false,
                    errno: None,
                    inconclusive: true,
                }),
                None
            )
            .ends_with("\"result\":\"inconclusive\"}"));
            assert!(
                boot_line(attack.name, None, Some("launcher:probe-fixture-missing"))
                    .ends_with("\"result\":\"inconclusive\"}")
            );
            assert!(
                boot_line(attack.name, None, Some("launcher:probe-fixture-collision"))
                    .ends_with("\"result\":\"inconclusive\"}")
            );
        }
    }

    #[test]
    fn antibody_boot_probe_detects_a_missing_pid_namespace() {
        let contained = pid_namespace_outcome(1);
        assert!(!contained.allowed && !contained.inconclusive && contained.errno.is_none());
        assert!(
            boot_line("pid-namespace", Some(contained), None).ends_with("\"result\":\"refused\"}")
        );
        let escaped = pid_namespace_outcome(1234);
        assert!(escaped.allowed);
        assert!(
            boot_line("pid-namespace", Some(escaped), None).ends_with("\"result\":\"allowed\"}")
        );
    }

    #[test]
    fn antibody_boot_probe_detects_non_loopback_interfaces_and_invalid_observations() {
        let headers = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n";
        let loopback = "lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        let other = "eth0: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n";
        let observe =
            |contents: &str| network_namespace_outcome(contents, Some("4:100"), Some((4, 101)));
        let contained = observe(&format!("{headers}{loopback}"));
        assert!(!contained.allowed && !contained.inconclusive && contained.errno.is_none());
        assert!(boot_line("network-namespace", Some(contained), None)
            .ends_with("\"result\":\"refused\"}"));
        let escaped = observe(&format!("{headers}{loopback}{other}"));
        assert!(escaped.allowed && !escaped.inconclusive);
        for invalid in [
            "".to_owned(),
            headers.to_owned(),
            format!("{headers}{other}"),
            format!("{headers}lo: bad\n"),
            format!("{headers}{loopback}{loopback}"),
        ] {
            let outcome = observe(&invalid);
            assert!(outcome.inconclusive);
            assert!(boot_line("network-namespace", Some(outcome), None)
                .ends_with("\"result\":\"inconclusive\"}"));
        }
    }

    #[test]
    fn antibody_boot_probe_rejects_the_supervisor_loopback_only_network_namespace() {
        let contents =
            "Inter-| Receive | Transmit\n face | counters\nlo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        let escaped = network_namespace_outcome(contents, Some("4:100"), Some((4, 100)));
        assert!(escaped.allowed && !escaped.inconclusive);
        assert!(boot_line("network-namespace", Some(escaped), None)
            .ends_with("\"result\":\"allowed\"}"));
        for own in [(4, 101), (5, 100)] {
            let contained = network_namespace_outcome(contents, Some("4:100"), Some(own));
            assert!(!contained.allowed && !contained.inconclusive);
            assert!(boot_line("network-namespace", Some(contained), None)
                .ends_with("\"result\":\"refused\"}"));
        }
    }

    #[test]
    fn antibody_boot_probe_network_namespace_identity_must_be_observed_and_valid() {
        let contents =
            "Inter-| Receive | Transmit\n face | counters\nlo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        for supervisor in [
            None,
            Some(""),
            Some("4"),
            Some("4:"),
            Some(":100"),
            Some("4:0"),
            Some("4:100:1"),
            Some("4:+100"),
            Some("4:-1"),
            Some("4: 100"),
            Some("4:100\n"),
            Some("04:100"),
            Some("4:0100"),
            Some("18446744073709551616:100"),
            Some("4:18446744073709551616"),
        ] {
            let outcome = network_namespace_outcome(contents, supervisor, Some((4, 101)));
            assert!(outcome.inconclusive, "{supervisor:?}");
            assert!(boot_line("network-namespace", Some(outcome), None)
                .ends_with("\"result\":\"inconclusive\"}"));
        }
        for own in [None, Some((4, 0))] {
            assert!(network_namespace_outcome(contents, Some("4:100"), own).inconclusive);
        }
    }

    #[test]
    fn antibody_boot_probe_uses_only_the_current_fixture_directory() {
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("probe-fresh-directory-{}", std::process::id()));
        std::fs::create_dir(&workspace).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(workspace.clone());
        let stale = workspace.join(".aukora-boot-probe");
        let fresh = workspace.join(".aukora-boot-probe-fresh");
        std::fs::create_dir(&stale).unwrap();
        std::fs::create_dir(&fresh).unwrap();
        std::fs::write(stale.join("file-size"), b"stale guest bytes").unwrap();
        assert_eq!(
            boot_fixture(
                "write-past-fsize",
                &workspace,
                &fresh,
                &fresh.join("supervisor-file"),
                &workspace.join("profile")
            ),
            Ok(())
        );
        std::fs::write(fresh.join("file-size"), b"current collision").unwrap();
        assert_eq!(
            boot_fixture(
                "write-past-fsize",
                &workspace,
                &fresh,
                &fresh.join("supervisor-file"),
                &workspace.join("profile")
            ),
            Err("launcher:probe-fixture-collision")
        );
    }

    #[test]
    fn antibody_boot_probe_missing_and_colliding_fixtures_are_inconclusive() {
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("probe-boot-fixtures-{}", std::process::id()));
        std::fs::create_dir(&workspace).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(workspace.clone());
        let mount_dir = workspace.join(".aukora-boot-probe");
        let sticky_file = mount_dir.join("supervisor-file");
        let profile_file = workspace.join("profile-file");
        let check =
            |attack| boot_fixture(attack, &workspace, &mount_dir, &sticky_file, &profile_file);
        for attack in [
            "mount",
            "write-git",
            "write-past-fsize",
            "unlink-supervisor-file",
            "write-readonly-profile",
        ] {
            assert_eq!(check(attack), Err("launcher:probe-fixture-missing"));
        }
        std::fs::create_dir(&mount_dir).unwrap();
        std::fs::create_dir(workspace.join(".git")).unwrap();
        std::fs::write(&sticky_file, b"fixture").unwrap();
        std::fs::write(&profile_file, b"fixture").unwrap();
        for attack in [
            "mount",
            "write-git",
            "write-past-fsize",
            "unlink-supervisor-file",
            "write-readonly-profile",
        ] {
            assert_eq!(check(attack), Ok(()));
        }
        std::fs::write(mount_dir.join("file-size"), b"guest bytes").unwrap();
        std::fs::write(
            workspace.join(".git/.aukora-boot-probe-write"),
            b"guest bytes",
        )
        .unwrap();
        for attack in ["write-git", "write-past-fsize"] {
            assert_eq!(check(attack), Err("launcher:probe-fixture-collision"));
        }
        assert_eq!(
            std::fs::read(mount_dir.join("file-size")).unwrap(),
            b"guest bytes"
        );
        #[cfg(unix)]
        {
            std::fs::remove_file(&profile_file).unwrap();
            std::os::unix::fs::symlink(&sticky_file, &profile_file).unwrap();
            assert_eq!(
                check("write-readonly-profile"),
                Err("launcher:probe-fixture-missing")
            );
        }
    }
}
