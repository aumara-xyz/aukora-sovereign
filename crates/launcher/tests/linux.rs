#![cfg(target_os = "linux")]

use launcher::{launch, CgroupPolicy, IdentityPolicy, LaunchPolicy, ReadonlyBind};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const TEST_ENV: [&str; 5] = [
    "LAUNCHER_TEST_CGROUP",
    "LAUNCHER_TEST_WORKSPACE",
    "LAUNCHER_TEST_ROOT",
    "LAUNCHER_TEST_UID",
    "LAUNCHER_TEST_GID",
];

static LIVE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const NAMESPACES: [&str; 7] = ["user", "mnt", "pid", "net", "ipc", "uts", "cgroup"];

struct Fixture {
    workspace: PathBuf,
    root: PathBuf,
    secrets: PathBuf,
    readonly_bind: PathBuf,
    original_workspace_mode: u32,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in [
            ".git",
            "launcher-test-guest",
            "launcher-probe",
            "outside-link",
            "rename-source",
            "writable-control",
            "sticky",
            "supervisor-profile",
            "probe-file-size",
            ".aukora-boot-probe",
            ".aukora-boot-probes",
            "dsh",
        ] {
            let path = self.workspace.join(name);
            if path.is_dir() && !path.is_symlink() {
                let _ = fs::remove_dir_all(path);
            } else {
                let _ = fs::remove_file(path);
            }
        }
        let _ = fs::set_permissions(
            &self.workspace,
            fs::Permissions::from_mode(self.original_workspace_mode),
        );
        let _ = fs::remove_dir_all(&self.secrets);
        let _ = fs::remove_dir_all(&self.readonly_bind);
    }
}

fn required(name: &str) -> OsString {
    std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required for the Linux live test"))
}

fn require_static_probe() -> PathBuf {
    let path = PathBuf::from(required("LAUNCHER_TEST_PROBE"));
    let bytes = fs::read(&path).expect("LAUNCHER_TEST_PROBE must name the static Linux probe");
    assert!(bytes.len() >= 64);
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(&bytes[4..6], &[2, 1], "probe must be ELF64 little endian");
    let offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let entry_size = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let entry_count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    assert!(entry_size >= 4);
    assert!(offset + entry_size * entry_count <= bytes.len());
    for index in 0..entry_count {
        let start = offset + index * entry_size;
        let kind = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
        assert_ne!(
            kind, 3,
            "probe has PT_INTERP and must be rebuilt statically"
        );
    }
    path
}

fn fixture() -> Option<(Fixture, PathBuf, u32, u32)> {
    if TEST_ENV.iter().all(|key| std::env::var_os(key).is_none()) {
        eprintln!("UNPERFORMED launcher Linux live test: configure {TEST_ENV:?} with disposable directories and subordinate ids");
        return None;
    }
    let cgroup = PathBuf::from(required(TEST_ENV[0]));
    let workspace = fs::canonicalize(PathBuf::from(required(TEST_ENV[1])))
        .expect("workspace must already exist");
    let root =
        fs::canonicalize(PathBuf::from(required(TEST_ENV[2]))).expect("root must already exist");
    let uid = required(TEST_ENV[3])
        .into_string()
        .expect("uid is UTF-8")
        .parse()
        .expect("uid is u32");
    let gid = required(TEST_ENV[4])
        .into_string()
        .expect("gid is UTF-8")
        .parse()
        .expect("gid is u32");
    assert!(cgroup.is_absolute(), "cgroup must be an absolute path");
    assert_ne!(workspace, root, "root and workspace must differ");
    for path in [&workspace, &root] {
        assert!(
            fs::read_dir(path).unwrap().next().is_none(),
            "{} must be an empty disposable directory",
            path.display()
        );
    }
    let secrets = workspace
        .parent()
        .unwrap()
        .join(format!("launcher-host-secrets-{}", std::process::id()));
    let readonly_bind = workspace
        .parent()
        .unwrap()
        .join(format!("launcher-readonly-bind-{}", std::process::id()));
    fs::create_dir(&secrets).expect("a fresh host secret directory is required");
    fs::create_dir(&readonly_bind).expect("a fresh read-only bind directory is required");
    let original_workspace_mode = fs::metadata(&workspace).unwrap().permissions().mode();
    let fixture = Fixture {
        workspace,
        root,
        secrets,
        readonly_bind,
        original_workspace_mode,
    };
    fs::set_permissions(&fixture.workspace, fs::Permissions::from_mode(0o1777)).unwrap();
    fs::create_dir(fixture.workspace.join("sticky")).unwrap();
    fs::set_permissions(
        fixture.workspace.join("sticky"),
        fs::Permissions::from_mode(0o1777),
    )
    .unwrap();
    fs::write(
        fixture.workspace.join("sticky/supervisor-file"),
        b"supervisor file",
    )
    .unwrap();
    fs::write(
        fixture.workspace.join("supervisor-profile"),
        b"supervisor profile",
    )
    .unwrap();
    fs::set_permissions(
        fixture.workspace.join("supervisor-profile"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    fs::set_permissions(&fixture.secrets, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.readonly_bind, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        fixture.readonly_bind.join("readable"),
        b"read-only bind control",
    )
    .unwrap();
    fs::write(
        fixture.readonly_bind.join("executable.sh"),
        b"#!/bin/sh\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(
        fixture.readonly_bind.join("executable.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::create_dir(fixture.workspace.join(".git")).unwrap();
    fs::set_permissions(
        fixture.workspace.join(".git"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    for name in ["key", "database"] {
        let path = fixture.secrets.join(name);
        fs::write(&path, b"disposable host secret").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let git_file = fixture.workspace.join(".git/write-control");
    fs::write(&git_file, b"must stay read-only").unwrap();
    fs::set_permissions(git_file, fs::Permissions::from_mode(0o666)).unwrap();
    OpenOptions::new()
        .append(true)
        .open(fixture.workspace.join(".git/write-control"))
        .expect("unconfined .git write control must be allowed");
    fs::write(
        fixture.workspace.join("rename-source"),
        b"workspace control",
    )
    .unwrap();
    fs::set_permissions(
        fixture.workspace.join("rename-source"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    symlink(
        fixture.secrets.join("key"),
        fixture.workspace.join("outside-link"),
    )
    .unwrap();
    assert_eq!(
        fs::read(fixture.workspace.join("outside-link")).unwrap(),
        b"disposable host secret",
        "unconfined symlink control must reach the planted key"
    );
    for name in ["launcher-test-guest", ".git/exec-control"] {
        fs::copy(
            std::env::current_exe().unwrap(),
            fixture.workspace.join(name),
        )
        .unwrap();
        fs::set_permissions(
            fixture.workspace.join(name),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    assert!(Command::new(fixture.workspace.join(".git/exec-control"))
        .arg("--list")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unconfined .git execution control must execute")
        .success());
    Some((fixture, cgroup, uid, gid))
}

fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    // SAFETY: fds has room for the two descriptors returned by socketpair.
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    // SAFETY: socketpair returned two distinct owned descriptors.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    // SAFETY: fds has room for both descriptors produced by pipe2.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: pipe2 returned two distinct owned descriptors.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn abstract_listener(name: &str) -> OwnedFd {
    // SAFETY: socket has only integer arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0);
    // SAFETY: socket returned a new descriptor owned by this function.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    assert!(name.len() < address.sun_path.len() - 1);
    for (out, byte) in address.sun_path[1..].iter_mut().zip(name.bytes()) {
        *out = byte as libc::c_char;
    }
    // SAFETY: address is initialized and length includes its abstract name.
    assert_eq!(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                (std::mem::size_of::<libc::sa_family_t>() + name.len() + 1) as libc::socklen_t,
            )
        },
        0
    );
    // SAFETY: fd is a valid bound STREAM socket.
    assert_eq!(unsafe { libc::listen(fd.as_raw_fd(), 1) }, 0);
    fd
}

// FD 3 is a stream (CONTRACTS C4 v1.1), so this test's own messages are newline-delimited lines.
fn send(fd: RawFd, bytes: &[u8]) {
    let mut line = bytes.to_vec();
    line.push(b'\n');
    // SAFETY: line is a readable slice for the duration of send.
    assert_eq!(
        unsafe { libc::send(fd, line.as_ptr().cast(), line.len(), libc::MSG_NOSIGNAL) },
        line.len() as isize,
        "{}",
        io::Error::last_os_error()
    );
}

fn recv(fd: RawFd) -> String {
    let mut event = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: event points to one initialized pollfd.
    assert_eq!(
        unsafe { libc::poll(&mut event, 1, 15_000) },
        1,
        "guest timed out"
    );
    let mut line = Vec::new();
    loop {
        let mut byte = 0_u8;
        // SAFETY: byte is writable for the duration of recv.
        let count = unsafe { libc::recv(fd, (&mut byte as *mut u8).cast(), 1, 0) };
        assert!(count > 0, "guest closed the result channel");
        if byte == b'\n' {
            break;
        }
        line.push(byte);
        assert!(line.len() <= 1024, "line too long");
    }
    String::from_utf8(line).unwrap()
}

fn proc_text(pid: i32, name: &str) -> String {
    fs::read_to_string(format!("/proc/{pid}/{name}")).unwrap()
}

fn mount<'a>(mountinfo: &'a str, path: &str) -> (&'a str, &'a str) {
    mountinfo
        .lines()
        .find_map(|line| {
            let (before, after) = line.split_once(" - ").unwrap();
            let fields: Vec<_> = before.split_whitespace().collect();
            (fields[4] == path).then_some((fields[5], after))
        })
        .unwrap_or_else(|| panic!("missing {path} mount"))
}

fn assert_security_status(status: &str) {
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert_eq!(
            status
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}:")))
                .unwrap()
                .trim(),
            "0000000000000000",
            "{name} must be empty"
        );
    }
    for (name, value) in [("NoNewPrivs", "1"), ("Seccomp", "2")] {
        assert_eq!(
            status
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}:")))
                .unwrap()
                .trim(),
            value
        );
    }
}

fn assert_live_setup(pid: i32, cgroup: &Path) {
    assert_security_status(&proc_text(pid, "status"));
    let limits = proc_text(pid, "limits");
    for (name, value) in [
        ("Max open files", "1024"),
        ("Max core file size", "0"),
        ("Max file size", "268435456"),
    ] {
        let values: Vec<_> = limits
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(&values[..2], &[value, value]);
    }
    for (name, value) in [
        ("pids.max", "16"),
        ("memory.max", "134217728"),
        ("memory.swap.max", "0"),
        ("cpu.max", "10000 100000"),
    ] {
        assert_eq!(fs::read_to_string(cgroup.join(name)).unwrap().trim(), value);
    }
    assert!(fs::read_to_string(cgroup.join("cgroup.procs"))
        .unwrap()
        .lines()
        .any(|line| line == pid.to_string()));
}

fn assert_mount_setup(mountinfo: &str) {
    assert!(mount(mountinfo, "/").1.starts_with("tmpfs "));
    assert!(mount(mountinfo, "/workspace")
        .0
        .split(',')
        .any(|v| v == "rw"));
    for flag in ["ro", "nosuid", "nodev", "noexec"] {
        assert!(
            mount(mountinfo, "/workspace/.git")
                .0
                .split(',')
                .any(|v| v == flag),
            ".git lacks {flag}"
        );
    }
    for flag in ["ro", "nosuid", "nodev"] {
        assert!(
            mount(mountinfo, "/opt/aukora/runtime")
                .0
                .split(',')
                .any(|v| v == flag),
            "read-only bind lacks {flag}"
        );
    }
    assert!(
        mount(mountinfo, "/opt/aukora/runtime")
            .0
            .split(',')
            .all(|v| v != "noexec"),
        "read-only bind must remain executable"
    );
    let proc = mount(mountinfo, "/proc").1;
    assert!(proc.starts_with("proc "));
    assert!(proc.contains("hidepid=2") || proc.contains("hidepid=invisible"));
    for line in mountinfo.lines() {
        let (before, _) = line.split_once(" - ").unwrap();
        let fields: Vec<_> = before.split_whitespace().collect();
        assert!(
            fields[6..]
                .iter()
                .all(|v| !v.starts_with("shared:") && !v.starts_with("master:")),
            "mount propagation is not private"
        );
        if fields[4] == "/usr" || fields[4].starts_with("/usr/") {
            assert!(fields[5].split(',').any(|v| v == "ro"));
        }
        assert!(
            ["/", "/usr", "/workspace", "/opt", "/proc", "/dev", "/tmp"]
                .iter()
                .any(|root| fields[4] == *root
                    || (*root != "/" && fields[4].starts_with(&format!("{root}/")))),
            "unexpected surviving mount {}",
            fields[4]
        );
    }
}

fn assert_guest_network() {
    let dev = fs::read_to_string("/proc/self/net/dev").unwrap();
    let interfaces: Vec<_> = dev
        .lines()
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    assert_eq!(interfaces, ["lo"]);
    // A fresh network namespace has no IPv4 routes; kernels differ on whether the header line is printed.
    let routes = fs::read_to_string("/proc/self/net/route").unwrap();
    assert!(
        routes.lines().all(|line| line.starts_with("Iface")),
        "unexpected route in the guest network namespace: {routes}"
    );
}

fn null_stdio() -> [OwnedFd; 3] {
    std::array::from_fn(|_| {
        OwnedFd::from(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap(),
        )
    })
}

#[test]
fn linux_namespace_and_descriptor_boundary() {
    let _live_guard = LIVE_TEST_LOCK.lock().unwrap();
    let Some((fixture, cgroup, uid, gid)) = fixture() else {
        return;
    };
    let probe = require_static_probe();
    let leaked_secret = File::open(fixture.secrets.join("key")).unwrap();
    // SAFETY: F_DUPFD creates an owned duplicate that survives exec without close_range.
    let leaked_high = unsafe { libc::fcntl(leaked_secret.as_raw_fd(), libc::F_DUPFD, 128) };
    assert!(leaked_high >= 128);
    // SAFETY: fcntl returned a new owned descriptor.
    let _leaked_high = unsafe { OwnedFd::from_raw_fd(leaked_high) };
    let (parent, child) = socketpair();
    let listener_path = fixture.secrets.join("ui.sock");
    let listener = UnixListener::bind(&listener_path).unwrap();
    let mut env = vec![
        OsString::from("LAUNCHER_INTEGRATION_GUEST=1"),
        OsString::from(format!(
            "LAUNCHER_HOST_SECRETS={}",
            fixture.secrets.display()
        )),
        OsString::from("RUST_TEST_THREADS=1"),
    ];
    for name in NAMESPACES {
        let value = fs::read_link(format!("/proc/self/ns/{name}")).unwrap();
        env.push(OsString::from(format!(
            "LAUNCHER_HOST_NS_{name}={}",
            value.display()
        )));
    }
    let policy = LaunchPolicy {
        workspace: fixture.workspace.clone(),
        root: fixture.root.clone(),
        cgroup: CgroupPolicy {
            path: cgroup.clone(),
            pids_max: 16,
            memory_max: 134_217_728,
            cpu_max: "10000 100000".into(),
        },
        identity: IdentityPolicy {
            subordinate_uid: uid,
            subordinate_gid: gid,
            allow_development_own_id: false,
        },
        file_size_max_bytes: launcher::DEFAULT_FILE_SIZE_MAX_BYTES,
        executable: PathBuf::from("/workspace/launcher-test-guest"),
        argv: [
            "/workspace/launcher-test-guest",
            "--exact",
            "guest_setup",
            "--ignored",
            "--nocapture",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        env,
        readonly_binds: vec![ReadonlyBind {
            host: fixture.readonly_bind.clone(),
            guest: "/opt/aukora/runtime".into(),
        }],
        readonly_workspace_files: vec!["supervisor-profile".into()],
    };
    // A SEQPACKET pair is the wrong proposal type since contracts v1.1 (FD 3 is a length-prefixed stream).
    let mut wrong_pair = [-1; 2];
    // SAFETY: wrong_pair has room for the two descriptors socketpair returns.
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                wrong_pair.as_mut_ptr(),
            )
        },
        0
    );
    // SAFETY: socketpair returned two new descriptors.
    let (wrong, _wrong_peer) = unsafe {
        (
            OwnedFd::from_raw_fd(wrong_pair[0]),
            OwnedFd::from_raw_fd(wrong_pair[1]),
        )
    };
    let invalid_listener = UnixListener::bind(fixture.secrets.join("invalid-ui.sock")).unwrap();
    assert_eq!(
        launch(
            &policy,
            wrong,
            OwnedFd::from(invalid_listener),
            null_stdio()
        )
        .unwrap_err()
        .code,
        "launcher:invalid-socket"
    );
    let (_wrong_parent, wrong_proposal) = socketpair();
    let (wrong_ui, _wrong_ui_peer) = UnixStream::pair().unwrap();
    assert_eq!(
        launch(
            &policy,
            wrong_proposal,
            OwnedFd::from(wrong_ui),
            null_stdio()
        )
        .unwrap_err()
        .code,
        "launcher:invalid-socket"
    );
    let child = launch(&policy, child, OwnedFd::from(listener), null_stdio())
        .unwrap_or_else(|error| panic!("Linux launch refused: {error}"));
    assert!(child.pid > 0);
    assert_eq!(
        child.kernel_release,
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap()
            .trim()
    );
    // SAFETY: Landlock's VERSION query uses null/zero attributes and no output storage.
    let expected_abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    } as i32;
    assert_eq!(child.landlock_abi, expected_abi);
    assert!(child.landlock_abi >= 4);
    assert_eq!(child.seccomp_filter_hash.len(), 64);
    assert!(child
        .seccomp_filter_hash
        .bytes()
        .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)));
    assert_eq!(child.cgroup_path, cgroup);
    assert!(!child.development_own_id);
    for (name, id) in [("uid_map", uid), ("gid_map", gid)] {
        let values: Vec<u32> = proc_text(child.pid, name)
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(values, [0, id, 1], "identity must map one subordinate id");
    }
    assert_live_setup(child.pid, &cgroup);
    let _ui = UnixStream::connect(&listener_path).unwrap();
    send(parent.as_raw_fd(), b"host-to-guest");
    for name in [
        "fd3-stream",
        "fd4-stream-listener",
        "descriptors-closed",
        "identity",
        "fd3-receive",
        "fd4-accept",
        "namespace-state",
        "mount-state",
        "security-state",
        "network-state",
        "workspace-tmp-writable",
        "workspace-no-rendezvous",
        "workspace-executable",
        "git-noexec",
        "readonly-bind-readable",
        "readonly-bind-executable",
        "readonly-bind-read-only",
        "opt-write-refused",
        "planted-key",
        "planted-database",
        "planted-socket",
        "git-read-only",
        "symlink-escape",
        "hardlink-escape",
        "rename-escape",
        "usr-read-only",
        "dev-shm",
        "var-tmp",
        "dev-tty",
        "dev-mem",
        "dev-kmsg",
    ] {
        assert_eq!(recv(parent.as_raw_fd()), format!("{name}:ok"));
    }
    assert_eq!(child.wait().unwrap(), 0);
    assert_eq!(
        fs::read(fixture.workspace.join(".git/write-control")).unwrap(),
        b"must stay read-only"
    );
    assert_eq!(
        fs::read(fixture.secrets.join("key")).unwrap(),
        b"disposable host secret"
    );
    assert_eq!(
        fs::read(fixture.readonly_bind.join("readable")).unwrap(),
        b"read-only bind control"
    );
    // The hostile probe runs from the read-only bind, where the agent runtime's Node lives.
    fs::copy(probe, fixture.readonly_bind.join("launcher-probe")).unwrap();
    fs::set_permissions(
        fixture.readonly_bind.join("launcher-probe"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    run_hostile_probe(&policy, &fixture);
}

#[test]
fn antibody_guest_fsize_sticky_and_readonly_profile() {
    let _live_guard = LIVE_TEST_LOCK.lock().unwrap();
    // EFBIG, EPERM, EROFS; the subordinate guest cannot grow a file, unlink the supervisor, or rewrite its profile.
    let Some((fixture, cgroup, uid, gid)) = fixture() else {
        return;
    };
    fs::copy(
        require_static_probe(),
        fixture.readonly_bind.join("launcher-probe"),
    )
    .unwrap();
    fs::set_permissions(
        fixture.readonly_bind.join("launcher-probe"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut policy = LaunchPolicy {
        workspace: fixture.workspace.clone(),
        root: fixture.root.clone(),
        cgroup: CgroupPolicy {
            path: cgroup,
            pids_max: 16,
            memory_max: 134_217_728,
            cpu_max: "10000 100000".into(),
        },
        identity: IdentityPolicy {
            subordinate_uid: uid,
            subordinate_gid: gid,
            allow_development_own_id: false,
        },
        file_size_max_bytes: 1024,
        executable: "/opt/aukora/runtime/launcher-probe".into(),
        argv: vec![],
        env: vec!["AUKORA_PROBE_FILE_SIZE_MAX_BYTES=1024".into()],
        readonly_binds: vec![ReadonlyBind {
            host: fixture.readonly_bind.clone(),
            guest: "/opt/aukora/runtime".into(),
        }],
        readonly_workspace_files: vec!["supervisor-profile".into()],
    };
    for (attack, errno) in [
        ("write-past-fsize", libc::EFBIG),
        ("unlink-supervisor-file", libc::EPERM),
        ("write-readonly-profile", libc::EROFS),
    ] {
        policy.argv = vec![
            "/opt/aukora/runtime/launcher-probe".into(),
            "--confined".into(),
            format!("--only={attack}").into(),
        ];
        let (_parent, child_fd) = socketpair();
        let listener = UnixListener::bind(fixture.secrets.join(format!("{attack}.sock"))).unwrap();
        let (read, write) = pipe();
        let input = OwnedFd::from(File::open("/dev/null").unwrap());
        let error = OwnedFd::from(OpenOptions::new().write(true).open("/dev/null").unwrap());
        let child = launch(&policy, child_fd, listener.into(), [input, write, error]).unwrap();
        assert_eq!(child.wait().unwrap(), 0, "{attack} probe failed");
        let mut output = String::new();
        File::from(read).read_to_string(&mut output).unwrap();
        assert_eq!(
            output,
            format!("{{\"attack\":\"{attack}\",\"errno\":{errno},\"result\":\"refused\"}}\n")
        );
    }
    assert_eq!(
        fs::read(fixture.workspace.join("supervisor-profile")).unwrap(),
        b"supervisor profile"
    );
    assert!(fixture.workspace.join("sticky/supervisor-file").is_file());
}

#[test]
fn antibody_boot_probe_detects_weakened_readonly_policy() {
    let _live_guard = LIVE_TEST_LOCK.lock().unwrap();
    let Some((fixture, cgroup, uid, gid)) = fixture() else {
        return;
    };
    fs::create_dir(fixture.readonly_bind.join("guest")).unwrap();
    fs::copy(
        require_static_probe(),
        fixture.readonly_bind.join("guest/probe"),
    )
    .unwrap();
    fs::set_permissions(
        fixture.readonly_bind.join("guest/probe"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::create_dir_all(fixture.workspace.join("dsh/profiles/web")).unwrap();
    let profile = fixture.workspace.join("dsh/profiles/web/package.json");
    fs::write(&profile, b"disposable profile").unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o666)).unwrap();
    let probe_parent = fixture.workspace.join(".aukora-boot-probes");
    fs::create_dir(&probe_parent).unwrap();
    fs::set_permissions(&probe_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let probe_directory = probe_parent.join("probe-disposable");
    fs::create_dir(&probe_directory).unwrap();
    fs::set_permissions(&probe_directory, fs::Permissions::from_mode(0o1777)).unwrap();
    fs::write(
        probe_directory.join("supervisor-file"),
        b"disposable supervisor fixture",
    )
    .unwrap();
    let mut policy = LaunchPolicy {
        workspace: fixture.workspace.clone(),
        root: fixture.root.clone(),
        cgroup: CgroupPolicy {
            path: cgroup,
            pids_max: 16,
            memory_max: 134_217_728,
            cpu_max: "10000 100000".into(),
        },
        identity: IdentityPolicy {
            subordinate_uid: uid,
            subordinate_gid: gid,
            allow_development_own_id: false,
        },
        file_size_max_bytes: 1024,
        executable: "/opt/sovereign/guest/probe".into(),
        argv: vec!["unused production argv".into()],
        env: vec![],
        readonly_binds: vec![ReadonlyBind {
            host: fixture.readonly_bind.clone(),
            guest: "/opt/sovereign".into(),
        }],
        readonly_workspace_files: vec!["dsh/profiles/web/package.json".into()],
    };
    for weakened in [false, true] {
        if weakened {
            policy.readonly_workspace_files.clear();
        }
        let (_parent, guest) = socketpair();
        let listener =
            UnixListener::bind(fixture.secrets.join(format!("boot-probe-{weakened}.sock")))
                .unwrap();
        let execution = launcher::run_boot_probe(
            &policy,
            Path::new("/workspace/.aukora-boot-probes/probe-disposable"),
            guest,
            listener.into(),
        );
        assert!(execution.refusal.is_none(), "{:?}", execution.refusal);
        assert!(execution.setup.as_ref().is_some_and(
            |setup| setup.seccomp_filter_hash == launcher::seccomp_filter_hash().unwrap()
        ));
        let output = String::from_utf8(execution.output).unwrap();
        let lines: Vec<_> = output.lines().collect();
        // Error diagnostics from an unsuccessful probe are also captured and bounded.
        assert!(
            lines.len() >= launcher::BOOT_PROBE_ATTACKS.len(),
            "{output}"
        );
        let mut all_refused = true;
        for (line, attack) in lines.iter().zip(launcher::BOOT_PROBE_ATTACKS) {
            if let Some(reason) = attack.skip_reason {
                assert_eq!(*line, format!("{{\"attack\":\"{}\",\"errno\":null,\"reason\":\"{reason}\",\"result\":\"skipped\"}}", attack.name));
            } else if weakened && attack.name == "write-readonly-profile" {
                assert_eq!(*line, "{\"attack\":\"write-readonly-profile\",\"errno\":null,\"reason\":null,\"result\":\"allowed\"}");
                all_refused = false;
            } else {
                assert_eq!(
                    *line,
                    format!(
                        "{{\"attack\":\"{}\",\"errno\":{},\"reason\":null,\"result\":\"refused\"}}",
                        attack.name,
                        launcher::boot_probe_expected_errno(attack.name)
                            .map_or_else(|| "null".to_owned(), |errno| errno.to_string())
                    )
                );
            }
        }
        let mut starts = 0;
        if all_refused && execution.wait_status == Some(0) {
            starts += 1;
        }
        assert_eq!(starts, usize::from(!weakened));
    }
    eprintln!(
        "RAN launcher boot probe: production refusals pass; writable profile blocks start callback"
    );
}

fn run_hostile_probe(policy: &LaunchPolicy, fixture: &Fixture) {
    let abstract_name = format!("aukora-launcher-test-{}", std::process::id());
    let _abstract = abstract_listener(&abstract_name);
    let _control = UnixStream::connect_addr(
        &SocketAddr::from_abstract_name(abstract_name.as_bytes()).unwrap(),
    )
    .expect("host abstract-socket control must connect");
    let mut policy = policy.clone();
    policy.executable = PathBuf::from("/opt/aukora/runtime/launcher-probe");
    policy.argv = ["/opt/aukora/runtime/launcher-probe", "--confined"]
        .into_iter()
        .map(OsString::from)
        .collect();
    let probe_byte = 0x5a_u8;
    let network_namespace = fs::metadata("/proc/self/ns/net").unwrap();
    policy.env = vec![
        OsString::from(format!(
            "AUKORA_PROBE_SUPERVISOR_NET_NAMESPACE={}:{}",
            network_namespace.dev(),
            network_namespace.ino()
        )),
        OsString::from(format!(
            "AUKORA_PROBE_KEY_PATH={}",
            fixture.secrets.join("key").display()
        )),
        OsString::from(format!(
            "AUKORA_PROBE_DB_PATH={}",
            fixture.secrets.join("database").display()
        )),
        OsString::from(format!(
            "AUKORA_PROBE_SOCKET_PATH={}",
            fixture.secrets.join("ui.sock").display()
        )),
        OsString::from(format!(
            "AUKORA_PROBE_ESCAPE_DIR={}",
            fixture.secrets.display()
        )),
        OsString::from(format!("AUKORA_PROBE_ABSTRACT_NAME={abstract_name}")),
        OsString::from(format!("AUKORA_PROBE_OUTSIDE_PID={}", std::process::id())),
        OsString::from(format!(
            "AUKORA_PROBE_VM_ADDRESS={}",
            &probe_byte as *const u8 as usize
        )),
        OsString::from(format!(
            "AUKORA_PROBE_FILE_SIZE_MAX_BYTES={}",
            policy.file_size_max_bytes
        )),
        OsString::from("AUKORA_PROBE_MEMORY_MIB=256"),
        OsString::from("AUKORA_PROBE_FORK_LIMIT=64"),
    ];
    if let Some(path) = std::env::var_os("LAUNCHER_TEST_SETUID_HELPER") {
        let mut entry = OsString::from("AUKORA_PROBE_SETUID_HELPER=");
        entry.push(path);
        policy.env.push(entry);
    } else {
        eprintln!("UNPERFORMED setuid escalation control: install the probe helper under /usr and configure LAUNCHER_TEST_SETUID_HELPER; an absent helper only proves path refusal");
    }
    let (_parent, child_fd) = socketpair();
    let listener = UnixListener::bind(fixture.secrets.join("probe-ui.sock")).unwrap();
    let (output_read, output_write) = pipe();
    let input = OwnedFd::from(File::open("/dev/null").unwrap());
    let error = OwnedFd::from(OpenOptions::new().write(true).open("/dev/null").unwrap());
    let before_pids_max = event_count(&policy.cgroup.path.join("pids.events"), "max");
    let before_memory_max = event_count(&policy.cgroup.path.join("memory.events"), "max");
    let before_oom_kill = event_count(&policy.cgroup.path.join("memory.events"), "oom_kill");
    let child = launch(
        &policy,
        child_fd,
        OwnedFd::from(listener),
        [input, output_write, error],
    )
    .unwrap_or_else(|error| panic!("hostile probe launch refused: {error}"));
    assert_eq!(child.wait().unwrap(), 0, "hostile probe did not finish");
    assert!(
        event_count(&policy.cgroup.path.join("pids.events"), "max") > before_pids_max,
        "fork probe did not hit the configured pids.max"
    );
    assert!(
        event_count(&policy.cgroup.path.join("memory.events"), "max") > before_memory_max,
        "memory probe did not hit the configured memory.max"
    );
    assert!(
        event_count(&policy.cgroup.path.join("memory.events"), "oom_kill") > before_oom_kill,
        "memory probe was not killed by the configured memory.max"
    );
    let mut output = String::new();
    File::from(output_read).read_to_string(&mut output).unwrap();
    let expected = [
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
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), expected.len(), "{output}");
    for (line, attack) in lines.into_iter().zip(expected) {
        let errno = line
            .strip_prefix(&format!("{{\"attack\":\"{attack}\",\"errno\":"))
            .and_then(|line| line.strip_suffix(",\"result\":\"refused\"}"))
            .unwrap_or_else(|| panic!("attack was allowed or output was not canonical: {line}"));
        assert!(
            errno == "null"
                || errno
                    .parse::<i32>()
                    .is_ok_and(|value| value > 0 && value.to_string() == errno),
            "invalid canonical errno: {line}"
        );
    }
    eprintln!("RAN launcher hostile probe: 42 canonical refusals; full privileged unconfined controls are a separate Nebius acceptance step");
}

fn event_count(path: &Path, name: &str) -> u64 {
    let text = fs::read_to_string(path).unwrap();
    let mut found = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 2, "malformed cgroup event line: {line}");
        if fields[0] == name {
            assert!(found.is_none(), "duplicate cgroup event {name}");
            found = Some(fields[1].parse().expect("cgroup event count must be u64"));
        }
    }
    found.unwrap_or_else(|| panic!("{} has no {name} event", path.display()))
}

fn sockopt(fd: RawFd, option: i32) -> i32 {
    let mut value: i32 = -1;
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: value and size are writable, and value has the requested integer size.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut i32).cast(),
                &mut size,
            )
        },
        0
    );
    value
}

fn unix_socket(fd: RawFd) -> bool {
    let mut addr: libc::sockaddr_storage = unsafe {
        // SAFETY: sockaddr_storage accepts an all-zero initialization.
        std::mem::zeroed()
    };
    let mut size = std::mem::size_of_val(&addr) as libc::socklen_t;
    // SAFETY: addr and size are writable and correctly sized.
    unsafe {
        libc::getsockname(
            fd,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut size,
        ) == 0
            && addr.ss_family == libc::AF_UNIX as libc::sa_family_t
    }
}

fn report(name: &str, ok: bool) {
    send(
        3,
        format!("{name}:{}", if ok { "ok" } else { "FAIL" }).as_bytes(),
    );
}

fn open_refused(path: &Path, flags: i32) -> bool {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: path is a terminated path and mode is provided for O_CREAT.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
    if fd < 0 {
        true
    } else {
        // SAFETY: open returned a descriptor owned by this function.
        unsafe { libc::close(fd) };
        false
    }
}

#[test]
#[ignore = "executed only as the confined guest by linux_namespace_and_descriptor_boundary"]
fn guest_setup() {
    assert_eq!(
        std::env::var("LAUNCHER_INTEGRATION_GUEST").as_deref(),
        Ok("1")
    );
    let fd3_ok = sockopt(3, libc::SO_TYPE) == libc::SOCK_STREAM && unix_socket(3);
    let fd4_ok = sockopt(4, libc::SO_TYPE) == libc::SOCK_STREAM
        && sockopt(4, libc::SO_ACCEPTCONN) == 1
        && unix_socket(4);
    let closed = (5..1024).all(|fd| {
        // SAFETY: F_GETFD only inspects the integer descriptor.
        unsafe { libc::fcntl(fd, libc::F_GETFD) < 0 }
    });
    // SAFETY: these identity queries have no pointer arguments.
    let identity = unsafe { libc::getuid() == 0 && libc::getgid() == 0 && libc::getpid() == 1 };
    report("fd3-stream", fd3_ok);
    report("fd4-stream-listener", fd4_ok);
    report("descriptors-closed", closed);
    report("identity", identity);
    report("fd3-receive", recv(3) == "host-to-guest");
    // SAFETY: null address pointers request accepting without address output.
    let accepted = unsafe {
        libc::accept4(
            4,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    report("fd4-accept", accepted >= 5);
    if accepted >= 0 {
        // SAFETY: accept4 returned a descriptor owned by this function.
        unsafe { libc::close(accepted) };
    }
    for name in NAMESPACES {
        let host = PathBuf::from(std::env::var_os(format!("LAUNCHER_HOST_NS_{name}")).unwrap());
        let guest = fs::read_link(format!("/proc/self/ns/{name}")).unwrap();
        assert_ne!(host, guest, "{name} namespace was inherited");
    }
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uts points to writable utsname storage.
    assert_eq!(unsafe { libc::uname(uts.as_mut_ptr()) }, 0);
    // SAFETY: uname initialized uts and nodename is NUL-terminated.
    let nodename = unsafe { std::ffi::CStr::from_ptr(uts.assume_init().nodename.as_ptr()) };
    assert_eq!(
        nodename.to_bytes(),
        b"aukora",
        "the guest must not see the host name"
    );
    report("namespace-state", true);
    assert_mount_setup(&fs::read_to_string("/proc/self/mountinfo").unwrap());
    report("mount-state", true);
    assert_security_status(&fs::read_to_string("/proc/self/status").unwrap());
    report("security-state", true);
    assert_guest_network();
    report("network-state", true);
    report(
        "workspace-tmp-writable",
        fs::write("/workspace/writable-control", b"workspace control").is_ok()
            && fs::write("/tmp/writable-control", b"tmp control").is_ok(),
    );
    // No socket or FIFO files in the host-shared workspace (Landlock refuses the socket
    // inode; seccomp already refuses mknod for FIFOs); the private /tmp still allows sockets.
    // A datagram bind creates the inode without listen(2), which only FD 4 may call.
    let workspace_socket = std::os::unix::net::UnixDatagram::bind("/workspace/rendezvous.sock")
        .is_err_and(|error| error.raw_os_error() == Some(libc::EACCES));
    let workspace_fifo = {
        // SAFETY: the path is a static NUL-terminated string.
        let result = unsafe { libc::mkfifo(c"/workspace/rendezvous.fifo".as_ptr(), 0o600) };
        result != 0 && !Path::new("/workspace/rendezvous.fifo").exists()
    };
    let tmp_socket = std::os::unix::net::UnixDatagram::bind("/tmp/private.sock").is_ok();
    report(
        "workspace-no-rendezvous",
        workspace_socket && workspace_fifo && tmp_socket,
    );
    report(
        "workspace-executable",
        Command::new("/workspace/launcher-test-guest")
            .arg("--list")
            .status()
            .is_ok_and(|status| status.success()),
    );
    report(
        "git-noexec",
        Command::new("/workspace/.git/exec-control")
            .arg("--list")
            .status()
            .is_err_and(|error| error.raw_os_error() == Some(libc::EACCES)),
    );
    report(
        "readonly-bind-readable",
        fs::read("/opt/aukora/runtime/readable")
            .is_ok_and(|bytes| bytes == b"read-only bind control"),
    );
    report(
        "readonly-bind-executable",
        Command::new("/opt/aukora/runtime/executable.sh")
            .status()
            .is_ok_and(|status| status.success()),
    );
    report(
        "readonly-bind-read-only",
        open_refused(
            Path::new("/opt/aukora/runtime/readable"),
            libc::O_WRONLY | libc::O_APPEND,
        ),
    );
    report(
        "opt-write-refused",
        open_refused(
            Path::new("/opt/launcher-write-control"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
    );
    let secrets = PathBuf::from(std::env::var_os("LAUNCHER_HOST_SECRETS").unwrap());
    for (name, path, flags) in [
        ("planted-key", secrets.join("key"), libc::O_RDONLY),
        ("planted-database", secrets.join("database"), libc::O_RDONLY),
        ("planted-socket", secrets.join("ui.sock"), libc::O_RDONLY),
        (
            "git-read-only",
            PathBuf::from("/workspace/.git/write-control"),
            libc::O_WRONLY | libc::O_APPEND,
        ),
        (
            "symlink-escape",
            PathBuf::from("/workspace/outside-link"),
            libc::O_RDONLY,
        ),
    ] {
        report(name, open_refused(&path, flags));
    }
    report(
        "hardlink-escape",
        fs::hard_link(secrets.join("key"), "/workspace/escaped-hardlink").is_err(),
    );
    report(
        "rename-escape",
        fs::rename(
            "/workspace/rename-source",
            secrets.join("rename-destination"),
        )
        .is_err(),
    );
    for (name, path, flags) in [
        (
            "usr-read-only",
            "/usr/launcher-write-control",
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "dev-shm",
            "/dev/shm/launcher-write-control",
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "var-tmp",
            "/var/tmp/launcher-write-control",
            libc::O_WRONLY | libc::O_CREAT,
        ),
        ("dev-tty", "/dev/tty", libc::O_RDONLY),
        ("dev-mem", "/dev/mem", libc::O_RDONLY),
        ("dev-kmsg", "/dev/kmsg", libc::O_RDONLY),
    ] {
        report(name, open_refused(Path::new(path), flags));
    }
}
