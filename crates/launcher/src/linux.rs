//! Child code uses preallocated data and raw syscalls until exec.

use crate::boot_probe::{append_probe_output, probe_poll_budget as poll_budget};
use crate::requirements::*;
use crate::{seccomp, LaunchPolicy, LaunchResult, Refusal};
use std::ffi::{CStr, CString};
use std::fs;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

const CODES: [&str; 15] = [
    "launcher:child-sync",
    "launcher:parent-death",
    "launcher:mounts",
    "launcher:network",
    "launcher:rlimits",
    "launcher:no-new-privs",
    "launcher:capabilities",
    "launcher:landlock",
    "launcher:seccomp",
    "launcher:descriptors",
    "launcher:close-range",
    "launcher:stdio",
    "launcher:exec",
    "launcher:child-failed",
    "launcher:setup-timeout",
];

struct Prepared {
    root: CString,
    // Bind sources as absolute paths plus the index of the descriptor pinned in the parent. A
    // /proc/self/fd path opened before the new mount namespace names the parent's mounts and
    // mount(2) refuses it (EINVAL), so the child re-opens each path and requires the same inode.
    workspace: (CString, usize),
    git: (CString, usize),
    git_destination: CString,
    usr: (CString, usize),
    directories: Vec<CString>,
    readonly_bind_directories: Vec<CString>,
    readonly_binds: Vec<PreparedReadonlyBind>,
    readonly_workspace_files: Vec<PreparedWorkspaceFile>,
    probe_fixture: Option<PreparedProbeFixture>,
    file_size_max_bytes: u64,
    devices: Vec<((CString, usize), CString)>,
    aliases: Vec<(CString, CString)>,
    executable: CString,
    _argv: Vec<CString>,
    _env: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    env: Vec<*const libc::c_char>,
    filter: seccompiler::BpfProgram,
    fds: [OwnedFd; 5],
    _paths: Vec<OwnedFd>,
}

struct PreparedReadonlyBind {
    source: (CString, usize),
    destination: CString,
    guest: CString,
}

struct PreparedWorkspaceFile {
    source: (CString, usize),
    components: Vec<CString>,
}

struct PreparedProbeFixture {
    source: (CString, usize),
    parent_index: usize,
    parent_name: CString,
    destination: CString,
}

fn cstring(bytes: &[u8]) -> Result<CString, Refusal> {
    CString::new(bytes).map_err(|_| Refusal::new("launcher:invalid-string"))
}

fn pin(path: &Path, directory: bool) -> Result<OwnedFd, Refusal> {
    let mut at = owned_open(c"/", libc::O_PATH | libc::O_DIRECTORY)?;
    for component in path.components().skip(1) {
        let name = cstring(component.as_os_str().as_bytes())?;
        // SAFETY: the component is NUL-terminated and at is an owned directory descriptor.
        let fd = unsafe {
            libc::openat(
                at.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Refusal::io("launcher:path-open"));
        }
        // SAFETY: fd is a newly returned descriptor.
        at = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut stat = mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat points to writable storage and at is valid.
        if unsafe { libc::fstat(at.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(Refusal::io("launcher:path-stat"));
        }
        // SAFETY: fstat initialized stat on success.
        if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(Refusal::new("launcher:symlink-path"));
        }
    }
    if directory {
        let mut stat = mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat is writable and at is valid.
        if unsafe { libc::fstat(at.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(Refusal::io("launcher:path-stat"));
        }
        // SAFETY: fstat initialized stat on success.
        if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(Refusal::new("launcher:not-directory"));
        }
    }
    Ok(at)
}

fn owned_open(path: &CStr, flags: i32) -> Result<OwnedFd, Refusal> {
    // SAFETY: path is NUL-terminated, flags do not create a file.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(Refusal::io("launcher:open"));
    }
    // SAFETY: open returned a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn duplicate(fd: RawFd) -> Result<OwnedFd, Refusal> {
    duplicate_from(fd, 10)
}

fn duplicate_from(fd: RawFd, minimum: i32) -> Result<OwnedFd, Refusal> {
    // SAFETY: fcntl duplicates an existing descriptor to avoid FD 0..4 collisions.
    let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    if fd < 0 {
        return Err(Refusal::io("launcher:descriptor-duplicate"));
    }
    // SAFETY: fcntl returned a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn socket_check(fd: RawFd, kind: i32, listener: bool) -> Result<(), Refusal> {
    for (option, expected) in [
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, kind),
        (libc::SO_ACCEPTCONN, i32::from(listener)),
    ] {
        let mut value: i32 = 0;
        let mut size = mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: getsockopt receives correctly sized output storage.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut i32).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(Refusal::io("launcher:invalid-socket"));
        }
        if value != expected {
            return Err(Refusal::new("launcher:invalid-socket"));
        }
    }
    if !listener {
        let mut address = mem::MaybeUninit::<libc::sockaddr_un>::uninit();
        let mut length = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // SAFETY: getpeername receives writable sockaddr storage of the specified size.
        if unsafe { libc::getpeername(fd, address.as_mut_ptr().cast(), &mut length) } != 0 {
            return Err(Refusal::io("launcher:proposal-not-connected"));
        }
        if length as usize != mem::size_of::<libc::sa_family_t>() {
            return Err(Refusal::new("launcher:proposal-not-socketpair"));
        }
    } else {
        let mut address = mem::MaybeUninit::<libc::sockaddr_un>::uninit();
        let mut length = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        // SAFETY: getsockname receives writable sockaddr_un storage.
        if unsafe { libc::getsockname(fd, address.as_mut_ptr().cast(), &mut length) } != 0 {
            return Err(Refusal::io("launcher:invalid-socket"));
        }
        // SAFETY: getsockname initialized address; a filesystem listener has a nonzero first path byte.
        if length as usize <= mem::size_of::<libc::sa_family_t>()
            || unsafe { address.assume_init() }.sun_path[0] == 0
        {
            return Err(Refusal::new("launcher:ui-not-filesystem-listener"));
        }
    }
    Ok(())
}

fn prepare(
    policy: &LaunchPolicy,
    fds: [OwnedFd; 5],
    fixture_directory: Option<&Path>,
) -> Result<Prepared, Refusal> {
    let mut paths = vec![
        pin(&policy.root, true)?,
        pin(&policy.workspace, true)?,
        pin(&policy.workspace.join(".git"), true)?,
        pin(Path::new("/usr"), true)?,
    ];
    let absolute = |path: &Path| cstring(path.as_os_str().as_bytes());
    let root = cstring(policy.root.as_os_str().as_bytes())?;
    let workspace = (absolute(&policy.workspace)?, 1);
    let git = (absolute(&policy.workspace.join(".git"))?, 2);
    let usr = (absolute(Path::new("/usr"))?, 3);
    let directories = ["usr", "workspace", "proc", "dev", "tmp", ".oldroot"]
        .iter()
        .map(|name| cstring(policy.root.join(name).as_os_str().as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut bind_directories = Vec::new();
    if !policy.readonly_binds.is_empty() {
        bind_directories.push(policy.root.join("opt"));
    }
    let mut readonly_binds = Vec::with_capacity(policy.readonly_binds.len());
    for bind in &policy.readonly_binds {
        paths.push(pin(&bind.host, true)?);
        let source = (absolute(&bind.host)?, paths.len() - 1);
        let mut destination = policy.root.clone();
        for component in bind.guest.components().skip(1) {
            destination.push(component);
            if !bind_directories.contains(&destination) {
                bind_directories.push(destination.clone());
            }
        }
        readonly_binds.push(PreparedReadonlyBind {
            source,
            destination: cstring(destination.as_os_str().as_bytes())?,
            guest: absolute(&bind.guest)?,
        });
    }
    let mut readonly_workspace_files = Vec::with_capacity(policy.readonly_workspace_files.len());
    // SAFETY: geteuid has no pointer arguments.
    let supervisor_uid = unsafe { libc::geteuid() };
    for relative in &policy.readonly_workspace_files {
        let host = policy.workspace.join(relative);
        let fd = pin(&host, false)?;
        let metadata = fs::File::from(duplicate(fd.as_raw_fd())?)
            .metadata()
            .map_err(|_| Refusal::io("launcher:path-stat"))?;
        validate_workspace_file(&metadata, supervisor_uid)?;
        paths.push(fd);
        readonly_workspace_files.push(PreparedWorkspaceFile {
            source: (absolute(&host)?, paths.len() - 1),
            components: relative
                .components()
                .map(|part| cstring(part.as_os_str().as_bytes()))
                .collect::<Result<_, _>>()?,
        });
    }
    let readonly_bind_directories = bind_directories
        .into_iter()
        .map(|path| cstring(path.as_os_str().as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let probe_fixture = if let Some(guest) = fixture_directory {
        let relative = guest
            .strip_prefix("/workspace")
            .map_err(|_| Refusal::new("launcher:probe-fixture-path"))?;
        if relative.starts_with(".aukora-boot-probes") {
            if !normalized_relative(relative) || relative.components().count() != 2 {
                return Err(Refusal::new("launcher:probe-fixture-path"));
            }
            let parent = policy.workspace.join(".aukora-boot-probes");
            let host = policy.workspace.join(relative);
            paths.push(pin(&parent, true)?);
            let parent_index = paths.len() - 1;
            let metadata = fs::File::from(duplicate(paths[parent_index].as_raw_fd())?)
                .metadata()
                .map_err(|_| Refusal::io("launcher:probe-fixture-parent"))?;
            if metadata.uid() != supervisor_uid || metadata.mode() & 0o7777 != 0o700 {
                return Err(Refusal::new("launcher:probe-fixture-parent"));
            }
            paths.push(pin(&host, true)?);
            let source = (absolute(&host)?, paths.len() - 1);
            Some(PreparedProbeFixture {
                source,
                parent_index,
                parent_name: cstring(b".aukora-boot-probes")?,
                destination: absolute(&policy.root.join("workspace").join(relative))?,
            })
        } else {
            None
        }
    } else {
        None
    };
    let mut devices = Vec::new();
    for name in ["null", "zero", "urandom", "full"] {
        paths.push(pin(&Path::new("/dev").join(name), false)?);
        devices.push((
            (absolute(&Path::new("/dev").join(name))?, paths.len() - 1),
            cstring(policy.root.join("dev").join(name).as_os_str().as_bytes())?,
        ));
    }
    let aliases = [
        ("usr/bin", "bin"),
        ("usr/lib", "lib"),
        ("usr/lib64", "lib64"),
    ]
    .into_iter()
    .map(|(source, dest)| {
        Ok((
            cstring(source.as_bytes())?,
            cstring(policy.root.join(dest).as_os_str().as_bytes())?,
        ))
    })
    .collect::<Result<_, Refusal>>()?;
    let argv = policy
        .argv
        .iter()
        .map(|arg| cstring(arg.as_os_str().as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let env = policy
        .env
        .iter()
        .map(|arg| cstring(arg.as_os_str().as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let pointers = |items: &[CString]| {
        items
            .iter()
            .map(|arg| arg.as_ptr())
            .chain([ptr::null()])
            .collect()
    };
    Ok(Prepared {
        root,
        workspace,
        git,
        git_destination: cstring(policy.root.join("workspace/.git").as_os_str().as_bytes())?,
        usr,
        directories,
        readonly_bind_directories,
        readonly_binds,
        readonly_workspace_files,
        probe_fixture,
        file_size_max_bytes: policy.file_size_max_bytes,
        devices,
        aliases,
        executable: cstring(policy.executable.as_os_str().as_bytes())?,
        argv: pointers(&argv),
        env: pointers(&env),
        _argv: argv,
        _env: env,
        filter: seccomp::build()?,
        fds,
        _paths: paths,
    })
}

fn pipe() -> Result<[OwnedFd; 2], Refusal> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to storage for two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Refusal::io("launcher:pipe"));
    }
    // SAFETY: pipe2 returned two new descriptors.
    let originals = unsafe { [OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])] };
    Ok([
        duplicate_from(originals[0].as_raw_fd(), 64)?,
        duplicate_from(originals[1].as_raw_fd(), 64)?,
    ])
}

fn read_packet(fd: RawFd, deadline: Option<Instant>) -> Result<Option<[i32; 2]>, Refusal> {
    let mut event = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: poll receives one valid pollfd.
        let result = unsafe { libc::poll(&mut event, 1, poll_budget(deadline, 15000)?) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if result <= 0 {
            return Err(Refusal::new(if deadline.is_some() {
                "launcher:probe-timeout"
            } else {
                "launcher:setup-timeout"
            }));
        }
        let mut packet = [0i32; 2];
        // SAFETY: packet is writable storage for eight bytes.
        let count = unsafe { libc::read(fd, packet.as_mut_ptr().cast(), 8) };
        if count == 0 {
            return Ok(None);
        }
        if count < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if count != 8 {
            return Err(Refusal::new("launcher:child-sync"));
        }
        if packet[0] < 0 {
            let index = (-packet[0] - 1) as usize;
            return Err(Refusal {
                code: CODES.get(index).copied().unwrap_or("launcher:child-failed"),
                errno: Some(packet[1]),
            });
        }
        return Ok(Some(packet));
    }
}

fn release(fd: RawFd) -> Result<(), Refusal> {
    // SAFETY: the literal byte buffer is readable for one byte.
    if unsafe { libc::write(fd, b"Y".as_ptr().cast(), 1) } != 1 {
        return Err(Refusal::io("launcher:child-sync"));
    }
    Ok(())
}

fn map_identity(
    policy: &LaunchPolicy,
    pid: i32,
    uid: u32,
    gid: u32,
    deadline: Option<Instant>,
) -> Result<bool, Refusal> {
    #[cfg(not(debug_assertions))]
    let _ = (uid, gid);
    let proc = Path::new("/proc").join(pid.to_string());
    fs::write(proc.join("setgroups"), "deny").map_err(|_| Refusal::io("launcher:setgroups"))?;
    #[cfg(debug_assertions)]
    let direct = |id_uid, id_gid| {
        fs::write(proc.join("uid_map"), format!("0 {id_uid} 1\n"))
            .map_err(|_| Refusal::io("launcher:uid-map"))?;
        fs::write(proc.join("gid_map"), format!("0 {id_gid} 1\n"))
            .map_err(|_| Refusal::io("launcher:gid-map"))
    };
    #[cfg(debug_assertions)]
    if policy.identity.allow_development_own_id
        && policy.identity.subordinate_uid == uid
        && policy.identity.subordinate_gid == gid
    {
        direct(uid, gid)?;
        return Ok(true);
    }
    let helper = |name: &str, id: u32| -> Result<bool, Refusal> {
        let mut command = Command::new(name);
        command
            .args([pid.to_string(), "0".into(), id.to_string(), "1".into()])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if deadline.is_none() {
            return Ok(command.status().is_ok_and(|status| status.success()));
        }
        poll_budget(deadline, 1)?;
        let Ok(mut child) = command.spawn() else {
            return Ok(false);
        };
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status.success()),
                Ok(None) => {}
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(false);
                }
            }
            if let Err(error) = poll_budget(deadline, 1) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    if !helper("/usr/bin/newuidmap", policy.identity.subordinate_uid)? {
        #[cfg(debug_assertions)]
        if policy.identity.allow_development_own_id
            && fs::read_to_string(proc.join("uid_map")).is_ok_and(|map| map.trim().is_empty())
        {
            direct(uid, gid)?;
            return Ok(true);
        }
        return Err(Refusal::new("launcher:uid-map"));
    }
    if !helper("/usr/bin/newgidmap", policy.identity.subordinate_gid)? {
        return Err(Refusal::new("launcher:gid-map"));
    }
    Ok(false)
}

fn cgroup(policy: &LaunchPolicy, pid: i32) -> Result<(), Refusal> {
    let directory = pin(&policy.cgroup.path, true)?;
    let mut stat = mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: stat is writable storage and directory is valid.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(Refusal::io("launcher:cgroup-stat"));
    }
    // SAFETY: fstatfs initialized stat.
    if unsafe { stat.assume_init() }.f_type != 0x63677270 {
        return Err(Refusal::new("launcher:cgroup-not-v2"));
    }
    let base = Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string());
    if !fs::read_to_string(base.join("cgroup.procs"))
        .map_err(|_| Refusal::io("launcher:cgroup-read"))?
        .trim()
        .is_empty()
    {
        return Err(Refusal::new("launcher:cgroup-not-empty"));
    }
    for (name, value) in [
        ("pids.max", policy.cgroup.pids_max.to_string()),
        ("memory.max", policy.cgroup.memory_max.to_string()),
        ("memory.swap.max", "0".into()),
        ("cpu.max", policy.cgroup.cpu_max.clone()),
        ("cgroup.procs", pid.to_string()),
    ] {
        fs::write(base.join(name), value).map_err(|_| Refusal::io("launcher:cgroup-write"))?;
    }
    Ok(())
}

pub(crate) fn launch(
    policy: &LaunchPolicy,
    proposal: OwnedFd,
    ui: OwnedFd,
    stdio: [OwnedFd; 3],
) -> Result<LaunchResult, Refusal> {
    launch_deadline(policy, proposal, ui, stdio, None, None)
}

fn launch_deadline(
    policy: &LaunchPolicy,
    proposal: OwnedFd,
    ui: OwnedFd,
    stdio: [OwnedFd; 3],
    deadline: Option<Instant>,
    fixture_directory: Option<&Path>,
) -> Result<LaunchResult, Refusal> {
    poll_budget(deadline, 1)?;
    // SAFETY: getuid/getgid have no pointer arguments.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    validate(policy, uid, gid)?;
    let metadata =
        fs::symlink_metadata(&policy.root).map_err(|_| Refusal::io("launcher:root-stat"))?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || fs::read_dir(&policy.root)
            .map_err(|_| Refusal::io("launcher:root-read"))?
            .next()
            .is_some()
    {
        return Err(Refusal::new("launcher:root-not-private-empty"));
    }
    socket_check(proposal.as_raw_fd(), libc::SOCK_STREAM, false)?;
    socket_check(ui.as_raw_fd(), libc::SOCK_STREAM, true)?;
    for (index, fd) in stdio.iter().enumerate() {
        let mut info = mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fd is owned and info points to writable stat storage.
        if unsafe { libc::fstat(fd.as_raw_fd(), info.as_mut_ptr()) } != 0 {
            return Err(Refusal::io("launcher:invalid-stdio"));
        }
        // SAFETY: fstat initialized info on success.
        let info = unsafe { info.assume_init() };
        let kind = info.st_mode & libc::S_IFMT;
        if kind != libc::S_IFIFO && !(kind == libc::S_IFCHR && info.st_rdev == libc::makedev(1, 3))
        {
            return Err(Refusal::new("launcher:invalid-stdio"));
        }
        // SAFETY: F_GETFL takes only the owned descriptor and scalar command.
        let mode = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if mode < 0
            || (index == 0 && mode & libc::O_ACCMODE == libc::O_WRONLY)
            || (index != 0 && mode & libc::O_ACCMODE == libc::O_RDONLY)
        {
            return Err(Refusal::new("launcher:invalid-stdio"));
        }
    }
    let host_executable = if let Ok(relative) = policy.executable.strip_prefix("/workspace") {
        if relative.starts_with(".git") {
            return Err(Refusal::new("launcher:git-executable"));
        }
        policy.workspace.join(relative)
    } else if let Some((bind, relative)) = policy.readonly_binds.iter().find_map(|bind| {
        policy
            .executable
            .strip_prefix(&bind.guest)
            .ok()
            .map(|relative| (bind, relative))
    }) {
        // An executable inside a read-only bind (the agent runtime's Node) is checked on the host side.
        bind.host.join(relative)
    } else {
        policy.executable.clone()
    };
    let executable =
        fs::metadata(host_executable).map_err(|_| Refusal::io("launcher:executable"))?;
    if !executable.is_file() || executable.mode() & 0o111 == 0 {
        return Err(Refusal::new("launcher:executable"));
    }
    let prepared = prepare(
        policy,
        [
            duplicate(proposal.as_raw_fd())?,
            duplicate(ui.as_raw_fd())?,
            duplicate(stdio[0].as_raw_fd())?,
            duplicate(stdio[1].as_raw_fd())?,
            duplicate(stdio[2].as_raw_fd())?,
        ],
        fixture_directory,
    )?;
    let status = pipe()?;
    let control = pipe()?;
    let mut uts = mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uts points to writable utsname storage.
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return Err(Refusal::io("launcher:uname"));
    }
    // SAFETY: uname initialized uts and release is NUL-terminated.
    let kernel_release = unsafe { CStr::from_ptr(uts.assume_init().release.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    poll_budget(deadline, 1)?;
    // SAFETY: raw clone has fork semantics (no CLONE_VM), no shared stack, and only raw child syscalls follow.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            NAMESPACES | libc::SIGCHLD as u64,
            0,
            0,
            0,
            0,
        )
    } as i32;
    if pid < 0 {
        return Err(Refusal::io("launcher:clone"));
    }
    if pid == 0 {
        // SAFETY: these are inherited descriptors; the child never returns or runs destructors.
        unsafe {
            libc::close(status[0].as_raw_fd());
            libc::close(control[1].as_raw_fd());
        }
        child(&prepared, status[1].as_raw_fd(), control[0].as_raw_fd());
    }
    let [status_read, status_write] = status;
    let [control_read, control_write] = control;
    drop(status_write);
    drop(control_read);
    let setup = (|| {
        if read_packet(status_read.as_raw_fd(), deadline)? != Some([1, 0]) {
            return Err(Refusal::new("launcher:child-sync"));
        }
        let development_own_id = map_identity(policy, pid, uid, gid, deadline)?;
        release(control_write.as_raw_fd())?;
        if read_packet(status_read.as_raw_fd(), deadline)? != Some([2, 0]) {
            return Err(Refusal::new("launcher:child-sync"));
        }
        cgroup(policy, pid)?;
        release(control_write.as_raw_fd())?;
        if read_packet(status_read.as_raw_fd(), deadline)? != Some([3, 0]) {
            return Err(Refusal::new("launcher:child-sync"));
        }
        release(control_write.as_raw_fd())?;
        let packet = read_packet(status_read.as_raw_fd(), deadline)?
            .ok_or_else(|| Refusal::new("launcher:child-failed"))?;
        if packet[0] != 4 || packet[1] < MIN_ABI {
            return Err(Refusal::new("launcher:landlock"));
        }
        if read_packet(status_read.as_raw_fd(), deadline)?.is_some() {
            return Err(Refusal::new("launcher:child-sync"));
        }
        Ok(LaunchResult {
            pid,
            kernel_release,
            landlock_abi: packet[1],
            seccomp_filter_hash: seccomp::hash(&prepared.filter),
            cgroup_path: policy.cgroup.path.clone(),
            development_own_id,
        })
    })();
    if setup.is_err() {
        // SAFETY: pid names the child we created, and killing PID1 also kills its namespace descendants.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = wait(pid);
    }
    setup
}

pub(crate) fn wait(pid: i32) -> Result<i32, Refusal> {
    let mut status = 0;
    loop {
        // SAFETY: status points to valid output storage and pid is the launched child.
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(status);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(Refusal::io("launcher:wait"));
        }
    }
}

pub(crate) fn run_boot_probe(
    policy: &LaunchPolicy,
    fixture_directory: &Path,
    proposal: OwnedFd,
    ui: OwnedFd,
) -> crate::BootProbeExecution {
    let deadline = Instant::now() + crate::BOOT_PROBE_TIMEOUT;
    let mut result = crate::BootProbeExecution {
        output: Vec::new(),
        setup: None,
        wait_status: None,
        refusal: None,
    };
    let launched = (|| {
        let [read, write] = pipe()?;
        let null = owned_open(c"/dev/null", libc::O_RDWR)?;
        let stdio = [null, duplicate(write.as_raw_fd())?, write];
        let setup = launch_deadline(
            policy,
            proposal,
            ui,
            stdio,
            Some(deadline),
            Some(fixture_directory),
        )?;
        result.setup = Some(setup);
        let pid = result.setup.as_ref().expect("launched probe").pid;
        capture_probe(
            pid,
            read.as_raw_fd(),
            deadline,
            &mut result.output,
            &mut result.wait_status,
        )
    })();
    if let Err(error) = launched {
        if let Some(setup) = &result.setup {
            if result.wait_status.is_none() {
                // SAFETY: this is the launched namespace PID1; killing it also terminates descendants.
                unsafe { libc::kill(setup.pid, libc::SIGKILL) };
                result.wait_status = wait(setup.pid).ok();
            }
        }
        result.refusal = Some(error);
    }
    result
}

fn capture_probe(
    pid: i32,
    fd: RawFd,
    deadline: Instant,
    output: &mut Vec<u8>,
    wait_status: &mut Option<i32>,
) -> Result<(), Refusal> {
    // SAFETY: fd is an owned pipe reader; O_NONBLOCK prevents unbounded reads.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err(Refusal::io("launcher:probe-output-failed"));
    }
    let mut eof = false;
    while !eof || wait_status.is_none() {
        let timeout = poll_budget(Some(deadline), 10)?;
        if wait_status.is_none() {
            let mut status = 0;
            // SAFETY: pid is our child and status is writable output storage.
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                *wait_status = Some(status);
            } else if waited < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                return Err(Refusal::io("launcher:probe-wait-failed"));
            }
        }
        let mut event = libc::pollfd {
            fd: if eof { -1 } else { fd },
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: event points to one initialized poll descriptor.
        let polled = unsafe { libc::poll(&mut event, 1, timeout) };
        if polled < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(Refusal::io("launcher:probe-output-failed"));
        }
        if polled == 0 || eof {
            continue;
        }
        let mut buffer = [0u8; 1024];
        // SAFETY: buffer is writable for its length, and fd is the pipe reader.
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read == 0 {
            eof = true;
        } else if read > 0 {
            append_probe_output(output, &buffer[..read as usize])?;
        } else if ![Some(libc::EAGAIN), Some(libc::EINTR)]
            .contains(&std::io::Error::last_os_error().raw_os_error())
        {
            return Err(Refusal::io("launcher:probe-output-failed"));
        }
    }
    Ok(())
}

fn fail(status: RawFd, code: usize) -> ! {
    // SAFETY: errno location is valid for this thread; packet is readable and _exit skips destructors.
    unsafe {
        let packet = [-(code as i32) - 1, *libc::__errno_location()];
        libc::write(status, packet.as_ptr().cast(), 8);
        libc::_exit(120 + code as i32);
    }
}

fn check(result: libc::c_long, status: RawFd, code: usize) {
    if result < 0 {
        fail(status, code);
    }
}

fn barrier(status: RawFd, control: RawFd, stage: i32) {
    let packet = [stage, 0];
    let mut byte = 0u8;
    // SAFETY: both buffers are correctly sized; pipe descriptors are inherited.
    unsafe {
        if libc::write(status, packet.as_ptr().cast(), 8) != 8
            || libc::read(control, (&mut byte as *mut u8).cast(), 1) != 1
            || byte != b'Y'
        {
            fail(status, 0);
        }
    }
}

fn mount(
    source: Option<&CStr>,
    target: &CStr,
    kind: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
    status: RawFd,
) {
    // SAFETY: CStr pointers remain valid for the syscall, absent arguments are null.
    let result = unsafe {
        libc::mount(
            source.map_or(ptr::null(), CStr::as_ptr),
            target.as_ptr(),
            kind.map_or(ptr::null(), CStr::as_ptr),
            flags,
            data.map_or(ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    check(result.into(), status, 2);
}

#[repr(C)]
struct MountAttr {
    set: u64,
    clear: u64,
    propagation: u64,
    userns: u64,
}

fn readonly(target: &CStr, status: RawFd) {
    let attr = MountAttr {
        set: 1 | 2 | 4,
        clear: 0,
        propagation: 0,
        userns: 0,
    };
    // SAFETY: mount_setattr receives a NUL-terminated path and initialized ABI struct; AT_RECURSIVE covers submounts.
    check(
        unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                target.as_ptr(),
                0x8000,
                &attr,
                mem::size_of::<MountAttr>(),
            )
        },
        status,
        2,
    );
}

fn child(p: &Prepared, status: RawFd, control: RawFd) -> ! {
    // SAFETY: prctl arguments are scalar; parent EOF prevents continuing after a supervisor death during setup.
    check(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }.into(),
        status,
        1,
    );
    barrier(status, control, 1);
    // Reopen while the original supervisor fsuid can traverse the private parent.
    let probe_source = p
        .probe_fixture
        .as_ref()
        .map(|fixture| rebind_source(p, &fixture.source, true, status));
    // The parent has written the single-id maps. Until the child takes the mapped id 0, its fsuid and fsgid
    // are unmapped and creating any inode fails with EOVERFLOW, so this precedes every mount and mkdir.
    // SAFETY: the namespace maps only id 0 and all outputs are scalar.
    unsafe {
        check(libc::syscall(libc::SYS_setresgid, 0, 0, 0), status, 1);
        check(libc::syscall(libc::SYS_setresuid, 0, 0, 0), status, 1);
    }
    // SAFETY: scalar prctl call; changing credentials cleared the supervisor-death signal.
    check(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }.into(),
        status,
        1,
    );
    // The UTS namespace is the guest's own; it never sees the host's name.
    // SAFETY: both names are static NUL-terminated strings passed with their exact lengths.
    unsafe {
        check(libc::sethostname(c"aukora".as_ptr(), 6).into(), status, 1);
        check(libc::setdomainname(c"".as_ptr(), 0).into(), status, 1);
    }
    mount(
        None,
        c"/",
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
        status,
    );
    mount(
        Some(c"tmpfs"),
        &p.root,
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(c"mode=0755,size=16m"),
        status,
    );
    for path in &p.directories {
        // SAFETY: paths address directories inside the fresh root.
        check(
            unsafe { libc::mkdir(path.as_ptr(), 0o755) }.into(),
            status,
            2,
        );
    }
    let usr = rebind_source(p, &p.usr, true, status);
    // SAFETY: rebind_source returns a NUL-terminated buffer.
    let usr = unsafe { CStr::from_ptr(usr.as_ptr().cast()) };
    mount(
        Some(usr),
        &p.directories[0],
        None,
        libc::MS_BIND | libc::MS_REC,
        None,
        status,
    );
    readonly(&p.directories[0], status);
    for path in &p.readonly_bind_directories {
        // SAFETY: validated components place every directory inside the fresh root under /opt.
        check(
            unsafe { libc::mkdir(path.as_ptr(), 0o755) }.into(),
            status,
            2,
        );
    }
    for bind in &p.readonly_binds {
        let source = rebind_source(p, &bind.source, true, status);
        // SAFETY: rebind_source returns a NUL-terminated buffer.
        let source = unsafe { CStr::from_ptr(source.as_ptr().cast()) };
        mount(
            Some(source),
            &bind.destination,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
            status,
        );
        readonly(&bind.destination, status);
    }
    let workspace = rebind_source(p, &p.workspace, true, status);
    // SAFETY: rebind_source returns a NUL-terminated buffer.
    let workspace = unsafe { CStr::from_ptr(workspace.as_ptr().cast()) };
    mount(
        Some(workspace),
        &p.directories[1],
        None,
        libc::MS_BIND,
        None,
        status,
    );
    mount(
        None,
        &p.directories[1],
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
        None,
        status,
    );
    // SAFETY: openat pins the .git mount target without following a replaced symlink.
    let work = unsafe {
        libc::open(
            p.directories[1].as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    check(work.into(), status, 2);
    // SAFETY: work is a directory fd, .git is a static terminated component.
    let git = unsafe {
        libc::openat(
            work,
            c".git".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    check(git.into(), status, 2);
    let git_path = descriptor_path(git);
    // SAFETY: descriptor_path returns a NUL-terminated stack buffer.
    let git_path = unsafe { CStr::from_ptr(git_path.as_ptr().cast()) };
    let git_source = rebind_source(p, &p.git, true, status);
    // SAFETY: rebind_source returns a NUL-terminated buffer.
    let git_source = unsafe { CStr::from_ptr(git_source.as_ptr().cast()) };
    mount(
        Some(git_source),
        git_path,
        None,
        libc::MS_BIND,
        None,
        status,
    );
    // Reopen after the attachment to obtain its new vfsmount.
    // SAFETY: O_NOFOLLOW refuses a replacement symlink and pins the mounted directory.
    let mounted_git = unsafe {
        libc::open(
            p.git_destination.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    check(mounted_git.into(), status, 2);
    let mut original = mem::MaybeUninit::<libc::stat>::uninit();
    let mut attached = mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: both descriptors are pinned directories and both outputs are writable stat buffers.
    unsafe {
        check(
            libc::fstat(p._paths[2].as_raw_fd(), original.as_mut_ptr()).into(),
            status,
            2,
        );
        check(
            libc::fstat(mounted_git, attached.as_mut_ptr()).into(),
            status,
            2,
        );
        let original = original.assume_init();
        let attached = attached.assume_init();
        if original.st_dev != attached.st_dev || original.st_ino != attached.st_ino {
            fail(status, 2);
        }
    }
    let mounted_path = descriptor_path(mounted_git);
    // SAFETY: descriptor_path produces a terminated buffer.
    let mounted_path = unsafe { CStr::from_ptr(mounted_path.as_ptr().cast()) };
    mount(
        None,
        mounted_path,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_RDONLY
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | libc::MS_NOEXEC,
        None,
        status,
    );
    for file in &p.readonly_workspace_files {
        mount_workspace_file(p, file, work, status);
    }
    if let (Some(fixture), Some(source)) = (&p.probe_fixture, &probe_source) {
        mount_probe_fixture(p, fixture, source, work, status);
    }
    let mut git_flags = mem::MaybeUninit::<libc::statvfs>::uninit();
    let mut work_flags = mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: fstatvfs receives valid descriptors and writable statvfs buffers.
    unsafe {
        check(
            libc::fstatvfs(mounted_git, git_flags.as_mut_ptr()).into(),
            status,
            2,
        );
        check(
            libc::fstatvfs(work, work_flags.as_mut_ptr()).into(),
            status,
            2,
        );
        let required = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        if git_flags.assume_init().f_flag & required != required
            || work_flags.assume_init().f_flag & libc::MS_RDONLY != 0
        {
            fail(status, 2);
        }
    }
    // SAFETY: these setup descriptors are no longer used.
    unsafe {
        libc::close(work);
        libc::close(git);
        libc::close(mounted_git);
    }
    mount(
        Some(c"proc"),
        &p.directories[2],
        Some(c"proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(c"hidepid=2"),
        status,
    );
    mount(
        Some(c"tmpfs"),
        &p.directories[3],
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some(c"mode=0755,size=1m"),
        status,
    );
    for (source, target) in &p.devices {
        let source = rebind_source(p, source, false, status);
        // SAFETY: rebind_source returns a NUL-terminated buffer.
        let source = unsafe { CStr::from_ptr(source.as_ptr().cast()) };
        // SAFETY: targets are fresh regular files inside private /dev.
        let fd = unsafe {
            libc::open(
                target.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
                0o666,
            )
        };
        check(fd.into(), status, 2);
        // SAFETY: fd was opened above.
        unsafe {
            libc::close(fd);
        }
        mount(Some(source), target, None, libc::MS_BIND, None, status);
        mount(
            None,
            target,
            None,
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NOEXEC,
            None,
            status,
        );
    }
    mount(
        Some(c"tmpfs"),
        &p.directories[4],
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(c"mode=1777,size=64m"),
        status,
    );
    for (source, target) in &p.aliases {
        // SAFETY: symlinks are created inside the fresh root and target /usr inside it.
        check(
            unsafe { libc::symlink(source.as_ptr(), target.as_ptr()) }.into(),
            status,
            2,
        );
    }
    // SAFETY: root and oldroot are NUL-terminated paths in the private mount namespace.
    unsafe {
        check(
            libc::syscall(
                libc::SYS_pivot_root,
                p.root.as_ptr(),
                p.directories[5].as_ptr(),
            ),
            status,
            2,
        );
        check(libc::chdir(c"/".as_ptr()).into(), status, 2);
        check(
            libc::umount2(c"/.oldroot".as_ptr(), libc::MNT_DETACH).into(),
            status,
            2,
        );
        check(libc::rmdir(c"/.oldroot".as_ptr()).into(), status, 2);
    }
    for fd in &p._paths {
        // SAFETY: pinned source paths are no longer used after pivot and are child-local copies.
        unsafe {
            libc::close(fd.as_raw_fd());
        }
    }
    // Reserve slots for Landlock after lowering NOFILE, even when the supervisor has many descriptors.
    // SAFETY: live transport sources are duplicated above 9; path sources are already closed and pipes are above 63.
    check(
        unsafe { libc::syscall(libc::SYS_close_range, 5u32, 9u32, 0u32) },
        status,
        10,
    );
    network(status);
    for (resource, value) in [(libc::RLIMIT_NOFILE, NOFILE), (libc::RLIMIT_CORE, CORE)] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        // SAFETY: limit is an initialized rlimit struct.
        check(
            unsafe { libc::setrlimit(resource, &limit) }.into(),
            status,
            4,
        );
    }
    if crate::resources::install_file_size_limit(p.file_size_max_bytes).is_err() {
        fail(status, 4);
    }
    barrier(status, control, 2);
    // Changing credentials (done before the mounts) clears PDEATHSIG; it is restored here once more.
    // SAFETY: scalar prctl call restores the supervisor-death signal after credentials change.
    check(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }.into(),
        status,
        1,
    );
    barrier(status, control, 3);
    // SAFETY: prctl takes scalar arguments.
    check(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }.into(),
        status,
        5,
    );
    capabilities(status);
    let abi = landlock(p, status);
    let packet = [4i32, abi];
    // SAFETY: packet contains eight readable bytes for the status pipe.
    check(
        unsafe { libc::write(status, packet.as_ptr().cast(), 8) } as libc::c_long,
        status,
        0,
    );
    if seccomp::install(&p.filter).is_err() {
        fail(status, 8);
    }
    // Preserve supplied pipes before closing all descriptors above 4.
    for index in 0..3 {
        // SAFETY: every source was duplicated above 9, so no destination aliases another source.
        check(
            unsafe { libc::dup3(p.fds[index + 2].as_raw_fd(), index as i32, 0) }.into(),
            status,
            11,
        );
    }
    for index in 0..2 {
        // SAFETY: sources are distinct descriptors above 9, destinations are FD3/FD4.
        check(
            unsafe { libc::dup3(p.fds[index].as_raw_fd(), index as i32 + 3, 0) }.into(),
            status,
            9,
        );
    }
    // SAFETY: closes every inherited descriptor except the five explicitly assigned guest descriptors.
    check(
        unsafe { libc::syscall(libc::SYS_close_range, 5u32, u32::MAX, 0u32) },
        status,
        10,
    );
    // SAFETY: pointers and their CString storage were prepared before clone; exec failure exits without destructors.
    unsafe {
        libc::execve(p.executable.as_ptr(), p.argv.as_ptr(), p.env.as_ptr());
        libc::_exit(127);
    }
}

fn mount_workspace_file(p: &Prepared, file: &PreparedWorkspaceFile, work: RawFd, status: RawFd) {
    let mut parent = work;
    for component in &file.components[..file.components.len() - 1] {
        // SAFETY: each validated component is terminated; O_NOFOLLOW pins a directory inside workspace.
        let next = unsafe {
            libc::openat(
                parent,
                component.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        check(next.into(), status, 2);
        if parent != work {
            // SAFETY: parent is an owned setup descriptor, no longer needed.
            unsafe { libc::close(parent) };
        }
        parent = next;
    }
    let name = file
        .components
        .last()
        .expect("validated nonempty file path");
    // SAFETY: parent is pinned and name is one terminated normal component.
    let target = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    check(target.into(), status, 2);
    check_file_attachment(p, file, target, status);
    let source = rebind_source(p, &file.source, false, status);
    let target_path = descriptor_path(target);
    // SAFETY: descriptor paths are terminated stack buffers.
    let (source, target_path) = unsafe {
        (
            CStr::from_ptr(source.as_ptr().cast()),
            CStr::from_ptr(target_path.as_ptr().cast()),
        )
    };
    mount(Some(source), target_path, None, libc::MS_BIND, None, status);
    // SAFETY: the pinned parent directory and normal name reopen the new attachment without a symlink.
    let mounted = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    check(mounted.into(), status, 2);
    check_file_attachment(p, file, mounted, status);
    let mounted_path = descriptor_path(mounted);
    // SAFETY: descriptor_path returns a terminated buffer.
    let mounted_path = unsafe { CStr::from_ptr(mounted_path.as_ptr().cast()) };
    mount(
        None,
        mounted_path,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_RDONLY
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | libc::MS_NOEXEC,
        None,
        status,
    );
    // SAFETY: mounted and target are setup descriptors no longer needed.
    unsafe {
        libc::close(mounted);
        libc::close(target);
        if parent != work {
            libc::close(parent);
        }
    }
}

fn mount_probe_fixture(
    p: &Prepared,
    fixture: &PreparedProbeFixture,
    source: &[u8; 64],
    work: RawFd,
    status: RawFd,
) {
    // SAFETY: work is pinned and the static single component cannot traverse a link.
    let parent = unsafe {
        libc::openat(
            work,
            fixture.parent_name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    check(parent.into(), status, 2);
    let mut opened = mem::MaybeUninit::<libc::stat>::uninit();
    let mut pinned = mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: descriptors are live directories and stat outputs are writable.
    unsafe {
        check(libc::fstat(parent, opened.as_mut_ptr()).into(), status, 2);
        check(
            libc::fstat(
                p._paths[fixture.parent_index].as_raw_fd(),
                pinned.as_mut_ptr(),
            )
            .into(),
            status,
            2,
        );
        let opened = opened.assume_init();
        let pinned = pinned.assume_init();
        if opened.st_dev != pinned.st_dev || opened.st_ino != pinned.st_ino {
            fail(status, 2);
        }
    }
    let parent_path = descriptor_path(parent);
    // SAFETY: descriptor_path returns a terminated buffer for the child-local target.
    let parent_path = unsafe { CStr::from_ptr(parent_path.as_ptr().cast()) };
    mount(
        Some(c"tmpfs"),
        parent_path,
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(c"mode=0700,size=1m"),
        status,
    );
    // SAFETY: the target is beneath the private tmpfs shadow inside the new root.
    check(
        unsafe { libc::mkdir(fixture.destination.as_ptr(), 0o700) }.into(),
        status,
        2,
    );
    // SAFETY: rebind_source returned this terminated path before changing fsuid.
    let source = unsafe { CStr::from_ptr(source.as_ptr().cast()) };
    mount(
        Some(source),
        &fixture.destination,
        None,
        libc::MS_BIND,
        None,
        status,
    );
    mount(
        None,
        &fixture.destination,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
        None,
        status,
    );
    // SAFETY: parent is a setup-only descriptor, no longer needed.
    unsafe { libc::close(parent) };
}

fn check_file_attachment(
    p: &Prepared,
    file: &PreparedWorkspaceFile,
    attached_fd: RawFd,
    status: RawFd,
) {
    let mut original = mem::MaybeUninit::<libc::stat>::uninit();
    let mut attached = mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: both descriptors are valid and stat outputs point to writable storage.
    unsafe {
        check(
            libc::fstat(p._paths[file.source.1].as_raw_fd(), original.as_mut_ptr()).into(),
            status,
            2,
        );
        check(
            libc::fstat(attached_fd, attached.as_mut_ptr()).into(),
            status,
            2,
        );
        let original = original.assume_init();
        let attached = attached.assume_init();
        if original.st_dev != attached.st_dev || original.st_ino != attached.st_ino {
            fail(status, 2);
        }
    }
}

/// Re-open a bind source by absolute path inside the child's mount namespace and refuse unless it is
/// the very inode the parent pinned (same st_dev and st_ino), so a path swapped between the parent's
/// pin and this open cannot be mounted. The new descriptor stays open until exec closes it (CLOEXEC).
fn rebind_source(
    p: &Prepared,
    source: &(CString, usize),
    directory: bool,
    status: RawFd,
) -> [u8; 64] {
    let flags = libc::O_PATH
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | if directory { libc::O_DIRECTORY } else { 0 };
    // SAFETY: the path is NUL-terminated; O_PATH creates nothing.
    let fd = unsafe { libc::open(source.0.as_ptr(), flags) };
    check(fd.into(), status, 2);
    let mut opened = mem::MaybeUninit::<libc::stat>::uninit();
    let mut pinned = mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: both descriptors are valid and both outputs are writable stat buffers.
    unsafe {
        check(libc::fstat(fd, opened.as_mut_ptr()).into(), status, 2);
        check(
            libc::fstat(p._paths[source.1].as_raw_fd(), pinned.as_mut_ptr()).into(),
            status,
            2,
        );
        let opened = opened.assume_init();
        let pinned = pinned.assume_init();
        if opened.st_dev != pinned.st_dev || opened.st_ino != pinned.st_ino {
            fail(status, 2);
        }
    }
    descriptor_path(fd)
}

fn descriptor_path(fd: i32) -> [u8; 64] {
    let mut path = [0u8; 64];
    let prefix = b"/proc/self/fd/";
    path[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 10];
    let mut count = 0;
    let mut number = fd as u32;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    for index in 0..count {
        path[prefix.len() + index] = digits[count - index - 1];
    }
    path
}

fn network(status: RawFd) {
    // The new namespace has no interfaces except the kernel-created loopback.
    // SAFETY: socket has scalar arguments and exists only during setup.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    check(fd.into(), status, 3);
    // SAFETY: zeroed ifreq is a valid input/output buffer; lo is terminated.
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    request.ifr_name[0] = b'l' as libc::c_char;
    request.ifr_name[1] = b'o' as libc::c_char;
    // SAFETY: ioctl receives the correctly sized ifreq buffer.
    check(
        unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut request) }.into(),
        status,
        3,
    );
    // SAFETY: SIOCGIFFLAGS initialized the flags union field.
    if unsafe { request.ifr_ifru.ifru_flags } as i32 & libc::IFF_UP != 0 {
        fail(status, 3);
    }
    // SAFETY: fd is the setup socket and is no longer needed.
    unsafe {
        libc::close(fd);
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn capabilities(status: RawFd) {
    let mut cap = 0;
    loop {
        // SAFETY: scalar capability query; EINVAL marks the end of kernel-supported capability numbers.
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if result < 0 {
            // SAFETY: errno location is valid in this child.
            if unsafe { *libc::__errno_location() } == libc::EINVAL {
                break;
            }
            fail(status, 6);
        }
        // SAFETY: scalar capability drop, while CAP_SETPCAP is still effective.
        check(
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) }.into(),
            status,
            6,
        );
        cap += 1;
    }
    // SAFETY: scalar ambient-capability clear operation.
    check(
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        }
        .into(),
        status,
        6,
    );
    let header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: header and data match the Linux v3 capset ABI.
    check(
        unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) },
        status,
        6,
    );
}

#[repr(C)]
struct RulesetAttr {
    fs: u64,
    net: u64,
}
#[repr(C, packed)]
struct PathAttr {
    access: u64,
    parent: i32,
}

fn landlock(p: &Prepared, status: RawFd) -> i32 {
    // SAFETY: querying the ABI uses null/zero attrs with VERSION flag.
    let abi =
        unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, ptr::null::<u8>(), 0, 1) } as i32;
    if abi < MIN_ABI {
        fail(status, 7);
    }
    let handled = FS_READ | FS_WRITE | 64 | 2048 | if abi >= 5 { FS_IOCTL } else { 0 };
    let attr = RulesetAttr {
        fs: handled,
        net: NET_DENY,
    };
    // SAFETY: attr matches the ABI4 prefix; no rules allow TCP bind/connect.
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            mem::size_of::<RulesetAttr>(),
            0,
        )
    } as i32;
    check(ruleset.into(), status, 7);
    for (path, access) in [
        (c"/usr", FS_READ),
        (c"/workspace/.git", FS_READ),
        (c"/workspace", FS_READ | FS_WORKSPACE),
        (c"/tmp", FS_READ | FS_WRITE),
        (c"/proc", FS_READ & !1),
        (c"/dev", 2 | 4 | 8),
    ] {
        // SAFETY: each static path is NUL-terminated and remains inside the new root.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        check(fd.into(), status, 7);
        let path_attr = PathAttr { access, parent: fd };
        // SAFETY: packed PathAttr matches the Linux Landlock path-beneath ABI.
        check(
            unsafe { libc::syscall(libc::SYS_landlock_add_rule, ruleset, 1, &path_attr, 0) },
            status,
            7,
        );
        // SAFETY: fd was opened above and is no longer needed.
        unsafe {
            libc::close(fd);
        }
    }
    for bind in &p.readonly_binds {
        // SAFETY: guest bind paths are NUL-terminated and mounted inside the new root.
        let fd = unsafe { libc::open(bind.guest.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        check(fd.into(), status, 7);
        let path_attr = PathAttr {
            access: FS_READ,
            parent: fd,
        };
        // SAFETY: packed PathAttr matches the Linux Landlock path-beneath ABI.
        check(
            unsafe { libc::syscall(libc::SYS_landlock_add_rule, ruleset, 1, &path_attr, 0) },
            status,
            7,
        );
        // SAFETY: fd was opened above and is no longer needed.
        unsafe {
            libc::close(fd);
        }
    }
    // SAFETY: ruleset is an initialized Landlock fd and no_new_privs is already set.
    check(
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) },
        status,
        7,
    );
    // SAFETY: the installed ruleset remains effective after closing its descriptor.
    unsafe {
        libc::close(ruleset);
    }
    abi
}
