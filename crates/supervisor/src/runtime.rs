// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", test))]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "linux", test))]
use std::fs::OpenOptions;
use std::fs::{self, File};
#[cfg(any(target_os = "linux", test))]
use std::io::BufRead;
#[cfg(target_os = "linux")]
use std::io::BufReader;
use std::io::Read;
#[cfg(any(target_os = "linux", test))]
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", test))]
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
#[cfg(any(target_os = "linux", test))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(any(target_os = "linux", test))]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread;
use std::thread::JoinHandle;
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN_PREFIX: &[u8] = b"dsh web: http://127.0.0.1:3080/?token=";
#[cfg(any(target_os = "linux", test))]
const MAX_STDOUT_LINE: usize = 4096;
#[cfg(any(target_os = "linux", test))]
const PROFILE_MANIFEST: &[u8] = b"{\"name\":\"dsh-profile-web\",\"private\":true,\"dependencies\":{},\"dsh\":{\"profile\":{\"bundles\":[\"@deepseek-ai/dsh-base\",\"@deepseek-ai/dsh-web-app\"],\"patchReload\":\"startup\"}}}\n";
#[cfg(any(target_os = "linux", test))]
const WORKSPACE_SCAN_INTERVAL: Duration = Duration::from_secs(1);
/// The free-space reserve is checked on its own, much faster: a full scan of a large
/// workspace can take seconds, and the guest can write a lot in that time.
#[cfg(target_os = "linux")]
const DISK_CHECK_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct RuntimeConfig {
    pub boot_probe: bool,
    pub state_dir: PathBuf,
    pub work_dir: PathBuf,
    pub cgroup_root: PathBuf,
    pub node_dir: PathBuf,
    pub harness_dir: PathBuf,
    pub bundle_dir: PathBuf,
    pub subordinate_uid: u32,
    pub subordinate_gid: u32,
    pub chat_hostname: String,
    pub model: String,
    pub node_npub: String,
    pub agent_npub: String,
    pub pids_max: u64,
    pub memory_max_bytes: u64,
    pub file_size_max_bytes: u64,
    pub workspace_max_bytes: u64,
    pub cpu_max: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Components {
    pub node: String,
    pub harness: String,
    pub guest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDigests {
    pub digest: String,
    pub components: Components,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub current_digest: String,
    pub approved_digest: Option<String>,
    pub agent: String,
    pub since: i64,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            current_digest: String::new(),
            approved_digest: None,
            agent: "stopped".into(),
            since: now_ms(),
        }
    }
}

pub trait RuntimeBackend: Send + Sync + 'static {
    fn runtime_measured(&self, digests: &RuntimeDigests) -> Result<()>;
    fn is_bound(&self) -> Result<bool>;
    fn approved_release(&self) -> Result<Option<RuntimeDigests>>;
    fn ensure_release(&self, digests: &RuntimeDigests) -> Result<()>;
    fn runtime_changed(&self, status: &RuntimeStatus) -> Result<()>;
    fn sandbox_event(&self, kind: &str, op: &str, phase: &str, body: Value) -> Result<()>;
    fn dispatch(&self, stream: UnixStream, on_ready: Box<dyn FnOnce() + Send>) -> Result<()>;
    fn harness_token(&self, token: String) -> Result<()>;
    fn clear_harness_cookie(&self);
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_length(hash: &mut Sha256, length: usize) -> Result<()> {
    hash.update(
        u64::try_from(length)
            .context("runtime:tree-too-large")?
            .to_be_bytes(),
    );
    Ok(())
}

fn tree_paths(root: &Path, relative: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root.join(relative)).context("runtime:tree-read")? {
        let entry = entry.context("runtime:tree-read")?;
        let relative = relative.join(entry.file_name());
        let meta = fs::symlink_metadata(root.join(&relative)).context("runtime:tree-read")?;
        paths.push(relative.clone());
        if meta.is_dir() {
            tree_paths(root, &relative, paths)?;
        }
    }
    Ok(())
}

fn sort_paths(paths: &mut [PathBuf]) {
    paths.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
}

fn same_inode(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    before.dev() == opened.dev() && before.ino() == opened.ino()
}

fn stable_file(before: &fs::Metadata, after: &fs::Metadata, read: u64) -> bool {
    read == before.len()
        && after.len() == before.len()
        && after.mtime() == before.mtime()
        && after.mtime_nsec() == before.mtime_nsec()
        && after.ctime() == before.ctime()
        && after.ctime_nsec() == before.ctime_nsec()
}

pub fn tree_digest(root: &Path) -> Result<String> {
    let root_meta = fs::symlink_metadata(root).context("runtime:tree-read")?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        bail!("runtime:tree-not-directory");
    }
    let canonical_root = fs::canonicalize(root).context("runtime:tree-read")?;
    let mut paths = vec![PathBuf::new()];
    tree_paths(root, Path::new(""), &mut paths)?;
    sort_paths(&mut paths);
    let mut hash = Sha256::new();
    hash.update(b"aukora:runtime-tree:v1\0");
    for relative in paths {
        let path = root.join(&relative);
        let meta = fs::symlink_metadata(&path).context("runtime:tree-read")?;
        let bytes = relative.as_os_str().as_bytes();
        hash_length(&mut hash, bytes.len())?;
        hash.update(bytes);
        hash.update((meta.mode() & 0o7777).to_be_bytes());
        if meta.is_dir() {
            hash.update(b"d");
        } else if meta.is_file() {
            hash.update(b"f");
            hash.update(meta.len().to_be_bytes());
            let mut file = File::open(&path).context("runtime:tree-read")?;
            let opened = file.metadata().context("runtime:tree-read")?;
            if !same_inode(&meta, &opened) {
                bail!("runtime:tree-changed");
            }
            let mut buffer = [0_u8; 65536];
            let mut read = 0_u64;
            loop {
                let count = file.read(&mut buffer).context("runtime:tree-read")?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
                read += count as u64;
            }
            let after = file.metadata().context("runtime:tree-read")?;
            if !stable_file(&meta, &after, read) {
                bail!("runtime:tree-changed");
            }
        } else if meta.file_type().is_symlink() {
            // A release never depends on bytes outside its measured trees.
            if !fs::canonicalize(&path)
                .context("runtime:symlink-target")?
                .starts_with(&canonical_root)
            {
                bail!("runtime:symlink-escape");
            }
            hash.update(b"l");
            let target = fs::read_link(&path).context("runtime:tree-read")?;
            let target = target.as_os_str().as_bytes();
            hash_length(&mut hash, target.len())?;
            hash.update(target);
        } else {
            bail!("runtime:tree-special-file");
        }
    }
    Ok(hex(&hash.finalize()))
}

pub fn measure(config: &RuntimeConfig) -> Result<RuntimeDigests> {
    let components = Components {
        node: tree_digest(&config.node_dir)?,
        harness: tree_digest(&config.harness_dir)?,
        guest: tree_digest(&config.bundle_dir)?,
    };
    let value = canon::parse(&serde_json::to_vec(&components)?)?;
    let bytes = canon::canonical_json(&value)?;
    let mut hash = Sha256::new();
    hash.update(b"aukora:runtime-release:v1\0");
    hash.update(bytes);
    Ok(RuntimeDigests {
        digest: hex(&hash.finalize()),
        components,
    })
}

pub fn launch_allowed(
    bound: bool,
    current: &RuntimeDigests,
    approved: Option<&RuntimeDigests>,
) -> bool {
    bound && approved == Some(current)
}

pub fn parse_web_token(line: &[u8]) -> Option<String> {
    let token = line.strip_prefix(TOKEN_PREFIX)?;
    if token.len() != 43
        || !token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
    {
        return None;
    }
    String::from_utf8(token.to_vec()).ok()
}

#[cfg(any(target_os = "linux", test))]
fn read_stdout(
    mut stream: impl BufRead,
    mut token_ready: impl FnMut(String) -> Result<()>,
) -> usize {
    let mut line = Vec::new();
    let mut oversized = false;
    let mut offered = false;
    let mut largest = 0;
    loop {
        let bytes = match stream.fill_buf() {
            Ok([]) | Err(_) => break,
            Ok(bytes) => bytes,
        };
        let end = bytes.iter().position(|byte| *byte == b'\n');
        let count = end.map_or(bytes.len(), |index| index + 1);
        let fragment = &bytes[..end.unwrap_or(bytes.len())];
        if !oversized && line.len().saturating_add(fragment.len()) <= MAX_STDOUT_LINE {
            line.extend_from_slice(fragment);
            largest = largest.max(line.len());
        } else {
            oversized = true;
            line.clear();
        }
        stream.consume(count);
        if end.is_some() {
            if !oversized && !offered {
                if let Some(token) = parse_web_token(&line) {
                    offered = true;
                    let _ = token_ready(token);
                }
            }
            line.clear();
            oversized = false;
        }
    }
    largest
}

#[cfg(any(target_os = "linux", test))]
fn status(
    backend: &dyn RuntimeBackend,
    digests: &RuntimeDigests,
    approved: Option<&RuntimeDigests>,
    agent: &str,
) -> Result<()> {
    backend.runtime_changed(&RuntimeStatus {
        current_digest: digests.digest.clone(),
        approved_digest: approved.map(|release| release.digest.clone()),
        agent: agent.into(),
        since: now_ms(),
    })
}

pub fn start(
    backend: Arc<dyn RuntimeBackend>,
    config: RuntimeConfig,
) -> Result<JoinHandle<Result<()>>> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (backend, config);
        bail!("runtime:unsupported-platform");
    }
    #[cfg(target_os = "linux")]
    {
        thread::Builder::new()
            .name("sovereign-runtime".into())
            .spawn(move || manage(backend, config))
            .context("runtime:thread-start")
    }
}

#[cfg(target_os = "linux")]
fn cgroups(root: &Path) -> Result<PathBuf> {
    if !root.is_absolute() || root == Path::new("/sys/fs/cgroup") {
        bail!("runtime:cgroup-root");
    }
    let controllers =
        fs::read_to_string(root.join("cgroup.controllers")).context("runtime:cgroup-delegation")?;
    if !["cpu", "memory", "pids"].iter().all(|controller| {
        controllers
            .split_whitespace()
            .any(|entry| entry == *controller)
    }) {
        bail!("runtime:cgroup-controllers");
    }
    let supervisor = root.join("supervisor");
    fs::create_dir_all(&supervisor).context("runtime:cgroup-supervisor")?;
    fs::write(
        supervisor.join("cgroup.procs"),
        std::process::id().to_string(),
    )
    .context("runtime:cgroup-move")?;
    fs::write(root.join("cgroup.subtree_control"), "+cpu +memory +pids")
        .context("runtime:cgroup-enable")?;
    let guest = root.join("guest");
    fs::create_dir_all(&guest).context("runtime:cgroup-guest")?;
    if !fs::read_to_string(guest.join("cgroup.procs"))
        .context("runtime:cgroup-read")?
        .trim()
        .is_empty()
    {
        bail!("runtime:cgroup-guest-not-empty");
    }
    Ok(guest)
}

#[cfg(any(target_os = "linux", test))]
fn writable_dir(path: &Path) -> Result<()> {
    // SAFETY: geteuid only reads this process's credential.
    writable_dir_owned_by(path, unsafe { libc::geteuid() })
}

#[cfg(any(target_os = "linux", test))]
fn writable_dir_owned_by(path: &Path, supervisor_uid: u32) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => bail!("runtime:workspace-create"),
    }
    let metadata = fs::symlink_metadata(path).context("runtime:workspace-read")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("runtime:workspace-symlink");
    }
    if metadata.uid() != supervisor_uid {
        bail!("runtime:workspace-not-owned");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o1777))
        .context("runtime:workspace-mode")?;
    Ok(())
}

/// The guest work directory: owned by the supervisor, traversable but not listable.
#[cfg(any(target_os = "linux", test))]
fn traversable_dir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => bail!("runtime:work-dir-create"),
    }
    let metadata = fs::symlink_metadata(path).context("runtime:work-dir-read")?;
    // SAFETY: geteuid takes no arguments and only reads the process credential.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        bail!("runtime:work-dir-not-owned");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o711))
        .context("runtime:work-dir-mode")?;
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn prepare_workspace(state: &Path, work: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    traversable_dir(work)?;
    let workspace = work.join("workspace");
    writable_dir(&workspace)?;
    for name in [
        ".git",
        "home",
        "dsh",
        "agents",
        "dsh/profiles",
        "dsh/profiles/web",
    ] {
        writable_dir(&workspace.join(name))?;
    }
    write_manifest(&workspace.join("dsh/profiles/web"))?;
    let root = work.join("guest-root");
    let sockets = state.join("sockets");
    for path in [&root, &sockets] {
        fs::create_dir_all(path).context("runtime:directory-create")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .context("runtime:directory-mode")?;
    }
    Ok((workspace, root, sockets.join("ui.sock")))
}

#[cfg(any(target_os = "linux", test))]
fn prepare_bounded_workspace(
    state: &Path,
    work: &Path,
    maximum: u64,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let prepared = prepare_workspace(state, work)?;
    workspace_guard(&prepared.0, maximum).map_err(anyhow::Error::msg)?;
    Ok(prepared)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn write_manifest(profile: &Path) -> Result<()> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| anyhow::anyhow!("runtime:profile-random"))?;
    let temporary = profile.join(format!(".package-{}.tmp", hex(&random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .context("runtime:profile-seed")?;
    let result = (|| {
        file.write_all(PROFILE_MANIFEST)
            .context("runtime:profile-seed")?;
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .context("runtime:profile-mode")?;
        file.sync_all().context("runtime:profile-sync")?;
        // Rename replaces links and hostile bytes without writing through them.
        fs::rename(&temporary, profile.join("package.json")).context("runtime:profile-install")?;
        File::open(profile)
            .and_then(|directory| directory.sync_all())
            .context("runtime:profile-sync")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(any(target_os = "linux", test))]
fn workspace_size(workspace: &Path, maximum: u64) -> std::result::Result<u64, &'static str> {
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: fdopendir created this stream, closed exactly once here.
            unsafe { libc::closedir(self.0) };
        }
    }
    fn charge(
        stat: &libc::stat,
        used: &mut u64,
        maximum: u64,
    ) -> std::result::Result<(), &'static str> {
        // Count sparse lengths, preallocation, and at least one block per entry.
        let bytes = workspace_entry_bytes(stat.st_size.max(0) as u64, stat.st_blocks.max(0) as u64);
        *used = used.saturating_add(bytes);
        if *used > maximum {
            return Err("runtime:workspace-limit");
        }
        Ok(())
    }
    fn visit(
        file: File,
        used: &mut u64,
        maximum: u64,
        depth: usize,
    ) -> std::result::Result<(), &'static str> {
        if depth > 64 {
            // Stop descending: deeper entries go uncounted (the disk reserve still bounds
            // them), and a guest-built deep tree can never stop the agent starting.
            return Ok(());
        }
        let descriptor = file.into_raw_fd();
        // SAFETY: descriptor is an owned directory fd, transferred on success.
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            // SAFETY: fdopendir leaves ownership with the caller on failure.
            drop(unsafe { File::from_raw_fd(descriptor) });
            return Err("runtime:workspace-scan");
        }
        let directory = Directory(stream);
        loop {
            // SAFETY: this thread owns its errno location and the live directory stream.
            let entry = unsafe {
                #[cfg(target_os = "linux")]
                {
                    *libc::__errno_location() = 0;
                }
                #[cfg(target_os = "macos")]
                {
                    *libc::__error() = 0;
                }
                libc::readdir(directory.0)
            };
            if entry.is_null() {
                if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err("runtime:workspace-scan");
                }
                return Ok(());
            }
            // SAFETY: readdir returned an initialized, NUL-terminated name until its next call.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if [b".".as_slice(), b"..".as_slice()].contains(&name.to_bytes()) {
                continue;
            }
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: descriptor is live, name is terminated, and stat is writable.
            if unsafe {
                libc::fstatat(
                    descriptor,
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                if matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ENOENT | libc::EACCES | libc::EPERM)
                ) {
                    continue;
                }
                return Err("runtime:workspace-scan");
            }
            // SAFETY: fstatat initialized stat on success.
            let stat = unsafe { stat.assume_init() };
            charge(&stat, used, maximum)?;
            if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                // SAFETY: openat resolves only this child of the pinned directory; it cannot follow a link.
                let child = unsafe {
                    libc::openat(
                        descriptor,
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if child < 0 {
                    // The guest may keep private directories under its own uid; the size
                    // count is then a lower bound, and disk_reserve is the hard guard.
                    if matches!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::ENOENT | libc::EACCES)
                    ) {
                        continue;
                    }
                    return Err("runtime:workspace-scan");
                }
                // SAFETY: openat returned a unique fd owned by this scan.
                visit(
                    unsafe { File::from_raw_fd(child) },
                    used,
                    maximum,
                    depth + 1,
                )?;
            }
        }
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(workspace)
        .map_err(|_| "runtime:workspace-scan")?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: root is live and stat is a writable output buffer.
    if unsafe { libc::fstat(root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err("runtime:workspace-scan");
    }
    let mut used = 0;
    // SAFETY: fstat initialized stat on success.
    charge(&unsafe { stat.assume_init() }, &mut used, maximum)?;
    visit(root, &mut used, maximum, 0)?;
    Ok(used)
}

#[cfg(any(target_os = "linux", test))]
/// Free space the supervisor keeps on the workspace's filesystem, which it shares with the
/// node's database by default: below it the guest is refused or stopped.
const DISK_RESERVE_BYTES: u64 = 1 << 30;

#[cfg(any(target_os = "linux", test))]
fn disk_reserve(workspace: &Path, reserve: u64) -> std::result::Result<u64, &'static str> {
    let path = std::ffi::CString::new(workspace.as_os_str().as_encoded_bytes())
        .map_err(|_| "runtime:disk-reserve")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL-terminated and stat is a writable output buffer.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err("runtime:disk-reserve");
    }
    // SAFETY: statvfs initialized stat on success.
    let stat = unsafe { stat.assume_init() };
    // The libc field widths differ between Linux and macOS.
    #[allow(clippy::unnecessary_cast)]
    let free = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
    if free < reserve {
        return Err("runtime:disk-reserve");
    }
    Ok(free)
}

#[cfg(any(target_os = "linux", test))]
fn workspace_guard(workspace: &Path, maximum: u64) -> std::result::Result<u64, &'static str> {
    disk_reserve(workspace, DISK_RESERVE_BYTES)?;
    workspace_size(workspace, maximum)
}

fn workspace_entry_bytes(length: u64, blocks: u64) -> u64 {
    length.max(blocks.saturating_mul(512)).max(4096)
}

#[cfg(any(target_os = "linux", test))]
fn monitor_workspace(
    mut check: impl FnMut() -> std::result::Result<u64, &'static str>,
    stopped: std::sync::mpsc::Receiver<()>,
    stop_guest: impl FnOnce(&'static str),
    interval: Duration,
) -> Option<&'static str> {
    loop {
        if let Err(code) = check() {
            stop_guest(code);
            return Some(code);
        }
        match stopped.recv_timeout(interval) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => (),
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn exit_body(wait_status: Option<i32>, code: Option<&str>, setup: bool) -> Value {
    json!({"wait_status":wait_status,"code":code,"setup":setup})
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn guest_environment(config: &RuntimeConfig) -> Vec<std::ffi::OsString> {
    let mut env = vec![
        "HOME=/workspace/home".into(),
        "PATH=/opt/node/bin:/usr/bin:/bin".into(),
        "TMPDIR=/tmp".into(),
        "NARB_DISABLE_NATIVE_CACHE=1".into(),
        "LANG=C.UTF-8".into(),
        "SHELL=/bin/sh".into(),
        "DSH_HOME=/workspace/dsh".into(),
        "DSH_AGENTS_HOME=/workspace/agents".into(),
        "DSH_TELEMETRY_MODE=DISABLED".into(),
        "DSH_TELEMETRY_DISABLED=1".into(),
        "NODE_NO_WARNINGS=1".into(),
        "AUKORA_LISTEN_FD=4".into(),
    ];
    env.push(format!("DSH_SOVEREIGN_MODEL={}", config.model));
    env.push(format!("AUKORA_NODE_NPUB={}", config.node_npub));
    env.push(format!("AUKORA_AGENT_NPUB={}", config.agent_npub));
    env.iter().map(std::ffi::OsString::from).collect()
}

#[cfg(any(target_os = "linux", test))]
fn policy(
    config: &RuntimeConfig,
    workspace: PathBuf,
    root: PathBuf,
    guest: PathBuf,
) -> launcher::LaunchPolicy {
    use launcher::{CgroupPolicy, IdentityPolicy, LaunchPolicy, ReadonlyBind};
    use std::ffi::OsString;
    let argv = [
        "/opt/node/bin/node",
        "--import",
        "/opt/sovereign/guest/preload.mjs",
        "/opt/harness/apps/cli/lib/bin.js",
        "--patch",
        "/opt/sovereign/guest/sovereign.patch.yml",
        "--profile",
        "web",
        "--host",
        "127.0.0.1",
        "--port",
        "3080",
        "--no-open",
        "--trusted-host",
        &config.chat_hostname,
    ];
    LaunchPolicy {
        workspace,
        root,
        cgroup: CgroupPolicy {
            path: guest,
            pids_max: config.pids_max,
            memory_max: config.memory_max_bytes,
            cpu_max: config.cpu_max.clone(),
        },
        identity: IdentityPolicy {
            subordinate_uid: config.subordinate_uid,
            subordinate_gid: config.subordinate_gid,
            allow_development_own_id: false,
        },
        file_size_max_bytes: config.file_size_max_bytes,
        executable: "/opt/node/bin/node".into(),
        argv: argv.iter().map(OsString::from).collect(),
        env: guest_environment(config),
        readonly_binds: vec![
            ReadonlyBind {
                host: config.node_dir.clone(),
                guest: "/opt/node".into(),
            },
            ReadonlyBind {
                host: config.harness_dir.clone(),
                guest: "/opt/harness".into(),
            },
            ReadonlyBind {
                host: config.bundle_dir.clone(),
                guest: "/opt/sovereign".into(),
            },
        ],
        readonly_workspace_files: vec!["dsh/profiles/web/package.json".into()],
    }
}

#[cfg(target_os = "linux")]
fn pipe() -> Result<(File, std::os::fd::OwnedFd)> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors has space for both newly created pipe descriptors.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("runtime:stdio-pipe");
    }
    // SAFETY: pipe2 returned two unique descriptors with no existing Rust owner.
    Ok(unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

#[cfg(any(target_os = "linux", test))]
const PROBE_FIXTURE_PARENT: &str = ".aukora-boot-probes";
#[cfg(any(target_os = "linux", test))]
const PROBE_FIXTURE_PREFIX: &str = ".aukora-boot-probe-";

#[cfg(any(target_os = "linux", test))]
fn validate_probe_parent(metadata: &fs::Metadata, supervisor_uid: u32) -> Result<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("runtime:probe-parent-directory");
    }
    if metadata.uid() != supervisor_uid {
        bail!("runtime:probe-parent-owner");
    }
    if metadata.mode() & 0o7777 != 0o700 {
        bail!("runtime:probe-parent-mode");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn sweep_legacy_probe_fixtures(workspace: &Path, supervisor_uid: u32) -> Result<()> {
    for entry in fs::read_dir(workspace).context("runtime:probe-fixture-cleanup")? {
        let entry = entry.context("runtime:probe-fixture-cleanup")?;
        if !entry
            .file_name()
            .as_bytes()
            .starts_with(PROBE_FIXTURE_PREFIX.as_bytes())
        {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).context("runtime:probe-fixture-cleanup")?;
        if metadata.is_dir()
            && metadata.uid() == supervisor_uid
            && matches!(metadata.mode() & 0o7777, 0o700 | 0o1777)
        {
            // The sticky supervisor-owned workspace prevents guest replacement.
            fs::remove_dir_all(&path).context("runtime:probe-fixture-cleanup")?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn prepare_probe_parent(workspace: &Path) -> Result<PathBuf> {
    let parent = workspace.join(PROBE_FIXTURE_PARENT);
    match fs::DirBuilder::new().mode(0o700).create(&parent) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => bail!("runtime:probe-parent-create"),
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(&parent)
        .context("runtime:probe-parent-directory")?;
    // SAFETY: geteuid only reads the process credential.
    let supervisor_uid = unsafe { libc::geteuid() };
    validate_probe_parent(&directory.metadata()?, supervisor_uid)?;
    sweep_legacy_probe_fixtures(workspace, supervisor_uid)?;
    // The private parent and the sticky workspace prevent guest replacement.
    for entry in fs::read_dir(&parent).context("runtime:probe-fixture-cleanup")? {
        let entry = entry.context("runtime:probe-fixture-cleanup")?;
        if !entry
            .file_name()
            .as_bytes()
            .starts_with(PROBE_FIXTURE_PREFIX.as_bytes())
        {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).context("runtime:probe-fixture-cleanup")?;
        if metadata.is_dir() {
            // remove_dir_all uses descriptor-relative removal without following symlinks.
            fs::remove_dir_all(&path).context("runtime:probe-fixture-cleanup")?;
        } else {
            fs::remove_file(&path).context("runtime:probe-fixture-cleanup")?;
        }
    }
    Ok(parent)
}

#[cfg(any(target_os = "linux", test))]
fn prepare_probe_fixtures(workspace: &Path) -> Result<tempfile::TempDir> {
    let parent = prepare_probe_parent(workspace)?;
    let directory = tempfile::Builder::new()
        .prefix(PROBE_FIXTURE_PREFIX)
        .rand_bytes(32)
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .context("runtime:probe-fixture")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.path().join("supervisor-file"))
        .context("runtime:probe-fixture")?;
    file.write_all(b"disposable supervisor fixture\n")
        .context("runtime:probe-fixture")?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o1777))
        .context("runtime:probe-fixture")?;
    Ok(directory)
}

#[cfg(any(target_os = "linux", test))]
fn with_probe_channels<T>(
    sockets: &Path,
    bind: impl FnOnce(&Path) -> std::io::Result<std::os::fd::OwnedFd>,
    run: impl FnOnce(std::os::fd::OwnedFd, std::os::fd::OwnedFd) -> T,
) -> Result<T> {
    let directory = tempfile::Builder::new()
        .prefix("probe-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(sockets)
        .context("runtime:probe-descriptor")?;
    let (_supervisor, guest) = UnixStream::pair().context("runtime:probe-descriptor")?;
    let listener = bind(&directory.path().join("ui")).context("runtime:probe-descriptor")?;
    Ok(run(guest.into(), listener))
}

#[cfg(any(target_os = "linux", test))]
fn record_probe_fact(
    backend: &dyn RuntimeBackend,
    operation: &str,
    digests: &RuntimeDigests,
    fact: Value,
) -> Result<()> {
    let passed = fact["boot_probe"]["passed"] == true;
    backend.sandbox_event("boot.facts", operation, "fact", fact)?;
    if passed {
        status(backend, digests, Some(digests), "starting")?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn probe_binary_sha256(bundle: &Path) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(bundle.join("guest/probe"))
        .context("runtime:probe-binary")?;
    let before = file.metadata().context("runtime:probe-binary")?;
    if !before.is_file() || before.mode() & 0o111 == 0 || before.len() > 32 * 1024 * 1024 {
        bail!("runtime:probe-binary");
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).context("runtime:probe-binary")?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > 32 * 1024 * 1024 {
            bail!("runtime:probe-binary");
        }
        hash.update(&buffer[..count]);
    }
    if !stable_file(&before, &file.metadata()?, total) {
        bail!("runtime:probe-binary");
    }
    Ok(hex(&hash.finalize()))
}

#[cfg(target_os = "linux")]
fn operation_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")
        .context("runtime:random")?
        .read_exact(&mut bytes)
        .context("runtime:random")?;
    Ok(hex(&bytes))
}

#[cfg(target_os = "linux")]
fn run_guest(
    backend: Arc<dyn RuntimeBackend>,
    config: &RuntimeConfig,
    digests: &RuntimeDigests,
    guest: &Path,
) -> Result<()> {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixListener;
    let operation = operation_id()?;
    backend.clear_harness_cookie();
    backend.sandbox_event(
        "sandbox.start",
        &operation,
        "intent",
        json!({"digest":digests.digest}),
    )?;
    let prepared: Result<_> = (|| {
        let (workspace, root, socket) = prepare_bounded_workspace(
            &config.state_dir,
            &config.work_dir,
            config.workspace_max_bytes,
        )?;
        match fs::remove_file(&socket) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => bail!("runtime:socket-remove"),
        }
        let listener = UnixListener::bind(&socket).context("runtime:ui-listener")?;
        let (supervisor_end, guest_end) = UnixStream::pair().context("runtime:proposal-socket")?;
        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = pipe()?;
        let stdin = OwnedFd::from(File::open("/dev/null").context("runtime:stdin")?);
        Ok((
            workspace,
            root,
            listener,
            supervisor_end,
            guest_end,
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
            stdin,
        ))
    })();
    let (
        workspace,
        root,
        listener,
        supervisor_end,
        guest_end,
        stdout_read,
        stdout_write,
        stderr_read,
        stderr_write,
        stdin,
    ) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            backend.sandbox_event(
                "sandbox.exit",
                &operation,
                "terminal",
                exit_body(None, Some(&error.to_string()), false),
            )?;
            return Err(error);
        }
    };
    let launch_policy = policy(config, workspace.clone(), root, guest.to_owned());
    let child = match crate::boot_probe::guard_start(
        config.boot_probe,
        &digests.digest,
        || {
            let execution: Result<_> = (|| {
                let fixtures = prepare_probe_fixtures(&workspace)?;
                let fixture_directory = Path::new("/workspace").join(
                    fixtures
                        .path()
                        .strip_prefix(&workspace)
                        .context("runtime:probe-fixture")?,
                );
                let probe_sha256 = probe_binary_sha256(&config.bundle_dir)?;
                let execution = with_probe_channels(
                    &config.state_dir.join("sockets"),
                    |path| UnixListener::bind(path).map(Into::into),
                    |proposal, ui| {
                        launcher::run_boot_probe(&launch_policy, &fixture_directory, proposal, ui)
                    },
                )?;
                fixtures.close().context("runtime:probe-fixture-cleanup")?;
                Ok(crate::boot_probe::ProbeRun {
                    output: execution.output,
                    landlock_abi: execution.setup.as_ref().map(|setup| setup.landlock_abi),
                    seccomp_filter_sha256: execution.setup.map(|setup| setup.seccomp_filter_hash),
                    probe_sha256: Some(probe_sha256),
                    wait_status: execution.wait_status,
                    failure: execution.refusal.map(|refusal| refusal.code.to_owned()),
                })
            })();
            execution.unwrap_or_else(|error| crate::boot_probe::ProbeRun::failed(error.to_string()))
        },
        |fact| record_probe_fact(backend.as_ref(), &operation, digests, fact),
        || {
            // Approval and measured bytes must still match after the bounded probe.
            if measure(config)? != *digests
                || !launch_allowed(
                    backend.is_bound()?,
                    digests,
                    backend.approved_release()?.as_ref(),
                )
            {
                bail!("runtime:release-changed-during-probe");
            }
            Ok(())
        },
        || {
            launcher::launch(
                &launch_policy,
                guest_end.into(),
                listener.into(),
                [stdin, stdout_write, stderr_write],
            )
            .map_err(|refusal| anyhow::anyhow!(refusal.code))
        },
    ) {
        Ok(child) => child,
        Err(error) => {
            backend.sandbox_event(
                "sandbox.exit",
                &operation,
                "terminal",
                json!({"code":error.to_string(),"setup":false}),
            )?;
            return Err(error);
        }
    };
    if let Err(error) = backend.sandbox_event(
        "sandbox.start",
        &operation,
        "fact",
        json!({
            "pid":child.pid,"kernel":child.kernel_release,"landlock_abi":child.landlock_abi,
            "seccomp_filter_sha256":child.seccomp_filter_hash,"digest":digests.digest
        }),
    ) {
        // SAFETY: this is the unreaped child owned by this launch thread.
        unsafe { libc::kill(child.pid, libc::SIGKILL) };
        let _ = child.wait();
        let _ = backend.sandbox_event(
            "sandbox.exit",
            &operation,
            "terminal",
            json!({"code":"runtime:start-record-failed","setup":true}),
        );
        return Err(error);
    }
    // The agent is running once its web server answers on FD 4 (it then prints its launch
    // line) or once it first speaks on FD 3, whichever comes first; announced once.
    let announced = Arc::new(std::sync::Once::new());
    let stdout_backend = Arc::clone(&backend);
    let stdout_announced = Arc::clone(&announced);
    let stdout_digests = digests.clone();
    let stdout = thread::spawn(move || {
        let _ = read_stdout(BufReader::new(stdout_read), |token| {
            stdout_backend.harness_token(token)?;
            stdout_announced.call_once(|| {
                let _ = status(
                    stdout_backend.as_ref(),
                    &stdout_digests,
                    Some(&stdout_digests),
                    "running",
                );
            });
            Ok(())
        });
    });
    let stderr = thread::spawn(move || {
        let _ = std::io::copy(&mut BufReader::new(stderr_read), &mut std::io::sink());
    });
    let dispatcher_backend = Arc::clone(&backend);
    let ready_backend = Arc::clone(&backend);
    let current = digests.clone();
    // SAFETY: pidfd_open takes a live child pid and returns a new owned descriptor.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child.pid, 0) };
    if descriptor < 0 {
        // SAFETY: the launch thread still owns this unreaped child.
        unsafe { libc::kill(child.pid, libc::SIGKILL) };
        let _ = child.wait();
        backend.sandbox_event(
            "sandbox.exit",
            &operation,
            "terminal",
            json!({"code":"runtime:pidfd","setup":true}),
        )?;
        bail!("runtime:pidfd");
    }
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: pidfd_open returned a unique descriptor that has no Rust owner.
    let pidfd = Arc::new(unsafe { OwnedFd::from_raw_fd(descriptor as i32) });
    let budget_pidfd = Arc::clone(&pidfd);
    let dispatcher = thread::spawn(move || {
        let on_ready = Box::new(move || {
            announced.call_once(|| {
                let _ = status(ready_backend.as_ref(), &current, Some(&current), "running");
            });
        });
        let _ = dispatcher_backend.dispatch(supervisor_end, on_ready);
        // SAFETY: the pidfd identifies this child even if its pid has been reused.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
    });
    let maximum = config.workspace_max_bytes;
    let stop_guest = {
        let cgroup = guest.to_owned();
        move |_: &'static str| {
            let _ = fs::write(cgroup.join("cgroup.kill"), "1");
            // SAFETY: the pidfd identifies this guest even if its pid was reused.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    budget_pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
        }
    };
    let (reserve_stop, reserve_stopped) = std::sync::mpsc::channel();
    let (scan_stop, scan_stopped) = std::sync::mpsc::channel();
    let reserve_monitor = {
        let (workspace, stop_guest) = (workspace.clone(), stop_guest.clone());
        thread::spawn(move || {
            monitor_workspace(
                || disk_reserve(&workspace, DISK_RESERVE_BYTES),
                reserve_stopped,
                stop_guest,
                DISK_CHECK_INTERVAL,
            )
        })
    };
    let monitor = thread::spawn(move || {
        monitor_workspace(
            || workspace_size(&workspace, maximum),
            scan_stopped,
            stop_guest,
            WORKSPACE_SCAN_INTERVAL,
        )
    });
    let wait = child.wait();
    let _ = reserve_stop.send(());
    let _ = scan_stop.send(());
    let reserve_code = reserve_monitor
        .join()
        .unwrap_or(Some("runtime:workspace-monitor"));
    let scan_code = monitor.join().unwrap_or(Some("runtime:workspace-monitor"));
    let workspace_code = reserve_code.or(scan_code);
    let _ = dispatcher.join();
    let _ = stdout.join();
    let _ = stderr.join();
    backend.clear_harness_cookie();
    let (wait_status, code) = match wait {
        Ok(wait_status) => (Some(wait_status), None),
        Err(refusal) => (None, Some(refusal.code)),
    };
    backend.sandbox_event(
        "sandbox.exit",
        &operation,
        "terminal",
        exit_body(wait_status, workspace_code.or(code), true),
    )?;
    status(backend.as_ref(), digests, Some(digests), "exited")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn manage(backend: Arc<dyn RuntimeBackend>, config: RuntimeConfig) -> Result<()> {
    let mut digests = measure(&config)?;
    backend.runtime_measured(&digests)?;
    let guest = cgroups(&config.cgroup_root)?;
    let mut failures = 0_u32;
    let mut probe_failed = false;
    loop {
        let bound = backend.is_bound()?;
        let approved = backend.approved_release()?;
        status(
            backend.as_ref(),
            &digests,
            approved.as_ref(),
            if probe_failed {
                crate::boot_probe::FAILURE
            } else {
                "stopped"
            },
        )?;
        if bound && approved.as_ref() != Some(&digests) {
            backend.ensure_release(&digests)?;
        }
        if !launch_allowed(bound, &digests, approved.as_ref()) {
            thread::sleep(Duration::from_millis(250));
            continue;
        }
        // Re-measure before each launch so changed runtime bytes require a fresh approval.
        let measured = measure(&config)?;
        if measured != digests {
            digests = measured;
            failures = 0;
            continue;
        }
        if !launch_allowed(
            backend.is_bound()?,
            &digests,
            backend.approved_release()?.as_ref(),
        ) {
            continue;
        }
        status(
            backend.as_ref(),
            &digests,
            Some(&digests),
            agent_start_status(probe_failed),
        )?;
        let started = std::time::Instant::now();
        let result = run_guest(Arc::clone(&backend), &config, &digests, &guest);
        probe_failed = false;
        if let Err(error) = result {
            eprintln!("runtime guest refused: {error:#}");
            probe_failed = config.boot_probe && error.to_string() == crate::boot_probe::FAILURE;
            status(
                backend.as_ref(),
                &digests,
                Some(&digests),
                if probe_failed {
                    crate::boot_probe::FAILURE
                } else {
                    "exited"
                },
            )?;
        }
        failures = if started.elapsed() >= Duration::from_secs(60) {
            0
        } else {
            failures.saturating_add(1)
        };
        thread::sleep(restart_delay(failures));
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn agent_start_status(probe_failed: bool) -> &'static str {
    if probe_failed {
        crate::boot_probe::FAILURE
    } else {
        "starting"
    }
}

#[cfg(any(target_os = "linux", test))]
fn restart_delay(failures: u32) -> Duration {
    Duration::from_millis(250_u64.saturating_mul(1_u64 << failures.min(7)).min(30_000))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    static LINUX_GUEST_FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    use super::*;

    #[test]
    fn antibody_guest_private_directories_do_not_stop_the_scan() {
        // Found live on S2: the guest's 0700 directories made every scan fail
        // (runtime:workspace-scan) and the agent could never start again.
        let workspace = TestDir::new();
        let private = workspace.0.join("guest-private");
        fs::create_dir(&private).unwrap();
        fs::write(private.join("data"), vec![0; 4096]).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o000)).unwrap();
        let result = workspace_size(&workspace.0, 1 << 30);
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn antibody_disk_reserve_refuses_when_the_filesystem_is_short() {
        let workspace = TestDir::new();
        assert!(disk_reserve(&workspace.0, 1).is_ok());
        assert_eq!(
            disk_reserve(&workspace.0, u64::MAX),
            Err("runtime:disk-reserve")
        );
        assert!(workspace_guard(&workspace.0, 1 << 30).is_ok());
    }
    use std::io::Cursor;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sovereign-runtime-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn release() -> RuntimeDigests {
        RuntimeDigests {
            digest: "a".repeat(64),
            components: Components {
                node: "b".repeat(64),
                harness: "c".repeat(64),
                guest: "d".repeat(64),
            },
        }
    }

    #[test]
    fn never_unbound_or_unapproved_launch() {
        let current = release();
        assert!(!launch_allowed(false, &current, Some(&current)));
        assert!(!launch_allowed(true, &current, None));
        let mut wrong = current.clone();
        wrong.digest = "e".repeat(64);
        assert!(!launch_allowed(true, &current, Some(&wrong)));
        wrong = current.clone();
        wrong.components.node = "f".repeat(64);
        assert!(!launch_allowed(true, &current, Some(&wrong)));
        assert!(launch_allowed(true, &current, Some(&current)));
    }

    #[test]
    fn stdout_token_parser_rejects_hostile_inputs() {
        let valid = format!(
            "{}{}",
            String::from_utf8_lossy(TOKEN_PREFIX),
            "Az0_-".repeat(8) + "abc"
        );
        assert_eq!(
            parse_web_token(valid.as_bytes()),
            Some("Az0_-".repeat(8) + "abc")
        );
        for hostile in [
            format!(" {valid}"),
            format!("{valid} "),
            format!("{valid}\r"),
            format!("{valid}\n"),
            format!("{valid}&next=owner"),
            valid.replace("http://", "https://"),
            valid.replace("127.0.0.1", "evil.example"),
            valid.replace("3080", "3081"),
            valid.replace("?token=", "?token=x&token="),
            valid.replace("Az0_-", "Az0_/"),
            valid.replace("Az0_-", "Az0_%"),
            valid.replace("abc", "ab"),
            valid.replace("abc", "abcd"),
        ] {
            assert!(
                parse_web_token(hostile.as_bytes()).is_none(),
                "hostile token line accepted"
            );
        }
        assert!(parse_web_token(&[0xff; 80]).is_none());
    }

    #[test]
    fn stdout_caps_lines_and_offers_token_once() {
        let valid = format!(
            "{}{}\n",
            String::from_utf8_lossy(TOKEN_PREFIX),
            "a".repeat(43)
        );
        let input = format!("{}\nnoise\n{valid}{valid}", "x".repeat(MAX_STDOUT_LINE + 1));
        let mut tokens = Vec::new();
        let largest = read_stdout(Cursor::new(input), |token| {
            tokens.push(token);
            Ok(())
        });
        assert!(largest <= MAX_STDOUT_LINE);
        assert_eq!(tokens, vec!["a".repeat(43)]);
    }

    #[test]
    fn digest_binds_paths_modes_contents_and_link_targets() {
        let directory = TestDir::new();
        fs::write(directory.0.join("a"), b"first").unwrap();
        fs::write(directory.0.join("z"), b"second").unwrap();
        let original = tree_digest(&directory.0).unwrap();
        fs::rename(directory.0.join("a"), directory.0.join("c")).unwrap();
        assert_ne!(tree_digest(&directory.0).unwrap(), original);
        fs::rename(directory.0.join("c"), directory.0.join("a")).unwrap();
        fs::write(directory.0.join("a"), b"alter").unwrap();
        assert_ne!(tree_digest(&directory.0).unwrap(), original);
        fs::write(directory.0.join("a"), b"first").unwrap();
        fs::set_permissions(directory.0.join("a"), fs::Permissions::from_mode(0o600)).unwrap();
        let private = tree_digest(&directory.0).unwrap();
        fs::set_permissions(directory.0.join("a"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(tree_digest(&directory.0).unwrap(), private);
        symlink("a", directory.0.join("link")).unwrap();
        let first_link = tree_digest(&directory.0).unwrap();
        fs::remove_file(directory.0.join("link")).unwrap();
        symlink("z", directory.0.join("link")).unwrap();
        assert_ne!(tree_digest(&directory.0).unwrap(), first_link);
    }

    #[test]
    fn runtime_paths_have_a_stable_byte_order() {
        let mut paths = [
            PathBuf::from("z"),
            PathBuf::from("a/y"),
            PathBuf::from("a"),
            PathBuf::new(),
        ];
        sort_paths(&mut paths);
        assert_eq!(
            paths,
            [
                PathBuf::new(),
                PathBuf::from("a"),
                PathBuf::from("a/y"),
                PathBuf::from("z")
            ]
        );
    }

    #[test]
    fn hashing_refuses_changed_or_replaced_files() {
        let directory = TestDir::new();
        fs::write(directory.0.join("a"), b"first").unwrap();
        fs::write(directory.0.join("b"), b"other").unwrap();
        let before = fs::metadata(directory.0.join("a")).unwrap();
        let other = fs::metadata(directory.0.join("b")).unwrap();
        assert!(same_inode(&before, &before));
        assert!(!same_inode(&before, &other));
        assert!(stable_file(&before, &before, before.len()));
        assert!(!stable_file(&before, &before, before.len() + 1));
        std::thread::sleep(Duration::from_millis(10));
        fs::write(directory.0.join("a"), b"alter").unwrap();
        let after = fs::metadata(directory.0.join("a")).unwrap();
        assert_eq!(before.len(), after.len());
        assert!(!stable_file(&before, &after, after.len()));
    }

    #[test]
    fn runtime_links_cannot_escape_measured_tree() {
        let directory = TestDir::new();
        let outside = TestDir::new();
        fs::write(outside.0.join("unmeasured"), b"outside").unwrap();
        symlink(outside.0.join("unmeasured"), directory.0.join("escape")).unwrap();
        assert!(tree_digest(&directory.0)
            .unwrap_err()
            .to_string()
            .contains("runtime:symlink-escape"));
    }

    #[test]
    fn runtime_root_cannot_be_a_symlink() {
        let directory = TestDir::new();
        let parent = TestDir::new();
        symlink(&directory.0, parent.0.join("runtime")).unwrap();
        assert!(tree_digest(&parent.0.join("runtime")).is_err());
        fs::write(parent.0.join("file"), b"file").unwrap();
        assert!(tree_digest(&parent.0.join("file")).is_err());
    }

    #[test]
    fn runtime_special_files_are_refused() {
        let directory = TestDir::new();
        assert!(std::process::Command::new("mkfifo")
            .arg(directory.0.join("fifo"))
            .status()
            .unwrap()
            .success());
        assert!(tree_digest(&directory.0)
            .unwrap_err()
            .to_string()
            .contains("runtime:tree-special-file"));
    }

    #[test]
    fn restarted_workspace_cannot_follow_guest_symlinks() {
        let state = TestDir::new();
        let outside = TestDir::new();
        fs::set_permissions(&outside.0, fs::Permissions::from_mode(0o700)).unwrap();
        let (workspace, _, _) = prepare_workspace(&state.0, &state.0.join("guest")).unwrap();
        assert_eq!(
            fs::metadata(workspace.join("dsh/profiles/web/package.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
        fs::remove_dir(workspace.join("home")).unwrap();
        symlink(&outside.0, workspace.join("home")).unwrap();
        assert!(prepare_workspace(&state.0, &state.0.join("guest"))
            .unwrap_err()
            .to_string()
            .contains("runtime:workspace-symlink"));
        assert_eq!(fs::metadata(&outside.0).unwrap().mode() & 0o777, 0o700);
        fs::remove_file(workspace.join("home")).unwrap();
        fs::write(workspace.join("home"), b"file").unwrap();
        assert!(prepare_workspace(&state.0, &state.0.join("guest")).is_err());
        fs::remove_file(workspace.join("home")).unwrap();
        writable_dir(&workspace.join("home")).unwrap();
        let manifest = workspace.join("dsh/profiles/web/package.json");
        fs::remove_file(&manifest).unwrap();
        fs::write(outside.0.join("file"), b"owner bytes").unwrap();
        symlink(outside.0.join("file"), &manifest).unwrap();
        prepare_workspace(&state.0, &state.0.join("guest")).unwrap();
        assert_eq!(fs::read(&manifest).unwrap(), PROFILE_MANIFEST);
        assert_eq!(fs::read(outside.0.join("file")).unwrap(), b"owner bytes");
        fs::remove_file(&manifest).unwrap();
        fs::hard_link(outside.0.join("file"), &manifest).unwrap();
        prepare_workspace(&state.0, &state.0.join("guest")).unwrap();
        assert_eq!(fs::read(&manifest).unwrap(), PROFILE_MANIFEST);
        assert_eq!(fs::read(outside.0.join("file")).unwrap(), b"owner bytes");
    }

    #[test]
    fn antibody_profile_replacement_is_undone_before_launch() {
        // Repair succeeds; a directory obstruction is runtime:profile-install.
        let state = TestDir::new();
        let work = state.0.join("guest");
        let (workspace, _, _) = prepare_workspace(&state.0, &work).unwrap();
        let manifest = workspace.join("dsh/profiles/web/package.json");
        let hostile = state.0.join("hostile");
        fs::write(
            &hostile,
            b"{\"dsh\":{\"profile\":{\"bundles\":[\"guest-code\"]}}}",
        )
        .unwrap();
        for attack in ["bytes", "mode", "symlink", "hardlink"] {
            fs::remove_file(&manifest).unwrap();
            match attack {
                "bytes" => fs::copy(&hostile, &manifest).map(|_| ()).unwrap(),
                "mode" => {
                    fs::write(&manifest, PROFILE_MANIFEST).unwrap();
                    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o666)).unwrap();
                }
                "symlink" => symlink(&hostile, &manifest).unwrap(),
                "hardlink" => fs::hard_link(&hostile, &manifest).unwrap(),
                _ => unreachable!(),
            }
            prepare_workspace(&state.0, &work).unwrap();
            let metadata = fs::symlink_metadata(&manifest).unwrap();
            assert!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "{attack}"
            );
            // SAFETY: geteuid only reads the test process's credential.
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() }, "{attack}");
            assert_eq!(metadata.mode() & 0o7777, 0o644, "{attack}");
            assert_eq!(metadata.nlink(), 1, "{attack}");
            assert_eq!(fs::read(&manifest).unwrap(), PROFILE_MANIFEST, "{attack}");
            assert!(fs::read(&hostile)
                .unwrap()
                .windows(10)
                .any(|bytes| bytes == b"guest-code"));
        }
        fs::remove_file(&manifest).unwrap();
        fs::create_dir(&manifest).unwrap();
        fs::write(manifest.join("guest-entry"), b"must not traverse or delete").unwrap();
        assert_eq!(
            prepare_workspace(&state.0, &work).unwrap_err().to_string(),
            "runtime:profile-install"
        );
        assert_eq!(
            fs::read(manifest.join("guest-entry")).unwrap(),
            b"must not traverse or delete"
        );
    }

    #[test]
    fn antibody_supervisor_directories_keep_sticky_bit() {
        // Sticky ownership prevents guest unlink; kernel refusal is EPERM.
        let state = TestDir::new();
        let (workspace, _, _) = prepare_workspace(&state.0, &state.0.join("guest")).unwrap();
        for name in [
            "",
            ".git",
            "home",
            "dsh",
            "agents",
            "dsh/profiles",
            "dsh/profiles/web",
        ] {
            let metadata = fs::metadata(workspace.join(name)).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o1777, "{name}");
            // SAFETY: geteuid only reads the test process's credential.
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        }
    }

    #[test]
    fn antibody_workspace_refuses_foreign_directory_owner() {
        // Refusal: runtime:workspace-not-owned, before changing directory permissions.
        let state = TestDir::new();
        let metadata = fs::metadata(&state.0).unwrap();
        assert_eq!(
            writable_dir_owned_by(&state.0, metadata.uid().wrapping_add(1))
                .unwrap_err()
                .to_string(),
            "runtime:workspace-not-owned"
        );
        assert_eq!(fs::metadata(&state.0).unwrap().mode(), metadata.mode());
    }

    #[test]
    fn antibody_workspace_limit_refuses_sparse_growth_before_launch() {
        // Refusal: runtime:workspace-limit; symlinks never charge outside owner data.
        let workspace = TestDir::new();
        let outside = TestDir::new();
        let maximum = 128 * 1024;
        File::create(outside.0.join("owner-data"))
            .unwrap()
            .set_len(maximum * 2)
            .unwrap();
        symlink(&outside.0, workspace.0.join("outside")).unwrap();
        assert!(workspace_size(&workspace.0, maximum).is_ok());
        let file = File::create(workspace.0.join("guest-sparse")).unwrap();
        file.set_len(maximum * 2).unwrap();
        assert_eq!(
            workspace_size(&workspace.0, maximum),
            Err("runtime:workspace-limit")
        );
        assert!(workspace_size(&workspace.0, maximum * 4).is_ok());
        assert_eq!(
            workspace_size(&workspace.0.join("outside"), maximum),
            Err("runtime:workspace-scan")
        );
        let state = TestDir::new();
        let work = state.0.join("guest");
        let (workspace, _, _) = prepare_bounded_workspace(&state.0, &work, maximum).unwrap();
        File::create(workspace.join("guest-growth"))
            .unwrap()
            .set_len(maximum * 2)
            .unwrap();
        assert_eq!(
            prepare_bounded_workspace(&state.0, &work, maximum)
                .unwrap_err()
                .to_string(),
            "runtime:workspace-limit"
        );
    }

    #[test]
    fn antibody_workspace_monitor_stops_guest_and_records_reason() {
        // Terminal sandbox.exit code: runtime:workspace-limit; owner state is untouched.
        let workspace = TestDir::new();
        let owner = TestDir::new();
        fs::write(owner.0.join("owner-state"), b"owner can still act").unwrap();
        let (_done, stopped) = std::sync::mpsc::channel();
        let mut scans = 0;
        let mut recorded = None;
        let reason = monitor_workspace(
            || {
                scans += 1;
                if scans == 2 {
                    File::create(workspace.0.join("guest-growth"))
                        .unwrap()
                        .set_len(256 * 1024)
                        .unwrap();
                }
                workspace_size(&workspace.0, 128 * 1024)
            },
            stopped,
            |code| recorded = Some(exit_body(None, Some(code), true)),
            Duration::from_millis(10),
        );
        assert_eq!(scans, 2);
        assert_eq!(reason, Some("runtime:workspace-limit"));
        assert_eq!(recorded.unwrap()["code"], "runtime:workspace-limit");
        assert_eq!(
            fs::read(owner.0.join("owner-state")).unwrap(),
            b"owner can still act"
        );
    }

    #[test]
    fn antibody_workspace_depth_is_bounded() {
        // The scan stops descending past 64 levels (bounded descriptors and stack) and a
        // guest-built deep tree never stops the agent; the disk reserve still bounds it.
        let workspace = TestDir::new();
        let mut path = workspace.0.clone();
        for _ in 0..70 {
            path.push("d");
            fs::create_dir(&path).unwrap();
        }
        fs::write(path.join("deep"), vec![0; 64 * 1024]).unwrap();
        let counted = workspace_size(&workspace.0, 1024 * 1024 * 1024).unwrap();
        assert!(counted < 64 * 1024 + 70 * 8192, "{counted}");
    }

    #[test]
    fn antibody_guest_unsearchable_directories_do_not_stop_the_scan() {
        // Independent review: a directory the supervisor can list but not search (0644)
        // made every fstatat fail EACCES and the agent could never start again.
        let workspace = TestDir::new();
        let listable = workspace.0.join("listable-only");
        fs::create_dir(&listable).unwrap();
        fs::write(listable.join("hidden"), vec![0; 4096]).unwrap();
        fs::set_permissions(&listable, fs::Permissions::from_mode(0o644)).unwrap();
        let result = workspace_size(&workspace.0, 1 << 30);
        fs::set_permissions(&listable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn antibody_workspace_entry_flood_and_preallocation_are_counted() {
        // Refusal: runtime:workspace-limit, including empty-file metadata and reserved blocks.
        assert_eq!(workspace_entry_bytes(0, 16), 8192);
        let workspace = TestDir::new();
        File::create(workspace.0.join("guest-empty-file")).unwrap();
        assert_eq!(
            workspace_size(&workspace.0, 4096),
            Err("runtime:workspace-limit")
        );
    }

    #[test]
    fn antibody_production_runtime_never_selects_own_uid_mapping() {
        // Refusal for caller uid is launcher:invalid-identity; production never opts in.
        let config = RuntimeConfig {
            boot_probe: false,
            state_dir: "/state".into(),
            work_dir: "/work".into(),
            cgroup_root: "/sys/fs/cgroup/guest".into(),
            node_dir: "/node".into(),
            harness_dir: "/harness".into(),
            bundle_dir: "/bundle".into(),
            subordinate_uid: 100_000,
            subordinate_gid: 100_000,
            chat_hostname: "chat.example".into(),
            model: "model".into(),
            node_npub: "npub-node".into(),
            agent_npub: "npub-agent".into(),
            pids_max: 512,
            memory_max_bytes: 2 * 1024 * 1024 * 1024,
            cpu_max: "200000 100000".into(),
            file_size_max_bytes: 1024 * 1024 * 1024,
            workspace_max_bytes: 16 * 1024 * 1024 * 1024,
        };
        let policy = policy(
            &config,
            "/work/workspace".into(),
            "/work/root".into(),
            "/sys/fs/cgroup/guest".into(),
        );
        assert!(!policy.identity.allow_development_own_id);
        let env = policy
            .env
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert!(env.contains(&"AUKORA_NODE_NPUB=npub-node"));
        assert!(env.contains(&"AUKORA_AGENT_NPUB=npub-agent"));
        assert_eq!(
            env.iter()
                .filter(|value| value.starts_with("AUKORA_"))
                .count(),
            3
        );
        assert!(policy
            .readonly_binds
            .iter()
            .all(|bind| !config.state_dir.starts_with(&bind.host)
                && !bind.host.starts_with(&config.state_dir)));
        assert_eq!(policy.file_size_max_bytes, config.file_size_max_bytes);
        assert_eq!(
            policy.readonly_workspace_files,
            vec![PathBuf::from("dsh/profiles/web/package.json")]
        );
    }

    #[test]
    fn antibody_boot_probe_fixtures_cannot_follow_guest_links() {
        let workspace = TestDir::new();
        let outside = TestDir::new();
        fs::write(outside.0.join("owner-file"), b"private owner bytes").unwrap();
        symlink(&outside.0, workspace.0.join(".aukora-boot-probe")).unwrap();
        let first = prepare_probe_fixtures(&workspace.0).unwrap();
        assert_ne!(first.path(), workspace.0.join(".aukora-boot-probe"));
        assert!(!outside.0.join("supervisor-file").exists());
        let fixture = first.path().join("supervisor-file");
        fs::remove_file(&fixture).unwrap();
        symlink(outside.0.join("owner-file"), &fixture).unwrap();
        let first_path = first.keep();
        let second = prepare_probe_fixtures(&workspace.0).unwrap();
        assert_ne!(first_path, second.path());
        assert!(!first_path.exists());
        second.close().unwrap();
        assert_eq!(
            fs::read(outside.0.join("owner-file")).unwrap(),
            b"private owner bytes"
        );
    }

    #[test]
    fn antibody_boot_probe_stale_foreign_and_crash_debris_never_select_the_next_fixture() {
        let workspace = TestDir::new();
        let stale = workspace.0.join(".aukora-boot-probe");
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("file-size"), b"agent bytes").unwrap();
        fs::create_dir(stale.join("supervisor-file")).unwrap();
        let first = prepare_probe_fixtures(&workspace.0).unwrap().keep();
        fs::write(first.join("file-size"), b"crash debris").unwrap();
        for _ in 0..3 {
            let next = prepare_probe_fixtures(&workspace.0).unwrap();
            assert_ne!(next.path(), stale);
            assert_ne!(next.path(), first);
            assert!(!next.path().join("file-size").exists());
            assert!(next.path().join("supervisor-file").is_file());
        }
        assert_eq!(fs::read(stale.join("file-size")).unwrap(), b"agent bytes");
        assert!(!first.exists());
    }

    #[test]
    fn antibody_boot_probe_parent_is_private_and_supervisor_owned() {
        let workspace = TestDir::new();
        let fixtures = prepare_probe_fixtures(&workspace.0).unwrap();
        let parent = fixtures.path().parent().unwrap();
        assert_eq!(parent, workspace.0.join(PROBE_FIXTURE_PARENT));
        let metadata = fs::symlink_metadata(parent).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        // SAFETY: geteuid only reads the test process credential.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(
            validate_probe_parent(&metadata, metadata.uid().wrapping_add(1))
                .unwrap_err()
                .to_string(),
            "runtime:probe-parent-owner"
        );
        let file = parent.join("not-a-directory");
        fs::write(&file, b"supervisor bytes").unwrap();
        assert_eq!(
            validate_probe_parent(&fs::symlink_metadata(file).unwrap(), metadata.uid())
                .unwrap_err()
                .to_string(),
            "runtime:probe-parent-directory"
        );
    }

    #[test]
    fn antibody_boot_probe_parent_refuses_guest_links() {
        let workspace = TestDir::new();
        let outside = TestDir::new();
        fs::set_permissions(&outside.0, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(outside.0.join("owner-file"), b"private owner bytes").unwrap();
        let parent = workspace.0.join(PROBE_FIXTURE_PARENT);
        symlink(&outside.0, &parent).unwrap();
        assert_eq!(
            prepare_probe_fixtures(&workspace.0)
                .unwrap_err()
                .to_string(),
            "runtime:probe-parent-directory"
        );
        assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 1);
        assert_eq!(
            fs::read(outside.0.join("owner-file")).unwrap(),
            b"private owner bytes"
        );
    }

    #[test]
    fn antibody_boot_probe_sweep_refuses_unsafe_parent_before_removing_data() {
        let workspace = TestDir::new();
        let stale = prepare_probe_fixtures(&workspace.0).unwrap().keep();
        let parent = stale.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o777)).unwrap();
        let result = prepare_probe_fixtures(&workspace.0);
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result.unwrap_err().to_string(), "runtime:probe-parent-mode");
        assert!(stale.join("supervisor-file").is_file());
    }

    #[test]
    fn antibody_boot_probe_entry_sweep_removes_crash_debris_without_following_links() {
        let workspace = TestDir::new();
        let outside = TestDir::new();
        fs::write(outside.0.join("owner-file"), b"private owner bytes").unwrap();
        let stale = prepare_probe_fixtures(&workspace.0).unwrap().keep();
        fs::write(stale.join("file-size"), b"crash debris").unwrap();
        fs::create_dir(stale.join("nested")).unwrap();
        symlink(&outside.0, stale.join("nested/outside")).unwrap();
        let parent = stale.parent().unwrap();
        let top_link = parent.join(format!("{PROBE_FIXTURE_PREFIX}outside"));
        symlink(&outside.0, &top_link).unwrap();
        let top_hardlink = parent.join(format!("{PROBE_FIXTURE_PREFIX}hardlink"));
        fs::hard_link(outside.0.join("owner-file"), &top_hardlink).unwrap();
        fs::write(parent.join("unrelated"), b"supervisor bytes").unwrap();
        let next = prepare_probe_fixtures(&workspace.0).unwrap();
        assert_ne!(next.path(), stale);
        assert!(!stale.exists());
        assert!(fs::symlink_metadata(top_link).is_err());
        assert!(!top_hardlink.exists());
        assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 1);
        assert_eq!(
            fs::read(outside.0.join("owner-file")).unwrap(),
            b"private owner bytes"
        );
        assert_eq!(
            fs::read(parent.join("unrelated")).unwrap(),
            b"supervisor bytes"
        );
        assert!(!next.path().join("file-size").exists());
    }

    #[test]
    fn antibody_boot_probe_legacy_sweep_preserves_foreign_entries_and_link_targets() {
        let workspace = TestDir::new();
        writable_dir(&workspace.0).unwrap();
        let outside = TestDir::new();
        fs::set_permissions(&outside.0, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(outside.0.join("owner-file"), b"private owner bytes").unwrap();
        let legacy = workspace.0.join(format!("{PROBE_FIXTURE_PREFIX}legacy"));
        fs::create_dir(&legacy).unwrap();
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o1777)).unwrap();
        fs::write(legacy.join("supervisor-file"), b"crash debris").unwrap();
        symlink(&outside.0, legacy.join("outside")).unwrap();
        let top_link = workspace.0.join(format!("{PROBE_FIXTURE_PREFIX}link"));
        symlink(&outside.0, &top_link).unwrap();
        let top_file = workspace.0.join(format!("{PROBE_FIXTURE_PREFIX}file"));
        fs::write(&top_file, b"supervisor bytes").unwrap();
        fs::set_permissions(&top_file, fs::Permissions::from_mode(0o700)).unwrap();
        let unrelated = workspace.0.join(format!("{PROBE_FIXTURE_PREFIX}unrelated"));
        fs::create_dir(&unrelated).unwrap();
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o755)).unwrap();
        let uid = fs::symlink_metadata(&legacy).unwrap().uid();
        sweep_legacy_probe_fixtures(&workspace.0, uid.wrapping_add(1)).unwrap();
        assert!(legacy.is_dir());
        prepare_probe_fixtures(&workspace.0).unwrap();
        assert!(!legacy.exists());
        assert!(unrelated.is_dir());
        assert_eq!(fs::read(top_file).unwrap(), b"supervisor bytes");
        assert!(fs::symlink_metadata(top_link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 1);
        assert_eq!(
            fs::read(outside.0.join("owner-file")).unwrap(),
            b"private owner bytes"
        );
    }

    #[test]
    fn antibody_boot_probe_fixture_is_private_and_removed_on_success_or_error() {
        let workspace = TestDir::new();
        let fixtures = prepare_probe_fixtures(&workspace.0).unwrap();
        let path = fixtures.path().to_owned();
        let file = fs::symlink_metadata(path.join("supervisor-file")).unwrap();
        assert!(file.is_file());
        assert_eq!(file.nlink(), 1);
        assert_eq!(file.mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o1777);
        // SAFETY: geteuid only reads the process credential.
        assert_eq!(file.uid(), unsafe { libc::geteuid() });
        fixtures.close().unwrap();
        assert!(!path.exists());
        let mut failed_path = PathBuf::new();
        let result = (|| -> Result<()> {
            let fixtures = prepare_probe_fixtures(&workspace.0)?;
            failed_path = fixtures.path().to_owned();
            fs::write(failed_path.join("file-size"), b"interrupted probe")?;
            bail!("runtime:test-probe-timeout");
        })();
        assert!(result.is_err());
        assert!(!failed_path.exists());
    }

    #[test]
    fn antibody_boot_probe_channels_are_disposable_and_separate_from_live_sockets() {
        let sockets = tempfile::tempdir_in("/tmp").unwrap();
        let live_path = sockets.path().join("ui.sock");
        fs::write(&live_path, b"live listener marker").unwrap();
        let (mut live_parent, _live_guest) = UnixStream::pair().unwrap();
        live_parent.set_nonblocking(true).unwrap();
        let (mut ui_parent, ui_mock) = UnixStream::pair().unwrap();
        let mut throwaway_path = PathBuf::new();
        // The sandbox denies filesystem binds; inject only the listener factory.
        with_probe_channels(
            sockets.path(),
            |path| {
                throwaway_path = path.to_owned();
                assert_ne!(path, live_path);
                assert_ne!(path.parent().unwrap(), sockets.path());
                assert_eq!(fs::metadata(path.parent().unwrap())?.mode() & 0o777, 0o700);
                fs::write(path, b"disposable listener marker")?;
                Ok(ui_mock.into())
            },
            |proposal, ui| {
                let mut proposal = UnixStream::from(proposal);
                proposal.write_all(b"untrusted probe frame").unwrap();
                let mut ui = UnixStream::from(ui);
                ui.write_all(b"disposable UI bytes").unwrap();
                let mut bytes = [0; 19];
                ui_parent.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"disposable UI bytes");
                assert_eq!(
                    live_parent.read(&mut [0]).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            },
        )
        .unwrap();
        assert!(!throwaway_path.exists());
        assert_eq!(fs::read(&live_path).unwrap(), b"live listener marker");
        assert_eq!(fs::read_dir(sockets.path()).unwrap().count(), 1);
    }

    #[test]
    fn antibody_boot_probe_pass_clears_a_previous_failure_before_agent_announces() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = crate::node::Node::open(
            crate::e2e::config(directory.path()),
            runtime.handle().clone(),
        )
        .unwrap();
        let digest = release();
        status(
            node.as_ref(),
            &digest,
            Some(&digest),
            crate::boot_probe::FAILURE,
        )
        .unwrap();
        record_probe_fact(
            node.as_ref(),
            "probe",
            &digest,
            json!({"boot_probe":{"passed":false}}),
        )
        .unwrap();
        assert_eq!(
            node.runtime.lock().unwrap().agent,
            crate::boot_probe::FAILURE
        );
        record_probe_fact(
            node.as_ref(),
            "probe",
            &digest,
            json!({"boot_probe":{"passed":true}}),
        )
        .unwrap();
        assert_eq!(node.runtime.lock().unwrap().agent, "starting");
        let record: String = node
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT body FROM aura WHERE kind='boot.facts' ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&record).unwrap()["boot_probe"]["passed"],
            true
        );
    }

    #[test]
    fn antibody_boot_probe_binary_hash_binds_bytes_and_refuses_links() {
        let bundle = TestDir::new();
        fs::create_dir(bundle.0.join("guest")).unwrap();
        let probe = bundle.0.join("guest/probe");
        fs::write(&probe, b"first approved probe").unwrap();
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap();
        let first = probe_binary_sha256(&bundle.0).unwrap();
        fs::write(&probe, b"other approved probe").unwrap();
        assert_ne!(probe_binary_sha256(&bundle.0).unwrap(), first);
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(probe_binary_sha256(&bundle.0).is_err());
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&probe, bundle.0.join("other")).unwrap();
        symlink(bundle.0.join("other"), &probe).unwrap();
        assert!(probe_binary_sha256(&bundle.0).is_err());
        fs::remove_file(&probe).unwrap();
        let file = File::create(&probe).unwrap();
        file.set_len(32 * 1024 * 1024 + 1).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(probe_binary_sha256(&bundle.0).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn antibody_nostr_guest_cannot_open_supervisor_database_or_key() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixListener;
        let Some(cgroup) = std::env::var_os("LAUNCHER_TEST_CGROUP") else {
            eprintln!(
                "UNPERFORMED Nostr isolation: configure existing LAUNCHER_TEST Linux fixtures"
            );
            return;
        };
        let _fixture_guard = LINUX_GUEST_FIXTURE.lock().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o711)).unwrap();
        let get_path =
            |name| PathBuf::from(std::env::var_os(name).expect("Linux fixture variable required"));
        let workspace = get_path("LAUNCHER_TEST_WORKSPACE");
        writable_dir(&workspace).unwrap();
        for name in [".git", "dsh", "dsh/profiles", "dsh/profiles/web"] {
            writable_dir(&workspace.join(name)).unwrap();
        }
        write_manifest(&workspace.join("dsh/profiles/web")).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node =
            crate::node::Node::open(crate::e2e::config(fixture.path()), runtime.handle().clone())
                .unwrap();
        let mut config = node.runtime_config();
        config.subordinate_uid = std::env::var("LAUNCHER_TEST_UID").unwrap().parse().unwrap();
        config.subordinate_gid = std::env::var("LAUNCHER_TEST_GID").unwrap().parse().unwrap();
        for directory in [&config.node_dir, &config.harness_dir, &config.bundle_dir] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir(config.bundle_dir.join("guest")).unwrap();
        fs::copy(
            get_path("LAUNCHER_TEST_PROBE"),
            config.bundle_dir.join("guest/probe"),
        )
        .unwrap();
        fs::set_permissions(
            config.bundle_dir.join("guest"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(
            config.bundle_dir.join("guest/probe"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut production = policy(
            &config,
            workspace,
            get_path("LAUNCHER_TEST_ROOT"),
            cgroup.into(),
        );
        production.executable = "/opt/sovereign/guest/probe".into();
        for (attack, variable, path) in [
            ("open-db", "DB_PATH", node.db_path()),
            (
                "open-key",
                "KEY_PATH",
                config.state_dir.join("node.ed25519"),
            ),
        ] {
            assert!(path.is_file());
            production.argv = [
                "/opt/sovereign/guest/probe",
                "--confined",
                &format!("--only={attack}"),
            ]
            .map(Into::into)
            .into();
            production
                .env
                .push(format!("AUKORA_PROBE_{variable}={}", path.display()).into());
            let listener =
                UnixListener::bind(fixture.path().join(format!("{attack}.sock"))).unwrap();
            let (_parent, child) = UnixStream::pair().unwrap();
            let (mut stdout, stdout_write) = pipe().unwrap();
            let child = launcher::launch(
                &production,
                child.into(),
                listener.into(),
                [
                    OwnedFd::from(File::open("/dev/null").unwrap()),
                    stdout_write,
                    OwnedFd::from(OpenOptions::new().write(true).open("/dev/null").unwrap()),
                ],
            )
            .unwrap();
            let mut output = String::new();
            stdout.read_to_string(&mut output).unwrap();
            assert_eq!(child.wait().unwrap(), 0, "{output}");
            let result: Value = serde_json::from_str(output.trim()).unwrap();
            assert_eq!(result["attack"], attack);
            assert_eq!(result["result"], "refused");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn antibody_boot_probe_weakened_policy_blocks_supervisor_start() {
        use std::cell::Cell;
        use std::os::unix::net::UnixListener;
        let Some(cgroup) = std::env::var_os("LAUNCHER_TEST_CGROUP") else {
            eprintln!(
                "UNPERFORMED boot probe supervisor: configure Linux delegated cgroup, subordinate ids, disposable workspace/root and static probe"
            );
            return;
        };
        let _fixture_guard = LINUX_GUEST_FIXTURE.lock().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o711)).unwrap();
        let get_path =
            |name| PathBuf::from(std::env::var_os(name).expect("Linux fixture variable required"));
        let workspace = get_path("LAUNCHER_TEST_WORKSPACE");
        let root = get_path("LAUNCHER_TEST_ROOT");
        writable_dir(&workspace).unwrap();
        for name in [".git", "dsh", "dsh/profiles", "dsh/profiles/web"] {
            writable_dir(&workspace.join(name)).unwrap();
        }
        write_manifest(&workspace.join("dsh/profiles/web")).unwrap();
        let tokio = tokio::runtime::Runtime::new().unwrap();
        let node =
            crate::node::Node::open(crate::e2e::config(fixture.path()), tokio.handle().clone())
                .unwrap();
        let mut config = node.runtime_config();
        config.boot_probe = true;
        config.file_size_max_bytes = 1024;
        config.subordinate_uid = std::env::var("LAUNCHER_TEST_UID").unwrap().parse().unwrap();
        config.subordinate_gid = std::env::var("LAUNCHER_TEST_GID").unwrap().parse().unwrap();
        for directory in [&config.node_dir, &config.harness_dir, &config.bundle_dir] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir(config.bundle_dir.join("guest")).unwrap();
        fs::set_permissions(
            config.bundle_dir.join("guest"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::copy(
            get_path("LAUNCHER_TEST_PROBE"),
            config.bundle_dir.join("guest/probe"),
        )
        .unwrap();
        fs::set_permissions(
            config.bundle_dir.join("guest/probe"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut production = policy(&config, workspace.clone(), root, cgroup.into());
        let listener = UnixListener::bind(fixture.path().join("ui.sock")).unwrap();
        let (parent, child) = UnixStream::pair().unwrap();
        let _parent = parent;
        let started = Cell::new(0);
        let digest = measure(&config).unwrap();
        for (weakened, mode) in [(false, 0o644), (true, 0o644), (true, 0o666)] {
            fs::set_permissions(
                workspace.join("dsh/profiles/web/package.json"),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            if weakened {
                production.readonly_workspace_files.clear();
            }
            let result = crate::boot_probe::guard_start(
                true,
                &digest.digest,
                || {
                    let fixtures = prepare_probe_fixtures(&workspace).unwrap();
                    let fixture_directory = Path::new("/workspace")
                        .join(fixtures.path().strip_prefix(&workspace).unwrap());
                    let execution = launcher::run_boot_probe(
                        &production,
                        &fixture_directory,
                        child.try_clone().unwrap().into(),
                        listener.try_clone().unwrap().into(),
                    );
                    crate::boot_probe::ProbeRun {
                        output: execution.output,
                        landlock_abi: execution.setup.as_ref().map(|setup| setup.landlock_abi),
                        seccomp_filter_sha256: execution
                            .setup
                            .map(|setup| setup.seccomp_filter_hash),
                        probe_sha256: Some(probe_binary_sha256(&config.bundle_dir).unwrap()),
                        wait_status: execution.wait_status,
                        failure: execution.refusal.map(|refusal| refusal.code.into()),
                    }
                },
                |fact| node.sandbox_event("boot.facts", "", "fact", fact),
                || Ok(()),
                || {
                    started.set(started.get() + 1);
                    Ok(())
                },
            );
            if weakened {
                assert_eq!(result.unwrap_err().to_string(), crate::boot_probe::FAILURE);
            } else {
                result.unwrap();
            }
        }
        assert_eq!(started.get(), 1);
        let db = node.db.lock().unwrap();
        let last: String = db
            .query_row(
                "SELECT body FROM aura WHERE kind='boot.facts' ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let fact: Value = serde_json::from_str(&last).unwrap();
        assert!(fact["boot_probe"]["outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|outcome| outcome["attack"] == "write-readonly-profile"
                && outcome["result"] == "allowed"));
        assert_eq!(fact["boot_probe"]["code"], crate::boot_probe::FAILURE);
        eprintln!(
            "RAN boot probe supervisor: exact production policy starts; writable profile permits attack and blocks start with Aura fact"
        );
    }

    #[test]
    fn backoff_has_a_fixed_ceiling() {
        assert_eq!(restart_delay(0), Duration::from_millis(250));
        assert_eq!(restart_delay(1), Duration::from_millis(500));
        assert_eq!(restart_delay(u32::MAX), Duration::from_secs(30));
    }
}
