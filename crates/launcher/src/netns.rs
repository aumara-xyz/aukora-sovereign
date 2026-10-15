// SPDX-License-Identifier: AGPL-3.0-or-later
//! Child namespace creation and observations from kernel namespace descriptors.

use crate::cage::{refusal, Result};

/// Identity mapping into a fresh user namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserMapping {
    /// Delegated host user id; zero and the supervisor id are refused.
    pub host_uid: u32,
    /// Delegated host group id; zero and the supervisor id are refused.
    pub host_gid: u32,
}

/// Namespace descriptor's device and inode pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespaceIdentity {
    /// Device identifier from the namespace descriptor.
    pub device: u64,
    /// Inode identifier from the namespace descriptor.
    pub inode: u64,
}

/// Kernel setup observations, never requested configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceFacts {
    /// Child's user namespace differs from the supervisor's.
    pub user_isolated: bool,
    /// Child's mount namespace differs from the supervisor's.
    pub mounts_isolated: bool,
    /// Child's PID namespace differs from the supervisor's.
    pub pids_isolated: bool,
    /// Child's IPC namespace differs from the supervisor's.
    pub ipc_isolated: bool,
    /// Child's UTS namespace differs from the supervisor's.
    pub uts_isolated: bool,
    /// Child's cgroup namespace differs from the supervisor's.
    pub cgroup_isolated: bool,
    /// Supervisor's network namespace before child setup.
    pub supervisor_network: NamespaceIdentity,
    /// Child's network namespace after setup.
    pub child_network: NamespaceIdentity,
    /// Interfaces observed with IFF_UP; loopback must stay down.
    pub active_interfaces: u32,
    /// Kernel routes with the UP flag in either address family.
    pub routes: u32,
}

/// Complete child setup is available only after a parent captured its namespace
/// baseline and mapped the stopped clone. This function never unshares its caller.
pub(crate) fn isolate(mapping: UserMapping) -> Result<NamespaceFacts> {
    #[cfg(target_os = "linux")]
    {
        let initial = INITIAL.get().ok_or(refusal("child-context-required"))?;
        mapping.validate_against(initial)?;
        verify_mapping("self", mapping)?;
        child_setup(initial)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mapping;
        Err(refusal("unsupported-platform"))
    }
}

#[cfg(target_os = "linux")]
const NAMES: [&str; 7] = ["user", "mnt", "pid", "ipc", "uts", "cgroup", "net"];

/// Parent observations captured before any child namespace operation.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub(crate) struct NamespaceBaseline {
    pub(crate) host_pid: u32,
    host_uid: u32,
    host_gid: u32,
    identities: [NamespaceIdentity; 7],
}

#[cfg(target_os = "linux")]
static INITIAL: std::sync::OnceLock<NamespaceBaseline> = std::sync::OnceLock::new();

/// Capture the supervisor's actual namespace descriptors and host identity.
#[cfg(target_os = "linux")]
pub(crate) fn baseline() -> Result<NamespaceBaseline> {
    let result = NamespaceBaseline {
        host_pid: std::process::id(),
        // SAFETY: these scalar identity queries require no pointer arguments.
        host_uid: unsafe { libc::getuid() },
        // SAFETY: this scalar identity query requires no pointer arguments.
        host_gid: unsafe { libc::getgid() },
        identities: namespace_ids("self")?,
    };
    if let Some(previous) = INITIAL.get() {
        if previous.host_pid != result.host_pid
            || previous.host_uid != result.host_uid
            || previous.host_gid != result.host_gid
            || previous.identities != result.identities
        {
            return Err(refusal("child-context-required"));
        }
    } else {
        let _ = INITIAL.set(result.clone());
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
impl UserMapping {
    fn validate_against(self, initial: &NamespaceBaseline) -> Result<()> {
        if self.host_uid == 0
            || self.host_gid == 0
            || self.host_uid == initial.host_uid
            || self.host_gid == initial.host_gid
        {
            return Err(refusal("identity"));
        }
        Ok(())
    }
}

/// Unshare only in a fork child; the parent then supplies the delegated maps.
/// A subsequent fork is required before child_setup, to enter the PID namespace.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_namespaces(initial: &NamespaceBaseline) -> Result<()> {
    if std::process::id() == initial.host_pid || namespace_ids("self")? != initial.identities {
        return Err(refusal("child-context-required"));
    }
    // SAFETY: scalar group-count query; inherited supplementary groups would
    // survive setgroups=deny and therefore must be removed before unsharing.
    let groups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if groups < 0 || (groups > 0 && unsafe { libc::setgroups(0, std::ptr::null()) } != 0) {
        return Err(refusal("identity-groups"));
    }
    // SAFETY: this query observes whether supplementary group removal succeeded.
    if unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0 {
        return Err(refusal("identity-groups"));
    }
    let flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWNET;
    // SAFETY: flags create namespaces in this validated fork child only.
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(refusal("namespaces"));
    }
    Ok(())
}

/// Write an exact one-entry identity map into a stopped, isolated direct child.
#[cfg(target_os = "linux")]
pub(crate) fn map_child(pid: u32, mapping: UserMapping) -> Result<()> {
    let initial = INITIAL.get().ok_or(refusal("child-context-required"))?;
    mapping.validate_against(initial)?;
    if pid <= 1 || pid == initial.host_pid {
        return Err(refusal("child-context-required"));
    }
    let name = pid.to_string();
    let status = read_proc(&name, "status")?;
    let parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse::<u32>().ok());
    if parent != Some(initial.host_pid) || namespace_ids(&name)?[0] == initial.identities[0] {
        return Err(refusal("child-context-required"));
    }
    write_proc(&name, "setgroups", "deny")?;
    write_proc(&name, "uid_map", &format!("0 {} 1\n", mapping.host_uid))?;
    write_proc(&name, "gid_map", &format!("0 {} 1\n", mapping.host_gid))?;
    verify_mapping(&name, mapping)
}

#[cfg(target_os = "linux")]
fn verify_mapping(name: &str, mapping: UserMapping) -> Result<()> {
    for (file, host) in [("uid_map", mapping.host_uid), ("gid_map", mapping.host_gid)] {
        let bytes = read_proc(name, file)?;
        let entries: Vec<&str> = bytes.split_ascii_whitespace().collect();
        if entries != ["0", &host.to_string(), "1"] {
            return Err(refusal("identity-readback"));
        }
    }
    if read_proc(name, "setgroups")?.trim() != "deny" {
        return Err(refusal("identity-readback"));
    }
    Ok(())
}

/// Make mounts private and verify the inner child entered every new namespace.
#[cfg(target_os = "linux")]
pub(crate) fn child_setup(initial: &NamespaceBaseline) -> Result<NamespaceFacts> {
    // SAFETY: getpid returns the current namespace's scalar process identifier.
    let observed = namespace_ids("self")?;
    if unsafe { libc::getpid() } != 1
        || observed
            .iter()
            .zip(&initial.identities)
            .any(|(child, parent)| child == parent)
    {
        return Err(refusal("child-context-required"));
    }
    // SAFETY: parent installed a single mapping; these calls select its inner id
    // and do not change the supervisor or any other process's credentials.
    if unsafe { libc::setresgid(0, 0, 0) } != 0 || unsafe { libc::setresuid(0, 0, 0) } != 0 {
        return Err(refusal("identity"));
    }
    // SAFETY: all identity queries return scalars without pointer arguments.
    if unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0
        || unsafe { libc::getegid() } != 0
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
    {
        return Err(refusal("identity-readback"));
    }
    // SAFETY: root is terminated; recursive private propagation changes only this
    // child's mount namespace, which was independently compared above.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(refusal("mounts"));
    }
    observe_current(initial)
}

/// Observe only the current child: interface flags cannot be read from another
/// process's network namespace without entering it or asking another process.
#[cfg(target_os = "linux")]
pub(crate) fn observe(pid: u32, initial: &NamespaceBaseline) -> Result<NamespaceFacts> {
    if pid != std::process::id() {
        return Err(refusal("namespace-observation"));
    }
    observe_current(initial)
}

#[cfg(target_os = "linux")]
fn observe_current(initial: &NamespaceBaseline) -> Result<NamespaceFacts> {
    let observed = namespace_ids("self")?;
    let different: [bool; 7] =
        std::array::from_fn(|index| observed[index] != initial.identities[index]);
    if different.contains(&false) {
        return Err(refusal("namespace-readback"));
    }
    let active_interfaces = active_interfaces()?;
    let routes = routes("self")?;
    if active_interfaces != 0 || routes != 0 {
        return Err(refusal("network"));
    }
    Ok(NamespaceFacts {
        user_isolated: different[0],
        mounts_isolated: different[1],
        pids_isolated: different[2],
        ipc_isolated: different[3],
        uts_isolated: different[4],
        cgroup_isolated: different[5],
        supervisor_network: initial.identities[6],
        child_network: observed[6],
        active_interfaces,
        routes,
    })
}

#[cfg(target_os = "linux")]
fn active_interfaces() -> Result<u32> {
    let mut first = std::ptr::null_mut();
    // SAFETY: first is writable and freeifaddrs releases the resulting linked list.
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(refusal("network-observation"));
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // SAFETY: this is the list returned by the successful getifaddrs call.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let addresses = Addresses(first);
    let mut cursor = addresses.0;
    let mut names = std::collections::BTreeSet::new();
    let mut active = std::collections::BTreeSet::new();
    while !cursor.is_null() {
        // SAFETY: getifaddrs guarantees valid nodes until ifa_next is null.
        let item = unsafe { &*cursor };
        if item.ifa_name.is_null() {
            return Err(refusal("network-observation"));
        }
        // SAFETY: getifaddrs returns a terminated name for each interface.
        let name = unsafe { std::ffi::CStr::from_ptr(item.ifa_name) }.to_bytes();
        if name != b"lo" || item.ifa_flags & libc::IFF_LOOPBACK as u32 == 0 {
            return Err(refusal("network"));
        }
        names.insert(name.to_vec());
        if item.ifa_flags & libc::IFF_UP as u32 != 0 {
            active.insert(name.to_vec());
        }
        cursor = item.ifa_next;
    }
    if names.len() != 1 {
        return Err(refusal("network-observation"));
    }
    u32::try_from(active.len()).map_err(|_| refusal("network-observation"))
}

#[cfg(target_os = "linux")]
fn routes(name: &str) -> Result<u32> {
    let mut count = 0u32;
    for (file, skip, flag_column) in [("net/route", 1, 3), ("net/ipv6_route", 0, 8)] {
        for line in read_proc(name, file)?.lines().skip(skip) {
            let flags = line
                .split_ascii_whitespace()
                .nth(flag_column)
                .and_then(|v| u32::from_str_radix(v, 16).ok())
                .ok_or(refusal("network-observation"))?;
            if flags & libc::RTF_UP as u32 != 0 {
                count = count.checked_add(1).ok_or(refusal("network-observation"))?;
            }
        }
    }
    Ok(count)
}

#[cfg(target_os = "linux")]
fn namespace_ids(name: &str) -> Result<[NamespaceIdentity; 7]> {
    use std::os::unix::fs::MetadataExt;
    let mut values = [NamespaceIdentity {
        device: 0,
        inode: 0,
    }; 7];
    for (index, namespace) in NAMES.into_iter().enumerate() {
        let file = std::fs::File::open(proc_path(name, &format!("ns/{namespace}")))
            .map_err(|_| refusal("namespace-open"))?;
        let metadata = file.metadata().map_err(|_| refusal("namespace-stat"))?;
        values[index] = NamespaceIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
fn proc_path(name: &str, file: &str) -> std::path::PathBuf {
    std::path::Path::new("/proc").join(name).join(file)
}

#[cfg(target_os = "linux")]
fn read_proc(name: &str, file: &str) -> Result<String> {
    use std::io::Read;
    let mut result = String::new();
    std::fs::File::open(proc_path(name, file))
        .map_err(|_| refusal("namespace-open"))?
        .take(65_537)
        .read_to_string(&mut result)
        .map_err(|_| refusal("namespace-read"))?;
    if result.len() > 65_536 {
        return Err(refusal("namespace-read"));
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn write_proc(name: &str, file: &str, value: &str) -> Result<()> {
    use std::io::Write;
    let mut opened = std::fs::OpenOptions::new()
        .write(true)
        .open(proc_path(name, file))
        .map_err(|_| refusal("identity-open"))?;
    if opened
        .write(value.as_bytes())
        .map_err(|_| refusal("identity-write"))?
        != value.len()
    {
        return Err(refusal("identity-write"));
    }
    Ok(())
}
