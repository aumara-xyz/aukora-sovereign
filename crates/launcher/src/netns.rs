// SPDX-License-Identifier: AGPL-3.0-or-later
//! Namespace setup contracts and observations; no host network fallback exists.

use crate::cage::Result;

/// Identity mapping into a fresh user namespace, not the supervisor's own identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserMapping {
    /// Delegated host user id; zero and the supervisor id are refused at setup.
    pub host_uid: u32,
    /// Delegated host group id; zero and the supervisor id are refused at setup.
    pub host_gid: u32,
}

/// Namespace identity from a kernel descriptor's device and inode pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespaceIdentity {
    /// Device identifier from the namespace descriptor.
    pub device: u64,
    /// Inode identifier from the namespace descriptor.
    pub inode: u64,
}

/// Plain setup observations for independent Body probes.
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
    /// Supervisor's network namespace identity before child setup.
    pub supervisor_network: NamespaceIdentity,
    /// Child's network namespace identity after setup.
    pub child_network: NamespaceIdentity,
    /// Count of active network interfaces; the isolated loopback stays down.
    pub active_interfaces: u32,
    /// Count of routes after namespace setup.
    pub routes: u32,
}

/// Row 26: create user, mount, PID, IPC, UTS, cgroup and network namespaces; deny
/// setgroups, establish the delegated uid/gid maps, and keep every interface down.
/// This child-only operation is never called against the supervisor itself.
pub(crate) fn isolate(_mapping: UserMapping) -> Result<NamespaceFacts> {
    todo!("row 26")
}
