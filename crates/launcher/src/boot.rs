// SPDX-License-Identifier: AGPL-3.0-or-later
//! Boot observations and the supervisor-owned Aura append port.

use canon::{authority::FactKind, digest::Digest32, json::Value};

use crate::{
    cage::Result, cgroup::CgroupFacts, landlock::LandlockFacts, netns::NamespaceFacts,
    profiles::ProfileKind, seccomp::SeccompFacts,
};

/// Supervisor boot precedes binding, release admission and child setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCageState {
    /// No child has been launched: no installed guest filter or containment claim.
    NotStarted,
}

/// Host observations recorded even when no guest may start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostBootFacts {
    /// Kernel release sampled on this supervisor boot.
    pub kernel_release: String,
    /// Available kernel ABI; None means unavailable, never successful restriction.
    pub available_landlock_abi: Option<u32>,
    /// Initial state explicitly distinguished from installed child facts.
    pub cage_state: HostCageState,
}

impl HostBootFacts {
    /// Host observations use only the nonauthorizing boot-fact kind.
    pub const fn kind(&self) -> FactKind {
        FactKind::BootFacts
    }

    /// Row 27: encode a versioned body distinguishing available host support from
    /// absent child observations. The installed guest seccomp digest is null, never
    /// a planned filter digest or a copied receipt from an earlier boot.
    pub fn to_body(&self) -> Result<Value> {
        todo!("row 27")
    }
}

/// Supervisor boot must be recorded before unbound or unapproved startup refuses.
pub trait HostBootRecorder {
    /// Append and durably commit C3 boot.facts with the supervisor's own clock,
    /// epoch and next sequence. This does not enable a guest or approve a release.
    fn append_host_boot(&mut self, facts: &HostBootFacts) -> Result<BootReceipt>;
}

/// Row 27: sample this host without starting a child or pretending an absent cage
/// has installed restrictions. Unsupported/missing Landlock stays unavailable data.
pub fn inspect_host() -> Result<HostBootFacts> {
    todo!("row 27")
}

/// Uninterpreted kernel observations from this launch, never permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootFacts {
    /// Kernel release obtained from the running kernel rather than release metadata.
    pub kernel_release: String,
    /// Executable digest checked from the pinned bytes actually loaded.
    pub executable_sha256: Digest32,
    /// Closed cage profile in effect for the child.
    pub profile: ProfileKind,
    /// Installed Landlock observations, including its ABI.
    pub landlock: LandlockFacts,
    /// Installed seccomp observations, including its exact filter commitment.
    pub seccomp: SeccompFacts,
    /// Namespace observations sampled during this launch.
    pub namespaces: NamespaceFacts,
    /// Resource settings read back after child attachment.
    pub cgroup: CgroupFacts,
    /// Number of inherited descriptors after closure; Auma retains exactly five.
    pub inherited_descriptors: u32,
    /// Whether child capability sets were read back as empty.
    pub capabilities_cleared: bool,
}

/// An acknowledgement from Aura's durable append path. It is never authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootReceipt {
    /// Aura's sequence for the committed `boot.facts` row.
    pub sequence: u64,
    /// C2 hash of the committed row.
    pub entry_sha256: Digest32,
}

/// The supervisor implements this port and supplies its clock and ledger context.
/// Launcher opens neither Aura's database nor any organ service socket.
pub trait BootRecorder {
    /// Append C3 `boot.facts` with phase `fact`, canonical body, supervisor clock,
    /// epoch and next sequence. Return only after durable commit. An append failure
    /// leaves the child blocked and causes the launcher to terminate and reap it.
    fn append_boot(&mut self, facts: &BootFacts) -> Result<BootReceipt>;
}

impl BootFacts {
    /// Boot observations cannot select an authority-bearing ledger kind.
    pub const fn kind(&self) -> FactKind {
        FactKind::BootFacts
    }

    /// Row 27: encode bounded canonical facts in C3's body. Kernel release,
    /// Landlock ABI and the seccomp hash are mandatory; no new C3 row key is added.
    pub fn to_body(&self) -> Result<Value> {
        todo!("row 27")
    }
}

/// A live sample is distinct from boot-time configuration and old observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CageSample {
    /// Monotonic elapsed time from the start of this cage, in milliseconds.
    pub observed_after_ms: u64,
    /// Whether the child is still present when sampled.
    pub running: bool,
    /// Landlock observation, absent when the process cannot be inspected.
    pub landlock: Option<LandlockFacts>,
    /// Seccomp observation, absent when the process cannot be inspected.
    pub seccomp: Option<SeccompFacts>,
    /// Namespace observation, absent when the process cannot be inspected.
    pub namespaces: Option<NamespaceFacts>,
    /// Resource observation, absent when the process cannot be inspected.
    pub cgroup: Option<CgroupFacts>,
}
