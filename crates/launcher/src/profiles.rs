// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed cage profiles and inert disposable requests. Policy is owned by the gate.

use canon::{digest::Digest32, ids::AppId};

use crate::{cage::Result, cgroup::ResourceLimits};

/// Names a fixed syscall and filesystem policy, never a caller-supplied filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileKind {
    /// Static Auma harness: no filesystem, process creation or socket creation.
    Auma,
    /// Isolated application runtime: no network, exec or WASI imports.
    UserApp,
    /// A separate command cage; this profile is disabled by default.
    Disposable,
}

impl ProfileKind {
    /// Exact local policy spelling; an unknown name is refused.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "auma" => Ok(Self::Auma),
            "user-app" => Ok(Self::UserApp),
            "disposable" => Ok(Self::Disposable),
            _ => Err(crate::cage::refusal("profile")),
        }
    }
}

/// Data selecting a closed profile. Construction does not start a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CageProfile {
    /// The harness's two inherited data channels and no writable filesystem.
    Auma {
        /// Fixed resource ceilings for this instance.
        limits: ResourceLimits,
    },
    /// One application, isolated from Auma and from every other application.
    UserApp {
        /// Identity used for brokered application services, never an authority.
        app: AppId,
        /// Exact approved bundle commitment checked by the supervisor.
        bundle_sha256: Digest32,
        /// Fixed resource ceilings for this instance.
        limits: ResourceLimits,
    },
}

impl CageProfile {
    /// Resolve the closed policy without accepting arbitrary syscall rules.
    pub const fn kind(&self) -> ProfileKind {
        match self {
            Self::Auma { .. } => ProfileKind::Auma,
            Self::UserApp { .. } => ProfileKind::UserApp,
        }
    }

    /// Resource ceilings retained by this requested profile.
    pub const fn limits(&self) -> &ResourceLimits {
        match self {
            Self::Auma { limits } | Self::UserApp { limits, .. } => limits,
        }
    }
}

/// No public constructor can enable the disposable cage.
#[derive(Debug, Default)]
pub struct DisposableSwitch {
    enabled_policy: Option<ConsumedStandingPolicy>,
}

impl DisposableSwitch {
    /// A fresh process and a restored default both keep decision 9 off.
    pub const fn disabled() -> Self {
        Self {
            enabled_policy: None,
        }
    }

    /// Whether a consumed owner policy has been installed, never a health verdict.
    pub const fn enabled(&self) -> bool {
        self.enabled_policy.is_some()
    }

    /// Row 39: bind every decoded field to the exact policy bytes under the authority
    /// port, consume its passkey authorization durably, then retain its activation. The port
    /// belongs to the supervisor/gate; it must not be implemented by guest input.
    pub fn enable<A: DisposableAuthority + ?Sized>(
        &mut self,
        _policy: &StandingPolicy,
        _authority: &mut A,
    ) -> Result<()> {
        todo!("row 39")
    }

    /// Disable future runs; running children still require explicit termination.
    pub fn disable(&mut self) {
        self.enabled_policy = None;
    }
}

/// A proposal for one standing disposable-cage rule, not an approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingPolicy {
    /// Exact canonical policy bytes presented to the owner; bounded to C4 size.
    canonical_bytes: Vec<u8>,
    /// Exact permitted directory identity supplied through the supervisor.
    directory_commitment: Digest32,
    /// Maximum number of commands covered by one consumed authorization.
    command_budget: u32,
    /// Resource ceilings applicable to every child in the disposable run.
    limits: ResourceLimits,
}

impl StandingPolicy {
    /// Row 39: decode the versioned policy, deriving every field from its exact
    /// canonical bytes. Refuse unknown fields, unbounded commands or invalid limits.
    pub fn decode(_canonical_bytes: Vec<u8>) -> Result<Self> {
        todo!("row 39")
    }

    /// Exact bytes presented to and signed by the owner.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// The single subtree identity retained from the exact policy bytes.
    pub const fn directory_commitment(&self) -> Digest32 {
        self.directory_commitment
    }

    /// Total command budget retained from the exact policy bytes.
    pub const fn command_budget(&self) -> u32 {
        self.command_budget
    }

    /// Resource ceilings retained from the exact policy bytes.
    pub const fn limits(&self) -> ResourceLimits {
        self.limits
    }
}

/// Exact inert request built from the pinned directory and command descriptors.
/// Callers cannot supply unrelated fields alongside the commitment.
#[derive(Debug)]
pub struct DisposableRun {
    canonical_bytes: Vec<u8>,
}

impl DisposableRun {
    /// The gate checks these bytes against the already signed standing rule.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// The supervisor-owned gate adapter checks exact bytes and consumes once.
/// It cannot obtain approval from a boot fact, a profile name or a model message.
pub trait DisposableAuthority {
    /// Verify the owner passkey and atomically consume this exact standing policy.
    /// Implementations also enforce current epoch, revocation and remaining budget.
    fn consume_exact(&mut self, policy: &StandingPolicy) -> Result<()>;

    /// Before every run, recheck owner epoch and revocation, compare the exact run
    /// with the signed folder, images, arguments and limits, and durably debit its
    /// command count. Invoke dispatch once under that admission scope; never invoke
    /// it on a refusal or before the debit commits. A failed child still spends the
    /// reserved count; retries require a new admission. Epoch/revocation changes
    /// must serialize with admission and dispatch, not occur in a check/use gap.
    fn with_authorized_run<T>(
        &mut self,
        policy: &StandingPolicy,
        run: &DisposableRun,
        dispatch: impl FnOnce() -> Result<T>,
    ) -> Result<T>;
}

#[derive(Debug)]
struct ConsumedStandingPolicy {
    _policy: StandingPolicy,
}
