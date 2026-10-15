// SPDX-License-Identifier: AGPL-3.0-or-later
//! Versioned health evidence and the frozen 110-cell observer registry.

use crate::alg::AlgorithmId;
use crate::digest::Digest32;
use crate::{Refusal, Result};

pub use crate::health_registry::{CHECKS, CORNERS};

/// Registry version shared by all 90 private checks and 20 paired corners.
pub const HEALTH_REGISTRY_VERSION: u16 = 1;
/// Wire version of a health observation or snapshot; unknown versions refuse.
pub const HEALTH_FORMAT_VERSION: u16 = 1;
/// Every organ owns exactly 18 private invariant checks.
pub const PRIVATE_CHECKS_PER_ORGAN: usize = 18;
/// The registry contains 90 private checks across the five organs.
pub const PRIVATE_CHECK_COUNT: usize = 90;
/// Each of the ten unordered organ pairs owns exactly two shared corners.
pub const CORNER_COUNT: usize = 20;
/// A complete observation set has 90 private reports and 40 corner reports.
pub const MAX_EVIDENCE_COUNT: usize = 130;

/// The five owners of Level 1 checks; this is independent of refusal namespaces.
/// Organ i, at zero-based position i in `OrganId::ALL`, is cube i of
/// `crates/pentora/vectors/geometry_index_table_v1.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum OrganId {
    /// Identity, root epochs, passkeys and delegated keys.
    Aumlok,
    /// Exact-byte authorization, consumption and the append-only record.
    GateAura,
    /// Encrypted memory, cited recall and disclosure permissions.
    Kira,
    /// Delegated identities, contacts, transport and relationship evidence.
    Network,
    /// Supervisor, cage, frontdoor, broker, release and immune observers.
    Body,
}

impl OrganId {
    /// Registry order used by the snapshot's 90 private cells.
    pub const ALL: [Self; 5] = [
        Self::Aumlok,
        Self::GateAura,
        Self::Kira,
        Self::Network,
        Self::Body,
    ];

    /// Returns the stable lowercase wire name of the check owner.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aumlok => "aumlok",
            Self::GateAura => "gate-aura",
            Self::Kira => "kira",
            Self::Network => "network",
            Self::Body => "body",
        }
    }
}

/// A health evidence cell, deliberately a different type from a Pentora
/// fingerprint trit. It describes organ state and cannot grant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cell {
    /// The registered invariant was confirmed in the snapshot's context.
    Verified,
    /// An implemented check is not yet checked, unreachable or stale.
    Undetermined,
    /// The invariant failed, evidence disagrees, or the check is unwritten/missing.
    Failed,
}

/// A private check owned by one organ, with an index in 1..=18. Private check j
/// is the j-th smallest private global cell index belonging to that organ's cube
/// in `crates/pentora/vectors/geometry_index_table_v1.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CheckId {
    organ: OrganId,
    index: u8,
}

impl CheckId {
    /// Refuses an index outside 1..=18 with `health:check-index`.
    pub const fn new(organ: OrganId, index: u8) -> Result<Self> {
        if index == 0 || index > PRIVATE_CHECKS_PER_ORGAN as u8 {
            return Err(Refusal::new("health", "check-index"));
        }
        Ok(Self { organ, index })
    }

    /// Returns the sole owner of this private check.
    pub const fn organ(self) -> OrganId {
        self.organ
    }

    /// Returns the checked, one-based index within that organ.
    pub const fn index(self) -> u8 {
        self.index
    }

    /// Builds a registry constant while checking the same public index bound.
    pub(crate) const fn fixed(organ: OrganId, index: u8) -> Self {
        assert!(index >= 1 && index <= PRIVATE_CHECKS_PER_ORGAN as u8);
        Self { organ, index }
    }
}

/// A shared corner's stable one-based registry index in 1..=20. Pairs follow the
/// pinned geometry's `pair_intersections` order; within each pair, corner k is
/// the k-th smallest `noncentre_corner_indices` member, for k in 1..=2. Thus the
/// pair at zero-based position p owns registry ids 2*p+1 and 2*p+2.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CornerId(u8);

impl CornerId {
    /// Refuses an index outside 1..=20 with `health:corner-index`.
    pub const fn new(index: u8) -> Result<Self> {
        if index == 0 || index > CORNER_COUNT as u8 {
            return Err(Refusal::new("health", "corner-index"));
        }
        Ok(Self(index))
    }

    /// Returns the checked index in the `CORNERS` table.
    pub const fn index(self) -> u8 {
        self.0
    }

    /// Builds a registry constant while checking the public corner bound.
    pub(crate) const fn fixed(index: u8) -> Self {
        assert!(index >= 1 && index <= CORNER_COUNT as u8);
        Self(index)
    }
}

/// Identifies one independent observation, including the reporting corner side.
/// Private numbering and paired-corner numbering follow the pinned geometry as
/// specified by `CheckId`, `CornerId` and `OrganId`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CheckRef {
    /// A report from its sole registered organ owner.
    Private(CheckId),
    /// A report from one of its two registered independent organ owners.
    Corner {
        /// Shared invariant's stable registry id.
        corner: CornerId,
        /// One of that corner's two registered organ owners.
        side: OrganId,
    },
}

/// Frozen observation contract for one private check or one corner side.
/// Sources are organ-owned observers; external content cannot supply evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckSpec {
    /// Independent observation identified using the pinned geometry numbering.
    pub check: CheckRef,
    /// Sole observer responsible for this report; equals a corner reference's side.
    pub owner: OrganId,
    /// Named organ-owned observation source, never an instruction or authority.
    pub source: &'static str,
    /// Maximum evidence age in milliseconds, even if expiry claims longer.
    pub freshness_ms: u64,
}

/// Frozen definition of a private check; freshness is measured from observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckDefinition {
    /// Stable organ and local index, never reused for a different invariant.
    pub id: CheckId,
    /// Observer responsible for the private check.
    pub owner: OrganId,
    /// Exact invariant this check must establish before reporting Verified.
    pub invariant: &'static str,
    /// Named organ-owned observation source; external text cannot substitute for it.
    pub source: &'static str,
    /// Maximum allowed evidence age in milliseconds, even if expiry claims longer.
    pub freshness_limit_ms: u64,
}

impl CheckDefinition {
    /// Returns this private check's frozen independent observation contract.
    pub const fn spec(self) -> CheckSpec {
        CheckSpec {
            check: CheckRef::Private(self.id),
            owner: self.owner,
            source: self.source,
            freshness_ms: self.freshness_limit_ms,
        }
    }
}

/// Frozen definition of one corner and its two independent observation sources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CornerDefinition {
    /// Stable one-based index; consecutive odd/even ids belong to one organ pair.
    pub id: CornerId,
    /// Organ pair spelling frozen word for word from the North Star table.
    pub organ_pair: &'static str,
    /// Both observers must report independently before the corner can be Verified.
    pub owners: [OrganId; 2],
    /// One invariant frozen word for word from the North Star's two-column pair.
    pub invariant: &'static str,
    /// Independent observation sources in the same order as `owners`.
    pub sources: [&'static str; 2],
    /// Maximum age of either report, even if its declared expiry claims longer.
    pub freshness_limit_ms: u64,
}

impl CornerDefinition {
    /// Returns both independent observation contracts in registered owner order.
    pub const fn specs(self) -> [CheckSpec; 2] {
        [
            CheckSpec {
                check: CheckRef::Corner {
                    corner: self.id,
                    side: self.owners[0],
                },
                owner: self.owners[0],
                source: self.sources[0],
                freshness_ms: self.freshness_limit_ms,
            },
            CheckSpec {
                check: CheckRef::Corner {
                    corner: self.id,
                    side: self.owners[1],
                },
                owner: self.owners[1],
                source: self.sources[1],
                freshness_ms: self.freshness_limit_ms,
            },
        ]
    }
}

/// Bounded machine reason for a health cell; it never supplies instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthReason {
    /// The registered invariant holds in the reported context.
    Satisfied,
    /// The check has not been implemented; its reduced cell must be Failed.
    Unwritten,
    /// No report exists for a required check or required corner owner.
    Missing,
    /// An implemented observer has not completed an observation.
    NotChecked,
    /// An implemented observer cannot reach its registered source.
    Unreachable,
    /// Evidence expired or exceeded the registry's maximum age.
    Stale,
    /// Independently reported states or commitments conflict.
    Disagreement,
    /// An observer measured a violation of the registered invariant.
    InvariantFailed,
    /// A report refers to another epoch, sequence or snapshot commitment.
    ContextMismatch,
    /// A report's version, algorithm, owner, time bounds or shape is invalid.
    InvalidEvidence,
}

/// One observation of organ state. `Cell` is not a Pentora fingerprint trit.
/// Evidence may refuse, escalate or inform; it never becomes authority, and no
/// gate, frontdoor or launcher effect may depend on it granting permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthEvidence {
    /// Health format version; unknown versions refuse.
    pub v: u16,
    /// Commitment algorithm; version 1 requires `AlgorithmId::Sha256`.
    pub algorithm: AlgorithmId,
    /// Private check or particular corner side being independently observed.
    pub check: CheckRef,
    /// Registered observer, assigned at trusted ingress rather than by model text;
    /// must equal the private check's owner or the corner reference's side.
    pub reporter: OrganId,
    /// Owner-state epoch of the observed context.
    pub epoch: u64,
    /// Aura sequence of the observed context; clocks never replace ordering.
    pub sequence: u64,
    /// Supervisor observation time in milliseconds, informational outside freshness.
    pub observed_at_ms: u64,
    /// Expiry in milliseconds, bounded again by the registry freshness limit.
    pub expires_at_ms: u64,
    /// The observer's state, interpreted by the reduction contract.
    pub cell: Cell,
    /// Bounded machine explanation of this report.
    pub reason: HealthReason,
    /// SHA-256 commitment to the exact common context inspected by the observer.
    pub commitment: Digest32,
}

/// One complete health map, labelled separately from the fingerprint. It carries
/// evidence only, cannot authorize effects and must retain all 110 registered ids.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    /// Health format version; unknown versions refuse.
    pub v: u16,
    /// Commitment algorithm; version 1 requires `AlgorithmId::Sha256`.
    pub algorithm: AlgorithmId,
    /// Shared registry version applying to both private checks and corners.
    pub registry_version: u16,
    /// Common owner-state epoch; reports from a different epoch cannot verify.
    pub epoch: u64,
    /// Common Aura sequence; reports from a different sequence cannot verify.
    pub sequence: u64,
    /// Snapshot time in milliseconds, used only to evaluate evidence freshness.
    pub observed_at_ms: u64,
    /// Common SHA-256 context commitment required of both owners of a corner.
    pub commitment: Digest32,
    /// At most 130 reports: one per private id and one per corner owner.
    pub evidence: Vec<HealthEvidence>,
    /// Exactly 90 cells in `CHECKS` order; no registry member may be omitted.
    pub private_cells: [Cell; PRIVATE_CHECK_COUNT],
    /// Exactly 20 cells in `CORNERS` order, independent of fingerprint geometry.
    pub corner_cells: [Cell; CORNER_COUNT],
}

/// Decodes exact canonical C1 snapshot bytes for health consumers only. The gate,
/// frontdoor and launcher must never call this parser or read its returned map.
/// FD 4 transports these bytes opaquely and does not invoke this function.
/// Refuses empty or more than 65,536 bytes, noncanonical JSON, unknown fields,
/// unsupported versions or algorithms, and any invalid evidence or cell counts.
/// The returned cells must match `HealthSnapshot::reduce` for the snapshot context;
/// evidence remains informational and cannot authorize an effect.
pub fn decode_snapshot(_bytes: &[u8]) -> Result<HealthSnapshot> {
    todo!("row 32")
}

impl HealthSnapshot {
    /// Reduces only registered observations, never instructions or authority.
    ///
    /// Missing or unwritten checks are Failed. Implemented checks with stale or
    /// unreachable evidence are Undetermined. A disagreement is Failed. A corner
    /// is Verified only when both registered owners independently report Verified
    /// with the exact same epoch, sequence and commitment as this snapshot, and
    /// both reports are fresh. Explicit failure takes precedence over uncertainty.
    /// Expiry must not precede observation, observation must not be in the future,
    /// and age must not exceed either expiry or the registry freshness limit.
    /// Duplicate check references, unregistered reporters, a reporter differing
    /// from the private owner or corner side, unsupported versions/algorithms and
    /// more than 130 reports refuse as `health:invalid-evidence`.
    /// All 110 ids remain present even when an observer has no implementation.
    pub fn reduce(
        epoch: u64,
        sequence: u64,
        observed_at_ms: u64,
        commitment: Digest32,
        evidence: Vec<HealthEvidence>,
    ) -> Result<Self> {
        let _ = (epoch, sequence, observed_at_ms, commitment, evidence);
        todo!("row 32")
    }
}
