// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reports separate arithmetic integrity from independently retained observations.

use canon::Refusal;

/// An observation about the supplied bytes, never authorization to execute them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// All required checks, including independent key and covering checkpoint, passed.
    Verified,
    /// A retained observation conflicts with the supplied chain.
    Rewritten,
    /// A row signature fails cryptographic verification.
    Forged,
    /// The supplied independent key differs from the export's claimed key.
    KeyMismatch,
    /// The bytes cannot be admitted under the selected schema.
    InvalidInput,
    /// Required checks or independent observations are missing.
    Unchecked,
}

impl Verdict {
    /// Only complete verification can yield the success exit code.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Verified => 0,
            Self::Unchecked => 1,
            Self::Rewritten | Self::Forged | Self::KeyMismatch => 2,
            Self::InvalidInput => 64,
        }
    }
}

/// Missing scope is represented explicitly and cannot be inferred from other checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// This property was not established from the supplied bytes.
    Unchecked,
    /// This property was established within the report's supplied observations.
    Checked,
}

/// Integrity properties, without independent identity or completeness claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityScope {
    /// Node signature verification over each entry's raw hash bytes.
    pub signatures: Scope,
    /// Contiguous sequences, predecessor links and recomputed entry hashes.
    pub chain: Scope,
    /// The recomputed RFC 6962 root and the export's claimed tail.
    pub tree_root: Scope,
    /// C5 owner authorization binding data contained in the rows.
    pub owner_bindings: Scope,
}

/// Claims about observations supplied independently from the export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationScope {
    /// The export key matched the caller's retained key.
    pub pinned_identity: Scope,
    /// An independently retained head covered the complete claimed tail.
    pub covering_checkpoint: Scope,
    /// The earlier and later observations were consistent.
    pub consistency: Scope,
}

/// A stable refusal and optional row location, with no executable content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finding {
    /// The verifier or underlying codec refusal.
    pub code: Refusal,
    /// A one-based row number, when attributable to a row.
    pub sequence: Option<u64>,
    /// False means the first changed row was not located from retained rows.
    pub exact_location: bool,
}

/// No public constructor can manufacture a positive verifier result.
#[derive(Clone, Debug)]
pub struct VerificationReport {
    verdict: Verdict,
    rows: u64,
    integrity: IntegrityScope,
    observations: ObservationScope,
    findings: Vec<Finding>,
}

impl VerificationReport {
    /// Overall verification outcome; an embedded head alone never fills missing scope.
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Number of rows covered by this report.
    pub const fn rows(&self) -> u64 {
        self.rows
    }

    /// Scope for node signatures, chain links, tree root and owner binding data.
    pub const fn integrity(&self) -> IntegrityScope {
        self.integrity
    }

    /// Scope for independently pinned identity, covering checkpoint and consistency.
    pub const fn observations(&self) -> ObservationScope {
        self.observations
    }

    /// Findings are returned as data; they do not become authority.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}
