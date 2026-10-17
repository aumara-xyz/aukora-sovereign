// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reports separate arithmetic integrity from independently retained observations.

use crate::format::refusal;
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
    owner_signatures: Scope,
    owner_required: bool,
    findings: Vec<Finding>,
}

impl VerificationReport {
    /// Exact C5 assertion signatures matched the caller's independently pinned credential key.
    /// This does not establish enrolment ceremony signatures or physical effects.
    pub const fn owner_signatures(&self) -> Scope {
        self.owner_signatures
    }

    pub(crate) fn owner_signatures_checked(&mut self) {
        self.owner_signatures = Scope::Checked;
        self.settle();
    }

    /// The rows include an operation only the owner can authorize, so nothing short of every retained assertion
    /// verifying under the pinned credential key makes the ledger verified.
    pub(crate) fn require_owner_signatures(&mut self) {
        self.owner_required = true;
    }

    /// The one finding for owner-required rows whose assertions were not (all) verified. A report that already says the
    /// bytes are not what they claim to be keeps that and nothing else.
    pub(crate) fn finish_owner(&mut self) {
        if self.owner_required && self.owner_signatures != Scope::Checked && !self.failed() {
            self.finding(
                Verdict::Unchecked,
                refusal("owner-signatures-unchecked"),
                None,
                false,
            );
        }
    }
    /// Overall verification outcome; an embedded head alone never fills missing scope.
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Number of rows covered by this report.
    pub const fn rows(&self) -> u64 {
        self.rows
    }

    /// Scope for node signatures, chain links, tree root and owner binding data. Owner bindings are checked only when
    /// the rows need no owner assertion or every retained one verified.
    pub fn integrity(&self) -> IntegrityScope {
        let mut integrity = self.integrity;
        if self.owner_required && self.owner_signatures != Scope::Checked {
            integrity.owner_bindings = Scope::Unchecked;
        }
        integrity
    }

    /// The scopes as the checks set them, before owner assertions are held against them.
    pub(crate) const fn walked(&self) -> IntegrityScope {
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

impl VerificationReport {
    pub(crate) fn new(rows: u64) -> Self {
        Self {
            verdict: Verdict::Unchecked,
            rows,
            integrity: IntegrityScope {
                signatures: Scope::Unchecked,
                chain: Scope::Unchecked,
                tree_root: Scope::Unchecked,
                owner_bindings: Scope::Unchecked,
            },
            observations: ObservationScope {
                pinned_identity: Scope::Unchecked,
                covering_checkpoint: Scope::Unchecked,
                consistency: Scope::Unchecked,
            },
            findings: Vec::new(),
            owner_signatures: Scope::Unchecked,
            owner_required: false,
        }
    }

    /// Whether a finding already says the supplied bytes are not what they claim to be.
    pub(crate) fn failed(&self) -> bool {
        matches!(
            self.verdict,
            Verdict::Rewritten | Verdict::Forged | Verdict::KeyMismatch | Verdict::InvalidInput
        )
    }

    pub(crate) fn scopes(&mut self, mut integrity: IntegrityScope, observations: ObservationScope) {
        if self.findings.iter().any(|finding| {
            finding.code.organ == "verifier"
                && matches!(
                    finding.code.reason,
                    "shorter-than-checkpoint"
                        | "checkpoint-mismatch"
                        | "presented-size"
                        | "presented-root"
                        | "bundle-tail-size"
                        | "bundle-head"
                )
        }) {
            integrity.tree_root = Scope::Unchecked;
        }
        self.integrity = integrity;
        self.observations = observations;
        self.settle();
    }

    fn settle(&mut self) {
        if !matches!(self.verdict, Verdict::Verified | Verdict::Unchecked) {
            return;
        }
        let (integrity, observations) = (self.integrity, self.observations);
        self.verdict = if integrity.signatures == Scope::Checked
            && integrity.chain == Scope::Checked
            && integrity.tree_root == Scope::Checked
            && integrity.owner_bindings == Scope::Checked
            && observations.pinned_identity == Scope::Checked
            && observations.covering_checkpoint == Scope::Checked
            && (!self.owner_required || self.owner_signatures == Scope::Checked)
            && self.findings.is_empty()
        {
            Verdict::Verified
        } else {
            Verdict::Unchecked
        };
    }

    pub(crate) fn finding(
        &mut self,
        verdict: Verdict,
        code: Refusal,
        sequence: Option<u64>,
        exact_location: bool,
    ) {
        self.findings.push(Finding {
            code,
            sequence,
            exact_location,
        });
        let rank = |v| match v {
            Verdict::Verified => 0,
            Verdict::Unchecked => 1,
            Verdict::Rewritten => 2,
            Verdict::Forged => 3,
            Verdict::KeyMismatch => 4,
            Verdict::InvalidInput => 5,
        };
        if rank(verdict) > rank(self.verdict) {
            self.verdict = verdict;
        }
    }
}
