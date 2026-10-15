// SPDX-License-Identifier: AGPL-3.0-or-later
//! Version selection for the frozen export formats.

use canon::{alg::AlgorithmId, Result};

/// The four-key pinned cold bundle schema.
pub const COLD_PROOF_V1: &str = "aukora-aura-cold-proof-v1";
/// The six-key C3 retained observation schema.
pub const RETAINED_HEAD_V1: &str = "aukora-aura-retained-head-v1";
/// The six-key C3 presentation schema.
pub const PRESENTED_HEAD_V1: &str = "aukora-aura-presented-head-v1";

/// No future version is silently interpreted as a v1 bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportVersion {
    /// Frozen C3 keys; algorithm and epoch are never added to these outer objects.
    ColdProofV1,
}

impl ExportVersion {
    /// Recognizes the one frozen schema and refuses every other string.
    pub fn from_schema(schema: &str) -> Result<Self> {
        match schema {
            COLD_PROOF_V1 => Ok(Self::ColdProofV1),
            _ => Err(crate::UNSUPPORTED_SCHEMA),
        }
    }

    /// Returns the exact format discriminator.
    pub const fn schema(self) -> &'static str {
        match self {
            Self::ColdProofV1 => COLD_PROOF_V1,
        }
    }

    /// V1 fixes Ed25519 by schema instead of adding an algorithm field to its rows.
    pub const fn signature_algorithm(self) -> AlgorithmId {
        match self {
            Self::ColdProofV1 => AlgorithmId::Ed25519,
        }
    }
}
