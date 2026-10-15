// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vocabulary is evidence only. The receipt verdict table lives in vectors/.

/// Sentinel claims never supply an authorization or a confidence percentage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentinelVerdict {
    ConsistentClaimed,
    Suspicious,
    Undetermined,
}

impl SentinelVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConsistentClaimed => "CONSISTENT_CLAIMED",
            Self::Suspicious => "SUSPICIOUS",
            Self::Undetermined => "UNDETERMINED",
        }
    }
}

pub const POSITION_SOURCE: &str = "SELF_REPORTED_UNVERIFIABLE";
pub const VERDICT_TABLE: &str = "vectors/verdicts-v1.json";
