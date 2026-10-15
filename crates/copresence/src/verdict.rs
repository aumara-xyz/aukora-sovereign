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

/// Common observation context supplied by the supervisor's health collector.
#[derive(Clone, Copy, Debug)]
pub struct HealthContext {
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub commitment: canon::digest::Digest32,
}

/// Network check 14 requires a completed signed challenge exchange and the same
/// durably accepted receipt. A legacy receipt cannot satisfy this observation.
pub fn evidence_health(
    exchange: Option<&crate::v1::Exchange>,
    receipt: Option<&crate::v1::VerifiedReceipt>,
    context: HealthContext,
) -> canon::health::HealthEvidence {
    use canon::{
        alg::AlgorithmId,
        health::{Cell, HealthEvidence, HealthReason, OrganId, HEALTH_FORMAT_VERSION},
        health_registry::CHECKS,
    };
    let spec = CHECKS[67].spec();
    let (cell, reason) = match (exchange, receipt) {
        (Some(exchange), Some(receipt)) => match exchange.verified_core() {
            Some((digest, at)) if digest == receipt.digest() => {
                let age = context.observed_at_ms.checked_sub(at.saturating_mul(1_000));
                if age.is_some_and(|age| age <= spec.freshness_ms) {
                    (Cell::Verified, HealthReason::Satisfied)
                } else {
                    (Cell::Undetermined, HealthReason::Stale)
                }
            }
            Some(_) => (Cell::Failed, HealthReason::ContextMismatch),
            None if exchange.stage() == crate::v1::Stage::Refused => {
                (Cell::Failed, HealthReason::InvariantFailed)
            }
            None => (Cell::Undetermined, HealthReason::NotChecked),
        },
        (Some(exchange), _) if exchange.stage() == crate::v1::Stage::Refused => {
            (Cell::Failed, HealthReason::InvariantFailed)
        }
        _ => (Cell::Undetermined, HealthReason::NotChecked),
    };
    HealthEvidence {
        v: HEALTH_FORMAT_VERSION,
        algorithm: AlgorithmId::Sha256,
        check: spec.check,
        reporter: OrganId::Network,
        epoch: context.epoch,
        sequence: context.sequence,
        observed_at_ms: context.observed_at_ms,
        expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
        cell,
        reason,
        commitment: context.commitment,
    }
}
