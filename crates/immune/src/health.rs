// SPDX-License-Identifier: AGPL-3.0-or-later
//! Body observers use canon's fixed ids, source names and freshness ceilings.

use canon::health::{
    Cell, CheckRef, CheckSpec, HealthEvidence, HealthReason, OrganId, CHECKS, CORNERS,
};
use canon::{alg::AlgorithmId, digest::Digest32};

pub const PRIVATE_CHECKS: [CheckSpec; 18] = [
    CHECKS[72].spec(),
    CHECKS[73].spec(),
    CHECKS[74].spec(),
    CHECKS[75].spec(),
    CHECKS[76].spec(),
    CHECKS[77].spec(),
    CHECKS[78].spec(),
    CHECKS[79].spec(),
    CHECKS[80].spec(),
    CHECKS[81].spec(),
    CHECKS[82].spec(),
    CHECKS[83].spec(),
    CHECKS[84].spec(),
    CHECKS[85].spec(),
    CHECKS[86].spec(),
    CHECKS[87].spec(),
    CHECKS[88].spec(),
    CHECKS[89].spec(),
];

pub const CORNER_CHECKS: [CheckSpec; 8] = [
    CORNERS[6].specs()[1],
    CORNERS[7].specs()[1],
    CORNERS[12].specs()[1],
    CORNERS[13].specs()[1],
    CORNERS[16].specs()[1],
    CORNERS[17].specs()[1],
    CORNERS[18].specs()[1],
    CORNERS[19].specs()[1],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub commitment: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Finding {
    Satisfied,
    Failed,
    Unwritten,
    NotChecked,
    Unreachable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyObservation {
    pub check: CheckRef,
    pub context: Context,
    pub finding: Finding,
}

/// Supervisor-owned observations from the named Body sources; no wire decoder.
pub struct BodyFacts<'a> {
    pub context: Context,
    pub observations: &'a [BodyObservation],
}

pub fn health(facts: &BodyFacts<'_>) -> Vec<HealthEvidence> {
    PRIVATE_CHECKS
        .iter()
        .chain(CORNER_CHECKS.iter())
        .map(|spec| {
            let mut matching = facts.observations.iter().filter(|o| o.check == spec.check);
            let first = matching.next();
            let duplicate = matching.next().is_some();
            let (context, cell, reason) = match first {
                _ if duplicate => (facts.context, Cell::Failed, HealthReason::InvalidEvidence),
                None => (facts.context, Cell::Failed, HealthReason::Unwritten),
                Some(observation) => {
                    let (cell, reason) = match observation.finding {
                        Finding::Satisfied => (Cell::Verified, HealthReason::Satisfied),
                        Finding::Failed => (Cell::Failed, HealthReason::InvariantFailed),
                        Finding::Unwritten => (Cell::Failed, HealthReason::Unwritten),
                        Finding::NotChecked => (Cell::Undetermined, HealthReason::NotChecked),
                        Finding::Unreachable => (Cell::Undetermined, HealthReason::Unreachable),
                    };
                    (observation.context, cell, reason)
                }
            };
            HealthEvidence {
                v: canon::health::HEALTH_FORMAT_VERSION,
                algorithm: AlgorithmId::Sha256,
                check: spec.check,
                reporter: OrganId::Body,
                epoch: context.epoch,
                sequence: context.sequence,
                observed_at_ms: context.observed_at_ms,
                expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
                commitment: context.commitment,
                cell,
                reason,
            }
        })
        .collect()
}
