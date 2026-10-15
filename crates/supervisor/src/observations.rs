// SPDX-License-Identifier: AGPL-3.0-or-later
//! Rows 12, 56 and 117: independent evidence collection for immune.
//! Evidence is not a routing or admission input.

use crate::services::ServiceFuture;
use canon::{
    alg::AlgorithmId,
    codes,
    digest::Digest32,
    health::{self, CheckRef, HealthEvidence, OrganId},
    Result,
};
use std::{collections::BTreeSet, time::Duration};

/// Context supplied by the supervisor from the actual observed node state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationContext {
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub commitment: Digest32,
}

/// Each observer reports its registered private checks and its independent corners.
/// Body adapters receive raw facts from their owning code; immune makes their cells.
pub trait OrganObserver: Send + Sync {
    fn organ(&self) -> OrganId;
    fn observe(&self, context: ObservationContext) -> ServiceFuture<'_, Vec<HealthEvidence>>;
}

/// Missing/unreachable observers are retained as absence, never invented verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationFailure {
    Missing(OrganId),
    Unreachable(OrganId),
    Refused(OrganId, canon::Refusal),
}

/// At most 130 reports; 90 private observations and two independent sides per corner.
/// The reducer interprets missing and unwritten checks; collection never approves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedEvidence {
    pub context: ObservationContext,
    pub reports: Vec<HealthEvidence>,
    pub unavailable: Vec<ObservationFailure>,
}

/// Exact opaque bytes returned by immune for the FD 4 health snapshot event.
/// This wrapper provides no authorization or fingerprint conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoherenceBytes(Vec<u8>);

impl CoherenceBytes {
    /// Retain only an immune-produced canonical snapshot within the FD 4 cap.
    /// The health reducer validates cells; the frontdoor only relays these bytes.
    pub fn from_immune(bytes: Vec<u8>) -> Result<Self> {
        let bounded = canon::fd4::OpaqueHealthSnapshot::new(bytes)?;
        health::decode_snapshot(bounded.as_bytes())?;
        Ok(Self(bounded.as_bytes().to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Immune is the only converter of raw Body facts and collected evidence into cells.
pub trait ImmuneService: Send + Sync {
    fn reduce(&self, evidence: CollectedEvidence) -> ServiceFuture<'_, CoherenceBytes>;
}

/// Call each of the five distinct trusted observers at most once per sample.
/// Validate reporter against the registered channel/owner, check duplicates and the
/// 130-report cap, and retain all failures for immune. No result feeds back to routing,
/// credentials, release admission, grant admission or an authority transaction.
pub async fn collect(
    context: ObservationContext,
    observers: &[&dyn OrganObserver],
) -> Result<CollectedEvidence> {
    let bound = canon::json::MAX_SAFE_INTEGER as u64;
    if context.epoch > bound
        || context.sequence > bound
        || context.observed_at_ms > bound
        || observers.len() > OrganId::ALL.len()
    {
        return Err(codes::HEALTH_INVALID_EVIDENCE);
    }
    let registered: Vec<_> = observers
        .iter()
        .map(|observer| (observer.organ(), *observer))
        .collect();
    let mut channels = BTreeSet::new();
    for (organ, _) in &registered {
        if !channels.insert(*organ) {
            return Err(codes::HEALTH_INVALID_EVIDENCE);
        }
    }
    let mut collected = CollectedEvidence {
        context,
        reports: Vec::new(),
        unavailable: OrganId::ALL
            .into_iter()
            .filter(|organ| !channels.contains(organ))
            .map(ObservationFailure::Missing)
            .collect(),
    };
    let mut accepted = BTreeSet::new();
    for (organ, observer) in registered {
        let outcome = tokio::time::timeout(Duration::from_secs(5), observer.observe(context)).await;
        let reports = match outcome {
            Err(_) => {
                collected
                    .unavailable
                    .push(ObservationFailure::Unreachable(organ));
                continue;
            }
            Ok(Err(refusal)) => {
                collected
                    .unavailable
                    .push(ObservationFailure::Refused(organ, refusal));
                continue;
            }
            Ok(Ok(reports)) => reports,
        };
        if !valid_reports(context, organ, &reports, &accepted)
            || collected.reports.len() + reports.len() > health::MAX_EVIDENCE_COUNT
        {
            collected.unavailable.push(ObservationFailure::Refused(
                organ,
                codes::HEALTH_INVALID_EVIDENCE,
            ));
            continue;
        }
        accepted.extend(reports.iter().map(|report| report.check));
        collected.reports.extend(reports);
    }
    Ok(collected)
}

fn valid_reports(
    context: ObservationContext,
    organ: OrganId,
    reports: &[HealthEvidence],
    accepted: &BTreeSet<CheckRef>,
) -> bool {
    if reports.len() > health::MAX_EVIDENCE_COUNT {
        return false;
    }
    let mut batch = BTreeSet::new();
    reports.iter().all(|report| {
        let registered = match report.check {
            CheckRef::Private(id) => health::CHECKS
                .iter()
                .any(|definition| definition.id == id && definition.owner == organ),
            CheckRef::Corner { corner, side } => {
                side == organ
                    && health::CORNERS.iter().any(|definition| {
                        definition.id == corner && definition.owners.contains(&organ)
                    })
            }
        };
        registered
            && report.reporter == organ
            && report.v == health::HEALTH_FORMAT_VERSION
            && report.algorithm == AlgorithmId::Sha256
            && report.epoch == context.epoch
            && report.sequence == context.sequence
            && report.commitment == context.commitment
            && report.observed_at_ms <= context.observed_at_ms
            && report.expires_at_ms >= report.observed_at_ms
            && report.expires_at_ms <= canon::json::MAX_SAFE_INTEGER as u64
            && !accepted.contains(&report.check)
            && batch.insert(report.check)
    })
}
