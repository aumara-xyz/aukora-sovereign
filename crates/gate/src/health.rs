// SPDX-License-Identifier: AGPL-3.0-or-later
//! Gate and Aura observers. Unwritten observers always report Failed.

use canon::{
    alg::AlgorithmId,
    digest::Digest32,
    health::{Cell, CheckSpec, HealthEvidence, HealthReason, CHECKS, CORNERS},
};

pub const CANONICAL_INGRESS: CheckSpec = CHECKS[18].spec();
pub const PROPOSAL_BASE: CheckSpec = CHECKS[19].spec();
pub const DISPLAY_COMMITMENT: CheckSpec = CHECKS[20].spec();
pub const REBUILT_AUTHORIZATION: CheckSpec = CHECKS[21].spec();
pub const CREDENTIAL_EPOCH: CheckSpec = CHECKS[22].spec();
pub const PASSKEY_CONTEXT: CheckSpec = CHECKS[23].spec();
pub const AUTHORITY_TRANSACTION: CheckSpec = CHECKS[24].spec();
pub const CONSUMPTION_ONCE: CheckSpec = CHECKS[25].spec();
pub const CHAIN_HEAD: CheckSpec = CHECKS[26].spec();
pub const RECORD_SIGNATURES: CheckSpec = CHECKS[27].spec();
pub const AUTHORITY_GUARDS: CheckSpec = CHECKS[28].spec();
pub const OPERATION_TERMINALS: CheckSpec = CHECKS[29].spec();
pub const APPEND_ONLY: CheckSpec = CHECKS[30].spec();
pub const RELEASE_FLOOR: CheckSpec = CHECKS[31].spec();
pub const BOOT_FACTS: CheckSpec = CHECKS[32].spec();
pub const RETAINED_EXPORT: CheckSpec = CHECKS[33].spec();
pub const BROWSER_WITNESS: CheckSpec = CHECKS[34].spec();
pub const AUTHORITY_SOURCES: CheckSpec = CHECKS[35].spec();

pub const PRIVATE_CHECKS: [CheckSpec; 18] = [
    CANONICAL_INGRESS,
    PROPOSAL_BASE,
    DISPLAY_COMMITMENT,
    REBUILT_AUTHORIZATION,
    CREDENTIAL_EPOCH,
    PASSKEY_CONTEXT,
    AUTHORITY_TRANSACTION,
    CONSUMPTION_ONCE,
    CHAIN_HEAD,
    RECORD_SIGNATURES,
    AUTHORITY_GUARDS,
    OPERATION_TERMINALS,
    APPEND_ONLY,
    RELEASE_FLOOR,
    BOOT_FACTS,
    RETAINED_EXPORT,
    BROWSER_WITNESS,
    AUTHORITY_SOURCES,
];

pub const OWNER_EPOCH: CheckSpec = CORNERS[0].specs()[1];
pub const OWNER_ENROLMENTS: CheckSpec = CORNERS[1].specs()[1];
pub const KIRA_ANCHOR: CheckSpec = CORNERS[8].specs()[0];
pub const KIRA_ACTION_COUNTS: CheckSpec = CORNERS[9].specs()[0];
pub const RELAY_HEAD: CheckSpec = CORNERS[10].specs()[0];
pub const RELATIONSHIP_CONSUMPTIONS: CheckSpec = CORNERS[11].specs()[0];
pub const APPROVED_RELEASE: CheckSpec = CORNERS[12].specs()[0];
pub const RELEASE_CORPUS: CheckSpec = CORNERS[13].specs()[0];

pub const CORNER_CHECKS: [CheckSpec; 8] = [
    OWNER_EPOCH,
    OWNER_ENROLMENTS,
    KIRA_ANCHOR,
    KIRA_ACTION_COUNTS,
    RELAY_HEAD,
    RELATIONSHIP_CONSUMPTIONS,
    APPROVED_RELEASE,
    RELEASE_CORPUS,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationContext {
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub commitment: Digest32,
}

pub struct ObservationSources<'a> {
    pub ledger: &'a aura::Ledger,
    pub configuration: &'a crate::service::GateConfig,
    pub targets: &'a dyn crate::target::TargetStore,
}

pub fn health(
    _sources: ObservationSources<'_>,
    context: ObservationContext,
) -> Vec<HealthEvidence> {
    PRIVATE_CHECKS
        .iter()
        .chain(CORNER_CHECKS.iter())
        .map(|spec| HealthEvidence {
            v: canon::health::HEALTH_FORMAT_VERSION,
            algorithm: AlgorithmId::Sha256,
            check: spec.check,
            reporter: spec.owner,
            epoch: context.epoch,
            sequence: context.sequence,
            observed_at_ms: context.observed_at_ms,
            expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
            cell: Cell::Failed,
            reason: HealthReason::Unwritten,
            commitment: context.commitment,
        })
        .collect()
}
