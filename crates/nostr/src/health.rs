// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network's 18 private checks and eight independent corner reports.
//!
//! Definitions are canon registry entries: each retains the exact observed fact,
//! source, owner and freshness limit. No local renumbering or observer override.

use canon::{
    alg::AlgorithmId,
    digest::Digest32,
    health::{Cell, CheckSpec, HealthEvidence, HealthReason, OrganId, HEALTH_FORMAT_VERSION},
    health_registry::{CHECKS, CORNERS},
};

pub const NODE_DELEGATION: CheckSpec = CHECKS[54].spec();
pub const AGENT_DELEGATION: CheckSpec = CHECKS[55].spec();
pub const CONTACT_BINDINGS: CheckSpec = CHECKS[56].spec();
pub const DEVICE_BINDINGS: CheckSpec = CHECKS[57].spec();
pub const INGRESS_ADMISSION: CheckSpec = CHECKS[58].spec();
pub const MESSAGE_PROVENANCE: CheckSpec = CHECKS[59].spec();
pub const SEND_RECEIPTS: CheckSpec = CHECKS[60].spec();
pub const RELAY_SET: CheckSpec = CHECKS[61].spec();
pub const EVENT_SIGNATURES: CheckSpec = CHECKS[62].spec();
pub const HEAD_WITNESSES: CheckSpec = CHECKS[63].spec();
pub const INVITE_CONSUMPTION: CheckSpec = CHECKS[64].spec();
pub const INVITE_BOUNDS: CheckSpec = CHECKS[65].spec();
pub const AUTHORITY_GUARDS: CheckSpec = CHECKS[66].spec();
pub const COPRESENCE_EVIDENCE: CheckSpec = CHECKS[67].spec();
pub const PAIRING_LABELS: CheckSpec = CHECKS[68].spec();
pub const DISCLOSURE_PERMISSIONS: CheckSpec = CHECKS[69].spec();
pub const REFUSAL_COUNTERS: CheckSpec = CHECKS[70].spec();
pub const ANTIBODY_ADMISSION: CheckSpec = CHECKS[71].spec();

pub const AUMLOK_IDENTITIES: CheckSpec = CORNERS[4].specs()[1];
pub const AUMLOK_RELATIONSHIPS: CheckSpec = CORNERS[5].specs()[1];
pub const AURA_HEAD: CheckSpec = CORNERS[10].specs()[1];
pub const AURA_CONSUMPTIONS: CheckSpec = CORNERS[11].specs()[1];
pub const KIRA_BACKUP: CheckSpec = CORNERS[14].specs()[1];
pub const KIRA_DISCLOSURES: CheckSpec = CORNERS[15].specs()[1];
pub const BODY_EGRESS: CheckSpec = CORNERS[18].specs()[0];
pub const BODY_ADDRESS: CheckSpec = CORNERS[19].specs()[0];

pub const PRIVATE_CHECKS: [CheckSpec; 18] = [
    NODE_DELEGATION,
    AGENT_DELEGATION,
    CONTACT_BINDINGS,
    DEVICE_BINDINGS,
    INGRESS_ADMISSION,
    MESSAGE_PROVENANCE,
    SEND_RECEIPTS,
    RELAY_SET,
    EVENT_SIGNATURES,
    HEAD_WITNESSES,
    INVITE_CONSUMPTION,
    INVITE_BOUNDS,
    AUTHORITY_GUARDS,
    COPRESENCE_EVIDENCE,
    PAIRING_LABELS,
    DISCLOSURE_PERMISSIONS,
    REFUSAL_COUNTERS,
    ANTIBODY_ADMISSION,
];

pub const CORNER_CHECKS: [CheckSpec; 8] = [
    AUMLOK_IDENTITIES,
    AUMLOK_RELATIONSHIPS,
    AURA_HEAD,
    AURA_CONSUMPTIONS,
    KIRA_BACKUP,
    KIRA_DISCLOSURES,
    BODY_EGRESS,
    BODY_ADDRESS,
];

/// Trusted supervisor context; no external message may supply observation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthContext {
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub commitment: Digest32,
}

/// The wave-0 observer emits all registered reports as Failed/Unwritten. No
/// caller-supplied boolean, fingerprint or receipt can manufacture Verified.
pub fn health(context: &HealthContext) -> Vec<HealthEvidence> {
    PRIVATE_CHECKS
        .iter()
        .chain(CORNER_CHECKS.iter())
        .map(|spec| HealthEvidence {
            v: HEALTH_FORMAT_VERSION,
            algorithm: AlgorithmId::Sha256,
            check: spec.check,
            reporter: OrganId::Network,
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
