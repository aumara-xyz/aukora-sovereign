// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUMLOK's registered observations; every unwritten observer reports Failed.

use canon::alg::AlgorithmId;
use canon::digest::Digest32;
use canon::health::{
    Cell, CheckSpec, HealthEvidence, HealthReason, OrganId, CHECKS, CORNERS, HEALTH_FORMAT_VERSION,
};

/// Private 1: random identity root is phrase-sealed; 30-second freshness.
pub const ROOT_SEAL: CheckSpec = CHECKS[0].spec();
/// Private 2: seven words match the enrolled acrostic and list version; 30 seconds.
pub const PHRASE_FORMAT: CheckSpec = CHECKS[1].spec();
/// Private 3: root envelope uses permitted KDF and AEAD algorithms; 30 seconds.
pub const ROOT_ENVELOPE: CheckSpec = CHECKS[2].spec();
/// Private 4: credential epoch is not below its rollback guard; 5 seconds.
pub const CREDENTIAL_EPOCH: CheckSpec = CHECKS[3].spec();
/// Private 5: accepted credentials have current owner bindings; 5 seconds.
pub const CREDENTIAL_BINDINGS: CheckSpec = CHECKS[4].spec();
/// Private 6: accepted assertions require presence and verification; 5 seconds.
pub const ASSERTION_FLAGS: CheckSpec = CHECKS[5].spec();
/// Private 7: accepted assertions match the enrolled RP hash; 5 seconds.
pub const ASSERTION_RP: CheckSpec = CHECKS[6].spec();
/// Private 8: accepted ceremony and shell origins match enrolment; 5 seconds.
pub const ASSERTION_ORIGINS: CheckSpec = CHECKS[7].spec();
/// Private 9: sign counters follow the persisted counter policy; 5 seconds.
pub const SIGN_COUNTERS: CheckSpec = CHECKS[8].spec();
/// Private 10: delegated keys bind to the active root epoch; 30 seconds.
pub const DELEGATED_KEYS: CheckSpec = CHECKS[9].spec();
/// Private 11: key and signature formats name permitted algorithms; 30 seconds.
pub const ALGORITHM_BINDINGS: CheckSpec = CHECKS[10].spec();
/// Private 12: public payloads contain neither root nor phrase material; 30 seconds.
pub const PUBLIC_PAYLOADS: CheckSpec = CHECKS[11].spec();
/// Private 13: enrolled bindings retain verified credential keys; 30 seconds.
pub const PASSKEY_PUBLIC_KEYS: CheckSpec = CHECKS[12].spec();
/// Private 14: unlock admission reads the current principal's limits; 5 seconds.
pub const UNLOCK_COUNTERS: CheckSpec = CHECKS[13].spec();
/// Private 15: refused unlocks are counted without authority; 5 seconds.
pub const UNLOCK_REFUSALS: CheckSpec = CHECKS[14].spec();
/// Private 16: root rotations advance an owner-approved epoch; 30 seconds.
pub const ROOT_ROTATIONS: CheckSpec = CHECKS[15].spec();
/// Private 17: recovery evidence does not replace owner approval; 30 seconds.
pub const RECOVERY_POLICY: CheckSpec = CHECKS[16].spec();
/// Private 18: active bindings retain their Aura enrolment anchor; 30 seconds.
pub const ENROLMENT_ANCHORS: CheckSpec = CHECKS[17].spec();

/// Corner 1, AUMLOK side: owner epoch equals Aura's recorded epoch; 5 seconds.
pub const AURA_OWNER_EPOCH: CheckSpec = CORNERS[0].specs()[0];
/// Corner 2, AUMLOK side: every accepted passkey has Aura enrolment; 5 seconds.
pub const AURA_ENROLMENT: CheckSpec = CORNERS[1].specs()[0];
/// Corner 3, AUMLOK side: Kira's key uses the current root epoch; 30 seconds.
pub const KIRA_ROOT_EPOCH: CheckSpec = CORNERS[2].specs()[0];
/// Corner 4, AUMLOK side: Kira permission changes have owner signatures; 5 seconds.
pub const KIRA_PERMISSION: CheckSpec = CORNERS[3].specs()[0];
/// Corner 5, AUMLOK side: active Nostr keys are the delegated keys; 30 seconds.
pub const NETWORK_NOSTR_KEYS: CheckSpec = CORNERS[4].specs()[0];
/// Corner 6, AUMLOK side: contacts and devices have owner approvals; 5 seconds.
pub const NETWORK_RELATIONSHIPS: CheckSpec = CORNERS[5].specs()[0];
/// Corner 7, AUMLOK side: frontdoor RP and top origin match enrolment; 5 seconds.
pub const BODY_ORIGINS: CheckSpec = CORNERS[6].specs()[0];
/// Corner 8, AUMLOK side: frontdoor limits match principal counters; 5 seconds.
pub const BODY_UNLOCK_LIMITS: CheckSpec = CORNERS[7].specs()[0];

/// Every private report in canon's one-based local-index order.
pub const PRIVATE_CHECKS: [CheckSpec; 18] = [
    ROOT_SEAL,
    PHRASE_FORMAT,
    ROOT_ENVELOPE,
    CREDENTIAL_EPOCH,
    CREDENTIAL_BINDINGS,
    ASSERTION_FLAGS,
    ASSERTION_RP,
    ASSERTION_ORIGINS,
    SIGN_COUNTERS,
    DELEGATED_KEYS,
    ALGORITHM_BINDINGS,
    PUBLIC_PAYLOADS,
    PASSKEY_PUBLIC_KEYS,
    UNLOCK_COUNTERS,
    UNLOCK_REFUSALS,
    ROOT_ROTATIONS,
    RECOVERY_POLICY,
    ENROLMENT_ANCHORS,
];

/// This organ's eight independent corner reports in canon registry order.
pub const CORNER_CHECKS: [CheckSpec; 8] = [
    AURA_OWNER_EPOCH,
    AURA_ENROLMENT,
    KIRA_ROOT_EPOCH,
    KIRA_PERMISSION,
    NETWORK_NOSTR_KEYS,
    NETWORK_RELATIONSHIPS,
    BODY_ORIGINS,
    BODY_UNLOCK_LIMITS,
];

/// Supervisor snapshot context, without root material or fingerprint trits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthContext {
    /// Owner epoch inspected by the collector.
    pub epoch: u64,
    /// Aura sequence inspected by the collector.
    pub sequence: u64,
    /// Supervisor report time; it does not establish authority.
    pub observed_at_ms: u64,
    /// Exact shared context commitment for independently reported corners.
    pub commitment: Digest32,
}

/// Reports all 26 observers as Failed/Unwritten. No observation is manufactured
/// from caller booleans, and this function does not reduce a health map.
pub fn health(context: HealthContext) -> Vec<HealthEvidence> {
    PRIVATE_CHECKS
        .iter()
        .chain(CORNER_CHECKS.iter())
        .map(|spec| HealthEvidence {
            v: HEALTH_FORMAT_VERSION,
            algorithm: AlgorithmId::Sha256,
            check: spec.check,
            reporter: OrganId::Aumlok,
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
