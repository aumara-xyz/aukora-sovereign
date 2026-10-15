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

pub fn health(sources: ObservationSources<'_>, context: ObservationContext) -> Vec<HealthEvidence> {
    let limits = aura::export::ExportLimits {
        max_bytes: 16 * 1024 * 1024,
        max_rows: 65_536,
    };
    let observation = sources
        .ledger
        .export_cold_proof(limits)
        .map_err(|_| (Cell::Undetermined, HealthReason::Unreachable))
        .and_then(|proof| {
            check_context(&proof, context).map_err(|reason| {
                let cell = if reason == HealthReason::NotChecked {
                    Cell::Undetermined
                } else {
                    Cell::Failed
                };
                (cell, reason)
            })?;
            proof
                .canonical_bytes(limits)
                .map_err(|_| (Cell::Failed, HealthReason::InvalidEvidence))?;
            Ok(proof)
        });
    PRIVATE_CHECKS
        .iter()
        .chain(CORNER_CHECKS.iter())
        .map(|spec| {
            let (cell, reason) = if spec.check == OPERATION_TERMINALS.check
                || spec.check == CONSUMPTION_ONCE.check
                || spec.check == CHAIN_HEAD.check
            {
                match &observation {
                    Err(failure) => *failure,
                    Ok(proof) => {
                        let result = if spec.check == OPERATION_TERMINALS.check {
                            crate::coverage::check_ledger_rows(&proof.rows).map(|_| ())
                        } else if spec.check == CONSUMPTION_ONCE.check {
                            crate::coverage::check_consumption_rows(&proof.rows)
                        } else {
                            Ok(())
                        };
                        if result.is_ok() {
                            (Cell::Verified, HealthReason::Satisfied)
                        } else {
                            (Cell::Failed, HealthReason::InvariantFailed)
                        }
                    }
                }
            } else {
                (Cell::Failed, HealthReason::Unwritten)
            };
            HealthEvidence {
                v: canon::health::HEALTH_FORMAT_VERSION,
                algorithm: AlgorithmId::Sha256,
                check: spec.check,
                reporter: spec.owner,
                epoch: context.epoch,
                sequence: context.sequence,
                observed_at_ms: context.observed_at_ms,
                expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
                cell,
                reason,
                commitment: context.commitment,
            }
        })
        .collect()
}

fn check_context(
    proof: &aura::export::ColdProofV1,
    context: ObservationContext,
) -> core::result::Result<(), HealthReason> {
    if proof.head.sequence != context.sequence || proof.head.hash != context.commitment {
        return Err(HealthReason::ContextMismatch);
    }
    if proof.rows.is_empty()
        || u64::try_from(proof.rows.len()).ok() != Some(proof.head.sequence)
        || proof.head.tree_size != proof.head.sequence
    {
        return Err(HealthReason::InvariantFailed);
    }
    let mut previous = None;
    for (index, row) in proof.rows.iter().enumerate() {
        if row.sequence != index as u64 + 1 || row.previous != previous {
            return Err(HealthReason::InvariantFailed);
        }
        let hash = aura::record::entry_hash_v1(row).map_err(|_| HealthReason::InvalidEvidence)?;
        if row.hash != hash {
            return Err(HealthReason::InvariantFailed);
        }
        previous = Some(hash);
    }
    if previous != Some(proof.head.hash) {
        return Err(HealthReason::InvariantFailed);
    }
    let mut epoch = None;
    for row in proof.rows.iter().rev() {
        if matches!(
            row.body.get("schema").map(canon::json::Value::view),
            Some(canon::json::ValueView::Text(
                aura::record::AUTHORITY_BODY_SCHEMA
            ))
        ) {
            let body = aura::record::AuthorityBodyV1::parse(&row.body)
                .map_err(|_| HealthReason::InvalidEvidence)?;
            if body.authority.sequence != row.sequence
                || body.authority.previous_hash != row.previous
            {
                return Err(HealthReason::ContextMismatch);
            }
            epoch = Some(body.authority.epoch);
            break;
        }
    }
    match epoch {
        Some(epoch) if epoch == context.epoch => Ok(()),
        Some(_) => Err(HealthReason::ContextMismatch),
        None => Err(HealthReason::NotChecked),
    }
}
