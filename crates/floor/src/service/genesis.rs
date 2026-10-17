// SPDX-License-Identifier: AGPL-3.0-or-later
//! A floor may use the supervisor's own release proposal as ordering evidence: the install's starting floor for the
//! installed release (genesis), and an owner's floor for the next release (an upgrade, NODE.md O17).

use super::*;

/// `Ok(true)`: `source` is the supervisor's release proposal from exactly the current floor, and it orders `proposed`.
/// `Ok(false)`: not a proposal record (the caller then requires an applied gate terminal). `Err`: a proposal record
/// that does not match.
pub(super) fn release_proposal_source(
    current: Option<&ProtectedState>,
    proposed: &ReleaseOrder,
    source: &AuthorityRecord,
    proposal: &aura::storage::ProposalState,
) -> Result<bool> {
    let Some(current) = current else {
        return Ok(false);
    };
    if source.kind != Kind::GatePropose {
        return Ok(false);
    }
    current.validate()?;
    let body = payload(&source.body)?;
    // Genesis approves only the release the install recorded; an upgrade names another release. Either way the
    // proposal must start from the floor as it stands (its base) and come after it.
    let step_ok = if current.is_install_genesis() {
        proposed.digest == current.floor.digest
    } else {
        proposed.digest != current.floor.digest
    };
    if !step_ok
        || proposed.ledger_seq <= current.floor.ledger_seq
        || source.authority != proposal.authority
        || source.authority.epoch != proposed.signer_epoch
        || source.authority.sequence != proposed.ledger_seq
        || source.hash != proposed.ledger_hash
        || source.phase != Phase::Intent
        || source.operation != Some(proposal.operation)
        || source.actor != "supervisor"
        || proposal.actor != "supervisor"
        || proposal.target != "release"
        || proposal.base_sha256 != canon::authority::BaseDigest::Present(current.floor.digest)
        || proposal.risk != canon::authority::CardRisk::Critical
        || proposal.cell.is_some()
        || proposal.evidence_source.is_some()
        || proposal.evidence_digest != Digest32::from_bytes([0; 32])
        || proposal.prior_reviewed_batch.is_some()
        || !proposal.model_note.is_empty()
        || Digest32::sha256(&proposal.new_bytes) != proposed.record
        || field_text(body, "proposal") != Some(proposal.proposal.to_string().as_str())
        || field_text(body, "target") != Some("release")
        || field_text(body, "operation") != Some(proposal.operation_digest.to_string().as_str())
    {
        return Err(refuse("ordering-evidence"));
    }
    release_pointer(&proposal.new_bytes, proposed.digest)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{state::CredentialHighWater, Floor, HighWater, SpentApproval};
    use canon::{
        alg::{Signature, Signatures},
        authority::{AuthorityVersion, BaseDigest, CardRisk},
        ids::{CredentialId, OperationDigest, OperationId, ProposalId},
    };

    fn d(n: u8) -> Digest32 {
        Digest32::from_bytes([n; 32])
    }

    fn version(epoch: u64, sequence: u64) -> AuthorityVersion {
        AuthorityVersion { epoch, sequence, previous_hash: (sequence != 1).then(|| d(99)) }
    }

    fn install(digest: Digest32) -> ProtectedState {
        ProtectedState {
            schema: crate::state::INSTALL_STATE_SCHEMA.into(),
            algorithm: AlgorithmId::Sha256,
            authority: version(0, 1),
            floor: Floor { digest, record: digest, signer_epoch: 0, ledger_seq: 1, signer_key_sha256: d(50), ledger_hash: d(51), history: vec![] },
            high_water: HighWater { highest_epoch: 0, highest_sequence: 1, head: d(51), credentials: vec![], spent: vec![] },
        }
    }

    fn owner(digest: Digest32) -> ProtectedState {
        ProtectedState {
            schema: crate::state::STATE_SCHEMA.into(),
            algorithm: AlgorithmId::Sha256,
            authority: version(1, 10),
            floor: Floor { digest, record: d(60), signer_epoch: 1, ledger_seq: 5, signer_key_sha256: d(50), ledger_hash: d(61), history: vec![d(40)] },
            high_water: HighWater {
                highest_epoch: 1,
                highest_sequence: 10,
                head: d(62),
                credentials: vec![CredentialHighWater {
                    credential: CredentialId::new(vec![1, 2, 3]).unwrap(),
                    algorithm: AlgorithmId::Ed25519,
                    key_sha256: d(64),
                    epoch: 1,
                    counter: 0,
                }],
                spent: vec![SpentApproval {
                    algorithm: AlgorithmId::Ed25519,
                    authority: version(1, 10),
                    operation: OperationId::from_bytes([1; 16]),
                    proposal: ProposalId::from_bytes([2; 16]),
                    authorization_sha256: d(63),
                }],
            },
        }
    }

    fn pointer(digest: Digest32) -> Vec<u8> {
        format!("{{\"digest\":\"{digest}\",\"v\":1}}").into_bytes()
    }

    /// The supervisor's release proposal from `base` to `target`, recorded at (epoch 1, sequence 20).
    fn proposal(base: Digest32, target: Digest32) -> (ReleaseOrder, AuthorityRecord, aura::storage::ProposalState) {
        let id = ProposalId::from_bytes([3; 16]);
        let operation = OperationId::from_bytes([4; 16]);
        let digest = OperationDigest::from_digest(d(80));
        let stored = aura::storage::ProposalState {
            proposal: id,
            operation,
            operation_digest: digest,
            authority: version(1, 20),
            target: "release".into(),
            base_sha256: BaseDigest::Present(base),
            new_bytes: pointer(target),
            cell: None,
            risk: CardRisk::Critical,
            evidence_digest: d(0),
            evidence_source: None,
            prior_reviewed_batch: None,
            actor: "supervisor".into(),
            model_note: String::new(),
            status: aura::storage::ProposalStatus::Pending,
        };
        let source = AuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: version(1, 20),
            hash: d(70),
            signatures: Signatures::new(vec![Signature { v: 1, algorithm: AlgorithmId::Ed25519, bytes: vec![0; 64] }]).unwrap(),
            at: 0,
            kind: Kind::GatePropose,
            actor: "supervisor".into(),
            operation: Some(operation),
            phase: Phase::Intent,
            body: aura::record::AuthorityBodyV1 {
                algorithm: AlgorithmId::Sha256,
                authority: version(1, 20),
                payload: object(vec![
                    ("proposal", text(id).unwrap()),
                    ("target", text("release").unwrap()),
                    ("operation", text(digest).unwrap()),
                ])
                .unwrap(),
            }
            .canonical_value()
            .unwrap(),
        };
        let order = ReleaseOrder {
            digest: target,
            record: Digest32::sha256(&pointer(target)),
            signer_epoch: 1,
            ledger_seq: 20,
            signer_key_sha256: d(50),
            ledger_hash: d(70),
        };
        (order, source, stored)
    }

    #[test]
    fn genesis_orders_only_the_installed_release() {
        let (a, b) = (d(1), d(2));
        let state = install(a);
        state.validate().unwrap();
        let (order, source, stored) = proposal(a, a);
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).unwrap());
        let (order, source, stored) = proposal(a, b);
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).is_err());
    }

    #[test]
    fn an_owner_floor_orders_an_upgrade_from_itself_to_another_release() {
        let (a, b) = (d(1), d(2));
        let state = owner(a);
        state.validate().unwrap();
        let (order, source, stored) = proposal(a, b);
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).unwrap());
        // The same release again is not an upgrade.
        let (order, source, stored) = proposal(a, a);
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).is_err());
        // A card raised from another floor (stale base) orders nothing.
        let (order, source, stored) = proposal(d(3), b);
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).is_err());
        // Only the supervisor raises release cards.
        let (order, mut source, stored) = proposal(a, b);
        source.actor = "auma".into();
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).is_err());
        let (order, source, mut stored) = proposal(a, b);
        stored.actor = "auma".into();
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).is_err());
        // A card from before the floor cannot order a step after it.
        let (mut order, mut source, mut stored) = proposal(a, b);
        order.ledger_seq = 5;
        source.authority = version(1, 5);
        stored.authority = version(1, 5);
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).is_err());
        // The pointer must name the ordered release.
        let (mut order, source, stored) = proposal(a, b);
        order.digest = d(9);
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).is_err());
        // Evidence or a model note is never part of a release card.
        let (order, source, mut stored) = proposal(a, b);
        stored.model_note = "x".into();
        assert!(release_proposal_source(Some(&state), &order, &source, &stored).is_err());
    }

    #[test]
    fn other_records_are_left_to_the_applied_terminal_rule() {
        let (a, b) = (d(1), d(2));
        let (order, mut source, stored) = proposal(a, b);
        assert!(!release_proposal_source(None, &order, &source, &stored).unwrap());
        source.kind = Kind::GateApply;
        assert!(!release_proposal_source(Some(&owner(a)), &order, &source, &stored).unwrap());
    }
}
