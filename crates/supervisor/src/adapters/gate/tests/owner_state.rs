// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn only_supported_latest_terminals_offer_ask_again() {
    let mut rig = rig("retry-state", 600_000);
    let first = rig.propose(PLUGIN, br#"{"set":"a"}"#).unwrap();
    assert!(rig.ledger.transaction(|txn| retry::review_state(txn, first)).is_ok());
    rig.decline(first).unwrap();
    assert_eq!(rig.ledger.transaction(|txn| retry::review_state(txn, first)).unwrap_err().reason, "declined-retryable");
    let again = rig.again(first, PLUGIN, br#"{"set":"a"}"#).unwrap();
    rig.decline(again).unwrap();
    assert!(rig.ledger.transaction(|txn| retry::review_state(txn, first)).is_ok(), "an older terminal must not offer Ask again");
    let door = rig.propose(ASK, br#"{"call":"a"}"#).unwrap();
    rig.decline(door).unwrap();
    assert!(rig.ledger.transaction(|txn| retry::review_state(txn, door)).is_ok(), "door cards have no Ask again route");
}

#[test]
fn an_expired_engine_card_has_its_own_retriable_state() {
    let mut rig = rig("retry-expired", 1);
    let id = rig.propose(PLUGIN, br#"{"set":"a"}"#).unwrap();
    rig.expire_all();
    assert_eq!(rig.ledger.transaction(|txn| retry::review_state(txn, id)).unwrap_err().reason, "expired-retryable");
}

#[test]
fn release_withdrawal_preserves_a_card_if_its_review_cannot_be_read() {
    use canon::{authority::{LifecycleKind, LifecycleRecord, Phase}, digest::Digest32, ids::OperationId, json::{SafeInteger, Value}};
    let mut rig = rig("withdraw-review-error", 60_000);
    let id = ProposalId::from_bytes([11; 16]);
    let operation = OperationId::from_bytes([12; 16]);
    let base = Digest32::from_bytes([1; 32]);
    let installed = Digest32::from_bytes([2; 32]);
    let digest = gate::service::scoped::release_operation_digest(rig.gate.config().node, base, installed).unwrap();
    rig.ledger.transaction(|txn| {
        let context = txn.observation_context()?;
        let bytes = canon::json::parse_strict(format!(r#"{{"digest":"{installed}","v":1}}"#).as_bytes())?.canonical_bytes();
        txn.stage_proposal(aura::storage::ProposalState {
            proposal: id, operation, operation_digest: digest, authority: context.authority,
            target: "release".into(), base_sha256: BaseDigest::Present(base), new_bytes: bytes,
            cell: None, risk: gate::RiskTier::Critical, evidence_digest: Digest32::from_bytes([0; 32]),
            evidence_source: None, prior_reviewed_batch: None, actor: "supervisor".into(),
            model_note: String::new(), status: aura::storage::ProposalStatus::Pending,
        })?;
        let body = Value::object(vec![
            ("proposal".into(), Value::text(id.to_string())?), ("target".into(), Value::text("release".into())?),
            ("operation".into(), Value::text(digest.to_string())?), ("suggestion".into(), Value::text("single".into())?),
            ("created_at_ms".into(), Value::integer(SafeInteger::new(context.at)?)),
            ("expires_at_ms".into(), Value::integer(SafeInteger::new(canon::json::MAX_SAFE_INTEGER)?)),
        ])?;
        txn.append_lifecycle(LifecycleRecord {
            v: 1, algorithm: AlgorithmId::Sha256, authority: context.authority, at: context.at,
            kind: LifecycleKind::GatePropose, actor: "supervisor".into(), operation, phase: Phase::Intent, body,
        })?;
        Ok(())
    }).unwrap();
    // A retained, spent review with unreadable material must stop withdrawal, rather than count as no review.
    let connection = rusqlite::Connection::open(rig.directory.join("aura.sqlite3")).unwrap();
    connection.execute("INSERT INTO authority_challenges(proposal,action,challenge,body,card,spent) VALUES (?1,'release',?2,x'00',x'00',1)",
        rusqlite::params![id.to_string(), "00".repeat(32)]).unwrap();
    assert!(rig.ledger.transaction(|txn| txn.read_live_review(id, OwnerOperation::Release)).is_err());
    let gate = &mut rig.gate;
    assert!(rig.ledger.transaction(|txn| gate.withdraw_release(txn, id)).is_err());
    assert_eq!(rig.status(id), aura::storage::ProposalStatus::Pending);
}
