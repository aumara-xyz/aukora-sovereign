// SPDX-License-Identifier: AGPL-3.0-or-later
//! A moving budget expiry must not undo an owner's answer to the spending terms.

use super::*;
use crate::model_broker::BUDGET_TARGET;
use aura::storage::ProposalStatus;
use broker::engine_link::budget::Budget;

impl GateAdapter {
    /// Automatic budget renewal respects the latest card's terms independently of its expiry. Exact card bytes,
    /// including the expiry, still bind the passkey approval; only the automatic retry hold ignores that clock field.
    pub fn propose_model_budget(
        &self,
        scope: PrincipalScope,
        note: String,
        bytes: Vec<u8>,
    ) -> ServiceFuture<'_, ProposalId> {
        self.submit(move |gate, host| {
            // The broker can run without a door, whose approver otherwise sweeps expired cards. Commit recovery
            // before proposing: a declined/expiry hold must not roll its newly recorded terminal back.
            host.scoped(scope, |txn| gate.recover(txn, &mut NoInjection).map(|_| ()))?;
            host.scoped(scope, |txn| propose_in(txn, gate, note, bytes))
        })
    }
}

fn propose_in<S: TargetStore>(
    txn: &mut aura::LedgerTxn<'_>,
    gate: &mut ScopedGate<S>,
    note: String,
    bytes: Vec<u8>,
) -> Result<ProposalId> {
    let mut wanted = Budget::parse(&bytes).map_err(|_| codes::GATE_UNKNOWN_TARGET)?;
    let epoch = txn.current_version()?.epoch;
    if let Some(latest) = txn.latest_proposal(BUDGET_TARGET)?.filter(|prior| prior.authority.epoch == epoch) {
        let prior = Budget::parse(&latest.new_bytes).map_err(|_| codes::SUPERVISOR_STATE)?;
        wanted.expires_at_ms = prior.expires_at_ms;
        if wanted == prior {
            match latest.status {
                ProposalStatus::Pending => return Ok(latest.proposal),
                ProposalStatus::Refused
                    if txn
                        .last_decline(latest.operation_digest)?
                        .is_some_and(|row| row.proposal == latest.proposal) =>
                {
                    return Err(refuse("declined-unchanged"));
                }
                ProposalStatus::Expired => {
                    if let Some((_, at)) = txn.last_expiry(latest.operation_digest)? {
                        if txn.observation_context()?.at.saturating_sub(at) < aura::ledger::DAY_MS {
                            return Err(refuse("recently-expired"));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let target = TargetId::new(BUDGET_TARGET.to_owned())?;
    let base = gate.target_store().observe(&target)?.digest;
    gate.propose(
        txn,
        request(target, base, note, bytes, None),
        &mut NoInjection,
    )
    .map(|proposal| proposal.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use canon::{
        alg::{PublicKey, Signature, Signatures},
        digest::Digest32,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicI64, Ordering};

    struct TestSigner(SigningKey);
    impl aura::RecordSigner for TestSigner {
        fn public_keys(&self) -> Result<Vec<PublicKey>> {
            Ok(vec![PublicKey {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: self.0.verifying_key().to_bytes().to_vec(),
            }])
        }
        fn sign_entry_hash(&self, hash: Digest32) -> Result<Signatures> {
            Signatures::new(vec![Signature {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: self.0.sign(hash.as_bytes()).to_bytes().to_vec(),
            }])
        }
    }
    struct Clock(AtomicI64);
    impl aura::TrustedClock for Clock {
        fn now_ms(&self) -> Result<i64> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }
    struct Rig {
        directory: PathBuf,
        ledger: HostLedger,
        gate: ScopedGate<ConfinedStore>,
        clock: Arc<Clock>,
    }
    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    fn rig() -> Rig {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let directory = std::env::temp_dir().join(format!("budget-cards-{}", hex::encode(nonce)));
        std::fs::create_dir(&directory).unwrap();
        let directory = std::fs::canonicalize(directory).unwrap();
        let clock = Arc::new(Clock(AtomicI64::new(1_800_000_000_000)));
        let ledger = HostLedger::open(
            &directory.join("aura.sqlite3"),
            Arc::new(TestSigner(SigningKey::from_bytes(&[52; 32]))),
            clock.clone(),
        )
        .unwrap();
        let targets = vec![TargetSpec {
            id: TargetId::new(BUDGET_TARGET.to_owned()).unwrap(),
            class: gate::target::TargetClass::Content,
            risk: gate::RiskTier::Critical,
            max_bytes: 65_536,
        }];
        let store = ConfinedStore::open(File::open(&directory).unwrap(), targets.clone()).unwrap();
        let gate = ScopedGate::new(
            store,
            GateConfig {
                node: canon::ids::NodeId::from_bytes([53; 16]),
                targets,
                proposal_lifetime_ms: 300_000,
                ceremony_lifetime_ms: 300_000,
            },
        )
        .unwrap();
        Rig {
            directory,
            ledger,
            gate,
            clock,
        }
    }
    fn budget(expiry: u64) -> Vec<u8> {
        Budget {
            expires_at_ms: expiry,
            kind: broker::engine_link::budget::BUDGET_KIND.into(),
            max_requests: 100,
            models: vec!["deepseek-flash".into()],
            per_request_cap_microusd: 10,
            prices: broker::engine_link::budget::Prices {
                cache_read_microusd_per_mtok: 1,
                input_microusd_per_mtok: 2,
                output_microusd_per_mtok: 3,
            },
            provider: broker::engine_link::budget::PROVIDER.into(),
            total_cap_microusd: 1000,
            v: 1,
        }
        .canonical_bytes()
        .unwrap()
    }
    impl Rig {
        fn propose(&mut self, bytes: Vec<u8>) -> Result<ProposalId> {
            self.ledger
                .transaction(|txn| self.gate.recover(txn, &mut NoInjection))?;
            self.ledger
                .transaction(|txn| propose_in(txn, &mut self.gate, String::new(), bytes))
        }
        fn advance(&self, ms: i64) {
            self.clock.0.fetch_add(ms, Ordering::SeqCst);
        }
        fn expire(&mut self) {
            self.advance(300_001);
            self.ledger
                .transaction(|txn| self.gate.recover(txn, &mut NoInjection))
                .unwrap();
        }
    }

    #[test]
    fn a_budget_decline_survives_new_expiries_and_restart_until_the_owner_asks_again() {
        let mut rig = rig();
        let bytes = budget(1_900_000_000_000);
        let first = rig.propose(bytes.clone()).unwrap();
        assert_eq!(
            rig.propose(budget(1_900_000_600_000)).unwrap(),
            first,
            "a moving expiry does not replace a pending card"
        );
        rig.ledger
            .transaction(|txn| rig.gate.decline(txn, first))
            .unwrap();
        rig.advance(3 * aura::ledger::DAY_MS);
        rig.ledger = HostLedger::open(
            &rig.directory.join("aura.sqlite3"),
            Arc::new(TestSigner(SigningKey::from_bytes(&[52; 32]))),
            rig.clock.clone(),
        )
        .unwrap();
        assert!(
            matches!(rig.propose(budget(1_900_259_200_000)), Err(code) if code.reason == "declined-unchanged")
        );
        let target = TargetId::new(BUDGET_TARGET.to_owned()).unwrap();
        let base = rig.gate.target_store().observe(&target).unwrap().digest;
        let second = rig
            .ledger
            .transaction(|txn| {
                propose_again_in(
                    txn,
                    &mut rig.gate,
                    first,
                    target,
                    base,
                    String::new(),
                    bytes,
                )
            })
            .unwrap();
        assert_ne!(second, first);
        assert_eq!(rig.propose(budget(1_900_259_200_000)).unwrap(), second);
    }

    #[test]
    fn an_ignored_budget_waits_a_day_even_when_the_next_expiry_is_different() {
        let mut rig = rig();
        let first = rig.propose(budget(1_900_000_000_000)).unwrap();
        rig.expire();
        for elapsed in [600_000, aura::ledger::DAY_MS - 600_001] {
            rig.advance(elapsed);
            assert!(
                matches!(rig.propose(budget(1_900_086_400_000)), Err(code) if code.reason == "recently-expired")
            );
        }
        rig.advance(1);
        assert_ne!(rig.propose(budget(1_900_086_400_000)).unwrap(), first);
    }

    #[test]
    fn changed_spending_terms_can_be_reviewed_after_a_decline() {
        let mut rig = rig();
        let bytes = budget(1_900_000_000_000);
        let first = rig.propose(bytes.clone()).unwrap();
        rig.ledger
            .transaction(|txn| rig.gate.decline(txn, first))
            .unwrap();
        let mut changed = Budget::parse(&bytes).unwrap();
        changed.total_cap_microusd += 1;
        assert_ne!(
            rig.propose(changed.canonical_bytes().unwrap()).unwrap(),
            first
        );
    }

    #[test]
    fn a_budget_keeper_without_a_door_commits_expiry_before_holding_the_next_card() {
        let mut rig = rig();
        let first = rig.propose(budget(1_900_000_000_000)).unwrap();
        rig.advance(300_001);
        assert!(matches!(rig.propose(budget(1_900_000_600_000)), Err(code) if code.reason == "recently-expired"));
        assert_eq!(rig.ledger.transaction(|txn| Ok(txn.proposal(&first)?.status)).unwrap(), ProposalStatus::Expired,
            "a refused automatic retry does not roll back the expiry");
        rig.advance(aura::ledger::DAY_MS);
        assert_ne!(rig.propose(budget(1_900_086_400_000)).unwrap(), first);
    }

    #[test]
    fn an_applied_budget_can_renew_and_an_unsettled_consumption_is_not_a_pending_card() {
        for status in ["applied", "consumed"] {
            let mut rig = rig();
            let previous = budget(1_900_000_000_000);
            let first = rig.propose(previous.clone()).unwrap();
            // Synthetic settlement fixture: this test exercises the keeper's treatment of stored states, not a
            // passkey ceremony. Real gate settlement and consumption proofs are covered by gate's own tests.
            std::fs::create_dir(rig.directory.join("engine")).unwrap();
            std::fs::write(rig.directory.join(BUDGET_TARGET), &previous).unwrap();
            let connection = rusqlite::Connection::open(rig.directory.join("aura.sqlite3")).unwrap();
            connection.execute("UPDATE authority_proposals SET status=?2 WHERE id=?1", rusqlite::params![first.to_string(), status]).unwrap();
            let renewed = budget(1_900_086_400_000);
            // Skip recovery only for this synthetic consumed fixture, which has no signed consumption to settle.
            let result = rig.ledger.transaction(|txn| propose_in(txn, &mut rig.gate, String::new(), renewed.clone()));
            if status == "consumed" {
                assert!(result.is_err(), "an unsettled reservation is refused rather than shown as awaiting approval");
            } else {
                let next = result.unwrap();
                assert_ne!(next, first);
                let stored = rig.ledger.transaction(|txn| txn.proposal(&next)).unwrap();
                assert_eq!(stored.new_bytes, renewed);
                assert_eq!(stored.base_sha256, BaseDigest::Present(Digest32::sha256(&previous)));
            }
        }
    }
}
