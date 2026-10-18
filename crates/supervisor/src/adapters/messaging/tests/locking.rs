// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fake transport verifies that scans and relay latency cannot own Aura's writer.
use super::*;
use crate::faces::{live_network::LiveNetwork, network::NetworkRead};
use nostr::transport::{ReceiveBatch, ReceiveRequest, SubmissionStatus};
use std::sync::mpsc;
use std::time::Duration;

fn write_fact(ledger: &HostLedger, scope: PrincipalScope) -> Result<()> {
    ledger.scoped(scope, |txn| {
        let context = txn.observation_context()?;
        txn.append_fact(FactRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: canon::authority::FactKind::BootFacts,
            actor: "messaging-lock-regression".into(),
            body: Value::object(vec![("test".into(), text("writer-progress")?)])?,
        })?;
        Ok(())
    })
}

struct Relay {
    ledger: Arc<HostLedger>,
    scope: PrincipalScope,
    sends: usize,
}
impl nostr::Transport for Relay {
    fn kind(&self) -> nostr::TransportKind {
        nostr::TransportKind::NostrRelays
    }
    fn send(
        &mut self,
        envelope: &nostr::TransportEnvelope,
        _: u64,
    ) -> Result<nostr::TransportReceipt> {
        let ledger = Arc::clone(&self.ledger);
        let scope = self.scope;
        let (done, result) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            done.send(write_fact(&ledger, scope)).unwrap();
        });
        // A relay must be able to wait while an independent approval writer
        // commits. The timeout turns a held mutex/SQLite lock into a failure.
        result
            .recv_timeout(Duration::from_secs(2))
            .expect("relay held Aura writer")?;
        writer.join().unwrap();
        self.sends += 1;
        Ok(nostr::TransportReceipt {
            envelope_id: envelope.id,
            transport: self.kind(),
            status: SubmissionStatus::Accepted,
        })
    }
    fn receive(&mut self, _: &ReceiveRequest) -> Result<ReceiveBatch> {
        Ok(ReceiveBatch {
            envelopes: Vec::new(),
            next_cursor: None,
            exhausted: true,
        })
    }
}

#[test]
fn snapshot_projection_does_not_reserve_the_live_writer() -> Result<()> {
    let rig = rig()?;
    let version = aura::Ledger::read_snapshot(
        &rig.directory.join("aura.sqlite3"),
        rig.ledger.services(),
        |snapshot| {
            let before = snapshot.current_version()?;
            write_fact(&rig.ledger, rig.scope)?;
            // This read remains at its original consistent snapshot, while the
            // independent live connection has committed a new signed record.
            assert_eq!(snapshot.current_version()?, before);
            assert_eq!(snapshot.owner_subject()?, rig.scope.subject);
            Ok(before)
        },
    )?;
    assert_ne!(
        rig.ledger.transaction(|txn| txn.current_version())?,
        version
    );
    Ok(())
}

#[test]
fn fake_relay_submission_allows_concurrent_aura_commit() -> Result<()> {
    let mut rig = rig()?;
    let action = contact_action(87, "Owner B");
    let OwnerAction::Contact(ContactChange::Add(draft)) = &action else {
        unreachable!()
    };
    rig.approve(&action, 1)?;
    let identity = Arc::new(crate::nostr_identity::NodeIdentity::open(
        &File::open(&rig.directory).unwrap(),
    )?);
    let mut store = messaging::Messaging::open(
        &rig.directory.join("messaging"),
        NodeId::from_bytes([86; 16]),
    )?;
    rig.ledger.messaging(rig.scope, true, |txn| {
        store.queue_owner_send(
            txn,
            &messaging::SendDraft {
                recipient: draft.key,
                text: "Lock-free relay I/O".into(),
                disclosures: Vec::new(),
            },
            identity.key(),
            NOW as u64,
        )
    })?;
    let config = rig.gate.as_ref().unwrap().config().clone();
    drop(rig.gate.take());
    let gate = Arc::new(crate::adapters::GateAdapter::start(
        rig.directory.join("aura.sqlite3"),
        File::open(rig.directory.join("targets")).unwrap(),
        config,
        Arc::clone(&rig.ledger),
    )?);
    let network = LiveNetwork::new(Arc::clone(&rig.ledger), store, identity, gate);
    let mut relay = Relay {
        ledger: Arc::clone(&rig.ledger),
        scope: rig.scope,
        sends: 0,
    };
    network.poll(&mut relay, NOW as u64 / 1000, 10_000)?;
    assert_eq!(relay.sends, 1);
    assert!(matches!(
        network
            .messages(rig.scope, Some(draft.key), None, 10)?
            .items[0]
            .state,
        Some(crate::faces::network::SendState::Published)
    ));
    Ok(())
}

#[test]
fn refusal_snapshot_indexes_extend_only_after_the_observation_commit() -> Result<()> {
    let rig = rig()?;
    let counted = rig.ledger.messaging(rig.scope, false, |txn| {
        let counted = messaging::ingress::append_refusal(
            txn,
            messaging::RefusalObservation {
                ingress_digest: Digest32::sha256(b"detached-refusal-index"),
                envelope_id: None,
                transport: nostr::TransportKind::NostrRelays,
                reason: messaging::RefusalReason::Stranger,
                observed_at_ms: NOW as u64,
            },
        )?;
        let counts = txn
            .committed_observation_state("messaging.refusals", "totals")?
            .unwrap();
        assert_eq!(counts.get("total"), Some(&number(1)?));
        let fact = txn
            .committed_observation_state("messaging.refusals.fact", "1")?
            .unwrap();
        assert_eq!(fact.get("sequence"), Some(&number(counted.sequence())?));
        let body = fact.get("body").unwrap();
        let attempt = string(body, "attempt")?;
        assert_eq!(
            txn.committed_observation_state("messaging.refusals.attempt", attempt)?,
            Some(fact)
        );
        Ok(counted)
    })?;
    rig.ledger.messaging(rig.scope, false, |txn| {
        let counts = txn
            .committed_observation_state("messaging.refusals", "totals")?
            .unwrap();
        assert_eq!(counts.get("stranger"), Some(&number(1)?));
        assert_eq!(
            counts.get("last_aura_sequence"),
            Some(&number(counted.sequence())?)
        );
        Ok(())
    })
}

struct InterleavingSigner {
    ledger: Arc<HostLedger>,
    scope: PrincipalScope,
    remaining: std::sync::atomic::AtomicUsize,
}
impl aura::RecordSigner for InterleavingSigner {
    fn public_keys(&self) -> Result<Vec<SigningKey>> {
        use std::sync::atomic::Ordering;
        if self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            // Commit after each detached snapshot was copied, but before its
            // generation can be adopted by the caller's live connection.
            write_fact(&self.ledger, self.scope)?;
        }
        self.ledger.signer.public_keys()
    }
    fn sign_entry_hash(&self, hash: Digest32) -> Result<Signatures> {
        self.ledger.signer.sign_entry_hash(hash)
    }
}

#[test]
fn changing_history_falls_back_to_a_locked_projection_and_runs_once() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut rig = rig()?;
    let action = contact_action(87, "Contact during traffic");
    let OwnerAction::Contact(ContactChange::Add(draft)) = &action else {
        unreachable!()
    };
    rig.approve(&action, 1)?;
    let signer = Arc::new(InterleavingSigner {
        ledger: Arc::clone(&rig.ledger),
        scope: rig.scope,
        remaining: AtomicUsize::new(3),
    });
    let ledger = HostLedger::open(
        &rig.directory.join("aura.sqlite3"),
        signer.clone(),
        Arc::new(Clock),
    )?;
    let calls = AtomicUsize::new(0);
    let keys = ledger.messaging(rig.scope, true, |txn| {
        calls.fetch_add(1, Ordering::SeqCst);
        txn.contact_keys()
    })?;
    assert_eq!(keys, vec![draft.key]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(signer.remaining.load(Ordering::SeqCst), 0);
    Ok(())
}
