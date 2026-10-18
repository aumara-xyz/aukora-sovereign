// SPDX-License-Identifier: AGPL-3.0-or-later
//! Send transport failures leave time for ingress and retain their retry backoff.
use super::*;
use crate::faces::{live_network::LiveNetwork, network::NetworkRead};
use nostr::{
    ReceiveBatch, ReceiveRequest, Transport, TransportEnvelope, TransportKind, TransportReceipt,
};

struct FailingRelay {
    incoming: TransportEnvelope,
    send_deadlines: Vec<u64>,
    receive_deadlines: Vec<u64>,
}
impl Transport for FailingRelay {
    fn kind(&self) -> TransportKind {
        TransportKind::NostrRelays
    }
    fn send(&mut self, _: &TransportEnvelope, deadline: u64) -> Result<TransportReceipt> {
        self.send_deadlines.push(deadline);
        Err(canon::Refusal {
            organ: "relay",
            reason: "deadline",
        })
    }
    fn receive(&mut self, request: &ReceiveRequest) -> Result<ReceiveBatch> {
        self.receive_deadlines.push(request.deadline_ms);
        Ok(ReceiveBatch {
            envelopes: vec![self.incoming.clone()],
            next_cursor: None,
            exhausted: true,
        })
    }
}

#[test]
fn transport_send_error_preserves_ingress_and_the_send_backoff() -> Result<()> {
    let mut rig = rig()?;
    let action = contact_action(87, "Contact");
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
                text: "Retry this send".into(),
                disclosures: Vec::new(),
            },
            identity.key(),
            NOW as u64,
        )
    })?;
    let sender = nostr::SecretKey::import(zeroize::Zeroizing::new([87; 32]))?;
    let rumor = nostr::Rumor::new(
        draft.key,
        NOW as u64 / 1000,
        nostr::nip59::MESSAGE_KIND,
        vec![vec![
            "p".into(),
            hex::encode(identity.public_key().as_bytes()),
        ]],
        "Incoming despite send failure".into(),
    )?;
    let wrap = nostr::nip59::gift_wrap(&rumor, &sender, &identity.public_key(), NOW as u64 / 1000)?;
    let incoming = TransportEnvelope {
        v: nostr::transport::TRANSPORT_VERSION,
        codec: nostr::EnvelopeCodec::Nip59V1,
        recipient: identity.public_key(),
        id: wrap.event().id,
        bytes: wrap.event().encode()?,
    };
    let config = rig.gate.as_ref().unwrap().config().clone();
    drop(rig.gate.take());
    let gate = Arc::new(crate::adapters::GateAdapter::start(
        rig.directory.join("aura.sqlite3"),
        File::open(rig.directory.join("targets")).unwrap(),
        config,
        Arc::clone(&rig.ledger),
    )?);
    let network = LiveNetwork::new(Arc::clone(&rig.ledger), store, identity, gate);
    let mut relay = FailingRelay {
        incoming,
        send_deadlines: Vec::new(),
        receive_deadlines: Vec::new(),
    };
    let deadline = crate::relay_worker::monotonic_ms().saturating_add(10_000);
    network.poll(&mut relay, NOW as u64 / 1000, deadline)?;
    assert_eq!(relay.send_deadlines.len(), 1);
    assert_eq!(relay.receive_deadlines, vec![deadline]);
    assert!(relay.send_deadlines[0] <= deadline - 5_000);
    let messages = network.messages(rig.scope, Some(draft.key), None, 10)?;
    assert!(messages
        .items
        .iter()
        .any(|row| row.text == "Incoming despite send failure"));
    network.poll(&mut relay, NOW as u64 / 1000, deadline)?;
    assert_eq!(
        relay.send_deadlines.len(),
        1,
        "the failed send remains in backoff"
    );
    assert_eq!(relay.receive_deadlines.len(), 2);
    Ok(())
}
