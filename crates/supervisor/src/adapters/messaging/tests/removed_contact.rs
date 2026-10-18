// SPDX-License-Identifier: AGPL-3.0-or-later
//! A revoked queued recipient cannot block other sends or the incoming batch.
use super::*;
use crate::faces::{
    live_network::LiveNetwork,
    network::{NetworkRead, SendState},
};
use nostr::{
    ReceiveBatch, ReceiveRequest, Transport, TransportEnvelope, TransportKind, TransportReceipt,
};

struct Relay {
    sent: Vec<nostr::PublicKey>,
    incoming: Vec<TransportEnvelope>,
    reads: usize,
}
impl Transport for Relay {
    fn kind(&self) -> TransportKind {
        TransportKind::NostrRelays
    }
    fn send(&mut self, envelope: &TransportEnvelope, _: u64) -> Result<TransportReceipt> {
        self.sent.push(envelope.recipient);
        Ok(TransportReceipt {
            envelope_id: envelope.id,
            transport: self.kind(),
            status: nostr::SubmissionStatus::Accepted,
        })
    }
    fn receive(&mut self, _: &ReceiveRequest) -> Result<ReceiveBatch> {
        self.reads += 1;
        Ok(ReceiveBatch {
            envelopes: self.incoming.clone(),
            next_cursor: None,
            exhausted: true,
            deferred: None,
        })
    }
}

#[test]
fn removed_contact_fails_only_its_send_and_the_same_poll_receives_and_publishes() -> Result<()> {
    let mut rig = rig()?;
    let removed = contact_action(87, "Removed");
    let retained = contact_action(88, "Retained");
    let contact_key = |action: &OwnerAction| match action {
        OwnerAction::Contact(ContactChange::Add(draft)) => draft.key,
        _ => unreachable!(),
    };
    let (removed_key, retained_key) = (contact_key(&removed), contact_key(&retained));
    rig.approve(&removed, 1)?;
    rig.approve(&retained, 2)?;
    let identity = Arc::new(crate::nostr_identity::NodeIdentity::open(
        &File::open(&rig.directory).unwrap(),
    )?);
    let mut store = messaging::Messaging::open(
        &rig.directory.join("messaging"),
        NodeId::from_bytes([86; 16]),
    )?;
    for recipient in [removed_key, retained_key] {
        rig.ledger.messaging(rig.scope, true, |txn| {
            store.queue_owner_send(
                txn,
                &messaging::SendDraft {
                    recipient,
                    text: "Queued before removal".into(),
                    disclosures: Vec::new(),
                },
                identity.key(),
                NOW as u64,
            )
        })?;
    }
    rig.approve(
        &OwnerAction::Contact(ContactChange::Remove { key: removed_key }),
        3,
    )?;
    let sender = nostr::SecretKey::import(zeroize::Zeroizing::new([88; 32]))?;
    let rumor = nostr::Rumor::new(
        retained_key,
        NOW as u64 / 1000,
        nostr::nip59::MESSAGE_KIND,
        vec![vec![
            "p".into(),
            hex::encode(identity.public_key().as_bytes()),
        ]],
        "Incoming after removal".into(),
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
    let mut relay = Relay {
        sent: Vec::new(),
        incoming: vec![incoming],
        reads: 0,
    };
    network.poll(&mut relay, NOW as u64 / 1000, 10_000)?;
    assert_eq!(relay.sent, vec![retained_key]);
    assert_eq!(relay.reads, 1);
    let removed = network.messages(rig.scope, Some(removed_key), None, 10)?;
    assert!(
        matches!(removed.items[0].state, Some(SendState::Failed(code)) if code.reason == "contact-removed")
    );
    let retained = network.messages(rig.scope, Some(retained_key), None, 10)?;
    assert_eq!(retained.items.len(), 2);
    assert!(retained
        .items
        .iter()
        .any(|row| matches!(row.state, Some(SendState::Published))));
    assert!(retained
        .items
        .iter()
        .any(|row| row.text == "Incoming after removal"));
    network.poll(&mut relay, NOW as u64 / 1000 + 30, 10_000)?;
    assert_eq!(relay.sent, vec![retained_key]);
    Ok(())
}
