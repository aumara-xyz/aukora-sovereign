// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

struct LimitedRelay {
    stored: FakeRelay,
    submissions: Vec<nostr::EventId>,
}
impl Transport for LimitedRelay {
    fn kind(&self) -> TransportKind {
        TransportKind::NostrRelays
    }
    fn send(&mut self, envelope: &TransportEnvelope, deadline: u64) -> Result<TransportReceipt> {
        self.submissions.push(envelope.id);
        let mut receipt = self.stored.send(envelope, deadline)?;
        // A relay may retain the event even when its response asks us to retry.
        if self.submissions.len() <= 5 {
            receipt.status = SubmissionStatus::Unknown;
        }
        Ok(receipt)
    }
    fn receive(&mut self, request: &ReceiveRequest) -> Result<ReceiveBatch> {
        self.stored.receive(request)
    }
}

#[test]
fn uncertain_submissions_back_off_persistently_without_new_wraps() -> Result<()> {
    let directory = TestDirectory::new();
    let node = NodeId::from_bytes([1; 16]);
    let (sender, recipient) = (key(21), key(22).public_key()?);
    let mut host = Host::default();
    host.add_contact(recipient);
    let mut store = Messaging::open(&directory.0, node)?;
    let id = store.queue_owner_send(&mut host, &draft(recipient, "retry me"), &sender, NOW)?;
    let mut relay = LimitedRelay {
        stored: FakeRelay::default(),
        submissions: Vec::new(),
    };
    let mut at = NOW;
    for delay in [30_000, 60_000, 120_000, 240_000, 300_000] {
        assert_eq!(store.pending_owner_sends_due(at, 20)?, vec![id]);
        let receipt = store.transmit_owner(&mut host, &mut relay, id, 1000)?;
        store.record_owner_attempt(id, at, Some(&receipt))?;
        assert_eq!(
            store.messages(None, None, 10)?[0].state,
            MessageState::Unconfirmed
        );
        drop(store);
        store = Messaging::open(&directory.0, node)?;
        assert!(store
            .pending_owner_sends_due(at + delay - 1, 20)?
            .is_empty());
        at += delay;
    }
    assert_eq!(relay.stored.0.len(), 1);
    assert!(relay
        .submissions
        .iter()
        .all(|id| *id == relay.submissions[0]));
    let receipt = store.transmit_owner(&mut host, &mut relay, id, 1000)?;
    store.record_owner_attempt(id, at, Some(&receipt))?;
    assert_eq!(
        store.messages(None, None, 10)?[0].state,
        MessageState::Published
    );
    assert!(store.pending_owner_sends_due(at + 300_000, 20)?.is_empty());
    Ok(())
}

struct LostReplyRelay {
    stored: FakeRelay,
    lose_next: bool,
}
impl Transport for LostReplyRelay {
    fn kind(&self) -> TransportKind {
        TransportKind::NostrRelays
    }
    fn send(&mut self, envelope: &TransportEnvelope, deadline: u64) -> Result<TransportReceipt> {
        let receipt = self.stored.send(envelope, deadline)?;
        if self.lose_next {
            self.lose_next = false;
            Err(refuse("test-lost-reply"))
        } else {
            Ok(receipt)
        }
    }
    fn receive(&mut self, request: &ReceiveRequest) -> Result<ReceiveBatch> {
        self.stored.receive(request)
    }
}

#[test]
fn lost_reply_backoff_survives_restart_and_does_not_hide_another_due_send() -> Result<()> {
    let directory = TestDirectory::new();
    let node = NodeId::from_bytes([2; 16]);
    let (sender, recipient) = (key(23), key(24).public_key()?);
    let mut host = Host::default();
    host.add_contact(recipient);
    let mut store = Messaging::open(&directory.0, node)?;
    let first = store.queue_owner_send(&mut host, &draft(recipient, "lost reply"), &sender, NOW)?;
    let second = store.queue_owner_send(&mut host, &draft(recipient, "still due"), &sender, NOW)?;
    assert_eq!(store.pending_owner_sends_due(NOW, 20)?, vec![first, second]);
    let mut relay = LostReplyRelay {
        stored: FakeRelay::default(),
        lose_next: true,
    };
    assert_eq!(
        store.transmit_owner(&mut host, &mut relay, first, 1000),
        Err(refuse("submission-unconfirmed"))
    );
    store.record_owner_attempt(first, NOW, None)?;
    drop(store);
    let mut store = Messaging::open(&directory.0, node)?;
    // The due predicate is applied before LIMIT, so a sleeping older row cannot
    // occupy the one slot that belongs to another queued send.
    assert_eq!(store.pending_owner_sends_due(NOW, 1)?, vec![second]);
    assert_eq!(
        store.pending_owner_sends_due(NOW + 29_999, 1)?,
        vec![second]
    );
    let receipt = store.transmit_owner(&mut host, &mut relay, second, 1000)?;
    store.record_owner_attempt(second, NOW, Some(&receipt))?;
    assert!(store.pending_owner_sends_due(NOW + 29_999, 20)?.is_empty());
    assert_eq!(store.pending_owner_sends_due(NOW + 30_000, 1)?, vec![first]);
    let receipt = store.transmit_owner(&mut host, &mut relay, first, 1000)?;
    store.record_owner_attempt(first, NOW + 30_000, Some(&receipt))?;
    assert_eq!(relay.stored.0.len(), 2);
    assert!(store.pending_owner_sends_due(NOW + 300_000, 20)?.is_empty());
    Ok(())
}
