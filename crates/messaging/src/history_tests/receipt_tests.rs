// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn accepted_receipt_survives_contact_removal_or_change_without_authorizing_a_retry() -> Result<()> {
    for removed in [true, false] {
        let directory = TestDirectory::new();
        let node = NodeId::from_bytes([3; 16]);
        let (sender, recipient) = (key(25), key(26).public_key()?);
        let mut host = Host::default();
        host.add_contact(recipient);
        let mut store = Messaging::open(&directory.0, node)?;
        let id = store.queue_owner_send(
            &mut host,
            &draft(recipient, "Accepted during contact change"),
            &sender,
            NOW,
        )?;
        let prepared = store.prepare_owner_send(&mut host, id)?;
        let mut relay = FakeRelay::default();
        let receipt = prepared.submit(&mut relay, 1000)?;
        let contact_key = hex::encode(recipient.as_bytes());
        let reason = if removed {
            host.contacts.remove(&contact_key);
            "contact-removed"
        } else {
            let ValueView::Object(fields) = host.contacts[&contact_key].view() else {
                panic!("contact object");
            };
            let changed = fields
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        if name == "receipt" {
                            text(&"03".repeat(32)).unwrap()
                        } else {
                            value.clone()
                        },
                    )
                })
                .collect();
            host.contacts
                .insert(contact_key, Value::checked_object(changed)?);
            "contact-changed"
        };
        store.record_owner_send(&mut host, &prepared, &receipt)?;
        assert_eq!(
            store.messages(None, None, 10)?[0].state,
            MessageState::Published
        );
        assert_eq!(store.owner_send_failure(id)?, None);
        assert!(store.pending_owner_sends_due(NOW + 300_000, 10)?.is_empty());
        assert_eq!(
            store.prepare_owner_send(&mut host, id).err(),
            Some(refuse(reason))
        );
        assert_eq!(
            store.messages(None, None, 10)?[0].state,
            MessageState::Published
        );
        assert_eq!(store.owner_send_failure(id)?, None);
        assert_eq!(relay.0.len(), 1);
        drop(store);
        let store = Messaging::open(&directory.0, node)?;
        assert_eq!(
            store.messages(None, None, 10)?[0].state,
            MessageState::Published
        );
    }
    Ok(())
}
