// SPDX-License-Identifier: AGPL-3.0-or-later
//! A bounded in-process NIP-01 relay: no sockets, DNS or external services.
use crate::{
    transport::{receive_page, relay_key},
    Filter,
};
use nostr::{Event, ReceiveRequest, SecretKey, VerifiedEvent};
use std::collections::BTreeSet;

fn event(key: &SecretKey, recipient: nostr::PublicKey, time: u64, text: &str) -> VerifiedEvent {
    Event::sign(
        key,
        time,
        nostr::nip59::GIFT_WRAP_KIND,
        vec![vec![
            "p".into(),
            recipient
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        ]],
        text.into(),
    )
    .unwrap()
}
fn query(events: &[VerifiedEvent], filter: &Filter) -> Vec<VerifiedEvent> {
    let mut selected: Vec<_> = events
        .iter()
        .filter(|e| filter.matches(e.event()))
        .collect();
    selected.sort_by_key(|e| (std::cmp::Reverse(e.event().created_at), e.event().id));
    selected.truncate(usize::from(filter.limit.unwrap_or(128)));
    selected
        .into_iter()
        .map(|e| e.event().clone().verify().unwrap())
        .collect()
}

#[test]
fn paged_flood_keeps_timestamp_ties_and_rotates_relays_across_restart() {
    let key = SecretKey::generate().unwrap();
    let recipient = SecretKey::generate().unwrap().public_key().unwrap();
    let mut flooded: Vec<_> = (0..300)
        .map(|n| event(&key, recipient, 100 + n, &n.to_string()))
        .collect();
    flooded.extend((0..100).map(|n| event(&key, recipient, 700, &format!("tie-{n}"))));
    // A contact's older wrap is behind more than the old 128-item snapshot.
    let contact = event(&key, recipient, 50, "contact");
    let contact_id = contact.event().id;
    flooded.push(contact);
    let other = vec![event(&key, recipient, 60, "other relay")];
    let other_id = other[0].event().id;
    let expected: BTreeSet<_> = flooded.iter().map(|e| e.event().id).collect();
    let keys = [
        relay_key("wss://first.example"),
        relay_key("wss://second.example"),
    ];
    let mut request = ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 128,
        max_bytes: 1_048_576,
        deadline_ms: 1,
    };
    let mut seen = BTreeSet::new();
    let mut queried = Vec::new();
    let mut completed = false;
    for poll in 0..500 {
        // All newer arrivals stay outside the already-frozen first sweep.
        flooded.push(event(&key, recipient, 1001 + poll, "new stranger"));
        let batch = receive_page(&keys, &request, 1000 + poll, |index, filter| {
            queried.push(index);
            Ok(query(if index == 0 { &flooded } else { &other }, filter))
        })
        .unwrap();
        assert!(batch.envelopes.len() <= 128);
        seen.extend(batch.envelopes.iter().map(|e| e.id));
        // Persist only the opaque cursor; the adapter carries no pagination state.
        request.cursor = batch.next_cursor;
        if poll == 1 {
            assert!(
                seen.contains(&other_id),
                "one relay cannot monopolize polls"
            );
        }
        if queried.last() == Some(&0) && batch.exhausted {
            completed = true;
            break;
        }
    }
    assert!(
        completed,
        "finite frozen backlog must finish despite newer arrivals"
    );
    assert!(seen.contains(&contact_id));
    assert!(
        expected.is_subset(&seen),
        "same-second wraps cannot be skipped at a page boundary"
    );
    assert!(queried.windows(2).all(|pair| pair[0] != pair[1]));
}

#[test]
fn incomplete_or_oversized_page_retains_history_and_rotates() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let events: Vec<_> = (0..17)
        .map(|n| event(&key, recipient, 80, &n.to_string()))
        .collect();
    let request = ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 128,
        max_bytes: 1_048_576,
        deadline_ms: 1,
    };
    let result = receive_page(
        &[relay_key("wss://relay.example")],
        &request,
        100,
        |_, _| Ok(events.clone()),
    );
    let batch = result.unwrap();
    assert!(batch.envelopes.is_empty());
    assert!(!batch.exhausted);
    let cursor: serde_json::Value =
        serde_json::from_str(batch.next_cursor.as_ref().unwrap()).unwrap();
    assert_eq!(cursor[2][0][2], 100);
    assert_eq!(cursor[2][0][6], false);
    let result = receive_page(
        &[relay_key("wss://relay.example")],
        &request,
        100,
        |_, _| {
            Err(canon::Refusal {
                organ: "relay",
                reason: "query-incomplete",
            })
        },
    );
    let batch = result.unwrap();
    assert!(batch.envelopes.is_empty());
    assert!(!batch.exhausted);
}

#[test]
fn saturated_timestamp_is_retained_without_starving_another_relay() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let flooded: Vec<_> = (0..300)
        .map(|n| event(&key, recipient, 80, &n.to_string()))
        .collect();
    let other = vec![event(&key, recipient, 60, "other")];
    let keys = [
        relay_key("wss://first.example"),
        relay_key("wss://second.example"),
    ];
    let mut request = ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 128,
        max_bytes: 1_048_576,
        deadline_ms: 1,
    };
    let mut seen_other = false;
    for _ in 0..16 {
        let batch = receive_page(&keys, &request, 100, |index, filter| {
            Ok(query(if index == 0 { &flooded } else { &other }, filter))
        })
        .unwrap();
        seen_other |= batch.envelopes.iter().any(|e| e.id == other[0].event().id);
        request.cursor = batch.next_cursor;
    }
    assert!(seen_other);
    let cursor: serde_json::Value = serde_json::from_str(request.cursor.as_ref().unwrap()).unwrap();
    let position = cursor[2]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p[0] == keys[0])
        .unwrap();
    assert_eq!(position[2], 80, "never move below an unexhausted timestamp");
    assert_eq!(position[4], true);
    assert_eq!(position[5], 128);
    assert_eq!(position[6], false);
}

#[test]
fn failed_query_cannot_pin_polling_to_an_unresponsive_relay() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let healthy = vec![event(&key, recipient, 80, "healthy relay")];
    let keys = [
        relay_key("wss://first.example"),
        relay_key("wss://second.example"),
    ];
    let mut request = ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 128,
        max_bytes: 1_048_576,
        deadline_ms: 1,
    };
    let mut delivered = 0;
    for poll in 0..4 {
        let batch = receive_page(&keys, &request, 100, |index, filter| {
            if index == 0 {
                Err(canon::Refusal {
                    organ: "relay",
                    reason: "operation-timeout",
                })
            } else {
                Ok(query(&healthy, filter))
            }
        })
        .unwrap();
        delivered += batch.envelopes.len();
        request.cursor = batch.next_cursor;
        assert_eq!(delivered > 0, poll > 0);
    }
    let cursor: serde_json::Value = serde_json::from_str(request.cursor.as_ref().unwrap()).unwrap();
    assert_eq!(cursor[2][0][2], 100);
    assert_eq!(cursor[2][0][6], false);
}

#[test]
fn periodic_full_history_sweep_finds_wrap_published_after_a_long_sender_outage() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let keys = [relay_key("wss://relay.example")];
    let now = nostr::nip59::TIMESTAMP_JITTER_SECONDS * 3;
    let mut request = ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 128,
        max_bytes: 1_048_576,
        deadline_ms: 1,
    };
    let empty = receive_page(&keys, &request, now, |_, _| Ok(Vec::new())).unwrap();
    assert!(empty.exhausted);
    request.cursor = empty.next_cursor;
    // This signed wrap was queued long before it could first reach the relay.
    let old = vec![event(&key, recipient, 10, "late publication")];
    let mut found = false;
    for _ in 0..8 {
        let batch = receive_page(&keys, &request, now + 30, |_, filter| {
            Ok(query(&old, filter))
        })
        .unwrap();
        found |= batch.envelopes.iter().any(|e| e.id == old[0].event().id);
        request.cursor = batch.next_cursor;
    }
    assert!(
        found,
        "timestamp overlap alone permanently loses old queued wraps"
    );
}

#[test]
fn fresh_tail_is_polled_while_frozen_history_is_still_backlogged() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let mut events: Vec<_> = (0..500)
        .map(|n| event(&key, recipient, 100 + n, &n.to_string()))
        .collect();
    let keys = [relay_key("wss://relay.example")];
    let mut request = ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 128,
        max_bytes: 1_048_576,
        deadline_ms: 1,
    };
    let first = receive_page(&keys, &request, 1000, |_, filter| Ok(query(&events, filter)))
        .unwrap();
    assert!(!first.exhausted);
    request.cursor = first.next_cursor;
    let fresh = event(&key, recipient, 1001, "new inbound during backfill");
    let fresh_id = fresh.event().id;
    events.push(fresh);
    let tail = receive_page(&keys, &request, 1001, |_, filter| Ok(query(&events, filter)))
        .unwrap();
    assert!(tail.envelopes.iter().any(|e| e.id == fresh_id));
    // The fresh query does not abandon the durable, frozen history position.
    request.cursor = tail.next_cursor;
    let mut until = None;
    receive_page(&keys, &request, 1002, |_, filter| {
        until = filter.until_seconds;
        Ok(query(&events, filter))
    })
    .unwrap();
    assert_eq!(until, Some(584));
}
