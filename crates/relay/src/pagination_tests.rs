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
fn a_saturated_second_is_stepped_past_without_starving_another_relay() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let flooded: Vec<_> = (0..300)
        .map(|n| event(&key, recipient, 80, &n.to_string()))
        .collect();
    let other = vec![event(&key, recipient, 60, "other")];
    // One older wrap on the flooded relay, below the crowded second.
    let mut flooded = flooded;
    let older = event(&key, recipient, 50, "older");
    let older_id = older.event().id;
    flooded.push(older);
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
    let mut delivered = BTreeSet::new();
    for _ in 0..24 {
        let batch = receive_page(&keys, &request, 100, |index, filter| {
            Ok(query(if index == 0 { &flooded } else { &other }, filter))
        })
        .unwrap();
        seen_other |= batch.envelopes.iter().any(|e| e.id == other[0].event().id);
        delivered.extend(batch.envelopes.iter().map(|e| e.id));
        request.cursor = batch.next_cursor;
    }
    assert!(seen_other);
    assert!(delivered.contains(&older_id), "history below the crowded second is reached");
    let crowded = flooded.iter().filter(|e| e.event().created_at == 80 && delivered.contains(&e.event().id)).count();
    assert!(crowded >= 128, "the full page of that second was delivered ({crowded})");
    let cursor: serde_json::Value = serde_json::from_str(request.cursor.as_ref().unwrap()).unwrap();
    let position = cursor[2]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p[0] == keys[0])
        .unwrap();
    // A full 128-item second cannot be paged further (NIP-01 has no offset): its 128 were delivered, and history
    // continues below it rather than freezing there.
    assert!(position[2].as_u64().unwrap() < 80 || position[6] == true, "{position}");
    assert_eq!(position[4], false);
}

#[test]
fn failed_query_reports_health_and_cannot_pin_polling_to_an_unresponsive_relay() {
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
        assert_eq!(
            batch.deferred,
            if poll % 2 == 0 {
                Some(canon::Refusal {
                    organ: "relay",
                    reason: "operation-timeout",
                })
            } else {
                None
            }
        );
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
    let first = receive_page(&keys, &request, 1000, |_, filter| {
        Ok(query(&events, filter))
    })
    .unwrap();
    assert!(!first.exhausted);
    request.cursor = first.next_cursor;
    let fresh = event(&key, recipient, 1001, "new inbound during backfill");
    let fresh_id = fresh.event().id;
    events.push(fresh);
    let tail = receive_page(&keys, &request, 1001, |_, filter| {
        Ok(query(&events, filter))
    })
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

#[test]
fn large_timestamp_tie_drains_in_byte_bounded_batches_and_keeps_receiving() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let mut events: Vec<_> = (0..20)
        .map(|n| event(&key, recipient, 80, &format!("{n}:{}", "x".repeat(60_000))))
        .collect();
    let expected: BTreeSet<_> = events.iter().map(|e| e.event().id).collect();
    let keys = [relay_key("wss://relay.example")];
    let mut request = ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 128,
        max_bytes: 1_048_576,
        deadline_ms: 1,
    };
    let mut seen = BTreeSet::new();
    let mut finished = false;
    for poll in 0..12 {
        let batch = receive_page(&keys, &request, 100 + poll, |_, filter| {
            Ok(query(&events, filter))
        })
        .unwrap();
        assert!(batch.envelopes.iter().map(|e| e.bytes.len()).sum::<usize>() <= 1_048_576);
        seen.extend(batch.envelopes.iter().map(|e| e.id));
        request.cursor = batch.next_cursor;
        if batch.exhausted {
            finished = true;
            break;
        }
    }
    assert!(finished, "a tie exceeding one delivery budget must drain");
    assert!(expected.is_subset(&seen));
    let fresh = event(&key, recipient, 200, "after the large tie");
    let fresh_id = fresh.event().id;
    events.push(fresh);
    let batch = receive_page(&keys, &request, 200, |_, filter| Ok(query(&events, filter))).unwrap();
    assert!(batch.envelopes.iter().any(|e| e.id == fresh_id));
}

// An outside review of the earlier client (one receive cycle refused as a whole when any relay held 129 or more
// matching wraps, or sent more than 500 frames) asked for this exact shape: two relays, one flooded. Each poll queries
// one relay; a flooded relay's refusal is deferred and rotated past, never a refusal of the clean relay's batch, and
// the flooded relay's history cursor does not move past what it never delivered.
#[test]
fn a_flooded_relay_never_refuses_the_clean_relays_batch() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let clean = vec![event(&key, recipient, 90, "clean relay")];
    let flood: Vec<_> = (0..200)
        .map(|n| event(&key, recipient, 80, &n.to_string()))
        .collect();
    let keys = [
        relay_key("wss://flooded.example"),
        relay_key("wss://clean.example"),
    ];
    for failure in ["query-event-limit", "query-page-invalid", "saturated"] {
        let mut request = ReceiveRequest {
            recipient,
            cursor: None,
            max_items: 128,
            max_bytes: 1_048_576,
            deadline_ms: 1,
        };
        let mut clean_seen = 0;
        // Enough polls for the saturated relay to sit on a full 128-item tie (16, 32, 64, 128).
        for poll in 0..24 {
            let batch = receive_page(&keys, &request, 100, |index, filter| {
                if index == 1 {
                    return Ok(query(&clean, filter));
                }
                match failure {
                    // More than MAX_QUERY_EVENTS frames: the client refuses that relay's query.
                    "query-event-limit" => Err(canon::Refusal {
                        organ: "relay",
                        reason: "query-event-limit",
                    }),
                    // All 200 wraps, beyond the requested limit: the page cannot move any cursor.
                    "query-page-invalid" => Ok(flood.clone()),
                    // 200 wraps in one second, answered within each requested limit.
                    _ => Ok(query(&flood, filter)),
                }
            })
            .unwrap();
            let flooded_turn = poll % 2 == 0;
            if failure != "saturated" {
                let expected = flooded_turn.then_some(canon::Refusal {
                    organ: "relay",
                    reason: failure,
                });
                assert_eq!(batch.deferred, expected, "{failure} poll {poll}");
            }
            clean_seen += batch
                .envelopes
                .iter()
                .filter(|e| e.id == clean[0].event().id)
                .count();
            request.cursor = batch.next_cursor;
        }
        assert!(clean_seen > 0, "{failure}: the clean relay's wrap is admitted");
        let cursor: serde_json::Value =
            serde_json::from_str(request.cursor.as_ref().unwrap()).unwrap();
        let flooded = cursor[2]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p[0] == keys[0])
            .unwrap();
        if failure == "saturated" {
            // After a full 128-item page at that second, the walk steps past it instead of freezing there.
            assert!(flooded[2].as_u64().unwrap() < 80, "{flooded}");
            assert_eq!(flooded[4], false);
        } else {
            assert_eq!(flooded[2], 100, "{failure}: the history cursor stays at its start");
        }
    }
}

// One event anyone can publish (the victim's p tag plus a second one: the relay filter matches it, the transport
// envelope refuses it) must not refuse the page it is in, or the same page would be replayed on every poll.
#[test]
fn an_uncarriable_wrap_is_skipped_instead_of_refusing_its_page() {
    let key = SecretKey::generate().unwrap();
    let recipient = SecretKey::generate().unwrap().public_key().unwrap();
    let hex = |k: nostr::PublicKey| k.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
    let other = SecretKey::generate().unwrap().public_key().unwrap();
    let poison = Event::sign(
        &key,
        95,
        nostr::nip59::GIFT_WRAP_KIND,
        vec![vec!["p".into(), hex(recipient)], vec!["p".into(), hex(other)]],
        "two recipients".into(),
    )
    .unwrap();
    let good = event(&key, recipient, 90, "carried");
    let poison_id = poison.event().id;
    let stored = vec![poison, good.clone()];
    let keys = [relay_key("wss://relay.example")];
    let mut request = ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 128,
        max_bytes: 1_048_576,
        deadline_ms: 1,
    };
    let mut delivered = Vec::new();
    for _ in 0..4 {
        let batch = receive_page(&keys, &request, 100, |_, filter| Ok(query(&stored, filter))).unwrap();
        assert_eq!(batch.deferred, None);
        delivered.extend(batch.envelopes.iter().map(|e| e.id));
        request.cursor = batch.next_cursor;
    }
    assert!(delivered.contains(&good.event().id), "the carriable wrap behind it is delivered");
    assert!(!delivered.contains(&poison_id), "the two-recipient wrap itself is not delivered");
}

// NIP-01 does not fix which 128 of a crowded second a relay returns. A page split by the delivery budget leaves a
// resume marker; if the replay returns another subset that lies wholly at or before that marker, nothing was
// consumed, and stepping past the second then would lose the rest of the first page. The marker is kept instead.
#[test]
fn a_replay_that_consumes_nothing_keeps_its_resume_marker() {
    let key = SecretKey::generate().unwrap();
    let recipient = key.public_key().unwrap();
    let mut crowd: Vec<_> = (0..200)
        .map(|n| event(&key, recipient, 80, &format!("{n:03}")))
        .collect();
    crowd.sort_by_key(|e| e.event().id);
    let high: Vec<_> = crowd[72..].to_vec(); // the 128 highest ids
    let low: Vec<_> = crowd[..128].to_vec(); // the 128 lowest ids
    let size = |e: &VerifiedEvent| e.event().encode().unwrap().len() as u32;
    // The budget delivers the first 60 of the high subset (overall rank 132, above every id in the low subset).
    let budget: u32 = high[..60].iter().map(size).sum();
    let relay = relay_key("wss://relay.example");
    let position = serde_json::json!([relay, 0, 80, 100, true, 128, false, 0, false, null]);
    let mut request = ReceiveRequest {
        recipient,
        cursor: Some(serde_json::json!([1, 0, [position]]).to_string()),
        max_items: 128,
        max_bytes: budget,
        deadline_ms: 1,
    };
    let keys = [relay];
    let mut delivered = BTreeSet::new();
    for call in 0..8 {
        let batch = receive_page(&keys, &request, 100, |_, _| {
            Ok(if call == 2 { low.clone() } else { high.clone() })
        })
        .unwrap();
        delivered.extend(batch.envelopes.iter().map(|e| e.id));
        request.cursor = batch.next_cursor;
    }
    let missing = high.iter().filter(|e| !delivered.contains(&e.event().id)).count();
    assert_eq!(missing, 0, "every wrap of the first page is delivered");
}
