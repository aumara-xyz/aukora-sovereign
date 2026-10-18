// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable, bounded relay history traversal with inclusive timestamp boundaries.
use crate::{client::transport_deadline, Client, Filter};
use nostr::{
    ReceiveBatch, ReceiveRequest, SubmissionStatus, Transport, TransportEnvelope, TransportKind,
    TransportReceipt, VerifiedEvent,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

const PAGE_ITEMS: u16 = 16;
const MAX_SECONDS: u64 = 9_007_199_254_740_991;

/// Bounded gift-wrap submission and paged queries over validated relays.
pub struct RelayTransport {
    clients: Vec<Client>,
}
impl RelayTransport {
    /// Retain a nonempty, bounded set of independently validated clients.
    pub fn new(clients: Vec<Client>) -> crate::Result<Self> {
        let mut urls = BTreeSet::new();
        if clients.is_empty()
            || clients.len() > crate::egress::MAX_RELAYS
            || clients
                .iter()
                .any(|c| !c.connected() || !urls.insert(c.relay_url()))
        {
            return Err(refusal("relay-set"));
        }
        Ok(Self { clients })
    }
}
impl Transport for RelayTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::NostrRelays
    }
    fn send(
        &mut self,
        envelope: &TransportEnvelope,
        deadline_ms: u64,
    ) -> canon::Result<TransportReceipt> {
        let deadline = transport_deadline(deadline_ms)?;
        envelope.validate()?;
        let event = nostr::Event::decode(&envelope.bytes)?.verify()?;
        deadline.remaining()?;
        let mut status = SubmissionStatus::Rejected;
        for client in &mut self.clients {
            if deadline.remaining().is_err() {
                if status != SubmissionStatus::Accepted {
                    status = SubmissionStatus::Unknown;
                }
                break;
            }
            match client.publish_until(&event, None, 0, deadline) {
                Ok(ack) if ack.status == SubmissionStatus::Accepted => {
                    status = SubmissionStatus::Accepted
                }
                Ok(ack) if ack.status == SubmissionStatus::Rejected => {}
                _ if status != SubmissionStatus::Accepted => status = SubmissionStatus::Unknown,
                _ => {}
            }
        }
        Ok(TransportReceipt {
            envelope_id: envelope.id,
            transport: self.kind(),
            status,
        })
    }
    fn receive(&mut self, request: &ReceiveRequest) -> canon::Result<ReceiveBatch> {
        let deadline = transport_deadline(request.deadline_ms)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refusal("clock-invalid"))?
            .as_secs();
        let keys: Vec<_> = self
            .clients
            .iter()
            .map(|c| relay_key(c.relay_url()))
            .collect();
        receive_page(&keys, request, now, |index, filter| {
            deadline.remaining()?;
            let result = self.clients[index].query_until(&[filter.clone()], None, 0, deadline)?;
            if !result.end_of_stored_events {
                return Err(refusal("query-incomplete"));
            }
            deadline.remaining()?;
            Ok(result.events)
        })
    }
}

pub(crate) fn relay_key(url: &str) -> String {
    canon::digest::Digest32::sha256(url.as_bytes()).to_string()
}

// Compact JSON arrays keep all sixteen relay cursors below the transport bound.
#[derive(Clone)]
struct Position {
    key: String,
    since: u64,
    until: u64,
    head: u64,
    tie: bool,
    limit: u16,
    done: bool,
    recent_sweeps: u8,
    next_tail: bool,
    resume: Option<(u64, String)>,
}
impl Position {
    fn new(key: String, now: u64) -> Self {
        Self {
            key,
            since: 0,
            until: now,
            head: now,
            tie: false,
            limit: PAGE_ITEMS,
            done: false,
            recent_sweeps: 0,
            next_tail: false,
            resume: None,
        }
    }
    fn encode(&self) -> Value {
        json!([
            self.key,
            self.since,
            self.until,
            self.head,
            self.tie,
            self.limit,
            self.done,
            self.recent_sweeps,
            self.next_tail,
            self.resume
        ])
    }
    fn decode(v: &Value) -> canon::Result<Self> {
        let a = v
            .as_array()
            .filter(|a| (8..=10).contains(&a.len()))
            .ok_or(refusal("cursor-invalid"))?;
        let key = a[0]
            .as_str()
            .filter(|s| valid_hex(s, 64) && s.len() == 64)
            .ok_or(refusal("cursor-invalid"))?
            .to_owned();
        let number = |i: usize| {
            a[i].as_u64()
                .filter(|n| *n <= MAX_SECONDS)
                .ok_or(refusal("cursor-invalid"))
        };
        let p = Self {
            key,
            since: number(1)?,
            until: number(2)?,
            head: number(3)?,
            tie: a[4].as_bool().ok_or(refusal("cursor-invalid"))?,
            limit: a[5]
                .as_u64()
                .filter(|n| {
                    *n >= u64::from(PAGE_ITEMS)
                        && *n <= u64::from(nostr::transport::MAX_BATCH_ITEMS)
                })
                .ok_or(refusal("cursor-invalid"))? as u16,
            done: a[6].as_bool().ok_or(refusal("cursor-invalid"))?,
            recent_sweeps: a[7]
                .as_u64()
                .filter(|n| *n < 4)
                .ok_or(refusal("cursor-invalid"))? as u8,
            next_tail: match a.get(8) {
                Some(v) => v.as_bool().ok_or(refusal("cursor-invalid"))?,
                None => false,
            },
            resume: serde_json::from_value(a.get(9).cloned().unwrap_or(Value::Null))
                .map_err(|_| refusal("cursor-invalid"))?,
        };
        if p.until > p.head
            || (!p.done && p.since > p.until)
            || p.resume.as_ref().is_some_and(|(time, id)| {
                *time > p.until || *time < p.since || id.len() != 64 || !valid_hex(id, 64)
            })
        {
            return Err(refusal("cursor-invalid"));
        }
        Ok(p)
    }
    fn complete(&mut self) {
        self.done = true;
        self.tie = false;
        self.limit = PAGE_ITEMS;
    }
    fn finish_tie(&mut self) {
        self.tie = false;
        self.limit = PAGE_ITEMS;
        if self.until <= self.since {
            self.complete();
        } else {
            self.until -= 1;
        }
    }
}
fn valid_hex(s: &str, max: usize) -> bool {
    s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One query per poll, rotating relays even when one has an unending backlog.
/// `query` is also the in-process fake-relay seam used by regression tests.
pub(crate) fn receive_page(
    keys: &[String],
    request: &ReceiveRequest,
    now: u64,
    mut query: impl FnMut(usize, &Filter) -> canon::Result<Vec<VerifiedEvent>>,
) -> canon::Result<ReceiveBatch> {
    if keys.is_empty()
        || keys.len() > crate::egress::MAX_RELAYS
        || now > MAX_SECONDS
        || request.max_items == 0
        || request.max_items > nostr::transport::MAX_BATCH_ITEMS
        || request.max_bytes == 0
        || request.max_bytes > nostr::transport::MAX_BATCH_BYTES
    {
        return Err(refusal("batch-limit"));
    }
    let (mut index, saved) = if let Some(cursor) = &request.cursor {
        if cursor.len() > nostr::transport::MAX_CURSOR_BYTES {
            return Err(refusal("cursor-invalid"));
        }
        let value: Value = serde_json::from_str(cursor).map_err(|_| refusal("cursor-invalid"))?;
        let a = value
            .as_array()
            .filter(|a| a.len() == 3 && a[0] == 1)
            .ok_or(refusal("cursor-invalid"))?;
        let index = a[1]
            .as_u64()
            .filter(|i| *i < crate::egress::MAX_RELAYS as u64)
            .ok_or(refusal("cursor-invalid"))? as usize;
        let saved = a[2]
            .as_array()
            .filter(|a| a.len() <= crate::egress::MAX_RELAYS)
            .ok_or(refusal("cursor-invalid"))?
            .iter()
            .map(Position::decode)
            .collect::<canon::Result<Vec<_>>>()?;
        (index, saved)
    } else {
        (0, Vec::new())
    };
    index %= keys.len();
    // Retain positions for temporarily unavailable relays too. Only a changed
    // policy that exceeds the relay-set bound can retire an old relay cursor.
    let mut positions = saved;
    for key in keys {
        if !positions.iter().any(|p| &p.key == key) {
            if positions.len() == crate::egress::MAX_RELAYS {
                let old = positions
                    .iter()
                    .position(|p| !keys.contains(&p.key))
                    .ok_or(refusal("cursor-invalid"))?;
                positions.remove(old);
            }
            positions.push(Position::new(key.clone(), now));
        }
    }
    let p = positions
        .iter_mut()
        .find(|p| p.key == keys[index])
        .ok_or(refusal("cursor-invalid"))?;
    let tail = p.next_tail;
    p.next_tail = !tail;
    if p.done && !tail {
        // Gift-wrap creation time is randomized up to two days into the past.
        // Overlap by that whole interval; never trust an event's time as a head.
        // Queued envelopes retain their original time even after a long sender
        // outage. Periodically rescan all history, with the same per-poll budget.
        p.since = if p.recent_sweeps == 3 {
            p.recent_sweeps = 0;
            0
        } else {
            p.recent_sweeps += 1;
            p.head
                .saturating_sub(nostr::nip59::TIMESTAMP_JITTER_SECONDS)
        };
        p.head = now.max(p.head);
        p.until = p.head;
        p.done = false;
    }
    let limit = if tail {
        PAGE_ITEMS
            .min(request.max_items)
            .min((request.max_bytes as usize / nostr::transport::MAX_ENVELOPE_BYTES).max(1) as u16)
    } else {
        p.limit
    };
    let filter = Filter {
        kinds: vec![nostr::nip59::GIFT_WRAP_KIND],
        recipients: vec![request.recipient],
        since_seconds: Some(if tail {
            now.saturating_sub(nostr::nip59::TIMESTAMP_JITTER_SECONDS)
        } else if p.tie {
            p.until
        } else {
            p.since
        }),
        until_seconds: Some(if tail { now } else { p.until }),
        limit: Some(limit),
        ..Filter::default()
    };
    let page = (|| {
        let mut events = query(index, &filter)?;
        // A relay exceeding the requested page or returning unrelated events cannot
        // move the durable cursor past unseen data.
        if events.len() > usize::from(limit) || events.iter().any(|e| !filter.matches(e.event())) {
            return Err(refusal("query-page-invalid"));
        }
        let mut seen = BTreeSet::new();
        if events.iter().any(|e| !seen.insert(e.event().id)) {
            return Err(refusal("query-page-invalid"));
        }
        let oldest = events.iter().map(|e| e.event().created_at).min();
        let count = events.len();
        // A relay query has its own event/byte ceilings. Its result can exceed
        // one delivery budget; replay that same bounded query after restart and
        // resume in NIP-01 order rather than discarding an oversized tie forever.
        events.sort_by_key(|e| (std::cmp::Reverse(e.event().created_at), e.event().id));
        let mut envelopes = Vec::new();
        let mut bytes = 0;
        let mut resume = None;
        let mut more = false;
        for verified in events {
            let event = verified.event();
            let marker = (event.created_at, event.id.digest().to_string());
            if !tail
                && p.resume.as_ref().is_some_and(|(time, id)| {
                    (std::cmp::Reverse(marker.0), &marker.1) <= (std::cmp::Reverse(*time), id)
                })
            {
                continue;
            }
            // A wrap this node cannot carry (say, a second `p` tag, which the relay filter still matches) is
            // skipped and counted as consumed: refusing the page would replay it on every poll and freeze the
            // relay's history (and its tail) behind one event anyone can publish.
            let Ok(encoded) = event.encode() else {
                resume = Some(marker);
                continue;
            };
            let envelope = TransportEnvelope {
                v: nostr::transport::TRANSPORT_VERSION,
                codec: nostr::EnvelopeCodec::Nip59V1,
                recipient: request.recipient,
                id: event.id,
                bytes: encoded,
            };
            if envelope.validate().is_err() {
                resume = Some(marker);
                continue;
            }
            if envelope.bytes.len() > request.max_bytes as usize {
                return Err(refusal("batch-limit"));
            }
            if bytes + envelope.bytes.len() > request.max_bytes as usize
                || envelopes.len() == usize::from(request.max_items)
            {
                more = true;
                break;
            }
            bytes += envelope.bytes.len();
            envelopes.push(envelope);
            resume = Some(marker);
        }
        Ok((envelopes, oldest, count, more, resume))
    })();
    let (envelopes, oldest, count, more, resume) = match page {
        Ok(page) => page,
        Err(code) => {
            eprintln!(
                "relay: query-deferred {}:{}; history cursor retained",
                code.organ, code.reason
            );
            let mut batch = finish_batch(Vec::new(), &positions, index, keys.len(), false)?;
            batch.deferred = Some(code);
            return Ok(batch);
        }
    };
    // A frozen or saturated history boundary must not also freeze the fresh
    // query's upper bound. Each relay alternates its own tail and history turns.
    if tail {
        return finish_batch(envelopes, &positions, index, keys.len(), false);
    }
    if more {
        p.resume = resume;
        return finish_batch(envelopes, &positions, index, keys.len(), false);
    }
    p.resume = None;
    if count == usize::from(limit) {
        if p.tie {
            if limit == nostr::transport::MAX_BATCH_ITEMS {
                // NIP-01 has inclusive second-resolution time bounds and exact
                // IDs, with no exclusion or offset. Never skip a full boundary:
                // more events can share this second. Other relays still rotate.
                eprintln!("relay: query-timestamp-saturated; history cursor retained");
            } else {
                p.limit = (limit * 2).min(nostr::transport::MAX_BATCH_ITEMS);
            }
        } else {
            p.until = oldest.ok_or(refusal("query-page-invalid"))?;
            p.tie = true;
        }
    } else if p.tie {
        p.finish_tie();
    } else {
        p.complete();
    }
    let exhausted = p.done;
    finish_batch(envelopes, &positions, index, keys.len(), exhausted)
}

fn finish_batch(
    envelopes: Vec<TransportEnvelope>,
    positions: &[Position],
    index: usize,
    relay_count: usize,
    exhausted: bool,
) -> canon::Result<ReceiveBatch> {
    let cursor = json!([
        1,
        (index + 1) % relay_count,
        positions.iter().map(Position::encode).collect::<Vec<_>>()
    ])
    .to_string();
    if cursor.len() > nostr::transport::MAX_CURSOR_BYTES {
        return Err(refusal("cursor-invalid"));
    }
    Ok(ReceiveBatch {
        envelopes,
        next_cursor: Some(cursor),
        exhausted,
        deferred: None,
    })
}
const fn refusal(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "relay",
        reason,
    }
}
