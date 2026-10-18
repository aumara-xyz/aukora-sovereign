// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-session network actions and scoped reads share supervisor-owned stores.
use super::{
    network::{Direction, Message, NetworkRead, Page, SendState},
    refuse, wire,
};
use crate::{
    adapters::{messaging::NetworkTxn, GateAdapter, HostLedger},
    nostr_identity::NodeIdentity,
};
use canon::{authority::AuthorityTxn, json::Value, Result};
use std::sync::{Arc, Mutex};
use supervisor::ingress::{BindingState, PrincipalScope};

pub struct LiveNetwork {
    ledger: Arc<HostLedger>,
    store: Mutex<messaging::Messaging>,
    identity: Arc<NodeIdentity>,
    gate: Arc<GateAdapter>,
}
impl LiveNetwork {
    pub fn new(
        ledger: Arc<HostLedger>,
        store: messaging::Messaging,
        identity: Arc<NodeIdentity>,
        gate: Arc<GateAdapter>,
    ) -> Self {
        Self {
            ledger,
            store: Mutex::new(store),
            identity,
            gate,
        }
    }

    /// One bounded transport cycle. The worker supplies policy-pinned transport
    /// and one absolute monotonic deadline; engine services never receive this handle.
    pub fn poll(
        &self,
        transport: &mut dyn nostr::Transport,
        now_seconds: u64,
        deadline_ms: u64,
    ) -> Result<()> {
        let BindingState::Bound(scope) = self.ledger.binding()? else {
            return Ok(());
        };
        let now_ms = now_seconds
            .checked_mul(1000)
            .ok_or(refuse("network-clock-invalid"))?;
        // Recovery gets a fresh Aura transaction for each observation commit.
        for _ in 0..messaging::MAX_PAGE_ITEMS {
            let recovered = self.ledger.messaging(scope, false, |txn| {
                self.store
                    .lock()
                    .map_err(|_| refuse("network-store-unavailable"))?
                    .recover_message(txn)
            })?;
            if !recovered {
                break;
            }
        }
        self.ledger.messaging(scope, false, |txn| {
            self.store
                .lock()
                .map_err(|_| refuse("network-store-unavailable"))?
                .recover_refusal(txn)
                .map(|_| ())
        })?;
        self.ledger.messaging(scope, false, |txn| {
            let mut store = self
                .store
                .lock()
                .map_err(|_| refuse("network-store-unavailable"))?;
            synchronize_contacts(&mut store, txn)
        })?;
        // Publish queued owner actions before a potentially slow relay query.
        let pending = self
            .store
            .lock()
            .map_err(|_| refuse("network-store-unavailable"))?
            .pending_owner_sends(20)?;
        for id in pending {
            self.ledger.messaging(scope, false, |txn| {
                self.store
                    .lock()
                    .map_err(|_| refuse("network-store-unavailable"))?
                    .transmit_owner(txn, transport, id, deadline_ms)
            })?;
        }
        let batch = transport.receive(&nostr::transport::ReceiveRequest {
            recipient: self.identity.public_key(),
            cursor: None,
            max_items: nostr::transport::MAX_BATCH_ITEMS,
            max_bytes: 1_048_576,
            deadline_ms,
        })?;
        if batch.envelopes.len() > usize::from(nostr::transport::MAX_BATCH_ITEMS) {
            return Err(refuse("network-batch-invalid"));
        }
        for envelope in batch.envelopes {
            self.ledger.messaging(scope, false, |txn| {
                let mut store = self
                    .store
                    .lock()
                    .map_err(|_| refuse("network-store-unavailable"))?;
                // A relay query repeats stored wraps. This is an already admitted
                // snapshot item, rather than another incoming delivery attempt.
                if store.seen_envelope(envelope.id)? {
                    return Ok(());
                }
                store
                    .receive(
                        txn,
                        &envelope,
                        self.identity.key(),
                        nostr::TransportKind::NostrRelays,
                        now_ms,
                    )
                    .map(|_| ())
            })?;
        }
        Ok(())
    }
}

impl NetworkRead for LiveNetwork {
    fn node_npub(&self) -> Result<Option<String>> {
        Ok(Some(self.identity.npub().to_owned()))
    }
    fn contacts(
        &self,
        scope: PrincipalScope,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Page<messaging::ApprovedContact>> {
        let after = before.map(nostr::PublicKey::from_npub).transpose()?;
        self.ledger.messaging(scope, false, |txn| {
            let mut store = self
                .store
                .lock()
                .map_err(|_| refuse("network-store-unavailable"))?;
            synchronize_contacts(&mut store, txn)?;
            let items = store.contacts(after, limit)?;
            let next = if items.len() == limit {
                items
                    .last()
                    .map(|item| item.key().to_npub().map(|npub| npub.as_str().to_owned()))
                    .transpose()?
            } else {
                None
            };
            Ok(Page { items, next })
        })
    }

    fn messages(
        &self,
        scope: PrincipalScope,
        contact: Option<nostr::PublicKey>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Page<Message>> {
        let after = before
            .map(|cursor| {
                let number = cursor
                    .parse::<u64>()
                    .map_err(|_| refuse("face-page-invalid"))?;
                if number == 0 || number.to_string() != cursor {
                    return Err(refuse("face-page-invalid"));
                }
                Ok(number)
            })
            .transpose()?;
        self.ledger.messaging(scope, false, |txn| {
            let store = self
                .store
                .lock()
                .map_err(|_| refuse("network-store-unavailable"))?;
            let mut bytes = 0;
            let mut cursor = after;
            let mut items = Vec::with_capacity(limit);
            let mut more = false;
            'pages: loop {
                let rows = store.messages(contact, cursor, messaging::MAX_PAGE_ITEMS)?;
                let full = rows.len() == messaging::MAX_PAGE_ITEMS;
                for row in rows {
                    // Skip another epoch's local rows while advancing the cursor.
                    if txn
                        .committed_observation_state("messaging.message", &row.id.to_string())?
                        .is_none()
                    {
                        cursor = Some(row.cursor);
                        continue;
                    }
                    let next_cursor = row.cursor;
                    let item = Message {
                        id: row.id.to_string(),
                        direction: match row.direction {
                            messaging::MessageDirection::Incoming => Direction::In,
                            messaging::MessageDirection::Outgoing => Direction::Out,
                        },
                        contact: row.contact,
                        at: row.created_at_ms,
                        text: row.text,
                        state: match row.state {
                            messaging::MessageState::Received => None,
                            messaging::MessageState::Queued => Some(SendState::Queued),
                            messaging::MessageState::Published => Some(SendState::Published),
                            messaging::MessageState::Unconfirmed => Some(SendState::Unconfirmed),
                            messaging::MessageState::Failed => {
                                Some(SendState::Failed(canon::Refusal {
                                    organ: "messaging",
                                    reason: "transport-rejected",
                                }))
                            }
                        },
                    };
                    let encoded = super::network::message(&item)?.canonical_bytes().len();
                    if encoded > 58_000 {
                        return Err(refuse("face-message-too-large"));
                    }
                    if items.len() == limit || bytes + encoded > 58_000 {
                        more = true;
                        break 'pages;
                    }
                    cursor = Some(next_cursor);
                    bytes += encoded;
                    items.push(item);
                }
                if !full {
                    break;
                }
            }
            let next = if more {
                cursor.map(|cursor| cursor.to_string())
            } else {
                None
            };
            Ok(Page { items, next })
        })
    }

    fn refusals(&self, scope: PrincipalScope) -> Result<messaging::RefusalCounts> {
        self.ledger.scoped(scope, |txn| {
            self.store
                .lock()
                .map_err(|_| refuse("network-store-unavailable"))?
                .refresh_refusal_counts(txn)
        })
    }

    fn propose_contact(
        &self,
        scope: PrincipalScope,
        npub: &str,
        label: Option<&str>,
    ) -> Result<Value> {
        let key = nostr::PublicKey::from_npub(npub)?;
        if key == self.identity.public_key() {
            return Err(refuse("contact-is-self"));
        }
        let label = label
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{}…{}", &npub[..12], &npub[npub.len() - 8..]));
        let action = messaging::OwnerAction::Contact(messaging::ContactChange::Add(
            messaging::ContactDraft {
                key,
                label,
                pairing: None,
            },
        ));
        let bytes = action.canonical_bytes()?;
        let id = tokio::runtime::Handle::try_current()
            .map_err(|_| refuse("face-runtime-unavailable"))?
            .block_on(self.gate.propose_owner_requested(
                scope,
                messaging::CONTACT_TARGET,
                String::new(),
                bytes,
            ))?;
        wire::object([
            ("proposal_id", wire::text(id.to_string())?),
            ("state", wire::text("pending")?),
        ])
    }

    fn send(&self, scope: PrincipalScope, npub: &str, text: &str) -> Result<Value> {
        let recipient = nostr::PublicKey::from_npub(npub)?;
        let now_ms = u64::try_from(self.ledger.clock.now_ms()?)
            .map_err(|_| refuse("network-clock-invalid"))?;
        let draft = messaging::SendDraft {
            recipient,
            text: text.to_owned(),
            disclosures: Vec::new(),
        };
        let id = self.ledger.messaging(scope, true, |txn| {
            self.store
                .lock()
                .map_err(|_| refuse("network-store-unavailable"))?
                .queue_owner_send(txn, &draft, self.identity.key(), now_ms)
        })?;
        wire::object([
            ("id", wire::text(id.0.to_string())?),
            ("state", wire::text("queued")?),
        ])
    }
}

fn synchronize_contacts(
    store: &mut messaging::Messaging,
    txn: &mut NetworkTxn<'_, '_>,
) -> Result<()> {
    let mut keys = txn.contact_keys()?;
    let mut after = None;
    loop {
        let rows = store.contacts(after, messaging::MAX_PAGE_ITEMS)?;
        keys.extend(rows.iter().map(messaging::ApprovedContact::key));
        if rows.len() < messaging::MAX_PAGE_ITEMS {
            break;
        }
        after = rows.last().map(messaging::ApprovedContact::key);
    }
    keys.sort();
    keys.dedup();
    for key in keys {
        store.synchronize_contact(txn, key)?;
    }
    Ok(())
}
