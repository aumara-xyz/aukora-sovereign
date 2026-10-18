// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner sends authorize and record under Aura; relay I/O owns no ledger lock.
use crate::{fixed, refuse, state_number, state_text, Messaging, OutboxId};
use canon::{authority::AuthorityTxn, digest::Digest32, json::Value, Result};
use nostr::{PublicKey, Transport, TransportEnvelope, TransportKind, TransportReceipt};
use rusqlite::params;

/// An exact committed envelope, authorized immediately before submission.
pub struct PreparedOwnerSend {
    id: OutboxId,
    envelope: TransportEnvelope,
    published: bool,
}
impl PreparedOwnerSend {
    /// This method needs neither an Aura transaction nor the messaging store.
    pub fn submit<T: Transport + ?Sized>(
        &self,
        transport: &mut T,
        deadline_ms: u64,
    ) -> Result<TransportReceipt> {
        if deadline_ms == 0 || transport.kind() != TransportKind::NostrRelays {
            return Err(refuse("transport-unavailable"));
        }
        let receipt = if self.published {
            TransportReceipt {
                envelope_id: self.envelope.id,
                transport: TransportKind::NostrRelays,
                status: nostr::transport::SubmissionStatus::Accepted,
            }
        } else {
            transport
                .send(&self.envelope, deadline_ms)
                .map_err(|_| refuse("submission-unconfirmed"))?
        };
        if receipt.envelope_id != self.envelope.id || receipt.transport != transport.kind() {
            return Err(refuse("receipt-mismatch"));
        }
        Ok(receipt)
    }
}

impl Messaging {
    pub fn prepare_owner_send<A: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut A,
        id: OutboxId,
    ) -> Result<PreparedOwnerSend> {
        let prepared = self.authorized_owner_send(txn, id)?;
        if !prepared.published {
            self.db
                .execute(
                    "UPDATE messaging_messages SET state=2 WHERE id=?1",
                    [id.0.as_bytes().as_slice()],
                )
                .map_err(|_| refuse("store-write"))?;
        }
        Ok(prepared)
    }

    fn authorized_owner_send<A: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut A,
        id: OutboxId,
    ) -> Result<PreparedOwnerSend> {
        let (prepared, body, state) = self.committed_owner_send(txn, id)?;
        let Some(contact) = self.current_contact(txn, prepared.envelope.recipient)? else {
            self.fail_contact_send(id, "contact-removed")?;
            return Err(refuse("contact-removed"));
        };
        let context = txn.observation_context()?;
        if contact.authority().epoch != context.authority.epoch
            || contact.authorization_receipt().to_string() != state_text(&body, "contact_receipt")?
        {
            self.fail_contact_send(id, "contact-changed")?;
            return Err(refuse("contact-changed"));
        }
        if state == 3 {
            return Err(refuse("transport-rejected"));
        }
        Ok(prepared)
    }

    fn committed_owner_send<A: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut A,
        id: OutboxId,
    ) -> Result<(PreparedOwnerSend, Value, i64)> {
        let (contact, bytes, body, state, sequence): (Vec<u8>, Vec<u8>, Vec<u8>, i64, Option<i64>) =
            self.db
                .query_row(
                    "SELECT contact,envelope,audit_body,state,aura_sequence FROM messaging_messages
             WHERE id=?1 AND direction='outgoing'",
                    [id.0.as_bytes().as_slice()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .map_err(|_| refuse("outbox-missing"))?;
        let body = canon::json::parse_strict(&body)?;
        let fact = txn
            .committed_observation_state("messaging.message", &id.0.to_string())?
            .ok_or(refuse("committed-send-required"))?;
        if sequence.is_none()
            || fact.get("body") != Some(&body)
            || Some(state_number(&fact, "sequence")? as i64) != sequence
        {
            return Err(refuse("committed-send-required"));
        }
        let contact_key = PublicKey::from_bytes(fixed(contact)?)?;
        let envelope = TransportEnvelope {
            v: nostr::transport::TRANSPORT_VERSION,
            codec: nostr::transport::EnvelopeCodec::Nip59V1,
            recipient: contact_key,
            id: nostr::EventId::from_bytes(
                *Digest32::from_hex(state_text(&body, "envelope_id")?)?.as_bytes(),
            ),
            bytes,
        };
        envelope.validate()?;
        Ok((
            PreparedOwnerSend {
                id,
                envelope,
                published: state == 1,
            },
            body,
            state,
        ))
    }

    /// An accepted receipt describes relay I/O that already happened. Contact
    /// changes prevent further submissions without erasing that receipt.
    pub fn record_owner_send<A: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut A,
        prepared: &PreparedOwnerSend,
        receipt: &TransportReceipt,
    ) -> Result<()> {
        use nostr::transport::SubmissionStatus;
        let current = if receipt.status == SubmissionStatus::Accepted {
            self.committed_owner_send(txn, prepared.id)?.0
        } else {
            self.authorized_owner_send(txn, prepared.id)?
        };
        if current.envelope != prepared.envelope
            || receipt.envelope_id != prepared.envelope.id
            || receipt.transport != TransportKind::NostrRelays
        {
            return Err(refuse("receipt-mismatch"));
        }
        let state = match receipt.status {
            SubmissionStatus::Accepted => 1,
            SubmissionStatus::Unknown => 2,
            SubmissionStatus::Rejected => 3,
        };
        let transaction = self
            .db
            .unchecked_transaction()
            .map_err(|_| refuse("store-write"))?;
        transaction
            .execute(
                "UPDATE messaging_messages SET state=?2 WHERE id=?1",
                params![prepared.id.0.as_bytes().as_slice(), state],
            )
            .map_err(|_| refuse("store-write"))?;
        if receipt.status == SubmissionStatus::Accepted {
            transaction
                .execute(
                    "DELETE FROM messaging_send_failure WHERE id=?1",
                    [prepared.id.0.as_bytes().as_slice()],
                )
                .map_err(|_| refuse("store-write"))?;
        }
        transaction.commit().map_err(|_| refuse("store-write"))
    }
}
