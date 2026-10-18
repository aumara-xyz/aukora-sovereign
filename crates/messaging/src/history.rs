// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable owner-session sends and admitted inbox data, reconciled with Aura.

use crate::{fixed, refuse, state_number, state_text, text, Messaging, OutboxId, SendDraft};
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, FactKind, FactRecord, Kind, Phase},
    digest::Digest32,
    json::{SafeInteger, Value, MAX_SAFE_INTEGER},
    Result,
};
use nostr::{PublicKey, Transport, TransportEnvelope, TransportKind, TransportReceipt};
use rusqlite::{params, Connection, OptionalExtension};

pub const MESSAGE_SCHEMA: &str = "aukora:messaging-event:v1";

/// Implemented only by the supervisor's authenticated shell-session adapter.
/// This is the owner's direct send path, never an engine or guest capability.
pub trait OwnerSessionTxn: AuthorityTxn {
    /// Verify the current signed-in owner shell session and its current epoch.
    /// Engine-origin requests must be rejected before constructing this adapter.
    fn check_owner_session(&mut self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageState {
    Received,
    Queued,
    Published,
    Unconfirmed,
    Failed,
}

/// Private text is returned only by the owner-scoped face reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRecord {
    pub cursor: u64,
    pub id: Digest32,
    pub contact: PublicKey,
    pub direction: MessageDirection,
    pub text: String,
    pub created_at_ms: u64,
    pub observed_at_ms: u64,
    pub state: MessageState,
    pub aura_sequence: u64,
}

impl Messaging {
    /// The supervisor checks the owner session, then reserves this exact message
    /// locally and commits its Aura observation before making it publishable.
    /// Contact approval is still required; no per-message passkey card is opened.
    pub fn queue_owner_send<T: OwnerSessionTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        draft: &SendDraft,
        sender: &nostr::SecretKey,
        now_ms: u64,
    ) -> Result<OutboxId> {
        txn.check_owner_session()?;
        if draft.text.is_empty() || draft.text.len() > crate::MAX_MESSAGE_BYTES {
            return Err(refuse("message-size"));
        }
        // This owner-session surface sends text only. Memory disclosure remains
        // on the separately reviewed API and cannot be smuggled into shell sends.
        if !draft.disclosures.is_empty() {
            return Err(refuse("disclosure-unavailable"));
        }
        number(now_ms)?;
        let contact = self
            .current_contact(txn, draft.recipient)?
            .ok_or(refuse("stranger"))?;
        let context = txn.observation_context()?;
        if contact.authority().epoch != context.authority.epoch
            || contact.authority().sequence >= context.authority.sequence
        {
            return Err(refuse("stale-contact"));
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| refuse("random-unavailable"))?;
        let rumor = nostr::Rumor::new(
            sender.public_key()?,
            now_ms / 1000,
            nostr::nip59::MESSAGE_KIND,
            vec![
                vec!["p".to_owned(), hex::encode(draft.recipient.as_bytes())],
                vec!["nonce".to_owned(), hex::encode(nonce)],
            ],
            draft.text.clone(),
        )?;
        let wrap = nostr::nip59::gift_wrap(&rumor, sender, &draft.recipient, now_ms / 1000)?;
        let envelope = TransportEnvelope {
            v: nostr::transport::TRANSPORT_VERSION,
            codec: nostr::transport::EnvelopeCodec::Nip59V1,
            recipient: draft.recipient,
            id: wrap.event().id,
            bytes: wrap.event().encode()?,
        };
        envelope.validate()?;
        let id = Digest32::from_bytes(*rumor.id.as_bytes());
        stage(
            &self.db,
            id,
            "outgoing",
            draft.recipient,
            &draft.text,
            now_ms,
            now_ms,
            &envelope,
            contact.consumed_card(),
        )?;
        self.audit_message(txn, id)?;
        Ok(OutboxId(id))
    }

    /// Reconcile at most one retained message with its committed signed fact.
    /// Call again with a fresh Aura transaction until false is returned. Retaining
    /// the exact fact body before append closes the two-database crash window.
    pub fn recover_message<T: AuthorityTxn + ?Sized>(&mut self, txn: &mut T) -> Result<bool> {
        let id: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT id FROM messaging_messages WHERE aura_sequence IS NULL ORDER BY cursor LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| refuse("store-read"))?;
        let Some(id) = id else { return Ok(false) };
        self.audit_message(txn, Digest32::from_bytes(fixed(id)?))?;
        Ok(true)
    }

    pub(crate) fn audit_message<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        id: Digest32,
    ) -> Result<()> {
        let bytes: Vec<u8> = self
            .db
            .query_row(
                "SELECT audit_body FROM messaging_messages WHERE id=?1",
                [id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| refuse("store-read"))?;
        let body = canon::json::parse_strict(&bytes)?;
        if state_text(&body, "schema")? != MESSAGE_SCHEMA
            || state_text(&body, "id")? != id.to_string()
        {
            return Err(refuse("message-record"));
        }
        let key = id.to_string();
        let committed = txn.committed_observation_state("messaging.message", &key)?;
        let fact = if let Some(fact) = committed {
            fact
        } else {
            let context = txn.observation_context()?;
            if context.authority.sequence == 0 || context.at < 0 {
                return Err(refuse("message-context"));
            }
            let record = txn.append_fact(FactRecord {
                v: 1,
                algorithm: AlgorithmId::Sha256,
                authority: context.authority,
                at: context.at,
                kind: FactKind::BootFacts,
                actor: "messaging".to_owned(),
                body: body.clone(),
            })?;
            if record.v != 1
                || record.algorithm != AlgorithmId::Sha256
                || record.authority != context.authority
                || record.at != context.at
                || record.kind != Kind::BootFacts
                || record.phase != Phase::Fact
                || record.operation.is_some()
                || record.actor != "messaging"
                || !crate::ingress::refusal_audit::record_body_matches(&record, &body)?
            {
                return Err(refuse("message-record"));
            }
            txn.commit_observations()?;
            txn.committed_observation_state("messaging.message", &key)?
                .ok_or(refuse("message-record"))?
        };
        crate::exact_object(&fact, &["body", "sequence"])?;
        let sequence = state_number(&fact, "sequence")?;
        if fact.get("body") != Some(&body) || sequence == 0 {
            return Err(refuse("message-record"));
        }
        self.db.execute(
            "UPDATE messaging_messages SET aura_sequence=?2 WHERE id=?1 AND (aura_sequence IS NULL OR aura_sequence=?2)",
            params![id.as_bytes().as_slice(), sequence as i64],
        ).map_err(|_| refuse("store-write"))?;
        Ok(())
    }

    /// Sends are publishable only after the exact durable Aura fact reconciles.
    pub fn pending_owner_sends(&self, limit: usize) -> Result<Vec<OutboxId>> {
        page_limit(limit)?;
        let mut stmt = self
            .db
            .prepare(
                "SELECT id FROM messaging_messages WHERE direction='outgoing'
             AND aura_sequence IS NOT NULL AND state IN(0,2) ORDER BY cursor LIMIT ?1",
            )
            .map_err(|_| refuse("store-read"))?;
        let rows = stmt
            .query_map([limit as i64], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| refuse("store-read"))?;
        rows.map(|row| {
            Ok(OutboxId(Digest32::from_bytes(fixed(
                row.map_err(|_| refuse("store-read"))?,
            )?)))
        })
        .collect()
    }

    /// Recheck current approved contact state immediately before network I/O.
    /// A transport retry uses the same signed envelope and id, never fresh text.
    pub fn transmit_owner<A: AuthorityTxn + ?Sized, T: Transport + ?Sized>(
        &mut self,
        txn: &mut A,
        transport: &mut T,
        id: OutboxId,
        deadline_ms: u64,
    ) -> Result<TransportReceipt> {
        if deadline_ms == 0 || transport.kind() != TransportKind::NostrRelays {
            return Err(refuse("transport-unavailable"));
        }
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
        let Some(contact) = self.current_contact(txn, contact_key)? else {
            self.fail_owner_send(id)?;
            return Err(refuse("stranger"));
        };
        let context = txn.observation_context()?;
        if contact.authority().epoch != context.authority.epoch
            || contact.consumed_card().to_string() != state_text(&body, "contact_receipt")?
        {
            self.fail_owner_send(id)?;
            return Err(refuse("stale-contact"));
        }
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
        if state == 3 {
            return Err(refuse("transport-rejected"));
        }
        if state == 1 {
            return Ok(TransportReceipt {
                envelope_id: envelope.id,
                transport: TransportKind::NostrRelays,
                status: nostr::transport::SubmissionStatus::Accepted,
            });
        }
        self.db
            .execute(
                "UPDATE messaging_messages SET state=2 WHERE id=?1",
                [id.0.as_bytes().as_slice()],
            )
            .map_err(|_| refuse("store-write"))?;
        let receipt = transport
            .send(&envelope, deadline_ms)
            .map_err(|_| refuse("submission-unconfirmed"))?;
        if receipt.envelope_id != envelope.id || receipt.transport != transport.kind() {
            return Err(refuse("receipt-mismatch"));
        }
        use nostr::transport::SubmissionStatus;
        let state = match receipt.status {
            SubmissionStatus::Accepted => 1,
            SubmissionStatus::Unknown => 2,
            SubmissionStatus::Rejected => 3,
        };
        self.db
            .execute(
                "UPDATE messaging_messages SET state=?2 WHERE id=?1",
                params![id.0.as_bytes().as_slice(), state],
            )
            .map_err(|_| refuse("store-write"))?;
        Ok(receipt)
    }

    fn fail_owner_send(&self, id: OutboxId) -> Result<()> {
        self.db
            .execute(
                "UPDATE messaging_messages SET state=3 WHERE id=?1 AND state IN(0,2)",
                [id.0.as_bytes().as_slice()],
            )
            .map_err(|_| refuse("store-write"))?;
        Ok(())
    }

    /// Newest local rows first; `before` continues toward older messages.
    /// The stable cursor is scoped to one contact when supplied.
    /// Pending ledger reconciliation is never visible as admitted history.
    pub fn messages(
        &self,
        contact: Option<PublicKey>,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<MessageRecord>> {
        page_limit(limit)?;
        if before.is_some_and(|cursor| cursor > MAX_SAFE_INTEGER as u64) {
            return Err(refuse("page-cursor"));
        }
        let mut stmt = self.db.prepare(
            "SELECT cursor,id,contact,direction,text,created_at_ms,observed_at_ms,state,aura_sequence
             FROM messaging_messages WHERE aura_sequence IS NOT NULL AND (?1 IS NULL OR cursor<?1)
             AND (?2 IS NULL OR contact=?2) ORDER BY cursor DESC LIMIT ?3",
        ).map_err(|_| refuse("store-read"))?;
        let rows = stmt
            .query_map(
                params![
                    before.map(|cursor| cursor as i64),
                    contact.map(|key| key.as_bytes().to_vec()),
                    limit as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .map_err(|_| refuse("store-read"))?;
        rows.map(|row| {
            let (
                cursor,
                id,
                contact,
                direction,
                text,
                created_at_ms,
                observed_at_ms,
                state,
                aura_sequence,
            ) = row.map_err(|_| refuse("store-read"))?;
            let direction = match direction.as_str() {
                "incoming" => MessageDirection::Incoming,
                "outgoing" => MessageDirection::Outgoing,
                _ => return Err(refuse("store-field")),
            };
            let state = match (direction, state) {
                (MessageDirection::Incoming, 4) => MessageState::Received,
                (MessageDirection::Outgoing, 0) => MessageState::Queued,
                (MessageDirection::Outgoing, 1) => MessageState::Published,
                (MessageDirection::Outgoing, 2) => MessageState::Unconfirmed,
                (MessageDirection::Outgoing, 3) => MessageState::Failed,
                _ => return Err(refuse("store-field")),
            };
            Ok(MessageRecord {
                cursor: unsigned(cursor)?,
                id: Digest32::from_bytes(fixed(id)?),
                contact: PublicKey::from_bytes(fixed(contact)?)?,
                direction,
                text,
                created_at_ms: unsigned(created_at_ms)?,
                observed_at_ms: unsigned(observed_at_ms)?,
                state,
                aura_sequence: unsigned(aura_sequence)?,
            })
        })
        .collect()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn stage(
    db: &Connection,
    id: Digest32,
    direction: &str,
    contact: PublicKey,
    content: &str,
    created_at_ms: u64,
    observed_at_ms: u64,
    envelope: &TransportEnvelope,
    contact_receipt: Digest32,
) -> Result<()> {
    let body = Value::checked_object(vec![
        ("schema".to_owned(), text(MESSAGE_SCHEMA)?),
        ("id".to_owned(), text(&id.to_string())?),
        ("direction".to_owned(), text(direction)?),
        (
            "contact".to_owned(),
            text(&hex::encode(contact.as_bytes()))?,
        ),
        (
            "envelope_id".to_owned(),
            text(&hex::encode(envelope.id.as_bytes()))?,
        ),
        (
            "contact_receipt".to_owned(),
            text(&contact_receipt.to_string())?,
        ),
        ("created_at_ms".to_owned(), number(created_at_ms)?),
        ("observed_at_ms".to_owned(), number(observed_at_ms)?),
    ])?;
    db.execute(
        "INSERT INTO messaging_messages(id,direction,contact,text,created_at_ms,observed_at_ms,
         envelope,audit_body,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            id.as_bytes().as_slice(),
            direction,
            contact.as_bytes().as_slice(),
            content,
            created_at_ms as i64,
            observed_at_ms as i64,
            &envelope.bytes,
            body.canonical_bytes(),
            if direction == "incoming" { 4 } else { 0 }
        ],
    )
    .map_err(|_| refuse("store-write"))?;
    Ok(())
}

fn number(value: u64) -> Result<Value> {
    if value > MAX_SAFE_INTEGER as u64 {
        return Err(refuse("message-time"));
    }
    Ok(Value::integer(SafeInteger::new(value as i64)?))
}

fn unsigned(value: i64) -> Result<u64> {
    value.try_into().map_err(|_| refuse("store-field"))
}

fn page_limit(limit: usize) -> Result<()> {
    if limit == 0 || limit > crate::MAX_PAGE_ITEMS {
        return Err(refuse("page-limit"));
    }
    Ok(())
}
