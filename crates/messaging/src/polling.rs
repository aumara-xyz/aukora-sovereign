// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private relay positions and durable retries after history advances.
use crate::{fixed, refuse, Messaging, MAX_PAGE_ITEMS};
use canon::Result;
use nostr::{EnvelopeCodec, EventId, PublicKey, TransportEnvelope};
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS messaging_receive_cursor(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), cursor TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS messaging_ingress_retry(
            envelope BLOB PRIMARY KEY CHECK(length(envelope)=32),
            recipient BLOB NOT NULL CHECK(length(recipient)=32), bytes BLOB NOT NULL,
            last_attempt INTEGER NOT NULL CHECK(last_attempt>=0));
        CREATE INDEX IF NOT EXISTS messaging_ingress_retry_attempt
            ON messaging_ingress_retry(last_attempt);",
    )
    .map_err(|_| refuse("store-schema"))
}
impl Messaging {
    /// Opaque adapter state, including a separate time window for every relay.
    pub fn receive_cursor(&self) -> Result<Option<String>> {
        self.db
            .query_row(
                "SELECT cursor FROM messaging_receive_cursor WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| refuse("store-read"))
    }
    /// Called only after every envelope in the page is admitted or durably refused.
    pub fn set_receive_cursor(&self, cursor: Option<&str>) -> Result<()> {
        if let Some(cursor) = cursor {
            if cursor.len() > nostr::transport::MAX_CURSOR_BYTES {
                return Err(refuse("page-cursor"));
            }
            self.db
                .execute(
                    "INSERT INTO messaging_receive_cursor VALUES(1,?1)
                ON CONFLICT(singleton) DO UPDATE SET cursor=excluded.cursor",
                    [cursor],
                )
                .map_err(|_| refuse("store-write"))?;
        }
        Ok(())
    }
    /// A bounded, fair retry slice; advancing a relay cursor never loses a
    /// clearable refusal, including across process restarts and long outages.
    pub fn retry_envelopes(&self, limit: usize) -> Result<Vec<TransportEnvelope>> {
        if limit == 0 || limit > MAX_PAGE_ITEMS {
            return Err(refuse("page-limit"));
        }
        let mut query = self
            .db
            .prepare(
                "SELECT envelope,recipient,bytes FROM messaging_ingress_retry
            ORDER BY last_attempt,rowid LIMIT ?1",
            )
            .map_err(|_| refuse("store-read"))?;
        let rows = query
            .query_map([limit as i64], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| refuse("store-read"))?;
        rows.map(|row| {
            let (id, recipient, bytes) = row.map_err(|_| refuse("store-read"))?;
            Ok(TransportEnvelope {
                v: nostr::transport::TRANSPORT_VERSION,
                codec: EnvelopeCodec::Nip59V1,
                recipient: PublicKey::from_bytes(fixed(recipient)?)?,
                id: EventId::from_bytes(fixed(id)?),
                bytes,
            })
        })
        .collect()
    }
}

pub(crate) fn retain_retry(db: &Connection, envelope: &TransportEnvelope) -> Result<()> {
    db.execute(
        "INSERT INTO messaging_ingress_retry
        SELECT ?1,?2,?3,coalesce(max(last_attempt),0)+1 FROM messaging_ingress_retry WHERE true
        ON CONFLICT(envelope) DO UPDATE SET last_attempt=excluded.last_attempt",
        params![
            envelope.id.as_bytes().as_slice(),
            envelope.recipient.as_bytes().as_slice(),
            &envelope.bytes
        ],
    )
    .map(|_| ())
    .map_err(|_| refuse("store-write"))
}
pub(crate) fn forget_retry(db: &Connection, envelope: &[u8; 32]) -> Result<()> {
    db.execute(
        "DELETE FROM messaging_ingress_retry WHERE envelope=?1",
        [envelope.as_slice()],
    )
    .map(|_| ())
    .map_err(|_| refuse("store-write"))
}
