// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable, bounded failure names for queued sends whose contact was revoked.
use crate::{refuse, Messaging, OutboxId};
use canon::{Refusal, Result};
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS messaging_send_failure(
            id BLOB PRIMARY KEY CHECK(length(id)=32),
            reason TEXT NOT NULL CHECK(reason IN('contact-removed','contact-changed')));",
    )
    .map_err(|_| refuse("store-schema"))
}

impl Messaging {
    pub(crate) fn fail_contact_send(&self, id: OutboxId, reason: &'static str) -> Result<()> {
        let transaction = self
            .db
            .unchecked_transaction()
            .map_err(|_| refuse("store-write"))?;
        transaction
            .execute(
                "UPDATE messaging_messages SET state=3 WHERE id=?1 AND state IN(0,2)",
                [id.0.as_bytes().as_slice()],
            )
            .map_err(|_| refuse("store-write"))?;
        transaction
            .execute(
                "INSERT INTO messaging_send_failure(id,reason) VALUES(?1,?2)
             ON CONFLICT(id) DO UPDATE SET reason=excluded.reason",
                params![id.0.as_bytes().as_slice(), reason],
            )
            .map_err(|_| refuse("store-write"))?;
        transaction.commit().map_err(|_| refuse("store-write"))
    }

    /// The face can distinguish a local contact revocation from relay rejection.
    pub fn owner_send_failure(&self, id: OutboxId) -> Result<Option<Refusal>> {
        let reason: Option<String> = self
            .db
            .query_row(
                "SELECT reason FROM messaging_send_failure WHERE id=?1",
                [id.0.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| refuse("store-read"))?;
        reason
            .map(|reason| match reason.as_str() {
                "contact-removed" => Ok(refuse("contact-removed")),
                "contact-changed" => Ok(refuse("contact-changed")),
                _ => Err(refuse("store-field")),
            })
            .transpose()
    }
}
