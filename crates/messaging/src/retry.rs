// SPDX-License-Identifier: AGPL-3.0-or-later
//! Persisted backoff for uncertain submissions, including relay rate limits.
use crate::{fixed, refuse, Messaging, OutboxId};
use canon::{digest::Digest32, json::MAX_SAFE_INTEGER, Result};
use nostr::{SubmissionStatus, TransportReceipt};
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS messaging_send_retry(
            id BLOB PRIMARY KEY CHECK(length(id)=32),
            attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 5),
            next_ms INTEGER NOT NULL CHECK(next_ms>=0));",
    )
    .map_err(|_| refuse("store-schema"))
}

impl Messaging {
    /// Select due sends without making a rate-limited contact block other work.
    pub fn pending_owner_sends_due(&self, now_ms: u64, limit: usize) -> Result<Vec<OutboxId>> {
        if limit == 0 || limit > crate::MAX_PAGE_ITEMS || now_ms > MAX_SAFE_INTEGER as u64 {
            return Err(refuse("page-limit"));
        }
        let mut statement = self.db.prepare(
            "SELECT m.id FROM messaging_messages m LEFT JOIN messaging_send_retry r ON r.id=m.id
             WHERE m.direction='outgoing' AND m.aura_sequence IS NOT NULL AND m.state IN(0,2)
             AND (r.next_ms IS NULL OR r.next_ms<=?1) ORDER BY m.cursor LIMIT ?2",
        ).map_err(|_| refuse("store-read"))?;
        let rows = statement
            .query_map(params![now_ms as i64, limit as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|_| refuse("store-read"))?;
        rows.map(|row| {
            Ok(OutboxId(Digest32::from_bytes(fixed(
                row.map_err(|_| refuse("store-read"))?,
            )?)))
        })
        .collect()
    }

    /// A missing receipt may also have stored the envelope. Retry the same id
    /// after 30, 60, 120, 240, then at most every 300 seconds, across restarts.
    pub fn record_owner_attempt(
        &mut self,
        id: OutboxId,
        now_ms: u64,
        receipt: Option<&TransportReceipt>,
    ) -> Result<()> {
        if receipt.is_some_and(|receipt| receipt.status != SubmissionStatus::Unknown) {
            self.db
                .execute(
                    "DELETE FROM messaging_send_retry WHERE id=?1",
                    [id.0.as_bytes().as_slice()],
                )
                .map_err(|_| refuse("store-write"))?;
            return Ok(());
        }
        let attempts: i64 = self
            .db
            .query_row(
                "SELECT attempts FROM messaging_send_retry WHERE id=?1",
                [id.0.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| refuse("store-read"))?
            .unwrap_or(0);
        let delay = (30_000u64 << attempts.min(4)).min(300_000);
        let next = now_ms
            .checked_add(delay)
            .filter(|next| *next <= MAX_SAFE_INTEGER as u64)
            .ok_or(refuse("message-time"))?;
        self.db
            .execute(
                "INSERT INTO messaging_send_retry(id,attempts,next_ms) VALUES(?1,?2,?3)
             ON CONFLICT(id) DO UPDATE SET attempts=excluded.attempts,next_ms=excluded.next_ms",
                params![
                    id.0.as_bytes().as_slice(),
                    (attempts + 1).min(5),
                    next as i64
                ],
            )
            .map_err(|_| refuse("store-write"))?;
        Ok(())
    }
}
