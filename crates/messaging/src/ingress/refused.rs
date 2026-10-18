// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which refused relay envelopes are remembered, so repeated relay snapshots never count one wrap on every poll.
use super::refuse;
use canon::Result;
use rusqlite::{params, Connection, OptionalExtension};

/// How many refused envelope ids are kept (32 bytes each), and how many retryable ones are being retried.
pub(crate) const REFUSED_ENVELOPE_CAP: i64 = 4096;
/// A refusal that can clear (clock skew, a contact approval still syncing, a local store error) is retried on later
/// polls and counted each time, at most this many times (about ten minutes of 30-second polls); then it is final.
pub(crate) const RETRY_LIMIT: i64 = 20;

/// Keep one refused envelope id, unless the table already holds `REFUSED_ENVELOPE_CAP` (past it a wrap is counted
/// again on a later poll, never dropped).
pub(crate) fn remember_refused(db: &Connection, envelope: &[u8; 32]) -> Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO messaging_refused_envelope SELECT ?1
         WHERE (SELECT count(*) FROM messaging_refused_envelope) < ?2",
        params![envelope.as_slice(), REFUSED_ENVELOPE_CAP],
    )
    .map(|_| ())
    .map_err(|_| refuse("store-write"))
}

/// After a counted refusal: a final one is remembered at once. A retryable one is retried; once it has been refused
/// `RETRY_LIMIT` times its retry row itself marks it seen (`seen_envelope`), even if the refused table is full. A
/// retryable refusal is never pinned early: with the retry table full it is simply counted again on a later poll.
pub(crate) fn settle_refused(db: &Connection, envelope: &[u8; 32], retryable: bool) -> Result<()> {
    if !retryable {
        return remember_refused(db, envelope);
    }
    let write = |_| refuse("store-write");
    db.execute(
        "INSERT INTO messaging_retry_envelope SELECT ?1,0
         WHERE (SELECT count(*) FROM messaging_retry_envelope) < ?2
         ON CONFLICT(envelope) DO NOTHING",
        params![envelope.as_slice(), REFUSED_ENVELOPE_CAP],
    )
    .map_err(write)?;
    db.execute(
        "UPDATE messaging_retry_envelope SET tries=min(tries+1,?2) WHERE envelope=?1",
        params![envelope.as_slice(), RETRY_LIMIT],
    )
    .map_err(write)?;
    let tries: Option<i64> = db
        .query_row("SELECT tries FROM messaging_retry_envelope WHERE envelope=?1", [envelope.as_slice()], |row| row.get(0))
        .optional()
        .map_err(|_| refuse("store-read"))?;
    if tries.is_some_and(|tries| tries >= RETRY_LIMIT) {
        remember_refused(db, envelope)?;
    }
    Ok(())
}

/// An admitted wrap leaves the retry table, so retry slots are held only by wraps still being refused.
pub(crate) fn forget_retry(db: &Connection, envelope: &[u8; 32]) -> Result<()> {
    db.execute("DELETE FROM messaging_retry_envelope WHERE envelope=?1", [envelope.as_slice()])
        .map(|_| ())
        .map_err(|_| refuse("store-write"))
}
