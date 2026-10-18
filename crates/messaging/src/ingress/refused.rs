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

/// After a counted refusal: a final one is remembered at once; a retryable one is remembered once it has been refused
/// `RETRY_LIMIT` times, so no stored wrap is counted on every poll for ever, whatever its reason.
pub(crate) fn settle_refused(db: &Connection, envelope: &[u8; 32], retryable: bool) -> Result<()> {
    if retryable {
        let write = |_| refuse("store-write");
        db.execute(
            "INSERT INTO messaging_retry_envelope SELECT ?1,0
             WHERE (SELECT count(*) FROM messaging_retry_envelope) < ?2
             ON CONFLICT(envelope) DO NOTHING",
            params![envelope.as_slice(), REFUSED_ENVELOPE_CAP],
        )
        .map_err(write)?;
        db.execute("UPDATE messaging_retry_envelope SET tries=tries+1 WHERE envelope=?1", [envelope.as_slice()])
            .map_err(write)?;
        let tries: Option<i64> = db
            .query_row("SELECT tries FROM messaging_retry_envelope WHERE envelope=?1", [envelope.as_slice()], |row| row.get(0))
            .optional()
            .map_err(|_| refuse("store-read"))?;
        // Past the retry table's own cap there is no budget to track: treat it as final.
        if tries.is_some_and(|tries| tries < RETRY_LIMIT) {
            return Ok(());
        }
    }
    remember_refused(db, envelope)
}
