// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable pairing state: sessions, counted attempts, spent receipts and paired devices.
//!
//! One SQLite file with `synchronous=FULL`. A spent receipt row can never be updated or
//! deleted, and its primary key is the verified receipt digest, so a second acceptance of
//! the same receipt fails at the constraint, after a crash as much as before one.

use super::refuse;
use canon::Result;
use copresence::v1::{AttemptJournal, AttemptOutcome, AttemptTicket};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;

pub const STORE_SCHEMA: &str = "aukora.copresence.pairing-store.v1";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pairing_meta(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema TEXT NOT NULL CHECK(schema='aukora.copresence.pairing-store.v1'),
  node TEXT NOT NULL CHECK(length(node)=32));
CREATE TABLE IF NOT EXISTS pairings(
  id TEXT PRIMARY KEY CHECK(length(id)=32),
  subject TEXT NOT NULL,
  epoch INTEGER NOT NULL CHECK(epoch>=0),
  session TEXT NOT NULL CHECK(length(session)=64),
  initiator_key TEXT NOT NULL CHECK(length(initiator_key)=130),
  join_digest TEXT NOT NULL UNIQUE CHECK(length(join_digest)=64),
  phone_digest TEXT UNIQUE CHECK(phone_digest IS NULL OR length(phone_digest)=64),
  joiner_key TEXT CHECK(joiner_key IS NULL OR length(joiner_key)=130),
  context TEXT,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>created_ms),
  attempts INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK(state IN ('open','joined','spent','closed')),
  receipt TEXT CHECK(receipt IS NULL OR length(receipt)=64),
  verdict TEXT,
  fact TEXT,
  aura_floor INTEGER CHECK(aura_floor IS NULL OR aura_floor>=0),
  aura_sequence INTEGER,
  aura_entry TEXT);
CREATE INDEX IF NOT EXISTS pairings_subject ON pairings(subject,state);
CREATE TABLE IF NOT EXISTS spent_receipts(
  receipt TEXT PRIMARY KEY CHECK(length(receipt)=64),
  pairing TEXT NOT NULL UNIQUE,
  spent_ms INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS spent_receipts_no_update BEFORE UPDATE ON spent_receipts
  BEGIN SELECT RAISE(ABORT,'copresence:receipt-spent'); END;
CREATE TRIGGER IF NOT EXISTS spent_receipts_no_delete BEFORE DELETE ON spent_receipts
  BEGIN SELECT RAISE(ABORT,'copresence:receipt-spent'); END;
CREATE TABLE IF NOT EXISTS attempts(
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  pairing TEXT NOT NULL,
  session TEXT NOT NULL CHECK(length(session)=32),
  began_ms INTEGER NOT NULL,
  outcome TEXT CHECK(outcome IS NULL OR outcome IN ('accepted','refused','abandoned')),
  reason TEXT,
  receipt TEXT);
CREATE TRIGGER IF NOT EXISTS attempts_no_delete BEFORE DELETE ON attempts
  BEGIN SELECT RAISE(ABORT,'copresence:attempt-retained'); END;
CREATE TABLE IF NOT EXISTS devices(
  key_sha256 TEXT PRIMARY KEY CHECK(length(key_sha256)=64),
  public_key TEXT NOT NULL UNIQUE CHECK(length(public_key)=130),
  subject TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('initiator','joiner')),
  first_pairing TEXT NOT NULL,
  last_pairing TEXT NOT NULL,
  first_ms INTEGER NOT NULL,
  last_ms INTEGER NOT NULL,
  pairings INTEGER NOT NULL CHECK(pairings>0));
CREATE TRIGGER IF NOT EXISTS devices_no_delete BEFORE DELETE ON devices
  BEGIN SELECT RAISE(ABORT,'copresence:device-retained'); END;";

fn sql(_: rusqlite::Error) -> canon::Refusal {
    refuse("store")
}

pub(super) fn ms(value: u64) -> Result<i64> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value <= canon::json::MAX_SAFE_INTEGER)
        .ok_or(refuse("store-integer"))
}

fn unsigned(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| refuse("store-integer"))
}

/// One row of `pairings`, as read.
#[derive(Clone, Debug)]
pub(super) struct Row {
    pub id: String,
    pub subject: String,
    pub epoch: u64,
    pub session: String,
    pub initiator_key: String,
    pub joiner_key: Option<String>,
    pub context: Option<String>,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub attempts: u64,
    pub state: String,
    pub verdict: Option<String>,
    pub fact: Option<String>,
    pub aura_floor: Option<u64>,
    pub aura_sequence: Option<u64>,
    pub aura_entry: Option<String>,
}

const COLUMNS: &str = "id,subject,epoch,session,initiator_key,joiner_key,context,created_ms,expires_ms,\
attempts,state,receipt,verdict,fact,aura_sequence,aura_entry,aura_floor";

type Parts = (Row, i64, i64, i64, i64, Option<i64>, Option<i64>);

fn row(value: &rusqlite::Row<'_>) -> rusqlite::Result<Parts> {
    Ok((
        Row {
            id: value.get(0)?,
            subject: value.get(1)?,
            epoch: 0,
            session: value.get(3)?,
            initiator_key: value.get(4)?,
            joiner_key: value.get(5)?,
            context: value.get(6)?,
            created_ms: 0,
            expires_ms: 0,
            attempts: 0,
            state: value.get(10)?,
            verdict: value.get(12)?,
            fact: value.get(13)?,
            aura_floor: None,
            aura_sequence: None,
            aura_entry: value.get(15)?,
        },
        value.get(2)?,
        value.get(7)?,
        value.get(8)?,
        value.get(9)?,
        value.get(14)?,
        value.get(16)?,
    ))
}

fn finish_row(parts: Parts) -> Result<Row> {
    let (mut row, epoch, created, expires, attempts, sequence, floor) = parts;
    row.aura_floor = floor.map(unsigned).transpose()?;
    row.epoch = unsigned(epoch)?;
    row.created_ms = unsigned(created)?;
    row.expires_ms = unsigned(expires)?;
    row.attempts = unsigned(attempts)?;
    row.aura_sequence = sequence.map(unsigned).transpose()?;
    Ok(row)
}

/// One paired device, newest pairing last.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRow {
    pub key_sha256: String,
    pub public_key: String,
    pub role: String,
    pub first_pairing: String,
    pub last_pairing: String,
    pub first_ms: u64,
    pub last_ms: u64,
    pub pairings: u64,
}

pub(super) struct Store {
    db: Connection,
}

impl Store {
    pub fn open(path: &Path, node: &str) -> Result<Self> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| refuse("store-open"))?;
        db.busy_timeout(std::time::Duration::from_millis(500))
            .map_err(sql)?;
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;
             PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
        )
        .map_err(sql)?;
        db.execute_batch(SCHEMA).map_err(sql)?;
        db.execute(
            "INSERT OR IGNORE INTO pairing_meta(singleton,schema,node) VALUES(1,?1,?2)",
            params![STORE_SCHEMA, node],
        )
        .map_err(sql)?;
        let stored: String = db
            .query_row("SELECT node FROM pairing_meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .map_err(sql)?;
        if stored != node {
            return Err(refuse("store-node"));
        }
        Ok(Self { db })
    }

    pub fn by_id(&self, id: &str) -> Result<Option<Row>> {
        self.db
            .query_row(
                &format!("SELECT {COLUMNS} FROM pairings WHERE id=?1"),
                [id],
                row,
            )
            .optional()
            .map_err(sql)?
            .map(finish_row)
            .transpose()
    }

    pub fn by_join(&self, digest: &str) -> Result<Option<Row>> {
        self.db
            .query_row(
                &format!("SELECT {COLUMNS} FROM pairings WHERE join_digest=?1"),
                [digest],
                row,
            )
            .optional()
            .map_err(sql)?
            .map(finish_row)
            .transpose()
    }

    pub fn by_phone(&self, digest: &str) -> Result<Option<Row>> {
        self.db
            .query_row(
                &format!("SELECT {COLUMNS} FROM pairings WHERE phone_digest=?1"),
                [digest],
                row,
            )
            .optional()
            .map_err(sql)?
            .map(finish_row)
            .transpose()
    }

    /// A new start closes the owner's earlier unfinished pairings and forgets
    /// unfinished ones older than a day. Spent pairings and their receipts stay.
    pub fn insert(&mut self, row: &Row, join_digest: &str, now_ms: u64) -> Result<()> {
        let transaction = self.db.transaction().map_err(sql)?;
        transaction
            .execute(
                "UPDATE pairings SET state='closed' WHERE subject=?1 AND state IN ('open','joined')",
                [&row.subject],
            )
            .map_err(sql)?;
        transaction
            .execute(
                "DELETE FROM pairings WHERE state IN ('open','joined','closed') AND expires_ms<?1",
                [ms(now_ms.saturating_sub(86_400_000))?],
            )
            .map_err(sql)?;
        transaction
            .execute(
                "INSERT INTO pairings(id,subject,epoch,session,initiator_key,join_digest,created_ms,expires_ms,state)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'open')",
                params![
                    row.id,
                    row.subject,
                    ms(row.epoch)?,
                    row.session,
                    row.initiator_key,
                    join_digest,
                    ms(row.created_ms)?,
                    ms(row.expires_ms)?
                ],
            )
            .map_err(sql)?;
        transaction.commit().map_err(sql)
    }

    /// The join token is single use: the update matches only an open row.
    pub fn join(&self, id: &str, phone_digest: &str, joiner_key: &str, context: &str) -> Result<()> {
        let changed = self
            .db
            .execute(
                "UPDATE pairings SET state='joined',phone_digest=?2,joiner_key=?3,context=?4
                 WHERE id=?1 AND state='open'",
                params![id, phone_digest, joiner_key, context],
            )
            .map_err(sql)?;
        if changed != 1 {
            return Err(refuse("join-used"));
        }
        Ok(())
    }

    pub fn close(&self, id: &str) -> Result<()> {
        self.db
            .execute(
                "UPDATE pairings SET state='closed' WHERE id=?1 AND state IN ('open','joined')",
                [id],
            )
            .map_err(sql)?;
        Ok(())
    }

    /// Counted before the receipt is decoded; the count survives every later failure.
    pub fn count_attempt(&self, id: &str) -> Result<u64> {
        let changed = self
            .db
            .execute(
                "UPDATE pairings SET attempts=attempts+1 WHERE id=?1 AND state='joined'",
                [id],
            )
            .map_err(sql)?;
        if changed != 1 {
            return Err(refuse("pairing-state"));
        }
        let count: i64 = self
            .db
            .query_row("SELECT attempts FROM pairings WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .map_err(sql)?;
        unsigned(count)
    }

    /// Spend exactly once: the receipt row, the pairing's terminal state and both
    /// device rows commit together, or none of them do.
    #[allow(clippy::too_many_arguments)]
    pub fn spend(
        &mut self,
        id: &str,
        subject: &str,
        receipt: &str,
        verdict: &str,
        fact: &str,
        devices: [(&str, &str, &str); 2],
        now_ms: u64,
    ) -> Result<()> {
        let now = ms(now_ms)?;
        let transaction = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sql)?;
        let spent = transaction.execute(
            "INSERT INTO spent_receipts(receipt,pairing,spent_ms) VALUES(?1,?2,?3)",
            params![receipt, id, now],
        );
        match spent {
            Ok(1) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(refuse("receipt-spent"));
            }
            _ => return Err(refuse("store")),
        }
        let changed = transaction
            .execute(
                "UPDATE pairings SET state='spent',receipt=?2,verdict=?3,fact=?4 WHERE id=?1 AND state='joined'",
                params![id, receipt, verdict, fact],
            )
            .map_err(sql)?;
        if changed != 1 {
            return Err(refuse("pairing-state"));
        }
        for (key_sha256, public_key, role) in devices {
            let owner: Option<String> = transaction
                .query_row(
                    "SELECT subject FROM devices WHERE key_sha256=?1",
                    [key_sha256],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql)?;
            match owner {
                None => {
                    transaction
                        .execute(
                            "INSERT INTO devices(key_sha256,public_key,subject,role,first_pairing,last_pairing,first_ms,last_ms,pairings)
                             VALUES(?1,?2,?3,?4,?5,?5,?6,?6,1)",
                            params![key_sha256, public_key, subject, role, id, now],
                        )
                        .map_err(sql)?;
                }
                Some(owner) if owner == subject => {
                    transaction
                        .execute(
                            "UPDATE devices SET last_pairing=?2,last_ms=?3,pairings=pairings+1 WHERE key_sha256=?1",
                            params![key_sha256, id, now],
                        )
                        .map_err(sql)?;
                }
                Some(_) => return Err(refuse("device-owner")),
            }
        }
        transaction.commit().map_err(sql)
    }

    /// Spent pairings whose Aura fact is not yet recorded, oldest first.
    pub fn pending_facts(&self, limit: usize) -> Result<Vec<String>> {
        let mut statement = self
            .db
            .prepare(
                "SELECT id FROM pairings WHERE state='spent' AND aura_sequence IS NULL AND fact IS NOT NULL
                 ORDER BY created_ms,id LIMIT ?1",
            )
            .map_err(sql)?;
        let rows = statement
            .query_map([i64::try_from(limit).map_err(|_| refuse("store-integer"))?], |row| row.get(0))
            .map_err(sql)?;
        rows.collect::<rusqlite::Result<Vec<String>>>().map_err(sql)
    }

    pub fn pending_count(&self) -> Result<usize> {
        let count: i64 = self
            .db
            .query_row(
                "SELECT count(*) FROM pairings WHERE state='spent' AND aura_sequence IS NULL AND fact IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .map_err(sql)?;
        usize::try_from(count).map_err(|_| refuse("store-integer"))
    }

    /// Persists the Aura sequence the fact search starts after; the first value stays.
    pub fn set_floor(&self, id: &str, floor: u64) -> Result<u64> {
        self.db
            .execute(
                "UPDATE pairings SET aura_floor=?2 WHERE id=?1 AND state='spent' AND aura_floor IS NULL",
                params![id, ms(floor)?],
            )
            .map_err(sql)?;
        let stored: Option<i64> = self
            .db
            .query_row("SELECT aura_floor FROM pairings WHERE id=?1", [id], |row| row.get(0))
            .map_err(sql)?;
        unsigned(stored.ok_or(refuse("store"))?)
    }

    pub fn recorded(&self, id: &str, sequence: u64, entry: &str) -> Result<()> {
        self.db
            .execute(
                "UPDATE pairings SET aura_sequence=?2,aura_entry=?3 WHERE id=?1 AND state='spent' AND aura_sequence IS NULL",
                params![id, ms(sequence)?, entry],
            )
            .map_err(sql)?;
        Ok(())
    }

    /// The newest 128 devices, shown oldest first: past the cap it is the oldest that drop out of
    /// the view, never the most recent pairing.
    pub fn devices(&self, subject: &str) -> Result<Vec<DeviceRow>> {
        let mut statement = self
            .db
            .prepare(
                "SELECT key_sha256,public_key,role,first_pairing,last_pairing,first_ms,last_ms,pairings FROM (
                     SELECT key_sha256,public_key,role,first_pairing,last_pairing,first_ms,last_ms,pairings
                     FROM devices WHERE subject=?1 ORDER BY first_ms DESC,key_sha256 DESC LIMIT 128
                 ) ORDER BY first_ms,key_sha256",
            )
            .map_err(sql)?;
        let rows = statement
            .query_map([subject], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .map_err(sql)?;
        let mut devices = Vec::new();
        for row in rows {
            let (key_sha256, public_key, role, first_pairing, last_pairing, first, last, count) =
                row.map_err(sql)?;
            devices.push(DeviceRow {
                key_sha256,
                public_key,
                role,
                first_pairing,
                last_pairing,
                first_ms: unsigned(first)?,
                last_ms: unsigned(last)?,
                pairings: unsigned(count)?,
            });
        }
        Ok(devices)
    }

    pub fn journal<'a>(&'a self, pairing: &'a str, now_ms: u64) -> Journal<'a> {
        Journal {
            db: &self.db,
            pairing,
            now_ms,
        }
    }
}

/// The verifier's durable attempt journal, one row per verification attempt.
pub(super) struct Journal<'a> {
    db: &'a Connection,
    pairing: &'a str,
    now_ms: u64,
}

impl AttemptJournal for Journal<'_> {
    fn begin(&mut self, local_session: [u8; 16]) -> Result<AttemptTicket> {
        self.db
            .execute(
                "INSERT INTO attempts(pairing,session,began_ms) VALUES(?1,?2,?3)",
                params![self.pairing, hex::encode(local_session), ms(self.now_ms)?],
            )
            .map_err(sql)?;
        Ok(AttemptTicket {
            sequence: unsigned(self.db.last_insert_rowid())?,
            local_session,
        })
    }

    fn finish(&mut self, ticket: AttemptTicket, outcome: AttemptOutcome) -> Result<()> {
        let (name, reason, receipt) = match outcome {
            AttemptOutcome::Accepted { receipt } => ("accepted", None, Some(receipt.to_string())),
            AttemptOutcome::Refused(refusal) => (
                "refused",
                Some(format!("{}:{}", refusal.organ, refusal.reason)),
                None,
            ),
            AttemptOutcome::Abandoned => ("abandoned", None, None),
        };
        let changed = self
            .db
            .execute(
                "UPDATE attempts SET outcome=?2,reason=?3,receipt=?4
                 WHERE sequence=?1 AND session=?5 AND outcome IS NULL",
                params![
                    ms(ticket.sequence)?,
                    name,
                    reason,
                    receipt,
                    hex::encode(ticket.local_session)
                ],
            )
            .map_err(sql)?;
        if changed != 1 {
            return Err(refuse("attempt-finish"));
        }
        Ok(())
    }
}
