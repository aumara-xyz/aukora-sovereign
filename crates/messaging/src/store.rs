// SPDX-License-Identifier: AGPL-3.0-or-later
//! Versioned private projections. Aura remains the source of committed facts.

use crate::refuse;
use canon::{ids::NodeId, Result};
use rusqlite::{params, Connection, TransactionBehavior};

pub(crate) fn initialize(db: &mut Connection, node: NodeId) -> Result<()> {
    db.execute_batch(
        "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;
        PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS messaging_meta(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            schema_version INTEGER NOT NULL CHECK(schema_version=1), node BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS messaging_contacts(
            key BLOB PRIMARY KEY CHECK(length(key)=32), action BLOB NOT NULL,
            epoch INTEGER NOT NULL CHECK(epoch>=0), sequence INTEGER NOT NULL CHECK(sequence>0),
            previous_hash BLOB, proposal BLOB NOT NULL CHECK(length(proposal)=16),
            consumed_card BLOB NOT NULL CHECK(length(consumed_card)=32));
        CREATE TABLE IF NOT EXISTS messaging_outbox(
            id BLOB PRIMARY KEY CHECK(length(id)=32), proposal BLOB NOT NULL UNIQUE,
            authorization_receipt BLOB NOT NULL CHECK(length(authorization_receipt)=32),
            recipient BLOB NOT NULL CHECK(length(recipient)=32), envelope_id BLOB NOT NULL,
            envelope BLOB NOT NULL, state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),
            failure TEXT);",
    )
    .map_err(|_| refuse("store-schema"))?;
    db.execute(
        "INSERT OR IGNORE INTO messaging_meta VALUES(1,1,?1)",
        params![node.as_bytes().as_slice()],
    )
    .map_err(|_| refuse("store-write"))?;
    let (version, saved): (i64, Vec<u8>) = db
        .query_row(
            "SELECT schema_version,node FROM messaging_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| refuse("store-schema"))?;
    if saved != node.as_bytes() {
        return Err(refuse("store-node"));
    }
    if version != 1 {
        return Err(refuse("store-schema"));
    }
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| refuse("store-busy"))?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS messaging_history_meta(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            schema_version INTEGER NOT NULL CHECK(schema_version=1));
        INSERT OR IGNORE INTO messaging_history_meta VALUES(1,1);
        CREATE TABLE IF NOT EXISTS messaging_messages(
            cursor INTEGER PRIMARY KEY AUTOINCREMENT,
            id BLOB NOT NULL UNIQUE CHECK(length(id)=32),
            direction TEXT NOT NULL CHECK(direction IN('incoming','outgoing')),
            contact BLOB NOT NULL CHECK(length(contact)=32),
            text TEXT NOT NULL CHECK(length(CAST(text AS BLOB)) BETWEEN 1 AND 16384),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
            observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0),
            envelope BLOB NOT NULL,
            audit_body BLOB NOT NULL,
            aura_sequence INTEGER CHECK(aura_sequence>0),
            state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 4));
        CREATE INDEX IF NOT EXISTS messaging_messages_contact_cursor
            ON messaging_messages(contact,cursor);",
    )
    .map_err(|_| refuse("store-schema"))?;
    // Keep the base schema at v1 so a predecessor release can still open its
    // contacts/outbox on rollback. History is an independently versioned,
    // additive extension, installed in this one transaction on existing stores.
    let history_version: i64 = tx
        .query_row(
            "SELECT schema_version FROM messaging_history_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| refuse("store-schema"))?;
    if history_version != 1 {
        return Err(refuse("store-schema"));
    }
    tx.commit().map_err(|_| refuse("store-commit"))
}
