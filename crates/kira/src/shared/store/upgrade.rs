// SPDX-License-Identifier: AGPL-3.0-or-later
//! Upgrades of a store written by an older build: the chain version, and the derived tables (ancestry lineage,
//! supersede links, citations), which are rebuilt from the events and are not part of the chain.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Upgrades a v1 chain to v2, only when the whole v1 chain verifies first (signatures, columns and links). A store
/// whose v1 chain does not verify is left as it is, so it fails verification under v2 and the service refuses it.
pub(super) fn upgrade_chain(db: &mut Connection) -> Result<()> {
    let version: Option<String> = db
        .query_row("SELECT value FROM meta WHERE key = 'chain'", [], |r| r.get(0))
        .optional()
        .map_err(sql)?;
    match version.as_deref() {
        Some(v) if v == CHAIN_VERSION.to_string() => return Ok(()),
        Some(_) => return Err(refuse("store-chain-version")),
        None => {}
    }
    let Ok(v1) = walk(db, 1) else { return Ok(()) };
    let tx = db.transaction().map_err(sql)?;
    let mut prev = [0u8; 32];
    for (seq, _) in v1 {
        let row = tx.query_row(&format!("{ROW} WHERE seq = ?1"), params![seq], row_of).map_err(sql)?;
        let created_at = u64::try_from(row.created_at).map_err(|_| refuse("store-chain-broken"))?;
        let id: [u8; 32] = Event::decode(&row.raw)?.id.as_bytes().to_owned();
        let next = link(CHAIN_VERSION, &prev, seq, &id, created_at);
        tx.execute("UPDATE events SET chain = ?1 WHERE seq = ?2", params![next.to_vec(), seq]).map_err(sql)?;
        prev = next;
    }
    tx.execute("INSERT INTO meta(key, value) VALUES ('chain', ?1)", params![CHAIN_VERSION.to_string()]).map_err(sql)?;
    tx.commit().map_err(sql)
}

/// The lineage rule this build writes: 1 = every source-less note is its own root; 2 = a source-less note repeating an
/// earlier source-less statement (same scope, privacy, epoch) shares that note's root, whoever can read it; 3 = the same,
/// but only a root every reader of the new note can read (`may_adopt_root`: a `local` root only by the same author, a
/// `resume:` root only by the same slot).
const LINEAGE_VERSION: &str = "3";

/// Rebuilds the derived `ancestry` table under the current lineage rule, from the events alone (it is not in the chain,
/// so no event is rewritten). A store written under any earlier rule ends up exactly as if it had been written note by
/// note by this build, and a second open finds the version marker and does nothing.
pub(super) fn upgrade_lineage(db: &mut Connection) -> Result<()> {
    let have: Option<String> = db
        .query_row("SELECT value FROM meta WHERE key = 'lineage'", [], |r| r.get(0))
        .optional()
        .map_err(sql)?;
    if have.as_deref() == Some(LINEAGE_VERSION) {
        return Ok(());
    }
    let tx = db.transaction().map_err(sql)?;
    let rows: Vec<(i64, String, String, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT seq, id, pubkey, raw FROM events WHERE kind = ?1 ORDER BY seq").map_err(sql)?;
        let rows = stmt
            .query_map(params![NOTE_KIND], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        rows
    };
    type Key = (Vec<u8>, String, String, i64);
    let mut roots_of: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // Source-less roots seen so far, per statement, in seq order: (root id, author, slot).
    let mut earlier: BTreeMap<Key, Vec<(String, String, Option<String>)>> = BTreeMap::new();
    let mut out: Vec<(i64, String)> = Vec::new();
    for (seq, id, author, raw) in rows {
        let event = Event::decode(&raw)?;
        let Ok(meta) = NoteMeta::parse(&event.tags, &event.content) else {
            // A note that does not parse keeps being its own root; recall refuses it on read anyway.
            roots_of.insert(id.clone(), BTreeSet::from([id.clone()]));
            out.push((seq, id.clone()));
            continue;
        };
        let mut roots: BTreeSet<String> = BTreeSet::new();
        for source in &meta.sources {
            if let Some(found) = roots_of.get(source) {
                roots.extend(found.iter().cloned());
            }
        }
        if roots.is_empty() {
            let key: Key = (meta.statement_hash.to_vec(), meta.scope.clone(), meta.privacy.wire().to_owned(), i64::from(meta.epoch));
            let list = earlier.entry(key).or_default();
            let adopted = list
                .iter()
                .find(|(_, by, slot)| may_adopt_root(meta.privacy.wire(), &author, meta.slot.as_deref(), by, slot.as_deref()))
                .map(|(root, _, _)| root.clone());
            match adopted {
                Some(root) => roots.insert(root),
                None => {
                    list.push((id.clone(), author.clone(), meta.slot.clone()));
                    roots.insert(id.clone())
                }
            };
        }
        for root in &roots {
            out.push((seq, root.clone()));
        }
        roots_of.insert(id, roots);
    }
    tx.execute("DELETE FROM ancestry", []).map_err(sql)?;
    for (seq, root) in out {
        tx.execute("INSERT OR IGNORE INTO ancestry(seq, root) VALUES (?1, ?2)", params![seq, root]).map_err(sql)?;
    }
    tx.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('lineage', ?1)", params![LINEAGE_VERSION]).map_err(sql)?;
    tx.commit().map_err(sql)
}

/// Fills the derived `supersede_links` table for a store written before it existed (it is derived from the events and
/// is not in the chain; the read path re-verifies every control event it relies on).
pub(super) fn upgrade_links(db: &mut Connection) -> Result<()> {
    let have: Option<String> = db
        .query_row("SELECT value FROM meta WHERE key = 'links'", [], |r| r.get(0))
        .optional()
        .map_err(sql)?;
    if have.is_some() {
        return Ok(());
    }
    let tx = db.transaction().map_err(sql)?;
    let rows: Vec<(String, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT id, raw FROM events WHERE kind = ?1 ORDER BY seq").map_err(sql)?;
        let rows = stmt
            .query_map(params![SUPERSEDE_KIND], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        rows
    };
    for (id, raw) in rows {
        let event = Event::decode(&raw)?;
        let target = single_tag(&event, "supersedes")?.to_owned();
        let replacement = single_tag(&event, "replacement").ok().map(str::to_owned);
        tx.execute("INSERT OR IGNORE INTO supersede_links(event_id, target, replacement) VALUES (?1, ?2, ?3)", params![id, target, replacement])
            .map_err(sql)?;
    }
    tx.execute("INSERT INTO meta(key, value) VALUES ('links', '1')", []).map_err(sql)?;
    tx.commit().map_err(sql)
}

/// Fills the derived `citations` table (which note cites which, and in what form) for a store written before it
/// existed. Like the other derived tables it is not in the chain; it only finds candidates, and a reader re-loads
/// and re-verifies every note it names.
pub(super) fn upgrade_citations(db: &mut Connection) -> Result<()> {
    let have: Option<String> = db
        .query_row("SELECT value FROM meta WHERE key = 'citations'", [], |r| r.get(0))
        .optional()
        .map_err(sql)?;
    if have.is_some() {
        return Ok(());
    }
    let tx = db.transaction().map_err(sql)?;
    let rows: Vec<(i64, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT seq, raw FROM events WHERE kind = ?1 ORDER BY seq").map_err(sql)?;
        let rows = stmt
            .query_map(params![NOTE_KIND], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        rows
    };
    for (seq, raw) in rows {
        let event = Event::decode(&raw)?;
        let Ok(meta) = NoteMeta::parse(&event.tags, &event.content) else { continue };
        for source in &meta.sources {
            tx.execute("INSERT OR IGNORE INTO citations(seq, source, form) VALUES (?1, ?2, ?3)", params![seq, source, meta.form.wire()])
                .map_err(sql)?;
        }
    }
    tx.execute("INSERT INTO meta(key, value) VALUES ('citations', '1')", []).map_err(sql)?;
    tx.commit().map_err(sql)
}


/// Gives a store written before the `capture` side column existed that column, and fills it from the signed events. Like
/// the other side columns it only finds candidates; recall re-checks the capture against the signed event it loads.
pub(super) fn upgrade_capture(db: &mut Connection) -> Result<()> {
    let tx = db.transaction().map_err(sql)?;
    let has: i64 = tx
        .query_row("SELECT count(*) FROM pragma_table_info('events') WHERE name = 'capture'", [], |r| r.get(0))
        .map_err(sql)?;
    if has == 0 {
        tx.execute("ALTER TABLE events ADD COLUMN capture TEXT", []).map_err(sql)?;
    }
    let rows: Vec<(i64, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT seq, raw FROM events WHERE kind = ?1 AND capture IS NULL").map_err(sql)?;
        let rows = stmt
            .query_map(params![NOTE_KIND], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        rows
    };
    for (seq, raw) in rows {
        let event = Event::decode(&raw)?;
        if let Ok(meta) = NoteMeta::parse(&event.tags, &event.content) {
            tx.execute("UPDATE events SET capture = ?1 WHERE seq = ?2", params![meta.capture.wire(), seq]).map_err(sql)?;
        }
    }
    tx.commit().map_err(sql)
}
