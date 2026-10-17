// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shared store: one SQLite file of signed NIP-01 events, an append chain over every event, keyword (FTS5) and
//! vector indexes as rebuildable side tables, and an author registry. Every returned note is re-verified, and so is
//! every supersede or quarantine event that changes how a note reads.

use super::note::{check_capture_lane, may_write_slot, NoteMeta, Review, NOTE_KIND, QUARANTINE_KIND, SUPERSEDE_KIND};
use canon::{Refusal, Result};
use nostr::{Event, VerifiedEvent};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

fn refuse(code: &'static str) -> Refusal {
    Refusal { organ: "kira", reason: code }
}

fn sql(_: rusqlite::Error) -> Refusal {
    refuse("store-sql")
}

const SCHEMA: &str = "
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS agents(
  pubkey TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL, owner INTEGER NOT NULL,
  revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, pubkey TEXT NOT NULL, created_at INTEGER NOT NULL,
  kind INTEGER NOT NULL, raw BLOB NOT NULL, chain BLOB NOT NULL, epoch INTEGER, scope TEXT, lane TEXT,
  privacy TEXT, slot TEXT, statement_hash BLOB, target TEXT);
CREATE INDEX IF NOT EXISTS events_target ON events(target);
CREATE INDEX IF NOT EXISTS events_slot ON events(slot);
CREATE TABLE IF NOT EXISTS ancestry(seq INTEGER NOT NULL, root TEXT NOT NULL, PRIMARY KEY(seq, root));
CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(body, tokenize='unicode61 remove_diacritics 2');
CREATE TABLE IF NOT EXISTS embeddings(seq INTEGER NOT NULL, model TEXT NOT NULL, vec BLOB NOT NULL,
  PRIMARY KEY(seq, model));
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// The chain format this build writes. v1 hashed (prev, id); v2 adds the seq and the signed created_at.
const CHAIN_VERSION: u8 = 2;

/// One registered author. `scopes` lists where it may write and read; `*` means every scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRecord {
    pub pubkey: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub owner: bool,
    pub revoked_at: Option<u64>,
}

/// A re-verified note with what the store knows about it.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredNote {
    pub seq: i64,
    pub event: Event,
    pub meta: NoteMeta,
    pub author_name: String,
    /// The author is registered as an owner (read from the agents table, never from a tag).
    pub author_owner: bool,
    pub roots: Vec<String>,
    /// The id of the supersede EVENT that retired this note (an audit pointer; `get` on it resolves to `current_id`).
    pub superseded_by: Option<String>,
    /// The id of the note that stands now: the replacement of the supersede, followed through any later supersede of
    /// the replacement itself. None for a live note, for a retraction (no replacement) and for a replacement cycle.
    pub current_id: Option<String>,
    pub quarantined: bool,
}

/// What the side columns say about one note of an epoch: used to share recall's places among authors before any
/// note is loaded. Recall re-checks the author against the signed event when it loads the note.
pub(crate) struct EpochNote {
    pub seq: i64,
    pub pubkey: String,
    pub lane: String,
    pub owner: bool,
    pub scope: String,
    pub privacy: String,
}

pub struct SharedStore {
    db: Connection,
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn single_tag<'a>(event: &'a Event, name: &str) -> Result<&'a str> {
    let mut found = None;
    for tag in &event.tags {
        if tag.first().map(String::as_str) == Some(name) {
            if found.is_some() || tag.len() != 2 {
                return Err(refuse("event-tag-shape"));
            }
            found = Some(tag[1].as_str());
        }
    }
    found.ok_or_else(|| refuse("event-tag-missing"))
}

/// One chain link. v2: H(domain ‖ prev ‖ seq ‖ id ‖ created_at), integers as 8 big-endian bytes, so moving a row,
/// renumbering it or changing its time breaks the chain. v1 is kept only to check a store before upgrading it.
fn link(version: u8, prev: &[u8; 32], seq: i64, id: &[u8; 32], created_at: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    if version == 1 {
        h.update(b"aukora:kira:chain:v1\0");
        h.update(prev);
        h.update(id);
    } else {
        h.update(b"aukora:kira:chain:v2\0");
        h.update(prev);
        h.update(seq.to_be_bytes());
        h.update(id);
        h.update(created_at.to_be_bytes());
    }
    h.finalize().into()
}

/// An events row as stored.
struct Row {
    seq: i64,
    id: String,
    pubkey: String,
    created_at: i64,
    kind: i64,
    raw: Vec<u8>,
    chain: Vec<u8>,
}

const ROW: &str = "SELECT seq, id, pubkey, created_at, kind, raw, chain FROM events";

fn row_of(r: &rusqlite::Row) -> rusqlite::Result<Row> {
    Ok(Row {
        seq: r.get(0)?,
        id: r.get(1)?,
        pubkey: r.get(2)?,
        created_at: r.get(3)?,
        kind: r.get(4)?,
        raw: r.get(5)?,
        chain: r.get(6)?,
    })
}

/// The stored bytes must be a correctly signed event whose id, author, time and kind match the row's columns, and
/// whose chain link follows `prev`. Returns the event and its link.
fn check_row(row: &Row, prev: &[u8; 32], version: u8) -> Result<(Event, [u8; 32])> {
    let bad = || refuse("note-integrity");
    let event = Event::decode(&row.raw).and_then(Event::verify).map_err(|_| bad())?.event().clone();
    let agrees = hex32(event.id.as_bytes()) == row.id
        && hex32(event.pubkey.as_bytes()) == row.pubkey
        && i64::try_from(event.created_at).ok() == Some(row.created_at)
        && i64::from(event.kind) == row.kind;
    let next = link(version, prev, row.seq, event.id.as_bytes(), event.created_at);
    if !agrees || next.as_slice() != row.chain.as_slice() {
        return Err(bad());
    }
    Ok((event, next))
}

/// Walks every row in seq order under one chain version; returns the (seq, link) pairs.
fn walk(db: &Connection, version: u8) -> Result<Vec<(i64, [u8; 32])>> {
    let mut stmt = db.prepare(&format!("{ROW} ORDER BY seq")).map_err(sql)?;
    let rows = stmt.query_map([], row_of).map_err(sql)?;
    let (mut prev, mut links) = ([0u8; 32], Vec::new());
    for row in rows {
        let row = row.map_err(sql)?;
        let (_, next) = check_row(&row, &prev, version).map_err(|_| refuse("store-chain-broken"))?;
        links.push((row.seq, next));
        prev = next;
    }
    Ok(links)
}

/// Upgrades a v1 chain to v2, only when the whole v1 chain verifies first (signatures, columns and links). A store
/// whose v1 chain does not verify is left as it is, so it fails verification under v2 and the service refuses it.
fn upgrade_chain(db: &mut Connection) -> Result<()> {
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

impl SharedStore {
    pub fn open(path: &Path) -> Result<Self> {
        let mut db = Connection::open(path).map_err(sql)?;
        db.execute_batch(SCHEMA).map_err(sql)?;
        upgrade_chain(&mut db)?;
        Ok(Self { db })
    }

    pub fn open_in_memory() -> Result<Self> {
        let mut db = Connection::open_in_memory().map_err(sql)?;
        db.execute_batch(SCHEMA).map_err(sql)?;
        upgrade_chain(&mut db)?;
        Ok(Self { db })
    }

    // ---------- registry ----------

    pub fn register_agent(&self, name: &str, pubkey_hex: &str, scopes: &[String], owner: bool) -> Result<()> {
        if name.is_empty() || pubkey_hex.len() != 64 || scopes.is_empty() {
            return Err(refuse("agent-record"));
        }
        let scopes = serde_json::to_string(scopes).map_err(|_| refuse("agent-record"))?;
        self.db
            .execute(
                "INSERT INTO agents(pubkey, name, scopes, owner, revoked_at) VALUES (?1, ?2, ?3, ?4, NULL)",
                params![pubkey_hex, name, scopes, owner as i64],
            )
            .map_err(|_| refuse("agent-exists"))?;
        Ok(())
    }

    /// Whether any agent, revoked or not, was ever registered as an owner.
    pub fn has_owner(&self) -> Result<bool> {
        let owners: i64 = self.db.query_row("SELECT count(*) FROM agents WHERE owner = 1", [], |r| r.get(0)).map_err(sql)?;
        Ok(owners > 0)
    }

    /// Marks an agent revoked at `at` (an earlier revocation time stands). It can no longer write or authenticate;
    /// its notes stay readable (quarantine is the separate act that withdraws them).
    pub fn revoke_agent(&self, name: &str, at: u64) -> Result<()> {
        let at = i64::try_from(at).map_err(|_| refuse("agent-record"))?;
        let changed = self
            .db
            .execute("UPDATE agents SET revoked_at = COALESCE(revoked_at, ?1) WHERE name = ?2", params![at, name])
            .map_err(sql)?;
        if changed == 0 {
            return Err(refuse("agent-unknown"));
        }
        Ok(())
    }

    pub fn agent(&self, pubkey_hex: &str) -> Result<Option<AgentRecord>> {
        self.db
            .query_row(
                "SELECT pubkey, name, scopes, owner, revoked_at FROM agents WHERE pubkey = ?1",
                params![pubkey_hex],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(sql)?
            .map(|(pubkey, name, scopes, owner, revoked)| {
                Ok(AgentRecord {
                    pubkey,
                    name,
                    scopes: serde_json::from_str(&scopes).map_err(|_| refuse("agent-record"))?,
                    owner: owner != 0,
                    revoked_at: revoked.map(|t| t as u64),
                })
            })
            .transpose()
    }

    fn is_owner(&self, pubkey_hex: &str) -> Result<bool> {
        Ok(self.agent(pubkey_hex)?.is_some_and(|a| a.owner))
    }

    // ---------- verified rows ----------

    /// The chain link of the row just before `seq` (zero for the first row).
    fn prev_link(&self, seq: i64) -> Result<[u8; 32]> {
        let prev: Option<Vec<u8>> = self
            .db
            .query_row("SELECT chain FROM events WHERE seq < ?1 ORDER BY seq DESC LIMIT 1", params![seq], |r| r.get(0))
            .optional()
            .map_err(sql)?;
        match prev {
            None => Ok([0u8; 32]),
            Some(b) => b.try_into().map_err(|_| refuse("note-integrity")),
        }
    }

    /// Rows of one control kind aimed at `target`, oldest first, each re-verified (signature, columns, chain link).
    fn verified_controls(&self, kind: u16, target: &str) -> Result<Vec<(Row, Event)>> {
        let mut stmt = self.db.prepare(&format!("{ROW} WHERE kind = ?1 AND target = ?2 ORDER BY seq")).map_err(sql)?;
        let rows = stmt
            .query_map(params![kind, target], row_of)
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        rows.into_iter()
            .map(|row| {
                let (event, _) = check_row(&row, &self.prev_link(row.seq)?, CHAIN_VERSION)?;
                Ok((row, event))
            })
            .collect()
    }

    /// Whether a verified, owner-signed quarantine names this source. The `target` column only finds candidates: the
    /// signed `source` tag and the signer's owner flag decide, and a row that fails either is an integrity failure.
    fn quarantined(&self, pubkey_hex: &str) -> Result<bool> {
        let controls = self.verified_controls(QUARANTINE_KIND, pubkey_hex)?;
        for (row, event) in &controls {
            if single_tag(event, "source")? != pubkey_hex || !self.is_owner(&row.pubkey)? {
                return Err(refuse("note-integrity"));
            }
        }
        Ok(!controls.is_empty())
    }

    /// The verified supersede of note `id_hex` (written by `author`) that retired it: (event id, replacement note id).
    /// Each is signed by that author or the owner.
    fn superseded_by(&self, id_hex: &str, author: &str) -> Result<Option<(String, Option<String>)>> {
        let controls = self.verified_controls(SUPERSEDE_KIND, id_hex)?;
        for (row, event) in &controls {
            if single_tag(event, "supersedes")? != id_hex || (row.pubkey != author && !self.is_owner(&row.pubkey)?) {
                return Err(refuse("note-integrity"));
            }
        }
        Ok(controls.into_iter().next().map(|(row, event)| (row.id, single_tag(&event, "replacement").ok().map(str::to_owned))))
    }

    /// The note that stands where `id_hex` once did: its replacement, and that note's replacement if it was itself
    /// superseded, and so on. None when `id_hex` is not superseded, was retracted without a replacement, or the chain
    /// loops back on itself.
    fn current_of(&self, id_hex: &str) -> Result<Option<String>> {
        let (mut here, mut seen) = (id_hex.to_owned(), BTreeSet::from([id_hex.to_owned()]));
        loop {
            let author: Option<String> = self
                .db
                .query_row("SELECT pubkey FROM events WHERE id = ?1 AND kind = ?2", params![here, NOTE_KIND], |r| r.get(0))
                .optional()
                .map_err(sql)?;
            let Some(author) = author else { return Ok(None) };
            match self.superseded_by(&here, &author)? {
                None => return Ok((here != id_hex).then_some(here)),
                Some((_, None)) => return Ok(None),
                Some((_, Some(next))) => {
                    if !seen.insert(next.clone()) {
                        return Ok(None);
                    }
                    here = next;
                }
            }
        }
    }

    /// The note an event id stands for: for a supersede event, the note that stands now where its target was. None for
    /// anything else (a quarantine, an unknown id, a retraction).
    pub fn current_for_event(&self, event_id: &str) -> Result<Option<String>> {
        let target: Option<String> = self
            .db
            .query_row("SELECT target FROM events WHERE id = ?1 AND kind = ?2", params![event_id, SUPERSEDE_KIND], |r| r.get(0))
            .optional()
            .map_err(sql)?
            .flatten();
        match target {
            Some(target) => self.current_of(&target),
            None => Ok(None),
        }
    }

    // ---------- append ----------

    /// Append one verified event. Checks the author's registration, scope, review claim, and the kind's rules.
    pub fn append(&mut self, verified: VerifiedEvent) -> Result<StoredNote> {
        let event = verified.event().clone();
        let author = hex32(event.pubkey.as_bytes());
        let id = hex32(event.id.as_bytes());
        let agent = self.agent(&author)?.ok_or_else(|| refuse("author-unregistered"))?;
        if agent.revoked_at.is_some() {
            return Err(refuse("author-revoked"));
        }
        if self.quarantined(&author)? {
            return Err(refuse("author-quarantined"));
        }
        let raw = event.encode()?;
        let created_at = i64::try_from(event.created_at).map_err(|_| refuse("event-time"))?;
        let tx = self.db.transaction().map_err(sql)?;
        let last: Option<(i64, Vec<u8>)> = tx
            .query_row("SELECT seq, chain FROM events ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
            .map_err(sql)?;
        let (seq, prev): (i64, [u8; 32]) = match last {
            None => (1, [0u8; 32]),
            Some((s, b)) => (s + 1, b.try_into().map_err(|_| refuse("store-chain"))?),
        };
        let chain = link(CHAIN_VERSION, &prev, seq, event.id.as_bytes(), event.created_at).to_vec();
        let exists: i64 = tx
            .query_row("SELECT count(*) FROM events WHERE id = ?1", params![id], |r| r.get(0))
            .map_err(sql)?;
        if exists > 0 {
            return Err(refuse("note-duplicate"));
        }
        match event.kind {
            NOTE_KIND => {
                let meta = NoteMeta::parse(&event.tags, &event.content)?;
                let allowed = agent.scopes.iter().any(|s| s == "*" || s == &meta.scope);
                if !allowed {
                    return Err(refuse("scope-refused"));
                }
                if meta.review == Review::OwnerSigned && !agent.owner {
                    return Err(refuse("review-claim-refused"));
                }
                // Lanes by whitelist: commitments, the self file and the resume hold only the owner's own words.
                check_capture_lane(meta.capture, meta.lane)?;
                if meta.lane.owner_only() && !agent.owner {
                    return Err(refuse("note-capture-lane"));
                }
                if meta.slot.as_deref().is_some_and(|slot| !may_write_slot(slot, &agent.name, agent.owner)) {
                    return Err(refuse("slot-refused"));
                }
                // Ancestry is computed here, from notes the store holds; a tag cannot declare independence.
                let mut roots = BTreeSet::new();
                for source in &meta.sources {
                    let src_seq: Option<i64> = tx
                        .query_row("SELECT seq FROM events WHERE id = ?1 AND kind = ?2", params![source, NOTE_KIND], |r| r.get(0))
                        .optional()
                        .map_err(sql)?;
                    let src_seq = src_seq.ok_or_else(|| refuse("note-source-unknown"))?;
                    let mut stmt = tx.prepare("SELECT root FROM ancestry WHERE seq = ?1").map_err(sql)?;
                    let found = stmt
                        .query_map(params![src_seq], |r| r.get::<_, String>(0))
                        .map_err(sql)?
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(sql)?;
                    roots.extend(found);
                }
                if roots.is_empty() {
                    roots.insert(id.clone());
                }
                tx.execute(
                    "INSERT INTO events(seq, id, pubkey, created_at, kind, raw, chain, epoch, scope, lane, privacy, slot, statement_hash, target)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL)",
                    params![
                        seq, id, author, created_at, NOTE_KIND, raw, chain, meta.epoch as i64, meta.scope,
                        meta.lane.wire(), meta.privacy.wire(), meta.slot, meta.statement_hash.to_vec()
                    ],
                )
                .map_err(sql)?;
                tx.execute("INSERT INTO fts(rowid, body) VALUES (?1, ?2)", params![seq, event.content]).map_err(sql)?;
                for root in &roots {
                    tx.execute("INSERT INTO ancestry(seq, root) VALUES (?1, ?2)", params![seq, root]).map_err(sql)?;
                }
                tx.commit().map_err(sql)?;
            }
            SUPERSEDE_KIND => {
                let target = single_tag(&event, "supersedes")?.to_owned();
                let replacement = single_tag(&event, "replacement").ok().map(str::to_owned);
                let original: Option<String> = tx
                    .query_row("SELECT pubkey FROM events WHERE id = ?1 AND kind = ?2", params![target, NOTE_KIND], |r| r.get(0))
                    .optional()
                    .map_err(sql)?;
                let original = original.ok_or_else(|| refuse("supersede-target-unknown"))?;
                if original != author && !agent.owner {
                    return Err(refuse("supersede-not-author"));
                }
                if let Some(rep) = &replacement {
                    let ok: i64 = tx
                        .query_row("SELECT count(*) FROM events WHERE id = ?1 AND kind = ?2", params![rep, NOTE_KIND], |r| r.get(0))
                        .map_err(sql)?;
                    if ok == 0 {
                        return Err(refuse("supersede-replacement-unknown"));
                    }
                }
                tx.execute(
                    "INSERT INTO events(seq, id, pubkey, created_at, kind, raw, chain, target) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![seq, id, author, created_at, SUPERSEDE_KIND, raw, chain, target],
                )
                .map_err(sql)?;
                tx.commit().map_err(sql)?;
            }
            QUARANTINE_KIND => {
                if !agent.owner {
                    return Err(refuse("quarantine-owner-only"));
                }
                let source = single_tag(&event, "source")?.to_owned();
                tx.execute(
                    "INSERT INTO events(seq, id, pubkey, created_at, kind, raw, chain, target) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![seq, id, author, created_at, QUARANTINE_KIND, raw, chain, source],
                )
                .map_err(sql)?;
                tx.commit().map_err(sql)?;
            }
            _ => return Err(refuse("event-kind")),
        }
        if event.kind == NOTE_KIND {
            return self.get(&id)?.ok_or_else(|| refuse("store-sql"));
        }
        Err(refuse("event-recorded-not-a-note"))
    }

    /// Record a supersede or quarantine event; returns its id.
    pub fn record(&mut self, verified: VerifiedEvent) -> Result<String> {
        let id = hex32(verified.event().id.as_bytes());
        match self.append(verified) {
            Err(Refusal { reason: "event-recorded-not-a-note", .. }) => Ok(id),
            Err(other) => Err(other),
            Ok(note) => Ok(hex32(note.event.id.as_bytes())),
        }
    }

    // ---------- read ----------

    fn load(&self, seq: i64) -> Result<Option<StoredNote>> {
        let row = self.db.query_row(&format!("{ROW} WHERE seq = ?1"), params![seq], row_of).optional().map_err(sql)?;
        let Some(row) = row else { return Ok(None) };
        if row.kind != i64::from(NOTE_KIND) {
            return Ok(None);
        }
        // Verify on read: a correctly signed event matching its columns and its chain link.
        let (event, _) = check_row(&row, &self.prev_link(seq)?, CHAIN_VERSION)?;
        let meta = NoteMeta::parse(&event.tags, &event.content)?;
        let (author_name, author_owner): (String, bool) = self
            .db
            .query_row("SELECT name, owner FROM agents WHERE pubkey = ?1", params![row.pubkey], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0))
            })
            .optional()
            .map_err(sql)?
            .unwrap_or_else(|| ("unknown".into(), false));
        let mut stmt = self.db.prepare("SELECT root FROM ancestry WHERE seq = ?1 ORDER BY root").map_err(sql)?;
        let roots = stmt
            .query_map(params![seq], |r| r.get::<_, String>(0))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        let retired = self.superseded_by(&row.id, &row.pubkey)?;
        let current_id = if retired.is_some() { self.current_of(&row.id)? } else { None };
        let superseded_by = retired.map(|(event, _)| event);
        let quarantined = self.quarantined(&row.pubkey)?;
        Ok(Some(StoredNote { seq, event, meta, author_name, author_owner, roots, superseded_by, current_id, quarantined }))
    }

    pub fn get(&self, id_hex: &str) -> Result<Option<StoredNote>> {
        let seq: Option<i64> = self
            .db
            .query_row("SELECT seq FROM events WHERE id = ?1", params![id_hex], |r| r.get(0))
            .optional()
            .map_err(sql)?;
        match seq {
            Some(seq) => self.load(seq),
            None => Ok(None),
        }
    }

    pub fn note_by_seq(&self, seq: i64) -> Result<Option<StoredNote>> {
        self.load(seq)
    }

    /// Newest live note in a fixed slot (`d` tag), e.g. the owner's self file. A note whose author may not write that
    /// slot (one stored before append checked it) is passed over, never returned.
    pub fn slot(&self, slot: &str) -> Result<Option<StoredNote>> {
        let mut stmt = self
            .db
            .prepare("SELECT seq FROM events WHERE kind = ?1 AND slot = ?2 ORDER BY seq DESC")
            .map_err(sql)?;
        let seqs = stmt
            .query_map(params![NOTE_KIND, slot], |r| r.get::<_, i64>(0))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        for seq in seqs {
            if let Some(note) = self.load(seq)? {
                if note.superseded_by.is_none() && !note.quarantined && may_write_slot(slot, &note.author_name, note.author_owner) {
                    return Ok(Some(note));
                }
            }
        }
        Ok(None)
    }

    /// Newest notes first, live or not; callers filter. `before` is an exclusive seq cursor.
    pub fn list_recent(&self, limit: usize, before: Option<i64>, epoch: Option<u32>) -> Result<Vec<StoredNote>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT seq FROM events WHERE kind = ?1 AND seq < ?2 AND (?3 IS NULL OR epoch = ?3)
                 ORDER BY seq DESC LIMIT ?4",
            )
            .map_err(sql)?;
        let seqs = stmt
            .query_map(
                params![NOTE_KIND, before.unwrap_or(i64::MAX), epoch.map(|e| e as i64), limit.min(500) as i64],
                |r| r.get::<_, i64>(0),
            )
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        seqs.into_iter().filter_map(|s| self.load(s).transpose()).collect()
    }

    /// Walk the whole append chain, re-verifying every event's signature, columns and link; returns the number of
    /// events checked. Any mismatch is `store-chain-broken`.
    pub fn verify_chain(&self) -> Result<u64> {
        Ok(walk(&self.db, CHAIN_VERSION)?.len() as u64)
    }

    // ---------- index access for recall ----------

    /// Keyword search: (seq, bm25) with lower bm25 = better. Query words are quoted, so no FTS syntax is injectable.
    pub fn keyword(&self, query: &str, limit: usize) -> Result<Vec<(i64, f64)>> {
        let words: Vec<String> = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.chars().count() > 1)
            .map(|w| format!("\"{}\"", w.to_lowercase()))
            .collect();
        if words.is_empty() {
            return Ok(Vec::new());
        }
        let expr = words.join(" OR ");
        let mut stmt = self
            .db
            .prepare("SELECT rowid, bm25(fts) FROM fts WHERE fts MATCH ?1 ORDER BY bm25(fts) LIMIT ?2")
            .map_err(sql)?;
        let rows = stmt
            .query_map(params![expr, limit as i64], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?)))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        Ok(rows)
    }

    pub fn put_embedding(&self, seq: i64, model: &str, vector: &[f32]) -> Result<()> {
        let bytes: Vec<u8> = vector.iter().flat_map(|f| f.to_le_bytes()).collect();
        self.db
            .execute(
                "INSERT OR REPLACE INTO embeddings(seq, model, vec) VALUES (?1, ?2, ?3)",
                params![seq, model, bytes],
            )
            .map_err(sql)?;
        Ok(())
    }

    /// Note seqs (with text) that have no vector under `model`.
    pub fn missing_embeddings(&self, model: &str, limit: usize) -> Result<Vec<(i64, String)>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT e.seq, f.body FROM events e JOIN fts f ON f.rowid = e.seq
                 WHERE e.kind = ?1 AND NOT EXISTS (SELECT 1 FROM embeddings m WHERE m.seq = e.seq AND m.model = ?2)
                 ORDER BY e.seq LIMIT ?3",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map(params![NOTE_KIND, model, limit as i64], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        Ok(rows)
    }

    pub fn embeddings(&self, model: &str) -> Result<Vec<(i64, Vec<f32>)>> {
        let mut stmt = self.db.prepare("SELECT seq, vec FROM embeddings WHERE model = ?1").map_err(sql)?;
        let rows = stmt
            .query_map(params![model], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        Ok(rows
            .into_iter()
            .map(|(seq, bytes)| {
                (seq, bytes.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
            })
            .collect())
    }

    /// Every note of one epoch with its author, owner flag and lane, read from the side columns so recall can filter
    /// and share places among authors before loading. Recall re-verifies each note it uses and checks these columns
    /// against the signed event.
    pub(crate) fn note_authors_in_epoch(&self, epoch: u32) -> Result<Vec<EpochNote>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT e.seq, e.pubkey, e.lane, COALESCE(a.owner, 0), e.scope, e.privacy FROM events e LEFT JOIN agents a ON a.pubkey = e.pubkey
                 WHERE e.kind = ?1 AND e.epoch = ?2 ORDER BY e.seq",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map(params![NOTE_KIND, epoch as i64], |r| {
                Ok(EpochNote {
                    seq: r.get(0)?,
                    pubkey: r.get(1)?,
                    lane: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    owner: r.get::<_, i64>(3)? != 0,
                    scope: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    privacy: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                })
            })
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        Ok(rows)
    }

    /// The seqs that have a vector under `model`.
    pub fn embedded_seqs(&self, model: &str) -> Result<BTreeSet<i64>> {
        let mut stmt = self.db.prepare("SELECT seq FROM embeddings WHERE model = ?1").map_err(sql)?;
        let rows = stmt
            .query_map(params![model], |r| r.get::<_, i64>(0))
            .map_err(sql)?
            .collect::<std::result::Result<BTreeSet<_>, _>>()
            .map_err(sql)?;
        Ok(rows)
    }

    /// (notes with a vector under `model`, all notes) in one epoch, for coverage of the WHOLE store. Recall does not
    /// use it: it counts only what its caller may see (an owner's local note must not move a builder's counts).
    pub fn coverage(&self, model: &str, epoch: u32) -> Result<(u64, u64)> {
        let total: i64 = self
            .db
            .query_row("SELECT count(*) FROM events WHERE kind = ?1 AND epoch = ?2", params![NOTE_KIND, epoch as i64], |r| r.get(0))
            .map_err(sql)?;
        let indexed: i64 = self
            .db
            .query_row(
                "SELECT count(*) FROM events e JOIN embeddings m ON m.seq = e.seq AND m.model = ?3
                 WHERE e.kind = ?1 AND e.epoch = ?2",
                params![NOTE_KIND, epoch as i64, model],
                |r| r.get(0),
            )
            .map_err(sql)?;
        Ok((indexed as u64, total as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::super::note::*;
    use super::*;
    use nostr::SecretKey;

    fn key() -> SecretKey {
        SecretKey::generate().unwrap()
    }

    fn pub_hex(k: &SecretKey) -> String {
        hex32(k.public_key().unwrap().as_bytes())
    }

    fn draft(text: &str, scope: &str) -> NoteDraft {
        NoteDraft {
            text: text.into(),
            subject: "test".into(),
            scope: scope.into(),
            lane: Lane::Evidence,
            form: Form::Fact,
            privacy: Privacy::Builders,
            capture: Capture::ToolObserved,
            sources: vec![],
            slot: None,
            valid_from: None,
            valid_to: None,
            epoch: 2,
        }
    }

    fn sign(k: &SecretKey, d: &NoteDraft, review: Review, at: u64) -> VerifiedEvent {
        Event::sign(k, at, NOTE_KIND, d.tags(review).unwrap(), d.text.clone()).unwrap()
    }

    fn store_with(agents: &[(&str, &SecretKey, &[&str], bool)]) -> SharedStore {
        let s = SharedStore::open_in_memory().unwrap();
        for (name, k, scopes, owner) in agents {
            let scopes: Vec<String> = scopes.iter().map(|x| x.to_string()).collect();
            s.register_agent(name, &pub_hex(k), &scopes, *owner).unwrap();
        }
        s
    }

    #[test]
    fn a_writes_b_finds_with_author() {
        let (a, b) = (key(), key());
        let mut s = store_with(&[("claude", &a, &["builders"], false), ("grok", &b, &["builders"], false)]);
        let note = s.append(sign(&a, &draft("The figurine is on the left shelf", "builders"), Review::Remembered, 10)).unwrap();
        let hits = s.keyword("where is the figurine", 5).unwrap();
        assert_eq!(hits.len(), 1);
        let found = s.note_by_seq(hits[0].0).unwrap().unwrap();
        assert_eq!(found.author_name, "claude");
        assert_eq!(found.event.id, note.event.id);
    }

    #[test]
    fn unregistered_scope_and_review_claims_refuse() {
        let (a, stranger) = (key(), key());
        let mut s = store_with(&[("claude", &a, &["builders"], false)]);
        assert!(s.append(sign(&stranger, &draft("x y", "builders"), Review::Remembered, 1)).is_err());
        assert!(s.append(sign(&a, &draft("x y", "owner"), Review::Remembered, 1)).is_err());
        assert!(s.append(sign(&a, &draft("x y", "builders"), Review::OwnerSigned, 1)).is_err());
    }

    #[test]
    fn tampered_row_is_refused_on_read_and_chain() {
        let a = key();
        let mut s = store_with(&[("claude", &a, &["builders"], false)]);
        let note = s.append(sign(&a, &draft("original words here", "builders"), Review::Remembered, 5)).unwrap();
        let mut ev = note.event.clone();
        ev.content = "forged words here".into();
        let forged = ev.encode().unwrap();
        s.db.execute("UPDATE events SET raw = ?1 WHERE seq = ?2", params![forged, note.seq]).unwrap();
        assert!(s.note_by_seq(note.seq).is_err());
    }

    #[test]
    fn supersede_and_quarantine() {
        let (owner, a) = (key(), key());
        let mut s = store_with(&[("peter", &owner, &["*"], true), ("agent", &a, &["builders"], false)]);
        let old = s.append(sign(&a, &draft("plan uses tiny harness", "builders"), Review::Remembered, 1)).unwrap();
        let new = s.append(sign(&a, &draft("plan uses the deepseek harness", "builders"), Review::Remembered, 2)).unwrap();
        let old_id = hex32(old.event.id.as_bytes());
        let new_id = hex32(new.event.id.as_bytes());
        let sup = Event::sign(&a, 3, SUPERSEDE_KIND, vec![vec!["supersedes".into(), old_id.clone()], vec!["replacement".into(), new_id]], String::new()).unwrap();
        s.record(sup).unwrap();
        assert!(s.get(&old_id).unwrap().unwrap().superseded_by.is_some());
        // Only the owner may quarantine a source; afterwards that source can no longer write.
        let q = Event::sign(&a, 4, QUARANTINE_KIND, vec![vec!["source".into(), pub_hex(&a)]], String::new()).unwrap();
        assert!(s.record(q).is_err());
        let q = Event::sign(&owner, 4, QUARANTINE_KIND, vec![vec!["source".into(), pub_hex(&a)]], String::new()).unwrap();
        s.record(q).unwrap();
        assert!(s.get(&old_id).unwrap().unwrap().quarantined);
        assert!(s.append(sign(&a, &draft("after quarantine", "builders"), Review::Remembered, 5)).is_err());
        assert_eq!(s.verify_chain().unwrap(), 4);
    }

    #[test]
    fn ancestry_is_computed_not_declared() {
        let a = key();
        let mut s = store_with(&[("agent", &a, &["builders"], false)]);
        let root = s.append(sign(&a, &draft("one observation", "builders"), Review::Remembered, 1)).unwrap();
        let root_id = hex32(root.event.id.as_bytes());
        let mut d = draft("a restatement of it", "builders");
        d.sources = vec![root_id.clone()];
        let child = s.append(sign(&a, &d, Review::Remembered, 2)).unwrap();
        assert_eq!(child.roots, vec![root_id]);
        let mut fake = draft("claims an unknown source", "builders");
        fake.sources = vec!["ab".repeat(32)];
        assert!(s.append(sign(&a, &fake, Review::Remembered, 3)).is_err());
    }

    #[test]
    fn commitment_lanes_take_only_the_owners_words() {
        let (owner, a) = (key(), key());
        let mut s = store_with(&[("peter", &owner, &["*"], true), ("agent", &a, &["builders"], false)]);
        let mut d = draft("the figurine stays on the left shelf", "builders");
        d.lane = Lane::Decision;
        d.capture = Capture::OwnerTyped;
        // An owner-class capture signed by an agent's own key still cannot enter a commitment lane.
        assert_eq!(s.append(sign(&a, &d, Review::Remembered, 1)).err(), Some(refuse("note-capture-lane")));
        s.append(sign(&owner, &d, Review::Remembered, 1)).unwrap();
        // A hand-built event that skips NoteDraft::tags is refused by the store's own whitelist check.
        let mut tags = draft("x y", "builders").tags(Review::Remembered).unwrap();
        tags.retain(|t| t[0] != Lane::TAG);
        tags.push(vec![Lane::TAG.into(), "resume".into()]);
        let forged = Event::sign(&owner, 2, NOTE_KIND, tags, "x y".into()).unwrap();
        assert_eq!(s.append(forged).err(), Some(refuse("note-capture-lane")));
    }

    #[test]
    fn slots_take_only_their_writers_and_read_the_newest_live_one() {
        let (owner, a) = (key(), key());
        let mut s = store_with(&[("peter", &owner, &["*"], true), ("grok", &a, &["builders"], false)]);
        let mut d = draft("I am Auma", "builders");
        d.slot = Some(SELF_SLOT.into());
        assert_eq!(s.append(sign(&a, &d, Review::Remembered, 1)).err(), Some(refuse("slot-refused")));
        d.slot = Some("resume:claude".into());
        assert_eq!(s.append(sign(&a, &d, Review::Remembered, 1)).err(), Some(refuse("slot-refused")));
        d.slot = Some("resume:grok".into());
        let first = s.append(sign(&a, &d, Review::Remembered, 2)).unwrap();
        d.text = "grok resumes at row 9".into();
        let second = s.append(sign(&a, &d, Review::Remembered, 3)).unwrap();
        assert_eq!(s.slot("resume:grok").unwrap().unwrap().event.id, second.event.id);
        // The newest is superseded: the one before it is the head again.
        let sup = Event::sign(&a, 4, SUPERSEDE_KIND, vec![vec!["supersedes".into(), hex32(second.event.id.as_bytes())]], String::new()).unwrap();
        s.record(sup).unwrap();
        assert_eq!(s.slot("resume:grok").unwrap().unwrap().event.id, first.event.id);
        // A slot note stored before append checked the writer (simulated: grok was briefly an owner) is never the head.
        let mine = s.append(sign(&owner, &{ let mut o = draft("I am Auma, the owner wrote this", "builders"); o.slot = Some(SELF_SLOT.into()); o }, Review::Remembered, 5)).unwrap();
        s.db.execute("UPDATE agents SET owner = 1 WHERE name = 'grok'", []).unwrap();
        d.slot = Some(SELF_SLOT.into());
        d.text = "I am Grok now".into();
        s.append(sign(&a, &d, Review::Remembered, 6)).unwrap();
        s.db.execute("UPDATE agents SET owner = 0 WHERE name = 'grok'", []).unwrap();
        assert_eq!(s.slot(SELF_SLOT).unwrap().unwrap().event.id, mine.event.id);
        assert!(s.slot(RESUME_SLOT).unwrap().is_none());
    }

    #[test]
    fn chain_binds_seq_and_time_and_control_rows_are_verified() {
        let (owner, a, b) = (key(), key(), key());
        let mut s = store_with(&[("peter", &owner, &["*"], true), ("a", &a, &["builders"], false), ("b", &b, &["builders"], false)]);
        let one = s.append(sign(&a, &draft("first note here", "builders"), Review::Remembered, 1)).unwrap();
        let two = s.append(sign(&b, &draft("second note here", "builders"), Review::Remembered, 2)).unwrap();
        assert_eq!(s.verify_chain().unwrap(), 2);
        // Changing a row's time column breaks both the read and the chain walk.
        s.db.execute("UPDATE events SET created_at = 9 WHERE seq = ?1", params![one.seq]).unwrap();
        assert!(s.note_by_seq(one.seq).is_err());
        assert_eq!(s.verify_chain().err(), Some(refuse("store-chain-broken")));
        s.db.execute("UPDATE events SET created_at = 1 WHERE seq = ?1", params![one.seq]).unwrap();
        // A forged quarantine row (a column pointed at b, a raw event that is not a signed quarantine) is caught on
        // read instead of silently quarantining b.
        let q = Event::sign(&owner, 3, QUARANTINE_KIND, vec![vec!["source".into(), pub_hex(&a)]], String::new()).unwrap();
        s.record(q).unwrap();
        assert!(s.get(&hex32(one.event.id.as_bytes())).unwrap().unwrap().quarantined);
        s.db.execute("UPDATE events SET target = ?1 WHERE kind = ?2", params![pub_hex(&b), QUARANTINE_KIND]).unwrap();
        assert!(s.note_by_seq(two.seq).is_err());
        // A store from before v2 whose v1 chain verifies is upgraded in place on open.
        let path = std::env::temp_dir().join(format!("kira-chain-{}.sqlite", pub_hex(&key())));
        {
            let mut old = SharedStore::open(&path).unwrap();
            old.register_agent("a", &pub_hex(&a), &["builders".into()], false).unwrap();
            let n = old.append(sign(&a, &draft("an old note", "builders"), Review::Remembered, 4)).unwrap();
            let v1 = link(1, &[0u8; 32], n.seq, n.event.id.as_bytes(), 4);
            old.db.execute("UPDATE events SET chain = ?1", params![v1.to_vec()]).unwrap();
            old.db.execute("DELETE FROM meta", []).unwrap();
            assert!(old.verify_chain().is_err());
        }
        assert_eq!(SharedStore::open(&path).unwrap().verify_chain().unwrap(), 1);
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.clone().into_os_string();
            name.push(suffix);
            let _ = std::fs::remove_file(name);
        }
    }
}
