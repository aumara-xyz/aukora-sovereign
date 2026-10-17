// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shared store: one SQLite file of signed NIP-01 events, an append chain over every id, keyword (FTS5) and
//! vector indexes as rebuildable side tables, and an author registry. Every returned note is re-verified.

use super::note::{NoteMeta, Review, NOTE_KIND, QUARANTINE_KIND, SUPERSEDE_KIND};
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
";

/// One registered author. `scopes` lists where it may write; `*` means every scope.
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
    pub roots: Vec<String>,
    pub superseded_by: Option<String>,
    pub quarantined: bool,
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

impl SharedStore {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path).map_err(sql)?;
        db.execute_batch(SCHEMA).map_err(sql)?;
        Ok(Self { db })
    }

    pub fn open_in_memory() -> Result<Self> {
        let db = Connection::open_in_memory().map_err(sql)?;
        db.execute_batch(SCHEMA).map_err(sql)?;
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

    fn quarantined(&self, pubkey_hex: &str) -> Result<bool> {
        let n: i64 = self
            .db
            .query_row(
                "SELECT count(*) FROM events WHERE kind = ?1 AND target = ?2",
                params![QUARANTINE_KIND, pubkey_hex],
                |r| r.get(0),
            )
            .map_err(sql)?;
        Ok(n > 0)
    }

    // ---------- append ----------

    fn last_chain(&self) -> Result<[u8; 32]> {
        let chain: Option<Vec<u8>> = self
            .db
            .query_row("SELECT chain FROM events ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .optional()
            .map_err(sql)?;
        match chain {
            None => Ok([0u8; 32]),
            Some(bytes) => bytes.try_into().map_err(|_| refuse("store-chain")),
        }
    }

    fn next_chain(prev: &[u8; 32], id: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"aukora:kira:chain:v1\0");
        h.update(prev);
        h.update(id);
        h.finalize().into()
    }

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
        let tx = self.db.transaction().map_err(sql)?;
        let prev: Option<Vec<u8>> = tx
            .query_row("SELECT chain FROM events ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .optional()
            .map_err(sql)?;
        let prev: [u8; 32] = match prev {
            None => [0u8; 32],
            Some(b) => b.try_into().map_err(|_| refuse("store-chain"))?,
        };
        let chain = Self::next_chain(&prev, event.id.as_bytes());
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
                    "INSERT INTO events(id, pubkey, created_at, kind, raw, chain, epoch, scope, lane, privacy, slot, statement_hash, target)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL)",
                    params![
                        id, author, event.created_at as i64, NOTE_KIND, raw, chain.to_vec(), meta.epoch as i64,
                        meta.scope, meta.lane.wire(), meta.privacy.wire(), meta.slot, meta.statement_hash.to_vec()
                    ],
                )
                .map_err(sql)?;
                let seq = tx.last_insert_rowid();
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
                    "INSERT INTO events(id, pubkey, created_at, kind, raw, chain, target) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![id, author, event.created_at as i64, SUPERSEDE_KIND, raw, chain.to_vec(), target],
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
                    "INSERT INTO events(id, pubkey, created_at, kind, raw, chain, target) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![id, author, event.created_at as i64, QUARANTINE_KIND, raw, chain.to_vec(), source],
                )
                .map_err(sql)?;
                tx.commit().map_err(sql)?;
            }
            _ => return Err(refuse("event-kind")),
        }
        if event.kind == NOTE_KIND {
            return self.get(&id)?.ok_or_else(|| refuse("store-sql"));
        }
        let _ = self.last_chain()?;
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
        let row: Option<(String, Vec<u8>, Vec<u8>, i64)> = self
            .db
            .query_row(
                "SELECT pubkey, raw, chain, kind FROM events WHERE seq = ?1",
                params![seq],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(sql)?;
        let Some((author, raw, chain, kind)) = row else { return Ok(None) };
        if kind != NOTE_KIND as i64 {
            return Ok(None);
        }
        // Verify on read: the stored bytes must still be a correctly signed event with the stored id and chain link.
        let event = Event::decode(&raw)?.verify().map_err(|_| refuse("note-integrity"))?.event().clone();
        let id = hex32(event.id.as_bytes());
        let prev: Option<Vec<u8>> = self
            .db
            .query_row("SELECT chain FROM events WHERE seq < ?1 ORDER BY seq DESC LIMIT 1", params![seq], |r| r.get(0))
            .optional()
            .map_err(sql)?;
        let prev: [u8; 32] = match prev {
            None => [0u8; 32],
            Some(b) => b.try_into().map_err(|_| refuse("note-integrity"))?,
        };
        if Self::next_chain(&prev, event.id.as_bytes()).to_vec() != chain || hex32(event.pubkey.as_bytes()) != author {
            return Err(refuse("note-integrity"));
        }
        let meta = NoteMeta::parse(&event.tags, &event.content)?;
        let author_name: String = self
            .db
            .query_row("SELECT name FROM agents WHERE pubkey = ?1", params![author], |r| r.get(0))
            .optional()
            .map_err(sql)?
            .unwrap_or_else(|| "unknown".into());
        let mut stmt = self.db.prepare("SELECT root FROM ancestry WHERE seq = ?1 ORDER BY root").map_err(sql)?;
        let roots = stmt
            .query_map(params![seq], |r| r.get::<_, String>(0))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        let superseded_by: Option<String> = self
            .db
            .query_row(
                "SELECT id FROM events WHERE kind = ?1 AND target = ?2 ORDER BY seq LIMIT 1",
                params![SUPERSEDE_KIND, id],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        let quarantined = self.quarantined(&author)?;
        Ok(Some(StoredNote { seq, event, meta, author_name, roots, superseded_by, quarantined }))
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

    /// Newest live note in a fixed slot (`d` tag), e.g. the owner-signed self file.
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
                if note.superseded_by.is_none() && !note.quarantined {
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

    /// Walk the whole append chain; returns the number of events checked.
    pub fn verify_chain(&self) -> Result<u64> {
        let mut stmt = self.db.prepare("SELECT id, chain FROM events ORDER BY seq").map_err(sql)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(sql)?;
        let mut prev = [0u8; 32];
        let mut n = 0;
        for row in rows {
            let (id, chain) = row.map_err(sql)?;
            let mut idb = [0u8; 32];
            for (i, byte) in idb.iter_mut().enumerate() {
                *byte = u8::from_str_radix(id.get(i * 2..i * 2 + 2).ok_or_else(|| refuse("store-chain"))?, 16)
                    .map_err(|_| refuse("store-chain"))?;
            }
            let next = Self::next_chain(&prev, &idb);
            if next.to_vec() != chain {
                return Err(refuse("store-chain-broken"));
            }
            prev = next;
            n += 1;
        }
        Ok(n)
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

    /// Seqs of every note in one epoch, read from the side column so recall can filter before loading. Recall
    /// re-verifies each note it uses and checks this column against the signed epoch tag.
    pub(crate) fn note_seqs_in_epoch(&self, epoch: u32) -> Result<Vec<i64>> {
        let mut stmt = self
            .db
            .prepare("SELECT seq FROM events WHERE kind = ?1 AND epoch = ?2 ORDER BY seq")
            .map_err(sql)?;
        let seqs = stmt
            .query_map(params![NOTE_KIND, epoch as i64], |r| r.get::<_, i64>(0))
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        Ok(seqs)
    }

    /// (notes with a vector under `model`, all notes) in one epoch, for coverage.
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
}
