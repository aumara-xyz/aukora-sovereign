// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid recall over the shared store: keyword (FTS5) and dense (brute-force cosine) candidates, reciprocal rank
//! fusion, corrections, an optional cross-encoder rerank, dedupe by statement hash, then reserved lanes inside a
//! character budget.
//!
//! Similarity alone never answers: every item carries its score and the status decides. A recall that cannot see
//! its whole index, loses a model, or meets a note that fails verification says `undetermined`, never `empty`.

use super::note::{Capture, Lane, NoteMeta, Privacy, Review};
use super::recall::{Embedder, RecallItem, RecallOutcome, RecallQuery, RecallStatus, Reranker};
use super::store::{EpochNote, SharedStore, StoredNote};
use canon::{Refusal, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Candidates taken from each retriever (keyword and dense).
pub const POOL: usize = 50;
/// Reciprocal rank fusion constant.
pub const RRF_K: f64 = 60.0;
/// Live candidates sent to the reranker; with a reranker, only these can be returned as live items.
pub const RERANK_TOP: usize = 20;
/// History items (superseded, quarantined) shown after the current items.
pub const MAX_CORRECTIONS: usize = 4;
/// Character budget when the query leaves it at 0.
pub const DEFAULT_BUDGET: usize = 4_800;
/// Epoch searched when the query leaves it at 0 (epoch 1 is the archived import).
pub const DEFAULT_EPOCH: u32 = 2;
/// Calibration of the three floors below (bge-reranker-v2-m3 logits, Qwen3-Embedding-0.6B cosines): Grok's red-team
/// eval, 59 answerable LongMemEval-S questions split by question type into a PRACTICE half (30, the floors were
/// chosen here) and a HELD-OUT half (29, scored once afterwards). This is the sha256 of the practice question ids,
/// sorted and joined by newlines. Controls: every practice store was also asked 3 other questions (cross-question,
/// 90 queries). Practice scores at the chosen floors: evidence-turn recall 0.833 at 4,800 chars (floor 0.0: 0.406),
/// answerable questions found 29 of 30, controls answered `empty` 77%. Chosen by balanced accuracy of those two
/// rates (peak at -5.5, flat from -6 to -5). The four abstention questions of the set (false premises) score up to
/// 3.9 and are NOT separable by any floor: they need the evidence rule, not a threshold. Held-out (29 questions,
/// scored once): 0.776, against 0.333 at floor 0.0 and 0.928 for the C+CE baseline; the crate README has both halves. Change a floor only with a new calibration set and a new hash.
pub const CALIBRATION_SET: &str = "c2cdbeef02608f382c6a154020c8f2ad34a4d492f59af728f261d7fce9d87dfd";
/// With a reranker, the best live rerank score must reach this for `found`; below it the answer is `empty`.
pub const RERANK_FLOOR: f32 = -5.5;
/// With a reranker and a `found` answer, a note rides along (fills the budget) when its rerank score reaches this.
/// Lower than the floor on purpose: the floor decides whether there is an answer, this only decides which of the
/// reranked notes are worth the characters once there is one. Practice recall stops improving at -7.
pub const RERANK_KEEP: f32 = -7.0;
/// Without a reranker (and for the corrections lane), a note counts only with a keyword hit (a shared content word)
/// or at least this cosine. Of the practice answers, only 2 of about 95 gold turns had no keyword hit; the same
/// cosine let a note through for 10% of controls at 0.55 and 1% at 0.60.
pub const COSINE_FLOOR: f32 = 0.60;
/// Keyword rows read before the epoch and scope filters: FTS5 ranks over every epoch at once.
const KEYWORD_SCAN: usize = 1_000;
const MAX_QUERY_BYTES: usize = 4_096;
/// Dead notes kept after the prepare phase; `finish` admits the few whose current note is returned.
const MAX_HISTORY_CANDIDATES: usize = 32;
const MAX_INDEX_BATCH: usize = 256;

/// Words too common to count as a keyword hit for the threshold. They still rank in FTS5; they only cannot make
/// an unanswerable question look answered.
const STOPWORDS: &[&str] = &[
    "about", "after", "all", "also", "am", "an", "and", "any", "are", "as", "at", "be", "been", "before", "being",
    "but", "by", "can", "could", "did", "do", "does", "for", "from", "had", "has", "have", "he", "her", "here", "him",
    "his", "how", "if", "in", "into", "is", "it", "its", "me", "my", "no", "not", "now", "of", "on", "or", "our",
    "out", "she", "should", "so", "some", "than", "that", "the", "their", "them", "then", "there", "these", "they",
    "this", "those", "to", "up", "us", "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom",
    "whose", "why", "will", "with", "would", "you", "your",
];

fn refuse(code: &'static str) -> Refusal {
    Refusal { organ: "kira", reason: code }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Words as the keyword index splits a query: alphanumeric runs longer than one character, lowercased.
fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric()).filter(|w| w.chars().count() > 1).map(str::to_lowercase)
}

fn content_words(text: &str) -> BTreeSet<String> {
    words(text).filter(|w| !STOPWORDS.contains(&w.as_str())).collect()
}

fn norm(v: &[f32]) -> f64 {
    v.iter().map(|x| f64::from(*x) * f64::from(*x)).sum::<f64>().sqrt()
}

/// The vector scaled to unit length; None for an empty, zero or non-finite vector.
fn unit(v: Vec<f32>) -> Option<Vec<f32>> {
    let n = norm(&v);
    if v.is_empty() || !n.is_finite() || n == 0.0 || v.iter().any(|x| !x.is_finite()) {
        return None;
    }
    Some(v.into_iter().map(|x| (f64::from(x) / n) as f32).collect())
}

/// Cosine of a unit query vector with a stored vector; None when the stored vector is unusable.
fn cosine(query: &[f32], v: &[f32]) -> Option<f32> {
    let n = norm(v);
    if v.len() != query.len() || !n.is_finite() || n == 0.0 {
        return None;
    }
    let dot: f64 = query.iter().zip(v).map(|(a, b)| f64::from(*a) * f64::from(*b)).sum();
    let c = (dot / n) as f32;
    c.is_finite().then_some(c)
}


/// sha256 (hex) of the query as canonical JSON: keys sorted, scopes sorted and deduplicated, defaults applied.
fn query_digest(q: &RecallQuery, epoch: u32, budget: usize) -> Result<String> {
    let mut scopes: Vec<&str> = q.scopes.iter().map(String::as_str).collect();
    scopes.sort_unstable();
    scopes.dedup();
    let fields = [
        ("author", serde_json::to_string(&q.author)),
        ("budget_chars", serde_json::to_string(&budget)),
        ("caller", serde_json::to_string(&q.caller)),
        ("epoch", serde_json::to_string(&epoch)),
        ("include_local", serde_json::to_string(&q.include_local)),
        ("scopes", serde_json::to_string(&scopes)),
        ("text", serde_json::to_string(&q.text)),
    ];
    let mut canonical = String::from("{");
    for (i, (key, value)) in fields.into_iter().enumerate() {
        if i > 0 {
            canonical.push(',');
        }
        canonical.push('"');
        canonical.push_str(key);
        canonical.push_str("\":");
        canonical.push_str(&value.map_err(|_| refuse("recall-query"))?);
    }
    canonical.push('}');
    let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
    Ok(hex(&digest))
}

/// `current`, `expired` (after its `valid_to`) or `not-yet-valid` (before its `valid_from`) at time `at`.
pub fn validity(meta: &NoteMeta, at: u64) -> &'static str {
    if meta.valid_to.is_some_and(|to| at > to) {
        "expired"
    } else if meta.valid_from.is_some_and(|from| at < from) {
        "not-yet-valid"
    } else {
        "current"
    }
}

/// Why a note is not live memory, if it is not: the label it is shown under as history.
fn retired(note: &StoredNote, at: u64) -> Option<&'static str> {
    if note.quarantined {
        Some("quarantined")
    } else if note.superseded_by.is_some() {
        Some("superseded")
    } else {
        match validity(&note.meta, at) {
            "current" => None,
            label => Some(label),
        }
    }
}

/// The query text recall searches with, or a refusal for an empty or oversized query.
fn query_text(q: &RecallQuery) -> Result<&str> {
    let text = q.text.trim();
    if text.is_empty() || q.text.len() > MAX_QUERY_BYTES {
        return Err(refuse("recall-query"));
    }
    Ok(text)
}

/// The query's unit vector from the embedder, or None when the embedder fails. A model call: the service makes it
/// without holding the store.
pub fn query_vector(q: &RecallQuery, emb: &dyn Embedder) -> Option<Vec<f32>> {
    let text = query_text(q).ok()?;
    emb.embed(&[text]).ok().filter(|v| v.len() == 1).and_then(|mut v| unit(v.remove(0)))
}

/// Checks one embedding batch whole and scales it to unit length: one usable vector per row, all one dimension.
pub fn index_vectors(rows: usize, vectors: Vec<Vec<f32>>) -> Result<Vec<Vec<f32>>> {
    if vectors.len() != rows {
        return Err(refuse("index-vector"));
    }
    let vectors = vectors.into_iter().map(unit).collect::<Option<Vec<_>>>().ok_or_else(|| refuse("index-vector"))?;
    if vectors.windows(2).any(|w| w[0].len() != w[1].len()) {
        return Err(refuse("index-vector"));
    }
    Ok(vectors)
}

/// What the side columns say about a note's author, for sharing places among authors before any note is loaded.
struct Who {
    pubkey: String,
    owner: bool,
    experience: bool,
}

impl Who {
    /// Exempt from the per-author share: the owner's notes and the caller's own experience lane.
    fn exempt(&self, caller: &str) -> bool {
        self.owner || (self.experience && self.pubkey == caller)
    }
}

/// Loads candidate notes once each, applying the epoch, privacy, scope and author filters. A note the store cannot
/// verify marks the whole recall undetermined and is never returned.
struct Loader<'a> {
    store: &'a SharedStore,
    epoch: u32,
    in_epoch: BTreeMap<i64, Who>,
    caller: &'a str,
    scopes: BTreeSet<&'a str>,
    author: Option<&'a str>,
    include_local: bool,
    cache: BTreeMap<i64, Option<StoredNote>>,
    integrity: bool,
}

impl Loader<'_> {
    fn note(&mut self, seq: i64) -> Option<&StoredNote> {
        let Some(who) = self.in_epoch.get(&seq) else { return None };
        if !self.cache.contains_key(&seq) {
            let loaded = match self.store.note_by_seq(seq) {
                // The side columns said this epoch and author; the signed event must agree.
                Ok(Some(note)) if note.meta.epoch == self.epoch && hex(note.event.pubkey.as_bytes()) == who.pubkey => Some(note),
                Ok(_) | Err(_) => {
                    self.integrity = true;
                    None
                }
            };
            let kept = loaded.filter(|note| self.passes(note));
            self.cache.insert(seq, kept);
        }
        self.cache.get(&seq).and_then(Option::as_ref)
    }

    /// Privacy first: a `local` note never reaches a caller who may not read it, so it cannot claim a pool place,
    /// join a dedupe group or make the answer `found`.
    fn passes(&self, note: &StoredNote) -> bool {
        (self.include_local || note.meta.privacy != Privacy::Local)
            && (self.scopes.is_empty() || self.scopes.contains(note.meta.scope.as_str()))
            && self.author.is_none_or(|a| a == note.author_name || a.eq_ignore_ascii_case(&hex(note.event.pubkey.as_bytes())))
    }
}

/// Walk `ranked` (best first) and keep the first POOL notes that load and pass the filters, plus any tied with the
/// last kept score. No author other than the owner (or the caller's own experience) holds more than half the places
/// while others are waiting: a flood from one author cannot fill the pool, and its overflow only backfills places
/// nobody else claimed (an empty place protects no one). Returns (seq, 1-based rank); equal scores share a rank, so
/// storage order never decides a tie.
fn pool(loader: &mut Loader, ranked: &[(i64, f64)]) -> Vec<(i64, usize)> {
    let share = POOL / 2;
    let mut kept: Vec<(f64, String, i64)> = Vec::new();
    let mut held: BTreeMap<String, usize> = BTreeMap::new();
    let mut over: Vec<(i64, f64)> = Vec::new();
    for &(seq, score) in ranked {
        if kept.len() >= POOL && kept.last().is_some_and(|last| last.0 != score) {
            break;
        }
        let Some(who) = loader.in_epoch.get(&seq) else { continue };
        if !who.exempt(loader.caller) && held.get(&who.pubkey).copied().unwrap_or(0) >= share {
            over.push((seq, score));
            continue;
        }
        let pubkey = who.pubkey.clone();
        if let Some(note) = loader.note(seq) {
            *held.entry(pubkey).or_default() += 1;
            kept.push((score, hex(note.event.id.as_bytes()), seq));
        }
    }
    // Places left over go to the overflow, best first.
    for (seq, score) in over {
        if kept.len() >= POOL && kept.last().is_some_and(|last| last.0 != score) {
            break;
        }
        if let Some(note) = loader.note(seq) {
            kept.push((score, hex(note.event.id.as_bytes()), seq));
        }
    }
    kept.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut rank = 0;
    let mut out = Vec::with_capacity(kept.len());
    for (i, (score, _, seq)) in kept.iter().enumerate() {
        if i == 0 || *score != kept[i - 1].0 {
            rank = i + 1;
        }
        out.push((*seq, rank));
    }
    out
}

struct Cand {
    note: StoredNote,
    id: String,
    fused: f64,
    cosine: Option<f32>,
    /// Shares a content word (not a stopword) with the query.
    hit: bool,
    rerank: Option<f32>,
    /// Set for a note that is not live memory: why (`retired`).
    past: Option<&'static str>,
    /// Added because the stale note it replaced matched the question: it stands for that statement whatever words it
    /// shares with the question, so it is relevant by inheritance.
    inherited: bool,
}

impl Cand {
    /// The note itself matches the question: a keyword hit or the cosine floor.
    fn evidence(&self) -> bool {
        self.hit || self.cosine.is_some_and(|c| c >= COSINE_FLOOR)
    }

    fn author(&self) -> String {
        hex(self.note.event.pubkey.as_bytes())
    }

    /// Exempt from the per-author share: the owner's notes and the caller's own experience lane.
    fn exempt(&self, caller: &str) -> bool {
        self.note.author_owner || (self.note.meta.lane == Lane::Experience && self.author() == caller)
    }

    /// Which note stands for a statement, lowest first: owner-signed review, then the owner's own words, then any
    /// other capture; the earliest within a class, the note id last.
    fn standing(&self) -> (u8, u64, &str) {
        let meta = &self.note.meta;
        let trust = if meta.review == Review::OwnerSigned {
            0
        } else if meta.capture.owner_class() {
            1
        } else {
            2
        };
        (trust, self.note.event.created_at, &self.id)
    }

    fn item(&self, score: f32, also_by: Vec<String>, also_by_ids: Vec<String>, roots: usize, correction: Option<&str>) -> RecallItem {
        // A retired note points at the note that stands where it did (the service shows the id only to a caller who
        // may read that note).
        let meta = &self.note.meta;
        RecallItem {
            id: self.id.clone(),
            author: hex(self.note.event.pubkey.as_bytes()),
            author_name: self.note.author_name.clone(),
            also_by,
            also_by_ids,
            lane: meta.lane.wire().into(),
            form: meta.form.wire().into(),
            review: meta.review.wire().into(),
            capture: meta.capture.wire().into(),
            created_at: self.note.event.created_at,
            // A quarantined note is a stub: its body never resurfaces as text.
            text: if correction == Some("quarantined") { String::new() } else { self.note.event.content.clone() },
            score,
            roots,
            correction: correction.map(str::to_owned),
            current_id: if correction == Some("superseded") { self.note.current_id.clone() } else { None },
        }
    }
}

/// The best `limit` candidates (best first in, original order out) with the same per-author share as `pool`: no
/// author other than the owner (or the caller's own experience) holds more than half the places while others wait;
/// its overflow only fills places nobody else claimed.
fn fair_top(live: Vec<Cand>, limit: usize, caller: &str) -> Vec<Cand> {
    let share = limit / 2;
    let mut held: BTreeMap<String, usize> = BTreeMap::new();
    let (mut chosen, mut over) = (Vec::new(), Vec::new());
    for (i, c) in live.iter().enumerate() {
        if chosen.len() >= limit {
            break;
        }
        let author = c.author();
        if !c.exempt(caller) && held.get(&author).copied().unwrap_or(0) >= share {
            over.push(i);
        } else {
            *held.entry(author).or_default() += 1;
            chosen.push(i);
        }
    }
    chosen.extend(over.into_iter().take(limit.saturating_sub(chosen.len())));
    chosen.sort_unstable();
    let mut slots: Vec<Option<Cand>> = live.into_iter().map(Some).collect();
    chosen.into_iter().filter_map(|i| slots[i].take()).collect()
}

/// One statement (at one privacy level) after dedupe: the highest-standing note stands for it, every author is kept.
struct Group {
    keep: Cand,
    score: f32,
    /// Clears the floor that decides there is an answer.
    relevant: bool,
    /// Clears the lower test for riding along once there is an answer (the same as `relevant` without a reranker).
    carried: bool,
    names: BTreeSet<String>,
    ids: BTreeSet<String>,
    roots: BTreeSet<String>,
}

/// Reserved lanes, filled in this order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Slot {
    /// Owner-signed decisions, rulings and the charter.
    Commitment,
    /// Notes captured as the owner's own words.
    OwnerWords,
    /// The caller's own experience.
    OwnExperience,
    Rest,
}

/// Recall's first phase, gathered from the store: candidates and what the store said about its own health. The second
/// phase (`finish`) reranks and assembles without the store, so a model call never runs while the store is held.
pub struct Prepared {
    text: String,
    caller: String,
    budget: usize,
    query_digest: String,
    live: Vec<Cand>,
    /// Superseded and quarantined notes that match the question: shown only as history of a returned current note
    /// (superseded) or as a stub (quarantined), after the current items.
    history: Vec<Cand>,
    integrity: bool,
    embedder_down: bool,
    index_bad: bool,
    dense: bool,
    embed_model: Option<String>,
    indexed: u64,
    total: u64,
}

impl SharedStore {
    /// Hybrid recall; see the module docs. `emb` adds dense candidates and `rr` reranks; either may be absent.
    pub fn recall(&self, q: &RecallQuery, emb: Option<&dyn Embedder>, rr: Option<&dyn Reranker>) -> Result<RecallOutcome> {
        query_text(q)?;
        let dense = emb.map(|e| (e.model_id(), query_vector(q, e)));
        Ok(self.recall_prepare(q, dense)?.finish(rr))
    }

    /// Recall's first phase. `dense` is the embedder's model id with the query vector (`query_vector`), or None
    /// without an embedder; a None vector means the embedder was down.
    pub fn recall_prepare(&self, q: &RecallQuery, dense: Option<(&str, Option<Vec<f32>>)>) -> Result<Prepared> {
        let text = query_text(q)?;
        let epoch = if q.epoch == 0 { DEFAULT_EPOCH } else { q.epoch };
        let budget = if q.budget_chars == 0 { DEFAULT_BUDGET } else { q.budget_chars };
        let query_digest = query_digest(q, epoch, budget)?;
        let caller = q.caller.to_ascii_lowercase();
        // Only notes this caller may read take part in anything below, the counts included: `total` and `indexed` must
        // not reveal that a note it cannot see exists (a local note, or one in a scope it is not registered for).
        let scopes: BTreeSet<&str> = q.scopes.iter().map(String::as_str).collect();
        let in_epoch: BTreeMap<i64, Who> = self
            .note_authors_in_epoch(epoch)?
            .into_iter()
            .filter(|n| (q.include_local || n.privacy != Privacy::Local.wire()) && (scopes.is_empty() || scopes.contains(n.scope.as_str())))
            .map(|n: EpochNote| {
                let experience = n.lane == Lane::Experience.wire();
                (n.seq, Who { pubkey: n.pubkey, owner: n.owner, experience })
            })
            .collect();
        let mut loader = Loader {
            store: self,
            epoch,
            in_epoch,
            caller: &caller,
            scopes,
            author: q.author.as_deref(),
            include_local: q.include_local,
            cache: BTreeMap::new(),
            integrity: false,
        };
        // Without a dense retriever every note is searchable: the keyword row is written with the note.
        let (mut indexed, mut total) = (loader.in_epoch.len() as u64, loader.in_epoch.len() as u64);

        // Keyword: bm25 is lower-is-better, so negate it to rank best first.
        let keyword_rows: Vec<(i64, f64)> = self.keyword(text, KEYWORD_SCAN)?.into_iter().map(|(s, b)| (s, -b)).collect();
        let keyword = pool(&mut loader, &keyword_rows);

        // Dense: brute-force cosine over this epoch's vectors for the embedder's model.
        let (mut ranked_dense, mut cosines) = (Vec::new(), HashMap::new());
        let (mut embedder_down, mut index_bad) = (false, false);
        let has_dense = dense.is_some();
        let embed_model = dense.as_ref().map(|(model, _)| (*model).to_owned());
        if let Some((model, query_vector)) = dense {
            let embedded = self.embedded_seqs(model)?;
            total = loader.in_epoch.len() as u64;
            indexed = loader.in_epoch.keys().filter(|seq| embedded.contains(seq)).count() as u64;
            match query_vector {
                None => embedder_down = true,
                Some(qv) => {
                    let mut scored = Vec::new();
                    for (seq, v) in self.embeddings(model)? {
                        if !loader.in_epoch.contains_key(&seq) {
                            continue;
                        }
                        match cosine(&qv, &v) {
                            Some(c) => {
                                cosines.insert(seq, c);
                                scored.push((seq, f64::from(c)));
                            }
                            None => index_bad = true,
                        }
                    }
                    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
                    ranked_dense = pool(&mut loader, &scored);
                }
            }
        }

        // Reciprocal rank fusion.
        let mut fused: BTreeMap<i64, f64> = BTreeMap::new();
        for list in [&keyword, &ranked_dense] {
            for (seq, rank) in list {
                *fused.entry(*seq).or_insert(0.0) += 1.0 / (RRF_K + *rank as f64);
            }
        }
        let query_words = content_words(text);
        let mut cands: Vec<Cand> = fused
            .into_iter()
            .filter_map(|(seq, score)| {
                let note = loader.cache.remove(&seq).flatten()?;
                let hit = words(&note.event.content).any(|w| query_words.contains(&w));
                let id = hex(note.event.id.as_bytes());
                Some(Cand { note, id, fused: score, cosine: cosines.get(&seq).copied(), hit, rerank: None, past: None, inherited: false })
            })
            .collect();
        cands.sort_by(|a, b| b.fused.total_cmp(&a.fused).then_with(|| a.id.cmp(&b.id)));

        // Superseded and quarantined notes never stand as memory. A superseded note that matches is history of the note
        // that replaced it, so that note is a candidate too, even when it shares fewer words with the question than the
        // stale one did: the question gets the current answer, never only the retired one.
        let now = if q.now == 0 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()) } else { q.now };
        let (dead, mut live): (Vec<Cand>, Vec<Cand>) = cands.into_iter().partition(|c| retired(&c.note, now).is_some());
        let mut history: Vec<Cand> = dead
            .into_iter()
            .map(|mut c| {
                c.past = retired(&c.note, now);
                c
            })
            .filter(Cand::evidence)
            .collect();
        let mut pulled = 0;
        for stale in history.iter().filter(|c| c.past == Some("superseded")) {
            let Some(current) = stale.note.current_id.as_deref() else { continue };
            if pulled >= MAX_CORRECTIONS || live.iter().any(|c| c.id == current) {
                continue;
            }
            let Ok(Some(found)) = self.get(current) else { continue };
            if retired(&found, now).is_some() {
                continue;
            }
            if let Some(note) = loader.note(found.seq).cloned() {
                let hit = words(&note.event.content).any(|w| query_words.contains(&w));
                live.push(Cand { id: current.to_owned(), note, fused: stale.fused, cosine: None, hit, rerank: None, past: None, inherited: true });
                pulled += 1;
            }
        }
        history.truncate(MAX_HISTORY_CANDIDATES);
        Ok(Prepared {
            text: text.to_owned(),
            caller: q.caller.to_ascii_lowercase(),
            budget,
            query_digest,
            live,
            history,
            integrity: loader.integrity,
            embedder_down,
            index_bad,
            dense: has_dense,
            embed_model,
            indexed,
            total,
        })
    }

    /// Embed every note that has no vector under `emb.model_id()`, `batch` notes per call (clamped to 1..=256).
    /// Each batch is checked whole before any vector is written; vectors are stored at unit length. Returns how many
    /// notes were indexed.
    pub fn index_missing(&self, emb: &dyn Embedder, batch: usize) -> Result<usize> {
        let model = emb.model_id();
        if model.is_empty() {
            return Err(refuse("index-model"));
        }
        let batch = batch.clamp(1, MAX_INDEX_BATCH);
        let (mut done, mut last) = (0, i64::MIN);
        loop {
            let rows = self.missing_embeddings(model, batch)?;
            let (Some(first), Some(end)) = (rows.first(), rows.last()) else { return Ok(done) };
            // Each pass must move forward through the seqs, or a silent write failure would loop forever.
            if first.0 <= last {
                return Err(refuse("index-stuck"));
            }
            last = end.0;
            let texts: Vec<&str> = rows.iter().map(|(_, body)| body.as_str()).collect();
            let vectors = index_vectors(rows.len(), emb.embed(&texts)?)?;
            for ((seq, _), vector) in rows.iter().zip(&vectors) {
                self.put_embedding(*seq, model, vector)?;
            }
            done += rows.len();
        }
    }
}

impl Prepared {
    /// Recall's second phase, without the store: rerank (a model call), dedupe, reserved lanes and the budget.
    pub fn finish(self, rr: Option<&dyn Reranker>) -> RecallOutcome {
        let Prepared {
            text, caller, budget, query_digest, mut live, history, integrity, embedder_down, index_bad, dense, embed_model, indexed, total,
        } = self;
        // Rerank the top live candidates.
        let mut reranker_down = false;
        let rerank_model = rr.map(|r| r.model_id().to_owned());
        if let Some(rr) = rr {
            live = fair_top(live, RERANK_TOP, &caller);
            if !live.is_empty() {
                let passages: Vec<&str> = live.iter().map(|c| c.note.event.content.as_str()).collect();
                match rr.score(&text, &passages) {
                    Ok(scores) if scores.len() == live.len() && scores.iter().all(|s| s.is_finite()) => {
                        for (c, s) in live.iter_mut().zip(scores) {
                            c.rerank = Some(s);
                        }
                    }
                    _ => reranker_down = true,
                }
            }
        }
        let reranked = rr.is_some() && !reranker_down;
        // `strong` decides whether there is an answer; `weak` decides which notes ride along once there is one.
        let strong = |c: &Cand| c.inherited || if reranked { c.rerank.is_some_and(|s| s >= RERANK_FLOOR) } else { c.evidence() };
        let weak = |c: &Cand| c.inherited || if reranked { c.rerank.is_some_and(|s| s >= RERANK_KEEP) } else { c.evidence() };

        // Dedupe by statement hash within one privacy level: the highest-standing note stands, every author and note
        // id is named, ancestry roots are unioned.
        let mut groups: Vec<Group> = Vec::new();
        let mut by_hash: BTreeMap<([u8; 32], &'static str), usize> = BTreeMap::new();
        for c in live {
            let (score, is_strong, is_weak) = (c.rerank.unwrap_or(c.fused as f32), strong(&c), weak(&c));
            let key = (c.note.meta.statement_hash, c.note.meta.privacy.wire());
            if let Some(&i) = by_hash.get(&key) {
                let g = &mut groups[i];
                g.score = g.score.max(score);
                g.relevant |= is_strong;
                g.carried |= is_weak;
                g.names.insert(c.note.author_name.clone());
                g.ids.insert(c.id.clone());
                g.roots.extend(c.note.roots.iter().cloned());
                if c.standing() < g.keep.standing() {
                    g.keep = c;
                }
            } else {
                by_hash.insert(key, groups.len());
                groups.push(Group {
                    score,
                    relevant: is_strong,
                    carried: is_weak,
                    names: BTreeSet::from([c.note.author_name.clone()]),
                    ids: BTreeSet::from([c.id.clone()]),
                    roots: c.note.roots.iter().cloned().collect(),
                    keep: c,
                });
            }
        }
        let found = groups.iter().any(|g| g.relevant);
        // Nothing is returned without an answer; with one, only notes that clear the keep test ride along.
        groups.retain(|g| found && g.carried);

        // Reserved lanes. Only relevant notes claim a reserved lane; everything else competes by score.
        let slot = |g: &Group| {
            let meta = &g.keep.note.meta;
            if !g.relevant {
                Slot::Rest
            } else if (meta.review == Review::OwnerSigned || meta.capture == Capture::OwnerTyped)
                && matches!(meta.lane, Lane::Decision | Lane::Ruling | Lane::Charter)
            {
                Slot::Commitment
            } else if matches!(meta.capture, Capture::OwnerTyped | Capture::OwnerSigned) {
                Slot::OwnerWords
            } else if meta.lane == Lane::Experience && hex(g.keep.note.event.pubkey.as_bytes()) == caller {
                Slot::OwnExperience
            } else {
                Slot::Rest
            }
        };
        let mut ordered: Vec<(Slot, bool, RecallItem)> = groups
            .into_iter()
            .map(|g| {
                let lane = slot(&g);
                let exempt = lane == Slot::OwnExperience || g.keep.note.author_owner;
                let also_by = g.names.into_iter().filter(|n| *n != g.keep.note.author_name).collect();
                let also_by_ids = g.ids.into_iter().filter(|id| *id != g.keep.id).collect();
                (lane, exempt, g.keep.item(g.score, also_by, also_by_ids, g.roots.len(), None))
            })
            .collect();
        ordered.sort_by(|a, b| a.0.cmp(&b.0).then(b.2.score.total_cmp(&a.2.score)).then_with(|| a.2.id.cmp(&b.2.id)));

        // Fill the budget in lane order; an item that does not fit is skipped, never cut, and a skipped relevant
        // note is counted in `omitted`. First pass: no author other than the owner (or the caller's own experience)
        // takes more than half the budget, so one author's flood cannot push the rest out. Second pass: room nobody
        // else claimed goes back to the notes the share held out, in the same order (an empty place protects no one).
        let (mut used, mut taken) = (0, vec![false; ordered.len()]);
        let mut held: BTreeMap<&str, usize> = BTreeMap::new();
        for pass in 0..2 {
            for (i, (_, exempt, item)) in ordered.iter().enumerate() {
                let size = item.text.chars().count();
                if taken[i] || used + size > budget {
                    continue;
                }
                let share = held.get(item.author.as_str()).copied().unwrap_or(0);
                if pass == 0 && !exempt && share + size > budget / 2 {
                    continue;
                }
                used += size;
                taken[i] = true;
                *held.entry(item.author.as_str()).or_default() += size;
            }
        }
        let (mut items, mut omitted, mut kept_live) = (Vec::new(), 0, 0);
        for ((_, _, item), taken) in ordered.into_iter().zip(taken) {
            if taken {
                kept_live += 1;
                items.push(item);
            } else {
                omitted += 1;
            }
        }

        // History comes after the current items, with what is left of the budget: a superseded note only beside the
        // note that stands for it (which must itself be among the items), a quarantined one only as a stub.
        let shown: BTreeSet<&str> = items.iter().flat_map(|i| std::iter::once(i.id.as_str()).chain(i.also_by_ids.iter().map(String::as_str))).collect();
        let mut past: Vec<RecallItem> = history
            .iter()
            .filter(|c| c.past != Some("superseded") || c.note.current_id.as_deref().is_some_and(|id| shown.contains(id)))
            .map(|c| c.item(c.fused as f32, Vec::new(), Vec::new(), c.note.roots.len(), c.past))
            .collect();
        past.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        for item in past.into_iter().take(MAX_CORRECTIONS) {
            let size = item.text.chars().count();
            if used + size <= budget {
                used += size;
                items.push(item);
            }
        }

        let status = if integrity {
            RecallStatus::Undetermined("integrity")
        } else if embedder_down {
            RecallStatus::Undetermined("embedder-down")
        } else if reranker_down {
            RecallStatus::Undetermined("reranker-down")
        } else if dense && (indexed < total || index_bad) {
            RecallStatus::Undetermined("index-incomplete")
        } else if found && kept_live == 0 {
            // Every relevant note was too long for the budget: an answer exists but none can be shown.
            RecallStatus::Undetermined("budget")
        } else if found {
            RecallStatus::Found
        } else {
            RecallStatus::Empty
        };
        if status == RecallStatus::Empty {
            items.clear();
        }
        RecallOutcome {
            status,
            items,
            omitted,
            indexed,
            total,
            query_digest,
            judged_by: if reranked { "rerank" } else { "keyword+cosine" },
            rerank_floor: RERANK_FLOOR,
            cosine_floor: COSINE_FLOOR,
            embed_model,
            rerank_model,
            calibration_set: CALIBRATION_SET,
        }
    }
}

#[cfg(test)]
mod tests;
