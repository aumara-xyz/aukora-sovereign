// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid recall over the shared store: keyword (FTS5) and dense (brute-force cosine) candidates, reciprocal rank
//! fusion, corrections, an optional cross-encoder rerank, dedupe by statement hash, then reserved lanes inside a
//! character budget.
//!
//! Similarity alone never answers: every item carries its score and the status decides. A recall that cannot see
//! its whole index, loses a model, or meets a note that fails verification says `undetermined`, never `empty`.

use super::note::{Capture, Lane, Review};
use super::recall::{Embedder, RecallItem, RecallOutcome, RecallQuery, RecallStatus, Reranker};
use super::store::{SharedStore, StoredNote};
use canon::{Refusal, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Candidates taken from each retriever (keyword and dense).
pub const POOL: usize = 50;
/// Reciprocal rank fusion constant.
pub const RRF_K: f64 = 60.0;
/// Live candidates sent to the reranker; with a reranker, only these can be returned as live items.
pub const RERANK_TOP: usize = 20;
/// Superseded or quarantined notes shown as corrections.
pub const MAX_CORRECTIONS: usize = 2;
/// Character budget when the query leaves it at 0.
pub const DEFAULT_BUDGET: usize = 4_800;
/// Epoch searched when the query leaves it at 0 (epoch 1 is the archived import).
pub const DEFAULT_EPOCH: u32 = 2;
/// With a reranker, the best live rerank score must reach this for `found`. 0.0 suits raw cross-encoder logits.
/// Calibrate on practice questions, then lock.
pub const RERANK_FLOOR: f32 = 0.0;
/// Without a reranker, a note counts only with a keyword hit (a shared content word) or at least this cosine.
pub const COSINE_FLOOR: f32 = 0.55;
/// Keyword rows read before the epoch and scope filters: FTS5 ranks over every epoch at once.
const KEYWORD_SCAN: usize = 1_000;
const MAX_QUERY_BYTES: usize = 4_096;
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

/// Loads candidate notes once each, applying the epoch, scope and author filters. A note the store cannot verify
/// marks the whole recall undetermined and is never returned.
struct Loader<'a> {
    store: &'a SharedStore,
    epoch: u32,
    in_epoch: BTreeSet<i64>,
    scopes: BTreeSet<&'a str>,
    author: Option<&'a str>,
    cache: BTreeMap<i64, Option<StoredNote>>,
    integrity: bool,
}

impl Loader<'_> {
    fn note(&mut self, seq: i64) -> Option<&StoredNote> {
        if !self.in_epoch.contains(&seq) {
            return None;
        }
        if !self.cache.contains_key(&seq) {
            let loaded = match self.store.note_by_seq(seq) {
                // The side column said this epoch; the signed tag must agree.
                Ok(Some(note)) if note.meta.epoch == self.epoch => Some(note),
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

    fn passes(&self, note: &StoredNote) -> bool {
        (self.scopes.is_empty() || self.scopes.contains(note.meta.scope.as_str()))
            && self.author.is_none_or(|a| a == note.author_name || a.eq_ignore_ascii_case(&hex(note.event.pubkey.as_bytes())))
    }
}

/// Walk `ranked` (best first) and keep the first POOL notes that load and pass the filters, plus any tied with the
/// last kept score. Returns (seq, 1-based rank); equal scores share a rank, so storage order never decides a tie.
fn pool(loader: &mut Loader, ranked: &[(i64, f64)]) -> Vec<(i64, usize)> {
    let mut kept: Vec<(f64, String, i64)> = Vec::new();
    for &(seq, score) in ranked {
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
}

impl Cand {
    /// The note itself matches the question: a keyword hit or the cosine floor.
    fn evidence(&self) -> bool {
        self.hit || self.cosine.is_some_and(|c| c >= COSINE_FLOOR)
    }

    fn item(&self, score: f32, also_by: Vec<String>, roots: usize, correction: Option<&str>) -> RecallItem {
        let meta = &self.note.meta;
        RecallItem {
            id: self.id.clone(),
            author: hex(self.note.event.pubkey.as_bytes()),
            author_name: self.note.author_name.clone(),
            also_by,
            lane: meta.lane.wire().into(),
            form: meta.form.wire().into(),
            review: meta.review.wire().into(),
            capture: meta.capture.wire().into(),
            created_at: self.note.event.created_at,
            text: self.note.event.content.clone(),
            score,
            roots,
            correction: correction.map(str::to_owned),
        }
    }
}

/// One statement after dedupe: the earliest note stands for it, every author is kept.
struct Group {
    keep: Cand,
    score: f32,
    relevant: bool,
    names: BTreeSet<String>,
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
    Correction,
    Rest,
}

impl SharedStore {
    /// Hybrid recall; see the module docs. `emb` adds dense candidates and `rr` reranks; either may be absent.
    pub fn recall(&self, q: &RecallQuery, emb: Option<&dyn Embedder>, rr: Option<&dyn Reranker>) -> Result<RecallOutcome> {
        let text = q.text.trim();
        if text.is_empty() || q.text.len() > MAX_QUERY_BYTES {
            return Err(refuse("recall-query"));
        }
        let epoch = if q.epoch == 0 { DEFAULT_EPOCH } else { q.epoch };
        let budget = if q.budget_chars == 0 { DEFAULT_BUDGET } else { q.budget_chars };
        let query_digest = query_digest(q, epoch, budget)?;
        let in_epoch: BTreeSet<i64> = self.note_seqs_in_epoch(epoch)?.into_iter().collect();
        let mut loader = Loader {
            store: self,
            epoch,
            in_epoch,
            scopes: q.scopes.iter().map(String::as_str).collect(),
            author: q.author.as_deref(),
            cache: BTreeMap::new(),
            integrity: false,
        };
        // Without a dense retriever every note is searchable: the keyword row is written with the note.
        let (mut indexed, mut total) = (loader.in_epoch.len() as u64, loader.in_epoch.len() as u64);

        // Keyword: bm25 is lower-is-better, so negate it to rank best first.
        let keyword_rows: Vec<(i64, f64)> = self.keyword(text, KEYWORD_SCAN)?.into_iter().map(|(s, b)| (s, -b)).collect();
        let keyword = pool(&mut loader, &keyword_rows);

        // Dense: brute-force cosine over this epoch's vectors for the embedder's model.
        let (mut dense, mut cosines) = (Vec::new(), HashMap::new());
        let (mut embedder_down, mut index_bad) = (false, false);
        if let Some(emb) = emb {
            let model = emb.model_id();
            (indexed, total) = self.coverage(model, epoch)?;
            let query_vector = emb.embed(&[text]).ok().filter(|v| v.len() == 1).and_then(|mut v| unit(v.remove(0)));
            match query_vector {
                None => embedder_down = true,
                Some(qv) => {
                    let mut scored = Vec::new();
                    for (seq, v) in self.embeddings(model)? {
                        if !loader.in_epoch.contains(&seq) {
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
                    dense = pool(&mut loader, &scored);
                }
            }
        }

        // Reciprocal rank fusion.
        let mut fused: BTreeMap<i64, f64> = BTreeMap::new();
        for list in [&keyword, &dense] {
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
                Some(Cand { note, id, fused: score, cosine: cosines.get(&seq).copied(), hit, rerank: None })
            })
            .collect();
        cands.sort_by(|a, b| b.fused.total_cmp(&a.fused).then_with(|| a.id.cmp(&b.id)));

        // Superseded and quarantined notes never stand as memory; a matching few are shown as corrections.
        let (dead, mut live): (Vec<Cand>, Vec<Cand>) =
            cands.into_iter().partition(|c| c.note.quarantined || c.note.superseded_by.is_some());
        let corrections: Vec<Cand> = dead.into_iter().filter(Cand::evidence).take(MAX_CORRECTIONS).collect();

        // Rerank the top live candidates.
        let mut reranker_down = false;
        if let Some(rr) = rr {
            live.truncate(RERANK_TOP);
            if !live.is_empty() {
                let passages: Vec<&str> = live.iter().map(|c| c.note.event.content.as_str()).collect();
                match rr.score(text, &passages) {
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
        let relevant = |c: &Cand| if reranked { c.rerank.is_some_and(|s| s >= RERANK_FLOOR) } else { c.evidence() };

        // Dedupe by statement hash: the earliest note stands, every author is named, ancestry roots are unioned.
        let mut groups: Vec<Group> = Vec::new();
        let mut by_hash: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for c in live {
            let (score, is_relevant) = (c.rerank.unwrap_or(c.fused as f32), relevant(&c));
            if let Some(&i) = by_hash.get(&c.note.meta.statement_hash) {
                let g = &mut groups[i];
                g.score = g.score.max(score);
                g.relevant |= is_relevant;
                g.names.insert(c.note.author_name.clone());
                g.roots.extend(c.note.roots.iter().cloned());
                if (c.note.event.created_at, &c.id) < (g.keep.note.event.created_at, &g.keep.id) {
                    g.keep = c;
                }
            } else {
                by_hash.insert(c.note.meta.statement_hash, groups.len());
                groups.push(Group {
                    score,
                    relevant: is_relevant,
                    names: BTreeSet::from([c.note.author_name.clone()]),
                    roots: c.note.roots.iter().cloned().collect(),
                    keep: c,
                });
            }
        }
        let found = groups.iter().any(|g| g.relevant);
        // Only notes that clear the relevance test are returned; below-threshold notes never ride along as context.
        groups.retain(|g| g.relevant);

        // Reserved lanes. Only relevant notes claim a reserved lane; everything else competes by score.
        let caller = q.caller.to_ascii_lowercase();
        let slot = |g: &Group| {
            let meta = &g.keep.note.meta;
            if !g.relevant {
                Slot::Rest
            } else if meta.review == Review::OwnerSigned && matches!(meta.lane, Lane::Decision | Lane::Ruling | Lane::Charter) {
                Slot::Commitment
            } else if matches!(meta.capture, Capture::OwnerTyped | Capture::OwnerSigned) {
                Slot::OwnerWords
            } else if meta.lane == Lane::Experience && hex(g.keep.note.event.pubkey.as_bytes()) == caller {
                Slot::OwnExperience
            } else {
                Slot::Rest
            }
        };
        let mut ordered: Vec<(Slot, RecallItem)> = groups
            .into_iter()
            .map(|g| {
                let lane = slot(&g);
                let also_by = g.names.into_iter().filter(|n| *n != g.keep.note.author_name).collect();
                (lane, g.keep.item(g.score, also_by, g.roots.len(), None))
            })
            .collect();
        ordered.extend(corrections.iter().map(|c| {
            let label = if c.note.quarantined { "quarantined" } else { "superseded" };
            (Slot::Correction, c.item(c.fused as f32, Vec::new(), c.note.roots.len(), Some(label)))
        }));
        ordered.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.score.total_cmp(&a.1.score)).then_with(|| a.1.id.cmp(&b.1.id)));

        // Fill the budget in lane order; an item that does not fit is skipped, never cut.
        let mut used = 0;
        let mut items = Vec::new();
        for (_, item) in ordered {
            let size = item.text.chars().count();
            if used + size <= budget {
                used += size;
                items.push(item);
            }
        }

        let status = if loader.integrity {
            RecallStatus::Undetermined("integrity")
        } else if embedder_down {
            RecallStatus::Undetermined("embedder-down")
        } else if reranker_down {
            RecallStatus::Undetermined("reranker-down")
        } else if emb.is_some() && (indexed < total || index_bad) {
            RecallStatus::Undetermined("index-incomplete")
        } else if found {
            RecallStatus::Found
        } else {
            RecallStatus::Empty
        };
        if status == RecallStatus::Empty {
            items.clear();
        }
        Ok(RecallOutcome { status, items, indexed, total, query_digest })
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
            let vectors = emb.embed(&texts)?;
            if vectors.len() != rows.len() {
                return Err(refuse("index-vector"));
            }
            let vectors = vectors.into_iter().map(unit).collect::<Option<Vec<_>>>().ok_or_else(|| refuse("index-vector"))?;
            if vectors.windows(2).any(|w| w[0].len() != w[1].len()) {
                return Err(refuse("index-vector"));
            }
            for ((seq, _), vector) in rows.iter().zip(&vectors) {
                self.put_embedding(*seq, model, vector)?;
            }
            done += rows.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::note::{Form, NoteDraft, Privacy, NOTE_KIND, QUARANTINE_KIND, SUPERSEDE_KIND};
    use nostr::{Event, SecretKey};

    /// Content words hashed into 256 buckets plus a constant bias dimension: deterministic and model-free.
    struct Words;
    impl Embedder for Words {
        fn model_id(&self) -> &str {
            "fake-words"
        }
        fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            Ok(texts
                .iter()
                .map(|text| {
                    let mut v = vec![0.0f32; 257];
                    v[256] = 1.0;
                    for w in content_words(text) {
                        let h: [u8; 32] = Sha256::digest(w.as_bytes()).into();
                        v[usize::from(h[0])] += 1.0;
                    }
                    v
                })
                .collect())
        }
    }

    /// Shared content words minus one half: no overlap scores below the floor.
    struct Overlap;
    impl Reranker for Overlap {
        fn model_id(&self) -> &str {
            "fake-overlap"
        }
        fn score(&self, query: &str, passages: &[&str]) -> Result<Vec<f32>> {
            let q = content_words(query);
            Ok(passages.iter().map(|p| content_words(p).intersection(&q).count() as f32 - 0.5).collect())
        }
    }

    /// A model server that is down, under the same model id as `Words`.
    struct Down;
    impl Embedder for Down {
        fn model_id(&self) -> &str {
            "fake-words"
        }
        fn embed(&self, _: &[&str]) -> Result<Vec<Vec<f32>>> {
            Err(refuse("test-down"))
        }
    }
    impl Reranker for Down {
        fn model_id(&self) -> &str {
            "fake-overlap"
        }
        fn score(&self, _: &str, _: &[&str]) -> Result<Vec<f32>> {
            Err(refuse("test-down"))
        }
    }

    fn key() -> SecretKey {
        SecretKey::generate().unwrap()
    }

    fn pub_hex(k: &SecretKey) -> String {
        hex(k.public_key().unwrap().as_bytes())
    }

    fn register(s: &SharedStore, agents: &[(&str, &SecretKey, bool)]) {
        for (name, k, owner) in agents {
            let scopes = vec![if *owner { "*".to_string() } else { "builders".to_string() }];
            s.register_agent(name, &pub_hex(k), &scopes, *owner).unwrap();
        }
    }

    fn store_with(agents: &[(&str, &SecretKey, bool)]) -> SharedStore {
        let s = SharedStore::open_in_memory().unwrap();
        register(&s, agents);
        s
    }

    fn put(s: &mut SharedStore, k: &SecretKey, text: &str, lane: Lane, capture: Capture, review: Review, at: u64) -> String {
        let d = NoteDraft {
            text: text.into(),
            subject: "test".into(),
            scope: "builders".into(),
            lane,
            form: Form::Fact,
            privacy: Privacy::Builders,
            capture,
            sources: vec![],
            slot: None,
            valid_from: None,
            valid_to: None,
            epoch: 2,
        };
        let note = s.append(Event::sign(k, at, NOTE_KIND, d.tags(review).unwrap(), d.text.clone()).unwrap()).unwrap();
        hex(note.event.id.as_bytes())
    }

    fn note(s: &mut SharedStore, k: &SecretKey, text: &str, at: u64) -> String {
        put(s, k, text, Lane::Evidence, Capture::ToolObserved, Review::Remembered, at)
    }

    fn query(text: &str, caller: &str) -> RecallQuery {
        RecallQuery { text: text.into(), caller: caller.into(), epoch: 2, scopes: vec![], author: None, budget_chars: 0 }
    }

    fn chars(items: &[RecallItem]) -> usize {
        items.iter().map(|i| i.text.chars().count()).sum()
    }

    #[test]
    fn found_and_empty_with_and_without_reranker() {
        let a = key();
        let mut s = store_with(&[("claude", &a, false)]);
        note(&mut s, &a, "The figurine is on the left shelf.", 10);
        note(&mut s, &a, "The kettle needs descaling every month.", 11);
        assert_eq!(s.index_missing(&Words, 4).unwrap(), 2);
        let found = s.recall(&query("Where is the figurine?", "x"), Some(&Words), None).unwrap();
        assert_eq!(found.status, RecallStatus::Found);
        assert_eq!(found.items[0].text, "The figurine is on the left shelf.");
        assert_eq!(found.items[0].author_name, "claude");
        assert_eq!((found.indexed, found.total), (2, 2));
        // Stopwords match every note in FTS5, but they never make an unanswerable question look answered.
        let empty = s.recall(&query("What is the passport number?", "x"), Some(&Words), None).unwrap();
        assert_eq!(empty.status, RecallStatus::Empty);
        assert!(empty.items.is_empty());
        let reranked = s.recall(&query("Where is the figurine?", "x"), Some(&Words), Some(&Overlap)).unwrap();
        assert_eq!(reranked.status, RecallStatus::Found);
        assert_eq!(reranked.items[0].score, 0.5);
        let below_floor = s.recall(&query("What is the passport number?", "x"), Some(&Words), Some(&Overlap)).unwrap();
        assert_eq!(below_floor.status, RecallStatus::Empty);
        assert!(s.recall(&query("   ", "x"), None, None).is_err());
    }

    #[test]
    fn incomplete_index_and_down_models_are_undetermined() {
        let a = key();
        let mut s = store_with(&[("claude", &a, false)]);
        note(&mut s, &a, "The figurine is on the left shelf.", 10);
        s.index_missing(&Words, 8).unwrap();
        note(&mut s, &a, "The figurine was dusted on Sunday.", 11);
        let q = query("where is the figurine", "x");
        let partial = s.recall(&q, Some(&Words), None).unwrap();
        assert_eq!(partial.status, RecallStatus::Undetermined("index-incomplete"));
        assert_eq!((partial.indexed, partial.total), (1, 2));
        // Keyword alone is complete by construction: the FTS row is written with the note.
        let keyword_only = s.recall(&q, None, None).unwrap();
        assert_eq!(keyword_only.status, RecallStatus::Found);
        assert_eq!((keyword_only.indexed, keyword_only.total), (2, 2));
        assert_eq!(s.index_missing(&Words, 8).unwrap(), 1);
        assert_eq!(s.index_missing(&Words, 8).unwrap(), 0);
        assert_eq!(s.recall(&q, Some(&Words), None).unwrap().status, RecallStatus::Found);
        assert_eq!(s.recall(&q, Some(&Down), None).unwrap().status, RecallStatus::Undetermined("embedder-down"));
        assert_eq!(s.recall(&q, Some(&Words), Some(&Down)).unwrap().status, RecallStatus::Undetermined("reranker-down"));
        let down = s.recall(&query("what is the passport number", "x"), Some(&Down), None).unwrap();
        assert_eq!(down.status, RecallStatus::Undetermined("embedder-down"), "a down model is never reported as empty");
    }

    #[test]
    fn a_note_failing_verification_makes_recall_undetermined() {
        let path = std::env::temp_dir().join(format!("kira-hybrid-{}.sqlite", pub_hex(&key())));
        {
            let a = key();
            let mut s = SharedStore::open(&path).unwrap();
            register(&s, &[("claude", &a, false)]);
            let id = note(&mut s, &a, "original words here", 5);
            let stored = s.get(&id).unwrap().unwrap();
            let mut forged = stored.event.clone();
            forged.content = "forged words here".into();
            let side = rusqlite::Connection::open(&path).unwrap();
            side.execute("UPDATE events SET raw = ?1 WHERE seq = ?2", rusqlite::params![forged.encode().unwrap(), stored.seq])
                .unwrap();
            let r = s.recall(&query("original words", "x"), None, None).unwrap();
            assert_eq!(r.status, RecallStatus::Undetermined("integrity"));
            assert!(r.items.is_empty());
        }
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.clone().into_os_string();
            name.push(suffix);
            let _ = std::fs::remove_file(name);
        }
    }

    #[test]
    fn dedupe_keeps_the_earliest_note_and_names_every_author() {
        let (a, b) = (key(), key());
        let mut s = store_with(&[("claude", &a, false), ("grok", &b, false)]);
        let later = note(&mut s, &b, "the figurine is on the left   shelf.", 20);
        let earliest = note(&mut s, &a, "The Figurine is on the LEFT shelf.", 10);
        s.index_missing(&Words, 8).unwrap();
        let r = s.recall(&query("figurine shelf", "x"), Some(&Words), None).unwrap();
        assert_eq!(r.status, RecallStatus::Found);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].id, earliest);
        assert_ne!(r.items[0].id, later);
        assert_eq!(r.items[0].author_name, "claude");
        assert_eq!(r.items[0].also_by, vec!["grok".to_string()]);
        assert_eq!(r.items[0].roots, 2, "two independent observations, not one");
    }

    #[test]
    fn owner_commitments_lead_and_own_experience_is_reserved() {
        let (peter, grok, claude) = (key(), key(), key());
        let mut s = store_with(&[("peter", &peter, true), ("grok", &grok, false), ("claude", &claude, false)]);
        let decision = "Decision: the figurine stays on the left shelf.";
        let said = "Peter said the figurine is fragile.";
        let own = "I checked the figurine on the shelf myself.";
        put(&mut s, &peter, decision, Lane::Decision, Capture::OwnerTyped, Review::OwnerSigned, 1);
        put(&mut s, &grok, said, Lane::Evidence, Capture::OwnerTyped, Review::Remembered, 2);
        put(&mut s, &claude, own, Lane::Experience, Capture::ToolObserved, Review::Remembered, 3);
        put(&mut s, &grok, "Grok checked the figurine shelf too.", Lane::Experience, Capture::ToolObserved, Review::Remembered, 4);
        for i in 0..6 {
            note(&mut s, &grok, &format!("Figurine shelf figurine shelf figurine shelf, observation {i}."), 10 + i);
        }
        s.index_missing(&Words, 8).unwrap();
        let mut q = query("figurine shelf", &pub_hex(&claude).to_uppercase());
        q.budget_chars = decision.len() + said.len() + own.len() + 60;
        let r = s.recall(&q, Some(&Words), None).unwrap();
        assert_eq!(r.status, RecallStatus::Found);
        assert_eq!(r.items[0].text, decision);
        assert_eq!((r.items[0].lane.as_str(), r.items[0].review.as_str()), ("decision", "owner_signed"));
        assert_eq!(r.items[1].text, said);
        assert_eq!(r.items[2].text, own, "the caller's own experience is not crowded out by other authors");
        assert!(r.items[3..].iter().all(|i| i.author_name == "grok"));
        assert!(chars(&r.items) <= q.budget_chars);
        // Asked by someone else, the same experience note has no reserved lane and competes by score.
        let other = s.recall(&query("figurine shelf", "x"), Some(&Words), None).unwrap();
        assert_eq!(other.items[0].text, decision);
        assert_eq!(other.items[1].text, said);
    }

    #[test]
    fn superseded_and_quarantined_notes_appear_only_as_corrections() {
        let (peter, a, b) = (key(), key(), key());
        let mut s = store_with(&[("peter", &peter, true), ("agent", &a, false), ("other", &b, false)]);
        let old = note(&mut s, &a, "The harness is the tiny one.", 1);
        let new = note(&mut s, &a, "The harness is the deepseek one.", 2);
        let sup = vec![vec!["supersedes".into(), old.clone()], vec!["replacement".into(), new.clone()]];
        s.record(Event::sign(&a, 3, SUPERSEDE_KIND, sup, String::new()).unwrap()).unwrap();
        let bad = note(&mut s, &b, "The harness is secretly broken.", 4);
        let quarantine = vec![vec!["source".into(), pub_hex(&b)]];
        s.record(Event::sign(&peter, 5, QUARANTINE_KIND, quarantine, String::new()).unwrap()).unwrap();
        s.index_missing(&Words, 8).unwrap();
        let r = s.recall(&query("which harness", "x"), Some(&Words), None).unwrap();
        assert_eq!(r.status, RecallStatus::Found);
        let live: Vec<&str> = r.items.iter().filter(|i| i.correction.is_none()).map(|i| i.id.as_str()).collect();
        assert_eq!(live, vec![new.as_str()]);
        let correction = |id: &str| r.items.iter().find(|i| i.id == id).and_then(|i| i.correction.clone());
        assert_eq!(correction(&old).as_deref(), Some("superseded"));
        assert_eq!(correction(&bad).as_deref(), Some("quarantined"));
        // Corrections fill lane (d), ahead of the unreserved rest, and never more than two.
        assert_eq!(r.items.iter().filter(|i| i.correction.is_some()).count(), 2);
        assert_eq!(r.items.last().map(|i| i.id.as_str()), Some(new.as_str()));
    }

    #[test]
    fn ordering_is_deterministic_with_note_id_tie_break() {
        let a = key();
        let mut s = store_with(&[("claude", &a, false)]);
        note(&mut s, &a, "alpha figurine one", 1);
        note(&mut s, &a, "alpha figurine two", 1);
        s.index_missing(&Words, 8).unwrap();
        let q = query("alpha figurine", "x");
        let first = s.recall(&q, Some(&Words), None).unwrap();
        assert_eq!(first, s.recall(&q, Some(&Words), None).unwrap());
        assert_eq!(first.items.len(), 2);
        assert_eq!(first.items[0].score, first.items[1].score);
        assert!(first.items[0].id < first.items[1].id);
        let mut reordered = q.clone();
        reordered.scopes = vec!["b".into(), "a".into(), "a".into()];
        let mut sorted = q.clone();
        sorted.scopes = vec!["a".into(), "b".into()];
        assert_eq!(query_digest(&reordered, 2, 4_800).unwrap(), query_digest(&sorted, 2, 4_800).unwrap());
        assert_ne!(query_digest(&q, 2, 4_800).unwrap(), query_digest(&sorted, 2, 4_800).unwrap());
    }

    #[test]
    fn budget_is_respected() {
        let a = key();
        let mut s = store_with(&[("claude", &a, false)]);
        for i in 0..12 {
            note(&mut s, &a, &format!("Figurine note {i}: {}", "the figurine shelf story ".repeat(10)), i);
        }
        s.index_missing(&Words, 5).unwrap();
        let mut q = query("figurine story", "x");
        q.budget_chars = 1_000;
        let small = s.recall(&q, Some(&Words), None).unwrap();
        assert!(chars(&small.items) <= 1_000);
        assert_eq!(small.items.len(), 3);
        q.budget_chars = 0;
        let default = s.recall(&q, Some(&Words), None).unwrap();
        assert!(chars(&default.items) <= DEFAULT_BUDGET);
        assert_eq!(default.items.len(), 12);
    }

    #[test]
    fn index_missing_stores_unit_vectors_once() {
        let a = key();
        let mut s = store_with(&[("claude", &a, false)]);
        note(&mut s, &a, "one figurine on a shelf", 1);
        note(&mut s, &a, "a kettle on the stove", 2);
        assert_eq!(s.index_missing(&Words, 1).unwrap(), 2);
        assert_eq!(s.index_missing(&Words, 1).unwrap(), 0);
        for (_, v) in s.embeddings("fake-words").unwrap() {
            assert!((norm(&v) - 1.0).abs() < 1e-5);
        }
    }
}
