// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recall: found | empty | undetermined. Similarity alone never answers a factual question.
//! Types and model traits; the hybrid pipeline (FTS5 + dense + rerank + lanes) lives in `hybrid.rs`.

use canon::Result;

/// Turns text into a vector. Implemented out of process (llama-server); `model_id` is the model file's sha256.
pub trait Embedder {
    fn model_id(&self) -> &str;
    fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>>;
}

/// Scores (query, passage) pairs; higher is more relevant. Implemented out of process.
pub trait Reranker {
    fn model_id(&self) -> &str;
    fn score(&self, query: &str, passages: &[&str]) -> Result<Vec<f32>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecallQuery {
    pub text: String,
    /// The calling agent's public key (hex); its own experience lane is reserved budget.
    pub caller: String,
    /// Default 2; epoch 1 is the archived import, searched only when asked.
    pub epoch: u32,
    /// Restrict to these scopes (empty = all scopes the caller may read).
    pub scopes: Vec<String>,
    pub author: Option<String>,
    /// Character budget for returned text (default 4,800).
    pub budget_chars: usize,
    /// Whether `local` notes may be read. The service sets it for the owner only; when false, local notes are dropped
    /// before ranking, dedupe and the found decision.
    pub include_local: bool,
    /// Whether `web-derived` notes may take part. Automatic recall leaves them out (spec v0.3 §2: tainted material is
    /// excluded unless the caller asks for it); a caller that asks gets them, labelled by their capture.
    pub include_web: bool,
    /// The time notes are judged against for `valid_from` / `valid_to` (unix seconds). 0 means the system clock.
    pub now: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecallStatus {
    Found,
    /// Searched a complete, healthy index and nothing cleared the threshold.
    Empty,
    /// Could not tell: index incomplete, a model down, an integrity failure, or every relevant note over the budget.
    /// Never reported as empty.
    Undetermined(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecallItem {
    pub id: String,
    pub author: String,
    pub author_name: String,
    /// Other authors who wrote the same statement (deduped by statement hash).
    pub also_by: Vec<String>,
    /// Ids of the other notes folded into this one by dedupe.
    pub also_by_ids: Vec<String>,
    pub lane: String,
    pub form: String,
    pub review: String,
    /// The capture of the statement: the LOWEST-trust capture among the note shown and every note folded into it by
    /// dedupe (web-derived is lowest), so a web-derived copy cannot hide behind an earlier model-generated one. The
    /// note shown has its own capture in `kept_capture`.
    pub capture: String,
    pub kept_capture: String,
    /// The capture of each note in `also_by_ids`, in the same order.
    pub also_by_captures: Vec<String>,
    pub created_at: u64,
    pub text: String,
    pub score: f32,
    /// Ancestry roots: the distinct originating notes (computed by the store, never taken from tags). A count of
    /// roots is not a count of observations; see `evidence` for what the note stands on.
    pub roots: usize,
    /// What the note stands on: `owner-review`, `owner-words`, `archive-import` (an owner-run import), `corroborated`
    /// (roots by at least two different authors) or `unverified` (a note nobody reviewed or corroborated).
    pub evidence: &'static str,
    /// The statement cleared the relevance floor (an answer, as against a note that only rides along).
    pub relevant: bool,
    /// "superseded", "quarantined", "expired" or "not-yet-valid" when shown as history after the current items: none of
    /// these is live memory. A quarantined item's text is empty.
    pub correction: Option<String>,
    /// For a superseded item, the id of the note that stands where it did (always among the live items returned).
    pub current_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecallOutcome {
    pub status: RecallStatus,
    pub items: Vec<RecallItem>,
    /// Relevant notes skipped because they did not fit the budget.
    pub omitted: usize,
    pub indexed: u64,
    pub total: u64,
    /// sha256 (hex) of the canonical query, for the Aura receipt.
    pub query_digest: String,
    /// What judged this recall, so a receipt says which thresholds and models decided it: `rerank` when the
    /// cross-encoder score against `rerank_floor` decided, `keyword+cosine` when a keyword hit or `cosine_floor` did.
    pub judged_by: &'static str,
    pub rerank_floor: f32,
    pub cosine_floor: f32,
    /// Model ids (sha256 of the model file) of the embedder and reranker that took part; None when absent.
    pub embed_model: Option<String>,
    pub rerank_model: Option<String>,
    /// sha256 of the practice question set the floors were calibrated on (`hybrid::CALIBRATION_SET`).
    pub calibration_set: &'static str,
}
