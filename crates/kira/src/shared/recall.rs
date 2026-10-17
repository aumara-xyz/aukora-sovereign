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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecallStatus {
    Found,
    /// Searched a complete, healthy index and nothing cleared the threshold.
    Empty,
    /// Could not tell: index incomplete, a model down, or integrity failure. Never reported as empty.
    Undetermined(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecallItem {
    pub id: String,
    pub author: String,
    pub author_name: String,
    /// Other authors who wrote the same statement (deduped by statement hash).
    pub also_by: Vec<String>,
    pub lane: String,
    pub form: String,
    pub review: String,
    pub capture: String,
    pub created_at: u64,
    pub text: String,
    pub score: f32,
    /// Independent ancestry roots (computed by the store, never taken from tags).
    pub roots: usize,
    /// "superseded" or "quarantined" when shown in the corrections lane.
    pub correction: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecallOutcome {
    pub status: RecallStatus,
    pub items: Vec<RecallItem>,
    pub indexed: u64,
    pub total: u64,
    /// sha256 (hex) of the canonical query, for the Aura receipt.
    pub query_digest: String,
}
