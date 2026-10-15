// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::anchor::MemoryHead;
use crate::embed::{
    EmbedError, EmbedInput, EmbedPurpose, Embedding, LocalEmbedder, LocalEndpoint, LocalModel,
};
use canon::{digest::Digest32, ids::NoteId};
use core::fmt;
use core::mem::size_of;
use std::collections::BTreeSet;

pub const MAX_CANDIDATES: usize = 50;
pub const MAX_INDEX_BATCH_DOCUMENTS: usize = 128;
pub const MAX_INDEX_BATCH_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticError {
    Unavailable,
    IndexStale,
    IndexIncomplete,
    Model,
    Bounds,
    Response,
    Embedding(EmbedError),
}

impl SemanticError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "kira:semantic-unavailable",
            Self::IndexStale => "kira:semantic-index-stale",
            Self::IndexIncomplete => "kira:semantic-index-incomplete",
            Self::Model => "kira:semantic-model",
            Self::Bounds => "kira:semantic-too-large",
            Self::Response => "kira:semantic-response",
            Self::Embedding(error) => error.code(),
        }
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SemanticError {}

impl From<EmbedError> for SemanticError {
    fn from(error: EmbedError) -> Self {
        Self::Embedding(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexPin {
    head: MemoryHead,
    model: LocalModel,
}

impl IndexPin {
    pub fn new(head: MemoryHead, model: LocalModel) -> Result<Self, SemanticError> {
        head.validate().map_err(|_| SemanticError::IndexStale)?;
        Ok(Self { head, model })
    }

    pub const fn head(self) -> MemoryHead {
        self.head
    }

    pub const fn model(self) -> LocalModel {
        self.model
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexState {
    pub pin: IndexPin,
    pub indexed_notes: u64,
    pub eligible_notes: u64,
    pub complete: bool,
}

impl IndexState {
    pub fn require_complete(self, pin: IndexPin) -> Result<(), SemanticError> {
        if self.pin != pin {
            return Err(SemanticError::IndexStale);
        }
        if !self.complete || self.indexed_notes != self.eligible_notes {
            return Err(SemanticError::IndexIncomplete);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    note_id: NoteId,
    score: f64,
}

impl Candidate {
    pub fn new(note_id: NoteId, score: f64) -> Result<Self, SemanticError> {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(SemanticError::Response);
        }
        Ok(Self { note_id, score })
    }

    pub fn note_id(&self) -> &NoteId {
        &self.note_id
    }

    pub const fn score(&self) -> f64 {
        self.score
    }
}

pub struct SearchRequest<'a> {
    pin: IndexPin,
    embedding: &'a Embedding,
    limit: usize,
}

impl<'a> SearchRequest<'a> {
    pub fn new(
        pin: IndexPin,
        embedding: &'a Embedding,
        limit: usize,
    ) -> Result<Self, SemanticError> {
        if limit == 0 || limit > MAX_CANDIDATES {
            return Err(SemanticError::Bounds);
        }
        if embedding.model() != pin.model {
            return Err(SemanticError::Model);
        }
        Ok(Self {
            pin,
            embedding,
            limit,
        })
    }

    pub const fn pin(&self) -> IndexPin {
        self.pin
    }

    pub const fn embedding(&self) -> &Embedding {
        self.embedding
    }

    pub const fn limit(&self) -> usize {
        self.limit
    }
}

#[derive(Clone, Debug)]
pub struct SearchReply {
    pub state: IndexState,
    candidates: Vec<Candidate>,
}

impl SearchReply {
    pub fn new(state: IndexState, mut candidates: Vec<Candidate>) -> Result<Self, SemanticError> {
        if candidates.len() > MAX_CANDIDATES {
            return Err(SemanticError::Bounds);
        }
        let mut ids = BTreeSet::new();
        if candidates.iter().any(|item| !ids.insert(&item.note_id)) {
            return Err(SemanticError::Response);
        }
        candidates.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.note_id.cmp(&b.note_id))
        });
        Ok(Self { state, candidates })
    }

    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    pub fn into_candidates(self) -> Vec<Candidate> {
        self.candidates
    }
}

#[derive(Debug)]
pub struct IndexBuild {
    token: [u8; 16],
    target: IndexPin,
    eligible_notes: u64,
}

impl IndexBuild {
    pub const fn new(token: [u8; 16], target: IndexPin, eligible_notes: u64) -> Self {
        Self {
            token,
            target,
            eligible_notes,
        }
    }

    pub const fn token(&self) -> &[u8; 16] {
        &self.token
    }

    pub const fn target(&self) -> IndexPin {
        self.target
    }

    pub const fn eligible_notes(&self) -> u64 {
        self.eligible_notes
    }
}

pub struct IndexDocument<'a> {
    note_id: &'a NoteId,
    note_commitment: Digest32,
    start: u64,
    input: EmbedInput<'a>,
    embedding: &'a Embedding,
}

impl<'a> IndexDocument<'a> {
    pub fn new(
        note_id: &'a NoteId,
        note_commitment: Digest32,
        start: u64,
        text: &'a str,
        embedding: &'a Embedding,
    ) -> Result<Self, SemanticError> {
        let input = EmbedInput::new(EmbedPurpose::Document, text)?;
        start
            .checked_add(text.len() as u64)
            .ok_or(SemanticError::Bounds)?;
        Ok(Self {
            note_id,
            note_commitment,
            start,
            input,
            embedding,
        })
    }

    pub const fn note_id(&self) -> &NoteId {
        self.note_id
    }

    pub const fn note_commitment(&self) -> Digest32 {
        self.note_commitment
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn input(&self) -> EmbedInput<'a> {
        self.input
    }

    pub const fn embedding(&self) -> &Embedding {
        self.embedding
    }
}

pub struct IndexBatch<'a> {
    token: [u8; 16],
    target: IndexPin,
    documents: Vec<IndexDocument<'a>>,
}

impl<'a> IndexBatch<'a> {
    pub fn new(
        build: &IndexBuild,
        documents: Vec<IndexDocument<'a>>,
    ) -> Result<Self, SemanticError> {
        if documents.is_empty() || documents.len() > MAX_INDEX_BATCH_DOCUMENTS {
            return Err(SemanticError::Bounds);
        }
        let mut bytes = 0usize;
        let mut seen = BTreeSet::new();
        for document in &documents {
            if document.embedding.model() != build.target.model {
                return Err(SemanticError::Model);
            }
            if !seen.insert((document.note_id, document.start)) {
                return Err(SemanticError::Response);
            }
            bytes = bytes
                .checked_add(document.note_id.as_str().len() + 32 + size_of::<u64>())
                .and_then(|sum| sum.checked_add(document.input.text().len()))
                .and_then(|sum| {
                    sum.checked_add(document.embedding.values().len() * size_of::<f32>())
                })
                .ok_or(SemanticError::Bounds)?;
            if bytes > MAX_INDEX_BATCH_BYTES {
                return Err(SemanticError::Bounds);
            }
        }
        Ok(Self {
            token: build.token,
            target: build.target,
            documents,
        })
    }

    pub fn require_build(&self, build: &IndexBuild) -> Result<(), SemanticError> {
        if self.token != build.token || self.target != build.target {
            return Err(SemanticError::IndexStale);
        }
        Ok(())
    }

    pub fn documents(&self) -> &[IndexDocument<'a>] {
        &self.documents
    }
}

pub trait OpenViking {
    fn endpoint(&self) -> LocalEndpoint;
    fn index_state(&self) -> Result<IndexState, SemanticError>;
    fn begin_rebuild(
        &mut self,
        target: IndexPin,
        eligible_notes: u64,
    ) -> Result<IndexBuild, SemanticError>;
    fn index_batch(
        &mut self,
        build: &IndexBuild,
        batch: IndexBatch<'_>,
    ) -> Result<(), SemanticError>;
    fn finish_rebuild(&mut self, build: IndexBuild) -> Result<IndexState, SemanticError>;
    fn rank(&mut self, request: SearchRequest<'_>) -> Result<SearchReply, SemanticError>;
}

pub fn recall_candidates(
    index: &mut dyn OpenViking,
    embedder: &mut dyn LocalEmbedder,
    head: MemoryHead,
    query: &str,
    limit: usize,
) -> Result<SearchReply, SemanticError> {
    let input = EmbedInput::new(EmbedPurpose::Query, query)?;
    let pin = IndexPin::new(head, embedder.model())?;
    let before = index.index_state()?;
    before.require_complete(pin)?;
    let embedding = embedder.embed(input)?;
    let request = SearchRequest::new(pin, &embedding, limit)?;
    if embedder.model() != pin.model {
        return Err(SemanticError::Model);
    }
    let reply = index.rank(request)?;
    reply.state.require_complete(pin)?;
    if reply.state != before {
        return Err(SemanticError::IndexStale);
    }
    if reply.candidates.len() > limit {
        return Err(SemanticError::Response);
    }
    let after = index.index_state()?;
    after.require_complete(pin)?;
    if after != before {
        return Err(SemanticError::IndexStale);
    }
    Ok(reply)
}
