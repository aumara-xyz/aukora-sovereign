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
/// Scores encode `(cosine + 1) / 2`; 0.7 therefore requires cosine >= 0.4.
pub const SEMANTIC_RELEVANCE_FLOOR: f64 = 0.7;
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

    pub fn is_relevant(&self) -> bool {
        self.score >= SEMANTIC_RELEVANCE_FLOOR
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
                .and_then(|sum| sum.checked_add(std::mem::size_of_val(document.embedding.values())))
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

/// Returns ranked candidates from an index whose head and model stay unchanged.
/// Recall applies the relevance floor and an independent lexical search after
/// authenticating the retained notes. No score grants disclosure permission.
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
    if before.eligible_notes != 0 && reply.candidates.is_empty() {
        return Err(SemanticError::IndexIncomplete);
    }
    let after = index.index_state()?;
    after.require_complete(pin)?;
    if after != before {
        return Err(SemanticError::IndexStale);
    }
    Ok(reply)
}

/// The independent index unit has a sixty-second start grace.
pub const START_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

const MANIFEST_COLLECTION: &str = "aukora_kira_manifest_v1";
const VECTOR_INDEX: &str = "recall";
const HTTP_BOUND: usize = 1_048_576;

use crate::embed::{loopback_http, parse_local_json, LocalHttpError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    generation: String,
    sequence: u64,
    head: Option<String>,
    model: String,
    dimensions: u16,
    notes: u64,
}

impl Manifest {
    fn state(&self) -> Result<IndexState, SemanticError> {
        if self.schema != "aukora-kira-index-v1"
            || self.generation.len() != 32
            || !self
                .generation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.notes > canon::json::MAX_SAFE_INTEGER as u64
        {
            return Err(SemanticError::Response);
        }
        let head = MemoryHead {
            version: 1,
            sequence: self.sequence,
            hash: self
                .head
                .as_deref()
                .map(Digest32::from_hex)
                .transpose()
                .map_err(|_| SemanticError::Response)?,
        };
        let model = LocalModel::new(
            Digest32::from_hex(&self.model).map_err(|_| SemanticError::Response)?,
            self.dimensions,
        )?;
        Ok(IndexState {
            pin: IndexPin::new(head, model)?,
            indexed_notes: self.notes,
            eligible_notes: self.notes,
            complete: true,
        })
    }

    fn collection(&self) -> String {
        format!("aukora_kira_{}", self.generation)
    }
}

struct PendingIndex {
    token: [u8; 16],
    manifest: Manifest,
    pin: IndexPin,
    notes: BTreeMap<NoteId, Digest32>,
    parts: BTreeSet<(NoteId, u64)>,
}

/// Client for the direct-vector service shipped inside OpenViking 0.4.21.
/// No note text, file path or service URL comes back as a recall result.
pub struct VikingDb {
    port: NonZeroU16,
    model: LocalModel,
    timeout: Duration,
    pending: Option<PendingIndex>,
}

impl VikingDb {
    pub fn new(
        port: NonZeroU16,
        model: LocalModel,
        timeout: Duration,
    ) -> Result<Self, SemanticError> {
        if !(4..=4_096).contains(&model.dimensions()) || model.dimensions() % 4 != 0 {
            return Err(SemanticError::Model);
        }
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(SemanticError::Bounds);
        }
        Ok(Self {
            port,
            model,
            timeout,
            pending: None,
        })
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        deadline: Instant,
    ) -> Result<Value, SemanticError> {
        let bytes = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| SemanticError::Response)?;
        if bytes.as_ref().is_some_and(|b| b.len() > HTTP_BOUND) {
            return Err(SemanticError::Bounds);
        }
        let bytes = loopback_http(
            self.port,
            method,
            path,
            &[],
            bytes.as_deref(),
            deadline,
            HTTP_BOUND,
        )
        .map_err(|error| match error {
            LocalHttpError::Bounds => SemanticError::Bounds,
            LocalHttpError::Response => SemanticError::Response,
            LocalHttpError::Unavailable | LocalHttpError::Status(_) => SemanticError::Unavailable,
        })?;
        parse_local_json(&bytes).map_err(|_| SemanticError::Response)
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        deadline: Instant,
    ) -> Result<Value, SemanticError> {
        let reply = self.request(method, path, body, deadline)?;
        match reply.get("code").and_then(Value::as_u64) {
            Some(0) => reply.get("data").cloned().ok_or(SemanticError::Response),
            Some(1_000_003) => Err(SemanticError::IndexIncomplete),
            Some(_) => Err(SemanticError::Unavailable),
            None => Err(SemanticError::Response),
        }
    }

    /// Reachability alone does not establish a complete or correctly pinned index.
    pub fn health(&self) -> Result<(), SemanticError> {
        let reply = self.request("GET", "/health", None, Instant::now() + self.timeout)?;
        if reply.get("status").and_then(Value::as_str) != Some("healthy") {
            return Err(SemanticError::Unavailable);
        }
        Ok(())
    }

    fn create_collection(
        &self,
        name: &str,
        vectors: bool,
        deadline: Instant,
    ) -> Result<(), SemanticError> {
        let fields = if vectors {
            json!([
                {"FieldName":"id","FieldType":"string","IsPrimaryKey":true},
                {"FieldName":"embedding","FieldType":"vector","Dim":self.model.dimensions()},
                {"FieldName":"note_id","FieldType":"string"},
                {"FieldName":"commitment","FieldType":"string"},
                {"FieldName":"start","FieldType":"string"}
            ])
        } else {
            json!([
                {"FieldName":"id","FieldType":"string","IsPrimaryKey":true},
                {"FieldName":"marker","FieldType":"vector","Dim":4},
                {"FieldName":"manifest","FieldType":"string"}
            ])
        };
        self.call(
            "POST",
            "/CreateVikingdbCollection",
            Some(&json!({
                "CollectionName":name,"ProjectName":"default","Fields":fields
            })),
            deadline,
        )?;
        Ok(())
    }

    fn ensure_manifest_collection(&self, deadline: Instant) -> Result<(), SemanticError> {
        let path = format!(
            "/GetVikingdbCollection?CollectionName={MANIFEST_COLLECTION}&ProjectName=default"
        );
        match self.call("GET", &path, None, deadline) {
            Ok(_) => Ok(()),
            Err(SemanticError::IndexIncomplete) => {
                match self.create_collection(MANIFEST_COLLECTION, false, deadline) {
                    Ok(()) => Ok(()),
                    Err(SemanticError::IndexIncomplete) => {
                        self.call("GET", &path, None, deadline).map(|_| ())
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    fn manifest(&self, deadline: Instant) -> Result<Manifest, SemanticError> {
        let path = format!("/api/vikingdb/data/fetch_in_collection?collection_name={MANIFEST_COLLECTION}&project=default&ids=%5B%22active%22%5D");
        let reply = self.call("GET", &path, None, deadline)?;
        let missing = reply
            .get("ids_not_exist")
            .and_then(Value::as_array)
            .ok_or(SemanticError::Response)?;
        let items = reply
            .get("items")
            .and_then(Value::as_array)
            .ok_or(SemanticError::Response)?;
        if items.is_empty() && missing.as_slice() == [json!("active")] {
            return Err(SemanticError::IndexIncomplete);
        }
        if items.len() != 1 || !missing.is_empty() || items[0].get("id") != Some(&json!("active")) {
            return Err(SemanticError::Response);
        }
        let text = items[0]
            .get("fields")
            .and_then(|f| f.get("manifest"))
            .and_then(Value::as_str)
            .ok_or(SemanticError::Response)?;
        let value = parse_local_json(text.as_bytes()).map_err(|_| SemanticError::Response)?;
        let manifest: Manifest =
            serde_json::from_value(value).map_err(|_| SemanticError::Response)?;
        manifest.state()?;
        self.require_index(&manifest.collection(), deadline)?;
        Ok(manifest)
    }

    fn require_index(&self, collection: &str, deadline: Instant) -> Result<(), SemanticError> {
        let path = format!("/GetVikingdbIndex?CollectionName={collection}&ProjectName=default&IndexName={VECTOR_INDEX}");
        let info = self.call("GET", &path, None, deadline)?;
        if info.get("IndexName").and_then(Value::as_str) != Some(VECTOR_INDEX)
            || info.get("CollectionName").and_then(Value::as_str) != Some(collection)
            || info.get("VectorIndex")
                != Some(&json!({"IndexType":"flat","Distance":"cosine","Quant":"float"}))
        {
            return Err(SemanticError::IndexIncomplete);
        }
        Ok(())
    }

    fn upsert(
        &self,
        collection: &str,
        fields: Vec<Value>,
        deadline: Instant,
    ) -> Result<(), SemanticError> {
        let expected: BTreeSet<_> = fields
            .iter()
            .map(|f| {
                f.get("id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or(SemanticError::Response)
            })
            .collect::<Result<_, _>>()?;
        if expected.len() != fields.len() {
            return Err(SemanticError::Response);
        }
        let reply = self.call(
            "POST",
            "/api/vikingdb/data/upsert",
            Some(&json!({
                "collection_name":collection,"project":"default","fields":fields,"ttl":0
            })),
            deadline,
        )?;
        let ids = reply.as_array().ok_or(SemanticError::Response)?;
        let actual: BTreeSet<_> = ids
            .iter()
            .map(|id| {
                id.as_str()
                    .map(str::to_owned)
                    .ok_or(SemanticError::Response)
            })
            .collect::<Result<_, _>>()?;
        if actual != expected || ids.len() != actual.len() {
            return Err(SemanticError::Response);
        }
        for group in fields.chunks(48) {
            let ids: Vec<_> = group
                .iter()
                .map(|row| row["id"].as_str().unwrap_or_default())
                .collect();
            let encoded = ids
                .iter()
                .map(|id| format!("%22{id}%22"))
                .collect::<Vec<_>>()
                .join("%2C");
            let path = format!("/api/vikingdb/data/fetch_in_collection?collection_name={collection}&project=default&ids=%5B{encoded}%5D");
            let fetched = self.call("GET", &path, None, deadline)?;
            if fetched.get("ids_not_exist") != Some(&json!([])) {
                return Err(SemanticError::IndexIncomplete);
            }
            let items = fetched
                .get("items")
                .and_then(Value::as_array)
                .ok_or(SemanticError::Response)?;
            if items.len() != group.len() {
                return Err(SemanticError::IndexIncomplete);
            }
            let mut seen = BTreeSet::new();
            for item in items {
                let id = item
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or(SemanticError::Response)?;
                if !seen.insert(id) {
                    return Err(SemanticError::Response);
                }
                let original = group
                    .iter()
                    .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
                    .ok_or(SemanticError::Response)?;
                for (key, value) in original.as_object().ok_or(SemanticError::Response)? {
                    if key == "id" {
                        continue;
                    }
                    let actual = item
                        .get("fields")
                        .and_then(|f| f.get(key))
                        .ok_or(SemanticError::Response)?;
                    let equal = if let (Some(a), Some(b)) = (value.as_array(), actual.as_array()) {
                        a.len() == b.len()
                            && a.iter()
                                .zip(b)
                                .all(|(x, y)| match (x.as_f64(), y.as_f64()) {
                                    (Some(x), Some(y)) => x as f32 == y as f32,
                                    _ => false,
                                })
                    } else {
                        actual == value
                    };
                    if !equal {
                        return Err(SemanticError::Response);
                    }
                }
            }
        }
        Ok(())
    }
}

impl OpenViking for VikingDb {
    fn endpoint(&self) -> LocalEndpoint {
        LocalEndpoint::Loopback(self.port)
    }

    fn index_state(&self) -> Result<IndexState, SemanticError> {
        self.manifest(Instant::now() + self.timeout)?.state()
    }

    fn begin_rebuild(
        &mut self,
        target: IndexPin,
        eligible_notes: u64,
    ) -> Result<IndexBuild, SemanticError> {
        if target.model() != self.model {
            return Err(SemanticError::Model);
        }
        if eligible_notes > canon::json::MAX_SAFE_INTEGER as u64 {
            return Err(SemanticError::Bounds);
        }
        let deadline = Instant::now() + self.timeout;
        self.ensure_manifest_collection(deadline)?;
        let mut token = [0; 16];
        getrandom::fill(&mut token).map_err(|_| SemanticError::Unavailable)?;
        let generation = token.iter().map(|b| format!("{b:02x}")).collect();
        let manifest = Manifest {
            schema: "aukora-kira-index-v1".into(),
            generation,
            sequence: target.head().sequence,
            head: target.head().hash.map(|hash| hash.to_string()),
            model: self.model.digest().to_string(),
            dimensions: self.model.dimensions(),
            notes: eligible_notes,
        };
        self.create_collection(&manifest.collection(), true, deadline)?;
        self.pending = Some(PendingIndex {
            token,
            manifest,
            pin: target,
            notes: BTreeMap::new(),
            parts: BTreeSet::new(),
        });
        Ok(IndexBuild::new(token, target, eligible_notes))
    }

    fn index_batch(
        &mut self,
        build: &IndexBuild,
        batch: IndexBatch<'_>,
    ) -> Result<(), SemanticError> {
        batch.require_build(build)?;
        let mut pending = self.pending.take().ok_or(SemanticError::IndexIncomplete)?;
        if pending.token != *build.token()
            || pending.pin != build.target()
            || pending.manifest.notes != build.eligible_notes()
        {
            self.pending = Some(pending);
            return Err(SemanticError::IndexStale);
        }
        let mut fields = Vec::new();
        for document in batch.documents() {
            if !pending
                .parts
                .insert((document.note_id().clone(), document.start()))
            {
                return Err(SemanticError::Response);
            }
            if pending
                .notes
                .insert(document.note_id().clone(), document.note_commitment())
                .is_some_and(|prior| prior != document.note_commitment())
            {
                return Err(SemanticError::Response);
            }
            if pending.notes.len() as u64 > build.eligible_notes() {
                return Err(SemanticError::Bounds);
            }
            let mut hasher = Sha256::new();
            hasher.update(b"aukora:kira-index-part:v1\0");
            hasher.update(document.note_id().as_str().as_bytes());
            hasher.update(document.start().to_be_bytes());
            let id = Digest32::from_bytes(hasher.finalize().into()).to_string();
            fields.push(json!({"id":id,"embedding":document.embedding().values(),
                "note_id":document.note_id().as_str(),"commitment":document.note_commitment().to_string(),
                "start":document.start().to_string()}));
        }
        self.upsert(
            &pending.manifest.collection(),
            fields,
            Instant::now() + self.timeout,
        )?;
        self.pending = Some(pending);
        Ok(())
    }

    fn finish_rebuild(&mut self, build: IndexBuild) -> Result<IndexState, SemanticError> {
        let pending = self.pending.take().ok_or(SemanticError::IndexIncomplete)?;
        if pending.token != *build.token()
            || pending.pin != build.target()
            || pending.manifest.notes != build.eligible_notes()
        {
            self.pending = Some(pending);
            return Err(SemanticError::IndexStale);
        }
        if pending.notes.len() as u64 != build.eligible_notes() {
            return Err(SemanticError::IndexIncomplete);
        }
        let deadline = Instant::now() + self.timeout;
        self.call("POST", "/CreateVikingdbIndex", Some(&json!({
            "CollectionName":pending.manifest.collection(),"ProjectName":"default","IndexName":VECTOR_INDEX,
            "VectorIndex":{"IndexType":"flat","Distance":"cosine","Quant":"float"},"ScalarIndex":[]
        })), deadline)?;
        self.require_index(&pending.manifest.collection(), deadline)?;
        let state = pending.manifest.state()?;
        let text = serde_json::to_string(&pending.manifest).map_err(|_| SemanticError::Response)?;
        self.upsert(
            MANIFEST_COLLECTION,
            vec![json!({"id":"active","marker":[1.0,0.0,0.0,0.0],"manifest":text})],
            deadline,
        )?;
        if self.manifest(deadline)? != pending.manifest {
            return Err(SemanticError::IndexStale);
        }
        Ok(state)
    }

    fn rank(&mut self, request: SearchRequest<'_>) -> Result<SearchReply, SemanticError> {
        let deadline = Instant::now() + self.timeout;
        let manifest = self.manifest(deadline)?;
        let state = manifest.state()?;
        state.require_complete(request.pin())?;
        if request.pin().model() != self.model {
            return Err(SemanticError::Model);
        }
        let reply = self.call("POST", "/api/vikingdb/data/search/vector", Some(&json!({
            "collection_name":manifest.collection(),"index_name":VECTOR_INDEX,"project":"default",
            "dense_vector":request.embedding().values(),"limit":MAX_CANDIDATES,
            "output_fields":["note_id","commitment","start"]
        })), deadline)?;
        let rows = reply
            .get("data")
            .and_then(Value::as_array)
            .ok_or(SemanticError::Response)?;
        if rows.len() > MAX_CANDIDATES {
            return Err(SemanticError::Bounds);
        }
        let mut scores: BTreeMap<NoteId, f64> = BTreeMap::new();
        for row in rows {
            let fields = row.get("fields").ok_or(SemanticError::Response)?;
            let id = NoteId::new(
                fields
                    .get("note_id")
                    .and_then(Value::as_str)
                    .ok_or(SemanticError::Response)?
                    .to_owned(),
            )
            .map_err(|_| SemanticError::Response)?;
            let commitment = fields
                .get("commitment")
                .and_then(Value::as_str)
                .ok_or(SemanticError::Response)?;
            Digest32::from_hex(commitment).map_err(|_| SemanticError::Response)?;
            let start = fields
                .get("start")
                .and_then(Value::as_str)
                .ok_or(SemanticError::Response)?
                .parse::<u64>()
                .map_err(|_| SemanticError::Response)?;
            let mut hash = Sha256::new();
            hash.update(b"aukora:kira-index-part:v1\0");
            hash.update(id.as_str().as_bytes());
            hash.update(start.to_be_bytes());
            let part_id = Digest32::from_bytes(hash.finalize().into()).to_string();
            if row.get("id").and_then(Value::as_str) != Some(part_id.as_str()) {
                return Err(SemanticError::Response);
            }
            let cosine = row
                .get("score")
                .and_then(Value::as_f64)
                .ok_or(SemanticError::Response)?;
            if !cosine.is_finite() || !(-1.00001..=1.00001).contains(&cosine) {
                return Err(SemanticError::Response);
            }
            let score = (cosine.clamp(-1.0, 1.0) + 1.0) / 2.0;
            scores
                .entry(id)
                .and_modify(|s| *s = s.max(score))
                .or_insert(score);
        }
        if self.manifest(deadline)? != manifest {
            return Err(SemanticError::IndexStale);
        }
        let mut candidates = scores
            .into_iter()
            .map(|(id, score)| Candidate::new(id, score))
            .collect::<Result<Vec<_>, _>>()?;
        candidates.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.note_id.cmp(&b.note_id))
        });
        candidates.truncate(request.limit());
        SearchReply::new(state, candidates)
    }
}

/// Observes only Kira's private index pin; chain-head checks remain unwritten here.
pub struct IndexHealth<'a> {
    pub index: &'a dyn OpenViking,
    pub expected: IndexPin,
    pub context: crate::health::HealthContext,
}

impl crate::health::HealthObserver for IndexHealth<'_> {
    fn observe(
        &mut self,
        spec: canon::health::CheckSpec,
        _requested: crate::health::HealthContext,
    ) -> crate::health::CheckObservation {
        use crate::health::{CheckObservation, ObservationVerdict, ObservedCheck, INDEX_PIN};
        if spec != INDEX_PIN {
            return CheckObservation::Unwritten;
        }
        let verdict = match self
            .index
            .index_state()
            .and_then(|s| s.require_complete(self.expected))
        {
            Ok(()) => ObservationVerdict::Satisfied,
            Err(SemanticError::Unavailable | SemanticError::Embedding(EmbedError::Unavailable)) => {
                return CheckObservation::Unreachable
            }
            Err(SemanticError::IndexIncomplete) => return CheckObservation::NotChecked,
            Err(SemanticError::IndexStale) => ObservationVerdict::Disagreement,
            Err(_) => ObservationVerdict::InvariantFailed,
        };
        CheckObservation::Measured(ObservedCheck {
            check: spec.check,
            context: self.context,
            expires_at_ms: self
                .context
                .observed_at_ms
                .saturating_add(spec.freshness_ms),
            verdict,
        })
    }
}
