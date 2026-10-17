// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recall's model clients for a local llama.cpp `llama-server`: embeddings (POST /v1/embeddings) and rerank
//! (POST /v1/rerank). Loopback only, 30 s per request, over the crate's hardened HTTP/1.1 transport
//! (`embed::loopback_http`: IPv4 127.0.0.1, Content-Length bodies, no redirects or transfer encodings).
//!
//! The server must be started with `--alias <model_id>`, the model file's sha256. Every call first checks that
//! /v1/models serves that id, so a swapped model file refuses instead of filing vectors under the wrong name.

use super::recall::{Embedder, Reranker};
use crate::embed::{loopback_http, parse_local_json, LocalHttpError};
use canon::{Refusal, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::time::{Duration, Instant};

/// Deadline for each HTTP request.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Texts per embeddings request: keeps each response under the transport's 1 MiB cap up to 4,096 dimensions.
pub const EMBED_BATCH: usize = 8;
/// Leading bytes of a text sent to a model, cut at a character boundary. Keyword search still covers whole notes.
pub const MAX_INPUT_BYTES: usize = 2_048;
/// Passages per rerank call.
pub const MAX_RERANK_PASSAGES: usize = 64;
const MAX_DIMENSIONS: usize = 8_192;
const MAX_RESPONSE: usize = 1_048_576;
const MAX_MODELS_RESPONSE: usize = 65_536;

fn refuse(code: &'static str) -> Refusal {
    Refusal { organ: "kira", reason: code }
}

fn http(error: LocalHttpError) -> Refusal {
    refuse(match error {
        LocalHttpError::Unavailable => "llama-unavailable",
        LocalHttpError::Status(_) => "llama-status",
        LocalHttpError::Response => "llama-response",
        LocalHttpError::Bounds => "llama-bounds",
    })
}

/// The port of the one loopback address the transport reaches (127.0.0.1). Another loopback form refuses rather
/// than being silently redirected there; a non-loopback address refuses outright.
fn loopback_port(addr: SocketAddr) -> Result<NonZeroU16> {
    if !addr.ip().is_loopback() {
        return Err(refuse("llama-not-loopback"));
    }
    if addr.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(refuse("llama-addr"));
    }
    NonZeroU16::new(addr.port()).ok_or_else(|| refuse("llama-addr"))
}

/// A model id is the model file's sha256, lowercase hex.
fn check_model_id(id: &str) -> Result<()> {
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err(refuse("llama-model-id"))
    }
}

/// The leading `MAX_INPUT_BYTES` of a text, cut at a character boundary.
fn clip(text: &str) -> &str {
    let mut end = text.len().min(MAX_INPUT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// One loopback llama-server serving one model.
struct Server {
    port: NonZeroU16,
    model_id: String,
}

impl Server {
    fn open(addr: SocketAddr, model_id: &str) -> Result<Self> {
        check_model_id(model_id)?;
        Ok(Self { port: loopback_port(addr)?, model_id: model_id.to_owned() })
    }

    /// The server must list this model id among its models.
    fn check_served(&self) -> Result<()> {
        let reply = loopback_http(self.port, "GET", "/v1/models", &[], None, Instant::now() + TIMEOUT, MAX_MODELS_RESPONSE)
            .map_err(http)?;
        let value = parse_local_json(&reply).map_err(|_| refuse("llama-response"))?;
        let served = value.get("data").and_then(Value::as_array).is_some_and(|models| {
            models.iter().any(|m| m.get("id").and_then(Value::as_str) == Some(self.model_id.as_str()))
        });
        if served {
            Ok(())
        } else {
            Err(refuse("llama-model-mismatch"))
        }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let bytes = serde_json::to_vec(body).map_err(|_| refuse("llama-request"))?;
        let reply = loopback_http(self.port, "POST", path, &[], Some(&bytes), Instant::now() + TIMEOUT, MAX_RESPONSE)
            .map_err(http)?;
        parse_local_json(&reply).map_err(|_| refuse("llama-response"))
    }
}

/// `data[i].embedding` for `n` inputs, placed by `data[i].index` and scaled to unit length.
fn embeddings(reply: &Value, n: usize) -> Result<Vec<Vec<f32>>> {
    let bad = || refuse("llama-vector");
    let data = reply.get("data").and_then(Value::as_array).filter(|d| d.len() == n).ok_or_else(bad)?;
    let mut out: Vec<Option<Vec<f32>>> = vec![None; n];
    for entry in data {
        let index = entry.get("index").and_then(Value::as_u64).and_then(|i| usize::try_from(i).ok()).filter(|i| *i < n);
        let raw = entry.get("embedding").and_then(Value::as_array).filter(|v| !v.is_empty() && v.len() <= MAX_DIMENSIONS);
        let (Some(index), Some(raw)) = (index, raw) else { return Err(bad()) };
        let mut vector = Vec::with_capacity(raw.len());
        for x in raw {
            let x = x.as_f64().map(|f| f as f32).filter(|f| f.is_finite()).ok_or_else(bad)?;
            vector.push(x);
        }
        let norm = vector.iter().map(|x| f64::from(*x) * f64::from(*x)).sum::<f64>().sqrt();
        if !norm.is_finite() || norm == 0.0 {
            return Err(bad());
        }
        let unit = vector.into_iter().map(|x| (f64::from(x) / norm) as f32).collect();
        if out[index].replace(unit).is_some() {
            return Err(bad());
        }
    }
    out.into_iter().map(|v| v.ok_or_else(bad)).collect()
}

/// `results[i].relevance_score` for `n` documents, placed by `results[i].index`.
fn relevance(reply: &Value, n: usize) -> Result<Vec<f32>> {
    let bad = || refuse("llama-rerank");
    let results = reply.get("results").and_then(Value::as_array).filter(|r| r.len() == n).ok_or_else(bad)?;
    let mut out: Vec<Option<f32>> = vec![None; n];
    for entry in results {
        let index = entry.get("index").and_then(Value::as_u64).and_then(|i| usize::try_from(i).ok()).filter(|i| *i < n);
        let score = entry.get("relevance_score").and_then(Value::as_f64).map(|f| f as f32).filter(|f| f.is_finite());
        let (Some(index), Some(score)) = (index, score) else { return Err(bad()) };
        if out[index].replace(score).is_some() {
            return Err(bad());
        }
    }
    out.into_iter().map(|s| s.ok_or_else(bad)).collect()
}

/// Embeddings from a loopback llama-server (`llama-server --embedding --alias <model_id>`).
pub struct HttpEmbedder {
    addr: SocketAddr,
    model_id: String,
}

impl HttpEmbedder {
    /// `addr` must be 127.0.0.1 with a nonzero port; `model_id` the model file's sha256 (lowercase hex).
    pub fn new(addr: SocketAddr, model_id: &str) -> Result<Self> {
        Server::open(addr, model_id)?;
        Ok(Self { addr, model_id: model_id.to_owned() })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Embedder for HttpEmbedder {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let server = Server::open(self.addr, &self.model_id)?;
        server.check_served()?;
        let mut out = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(EMBED_BATCH) {
            let input: Vec<&str> = chunk.iter().map(|t| clip(t)).collect();
            let body = json!({ "model": self.model_id, "input": input, "encoding_format": "float" });
            out.extend(embeddings(&server.post("/v1/embeddings", &body)?, chunk.len())?);
        }
        // One model gives one dimension.
        if out.windows(2).any(|w| w[0].len() != w[1].len()) {
            return Err(refuse("llama-vector"));
        }
        Ok(out)
    }
}

/// Cross-encoder scores from a loopback llama-server (`llama-server --reranking --alias <model_id>`).
pub struct HttpReranker {
    addr: SocketAddr,
    model_id: String,
}

impl HttpReranker {
    /// `addr` must be 127.0.0.1 with a nonzero port; `model_id` the model file's sha256 (lowercase hex).
    pub fn new(addr: SocketAddr, model_id: &str) -> Result<Self> {
        Server::open(addr, model_id)?;
        Ok(Self { addr, model_id: model_id.to_owned() })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Reranker for HttpReranker {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn score(&self, query: &str, passages: &[&str]) -> Result<Vec<f32>> {
        if passages.is_empty() {
            return Ok(Vec::new());
        }
        if passages.len() > MAX_RERANK_PASSAGES {
            return Err(refuse("llama-bounds"));
        }
        let server = Server::open(self.addr, &self.model_id)?;
        server.check_served()?;
        let documents: Vec<&str> = passages.iter().map(|p| clip(p)).collect();
        let body = json!({ "model": self.model_id, "query": clip(query), "documents": documents, "top_n": passages.len() });
        relevance(&server.post("/v1/rerank", &body)?, passages.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439";

    #[test]
    fn only_loopback_and_sha256_ids() {
        let addr = |text: &str| text.parse::<SocketAddr>().unwrap();
        assert!(HttpEmbedder::new(addr("127.0.0.1:8080"), ID).is_ok());
        assert_eq!(HttpReranker::new(addr("127.0.0.1:8081"), ID).unwrap().addr(), addr("127.0.0.1:8081"));
        assert_eq!(HttpEmbedder::new(addr("192.0.2.7:8080"), ID).err(), Some(refuse("llama-not-loopback")));
        assert_eq!(HttpReranker::new(addr("[::1]:8080"), ID).err(), Some(refuse("llama-addr")));
        assert_eq!(HttpEmbedder::new(addr("127.0.0.2:8080"), ID).err(), Some(refuse("llama-addr")));
        assert!(HttpEmbedder::new(addr("127.0.0.1:0"), ID).is_err());
        assert_eq!(HttpEmbedder::new(addr("127.0.0.1:8080"), "qwen3").err(), Some(refuse("llama-model-id")));
        assert!(HttpEmbedder::new(addr("127.0.0.1:8080"), &ID.to_uppercase()).is_err());
    }

    #[test]
    fn embeddings_are_placed_by_index_and_unit_length() {
        let reply = json!({ "data": [
            { "index": 1, "embedding": [0.0, 2.0] },
            { "index": 0, "embedding": [3.0, 4.0] },
        ]});
        let v = embeddings(&reply, 2).unwrap();
        assert_eq!(v, vec![vec![0.6, 0.8], vec![0.0, 1.0]]);
        let duplicate = json!({ "data": [{ "index": 0, "embedding": [1.0] }, { "index": 0, "embedding": [1.0] }] });
        assert!(embeddings(&duplicate, 2).is_err());
        assert!(embeddings(&json!({ "data": [{ "index": 0, "embedding": [0.0, 0.0] }] }), 1).is_err());
        assert!(embeddings(&json!({ "data": [{ "index": 0, "embedding": [[1.0]] }] }), 1).is_err());
        assert!(embeddings(&json!({ "data": [{ "index": 3, "embedding": [1.0] }] }), 1).is_err());
        assert!(embeddings(&json!({ "data": [] }), 1).is_err());
    }

    #[test]
    fn rerank_scores_are_placed_by_index() {
        let reply = json!({ "results": [
            { "index": 2, "relevance_score": 4.5 },
            { "index": 0, "relevance_score": -1.0 },
            { "index": 1, "relevance_score": 0.25 },
        ]});
        assert_eq!(relevance(&reply, 3).unwrap(), vec![-1.0, 0.25, 4.5]);
        assert!(relevance(&reply, 4).is_err());
        let missing = json!({ "results": [{ "index": 0, "relevance_score": 1.0 }, { "index": 0, "relevance_score": 2.0 }] });
        assert!(relevance(&missing, 2).is_err());
        assert!(relevance(&json!({ "results": [{ "index": 0 }] }), 1).is_err());
    }

    #[test]
    fn inputs_are_clipped_at_a_char_boundary() {
        assert_eq!(clip("short"), "short");
        let long = "é".repeat(MAX_INPUT_BYTES);
        let cut = clip(&long);
        assert!(cut.len() <= MAX_INPUT_BYTES && cut.len() >= MAX_INPUT_BYTES - 1);
        assert!(cut.chars().all(|c| c == 'é'));
    }

    #[test]
    fn an_unreachable_server_is_an_error_not_an_answer() {
        let nobody = HttpEmbedder::new("127.0.0.1:1".parse().unwrap(), ID).unwrap();
        assert!(nobody.embed(&["anything"]).is_err());
        assert_eq!(nobody.embed(&[]).unwrap(), Vec::<Vec<f32>>::new());
        let nobody = HttpReranker::new("127.0.0.1:1".parse().unwrap(), ID).unwrap();
        assert!(nobody.score("q", &["p"]).is_err());
    }
}
