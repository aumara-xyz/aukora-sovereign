// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded HTTP ingress; no guest-controlled response headers or redirect destination.

use crate::tls::{Origin, SecureRequest};
use canon::{json::Value, Refusal, Result};

pub const MAX_BODY_BYTES: usize = 65_536;
pub const MAX_HEADER_BYTES: usize = 16_384;
pub const MAX_CONNECTIONS: usize = 64;
pub const REQUEST_DEADLINE_MS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Head,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostRole {
    Shell,
    Owner,
}

/// Raw values preserve duplicates so validation cannot silently choose one.
pub struct RequestInput {
    pub transport: SecureRequest,
    pub method: Method,
    pub path: String,
    pub origins: Vec<String>,
    pub fetch_sites: Vec<String>,
    pub content_types: Vec<String>,
    pub cookies: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct AdmittedRequest {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) origin: Origin,
    pub(crate) body: Value,
}

impl AdmittedRequest {
    pub fn method(&self) -> Method {
        self.method
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn origin(&self) -> &Origin {
        &self.origin
    }
    pub fn body(&self) -> &Value {
        &self.body
    }
}

/// Contract: exact paths, same-origin mutation requests, strict JSON and bounded reads.
/// Pinned failures retain body-invalid, origin-refused, fetch-site-refused and path-refused.
pub fn admit(_input: RequestInput) -> Result<AdmittedRequest> {
    todo!("rows 18, 24")
}

pub fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > 2048
        || path.contains(['%', '\\', '?', '#'])
        || path.contains("//")
        || path.bytes().any(|b| b.is_ascii_control() || b == b' ')
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(Refusal {
            organ: "frontdoor",
            reason: "path-refused",
        });
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct IngressFacts {
    pub active_connections: usize,
    pub refused_host_count: u64,
    pub refused_origin_count: u64,
    pub refused_frame_count: u64,
}
