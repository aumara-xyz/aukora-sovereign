// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only face endpoints. Approval, passkeys, credentials and frame creation are absent.

use crate::{
    documents::{DocumentPath, ListDocuments},
    ingress::{validate_path, Method},
    session::BoundSession,
};
use canon::{
    fd3_payloads::{MemoryList, MemoryRecall},
    json::Value,
    session::{SessionList, SessionOpen, Text},
    Refusal, Result,
};

pub const MAX_JSON_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaceEndpoint {
    MemoryList,
    MemoryRecall,
    Messages,
    Contacts,
    IdentityCard,
    Models,
    Spend,
    Presets,
    Sessions,
    SessionOpen,
    Threads,
    DocumentsList,
    DocumentsRead,
    Coherence,
    Fingerprint,
}

impl FaceEndpoint {
    pub fn resolve(method: Method, path: &str) -> Result<Self> {
        validate_path(path)?;
        match (method, path) {
            (Method::Post, "/api/memory/list") => Ok(Self::MemoryList),
            (Method::Post, "/api/memory/recall") => Ok(Self::MemoryRecall),
            (Method::Post, "/api/messages") => Ok(Self::Messages),
            (Method::Post, "/api/contacts") => Ok(Self::Contacts),
            (Method::Get, "/api/identity") => Ok(Self::IdentityCard),
            (Method::Get, "/api/models") => Ok(Self::Models),
            (Method::Get, "/api/spend") => Ok(Self::Spend),
            (Method::Get, "/api/presets") => Ok(Self::Presets),
            (Method::Post, "/api/sessions") => Ok(Self::Sessions),
            (Method::Post, "/api/sessions/open") => Ok(Self::SessionOpen),
            (Method::Post, "/api/threads") => Ok(Self::Threads),
            (Method::Post, "/api/documents/list") => Ok(Self::DocumentsList),
            (Method::Post, "/api/documents/read") => Ok(Self::DocumentsRead),
            (Method::Get, "/api/coherence") => Ok(Self::Coherence),
            (Method::Get, "/api/fingerprint") => Ok(Self::Fingerprint),
            _ => Err(Refusal {
                organ: "frontdoor",
                reason: "unknown-route",
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PageQuery {
    pub before: Option<Text<128>>,
    pub limit: u16,
}

#[derive(Clone, Debug)]
pub enum FaceRequest {
    MemoryList(MemoryList),
    MemoryRecall(MemoryRecall),
    Messages(PageQuery),
    Contacts(PageQuery),
    IdentityCard,
    Models,
    Spend,
    Presets,
    Sessions(SessionList),
    SessionOpen(SessionOpen),
    Threads(PageQuery),
    DocumentsList(ListDocuments),
    DocumentsRead(DocumentPath),
    Coherence,
    Fingerprint,
}

/// The face's granted read service, fixed by shell registration and checked on every call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadService {
    Memory,
    Messages,
    Identity,
    Models,
    Presets,
    Sessions,
    Documents,
    Coherence,
}

pub struct FaceAccess {
    face_id: Text<128>,
    services: Vec<ReadService>,
}

impl FaceAccess {
    /// Resolve the face and its closed read-service grants from the approved manifest only.
    /// The caller supplies an id, never its own grant list. No passkey or frame grant exists.
    pub fn register(
        _release: &crate::assets::ApprovedRelease,
        _face_id: Text<128>,
    ) -> Result<Self> {
        todo!("row 109 face registration")
    }

    pub fn face_id(&self) -> &str {
        self.face_id.as_str()
    }
    pub fn services(&self) -> &[ReadService] {
        &self.services
    }
}

/// Canonical bounded JSON data, without an HTTP status, location, script or header field.
pub struct JsonData(Vec<u8>);

impl JsonData {
    pub fn new(value: &Value) -> Result<Self> {
        let bytes = canon::json::to_canonical(value);
        if bytes.is_empty() || bytes.len() > MAX_JSON_BYTES {
            return Err(Refusal {
                organ: "frontdoor",
                reason: "response-too-large",
            });
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// This byte wrapper validates length only and has no snapshot parser.
pub struct OpaqueCoherence(Vec<u8>);

impl OpaqueCoherence {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_JSON_BYTES {
            return Err(Refusal {
                organ: "frontdoor",
                reason: "response-too-large",
            });
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub enum FaceResponse {
    Json(JsonData),
    Coherence(OpaqueCoherence),
    Fingerprint([u8; 32]),
}

/// The supervisor maps these calls to owning services. Frontdoor opens no organ sockets.
pub trait FaceServices {
    /// Responses are principal-scoped; messages, documents and memory are data, never authority.
    fn read(&mut self, session: &BoundSession<'_>, request: FaceRequest) -> Result<FaceResponse>;
}

/// Exact object keys per variant; page limits 1..=100, strict JSON, no unknown operations.
pub fn decode(_endpoint: FaceEndpoint, _body: &[u8]) -> Result<FaceRequest> {
    todo!("row 109 faces API")
}

/// Capability check and session guard precede the service call; no arbitrary RPC method name.
pub fn dispatch(
    _services: &mut impl FaceServices,
    _session: &BoundSession<'_>,
    _access: &FaceAccess,
    _request: FaceRequest,
) -> Result<FaceResponse> {
    todo!("row 109 faces API")
}
