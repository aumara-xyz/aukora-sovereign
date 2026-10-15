// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only face endpoints. Approval, passkeys, credentials and frame creation are absent.

use crate::{
    documents::{DocumentPath, ListDocuments},
    ingress::{validate_path, Method},
    session::BoundSession,
};
use canon::{
    fd3_payloads::{MemoryList, MemoryRecall, MemoryTier},
    ids::{NoteId, SessionId, ThreadId},
    json::{Value, ValueView},
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
    pub fn register(release: &crate::assets::ApprovedRelease, face_id: Text<128>) -> Result<Self> {
        use crate::assets::{AssetKind, AssetSurface};
        use ReadService::*;

        // Server-owned grants are fixed by id; only an approved face entry selects them.
        let services = match face_id.as_str() {
            "memory" => vec![Memory],
            "messages" | "humangraph" => vec![Messages],
            "identity" => vec![Identity],
            "models" => vec![Models],
            "presets" => vec![Presets],
            "threads" | "sidebar" | "archived" => vec![Sessions],
            "documents" => vec![Documents],
            "coherence" => vec![Coherence],
            "lingwa" | "live" | "zetaharp" | "media" | "aumlok" | "general" | "plugins" => {
                Vec::new()
            }
            _ => return Err(capability_refused()),
        };
        let expected = format!("app/faces/{}/index.html", face_id.as_str());
        let matches = release.entries().iter().filter(|entry| {
            entry.surface == AssetSurface::Face
                && entry.kind == AssetKind::Html
                && entry.path == expected
        });
        if matches.count() != 1 {
            return Err(capability_refused());
        }
        Ok(Self { face_id, services })
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
pub fn decode(endpoint: FaceEndpoint, body: &[u8]) -> Result<FaceRequest> {
    if body.len() > MAX_JSON_BYTES {
        return Err(body_invalid());
    }
    let no_arguments = match endpoint {
        FaceEndpoint::IdentityCard => Some(FaceRequest::IdentityCard),
        FaceEndpoint::Models => Some(FaceRequest::Models),
        FaceEndpoint::Spend => Some(FaceRequest::Spend),
        FaceEndpoint::Presets => Some(FaceRequest::Presets),
        FaceEndpoint::Coherence => Some(FaceRequest::Coherence),
        FaceEndpoint::Fingerprint => Some(FaceRequest::Fingerprint),
        _ => None,
    };
    if body.is_empty() {
        return no_arguments.ok_or_else(body_invalid);
    }
    let value = canon::json::parse_strict(body).map_err(|_| body_invalid())?;
    if let Some(request) = no_arguments {
        exact_keys(&value, &[])?;
        return Ok(request);
    }
    let request = match endpoint {
        FaceEndpoint::MemoryList => {
            exact_keys(&value, &["tier", "before"])?;
            let tier = match string_field(&value, "tier")? {
                "remembered" => MemoryTier::Remembered,
                "forgotten" => MemoryTier::Forgotten,
                _ => return Err(body_invalid()),
            };
            let before = nullable_string(&value, "before")?
                .map(|cursor| NoteId::new(cursor.to_owned()).map_err(|_| body_invalid()))
                .transpose()?;
            FaceRequest::MemoryList(MemoryList { tier, before })
        }
        FaceEndpoint::MemoryRecall => {
            exact_keys(&value, &["query", "limit"])?;
            let query = string_field(&value, "query")?.to_owned();
            FaceRequest::MemoryRecall(MemoryRecall {
                query,
                limit: limit_field(&value)?,
            })
        }
        FaceEndpoint::Messages => FaceRequest::Messages(page_query(&value)?),
        FaceEndpoint::Contacts => FaceRequest::Contacts(page_query(&value)?),
        FaceEndpoint::Threads => FaceRequest::Threads(page_query(&value)?),
        FaceEndpoint::Sessions => {
            exact_keys(
                &value,
                &["thread_id", "include_archived", "before", "limit"],
            )?;
            let thread_id = nullable_string(&value, "thread_id")?
                .map(ThreadId::from_hex)
                .transpose()
                .map_err(|_| body_invalid())?;
            let before = nullable_string(&value, "before")?
                .map(SessionId::from_hex)
                .transpose()
                .map_err(|_| body_invalid())?;
            let include_archived = match field(&value, "include_archived")?.view() {
                ValueView::Boolean(include) => include,
                _ => return Err(body_invalid()),
            };
            FaceRequest::Sessions(SessionList {
                thread_id,
                include_archived,
                before,
                limit: limit_field(&value)?,
            })
        }
        FaceEndpoint::SessionOpen => {
            exact_keys(&value, &["session_id", "after_sequence", "limit"])?;
            let session_id = SessionId::from_hex(string_field(&value, "session_id")?)
                .map_err(|_| body_invalid())?;
            FaceRequest::SessionOpen(SessionOpen {
                session_id,
                after_sequence: unsigned_field(&value, "after_sequence")?,
                limit: limit_field(&value)?,
            })
        }
        FaceEndpoint::DocumentsList => {
            exact_keys(&value, &["directory", "after", "limit"])?;
            let directory = nullable_string(&value, "directory")?
                .map(DocumentPath::parse)
                .transpose()?;
            let after = nullable_string(&value, "after")?
                .map(DocumentPath::parse)
                .transpose()?;
            FaceRequest::DocumentsList(ListDocuments {
                directory,
                after,
                limit: limit_field(&value)?,
            })
        }
        FaceEndpoint::DocumentsRead => {
            exact_keys(&value, &["path"])?;
            FaceRequest::DocumentsRead(DocumentPath::parse(string_field(&value, "path")?)?)
        }
        _ => return Err(body_invalid()),
    };
    validate_request(&request)?;
    Ok(request)
}

/// Capability check and session guard precede the service call; no arbitrary RPC method name.
pub fn dispatch(
    services: &mut impl FaceServices,
    session: &BoundSession<'_>,
    access: &FaceAccess,
    request: FaceRequest,
) -> Result<FaceResponse> {
    crate::fd4::require_data_session(session)?;
    let required = match &request {
        FaceRequest::MemoryList(_) | FaceRequest::MemoryRecall(_) => ReadService::Memory,
        FaceRequest::Messages(_) | FaceRequest::Contacts(_) => ReadService::Messages,
        FaceRequest::IdentityCard => ReadService::Identity,
        FaceRequest::Models | FaceRequest::Spend => ReadService::Models,
        FaceRequest::Presets => ReadService::Presets,
        FaceRequest::Sessions(_) | FaceRequest::SessionOpen(_) | FaceRequest::Threads(_) => {
            ReadService::Sessions
        }
        FaceRequest::DocumentsList(_) | FaceRequest::DocumentsRead(_) => ReadService::Documents,
        FaceRequest::Coherence | FaceRequest::Fingerprint => ReadService::Coherence,
    };
    if !access.services.contains(&required) {
        return Err(capability_refused());
    }
    validate_request(&request)?;
    let expected = match &request {
        FaceRequest::Coherence => 1,
        FaceRequest::Fingerprint => 2,
        _ => 0,
    };
    let response = services.read(session, request)?;
    let valid = match &response {
        FaceResponse::Json(data) => {
            expected == 0 && (1..=MAX_JSON_BYTES).contains(&data.as_bytes().len())
        }
        FaceResponse::Coherence(data) => {
            expected == 1 && (1..=MAX_JSON_BYTES).contains(&data.as_bytes().len())
        }
        FaceResponse::Fingerprint(_) => expected == 2,
    };
    if !valid {
        return Err(Refusal {
            organ: "frontdoor",
            reason: "response-refused",
        });
    }
    Ok(response)
}

fn body_invalid() -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason: "body-invalid",
    }
}

fn capability_refused() -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason: "capability-denied",
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or_else(body_invalid)
}

fn exact_keys(value: &Value, keys: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(members)
            if members.len() == keys.len()
                && members
                    .iter()
                    .all(|(name, _)| keys.contains(&name.as_str())) =>
        {
            Ok(())
        }
        _ => Err(body_invalid()),
    }
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    match field(value, name)?.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(body_invalid()),
    }
}

fn nullable_string<'a>(value: &'a Value, name: &str) -> Result<Option<&'a str>> {
    match field(value, name)?.view() {
        ValueView::Null => Ok(None),
        ValueView::Text(text) => Ok(Some(text)),
        _ => Err(body_invalid()),
    }
}

fn unsigned_field(value: &Value, name: &str) -> Result<u64> {
    match field(value, name)?.view() {
        ValueView::Integer(number) => u64::try_from(number.get()).map_err(|_| body_invalid()),
        _ => Err(body_invalid()),
    }
}

fn limit_field(value: &Value) -> Result<u16> {
    let limit = unsigned_field(value, "limit")?;
    if !(1..=100).contains(&limit) {
        return Err(body_invalid());
    }
    Ok(limit as u16)
}

fn page_query(value: &Value) -> Result<PageQuery> {
    exact_keys(value, &["before", "limit"])?;
    let before = nullable_string(value, "before")?
        .map(|cursor| Text::new(cursor.to_owned()).map_err(|_| body_invalid()))
        .transpose()?;
    Ok(PageQuery {
        before,
        limit: limit_field(value)?,
    })
}

fn validate_request(request: &FaceRequest) -> Result<()> {
    let limit = match request {
        FaceRequest::MemoryRecall(query) => {
            if query.query.len() > 32_768 {
                return Err(body_invalid());
            }
            Some(query.limit)
        }
        FaceRequest::Messages(query)
        | FaceRequest::Contacts(query)
        | FaceRequest::Threads(query) => {
            if let Some(cursor) = &query.before {
                if cursor.as_str().is_empty() || cursor.as_str().chars().any(char::is_control) {
                    return Err(body_invalid());
                }
            }
            Some(query.limit)
        }
        FaceRequest::Sessions(query) => Some(query.limit),
        FaceRequest::SessionOpen(query) => {
            if query.after_sequence > canon::json::MAX_SAFE_INTEGER as u64 {
                return Err(body_invalid());
            }
            Some(query.limit)
        }
        FaceRequest::DocumentsList(query) => Some(query.limit),
        _ => None,
    };
    if limit.is_some_and(|limit| !(1..=100).contains(&limit)) {
        return Err(body_invalid());
    }
    Ok(())
}
