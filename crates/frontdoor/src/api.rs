// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shell-host document reads. All agent commands and events use the FD 4 bridge.

use crate::{
    documents::{DocumentPath, ListDocuments},
    ingress::{validate_path, HostRole, Method},
    session::BoundSession,
};
use canon::{
    json::{Value, ValueView},
    session::Text,
    Refusal, Result,
};

pub mod service_reads;

pub const MAX_JSON_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaceEndpoint {
    DocumentsList,
    DocumentsRead,
}

impl FaceEndpoint {
    pub fn resolve(role: HostRole, method: Method, path: &str) -> Result<Self> {
        if role != HostRole::Shell {
            return Err(canon::codes::FRONTDOOR_HOST_REFUSED);
        }
        validate_path(path)?;
        match (method, path) {
            (Method::Post, "/api/documents/list") => Ok(Self::DocumentsList),
            (Method::Post, "/api/documents/read") => Ok(Self::DocumentsRead),
            _ => Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE),
        }
    }
}

#[derive(Clone, Debug)]
pub enum FaceRequest {
    DocumentsList(ListDocuments),
    DocumentsRead(DocumentPath),
}

/// The face's granted read service, fixed by shell registration and checked on every call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadService {
    Documents,
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
            "documents" => vec![Documents],
            "memory" | "messages" | "humangraph" | "identity" | "models" | "presets"
            | "threads" | "sidebar" | "archived" | "coherence" | "lingwa" | "live" | "zetaharp"
            | "media" | "aumlok" | "general" | "plugins" => Vec::new(),
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

pub enum FaceResponse {
    Json(JsonData),
}

/// The supervisor maps these calls to owning services. Frontdoor opens no organ sockets.
pub trait FaceServices {
    /// Responses contain principal-scoped documents as data, never authority.
    fn read(&mut self, session: &BoundSession<'_>, request: FaceRequest) -> Result<FaceResponse>;
}

/// Exact object keys per variant; page limits 1..=100, strict JSON, no unknown operations.
pub fn decode(endpoint: FaceEndpoint, body: &[u8]) -> Result<FaceRequest> {
    if body.len() > MAX_JSON_BYTES {
        return Err(body_invalid());
    }
    let value = canon::json::parse_strict(body).map_err(|_| body_invalid())?;
    let request = match endpoint {
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
    };
    validate_request(&request)?;
    Ok(request)
}

/// Shell admission, live session and the approved document grant precede service dispatch.
pub fn dispatch<S: crate::session::SessionStore>(
    services: &mut impl FaceServices,
    sessions: &mut S,
    admitted: &crate::ingress::AdmittedRequest,
    access: &FaceAccess,
    node: canon::ids::NodeId,
    now_ms: u64,
) -> Result<FaceResponse> {
    let endpoint = FaceEndpoint::resolve(admitted.role(), admitted.method(), admitted.path())?;
    if !access.services.contains(&ReadService::Documents) {
        return Err(capability_refused());
    }
    let request = decode(endpoint, &canon::json::to_canonical(admitted.body()))?;
    crate::session::with_bound_session(
        sessions,
        admitted
            .cookie()
            .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?,
        node,
        admitted.origin(),
        now_ms,
        |session| {
            crate::fd4::require_data_session(&session)?;
            services.read(&session, request)
        },
    )
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

fn validate_request(request: &FaceRequest) -> Result<()> {
    if let FaceRequest::DocumentsList(query) = request {
        if !(1..=100).contains(&query.limit) {
            return Err(body_invalid());
        }
    }
    Ok(())
}
