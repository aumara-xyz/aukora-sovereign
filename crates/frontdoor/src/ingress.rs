// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded HTTP ingress; no guest-controlled response headers or redirect destination.

use crate::{
    owner_origin::OwnerRoute,
    session::{OWNER_COOKIE, SHELL_COOKIE},
    tls::{Origin, SecureRequest},
};
use canon::{
    codes,
    json::{self, Value, ValueView},
    Refusal, Result,
};

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

pub struct AdmittedRequest {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) origin: Origin,
    pub(crate) body: Value,
    role: HostRole,
    cookie: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for AdmittedRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("origin", &self.origin)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
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
    pub fn role(&self) -> HostRole {
        self.role
    }
    /// The selected host's bearer; authentication still requires the durable store.
    pub fn cookie(&self) -> Option<&[u8]> {
        self.cookie.as_ref().map(|cookie| cookie.as_slice())
    }
}

/// Contract: exact paths, same-origin mutation requests, strict JSON and bounded reads.
/// Pinned failures retain body-invalid, origin-refused, fetch-site-refused and path-refused.
pub fn admit(input: RequestInput) -> Result<AdmittedRequest> {
    let cookie = request_metadata(&input)?;
    let body = if input.method == Method::Post {
        if input.body.is_empty() || input.body.len() > MAX_BODY_BYTES {
            return Err(codes::FRONTDOOR_BODY_INVALID);
        }
        let body = json::parse_strict(&input.body).map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
        if !matches!(body.view(), ValueView::Object(_)) {
            return Err(codes::FRONTDOOR_BODY_INVALID);
        }
        if input.transport.role() == HostRole::Shell
            && input.path == crate::fd4::DATA_PATH
            && json::to_canonical(&body) != input.body
        {
            return Err(codes::FRAME_NOT_CANONICAL);
        }
        body
    } else {
        if !input.body.is_empty() {
            return Err(codes::FRONTDOOR_BODY_INVALID);
        }
        Value::checked_object(Vec::new())?
    };
    Ok(AdmittedRequest {
        method: input.method,
        path: input.path,
        origin: input.transport.origin().clone(),
        body,
        role: input.transport.role(),
        cookie,
    })
}

fn request_metadata(input: &RequestInput) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    validate_path(&input.path)?;
    let role = input.transport.role();
    let origin = input.transport.origin();
    check_header_budget(input)?;
    if input.origins.len() > 1
        || input
            .origins
            .first()
            .is_some_and(|value| value != origin.as_str())
        || (input.method == Method::Post && input.origins.len() != 1)
    {
        return Err(codes::FRONTDOOR_ORIGIN_REFUSED);
    }
    if input.fetch_sites.len() > 1
        || input.fetch_sites.first().is_some_and(|value| {
            if input.method == Method::Post {
                value != "same-origin"
            } else {
                !(matches!(value.as_str(), "same-origin" | "same-site" | "none")
                    || (role == HostRole::Shell
                        && !input.path.starts_with("/api/")
                        && value == "cross-site"))
            }
        })
        || (input.method == Method::Post && input.fetch_sites.len() != 1)
    {
        return Err(codes::FRONTDOOR_FETCH_SITE_REFUSED);
    }
    let cookie = cookie_for(role, &input.cookies)?;
    require_route(role, input.method, &input.path)?;
    if input.method == Method::Post {
        if input.content_types.len() != 1 || !json_content_type(&input.content_types[0]) {
            return Err(codes::FRONTDOOR_BODY_INVALID);
        }
    } else if !input.content_types.is_empty() {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    }
    Ok(cookie)
}

fn check_header_budget(input: &RequestInput) -> Result<()> {
    let mut bytes = 0usize;
    for (name, values) in [
        ("origin", &input.origins),
        ("sec-fetch-site", &input.fetch_sites),
        ("content-type", &input.content_types),
        ("cookie", &input.cookies),
    ] {
        for value in values {
            if value.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(codes::FRONTDOOR_BODY_INVALID);
            }
            bytes = bytes
                .checked_add(name.len() + value.len() + 4)
                .ok_or(codes::FRONTDOOR_BODY_INVALID)?;
            if bytes > MAX_HEADER_BYTES {
                return Err(codes::FRONTDOOR_BODY_INVALID);
            }
        }
    }
    Ok(())
}

fn json_content_type(text: &str) -> bool {
    let mut parts = text.split(';');
    if !parts
        .next()
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(parameter), None) => parameter.trim().eq_ignore_ascii_case("charset=utf-8"),
        _ => false,
    }
}

fn cookie_for(role: HostRole, headers: &[String]) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    if headers.len() > 1 {
        return Err(codes::FRONTDOOR_SESSION_REQUIRED);
    }
    let mut selected = None;
    let mut names = std::collections::BTreeSet::new();
    for header in headers {
        for part in header.split(';') {
            let (name, value) = part
                .trim()
                .split_once('=')
                .ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?;
            if name.is_empty()
                || !names.insert(name)
                || name
                    .bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)))
                || value
                    .bytes()
                    .any(|b| b <= b' ' || b >= 0x7f || b"\";,\\".contains(&b))
            {
                return Err(codes::FRONTDOOR_SESSION_REQUIRED);
            }
            let expected = match role {
                HostRole::Owner => OWNER_COOKIE,
                HostRole::Shell => SHELL_COOKIE,
            };
            if name == OWNER_COOKIE || name == SHELL_COOKIE {
                if name != expected {
                    return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
                }
                crate::session::session_digest(value.as_bytes())?;
                selected = Some(zeroize::Zeroizing::new(value.as_bytes().to_vec()));
            }
        }
    }
    Ok(selected)
}

/// Owner APIs stay on the owner host; shell APIs are documents and the data bridge only.
fn require_route(role: HostRole, method: Method, path: &str) -> Result<()> {
    // This shell read contains notification ids only; owner ceremonies remain owner-host routes.
    if role == HostRole::Shell && path == "/api/approvals" {
        return if method == Method::Get {
            Ok(())
        } else {
            Err(codes::FRONTDOOR_UNKNOWN_ROUTE)
        };
    }
    if role == HostRole::Shell && path == crate::api::service_reads::PATH {
        return crate::api::service_reads::resolve(role, method, path);
    }
    if role == HostRole::Owner {
        if path.starts_with("/api/") {
            OwnerRoute::resolve(role, method, path).map(|_| ())
        } else if matches!(method, Method::Get | Method::Head) && !path.ends_with(".html") {
            Ok(())
        } else {
            Err(codes::FRONTDOOR_UNKNOWN_ROUTE)
        }
    } else if path == crate::fd4::DATA_PATH {
        crate::fd4::DataEndpoint::resolve(role, method, path).map(|_| ())
    } else if path.starts_with("/api/") {
        crate::api::FaceEndpoint::resolve(role, method, path).map(|_| ())
    } else if matches!(method, Method::Get | Method::Head) {
        Ok(())
    } else {
        Err(codes::FRONTDOOR_UNKNOWN_ROUTE)
    }
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

/// The permit remains held while the host dispatches this request and builds its response.
pub struct HttpAdmission {
    request: AdmittedRequest,
    owner_navigation: Option<crate::owner_origin::FrameNavigation>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl HttpAdmission {
    pub fn request(&self) -> &AdmittedRequest {
        &self.request
    }
    pub fn owner_navigation(&self) -> Option<&crate::owner_origin::FrameNavigation> {
        self.owner_navigation.as_ref()
    }
}

/// Bounded HTTP decoding behind the deployment's fixed private Caddy boundary.
pub struct HttpIngress {
    boundary: crate::tls::CaddyBoundary,
    permits: std::sync::Arc<tokio::sync::Semaphore>,
}

impl HttpIngress {
    pub fn new(boundary: crate::tls::CaddyBoundary) -> Result<Self> {
        boundary.validate()?;
        Ok(Self {
            boundary,
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
        })
    }

    /// Adapt Hyper's incoming stream without moving admission into the transport host.
    pub async fn admit_incoming(
        &self,
        peer: std::net::IpAddr,
        request: http::Request<hyper::body::Incoming>,
    ) -> Result<HttpAdmission> {
        self.admit_http(peer, request.map(axum::body::Body::new))
            .await
    }

    /// `peer` comes from the accepted connection, never a request header.
    /// The limit covers active admission/dispatch; the HTTP server owns idle connection limits.
    pub async fn admit_http(
        &self,
        peer: std::net::IpAddr,
        request: http::Request<axum::body::Body>,
    ) -> Result<HttpAdmission> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| codes::FRONTDOOR_OVERLOADED)?;
        let (request, owner_navigation) = tokio::time::timeout(
            std::time::Duration::from_millis(REQUEST_DEADLINE_MS),
            self.decode_http(peer, request),
        )
        .await
        .map_err(|_| codes::FRONTDOOR_REQUEST_TIMEOUT)??;
        Ok(HttpAdmission {
            request,
            owner_navigation,
            _permit: permit,
        })
    }

    async fn decode_http(
        &self,
        peer: std::net::IpAddr,
        request: http::Request<axum::body::Body>,
    ) -> Result<(
        AdmittedRequest,
        Option<crate::owner_origin::FrameNavigation>,
    )> {
        use http_body_util::BodyExt;
        let (parts, mut body) = request.into_parts();
        let transport = self.boundary.admit(crate::tls::ProxyObservation {
            peer,
            forwarded_proto: header_values(&parts.headers, "x-forwarded-proto")?,
            host: header_values(&parts.headers, "host")?,
        })?;
        if parts
            .uri
            .authority()
            .is_some_and(|host| host.as_str() != transport.origin().host())
            || parts
                .uri
                .scheme_str()
                .is_some_and(|scheme| scheme != "https")
        {
            return Err(codes::FRONTDOOR_HOST_REFUSED);
        }
        let mut size = 0usize;
        for (name, value) in &parts.headers {
            size = size
                .checked_add(name.as_str().len() + value.as_bytes().len() + 4)
                .ok_or(codes::FRONTDOOR_BODY_INVALID)?;
            if size > MAX_HEADER_BYTES {
                return Err(codes::FRONTDOOR_BODY_INVALID);
            }
        }
        let method = match parts.method {
            http::Method::GET => Method::Get,
            http::Method::HEAD => Method::Head,
            http::Method::POST => Method::Post,
            _ => return Err(codes::FRONTDOOR_UNKNOWN_ROUTE),
        };
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_owned();
        validate_path(&path)?;
        let owner_navigation = if transport.role() == HostRole::Owner
            && path == "/"
            && matches!(method, Method::Get | Method::Head)
        {
            let context = crate::owner_origin::CeremonyContext::from_boundary(&self.boundary)?;
            let destinations = header_values(&parts.headers, "sec-fetch-dest")?;
            let referrers = header_values(&parts.headers, "referer")?;
            let ([destination], [referrer]) = (destinations.as_slice(), referrers.as_slice())
            else {
                return Err(codes::FRONTDOOR_ORIGIN_REFUSED);
            };
            let referrer = referrer
                .parse::<http::Uri>()
                .map_err(|_| codes::FRONTDOOR_ORIGIN_REFUSED)?;
            // Exact authority matching excludes userinfo and explicit ports.
            if referrer.scheme_str() != Some("https")
                || referrer.authority().map(|authority| authority.as_str())
                    != Some(context.expected_top_origin.host())
            {
                return Err(codes::FRONTDOOR_ORIGIN_REFUSED);
            }
            Some(crate::owner_origin::admit_frame_navigation(
                &context,
                destination,
                context.expected_top_origin.as_str(),
            )?)
        } else {
            None
        };
        let lengths = header_values(&parts.headers, "content-length")?;
        let encodings = header_values(&parts.headers, "transfer-encoding")?;
        if lengths.len() > 1
            || encodings.len() > 1
            || encodings
                .first()
                .is_some_and(|value| !value.eq_ignore_ascii_case("chunked"))
            || (!lengths.is_empty() && !encodings.is_empty())
        {
            return Err(codes::FRONTDOOR_BODY_INVALID);
        }
        let expected_length = lengths
            .first()
            .map(|length| {
                if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(codes::FRONTDOOR_BODY_INVALID);
                }
                let length = length
                    .parse::<usize>()
                    .map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
                if length > MAX_BODY_BYTES {
                    return Err(codes::FRONTDOOR_BODY_INVALID);
                }
                Ok(length)
            })
            .transpose()?;
        let mut input = RequestInput {
            transport,
            method,
            path,
            origins: header_values(&parts.headers, "origin")?,
            fetch_sites: header_values(&parts.headers, "sec-fetch-site")?,
            content_types: header_values(&parts.headers, "content-type")?,
            cookies: header_values(&parts.headers, "cookie")?,
            body: Vec::new(),
        };
        request_metadata(&input)?;
        if method != Method::Post
            && (expected_length.is_some_and(|length| length > 0) || !encodings.is_empty())
        {
            return Err(codes::FRONTDOOR_BODY_INVALID);
        }
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
            let data = frame
                .into_data()
                .map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
            if data.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) {
                return Err(codes::FRONTDOOR_BODY_INVALID);
            }
            bytes.extend_from_slice(&data);
        }
        if expected_length.is_some_and(|length| length != bytes.len()) {
            return Err(codes::FRONTDOOR_BODY_INVALID);
        }
        input.body = bytes;
        let request = admit(input)?;
        Ok((request, owner_navigation))
    }
}

fn header_values(headers: &http::HeaderMap, name: &str) -> Result<Vec<String>> {
    headers
        .get_all(name)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| codes::FRONTDOOR_BODY_INVALID)
        })
        .collect()
}

/// Native handoff capability from a bound owner callback; no browser field constructs it.
pub struct ShellSessionGrant {
    parent: canon::digest::Digest32,
    node: canon::ids::NodeId,
    subject: canon::ids::SubjectId,
    epoch: u64,
    expires_at_ms: u64,
    shell: Origin,
}

impl ShellSessionGrant {
    pub fn from_owner(
        parent: &crate::session::BoundSession<'_>,
        boundary: &crate::tls::CaddyBoundary,
    ) -> Result<Self> {
        boundary.validate()?;
        let record = parent.record();
        if record.scope != crate::session::SessionScope::OwnerFrame
            || record.origin != boundary.owner
        {
            return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
        }
        Ok(Self {
            parent: record.token_digest,
            node: record.node,
            subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
            epoch: record.owner_epoch,
            expires_at_ms: record.expires_at_ms,
            shell: boundary.shell.clone(),
        })
    }

    /// Derive only for the admitted shell origin, rechecking the durable parent.
    pub fn issue_cookie(
        self,
        store: &mut impl crate::session::SessionStore,
        request: &AdmittedRequest,
        now_ms: u64,
        lifetime_ms: u64,
    ) -> Result<String> {
        use crate::session::{SessionBearer, SessionRecord, SessionScope, MAX_LIFETIME_MS};
        if request.role() != HostRole::Shell || request.origin() != &self.shell {
            return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
        }
        if !(1000..=MAX_LIFETIME_MS).contains(&lifetime_ms) {
            return Err(codes::FRONTDOOR_SESSION_REQUIRED);
        }
        let expires_at_ms = now_ms
            .checked_add(lifetime_ms)
            .map(|time| time.min(self.expires_at_ms))
            .ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?;
        let bearer = SessionBearer::generate()?;
        let cookie = bearer.cookie_header(SessionScope::Shell, expires_at_ms, now_ms)?;
        store.derive_shell(
            self.parent,
            SessionRecord {
                token_digest: bearer.digest(),
                node: self.node,
                origin: self.shell,
                subject: Some(self.subject),
                owner_epoch: self.epoch,
                scope: SessionScope::Shell,
                expires_at_ms,
                revoked: false,
            },
            now_ms,
        )?;
        Ok(cookie)
    }
}

/// Admission for the two native handoff operations and their HttpOnly metadata.
/// Correlation cookies never become a bound session or enter an FD 4 frame.
pub struct HandoffAdmission {
    pub admission: HttpAdmission,
    pub pending: Option<canon::digest::Digest32>,
    pub correlation: Option<canon::digest::Digest32>,
    pub owner_pending: Option<canon::digest::Digest32>,
    pub navigation: Option<canon::digest::Digest32>,
}

impl HttpIngress {
    pub async fn admit_incoming_with_handoff(
        &self,
        peer: std::net::IpAddr,
        request: http::Request<hyper::body::Incoming>,
    ) -> Result<HandoffAdmission> {
        self.admit_http_with_handoff(peer, request.map(axum::body::Body::new))
            .await
    }

    /// Reuses the original TLS, origin, metadata, length, JSON and permit checks.
    /// The frame locator reuses the exact iframe destination and shell referrer checks.
    pub async fn admit_http_with_handoff(
        &self,
        peer: std::net::IpAddr,
        mut request: http::Request<axum::body::Body>,
    ) -> Result<HandoffAdmission> {
        let original_path = request.uri().path_and_query().map(|path| path.as_str());
        let handoff_path = match original_path {
            Some(crate::fd4::HANDOFF_PREPARE_PATH) => Some(crate::fd4::HANDOFF_PREPARE_PATH),
            Some(crate::fd4::HANDOFF_COMPLETE_PATH) => Some(crate::fd4::HANDOFF_COMPLETE_PATH),
            _ => None,
        };
        let navigation = original_path
            .and_then(|path| path.strip_prefix("/handoff-v1-"))
            .map(|reference| {
                if request.method() != http::Method::GET {
                    return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
                }
                canon::digest::Digest32::from_hex(reference)
                    .map_err(|_| codes::FRONTDOOR_PATH_REFUSED)
            })
            .transpose()?;
        let cookies = header_values(request.headers(), "cookie")?;
        if handoff_path.is_some() || navigation.is_some() {
            if handoff_path.is_some() && request.method() != http::Method::POST {
                return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
            }
            // Preserve any absolute-form authority for the original boundary check.
            let mut parts = request.uri().clone().into_parts();
            parts.path_and_query = Some(http::uri::PathAndQuery::from_static(
                if navigation.is_some() {
                    "/"
                } else {
                    crate::fd4::DATA_PATH
                },
            ));
            *request.uri_mut() =
                http::Uri::from_parts(parts).map_err(|_| codes::FRONTDOOR_PATH_REFUSED)?;
        }
        let mut admission = self.admit_http(peer, request).await?;
        if navigation.is_some()
            && (admission.request.role != HostRole::Owner || admission.owner_navigation.is_none())
        {
            return Err(codes::FRONTDOOR_ORIGIN_REFUSED);
        }
        if let Some(path) = handoff_path {
            match admission.request.body.view() {
                ValueView::Object(fields) if fields.is_empty() => {}
                _ => return Err(codes::FRONTDOOR_BODY_INVALID),
            }
            if admission.request.role != HostRole::Shell {
                return Err(codes::FRONTDOOR_HOST_REFUSED);
            }
            admission.request.path = path.to_owned();
        }
        let pending = handoff_cookie_digest(&cookies, crate::fd4::HANDOFF_PENDING_COOKIE)?;
        let correlation = handoff_cookie_digest(&cookies, crate::fd4::HANDOFF_CORRELATION_COOKIE)?;
        let owner_pending = handoff_cookie_digest(&cookies, crate::fd4::HANDOFF_OWNER_COOKIE)?;
        if pending.is_some() && admission.request.role != HostRole::Shell {
            return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
        }
        if owner_pending.is_some() && admission.request.role != HostRole::Owner {
            return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
        }
        Ok(HandoffAdmission {
            admission,
            pending,
            correlation,
            owner_pending,
            navigation,
        })
    }
}

fn handoff_cookie_digest(
    headers: &[String],
    name: &str,
) -> Result<Option<canon::digest::Digest32>> {
    let mut digest = None;
    for header in headers {
        for cookie in header.split(';') {
            let (key, value) = cookie
                .trim()
                .split_once('=')
                .ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?;
            if key == name {
                if digest.is_some() {
                    return Err(codes::FRONTDOOR_SESSION_REQUIRED);
                }
                digest = Some(crate::session::session_digest(value.as_bytes())?);
            }
        }
    }
    Ok(digest)
}
