// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ceremony routes exist on the owner host; no top-level owner navigation route exists.

use crate::{
    ingress::{validate_path, HostRole, Method},
    session::BoundSession,
    tls::{CaddyBoundary, Origin},
};
use canon::{ids::ProposalId, json::Value, Refusal, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerRoute {
    Claim,
    EnrolStart,
    EnrolFinish,
    BindingPrepare,
    BindingConfirm,
    BindingRefresh,
    BindingRefreshPrepare,
    SigninStart,
    SigninFinish,
    Approvals,
    ApprovalRetireChallenge,
}

impl OwnerRoute {
    pub fn resolve(host: HostRole, method: Method, path: &str) -> Result<Self> {
        validate_path(path)?;
        if host != HostRole::Owner {
            return Err(Refusal {
                organ: "frontdoor",
                reason: "unknown-route",
            });
        }
        match (method, path) {
            (Method::Post, "/api/claim") => Ok(Self::Claim),
            (Method::Post, "/api/enrol/start") => Ok(Self::EnrolStart),
            (Method::Post, "/api/enrol/finish") => Ok(Self::EnrolFinish),
            (Method::Post, "/api/binding/prepare") => Ok(Self::BindingPrepare),
            (Method::Post, "/api/binding/confirm") => Ok(Self::BindingConfirm),
            (Method::Post, "/api/binding/refresh") => Ok(Self::BindingRefresh),
            (Method::Post, "/api/binding/refresh/prepare") => Ok(Self::BindingRefreshPrepare),
            (Method::Post, "/api/signin/start") => Ok(Self::SigninStart),
            (Method::Post, "/api/signin/finish") => Ok(Self::SigninFinish),
            (Method::Get, "/api/approvals") => Ok(Self::Approvals),
            (Method::Post, "/api/approvals/retire/challenge") => Ok(Self::ApprovalRetireChallenge),
            _ => Err(Refusal {
                organ: "frontdoor",
                reason: "unknown-route",
            }),
        }
    }
}

/// Mandatory context passed unchanged to AUMLOK, never taken from clientDataJSON.
#[derive(Clone, Debug)]
pub struct CeremonyContext {
    pub relying_party_id: String,
    pub owner_origin: Origin,
    pub expected_top_origin: Origin,
}

impl CeremonyContext {
    /// The RP defaults to the owner host; both origins come from native configuration.
    pub fn from_boundary(boundary: &CaddyBoundary) -> Result<Self> {
        boundary.validate()?;
        Ok(Self {
            relying_party_id: boundary.owner.host().to_owned(),
            owner_origin: boundary.owner.clone(),
            expected_top_origin: boundary.shell.clone(),
        })
    }

    /// This node's RP is its exact owner host, without a broader domain suffix.
    pub fn validate(&self) -> Result<()> {
        let rp = Origin::parse(&format!("https://{}", self.relying_party_id))?;
        if self.owner_origin == self.expected_top_origin
            || rp.host().split('.').count() < 2
            || rp.host().parse::<std::net::IpAddr>().is_ok()
            || rp != self.owner_origin
        {
            return Err(configuration_refused());
        }
        Ok(())
    }
}

/// The identity adapter supplies the verifier; frontdoor cannot verify or grant locally.
pub trait IdentityService {
    /// The verifier requires crossOrigin=true and exact topOrigin. It parses WebAuthn's
    /// clientDataJSON itself; the nested clientDataJSON bytes do not use canon's C1 parser.
    fn ceremony(
        &mut self,
        context: &CeremonyContext,
        route: OwnerRoute,
        session_digest: Option<canon::digest::Digest32>,
        body: Value,
    ) -> Result<Value>;
}

/// Exact supervisor-owned card and authorization bytes for one proposal; never shell-supplied.
#[derive(Clone, Debug)]
pub struct ReviewBytes {
    pub proposal_id: ProposalId,
    pub card: Vec<u8>,
    pub authorization: Vec<u8>,
}

pub trait OwnerReviewService {
    fn load_by_id(
        &mut self,
        session: &BoundSession<'_>,
        proposal: ProposalId,
    ) -> Result<ReviewBytes>;
}

/// The admitted owner-document navigation, distinct from a JSON API request.
pub struct FrameNavigation {
    context: CeremonyContext,
}

impl FrameNavigation {
    pub fn context(&self) -> &CeremonyContext {
        &self.context
    }
}

/// Embedded navigation contract: destination=iframe, exact shell parent, owner CSP restricted
/// to that shell; top-level document requests refuse instead of redirecting.
pub fn admit_frame_navigation(
    context: &CeremonyContext,
    fetch_dest: &str,
    parent_origin: &str,
) -> Result<FrameNavigation> {
    context.validate()?;
    if fetch_dest != "iframe" || parent_origin != context.expected_top_origin.as_str() {
        return Err(canon::codes::FRONTDOOR_ORIGIN_REFUSED);
    }
    Ok(FrameNavigation {
        context: context.clone(),
    })
}

/// GET `/` on the owner host serves its approved index only after frame admission.
/// Remaining owner assets resolve only in AssetSurface::Owner. No redirect or top-level
/// owner page is returned, and the response carries frame-ancestors for the exact shell.
pub fn serve_document(
    navigation: &FrameNavigation,
    release: &crate::assets::ApprovedRelease,
    source: &mut impl crate::assets::ReleaseSource,
) -> Result<crate::assets::AssetResponse> {
    navigation.context.validate()?;
    let response = crate::assets::serve(release, source, crate::assets::AssetSurface::Owner, "/")?;
    if response.kind != crate::assets::AssetKind::Html {
        return Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE);
    }
    Ok(response)
}

/// HTTP adapter for the frozen asset-only return type. Policy is derived from admitted
/// configuration, and the approved document is the entire response body.
pub fn serve_document_response(
    navigation: &FrameNavigation,
    release: &crate::assets::ApprovedRelease,
    source: &mut impl crate::assets::ReleaseSource,
) -> Result<http::Response<Vec<u8>>> {
    let asset = serve_document(navigation, release, source)?;
    let mut response = http::Response::new(asset.bytes);
    *response.headers_mut() = navigation.security_headers()?;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(response)
}

impl FrameNavigation {
    /// Only the shell origin can frame owner documents. No caller supplies a policy.
    pub fn security_headers(&self) -> Result<http::HeaderMap> {
        owner_security_headers(&self.context)
    }
}

fn owner_security_headers(context: &CeremonyContext) -> Result<http::HeaderMap> {
    context.validate()?;
    let mut headers = http::HeaderMap::new();
    let policy = crate::shell::policies(&context.expected_top_origin, &context.owner_origin);
    headers.insert(
        http::header::CONTENT_SECURITY_POLICY,
        http::HeaderValue::from_str(&policy.owner_csp).map_err(|_| configuration_refused())?,
    );
    let permissions = format!(
        "publickey-credentials-create=(self \"{0}\"), publickey-credentials-get=(self \"{0}\")",
        context.expected_top_origin.as_str()
    );
    headers.insert(
        "permissions-policy",
        http::HeaderValue::from_str(&permissions).map_err(|_| configuration_refused())?,
    );
    for (name, value) in [
        (http::header::CACHE_CONTROL, "no-store"),
        (http::header::REFERRER_POLICY, "no-referrer"),
        (http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (http::header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"),
    ] {
        headers.insert(name, http::HeaderValue::from_static(value));
    }
    Ok(headers)
}

/// The owner entry document requires admitted frame navigation. Every other HTML
/// alias refuses, while scripts and data remain restricted to the owner surface.
pub fn serve_owner_asset_response(
    context: &CeremonyContext,
    request: &crate::ingress::AdmittedRequest,
    navigation: Option<&FrameNavigation>,
    release: &crate::assets::ApprovedRelease,
    source: &mut impl crate::assets::ReleaseSource,
) -> Result<http::Response<Vec<u8>>> {
    context.validate()?;
    if request.role() != HostRole::Owner || request.origin() != &context.owner_origin {
        return Err(canon::codes::FRONTDOOR_ORIGIN_REFUSED);
    }
    if !matches!(request.method(), Method::Get | Method::Head) {
        return Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE);
    }
    let mut response = if request.path() == "/" {
        let navigation = navigation.ok_or(canon::codes::FRONTDOOR_ORIGIN_REFUSED)?;
        if navigation.context.owner_origin != context.owner_origin
            || navigation.context.expected_top_origin != context.expected_top_origin
            || navigation.context.relying_party_id != context.relying_party_id
        {
            return Err(canon::codes::FRONTDOOR_ORIGIN_REFUSED);
        }
        serve_document_response(navigation, release, source)?
    } else {
        let asset = crate::assets::serve(
            release,
            source,
            crate::assets::AssetSurface::Owner,
            request.path(),
        )?;
        use crate::assets::AssetKind;
        let content_type = match asset.kind {
            AssetKind::Html => return Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE),
            AssetKind::Script => "text/javascript; charset=utf-8",
            AssetKind::Style => "text/css; charset=utf-8",
            AssetKind::Wasm => "application/wasm",
            AssetKind::Json => "application/json",
            AssetKind::Font if request.path().ends_with(".woff2") => "font/woff2",
            AssetKind::Font => "font/woff",
            AssetKind::Image if request.path().ends_with(".svg") => "image/svg+xml",
            AssetKind::Image if request.path().ends_with(".png") => "image/png",
            AssetKind::Image if request.path().ends_with(".webp") => "image/webp",
            AssetKind::Image => "image/jpeg",
        };
        let mut response = http::Response::new(asset.bytes);
        *response.headers_mut() = owner_security_headers(context)?;
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(content_type),
        );
        response
    };
    let length = response.body().len();
    response.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&length.to_string()).map_err(|_| configuration_refused())?,
    );
    if request.method() == Method::Head {
        response.body_mut().clear();
    }
    Ok(response)
}

/// Sign-in start is public; enrolment and binding retain their live-session guard
/// throughout identity dispatch. Claim, sign-in finish and approvals use dedicated handlers.
pub fn dispatch_ceremony<S: crate::session::SessionStore>(
    context: &CeremonyContext,
    identity: &mut impl IdentityService,
    sessions: &mut S,
    request: &crate::ingress::AdmittedRequest,
    node: canon::ids::NodeId,
    now_ms: u64,
) -> Result<Value> {
    context.validate()?;
    if request.role() != HostRole::Owner || request.origin() != &context.owner_origin {
        return Err(canon::codes::FRONTDOOR_ORIGIN_REFUSED);
    }
    let route = OwnerRoute::resolve(HostRole::Owner, request.method(), request.path())?;
    match route {
        OwnerRoute::SigninStart => identity.ceremony(context, route, None, request.body().clone()),
        OwnerRoute::Claim | OwnerRoute::SigninFinish | OwnerRoute::Approvals => {
            Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE)
        }
        _ => crate::session::with_owner_session(
            sessions,
            request
                .cookie()
                .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?,
            node,
            &context.owner_origin,
            route,
            now_ms,
            |session| {
                let digest = match session {
                    crate::session::OwnerSession::Binding(session) => session.record().token_digest,
                    crate::session::OwnerSession::Bound(session) => session.record().token_digest,
                };
                identity.ceremony(context, route, Some(digest), request.body().clone())
            },
        ),
    }
}

/// The requested record commits only a digest; no bearer enters identity storage.
pub struct SigninSessionRequest {
    pub node: canon::ids::NodeId,
    pub context: CeremonyContext,
    pub body: Value,
    pub session_digest: canon::digest::Digest32,
    pub expires_at_ms: u64,
}

pub struct SigninSessionOutcome {
    pub record: crate::session::SessionRecord,
    pub body: Value,
}

/// AUMLOK verifies the exact assertion and commits the credential counter, sign-in
/// record and session together. Returning success requires durable commit completion.
pub trait SigninSessionService {
    fn verify_and_create_session(
        &mut self,
        request: SigninSessionRequest,
    ) -> Result<SigninSessionOutcome>;
}

/// Cookie issuance follows the verifier's durable transaction; a JSON success value
/// from the generic identity interface is insufficient to create a browser session.
/// Sign-in issues only an owner-frame session carrying the verified subject.
pub fn finish_signin(
    service: &mut impl SigninSessionService,
    context: &CeremonyContext,
    request: &crate::ingress::AdmittedRequest,
    node: canon::ids::NodeId,
    now_ms: u64,
    lifetime_ms: u64,
) -> Result<http::Response<Vec<u8>>> {
    context.validate()?;
    if request.role() != HostRole::Owner || request.origin() != &context.owner_origin {
        return Err(canon::codes::FRONTDOOR_ORIGIN_REFUSED);
    }
    if OwnerRoute::resolve(request.role(), request.method(), request.path())?
        != OwnerRoute::SigninFinish
    {
        return Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE);
    }
    if !(1000..=crate::session::MAX_LIFETIME_MS).contains(&lifetime_ms) {
        return Err(canon::codes::FRONTDOOR_SESSION_REQUIRED);
    }
    let expires_at_ms = now_ms
        .checked_add(lifetime_ms)
        .filter(|expires| *expires <= canon::json::MAX_SAFE_INTEGER as u64)
        .ok_or(canon::codes::FRONTDOOR_SESSION_REQUIRED)?;
    let bearer = crate::session::SessionBearer::generate()?;
    let outcome = service.verify_and_create_session(SigninSessionRequest {
        node,
        context: context.clone(),
        body: request.body().clone(),
        session_digest: bearer.digest(),
        expires_at_ms,
    })?;
    let record = outcome.record;
    if record.token_digest != bearer.digest()
        || record.node != node
        || record.origin != context.owner_origin
        || record.expires_at_ms != expires_at_ms
        || record.revoked
        || record.scope != crate::session::SessionScope::OwnerFrame
        || record.subject.is_none()
    {
        return Err(canon::codes::FRONTDOOR_SESSION_REQUIRED);
    }
    if !matches!(outcome.body.view(), canon::json::ValueView::Object(_)) {
        return Err(canon::codes::FRONTDOOR_BODY_INVALID);
    }
    let bytes = outcome.body.canonical_bytes();
    if bytes.len() > crate::ingress::MAX_BODY_BYTES {
        return Err(canon::codes::FRONTDOOR_BODY_INVALID);
    }
    let cookie = bearer.cookie_header(record.scope, record.expires_at_ms, now_ms)?;
    let mut response = http::Response::new(bytes);
    *response.headers_mut() = owner_security_headers(context)?;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        http::header::SET_COOKIE,
        http::HeaderValue::from_str(&cookie)
            .map_err(|_| canon::codes::FRONTDOOR_SESSION_REQUIRED)?,
    );
    Ok(response)
}

fn configuration_refused() -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason: "config-invalid",
    }
}

#[derive(Clone, Debug)]
pub struct OwnerOriginFacts {
    pub relying_party_id: String,
    pub accepted_top_origin: Origin,
    pub active_principal_limits: Vec<(canon::digest::Digest32, u32)>,
}
