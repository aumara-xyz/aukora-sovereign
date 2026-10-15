// SPDX-License-Identifier: AGPL-3.0-or-later
//! Approved static bundles on a dedicated host, outside shell and owner routing.

use crate::tls::{CaddyBoundary, Origin, ProxyObservation};
use canon::{digest::Digest32, ids::ProposalId, Refusal, Result};
use gate::target::sites::PublishedSite;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// An opaque document cannot use cookies, WebAuthn, workers or authenticated APIs.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none'; worker-src 'none'; frame-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; sandbox allow-scripts";
pub const PERMISSIONS_POLICY: &str = "publickey-credentials-create=(), publickey-credentials-get=(), camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()";
const MAX_HEADERS: usize = 16_384;

/// Deployment fixes all three hosts and trusted TLS proxy peers before admission.
#[derive(Clone, Debug)]
pub struct SiteBoundary {
    origin: Origin,
    node: CaddyBoundary,
}

impl SiteBoundary {
    pub fn new(origin: Origin, node: CaddyBoundary) -> Result<Self> {
        node.validate()?;
        let site = node.registered_site.host();
        if origin == node.shell
            || origin == node.owner
            || origin.host() == site
            || !origin
                .host()
                .strip_suffix(site)
                .is_some_and(|p| p.ends_with('.'))
            || origin.host().parse::<IpAddr>().is_ok()
            || overlaps(origin.host(), node.shell.host())
            || overlaps(origin.host(), node.owner.host())
        {
            return Err(refuse("site-host"));
        }
        Ok(Self { origin, node })
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    fn admit(&self, connection: &ProxyObservation) -> Result<()> {
        if !self.node.allowed_proxy_peers.contains(&connection.peer)
            || connection.forwarded_proto.as_slice() != ["https"]
            || connection.host.as_slice() != [self.origin.host()]
        {
            return Err(refuse("site-transport"));
        }
        Ok(())
    }

    /// This listener has no fallback into either authenticated host.
    pub fn caddy_block(&self, upstream: SocketAddr) -> Result<String> {
        if !upstream.ip().is_loopback()
            || upstream.port() == 0
            || !self.node.allowed_proxy_peers.contains(&upstream.ip())
        {
            return Err(refuse("site-transport"));
        }
        Ok(format!(
            "{} {{\n    reverse_proxy {} {{\n        header_up -Forwarded\n        header_up X-Forwarded-Proto https\n        header_down -Set-Cookie\n    }}\n}}\n",
            self.origin.as_str(), upstream
        ))
    }
}

fn overlaps(left: &str, right: &str) -> bool {
    left == right
        || left.strip_suffix(right).is_some_and(|p| p.ends_with('.'))
        || right.strip_suffix(left).is_some_and(|p| p.ends_with('.'))
}

/// A mounted site is obtainable only from the gate's consumed approval record.
pub struct SiteHost {
    boundary: SiteBoundary,
    publication: Option<PublishedSite>,
}

impl SiteHost {
    pub fn new(boundary: SiteBoundary) -> Self {
        Self {
            boundary,
            publication: None,
        }
    }

    pub fn boundary(&self) -> &SiteBoundary {
        &self.boundary
    }

    /// Publishing a proposal never mounts its bytes. A passkey apply is separate.
    pub fn propose<S: gate::target::TargetStore>(
        &self,
        gate: &mut gate::service::Gate<'_, S>,
        request: canon::fd3_payloads::sites::SiteProposal,
        crash: &mut dyn gate::recovery::CrashInjector,
    ) -> Result<gate::Proposal> {
        if request.bundle.host() != self.boundary.origin.host() {
            return Err(refuse("site-host"));
        }
        gate.propose_site(request, crash)
    }

    /// Re-reads consumed authority and current target bytes, including after reboot.
    pub fn mount<S: gate::target::TargetStore>(
        &mut self,
        gate: &mut gate::service::Gate<'_, S>,
        proposal: ProposalId,
    ) -> Result<()> {
        let publication = gate.published_site(proposal)?;
        if publication.bundle().host() != self.boundary.origin.host() {
            return Err(refuse("site-host"));
        }
        self.publication = Some(publication);
        Ok(())
    }

    pub fn review<S: gate::target::TargetStore>(
        &self,
        gate: &mut gate::service::Gate<'_, S>,
        proposal: ProposalId,
        crash: &mut dyn gate::recovery::CrashInjector,
    ) -> Result<gate::service::OwnerReview> {
        if gate.site_bundle(proposal)?.host() != self.boundary.origin.host() {
            return Err(refuse("site-host"));
        }
        let review = gate.review_site(proposal, crash)?;
        let expected = canon::json::Value::text(format!("{}/", self.boundary.origin.as_str()))?;
        if !review
            .card
            .card()
            .facts
            .iter()
            .any(|(key, value)| key == "address" && value == &expected)
        {
            return Err(refuse("site-host"));
        }
        Ok(review)
    }

    /// The owner's retained assertion is checked and consumed before any mount.
    pub fn approve_and_mount<S: gate::target::TargetStore>(
        &mut self,
        gate: &mut gate::service::Gate<'_, S>,
        proposal: ProposalId,
        assertion: canon::authority::OwnerAssertion,
        crash: &mut dyn gate::recovery::CrashInjector,
    ) -> Result<gate::service::Outcome> {
        if gate.site_bundle(proposal)?.host() != self.boundary.origin.host() {
            return Err(refuse("site-host"));
        }
        let outcome = gate.apply_site(proposal, assertion, crash)?;
        if outcome.state == gate::ProposalState::Applied {
            self.mount(gate, proposal)?;
        }
        Ok(outcome)
    }

    /// GET and HEAD are static lookups only; all request authority is discarded.
    pub fn serve(
        &self,
        connection: &ProxyObservation,
        method: &Method,
        uri: &http::Uri,
        headers: &HeaderMap,
    ) -> Result<SiteResponse> {
        self.boundary.admit(connection)?;
        if method != Method::GET && method != Method::HEAD {
            return Err(refuse("site-method"));
        }
        let size = headers.iter().try_fold(0usize, |sum, (key, value)| {
            sum.checked_add(key.as_str().len() + value.as_bytes().len() + 4)
        });
        if size.is_none_or(|size| size > MAX_HEADERS)
            || headers.contains_key("cookie")
            || headers.contains_key("authorization")
            || headers.contains_key("proxy-authorization")
            || headers.contains_key("transfer-encoding")
            || headers.get_all("content-length").iter().count() > 1
            || headers
                .get("content-length")
                .is_some_and(|v| v.as_bytes() != b"0")
        {
            return Err(refuse("site-credentials"));
        }
        if uri.scheme_str().is_some_and(|scheme| scheme != "https")
            || uri
                .authority()
                .is_some_and(|host| host.as_str() != self.boundary.origin.host())
            || uri.query().is_some()
        {
            return Err(refuse("site-path"));
        }
        let path = uri.path();
        let key = if path == "/" {
            "index.html"
        } else {
            path.strip_prefix('/').ok_or(refuse("site-path"))?
        };
        if key.is_empty()
            || key.len() > 192
            || key
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            || key == "api"
            || key.starts_with("api/")
            || key == "ui"
            || key.starts_with("ui/")
            || key.starts_with(".well-known/")
        {
            return Err(refuse("site-path"));
        }
        let site = self
            .publication
            .as_ref()
            .ok_or(refuse("site-unpublished"))?;
        let file = site
            .bundle()
            .files()
            .iter()
            .find(|file| file.path == key)
            .ok_or(refuse("site-missing"))?;
        let mut response = policy_headers();
        response.insert(
            http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        response.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(&file.media_type).map_err(|_| refuse("site-response"))?,
        );
        response.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&file.bytes.len().to_string())
                .map_err(|_| refuse("site-response"))?,
        );
        Ok(SiteResponse {
            status: StatusCode::OK,
            headers: response,
            body: if method == Method::HEAD {
                Vec::new()
            } else {
                file.bytes.clone()
            },
        })
    }

    /// Observe the mounted HTTPS host through the supervisor's external transport.
    /// Every asset and the root alias must match; no local handler response is sampled.
    pub async fn isolation_probe<F, Fut>(&self, mut fetch: F) -> Result<IsolationObservation>
    where
        F: FnMut(SiteProbeRequest) -> Fut,
        Fut: Future<Output = Result<SiteProbeResponse>>,
    {
        let site = self
            .publication
            .as_ref()
            .ok_or(refuse("site-unpublished"))?;
        let index = site
            .bundle()
            .files()
            .iter()
            .find(|file| file.path == "index.html")
            .ok_or(refuse("site-isolation"))?;
        tokio::time::timeout(Duration::from_secs(10), async {
            let paths = std::iter::once(("", index)).chain(
                site.bundle()
                    .files()
                    .iter()
                    .map(|file| (file.path.as_str(), file)),
            );
            for (path, file) in paths {
                let response = fetch(SiteProbeRequest {
                    url: format!("{}/{path}", self.boundary.origin.as_str()),
                    headers: HeaderMap::new(),
                    max_body_bytes: file.bytes.len(),
                })
                .await?;
                response.check_policy()?;
                if response.status != StatusCode::OK
                    || response.body != file.bytes
                    || !single_header(&response.headers, "content-type", &file.media_type)
                    || !single_header(
                        &response.headers,
                        "content-length",
                        &file.bytes.len().to_string(),
                    )
                    || !single_header(&response.headers, "access-control-allow-origin", "*")
                {
                    return Err(refuse("site-isolation"));
                }
            }
            for (name, value) in [
                ("cookie", "probe=1"),
                ("authorization", "Bearer site-isolation-probe"),
            ] {
                let mut headers = HeaderMap::new();
                headers.insert(
                    http::header::HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                );
                let response = fetch(SiteProbeRequest {
                    url: format!("{}/", self.boundary.origin.as_str()),
                    headers,
                    max_body_bytes: 0,
                })
                .await?;
                response.check_policy()?;
                if response.status != StatusCode::NOT_FOUND || !response.body.is_empty() {
                    return Err(refuse("site-isolation"));
                }
            }
            Ok(IsolationObservation {
                host: self.boundary.origin.host().to_owned(),
                bundle_sha256: site.bundle().digest(),
            })
        })
        .await
        .map_err(|_| refuse("site-transport"))?
    }

    /// An HTTP adapter for the separate TLS proxy listener, with a bounded read deadline.
    pub async fn handle(
        &self,
        peer: IpAddr,
        request: http::Request<axum::body::Body>,
    ) -> http::Response<axum::body::Body> {
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(10_000),
            self.read_request(peer, request),
        )
        .await;
        match result {
            Ok(Ok(response)) => response.into_http(),
            _ => SiteResponse {
                status: StatusCode::NOT_FOUND,
                headers: policy_headers(),
                body: Vec::new(),
            }
            .into_http(),
        }
    }

    async fn read_request(
        &self,
        peer: IpAddr,
        request: http::Request<axum::body::Body>,
    ) -> Result<SiteResponse> {
        use http_body_util::BodyExt;
        let (parts, mut body) = request.into_parts();
        let connection = ProxyObservation {
            peer,
            forwarded_proto: header_values(&parts.headers, "x-forwarded-proto")?,
            host: header_values(&parts.headers, "host")?,
        };
        let response = self.serve(&connection, &parts.method, &parts.uri, &parts.headers)?;
        while let Some(frame) = body.frame().await {
            let data = frame
                .map_err(|_| refuse("site-body"))?
                .into_data()
                .map_err(|_| refuse("site-body"))?;
            if !data.is_empty() {
                return Err(refuse("site-body"));
            }
        }
        Ok(response)
    }
}

/// Evidence for the external observer; the serving path does not consume it.
pub struct IsolationObservation {
    pub host: String,
    pub bundle_sha256: Digest32,
}

/// One GET selected by the mounted bundle, never by an incoming request.
pub struct SiteProbeRequest {
    url: String,
    headers: HeaderMap,
    max_body_bytes: usize,
}

impl SiteProbeRequest {
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }
}

/// Bounded response bytes and headers supplied by the supervisor transport.
pub struct SiteProbeResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl SiteProbeResponse {
    pub fn new(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Result<Self> {
        let size = headers.iter().try_fold(0usize, |sum, (key, value)| {
            sum.checked_add(key.as_str().len() + value.as_bytes().len() + 4)
        });
        if size.is_none_or(|size| size > MAX_HEADERS)
            || body.len() > canon::fd3_payloads::sites::MAX_BUNDLE_BYTES
        {
            return Err(refuse("site-isolation"));
        }
        Ok(Self {
            status,
            headers,
            body,
        })
    }

    fn check_policy(&self) -> Result<()> {
        for (name, expected) in &policy_headers() {
            if self.headers.get_all(name).iter().count() != 1
                || self.headers.get(name) != Some(expected)
            {
                return Err(refuse("site-isolation"));
            }
        }
        if [
            "set-cookie",
            "set-cookie2",
            "www-authenticate",
            "proxy-authenticate",
            "access-control-allow-credentials",
            "content-encoding",
            "location",
            "refresh",
        ]
        .iter()
        .any(|name| self.headers.contains_key(*name))
        {
            return Err(refuse("site-isolation"));
        }
        Ok(())
    }
}

fn single_header(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    headers.get_all(name).iter().count() == 1
        && headers
            .get(name)
            .is_some_and(|value| value.as_bytes() == expected.as_bytes())
}

pub struct SiteResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl SiteResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn into_http(self) -> http::Response<axum::body::Body> {
        let mut response = http::Response::new(axum::body::Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

fn policy_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (key, value) in [
        ("content-security-policy", CONTENT_SECURITY_POLICY),
        ("permissions-policy", PERMISSIONS_POLICY),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("cross-origin-resource-policy", "cross-origin"),
        ("cross-origin-opener-policy", "same-origin"),
        ("strict-transport-security", "max-age=31536000"),
    ] {
        headers.insert(
            http::header::HeaderName::from_static(key),
            HeaderValue::from_static(value),
        );
    }
    headers
}

fn header_values(headers: &HeaderMap, name: &str) -> Result<Vec<String>> {
    headers
        .get_all(name)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| refuse("site-transport"))
        })
        .collect()
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason,
    }
}
