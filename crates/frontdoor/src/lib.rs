// SPDX-License-Identifier: AGPL-3.0-or-later

mod backend;
mod holding;
mod proxy;
#[cfg(test)]
mod session_admission_tests;
mod static_files;
mod warmup;

pub use backend::*;

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const OWNER_COOKIE: &str = "__Host-aukora-owner";
pub const CHAT_COOKIE: &str = "__Host-aukora-chat";
pub const OWNER_CSP: &str =
    "default-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'";
/// The chat origin is untrusted by design and isolated from the owner origin (separate
/// host, cookies and routes); that isolation is the defence, not this policy (SPEC §2).
/// The agent's web app boots with an inline script, evaluates small config expressions
/// with `new Function`, and uses inline styles, data: images and blob: workers.
pub const CHAT_CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; worker-src 'self' blob:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; object-src 'none'";
const MAX_SESSION: Duration = Duration::from_secs(86_400);
const MAX_CHAT_SESSIONS: usize = 1024;
const OWNER_HANDOFF: &str = "/__aukora/handoff";

/// Transport facts are supplied by the listener, never by a request header alone.
#[derive(Clone)]
pub enum Transport {
    TrustedProxy {
        peers: Vec<IpAddr>,
    },
    /// Reserved for a TLS acceptor; this release refuses to start in this mode.
    DirectTls,
}

#[derive(Clone)]
pub struct Config {
    pub node: String,
    pub owner_host: String,
    pub chat_host: String,
    pub guest_socket: PathBuf,
    pub transport: Transport,
    pub session_lifetime: Duration,
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
    pub max_connections: usize,
    pub wrong_guesses: usize,
    pub guess_window: Duration,
}

impl Config {
    pub fn behind_proxy(
        node: String,
        owner_host: String,
        chat_host: String,
        guest_socket: PathBuf,
        peers: Vec<IpAddr>,
    ) -> Self {
        Self {
            node,
            owner_host,
            chat_host,
            guest_socket,
            transport: Transport::TrustedProxy { peers },
            session_lifetime: MAX_SESSION,
            request_timeout: Duration::from_secs(10),
            max_body_bytes: 64 * 1024,
            max_connections: 64,
            wrong_guesses: 5,
            guess_window: Duration::from_secs(60),
        }
    }

    fn validate(&self) -> Result<(), ApiError> {
        if self.node.len() != 32
            || !self
                .node
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !hostname(&self.owner_host, "owner-")
            || !hostname(&self.chat_host, "chat-")
            || self.owner_host == self.chat_host
            || !self.guest_socket.is_absolute()
            || self.session_lifetime.as_secs() == 0
            || self.session_lifetime.subsec_nanos() != 0
            || self.session_lifetime > MAX_SESSION
            || self.request_timeout.is_zero()
            || self.max_connections == 0
            || self.max_body_bytes == 0
            || self.wrong_guesses == 0
            || self.guess_window.is_zero()
        {
            return Err(error(StatusCode::BAD_REQUEST, "frontdoor:config-invalid"));
        }
        match &self.transport {
            Transport::TrustedProxy { peers } if !peers.is_empty() => Ok(()),
            Transport::TrustedProxy { .. } => {
                Err(error(StatusCode::BAD_REQUEST, "frontdoor:config-invalid"))
            }
            Transport::DirectTls => Err(error(
                StatusCode::NOT_IMPLEMENTED,
                "frontdoor:tls-unavailable",
            )),
        }
    }
}

fn hostname(host: &str, prefix: &str) -> bool {
    host.starts_with(prefix)
        && host.len() <= 253
        && host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[derive(Clone)]
pub(crate) struct ConnectionLease {
    _permit: Arc<tokio::sync::OwnedSemaphorePermit>,
}

struct Session {
    expires: Instant,
    host: String,
    owner: Option<[u8; 32]>,
}

struct ChatTicket {
    expires: Instant,
    owner: [u8; 32],
}

struct FailureWindow {
    start: Instant,
    count: usize,
}

struct Tables {
    sessions: HashMap<[u8; 32], Session>,
    failures: HashMap<String, FailureWindow>,
    chat_tickets: HashMap<[u8; 32], ChatTicket>,
}

pub struct Frontdoor {
    config: Config,
    backend: Arc<dyn Backend>,
    tables: Mutex<Tables>,
    harness_cookie: Mutex<Option<HeaderValue>>,
    warmup_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    warmup_connector: Mutex<Option<warmup::Connector>>,
}

impl Frontdoor {
    pub fn new(config: Config, backend: Arc<dyn Backend>) -> Result<Arc<Self>, ApiError> {
        config.validate()?;
        Ok(Arc::new(Self {
            config,
            backend,
            tables: Mutex::new(Tables {
                sessions: HashMap::new(),
                failures: HashMap::new(),
                chat_tickets: HashMap::new(),
            }),
            harness_cookie: Mutex::new(None),
            warmup_task: Mutex::new(None),
            #[cfg(test)]
            warmup_connector: Mutex::new(None),
        }))
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .fallback(dispatch)
            .with_state(Arc::clone(self))
    }

    /// The caller binds the private Caddy upstream, not a public plaintext listener.
    pub async fn serve(self: &Arc<Self>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
        let permits = Arc::new(tokio::sync::Semaphore::new(self.config.max_connections));
        loop {
            let (stream, peer) = listener.accept().await?;
            let Transport::TrustedProxy { peers } = &self.config.transport else {
                return Err(std::io::Error::other("frontdoor:tls-unavailable"));
            };
            if !peers.contains(&peer.ip()) {
                continue;
            }
            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                continue;
            };
            let frontdoor = Arc::clone(self);
            tokio::spawn(async move {
                let lease = ConnectionLease {
                    _permit: Arc::new(permit),
                };
                let _ = frontdoor.connection(stream, peer, Some(lease)).await;
            });
        }
    }

    async fn connection<I>(
        self: &Arc<Self>,
        stream: I,
        peer: SocketAddr,
        lease: Option<ConnectionLease>,
    ) -> Result<(), hyper::Error>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use tower::ServiceExt;
        let router = self.router();
        hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(self.config.request_timeout) // MUTATION: header-timeout
            .max_buf_size(8192)
            .max_headers(64)
            .serve_connection(
                hyper_util::rt::TokioIo::new(stream),
                hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                    let router = router.clone();
                    let lease = lease.clone();
                    async move {
                        let mut request = request.map(Body::new);
                        request.extensions_mut().insert(ConnectInfo(peer));
                        if let Some(lease) = lease {
                            request.extensions_mut().insert(lease);
                        }
                        router.oneshot(request).await
                    }
                }),
            )
            .with_upgrades()
            .await
    }

    /// Revocation also invalidates a copied cookie. Tokens are never retained.
    pub async fn revoke(&self, token: &str) -> Result<(), ApiError> {
        let key = digest(token);
        self.backend.revoke_session(key).await?;
        if self.backend.durable_sessions() {
            self.backend.revoke_chat_session(key).await?;
        }
        self.tables
            .lock()
            .expect("session lock")
            .sessions
            .remove(&key);
        Ok(())
    }

    async fn session(&self, headers: &HeaderMap, host: &str) -> Option<[u8; 32]> {
        let token = owner_token(headers)?;
        let key = digest(token);
        let local = {
            let mut tables = self.tables.lock().expect("session lock");
            tables
                .sessions
                .retain(|_, session| session.expires > Instant::now()); // MUTATION: session-expiry
            tables
                .sessions
                .get(&key)
                .filter(|session| session.host == host)
                .is_some() // MUTATION: session-audience
        };
        if local && (host != self.config.owner_host || !self.backend.durable_sessions()) {
            return Some(key);
        }
        if host != self.config.owner_host {
            return None;
        }
        // The stored row decides, also on a memory hit: revocation and wall-clock expiry apply at once.
        self.backend
            .session_valid(key, timestamp_ms()?)
            .await
            .ok()
            .filter(|valid| *valid)
            .map(|_| key)
    }

    fn limited(&self, principal: &str) -> bool {
        let tables = self.tables.lock().expect("rate lock");
        tables.failures.get(principal).is_some_and(|window| {
            window.start.elapsed() < self.config.guess_window
                && window.count >= self.config.wrong_guesses
        })
    }

    fn failed_guess(&self, principal: &str) -> bool {
        let mut tables = self.tables.lock().expect("rate lock");
        tables
            .failures
            .retain(|_, window| window.start.elapsed() < self.config.guess_window);
        // Eviction bounds unauthenticated address bookkeeping without a global lockout.
        if tables.failures.len() >= 4096 && !tables.failures.contains_key(principal) {
            if let Some(key) = tables
                .failures
                .iter()
                .min_by_key(|(_, w)| w.start)
                .map(|(k, _)| k.clone())
            {
                tables.failures.remove(&key);
            }
        }
        let window = tables
            .failures
            .entry(principal.to_owned())
            .or_insert(FailureWindow {
                start: Instant::now(),
                count: 0,
            });
        window.count += 1;
        window.count > self.config.wrong_guesses // MUTATION: wrong-guess-limit
    }

    fn transport(&self, request: &Request<Body>) -> Result<IpAddr, ApiError> {
        let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() else {
            return Err(error(StatusCode::FORBIDDEN, "frontdoor:transport-required"));
        };
        match &self.config.transport {
            Transport::TrustedProxy { peers } => {
                if !peers.contains(&peer.ip()) {
                    // MUTATION: proxy-peer
                    return Err(error(StatusCode::FORBIDDEN, "frontdoor:untrusted-proxy"));
                }
                if single(request.headers(), "x-forwarded-proto") != Some("https") {
                    // MUTATION: proxy-https
                    return Err(error(StatusCode::FORBIDDEN, "frontdoor:https-required"));
                }
                // Only a configured proxy can assert a canonical single client IP.
                match single(request.headers(), "x-forwarded-for") {
                    Some(value) => value
                        .parse()
                        .map_err(|_| error(StatusCode::BAD_REQUEST, "frontdoor:proxy-invalid")),
                    None if !request.headers().contains_key("x-forwarded-for") => Ok(peer.ip()),
                    None => Err(error(StatusCode::BAD_REQUEST, "frontdoor:proxy-invalid")),
                }
            }
            Transport::DirectTls => Err(error(
                StatusCode::NOT_IMPLEMENTED,
                "frontdoor:tls-unavailable",
            )),
        }
    }

    async fn handle(&self, request: Request<Body>) -> Response {
        let host = single(request.headers(), "host").unwrap_or("").to_owned();
        if host != self.config.owner_host && host != self.config.chat_host {
            // MUTATION: exact-host
            return refusal(error(
                StatusCode::MISDIRECTED_REQUEST,
                "frontdoor:host-refused",
            ));
        }
        if request
            .uri()
            .authority()
            .is_some_and(|authority| authority.as_str() != host)
            || request
                .uri()
                .scheme_str()
                .is_some_and(|scheme| scheme != "https")
        {
            return refusal(error(
                StatusCode::MISDIRECTED_REQUEST,
                "frontdoor:host-refused",
            ));
        }
        let ip = match self.transport(&request) {
            Ok(ip) => ip,
            Err(err) => return refusal(err),
        };
        let path = request.uri().path().to_owned();
        if ambiguous_path(&path) {
            // MUTATION: path-alias
            return refusal(error(StatusCode::BAD_REQUEST, "frontdoor:path-refused"));
        }
        // The agent's web app loads its plugins through one combined URL of several KB; the
        // owner origin's routes are short.
        let uri_limit = if host == self.config.chat_host {
            16 * 1024
        } else {
            2048
        };
        if request.uri().to_string().len() > uri_limit
            || request
                .headers()
                .iter()
                .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
                .sum::<usize>()
                > 8192
        {
            return refusal(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "frontdoor:request-too-large",
            ));
        }
        let upgrade = request.headers().contains_key(header::UPGRADE);
        let sensitive = request.method() != Method::GET && request.method() != Method::HEAD
            || upgrade
            || request
                .headers()
                .get_all(header::ACCEPT)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|v| v.split(',').any(sse_type));
        if sensitive {
            if single(request.headers(), "origin") != Some(format!("https://{host}").as_str()) {
                // MUTATION: exact-origin
                return refusal(error(StatusCode::FORBIDDEN, "frontdoor:origin-refused"));
            }
            // Browsers send no Fetch Metadata on a WebSocket handshake but always send its
            // Origin, which a page cannot forge; when the header is present it must agree.
            // Only a genuine WebSocket handshake (Upgrade: websocket, Connection: upgrade).
            let site_absent_on_upgrade = proxy::websocket_headers(request.headers())
                && !request.headers().contains_key("sec-fetch-site");
            if !site_absent_on_upgrade
                && single(request.headers(), "sec-fetch-site") != Some("same-origin")
            {
                // MUTATION: fetch-site
                return refusal(error(StatusCode::FORBIDDEN, "frontdoor:fetch-site-refused"));
            }
        }
        if request.uri().query().is_some_and(|q| {
            secret_query(q)
                || (host == self.config.owner_host
                    && !(path == "/api/nostr/send/preview" && q.starts_with("id="))
                    && (q
                        .split('&')
                        .any(|part| !part.starts_with("since=") && !part.starts_with("limit="))
                        || (path != "/api/aura/head" && path != "/api/aura/recent")))
        }) {
            // MUTATION: query-scrub
            if request.method() == Method::GET || request.method() == Method::HEAD {
                let mut response = StatusCode::SEE_OTHER.into_response();
                response
                    .headers_mut()
                    .insert(header::LOCATION, HeaderValue::from_static("/"));
                return response;
            }
            return refusal(error(StatusCode::BAD_REQUEST, "frontdoor:query-refused"));
        }
        if host == self.config.chat_host {
            if request.method() == Method::GET && path == "/__aukora/chat" {
                let mut response = Response::new(Body::from(CHAT_BOOTSTRAP));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
                return response;
            }
            if request.method() == Method::POST && path == "/api/chat/session" {
                return self.chat_exchange(request).await;
            }
            if request.method() == Method::GET && path == "/manifest.webmanifest" {
                // Browsers fetch a manifest without cookies, so it can never carry the chat
                // session; answer it here and never proxy an unauthenticated request.
                let mut response = Response::new(Body::from(CHAT_MANIFEST));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/manifest+json"),
                );
                return response;
            }
            let release_poll = request.method() == Method::GET && path == "/__aukora/release";
            if proxy::owner_route(&path) && !release_poll {
                // MUTATION: chat-owner-route
                return refusal(error(StatusCode::NOT_FOUND, "frontdoor:unknown-route"));
            }
            if owner_token(request.headers()).is_some() {
                // MUTATION: wrong-host-cookie
                return refusal(error(
                    StatusCode::FORBIDDEN,
                    "frontdoor:cookie-host-refused",
                ));
            }
            let chat_session = self.chat_session(request.headers()).await;
            if !chat_session && browser_navigation(&request) {
                let mut response = StatusCode::SEE_OTHER.into_response();
                response.headers_mut().insert(
                    header::LOCATION,
                    HeaderValue::from_str(&format!(
                        "https://{}{}",
                        self.config.owner_host, OWNER_HANDOFF
                    ))
                    .expect("validated owner hostname"),
                );
                return response;
            }
            let running = match self.backend.state().await {
                Ok(state) if state.state.is_bound() => state.state == BootstrapState::Released,
                Ok(_) => return binding_required(), // MUTATION: chat-binding
                Err(err) => return refusal(err),
            };
            if !chat_session {
                return refusal(error(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:chat-session-required",
                ));
            }
            if release_poll {
                // Reload only after the harness session is ready.
                let ready = running
                    && self
                        .harness_cookie
                        .lock()
                        .expect("harness cookie lock")
                        .is_some();
                return json_response(json!({"agent":if ready { "running" } else { "stopped" }}));
            }
            if !running
                && matches!(*request.method(), Method::GET | Method::HEAD)
                && matches!(path.as_str(), "/" | "/index.html")
            {
                return holding::page(&self.config.owner_host, request.method() == Method::HEAD);
            }
            let Some(harness_cookie) = self
                .harness_cookie
                .lock()
                .expect("harness cookie lock")
                .clone()
            else {
                return refusal(error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "frontdoor:harness-auth-required",
                ));
            };
            let origin_ok =
                single(request.headers(), "origin") == Some(format!("https://{host}").as_str());
            let fetch_ok = single(request.headers(), "sec-fetch-site") == Some("same-origin");
            let socket = warmup::Socket::new(&self.config.guest_socket);
            #[cfg(test)]
            let socket = match self.warmup_connector.lock().unwrap().clone() {
                Some(connector) => {
                    warmup::Socket::with_connector(&self.config.guest_socket, connector)
                }
                None => socket,
            };
            let response = proxy::proxy_authenticated(
                request,
                socket.connect(),
                self.config.request_timeout,
                self.config.max_body_bytes,
                harness_cookie,
            )
            .await;
            if response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(sse_type)
                && (!origin_ok || !fetch_ok)
            {
                return refusal(error(
                    StatusCode::FORBIDDEN,
                    "frontdoor:stream-origin-refused",
                ));
            }
            return response;
        }
        self.owner(request, &path, ip).await
    }

    async fn owner(&self, request: Request<Body>, path: &str, ip: IpAddr) -> Response {
        if request.method() == Method::GET || request.method() == Method::HEAD {
            if let Some((mime, bytes)) = static_files::asset(path) {
                let body = if request.method() == Method::HEAD {
                    Body::empty()
                } else {
                    Body::from(bytes)
                };
                let mut response = Response::new(body);
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
                return response;
            }
        }
        let session = self
            .session(request.headers(), &self.config.owner_host)
            .await;
        if request.method() == Method::POST
            && matches!(path, "/api/signin/start" | "/api/signin/finish")
        {
            return self.signin(request, path, ip).await;
        }
        if request.method() == Method::GET && path == "/api/state" {
            // Without a session the node's state is public (so a bound node offers
            // sign-in and an unclaimed one the claim form); the subject is not.
            return match self.backend.state().await {
                Ok(state) => {
                    let signed_in = session.is_some();
                    json_response(json!({
                        "node": self.config.node,
                        "state": state.state.as_str(),
                        "session": signed_in,
                        "subject": if signed_in { json!(state.subject) } else { Value::Null },
                    }))
                }
                Err(err) => refusal(err),
            };
        }
        if request.method() == Method::POST && path == "/api/claim" {
            return self.claim(request, ip).await;
        }
        if session.is_none() {
            return if route(request.method(), path).is_some()
                || path == "/api/logout"
                || path == "/api/chat-session"
            {
                refusal(error(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:session-required",
                ))
            } else {
                refusal(error(StatusCode::NOT_FOUND, "frontdoor:unknown-route"))
            };
        }
        let session = session.expect("authenticated above");
        let owner_headers = request.headers().clone();
        if request.method() == Method::POST && path == "/api/logout" {
            let key = session;
            let parsed = match self.json_body(request).await {
                Ok(body) if body == json!({}) => body,
                Ok(_) => return refusal(error(StatusCode::BAD_REQUEST, "frontdoor:body-invalid")),
                Err(err) => return refusal(err),
            };
            drop(parsed);
            if self.session(&owner_headers, &self.config.owner_host).await != Some(session) {
                return refusal(error(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:session-required",
                ));
            }
            if let Err(err) = self.backend.revoke_session(session).await {
                return refusal(err);
            }
            self.tables
                .lock()
                .expect("session lock")
                .sessions
                .remove(&key); // MUTATION: logout-revoke
            let mut response = json_response(json!({"ok": true}));
            clear_owner_cookie(&mut response);
            return response;
        }
        let state = match self.backend.state().await {
            Ok(state) => state,
            Err(err) => return refusal(err),
        };
        if !state.state.is_bound() && !bootstrap_route(request.method(), path) {
            // MUTATION: owner-binding
            return binding_required();
        }
        if request.method() == Method::POST && path == "/api/chat-session" {
            let body = match self.json_body(request).await {
                Ok(body) if body == json!({}) => body,
                Ok(_) => return refusal(ApiError::invalid_body()),
                Err(err) => return refusal(err),
            };
            drop(body);
            let mut random = [0_u8; 32];
            if getrandom::fill(&mut random).is_err() {
                return refusal(error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "frontdoor:entropy-unavailable",
                ));
            }
            let ticket = hex(&random);
            if self.session(&owner_headers, &self.config.owner_host).await != Some(session) {
                return refusal(error(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:session-required",
                ));
            }
            let ticket_digest = digest(&ticket);
            if let Err(err) = self
                .backend
                .with_owner_session(
                    session,
                    Box::new(|| {
                        let mut tables = self.tables.lock().expect("ticket lock");
                        if !self.backend.durable_sessions()
                            && !tables.sessions.get(&session).is_some_and(|row| {
                                row.host == self.config.owner_host && row.expires > Instant::now()
                            })
                        {
                            return Err(error(
                                StatusCode::UNAUTHORIZED,
                                "frontdoor:session-required",
                            ));
                        }
                        tables
                            .chat_tickets
                            .retain(|_, ticket| ticket.expires > Instant::now());
                        if tables.chat_tickets.len() >= MAX_CHAT_SESSIONS {
                            return Err(error(
                                StatusCode::TOO_MANY_REQUESTS,
                                "frontdoor:chat-session-limit",
                            ));
                        }
                        tables.chat_tickets.insert(
                            ticket_digest,
                            ChatTicket {
                                expires: Instant::now() + Duration::from_secs(60),
                                owner: session,
                            },
                        );
                        Ok(())
                    }),
                )
                .await
            {
                return refusal(err);
            }
            return json_response(
                json!({"url":format!("https://{}/__aukora/chat#ticket={ticket}",self.config.chat_host)}),
            );
        }
        let Some(operation) = route(request.method(), path) else {
            return refusal(error(StatusCode::NOT_FOUND, "frontdoor:unknown-route"));
        };
        let body = if request.method() == Method::POST {
            match self.json_body(request).await {
                Ok(body) => body,
                Err(err) => return refusal(err),
            }
        } else {
            match query_body(operation, request.uri().query()) {
                Ok(body) => body,
                Err(err) => return refusal(err),
            }
        };
        if let Err(err) = validate_operation(operation, &body) {
            return refusal(err);
        }
        let principal = hex(&session);
        if guess_operation(operation) && self.limited(&principal) {
            // MUTATION: session-rate
            return refusal(error(
                StatusCode::TOO_MANY_REQUESTS,
                "frontdoor:guess-rate-limited",
            ));
        }
        let owner_principal = format!("owner:{}", self.config.node);
        let owner_principal = if session_operation(operation) {
            format!("session:{principal}")
        } else {
            owner_principal
        };
        // Logout during body upload removes this request's authority.
        if self.session(&owner_headers, &self.config.owner_host).await != Some(session) {
            return refusal(error(
                StatusCode::UNAUTHORIZED,
                "frontdoor:session-required",
            ));
        }
        match self
            .backend
            .call_owner(session, &owner_principal, operation, body)
            .await
        {
            Ok(value) => {
                // Production never enables the UI's development approval path.
                if contains_dev_bypass(&value) {
                    // MUTATION: no-dev-bypass
                    return refusal(error(StatusCode::BAD_GATEWAY, "frontdoor:backend-invalid"));
                }
                let mut response = json_response(value);
                if operation == Operation::LogoutEverywhereFinish {
                    self.tables.lock().expect("session lock").sessions.clear();
                    clear_owner_cookie(&mut response);
                }
                if matches!(
                    operation,
                    Operation::AuraRetained | Operation::AuraExport | Operation::BindingEnvelope
                ) {
                    response.headers_mut().insert(
                        header::CONTENT_DISPOSITION,
                        HeaderValue::from_static(if operation == Operation::BindingEnvelope {
                            "attachment; filename=\"aukora-envelope.json\""
                        } else if operation == Operation::AuraExport {
                            "attachment; filename=\"aukora-proof.json\""
                        } else {
                            "attachment; filename=\"aukora-head.json\""
                        }),
                    );
                }
                response
            }
            Err(err) => {
                if wrong_guess(&err) {
                    self.failed_guess(&principal);
                }
                refusal(err)
            }
        }
    }

    async fn json_body(&self, request: Request<Body>) -> Result<Value, ApiError> {
        if single(request.headers(), "content-type") != Some("application/json") {
            return Err(error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "frontdoor:json-required",
            ));
        }
        let bytes = to_bytes(request.into_body(), self.config.max_body_bytes)
            .await
            .map_err(|_| error(StatusCode::PAYLOAD_TOO_LARGE, "frontdoor:body-too-large"))?; // MUTATION: body-limit
        let parsed = canon::parse(&bytes)
            .map_err(|_| error(StatusCode::BAD_REQUEST, "frontdoor:body-invalid"))?; // MUTATION: strict-json
        let bytes = canon::canonical_json(&parsed)
            .map_err(|_| error(StatusCode::BAD_REQUEST, "frontdoor:body-invalid"))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| error(StatusCode::BAD_REQUEST, "frontdoor:body-invalid"))
    }

    pub async fn set_harness_token(&self, token: &str) -> Result<(), ApiError> {
        let socket = warmup::Socket::new(&self.config.guest_socket);
        #[cfg(test)]
        let socket = match self.warmup_connector.lock().unwrap().clone() {
            Some(connector) => warmup::Socket::with_connector(&self.config.guest_socket, connector),
            None => socket,
        };
        #[cfg(not(test))]
        let cookie = proxy::exchange_token(
            &self.config.guest_socket,
            &self.config.chat_host,
            token,
            self.config.request_timeout,
        )
        .await?;
        #[cfg(test)]
        let cookie = proxy::exchange_token_with_connection(
            socket.connect(),
            &self.config.chat_host,
            token,
            self.config.request_timeout,
        )
        .await?;
        let mut current = self.harness_cookie.lock().expect("harness cookie lock");
        // MUTATION: warmup-once
        if current.is_none() {
            let host = self.config.chat_host.clone();
            let session = cookie.clone();
            // MUTATION: warmup-background
            let task = tokio::spawn(async move {
                let _ = warmup::run(&socket, &host, session, warmup::Limits::default()).await;
            });
            *self.warmup_task.lock().expect("warmup task lock") = Some(task);
        }
        *current = Some(cookie);
        Ok(())
    }

    pub fn clear_harness_cookie(&self) {
        let mut cookie = self.harness_cookie.lock().expect("harness cookie lock");
        *cookie = None;
        if let Some(task) = self.warmup_task.lock().expect("warmup task lock").take() {
            // MUTATION: warmup-cancel
            task.abort();
        }
    }

    async fn chat_session(&self, headers: &HeaderMap) -> bool {
        let Some(token) = cookie_token(headers, CHAT_COOKIE) else {
            return false;
        };
        let key = digest(token);
        if self.backend.durable_sessions() {
            let Some(now) = timestamp_ms() else {
                return false;
            };
            return self
                .backend
                .chat_session_valid(key, now)
                .await
                .unwrap_or(false);
        }
        let tables = self.tables.lock().expect("chat session lock");
        tables.sessions.get(&key).is_some_and(|session| {
            session.host == self.config.chat_host
                && session.expires > Instant::now()
                && session.owner.is_some_and(|owner| {
                    tables.sessions.get(&owner).is_some_and(|parent| {
                        parent.host == self.config.owner_host && parent.expires > Instant::now()
                    })
                })
        })
    }

    async fn chat_exchange(&self, request: Request<Body>) -> Response {
        let body = match self.json_body(request).await {
            Ok(body) => body,
            Err(err) => return refusal(err),
        };
        let Some(ticket) = body.get("ticket").and_then(Value::as_str).filter(|ticket| {
            ticket.len() == 64
                && ticket
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) else {
            return refusal(ApiError::invalid_body());
        };
        if body.as_object().is_none_or(|fields| fields.len() != 1) {
            return refusal(ApiError::invalid_body());
        }
        let bound = matches!(self.backend.state().await,Ok(state) if state.state.is_bound());
        if !bound {
            return binding_required();
        }
        let mut bytes = [0; 32];
        if getrandom::fill(&mut bytes).is_err() {
            return refusal(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "frontdoor:entropy-unavailable",
            ));
        }
        let token = hex(&bytes);
        let ticket = self
            .tables
            .lock()
            .expect("chat ticket lock")
            .chat_tickets
            .remove(&digest(ticket));
        let Some(ticket) = ticket else {
            return refusal(error(
                StatusCode::FORBIDDEN,
                "frontdoor:chat-ticket-refused",
            ));
        };
        if ticket.expires <= Instant::now() {
            return refusal(error(
                StatusCode::FORBIDDEN,
                "frontdoor:chat-ticket-refused",
            ));
        }
        if self.backend.durable_sessions() {
            let Some(expires_at) = timestamp_ms()
                .and_then(|now| now.checked_add(self.config.session_lifetime.as_millis() as i64))
            else {
                return refusal(error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "frontdoor:clock-unavailable",
                ));
            };
            if let Err(err) = self
                .backend
                .create_chat_session(ticket.owner, digest(&token), expires_at)
                .await
            {
                return refusal(err);
            }
        } else {
            let mut tables = self.tables.lock().expect("chat session lock");
            let Some(parent) = tables.sessions.get(&ticket.owner).filter(|parent| {
                parent.host == self.config.owner_host && parent.expires > Instant::now()
            }) else {
                return refusal(error(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:session-required",
                ));
            };
            let expires = parent
                .expires
                .min(Instant::now() + self.config.session_lifetime);
            tables
                .sessions
                .retain(|_, row| row.expires > Instant::now());
            if tables
                .sessions
                .values()
                .filter(|row| row.host == self.config.chat_host)
                .count()
                >= MAX_CHAT_SESSIONS
            {
                return refusal(error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "frontdoor:chat-session-limit",
                ));
            }
            tables.sessions.insert(
                digest(&token),
                Session {
                    host: self.config.chat_host.clone(),
                    expires,
                    owner: Some(ticket.owner),
                },
            );
        }
        let mut response = json_response(json!({"ok":true}));
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{CHAT_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
                self.config.session_lifetime.as_secs()
            ))
            .expect("generated cookie"),
        );
        response
    }

    async fn signin(&self, request: Request<Body>, path: &str, ip: IpAddr) -> Response {
        let operation = if path == "/api/signin/start" {
            Operation::SigninStart
        } else {
            Operation::SigninFinish
        };
        let body = match self.json_body(request).await {
            Ok(body) => body,
            Err(err) => return refusal(err),
        };
        if let Err(err) = validate_operation(operation, &body) {
            return refusal(err);
        }
        let principal = format!("signin:{}", client_address(ip));
        let owner_principal = format!("owner:{}", self.config.node);
        let session = if operation == Operation::SigninFinish {
            let mut random = [0; 32];
            if getrandom::fill(&mut random).is_err() {
                return refusal(error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "frontdoor:entropy-unavailable",
                ));
            }
            let Some(expires_at) = timestamp_ms()
                .and_then(|at| at.checked_add(self.config.session_lifetime.as_millis() as i64))
            else {
                return refusal(error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "frontdoor:clock-unavailable",
                ));
            };
            Some((hex(&random), expires_at))
        } else {
            None
        };
        let result = if let Some((token, expires_at)) = &session {
            self.backend
                .signin_session(&owner_principal, body, digest(token), *expires_at)
                .await
        } else {
            self.backend.call(&owner_principal, operation, body).await
        };
        match result {
            Ok(value) => {
                if contains_dev_bypass(&value) {
                    return refusal(error(StatusCode::BAD_GATEWAY, "frontdoor:backend-invalid"));
                }
                let mut response = json_response(value);
                if let Some((token, _)) = session {
                    self.tables.lock().expect("session lock").sessions.insert(
                        digest(&token),
                        Session {
                            expires: Instant::now() + self.config.session_lifetime,
                            host: self.config.owner_host.clone(),
                            owner: None,
                        },
                    );
                    response.headers_mut().insert(header::SET_COOKIE,HeaderValue::from_str(&format!("{OWNER_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",self.config.session_lifetime.as_secs())).expect("generated cookie"));
                }
                response
            }
            Err(err) => {
                // A stranger's failures cannot reject a valid owner passkey.
                if wrong_guess(&err) && self.failed_guess(&principal) {
                    return refusal(error(
                        StatusCode::TOO_MANY_REQUESTS,
                        "frontdoor:guess-rate-limited",
                    ));
                }
                refusal(err)
            }
        }
    }

    async fn claim(&self, request: Request<Body>, ip: IpAddr) -> Response {
        let body = match self.json_body(request).await {
            Ok(body) => body,
            Err(err) => return refusal(err),
        };
        let Some(token) = body
            .get("token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 512)
        else {
            return refusal(error(StatusCode::BAD_REQUEST, "frontdoor:body-invalid"));
        };
        if body
            .as_object()
            .is_none_or(|fields| fields.keys().any(|key| key != "token" && key != "handover"))
        {
            return refusal(error(StatusCode::BAD_REQUEST, "frontdoor:body-invalid"));
        }
        let handover = match body.get("handover") {
            Some(Value::String(secret))
                if secret.len() == 64
                    && secret
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
            {
                Some(digest(secret))
            }
            None => None,
            _ => return refusal(error(StatusCode::BAD_REQUEST, "frontdoor:body-invalid")),
        };
        let mut random = [0_u8; 32];
        if getrandom::fill(&mut random).is_err() {
            return refusal(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "frontdoor:entropy-unavailable",
            ));
        }
        let session_token = hex(&random);
        // The durable backend spends before the cookie is issued; timeouts never unspend.
        let Some(expires_at) = timestamp_ms()
            .and_then(|at| at.checked_add(self.config.session_lifetime.as_millis() as i64))
        else {
            return refusal(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "frontdoor:clock-unavailable",
            ));
        };
        let consumed = if let Some(handover) = handover {
            self.backend
                .consume_invited_claim_session(
                    digest(token),
                    handover,
                    digest(&session_token),
                    expires_at,
                )
                .await
        } else {
            self.backend
                .consume_claim_session(digest(token), digest(&session_token), expires_at)
                .await
        };
        if let Err(err) = consumed {
            if wrong_guess(&err) && self.failed_guess(&format!("claim:{}", client_address(ip))) {
                // MUTATION: claim-principal
                return refusal(error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "frontdoor:guess-rate-limited",
                ));
            }
            return refusal(err);
        }
        let mut tables = self.tables.lock().expect("session lock");
        tables.sessions.insert(
            digest(&session_token),
            Session {
                expires: Instant::now() + self.config.session_lifetime,
                host: self.config.owner_host.clone(),
                owner: None,
            },
        );
        drop(tables);
        let mut response = json_response(json!({"ok": true, "state": "claim-open"}));
        let cookie = format!(
            "{OWNER_COOKIE}={session_token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
            self.config.session_lifetime.as_secs()
        ); // MUTATION: cookie-flags
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie).expect("generated cookie is ASCII"),
        );
        response
    }
}

async fn dispatch(State(frontdoor): State<Arc<Frontdoor>>, request: Request<Body>) -> Response {
    let chat = single(request.headers(), "host") == Some(frontdoor.config.chat_host.as_str());
    let mut response =
        match tokio::time::timeout(frontdoor.config.request_timeout, frontdoor.handle(request))
            .await
        {
            // MUTATION: request-timeout
            Ok(response) => response,
            Err(_) => refusal(error(
                StatusCode::REQUEST_TIMEOUT,
                "frontdoor:request-timeout",
            )),
        };
    let upgraded = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    let headers = response.headers_mut();
    if !upgraded {
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    let chat_origin = format!("https://{}", frontdoor.config.chat_host);
    let owner_policy = format!("{OWNER_CSP}; frame-ancestors {chat_origin}");
    let chat_policy = format!(
        "{CHAT_CSP}; frame-src 'self' https://{}",
        frontdoor.config.owner_host
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(if chat { &chat_policy } else { &owner_policy })
            .expect("validated hostname is ASCII"),
    ); // MUTATION: csp
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer")); // MUTATION: no-referrer
    if chat {
        headers.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
    } else {
        headers.remove("x-frame-options");
        let permissions = format!(
            "publickey-credentials-get=(self \"{chat_origin}\"), publickey-credentials-create=(self \"{chat_origin}\")"
        );
        headers.insert(
            "permissions-policy",
            HeaderValue::from_str(&permissions).expect("validated hostname is ASCII"),
        );
        headers.insert(
            "aukora-chat-origin",
            HeaderValue::from_str(&chat_origin).expect("validated hostname is ASCII"),
        );
    }
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn browser_navigation(request: &Request<Body>) -> bool {
    request.method() == Method::GET
        && single(request.headers(), "sec-fetch-mode") == Some("navigate")
        && (!request.headers().contains_key("sec-fetch-dest")
            || single(request.headers(), "sec-fetch-dest") == Some("document"))
        && single(request.headers(), "accept").is_some_and(|accept| {
            accept.split(',').any(|part| {
                let mut fields = part.split(';');
                fields
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"))
                    && fields.all(|field| {
                        let Some((key, value)) = field.trim().split_once('=') else {
                            return false;
                        };
                        !key.eq_ignore_ascii_case("q")
                            || value.parse::<f64>().is_ok_and(|q| q > 0.0 && q <= 1.0)
                    })
            })
        })
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    } // MUTATION: duplicate-header
    Some(value)
}

fn owner_token(headers: &HeaderMap) -> Option<&str> {
    cookie_token(headers, OWNER_COOKIE)
}

fn cookie_token<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie = single(headers, "cookie")?;
    let mut tokens = cookie.split(';').filter_map(|part| {
        let (found, value) = part.trim().split_once('=')?;
        (found == name).then_some(value)
    });
    let token = tokens.next()?;
    if tokens.next().is_some()
        || token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        // MUTATION: duplicate-cookie
        return None;
    }
    Some(token)
}

fn ambiguous_path(path: &str) -> bool {
    path.contains('%')
        || path.contains('\\')
        || path.contains("//")
        || path.split('/').any(|p| p == "." || p == "..")
}

fn secret_query(query: &str) -> bool {
    query.split('&').any(|part| {
        let key = part.split('=').next().unwrap_or_default();
        let mut decoded = Vec::new();
        let mut bytes = key.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let digit = |b: u8| char::from(b).to_digit(16).map(|n| n as u8);
                let Some(hi) = bytes.next().and_then(digit) else {
                    return true;
                };
                let Some(lo) = bytes.next().and_then(digit) else {
                    return true;
                };
                decoded.push(hi * 16 + lo);
            } else {
                decoded.push(byte);
            }
        }
        let key = String::from_utf8_lossy(&decoded).to_ascii_lowercase();
        matches!(
            key.as_str(),
            "claim"
                | "token"
                | "session"
                | "phrase"
                | "password"
                | "secret"
                | "api_key"
                | "authorization"
        ) || key.contains('%')
    })
}

fn bootstrap_route(method: &Method, path: &str) -> bool {
    *method == Method::POST
        && matches!(
            path,
            "/api/enrol/start"
                | "/api/enrol/finish"
                | "/api/binding/prepare"
                | "/api/binding/confirm"
                | "/api/binding/cancel"
        )
}

fn route(method: &Method, path: &str) -> Option<Operation> {
    use Operation::*;
    match (method.as_str(), path) {
        ("POST", "/api/enrol/start") => Some(EnrolStart),
        ("POST", "/api/enrol/finish") => Some(EnrolFinish),
        ("POST", "/api/binding/prepare") => Some(BindingPrepare),
        ("POST", "/api/binding/confirm") => Some(BindingConfirm),
        ("POST", "/api/binding/cancel") => Some(BindingCancel),
        ("POST", "/api/logout/everywhere") => Some(LogoutEverywhereStart),
        ("POST", "/api/logout/everywhere/confirm") => Some(LogoutEverywhereFinish),
        ("POST", "/api/binding/backup/start") => Some(BindingBackupStart),
        ("POST", "/api/binding/backup/finish") => Some(BindingBackupFinish),
        ("POST", "/api/binding/refresh") => Some(BindingRefresh),
        ("POST", "/api/binding/refresh/prepare") => Some(BindingRefreshPrepare),
        ("POST", "/api/binding/refresh/resume") => Some(BindingRefreshResume),
        ("POST", "/api/binding/refresh/confirm") => Some(BindingRefreshConfirm),
        ("POST", "/api/binding/refresh/cancel") => Some(BindingRefreshCancel),
        ("GET", "/api/approvals") => Some(Approvals),
        ("POST", "/api/approvals/challenge") => Some(ApprovalChallenge),
        ("POST", "/api/approvals/decide") => Some(ApprovalDecide),
        ("POST", "/api/approvals/despite/challenge") => Some(ApprovalDespiteChallenge),
        ("POST", "/api/approvals/despite/decide") => Some(ApprovalDespiteDecide),
        ("POST", "/api/release/retry") => Some(ReleaseRetry),
        ("POST", "/api/approvals/retire/challenge") => Some(ApprovalRetireChallenge),
        ("POST", "/api/approvals/retire") => Some(ApprovalRetire),
        ("POST", "/api/approvals/reconcile/challenge") => Some(ApprovalReconcileChallenge),
        ("POST", "/api/approvals/reconcile") => Some(ApprovalReconcile),
        ("GET", "/api/aura/head") => Some(AuraHead),
        ("GET", "/api/aura/recent") => Some(AuraRecent),
        ("GET", "/api/aura/retained") => Some(AuraRetained),
        ("GET", "/api/aura/export") => Some(AuraExport),
        ("GET", "/api/nostr") => Some(Nostr),
        ("GET", "/api/nostr/contacts") => Some(NostrContacts),
        ("POST", "/api/nostr/contacts/propose") => Some(NostrContactPropose),
        ("POST", "/api/nostr/send/propose") => Some(NostrSendPropose),
        ("GET", "/api/nostr/inbox") => Some(NostrInbox),
        ("GET", "/api/nostr/send/preview") => Some(NostrSendPreview),
        ("POST", "/api/memory/recall") => Some(MemoryRecall),
        ("POST", "/api/memory/demote") => Some(MemoryDemote),
        ("POST", "/api/signin/start") => Some(SigninStart),
        ("POST", "/api/signin/finish") => Some(SigninFinish),
        ("GET", "/api/broker") => Some(Broker),
        ("POST", "/api/broker/key/propose") => Some(BrokerKeyPropose),
        ("POST", "/api/broker/key") => Some(BrokerKeyRedeem),
        ("GET", "/api/slider") => Some(Slider),
        ("POST", "/api/slider/propose") => Some(SliderPropose),
        ("POST", "/api/broker/grant/propose") => Some(BrokerGrantPropose),
        ("GET", "/api/release") => Some(Release),
        ("POST", "/api/memory/permission/propose") => Some(MemoryPermissionPropose),
        ("GET", "/api/binding/envelope") => Some(BindingEnvelope),
        _ => None,
    }
}

fn query_body(operation: Operation, query: Option<&str>) -> Result<Value, ApiError> {
    if operation == Operation::NostrSendPreview {
        let id = query
            .and_then(|query| query.strip_prefix("id="))
            .filter(|id| {
                id.len() == 32
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or_else(|| error(StatusCode::BAD_REQUEST, "frontdoor:query-invalid"))?;
        return Ok(json!({"id":id}));
    }
    let key = match operation {
        Operation::AuraHead => "since",
        Operation::AuraRecent => "limit",
        _ => return Ok(json!({})),
    };
    let Some(query) = query else {
        return Ok(json!({}));
    };
    let Some(value) = query.strip_prefix(&format!("{key}=")) else {
        return Err(error(StatusCode::BAD_REQUEST, "frontdoor:query-invalid"));
    };
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(error(StatusCode::BAD_REQUEST, "frontdoor:query-invalid"));
    }
    let value = value
        .parse::<i64>()
        .ok()
        .filter(|n| *n <= canon::MAX_SAFE_INTEGER)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "frontdoor:query-invalid"))?;
    Ok(json!({key: value}))
}

fn sse_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}

fn contains_dev_bypass(value: &Value) -> bool {
    match value {
        Value::Object(fields) => {
            fields.contains_key("dev_bypass") || fields.values().any(contains_dev_bypass)
        }
        Value::Array(items) => items.iter().any(contains_dev_bypass),
        _ => false,
    }
}
fn guess_operation(op: Operation) -> bool {
    matches!(
        op,
        Operation::EnrolFinish
            | Operation::BindingConfirm
            | Operation::BindingRefreshPrepare
            | Operation::BindingRefreshResume
            | Operation::BindingRefreshConfirm
            | Operation::BindingBackupFinish
            | Operation::ApprovalDecide
            | Operation::ApprovalDespiteDecide
            | Operation::ApprovalRetire
            | Operation::ApprovalReconcile
    )
}
fn session_operation(op: Operation) -> bool {
    matches!(
        op,
        Operation::BindingBackupStart
            | Operation::BindingBackupFinish
            | Operation::BindingRefresh
            | Operation::BindingRefreshPrepare
            | Operation::BindingRefreshResume
            | Operation::BindingRefreshConfirm
            | Operation::BindingRefreshCancel
            | Operation::LogoutEverywhereStart
            | Operation::LogoutEverywhereFinish
    )
}
fn wrong_guess(err: &ApiError) -> bool {
    matches!(
        err.code,
        "aumlok:claim-unknown"
            | "aumlok:current-phrase"
            | "aumlok:word-mismatch"
            | "aumlok:attestation-refused"
            | "aumlok:assertion-refused"
    )
}
fn client_address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return IpAddr::V4(ip);
            }
            // IPv6 privacy addresses share their network's failure window.
            IpAddr::V6((u128::from(ip) & (u128::MAX << 64)).into())
        }
    }
}
fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn error(status: StatusCode, code: &'static str) -> ApiError {
    ApiError {
        status,
        code,
        position: None,
        expires_at: None,
    }
}
fn binding_required() -> Response {
    refusal(error(StatusCode::FORBIDDEN, "aumlok:binding-required"))
}
fn clear_owner_cookie(response: &mut Response) {
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-aukora-owner=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
}
fn refusal(err: ApiError) -> Response {
    let mut body = json!({"error": err.code});
    if let Some(position) = err.position {
        body["position"] = json!(position);
    }
    if let Some(expires_at) = err.expires_at {
        body["expires_at"] = json!(expires_at);
    }
    (err.status, axum::Json(body)).into_response()
}
fn json_response(value: Value) -> Response {
    let serialized = value.to_string();
    let bytes =
        match canon::parse(serialized.as_bytes()).and_then(|value| canon::canonical_json(&value)) {
            Ok(bytes) => bytes,
            Err(_) => return refusal(error(StatusCode::BAD_GATEWAY, "frontdoor:backend-invalid")),
        };
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

#[cfg(test)]
mod tests;

fn timestamp_ms() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
}
const CHAT_MANIFEST: &str =
    r#"{"name":"Aukora","short_name":"Aukora","start_url":"/","display":"standalone"}"#;
const CHAT_BOOTSTRAP: &str = r#"<!doctype html><meta charset="utf-8"><title>Aukora chat</title><p>Opening chat…</p><script>const ticket=new URLSearchParams(location.hash.slice(1)).get('ticket');history.replaceState(null,'',location.pathname);if(ticket&&/^[a-f0-9]{64}$/.test(ticket)){fetch('/api/chat/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket}),credentials:'same-origin'}).then(r=>{if(r.ok)location.replace('/');else document.querySelector('p').textContent='Chat access expired.'})}else document.querySelector('p').textContent='Open chat from the owner page.'</script>"#;
