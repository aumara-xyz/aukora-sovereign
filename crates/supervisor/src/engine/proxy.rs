// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine origin: `engine.<shell host>`, Caddy to `listen` on loopback, then to the harness's web listener over a
//! unix socket. Streaming in both directions (the harness's API is fetch plus server-sent events).
//!
//! What crosses, and what does not:
//! - In: a request on the engine host, from loopback, with one valid engine session cookie whose owner scope is still
//!   the node's binding and while the release floor still holds. Only an allowlist of request headers is forwarded;
//!   the browser's cookies never are. The harness gets its own cookie instead, obtained here by exchanging the
//!   launch token it printed inside the wall; the browser never sees that token or that cookie. A query naming
//!   `token` is refused (the harness's exchange is ours alone; Caddy also 404s it).
//! - Out: the harness's status, body and headers minus every `Set-Cookie` and CORS header, plus a frame and referrer
//!   policy: the engine's pages cannot frame or be framed, and cannot set cookies on the engine origin.
//!
//! - WebSocket: the harness client's live connection (`/api/remote.mux`, NODE.md O9) is the one upgrade forwarded,
//!   with the same admission as a request plus an Origin that must be exactly the engine origin; the frames are
//!   relayed and checked one by one (`socket.rs`: sizes, masking, no extensions), and the socket is closed when the
//!   session ends (sign-out, binding, release), when the engine stops, or after a minute without a frame. Any other
//!   upgrade (the web terminal's, which the composition removes) is refused.

use super::access::{self, ENTER_PREFIX};
use super::{refuse, socket, Engine};
use crate::host::{Host, ReleaseStanding};
use canon::Result;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::time::Duration;
use supervisor::ingress::BindingState;

type Body = BoxBody<Bytes, hyper::Error>;
const MAX_CONNECTIONS: usize = 64;
const ENDED: &str = "This engine session ended: you signed out of your node, or the owner binding or the approved release changed.\n";
const MAX_LAUNCH_FILE: u64 = 65_536;
const HEADER_DEADLINE: Duration = Duration::from_secs(10);
/// Request headers a browser may pass to the harness. Everything else (cookies first of all) stays here.
const FORWARD: &[&str] = &[
    "accept", "accept-encoding", "accept-language", "cache-control", "content-length", "content-type", "if-match",
    "if-modified-since", "if-none-match", "last-event-id", "origin", "pragma", "range", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site", "user-agent",
];
/// Response headers the harness may not set on the engine origin.
const DROP: &[&str] = &[
    "set-cookie", "set-cookie2", "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-headers", "access-control-allow-methods", "access-control-expose-headers",
    "strict-transport-security", "x-frame-options", "connection", "keep-alive", "transfer-encoding", "upgrade",
];

fn text(status: StatusCode, message: &'static str) -> Response<Body> {
    let mut response = Response::new(Full::new(Bytes::from_static(message.as_bytes())).map_err(|never| match never {}).boxed());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert("content-type", http::HeaderValue::from_static("text/plain; charset=utf-8"));
    headers.insert("cache-control", http::HeaderValue::from_static("no-store"));
    harden(headers);
    response
}

fn harden(headers: &mut http::HeaderMap) {
    // Added beside the harness's own policy: browsers enforce every CSP header they get, so this only narrows it.
    headers.append(
        "content-security-policy",
        http::HeaderValue::from_static("frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
    );
    // These take one value; a second header from the harness would make the browser ignore both (Grok review of
    // the node commit, part 3 #2), so ours replaces whatever the harness sent.
    for (name, value) in [
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        ("strict-transport-security", "max-age=31536000"),
        // No page on the engine origin may run a WebAuthn ceremony at all (Auma's review R6, verified live on the
        // rehearsal node 2026-10-18): the owner's passkey is already out of reach (its RP id is the owner host, which
        // is not a suffix of engine.<shell>: the browser answers SecurityError), but without this an engine page could
        // create and use a look-alike passkey of its own and stage a convincing fake "confirm your passkey" panel.
        (
            "permissions-policy",
            "publickey-credentials-get=(), publickey-credentials-create=(), identity-credentials-get=(), \
             otp-credentials=(), payment=()",
        ),
    ] {
        headers.insert(name, http::HeaderValue::from_static(value));
    }
}

/// Percent-decode one path segment once; `None` if an escape is malformed.
fn decode_segment(segment: &str) -> Option<Vec<u8>> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    Some(out)
}

/// A segment that is, or once decoded becomes, a dot segment, a separator, or another escape (double encoding).
fn unsafe_segment(segment: &str) -> bool {
    match decode_segment(segment) {
        None => true,
        Some(decoded) => {
            decoded == b"." || decoded == b".." || decoded.iter().any(|b| matches!(b, b'/' | b'\\' | b'%' | 0))
        }
    }
}

/// The path and query of a request the engine origin forwards: absolute, bounded, no dot segments, no `token`.
pub fn admit_target(uri: &http::Uri) -> Option<String> {
    let path = uri.path();
    if !path.starts_with('/')
        || path.len() > 4096
        || path.contains("//")
        || path.split('/').any(unsafe_segment)
        || path.bytes().any(|b| b.is_ascii_control() || b == b'\\')
    {
        return None;
    }
    match uri.query() {
        None => Some(path.to_owned()),
        Some(query) => {
            let token = query.split('&').any(|pair| {
                // Any parameter whose name mentions a token, in any case or percent-encoding of its letters.
                let name = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
                name.contains("token") || name.contains('%')
            });
            (!token && query.len() <= 4096 && !query.bytes().any(|b| b.is_ascii_control())).then(|| format!("{path}?{query}"))
        }
    }
}

/// The launch token in the harness's start-up line (`http://127.0.0.1:PORT/?token=<43 base64url>`). The file is
/// written inside the wall, so it is engine-controlled: the worst a lie does is make the exchange fail.
pub fn launch_token(text: &str) -> Option<String> {
    let start = text.find("?token=")? + "?token=".len();
    let token: String = text[start..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    (token.len() == 43).then_some(token)
}

/// The harness's session cookie from its exchange reply: `dsh-auth-<base64url>=<v1....>`, name and value only.
pub fn harness_cookie(set_cookie: &str) -> Option<String> {
    let pair = set_cookie.split(';').next()?.trim();
    let (name, value) = pair.split_once('=')?;
    let safe = |text: &str, extra: &[u8]| !text.is_empty() && text.len() <= 2048 && text.bytes().all(|b| b.is_ascii_alphanumeric() || extra.contains(&b));
    (name.starts_with("dsh-auth-") && safe(name, b"-_") && safe(value, b"-_.")).then(|| format!("{name}={value}"))
}

fn read_launch_file(engine: &Engine) -> Option<String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(&engine.config.launch_file)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_LAUNCH_FILE).read_to_string(&mut text).ok()?;
    Some(text)
}

async fn send(engine: &Engine, request: Request<Body>) -> Result<Response<Incoming>> {
    let stream = tokio::net::UnixStream::connect(&engine.config.web_socket).await.map_err(|_| refuse("engine-unavailable"))?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|_| refuse("engine-unavailable"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender.send_request(request).await.map_err(|_| refuse("engine-unavailable"))
}

/// Exchange the harness's launch token for its cookie, once per harness process.
async fn harness_session(engine: &Engine) -> Result<String> {
    if let Some(cookie) = engine.dsh_cookie.lock().map_err(|_| refuse("engine-state"))?.clone() {
        return Ok(cookie);
    }
    let token = read_launch_file(engine).as_deref().and_then(launch_token).ok_or_else(|| refuse("engine-starting"))?;
    let request = Request::builder()
        .method("GET")
        .uri(format!("/?token={token}"))
        .header("host", &engine.config.host)
        .body(Empty::new().map_err(|never| match never {}).boxed())
        .map_err(|_| refuse("engine-exchange"))?;
    let reply = send(engine, request).await?;
    let cookie = reply
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(harness_cookie)
        .ok_or_else(|| refuse("engine-exchange"))?;
    *engine.dsh_cookie.lock().map_err(|_| refuse("engine-state"))? = Some(cookie.clone());
    Ok(cookie)
}

/// The clock, or nothing: a clock that cannot be read refuses the request (Grok review, part 3 #3).
pub(super) fn now() -> Option<u64> {
    crate::host::now().ok().filter(|now| *now > 0)
}

async fn handle(host: Arc<Host>, engine: Arc<Engine>, peer: std::net::SocketAddr, request: Request<Incoming>) -> Response<Body> {
    if !peer.ip().is_loopback() {
        return text(StatusCode::FORBIDDEN, "not here\n");
    }
    let host_header = request.headers().get("host").and_then(|value| value.to_str().ok()).unwrap_or("");
    if host_header != engine.config.host || request.headers().get_all("host").iter().count() != 1 {
        return text(StatusCode::MISDIRECTED_REQUEST, "wrong host\n");
    }
    let upgrade = socket::asks_upgrade(request.headers());
    let Some(target) = admit_target(request.uri()) else { return text(StatusCode::NOT_FOUND, "not found\n") };
    if upgrade {
        if let Err(reason) = socket::admit_upgrade(request.method(), request.headers(), &target, &engine.config.host) {
            eprintln!("engine: WebSocket upgrade refused: {reason:?}");
            return text(reason.status(), reason.message());
        }
    }
    // The browser asks for a service worker's script with `Service-Worker: script`. None is ever served here, so no
    // engine page can install one to watch the owner's navigations (and read a ticket in flight; Grok review, part 4 #1).
    if request.headers().contains_key("service-worker") {
        return text(StatusCode::FORBIDDEN, "service workers are not allowed on the engine origin\n");
    }
    let Some(now) = now() else { return text(StatusCode::SERVICE_UNAVAILABLE, "clock unavailable\n") };
    let lifetime = engine.config.session_hours * 3_600_000;
    if let Some(ticket) = target.strip_prefix(ENTER_PREFIX) {
        if upgrade || request.method() != http::Method::GET || !top_level_navigation(request.headers()) {
            return text(StatusCode::FORBIDDEN, "Open the engine from your node (https://<your node>/engine/open).\n");
        }
        let redeemed = engine.access.lock().map_err(|_| refuse("engine-state")).and_then(|mut access| access.redeem(ticket, now, lifetime));
        return match redeemed {
            Ok((bearer, _, expires)) => {
                let mut response = text(StatusCode::SEE_OTHER, "\n");
                response.headers_mut().insert("location", http::HeaderValue::from_static("/"));
                // The cookie lasts no longer than the session, which lasts no longer than its shell session.
                if let Ok(cookie) = http::HeaderValue::from_str(&access::set_cookie(&bearer, expires.saturating_sub(now))) {
                    response.headers_mut().insert("set-cookie", cookie);
                }
                response
            }
            Err(_) => text(StatusCode::FORBIDDEN, "This link was already used or has expired. Open the engine from your node again.\n"),
        };
    }
    let cookies: Vec<&str> = request.headers().get_all("cookie").iter().filter_map(|value| value.to_str().ok()).collect();
    let bearer = access::bearer_from(&cookies);
    let lookup = match (bearer.as_deref(), engine.access.lock()) {
        (Some(bearer), Ok(mut access)) => access.lookup(bearer, now),
        _ => access::Lookup::Unknown,
    };
    let grant = match lookup {
        access::Lookup::Live(grant) => grant,
        access::Lookup::Ended => return text(StatusCode::FORBIDDEN, ENDED),
        access::Lookup::Unknown => {
            return text(StatusCode::UNAUTHORIZED, "Open the engine from your node (https://<your node>/engine/open).\n")
        }
    };
    match still_admitted(&host, &grant, now).await {
        Admitted::Yes => {}
        Admitted::Unknown => {
            // The floor could not be read just now: refuse this request, keep the session (NODE.md O11).
            return text(StatusCode::SERVICE_UNAVAILABLE, "Your node is busy for a moment. Try again.\n");
        }
        Admitted::Ended => {
            if let (Some(bearer), Ok(mut access)) = (bearer.as_deref(), engine.access.lock()) {
                access.end(bearer);
            }
            return text(StatusCode::FORBIDDEN, ENDED);
        }
        Admitted::ShellEnded => {
            if let Ok(mut access) = engine.access.lock() {
                access.end_shell(grant.shell);
            }
            return text(StatusCode::FORBIDDEN, ENDED);
        }
    }
    if upgrade {
        let bearer = bearer.unwrap_or_default();
        return websocket(host, engine, request, &target, grant, bearer).await;
    }
    if target == MODEL_KEY_STATUS {
        return model_key_status(&host, request.method(), request.headers()).await;
    }
    relay(&engine, request, &target).await
}

/// The Models row's read of the owner's DeepSeek key (NODE.md section 7): answered here, by the supervisor, for an
/// admitted engine session (the owner's bound scope, re-checked above). The engine process never sees this request;
/// engine-served script on this origin can read the reply (and could draw any status it likes), so the reply is
/// `{"state"}` only: never the key, any character of it, its digest or its fingerprint (O15). A GET changes nothing.
pub const MODEL_KEY_STATUS: &str = "/.aukora/model-key";

async fn model_key_status(host: &Host, method: &http::Method, headers: &http::HeaderMap) -> Response<Body> {
    if !status_read_admitted(method, headers) {
        return text(StatusCode::FORBIDDEN, "not here\n");
    }
    status_reply(host.model_key_status().await)
}

/// A read for the page itself: a GET from the engine origin's own script (`Sec-Fetch-Site: same-origin`, or no fetch
/// metadata at all). A sibling origin's request carries the SameSite=Strict cookie too, but is refused here.
fn status_read_admitted(method: &http::Method, headers: &http::HeaderMap) -> bool {
    let mut sites = headers.get_all("sec-fetch-site").iter();
    let same_origin = sites.next().is_none_or(|site| site.as_bytes() == b"same-origin") && sites.next().is_none();
    method == http::Method::GET && same_origin
}

fn status_reply(status: Option<Result<crate::model_broker::KeyStatus>>) -> Response<Body> {
    match status {
        None => text(StatusCode::NOT_FOUND, "This node has no model broker.\n"),
        Some(Err(_)) => text(StatusCode::SERVICE_UNAVAILABLE, "Your node is busy for a moment. Try again.\n"),
        Some(Ok(status)) => json(&status.to_json()),
    }
}

fn json(body: &str) -> Response<Body> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_owned())).map_err(|never| match never {}).boxed());
    let headers = response.headers_mut();
    headers.insert("content-type", http::HeaderValue::from_static("application/json"));
    headers.insert("cache-control", http::HeaderValue::from_static("no-store"));
    harden(headers);
    response
}

/// Forward an admitted WebSocket upgrade: the harness must switch protocols first (with its own cookie and the
/// browser's key, no extension), then the browser gets the 101 and the two upgraded streams are spliced with every
/// frame checked (`socket::splice`). The session is re-checked while the socket is open.
async fn websocket(
    host: Arc<Host>,
    engine: Arc<Engine>,
    mut request: Request<Incoming>,
    target: &str,
    grant: access::Grant,
    bearer: String,
) -> Response<Body> {
    if !engine.is_running() {
        return text(StatusCode::SERVICE_UNAVAILABLE, "The engine is starting or stopped. Try again in a moment.\n");
    }
    let Ok(slot) = engine.sockets.clone().try_acquire_owned() else {
        return text(StatusCode::SERVICE_UNAVAILABLE, "Too many open engine connections.\n");
    };
    let Ok(harness) = harness_session(&engine).await else {
        return text(StatusCode::SERVICE_UNAVAILABLE, "The engine is starting or stopped. Try again in a moment.\n");
    };
    let mut forward = Request::builder().method("GET").uri(target);
    for name in FORWARD.iter().filter(|name| **name != "content-length") {
        for value in request.headers().get_all(*name) {
            forward = forward.header(*name, value);
        }
    }
    for name in ["sec-websocket-key", "sec-websocket-version"] {
        if let Some(value) = request.headers().get(name) {
            forward = forward.header(name, value);
        }
    }
    let Ok(forward) = forward
        .header("host", &engine.config.host)
        .header("cookie", &harness)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .body::<Body>(Empty::new().map_err(|never| match never {}).boxed())
    else {
        return text(StatusCode::BAD_REQUEST, "\n");
    };
    let Ok(stream) = tokio::net::UnixStream::connect(&engine.config.web_socket).await else {
        return text(StatusCode::BAD_GATEWAY, "The engine did not answer.\n");
    };
    let Ok((mut sender, connection)) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await else {
        return text(StatusCode::BAD_GATEWAY, "The engine did not answer.\n");
    };
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let reply = match tokio::time::timeout(HEADER_DEADLINE, sender.send_request(forward)).await {
        Ok(Ok(reply)) => reply,
        _ => return text(StatusCode::BAD_GATEWAY, "The engine did not answer.\n"),
    };
    if reply.status() == StatusCode::UNAUTHORIZED {
        // A restarted harness: exchange again on the next request.
        if let Ok(mut cookie) = engine.dsh_cookie.lock() {
            *cookie = None;
        }
    }
    let Some(accept) = socket::switched(reply.status(), reply.headers()) else {
        eprintln!("engine: the harness did not switch protocols (HTTP {})", reply.status().as_u16());
        return text(StatusCode::BAD_GATEWAY, "The engine refused the live connection.\n");
    };
    let harness_side = hyper::upgrade::on(reply);
    let browser_side = hyper::upgrade::on(&mut request);
    let watch = socket::Watch { host, engine: engine.clone(), grant, bearer };
    tokio::spawn(async move {
        let _slot = slot;
        if let (Ok(browser), Ok(harness)) = (browser_side.await, harness_side.await) {
            socket::splice(TokioIo::new(browser), TokioIo::new(harness), watch).await;
        }
    });
    switching(accept)
}

/// The browser's 101: hardened like every other engine-origin reply (Codex review of node/pre-launch: it carried no
/// Permissions-Policy), then the upgrade's own headers.
fn switching(accept: http::HeaderValue) -> Response<Body> {
    let mut response: Response<Body> = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let headers = response.headers_mut();
    harden(headers);
    headers.insert("upgrade", http::HeaderValue::from_static("websocket"));
    headers.insert("connection", http::HeaderValue::from_static("Upgrade"));
    headers.insert("sec-websocket-accept", accept);
    response
}

/// Whether an engine session may still be served.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Admitted {
    Yes,
    /// The binding changed or the owner's release approval is gone: the session ends.
    Ended,
    /// The shell session it was minted from ended (signed out, expired, revoked, a new owner epoch): every engine
    /// session from it ends (O12).
    ShellEnded,
    /// The release floor could not be read just now: this request is refused, the session stays.
    Unknown,
}

/// Re-checked on every request: the owner scope is still the node's binding, the shell session that minted the engine
/// session is still live, and the running release is the one the owner approved. A floor or session store that cannot
/// be read is tried again briefly and is never taken for an answer.
pub(super) async fn still_admitted(host: &Host, grant: &access::Grant, now: u64) -> Admitted {
    if !matches!(host.ledger.binding(), Ok(BindingState::Bound(bound)) if bound == grant.scope) {
        return Admitted::Ended;
    }
    match host.shell_session_live(grant.shell, grant.scope, now) {
        Ok(true) => {}
        Ok(false) => return Admitted::ShellEnded,
        Err(_) => return Admitted::Unknown,
    }
    for attempt in 0..3 {
        match host.release_standing() {
            ReleaseStanding::Approved => return Admitted::Yes,
            ReleaseStanding::NotApproved => return Admitted::Ended,
            ReleaseStanding::Unknown if attempt < 2 => tokio::time::sleep(Duration::from_millis(100)).await,
            ReleaseStanding::Unknown => {}
        }
    }
    Admitted::Unknown
}

/// A ticket is spent only by the owner's own top-level navigation: not by a fetch, a frame or a worker that some page
/// on this origin started.
fn top_level_navigation(headers: &http::HeaderMap) -> bool {
    let one = |name: &str, want: &str| {
        let mut values = headers.get_all(name).iter();
        values.next().is_some_and(|value| value.as_bytes() == want.as_bytes()) && values.next().is_none()
    };
    one("sec-fetch-mode", "navigate") && one("sec-fetch-dest", "document")
}

/// Forward one admitted request to the harness with the harness's own cookie and only the allowlisted headers, and
/// return its reply without cookies, CORS or framing permission.
async fn relay<B>(engine: &Engine, request: Request<B>, target: &str) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    if !engine.is_running() {
        return text(StatusCode::SERVICE_UNAVAILABLE, "The engine is starting or stopped. Try again in a moment.\n");
    }
    let harness = match harness_session(engine).await {
        Ok(cookie) => cookie,
        Err(_) => return text(StatusCode::SERVICE_UNAVAILABLE, "The engine is starting or stopped. Try again in a moment.\n"),
    };
    let (parts, body) = request.into_parts();
    let mut forward = Request::builder().method(parts.method.clone()).uri(target);
    for name in FORWARD {
        for value in parts.headers.get_all(*name) {
            forward = forward.header(*name, value);
        }
    }
    let Ok(forward) = forward.header("host", &engine.config.host).header("cookie", &harness).body(body.boxed()) else {
        return text(StatusCode::BAD_REQUEST, "\n");
    };
    match send(engine, forward).await {
        Ok(reply) => {
            if reply.status() == StatusCode::UNAUTHORIZED {
                // A restarted harness has a new launch token and a new secret: exchange again on the next request.
                if let Ok(mut cookie) = engine.dsh_cookie.lock() {
                    *cookie = None;
                }
            }
            let (mut parts, body) = reply.into_parts();
            for name in DROP {
                parts.headers.remove(*name);
            }
            harden(&mut parts.headers);
            Response::from_parts(parts, body.boxed())
        }
        Err(_) => text(StatusCode::BAD_GATEWAY, "The engine did not answer.\n"),
    }
}

pub async fn serve(host: Arc<Host>, engine: Arc<Engine>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(engine.config.listen).await.map_err(|_| refuse("engine-listen"))?;
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    eprintln!("engine: origin https://{} served on {}", engine.config.host, engine.config.listen);
    loop {
        let Ok((stream, peer)) = listener.accept().await else { continue };
        let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
        let (host, engine) = (host.clone(), engine.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let service = hyper::service::service_fn(move |request| {
                let (host, engine) = (host.clone(), engine.clone());
                async move { Ok::<_, std::convert::Infallible>(handle(host, engine, peer, request).await) }
            });
            let mut server = hyper::server::conn::http1::Builder::new();
            server.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(HEADER_DEADLINE).max_buf_size(64 * 1024);
            // Upgrades: the one WebSocket route is answered 101 and spliced (socket.rs); the slot is held until then.
            let _ = server.serve_connection(TokioIo::new(stream), service).with_upgrades().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_paths_without_a_token_are_forwarded() {
        let uri = |text: &str| text.parse::<http::Uri>().unwrap();
        assert_eq!(admit_target(&uri("/api/x?a=1")).as_deref(), Some("/api/x?a=1"));
        assert_eq!(admit_target(&uri("/")).as_deref(), Some("/"));
        assert_eq!(admit_target(&uri("/files/a%20b.txt")).as_deref(), Some("/files/a%20b.txt"));
        for bad in [
            "/?token=abc", "/?a=1&token=x", "/?TOKEN=x", "/a/../b", "/a//b", "/%2e%2e/x", "/?x_token=1",
            "/%2e%2e%2f%2e%2e%2frun/aukora-engine/io/launch-url", "/%2E%2e/x", "/.%2E/x", "/%2e./x", "/a%2fb",
            "/a%5cb", "/%252e%252e/x", "/a%zz", "/a%2", "/%00",
        ] {
            assert_eq!(admit_target(&uri(bad)), None, "{bad}");
        }
    }

    #[test]
    fn the_launch_token_and_the_harness_cookie_are_read_strictly() {
        let token = "A".repeat(43);
        assert_eq!(launch_token(&format!("DeepSeek Harness at http://127.0.0.1:3080/?token={token}\n")), Some(token.clone()));
        assert_eq!(launch_token("http://127.0.0.1:3080/?token=short"), None);
        assert_eq!(launch_token("nothing here"), None);
        let cookie = "dsh-auth-AbC_d-1=v1.eyJ2Ijox.sig_-x; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict";
        assert_eq!(harness_cookie(cookie).as_deref(), Some("dsh-auth-AbC_d-1=v1.eyJ2Ijox.sig_-x"));
        assert_eq!(harness_cookie("other=1; Path=/"), None);
        assert_eq!(harness_cookie("dsh-auth-x=a b"), None);
        assert_eq!(harness_cookie("dsh-auth-x=a\r\nSet-Cookie: y=1"), None);
    }

    fn engine_at(dir: &std::path::Path) -> Engine {
        Engine {
            config: super::super::EngineConfig {
                v: 1,
                plugin_root: dir.join("plugins"),
                control_dir: dir.join("ctl"),
                web_socket: dir.join("web.sock"),
                launch_file: dir.join("launch-url"),
                host: "engine.n1.sslip.io".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                session_hours: 1,
            },
            access: std::sync::Mutex::new(access::Access::default()),
            dsh_cookie: std::sync::Mutex::new(None),
            status: std::sync::Mutex::new("running"),
            sockets: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    /// A stand-in for the harness's web listener: exchanges the launch token for a cookie, then serves only requests
    /// that carry exactly that cookie and nothing of the browser's; it also tries to set a cookie of its own.
    async fn fake_harness(socket: std::path::PathBuf, token: String) {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let token = token.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let token = token.clone();
                    async move {
                        let cookie = request.headers().get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
                        let host = request.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
                        let mut reply = Response::builder();
                        let body = if request.uri() == &*format!("/?token={token}") {
                            reply = reply.status(303).header("set-cookie", "dsh-auth-abc=v1.body.sig; Max-Age=60; Path=/; HttpOnly");
                            String::new()
                        } else if cookie == "dsh-auth-abc=v1.body.sig" && host == "engine.n1.sslip.io" {
                            reply = reply.status(200).header("set-cookie", "__Host-aukora-engine=forged").header("access-control-allow-origin", "*");
                            format!("ok {}", request.uri())
                        } else {
                            reply = reply.status(401);
                            format!("refused cookie={cookie}")
                        };
                        Ok::<_, std::convert::Infallible>(reply.body(Full::new(Bytes::from(body))).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
            });
        }
    }

    #[tokio::test]
    async fn the_harness_gets_its_own_cookie_never_the_browsers_and_cannot_set_one_back() {
        let dir = std::env::temp_dir().join(format!("aukora-engine-proxy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let engine = engine_at(&dir);
        let token = "T".repeat(43);
        tokio::spawn(fake_harness(dir.join("web.sock"), token.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let browser = || {
            Request::builder()
                .uri("/api/x")
                .header("cookie", "__Host-aukora-engine=secret-session; __Host-aukora-shell=shell-session")
                .header("authorization", "Bearer nope")
                .header("accept", "application/json")
                .body(Empty::<Bytes>::new().map_err(|never| match never {}))
                .unwrap()
        };
        // Before the harness printed its launch line: starting.
        assert_eq!(relay(&engine, browser(), "/api/x").await.status(), StatusCode::SERVICE_UNAVAILABLE);
        std::fs::write(dir.join("launch-url"), format!("dsh web: https://engine.n1.sslip.io/?token={token}\n")).unwrap();
        let reply = relay(&engine, browser(), "/api/x").await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert!(reply.headers().get("set-cookie").is_none() && reply.headers().get("access-control-allow-origin").is_none());
        assert_eq!(reply.headers().get("x-frame-options").unwrap(), "DENY");
        assert!(reply.headers().get("permissions-policy").unwrap().to_str().unwrap().contains("publickey-credentials-get=()"));
        let body = reply.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok /api/x");
        // A harness that forgets the cookie (restarted) answers 401 once; the next request exchanges again.
        *engine.dsh_cookie.lock().unwrap() = Some("dsh-auth-abc=stale".into());
        assert_eq!(relay(&engine, browser(), "/api/x").await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(relay(&engine, browser(), "/api/x").await.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_websocket_switch_is_hardened_too() {
        let reply = switching(http::HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert_eq!(reply.status(), StatusCode::SWITCHING_PROTOCOLS);
        let headers = reply.headers();
        assert!(headers.get("permissions-policy").unwrap().to_str().unwrap().contains("publickey-credentials-create=()"));
        assert_eq!(headers.get("upgrade").unwrap(), "websocket");
        assert_eq!(headers.get("sec-websocket-accept").unwrap(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn responses_cannot_set_cookies_or_be_framed() {
        let mut headers = http::HeaderMap::new();
        headers.insert("set-cookie", http::HeaderValue::from_static("__Host-aukora-engine=evil"));
        headers.insert("access-control-allow-origin", http::HeaderValue::from_static("*"));
        for name in DROP {
            headers.remove(*name);
        }
        headers.insert("cross-origin-opener-policy", http::HeaderValue::from_static("unsafe-none"));
        headers.insert("referrer-policy", http::HeaderValue::from_static("unsafe-url"));
        headers.insert("content-security-policy", http::HeaderValue::from_static("script-src 'self'"));
        headers.insert("permissions-policy", http::HeaderValue::from_static("publickey-credentials-get=*"));
        harden(&mut headers);
        // The harness cannot re-enable WebAuthn on its origin: ours is the only Permissions-Policy, and it denies both.
        let policy = headers.get_all("permissions-policy").iter().map(|v| v.to_str().unwrap()).collect::<Vec<_>>();
        assert_eq!(policy.len(), 1);
        assert!(policy[0].contains("publickey-credentials-get=()") && policy[0].contains("publickey-credentials-create=()"));
        assert!(headers.get("set-cookie").is_none() && headers.get("access-control-allow-origin").is_none());
        // One value each for the single-valued policies; the harness's CSP stays and ours is added beside it.
        assert_eq!(headers.get_all("cross-origin-opener-policy").iter().collect::<Vec<_>>(), ["same-origin"]);
        assert_eq!(headers.get_all("referrer-policy").iter().collect::<Vec<_>>(), ["no-referrer"]);
        assert_eq!(headers.get_all("content-security-policy").iter().count(), 2);
        let navigate = |mode: &'static str, dest: &'static str| {
            let mut headers = http::HeaderMap::new();
            headers.insert("sec-fetch-mode", http::HeaderValue::from_static(mode));
            headers.insert("sec-fetch-dest", http::HeaderValue::from_static(dest));
            top_level_navigation(&headers)
        };
        assert!(navigate("navigate", "document"));
        assert!(!navigate("cors", "empty") && !navigate("navigate", "iframe") && !top_level_navigation(&http::HeaderMap::new()));
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert!(headers.get_all("content-security-policy").iter().any(|v| v.to_str().unwrap().contains("frame-ancestors 'none'")));
        assert!(!FORWARD.contains(&"cookie") && !FORWARD.contains(&"authorization"));
    }

    #[tokio::test]
    async fn the_key_status_is_a_same_origin_get_with_state_only_and_hardened() {
        use crate::model_broker::KeyStatus;
        let headers = |site: Option<&'static str>| {
            let mut headers = http::HeaderMap::new();
            if let Some(site) = site {
                headers.append("sec-fetch-site", http::HeaderValue::from_static(site));
            }
            headers
        };
        assert!(status_read_admitted(&http::Method::GET, &headers(Some("same-origin"))));
        assert!(status_read_admitted(&http::Method::GET, &headers(None)));
        for site in ["same-site", "cross-site", "none"] {
            assert!(!status_read_admitted(&http::Method::GET, &headers(Some(site))), "{site}");
        }
        assert!(!status_read_admitted(&http::Method::POST, &headers(Some("same-origin"))));
        let mut two = headers(Some("same-origin"));
        two.append("sec-fetch-site", http::HeaderValue::from_static("same-origin"));
        assert!(!status_read_admitted(&http::Method::GET, &two));
        let reply = status_reply(Some(Ok(KeyStatus::Approved)));
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers().get("content-type").unwrap(), "application/json");
        assert_eq!(reply.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(reply.headers().get("x-frame-options").unwrap(), "DENY");
        assert!(reply.headers().get("access-control-allow-origin").is_none());
        let body = reply.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], br#"{"state":"approved"}"#);
        assert_eq!(status_reply(None).status(), StatusCode::NOT_FOUND);
        assert_eq!(status_reply(Some(Err(refuse("x")))).status(), StatusCode::SERVICE_UNAVAILABLE);
        // The route is the proxy's own: a path the harness would otherwise be asked for, never relayed.
        assert_eq!(admit_target(&"/.aukora/model-key".parse::<http::Uri>().unwrap()).as_deref(), Some(MODEL_KEY_STATUS));
    }
}
