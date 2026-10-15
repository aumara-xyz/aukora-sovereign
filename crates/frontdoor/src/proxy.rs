// SPDX-License-Identifier: AGPL-3.0-or-later

use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Uri};
use axum::response::Response;
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::time::{timeout_at, Instant, Sleep};

#[cfg(test)]
pub(crate) async fn proxy(
    request: Request<Body>,
    socket: &Path,
    timeout: Duration,
    max_body: usize,
) -> Response {
    proxy_with_connection(request, UnixStream::connect(socket), timeout, max_body).await
}

pub(crate) async fn proxy_authenticated(
    request: Request<Body>,
    connector: impl Future<Output = io::Result<UnixStream>>,
    timeout: Duration,
    max_body: usize,
    cookie: HeaderValue,
) -> Response {
    proxy_with_cookie(request, connector, timeout, max_body, Some(cookie)).await
}

#[cfg(test)]
async fn proxy_with_connection(
    request: Request<Body>,
    connector: impl Future<Output = io::Result<UnixStream>>,
    timeout: Duration,
    max_body: usize,
) -> Response {
    proxy_with_cookie(request, connector, timeout, max_body, None).await
}

async fn proxy_with_cookie(
    mut request: Request<Body>,
    connector: impl Future<Output = io::Result<UnixStream>>,
    timeout: Duration,
    max_body: usize,
    cookie: Option<HeaderValue>,
) -> Response {
    // MUTATION: proxy-owner-route
    if owner_route(request.uri().path()) {
        return refusal(StatusCode::NOT_FOUND, "frontdoor:unknown-route");
    }

    let websocket = websocket_headers(request.headers());
    let downstream_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    let lease = request
        .extensions()
        .get::<crate::ConnectionLease>()
        .cloned();
    let deadline = Instant::now() + timeout;
    let (mut parts, body) = request.into_parts();
    // MUTATION: proxy-body-limit
    let bytes = match timeout_at(deadline, to_bytes(body, max_body)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return refusal(StatusCode::PAYLOAD_TOO_LARGE, "frontdoor:body-too-large"),
        Err(_) => return refusal(StatusCode::GATEWAY_TIMEOUT, "frontdoor:request-timeout"),
    };
    strip_request_headers(&mut parts.headers, websocket);
    if let Some(cookie) = cookie {
        parts.headers.insert(header::COOKIE, cookie);
    }
    parts.headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).expect("body length is a decimal integer"),
    );
    parts.uri = match Uri::builder()
        .path_and_query(
            parts
                .uri
                .path_and_query()
                .cloned()
                .unwrap_or_else(|| axum::http::uri::PathAndQuery::from_static("/")),
        )
        .build()
    {
        Ok(uri) => uri,
        Err(_) => return refusal(StatusCode::BAD_REQUEST, "frontdoor:invalid-request"),
    };
    parts.version = axum::http::Version::HTTP_11;
    let request = Request::from_parts(parts, Body::from(bytes));
    let exchange = async {
        let stream = connector.await.map_err(|_| ())?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| ())?;
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        sender.send_request(request).await.map_err(|_| ())
    };
    // MUTATION: proxy-request-timeout
    let mut response = match timeout_at(deadline, exchange).await {
        Ok(Ok(response)) => response,
        Ok(Err(())) => return refusal(StatusCode::BAD_GATEWAY, "frontdoor:guest-unavailable"),
        Err(_) => return refusal(StatusCode::GATEWAY_TIMEOUT, "frontdoor:request-timeout"),
    };

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(downstream_upgrade) = downstream_upgrade else {
            return refusal(StatusCode::BAD_GATEWAY, "frontdoor:guest-response-refused");
        };
        if !websocket_headers(response.headers()) {
            return refusal(StatusCode::BAD_GATEWAY, "frontdoor:guest-response-refused");
        }
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        let (mut parts, _) = response.into_parts();
        strip_response_headers(&mut parts.headers, true);
        tokio::spawn(async move {
            // MUTATION: proxy-websocket-lease
            let _lease = lease;
            if let (Ok(downstream), Ok(upstream)) =
                tokio::join!(downstream_upgrade, upstream_upgrade)
            {
                let mut downstream = IdleIo::new(TokioIo::new(downstream), timeout);
                let mut upstream = IdleIo::new(TokioIo::new(upstream), timeout);
                let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
            }
        });
        return Response::from_parts(parts, Body::empty());
    }

    let (mut parts, body) = response.into_parts();
    strip_response_headers(&mut parts.headers, false);
    Response::from_parts(parts, Body::new(IdleBody::new(body, timeout)))
}

pub(crate) fn owner_route(path: &str) -> bool {
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let Some(high) = bytes.next().and_then(hex_digit) else {
                return true;
            };
            let Some(low) = bytes.next().and_then(hex_digit) else {
                return true;
            };
            decoded.push(high * 16 + low);
        } else {
            decoded.push(byte);
        }
    }
    let Ok(path) = std::str::from_utf8(&decoded) else {
        return true;
    };
    if path.contains(['\\', '%'])
        || path.contains("//")
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
    {
        return true;
    }
    [
        "/api/state",
        "/api/claim",
        "/api/logout",
        "/api/enrol",
        "/api/signin",
        "/api/broker",
        "/api/release",
        "/api/chat-session",
        "/api/binding",
        "/api/approvals",
        "/api/aura",
        "/api/nostr",
        "/api/memory",
        "/__aukora",
        "/api/aukora/aumlok-binding",
        "/api/aukora/aumlok-control",
        "/api/aukora/aumlok-identity",
    ]
    .iter()
    .any(|prefix| {
        path == *prefix
            || path
                .strip_prefix(*prefix)
                .is_some_and(|tail| tail.starts_with('/'))
    })
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn websocket_headers(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("upgrade"))
}

fn strip_request_headers(headers: &mut HeaderMap, websocket: bool) {
    strip_hop_headers(headers, websocket);
    let allowed = [
        "host",
        "origin",
        "content-type",
        "accept",
        "accept-encoding",
        "accept-language",
        "user-agent",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-fetch-user",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
    ];
    let removed: Vec<_> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            !(allowed.contains(&name) || websocket && matches!(name, "connection" | "upgrade"))
        })
        .cloned()
        .collect();
    // MUTATION: proxy-request-allowlist
    for name in removed {
        headers.remove(name);
    }
}

fn strip_response_headers(headers: &mut HeaderMap, websocket: bool) {
    strip_hop_headers(headers, websocket);
    let allowed = [
        "content-type",
        "content-length",
        "content-encoding",
        "etag",
        "last-modified",
        "cache-control",
    ];
    let removed: Vec<_> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            !(allowed.contains(&name)
                || websocket
                    && matches!(
                        name,
                        "connection"
                            | "upgrade"
                            | "sec-websocket-accept"
                            | "sec-websocket-protocol"
                            | "sec-websocket-extensions"
                    ))
        })
        .cloned()
        .collect();
    // MUTATION: proxy-response-allowlist
    for name in removed {
        headers.remove(name);
    }
}

fn strip_hop_headers(headers: &mut HeaderMap, websocket: bool) {
    let named: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    // MUTATION: proxy-hop-headers
    for name in named {
        if !websocket || name != header::UPGRADE {
            headers.remove(name);
        }
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    if websocket {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    }
}

fn refusal(status: StatusCode, code: &'static str) -> Response {
    let mut response = Response::new(Body::from(format!("{{\"error\":\"{code}\"}}")));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

struct IdleIo<T> {
    inner: T,
    timer: Pin<Box<Sleep>>,
    timeout: Duration,
}

impl<T> IdleIo<T> {
    fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timer: Box::pin(tokio::time::sleep(timeout)),
            timeout,
        }
    }

    fn expired(&mut self, context: &mut Context<'_>) -> bool {
        self.timer.as_mut().poll(context).is_ready()
    }

    fn activity(&mut self) {
        self.timer.as_mut().reset(Instant::now() + self.timeout);
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for IdleIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // MUTATION: proxy-websocket-idle
        if this.expired(context) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guest socket timed out",
            )));
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            // MUTATION: proxy-websocket-read-activity
            this.activity();
        }
        result
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IdleIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.expired(context) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guest socket timed out",
            )));
        }
        let result = Pin::new(&mut this.inner).poll_write(context, bytes);
        if matches!(&result, Poll::Ready(Ok(written)) if *written > 0) {
            // MUTATION: proxy-websocket-write-activity
            this.activity();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

struct IdleBody {
    incoming: Pin<Box<Incoming>>,
    timer: Pin<Box<Sleep>>,
    timeout: Duration,
    ended: bool,
}

impl IdleBody {
    fn new(incoming: Incoming, timeout: Duration) -> Self {
        Self {
            incoming: Box::pin(incoming),
            timer: Box::pin(tokio::time::sleep(timeout)),
            timeout,
            ended: false,
        }
    }
}

impl HttpBody for IdleBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        loop {
            match self.incoming.as_mut().poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    let deadline = Instant::now() + self.timeout;
                    self.timer.as_mut().reset(deadline);
                    // MUTATION: proxy-trailers
                    if frame.is_trailers() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(_))) => {
                    self.ended = true;
                    return Poll::Ready(Some(Err(io::Error::other("guest response failed"))));
                }
                Poll::Ready(None) => {
                    self.ended = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    // MUTATION: proxy-idle-timeout
                    if self.timer.as_mut().poll(context).is_ready() {
                        self.ended = true;
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "guest response timed out",
                        ))));
                    } else {
                        return Poll::Pending;
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended || self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.incoming.size_hint()
    }
}

#[cfg(not(test))]
pub(crate) async fn exchange_token(
    socket: &Path,
    host: &str,
    token: &str,
    timeout: Duration,
) -> Result<HeaderValue, crate::ApiError> {
    exchange_token_with_connection(UnixStream::connect(socket), host, token, timeout).await
}

pub(crate) async fn exchange_token_with_connection(
    connector: impl Future<Output = io::Result<UnixStream>>,
    host: &str,
    token: &str,
    timeout: Duration,
) -> Result<HeaderValue, crate::ApiError> {
    let invalid =
        || crate::ApiError::new(StatusCode::BAD_GATEWAY, "frontdoor:harness-auth-refused");
    if token.len() != 43
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(invalid());
    }
    let exchange = async {
        let stream = connector.await.map_err(|_| invalid())?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| invalid())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method("GET")
            .uri(format!("/?token={token}"))
            .header(header::HOST, host)
            .body(Body::empty())
            .map_err(|_| invalid())?;
        let response = sender.send_request(request).await.map_err(|_| invalid())?;
        if !response.status().is_success() && !response.status().is_redirection() {
            return Err(invalid());
        }
        let mut cookies = response.headers().get_all(header::SET_COOKIE).iter();
        let cookie = cookies
            .next()
            .ok_or_else(invalid)?
            .to_str()
            .map_err(|_| invalid())?;
        if cookies.next().is_some() {
            return Err(invalid());
        }
        let pair = cookie.split(';').next().ok_or_else(invalid)?;
        let (name, value) = pair.split_once('=').ok_or_else(invalid)?;
        if name.is_empty()
            || value.is_empty()
            || name.len() + value.len() > 4096
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'=' | b'/'))
        {
            return Err(invalid());
        }
        HeaderValue::from_str(pair).map_err(|_| invalid())
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| invalid())?
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{oneshot, Mutex};

    use super::*;

    // Socketpair fixtures exercise FD 4 transport without pathname bind/connect.
    #[derive(Clone)]
    struct Socket {
        sender: Arc<Mutex<Option<oneshot::Sender<UnixStream>>>>,
    }

    struct Listener {
        receiver: oneshot::Receiver<UnixStream>,
    }

    impl Socket {
        fn listener() -> (Self, Listener) {
            let (sender, receiver) = oneshot::channel();
            (
                Self {
                    sender: Arc::new(Mutex::new(Some(sender))),
                },
                Listener { receiver },
            )
        }

        async fn connect(&self) -> io::Result<UnixStream> {
            let (client, server) = UnixStream::pair()?;
            self.sender
                .lock()
                .await
                .take()
                .ok_or_else(|| io::Error::other("test connector already consumed"))?
                .send(server)
                .map_err(|_| io::Error::other("test listener closed"))?;
            Ok(client)
        }
    }

    impl Listener {
        async fn accept(&mut self) -> io::Result<(UnixStream, ())> {
            (&mut self.receiver)
                .await
                .map(|server| (server, ()))
                .map_err(|_| io::Error::other("test connector closed"))
        }
    }

    async fn proxy_connected(
        request: Request<Body>,
        socket: &Socket,
        timeout: Duration,
        max_body: usize,
    ) -> Response {
        proxy_with_connection(request, socket.connect(), timeout, max_body).await
    }

    async fn headers(io: &mut (impl AsyncRead + Unpin)) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            io.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 65536);
        }
        String::from_utf8(bytes).unwrap()
    }

    fn request(path: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header(header::HOST, "chat-node.example")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn fd4_removes_credentials_forwarding_hop_and_guest_security_headers() {
        let (socket, mut listener) = Socket::listener();
        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let received = headers(&mut stream).await.to_ascii_lowercase();
            for name in [
                "cookie:",
                "authorization:",
                "referer:",
                "forwarded:",
                "x-forwarded-for:",
                "x-forwarded-proto:",
                "x-forwarded-host:",
                "x-private-hop:",
                "proxy-authorization:",
                "x-custom-secret:",
                "sec-fetch-secret:",
                "accept:",
            ] {
                assert!(!received.contains(name), "guest received {name}");
            }
            assert!(!received.contains("disposable-owner-token"));
            assert!(received.starts_with("get /api/remote.mux http/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: guest=bad\r\nContent-Security-Policy: unsafe\r\nContent-Security-Policy-Report-Only: unsafe\r\nReferrer-Policy: unsafe-url\r\nStrict-Transport-Security: bad\r\nX-Frame-Options: SAMEORIGIN\r\nX-Content-Type-Options: bad\r\nLocation: https://owner-node.example/?claim=disposable-claim\r\nX-Custom-Secret: disposable-owner-token\r\nETag: disposable-hop\r\nConnection: close, x-response-hop, etag\r\nX-Response-Hop: bad\r\n\r\nok")
                .await
                .unwrap();
        });
        let mut request = request("/api/remote.mux");
        for (name, value) in [
            ("cookie", "__Host-owner=disposable-owner-token"),
            ("authorization", "Bearer disposable-owner-token"),
            (
                "referer",
                "https://owner-node.example/?claim=disposable-claim",
            ),
            ("forwarded", "proto=http;host=foreign.example"),
            ("x-forwarded-for", "127.0.0.1"),
            ("x-forwarded-proto", "http"),
            ("x-forwarded-host", "owner-node.example"),
            ("proxy-authorization", "disposable-owner-token"),
            ("connection", "x-private-hop, accept"),
            ("accept", "text/plain"),
            ("x-private-hop", "private"),
            ("x-custom-secret", "disposable-owner-token"),
            ("sec-fetch-secret", "disposable-owner-token"),
        ] {
            request.headers_mut().insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        let response = proxy_connected(request, &socket, Duration::from_secs(2), 1024).await;
        assert_eq!(response.status(), StatusCode::OK);
        for name in [
            "set-cookie",
            "content-security-policy",
            "content-security-policy-report-only",
            "referrer-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "connection",
            "x-response-hop",
            "location",
            "x-custom-secret",
            "etag",
        ] {
            assert!(!response.headers().contains_key(name), "returned {name}");
        }
        assert_eq!(to_bytes(response.into_body(), 1024).await.unwrap(), "ok");
        guest.await.unwrap();
    }

    #[tokio::test]
    async fn fd4_never_opens_for_owner_routes_or_ambiguous_paths() {
        let (socket, mut listener) = Socket::listener();
        for path in [
            "/api/state",
            "/api/claim",
            "/api/enrol/start",
            "/api/enrol/finish",
            "/api/binding/prepare",
            "/api/binding/confirm",
            "/api/binding/cancel",
            "/api/binding/refresh",
            "/api/approvals",
            "/api/approvals/challenge",
            "/api/approvals/decide",
            "/api/aura/head?since=1",
            "/api/aura/recent?limit=2",
            "/api/aura/retained",
            "/api/memory/recall",
            "/api/memory/demote",
            "/api/logout",
            "/%61pi/claim",
            "/api%2fclaim",
            "/api//claim",
            "/api/../api/claim",
            "/api%252fclaim",
            "/api/aukora/aumlok-binding/prepare",
            "/__aukora/claim",
        ] {
            let response =
                proxy_connected(request(path), &socket, Duration::from_millis(10), 1024).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "accepted {path}");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn fd4_body_limit_is_enforced_before_guest_connect() {
        let request = Request::builder()
            .uri("/api/remote.mux")
            .body(Body::from("four"))
            .unwrap();
        let response = proxy(
            request,
            Path::new("nonexistent-fd4.sock"),
            Duration::from_secs(1),
            3,
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn fd4_header_deadline_is_enforced() {
        let (socket, mut listener) = Socket::listener();
        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = headers(&mut stream).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        let response =
            proxy_connected(request("/events"), &socket, Duration::from_millis(20), 1024).await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        guest.await.unwrap();
    }

    #[tokio::test]
    async fn fd4_sse_is_streamed_before_guest_finishes() {
        let (socket, mut listener) = Socket::listener();
        let (release, wait) = oneshot::channel();
        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nB\r\ndata: one\n\n\r\n")
                .await
                .unwrap();
            wait.await.unwrap();
            stream
                .write_all(b"B\r\ndata: two\n\n\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            proxy_connected(request("/events"), &socket, Duration::from_secs(2), 1024),
        )
        .await
        .expect("proxy waited for SSE completion");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        let mut body = response.into_body();
        let first = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert_eq!(first, "data: one\n\n");
        release.send(()).unwrap();
        assert_eq!(to_bytes(body, 1024).await.unwrap(), "data: two\n\n");
        guest.await.unwrap();
    }

    #[tokio::test]
    async fn fd4_preserves_public_path_and_query() {
        let (socket, mut listener) = Socket::listener();
        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let received = headers(&mut stream).await;
            assert!(received.starts_with("GET /events?room=public-room&cursor=2 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 13\r\n\r\ndata: ready\n\n")
                .await
                .unwrap();
        });
        let response = proxy_connected(
            request("/events?room=public-room&cursor=2"),
            &socket,
            Duration::from_secs(2),
            1024,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "data: ready\n\n"
        );
        guest.await.unwrap();
    }

    #[tokio::test]
    async fn fd4_stream_idle_deadline_is_enforced_without_secret_errors() {
        let (socket, mut listener) = Socket::listener();
        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = stream.write_all(b"later").await;
        });
        let response =
            proxy_connected(request("/events"), &socket, Duration::from_millis(50), 1024).await;
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            to_bytes(response.into_body(), 1024),
        )
        .await
        .expect("response idle limit was not enforced");
        let error = result.unwrap_err().to_string();
        assert_eq!(error, "guest response timed out");
        assert!(!error.contains("disposable-private-fd4"));
        guest.await.unwrap();
    }

    #[tokio::test]
    async fn fd4_never_forwards_guest_trailers() {
        let (socket, mut listener) = Socket::listener();
        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Set-Cookie, X-Custom-Secret\r\n\r\n2\r\nok\r\n0\r\nSet-Cookie: guest=disposable-owner-token\r\nX-Custom-Secret: disposable-claim\r\n\r\n")
                .await
                .unwrap();
        });
        let response =
            proxy_connected(request("/events"), &socket, Duration::from_secs(2), 1024).await;
        assert!(!response.headers().contains_key(header::TRAILER));
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            assert!(!frame.is_trailers(), "guest trailers reached the browser");
            bytes.extend_from_slice(&frame.into_data().unwrap());
        }
        assert_eq!(bytes, b"ok");
        guest.await.unwrap();
    }

    #[tokio::test]
    async fn fd4_transport_errors_have_only_a_fixed_refusal() {
        let response = proxy(
            request("/events?room=disposable-public-room"),
            Path::new("disposable-private-fd4.sock"),
            Duration::from_secs(1),
            1024,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "{\"error\":\"frontdoor:guest-unavailable\"}"
        );
    }

    #[tokio::test]
    async fn fd4_websocket_upgrade_bridges_both_directions() {
        let (socket, mut listener) = Socket::listener();
        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let received = headers(&mut stream).await.to_ascii_lowercase();
            assert!(received.contains("upgrade: websocket\r\n"));
            assert!(received.contains("connection: upgrade\r\n"));
            assert!(!received.contains("cookie:"));
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSet-Cookie: guest=bad\r\n\r\n")
                .await
                .unwrap();
            let mut frame = [0; 8];
            stream.read_exact(&mut frame).await.unwrap();
            assert_eq!(frame, [0x81, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2]);
            stream.write_all(&[0x81, 2, b'h', b'i']).await.unwrap();
        });
        let (mut browser, server) = tokio::io::duplex(65536);
        let upstream_socket = socket.clone();
        let frontdoor = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(server),
                    service_fn(move |request| {
                        let socket = upstream_socket.clone();
                        async move {
                            let request = request.map(Body::new);
                            Ok::<_, std::convert::Infallible>(
                                proxy_connected(request, &socket, Duration::from_secs(2), 1024)
                                    .await,
                            )
                        }
                    }),
                )
                .with_upgrades()
                .await
                .unwrap();
        });
        browser
            .write_all(b"GET /api/remote.mux HTTP/1.1\r\nHost: chat-node.example\r\nOrigin: https://chat-node.example\r\nSec-Fetch-Site: same-origin\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: __Host-owner=disposable-owner-token\r\n\r\n")
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), headers(&mut browser))
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 101"));
        assert!(!response.to_ascii_lowercase().contains("set-cookie:"));
        assert!(response.to_ascii_lowercase().contains("upgrade: websocket"));
        browser
            .write_all(&[0x81, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2])
            .await
            .unwrap();
        let mut frame = [0; 4];
        tokio::time::timeout(Duration::from_secs(1), browser.read_exact(&mut frame))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame, [0x81, 2, b'h', b'i']);
        drop(browser);
        guest.await.unwrap();
        frontdoor.await.unwrap();
    }

    #[tokio::test]
    async fn fd4_websocket_idle_closes_and_releases_connection_lease() {
        let (socket, mut listener) = Socket::listener();
        let guest = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
                .await
                .unwrap();
            let mut byte = [0; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let lease = crate::ConnectionLease {
            _permit: Arc::new(semaphore.clone().acquire_owned().await.unwrap()),
        };
        let (mut browser, server) = tokio::io::duplex(65536);
        let frontdoor = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(server),
                    service_fn(move |mut request: Request<Incoming>| {
                        let socket = socket.clone();
                        request.extensions_mut().insert(lease.clone());
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                proxy_connected(
                                    request.map(Body::new),
                                    &socket,
                                    Duration::from_millis(20),
                                    1024,
                                )
                                .await,
                            )
                        }
                    }),
                )
                .with_upgrades()
                .await
                .unwrap();
        });
        browser
            .write_all(b"GET /api/remote.mux HTTP/1.1\r\nHost: chat-node.example\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            .await
            .unwrap();
        let response = headers(&mut browser).await;
        assert!(response.starts_with("HTTP/1.1 101"));
        frontdoor.await.unwrap();
        assert_eq!(
            semaphore.available_permits(),
            0,
            "upgrade lost its connection lease"
        );
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_millis(200), browser.read(&mut byte))
            .await
            .expect("idle websocket stayed open")
            .unwrap();
        assert_eq!(read, 0);
        guest.await.unwrap();
        assert_eq!(
            semaphore.available_permits(),
            1,
            "idle close retained its connection lease"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn websocket_read_traffic_resets_idle_deadline() {
        let (mut writer, reader) = tokio::io::duplex(16);
        let writer = tokio::spawn(async move {
            for byte in b"abc" {
                tokio::time::sleep(Duration::from_millis(30)).await;
                writer.write_all(&[*byte]).await.unwrap();
            }
        });
        let mut reader = IdleIo::new(reader, Duration::from_millis(50));
        let mut bytes = [0; 3];
        reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abc");
        writer.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn websocket_write_traffic_resets_idle_deadline() {
        let (writer, mut reader) = tokio::io::duplex(16);
        let mut writer = IdleIo::new(writer, Duration::from_millis(50));
        for byte in b"abc" {
            tokio::time::sleep(Duration::from_millis(30)).await;
            writer.write_all(&[*byte]).await.unwrap();
        }
        let mut bytes = [0; 3];
        reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abc");
    }

    #[tokio::test]
    async fn harness_exchange_is_private_strict_and_has_one_cookie() {
        for token in [
            "".to_owned(),
            "a".repeat(42),
            "a".repeat(44),
            format!("{}=", "a".repeat(42)),
            format!("{}\n", "a".repeat(42)),
            format!("{}é", "a".repeat(41)),
        ] {
            let connector = async {
                panic!("hostile token reached FD 4");
                #[allow(unreachable_code)]
                Ok::<_, io::Error>(UnixStream::pair().unwrap().0)
            };
            assert!(exchange_token_with_connection(
                connector,
                "chat-test.example",
                &token,
                Duration::from_secs(1)
            )
            .await
            .is_err());
        }
        for (set_cookie, accepted) in [
            (
                "Set-Cookie: harness=private_cookie; HttpOnly; Path=/\r\n",
                true,
            ),
            (
                "Set-Cookie: harness=private_cookie\r\nSet-Cookie: other=forbidden\r\n",
                false,
            ),
            ("Set-Cookie: harness=contains space\r\n", false),
            ("", false),
        ] {
            let (socket, mut listener) = Socket::listener();
            let token = "a".repeat(43);
            let expected = token.clone();
            let guest = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = headers(&mut stream).await;
                assert!(request.starts_with(&format!("GET /?token={expected} HTTP/1.1\r\n")));
                assert!(request
                    .to_ascii_lowercase()
                    .contains("host: chat-test.example\r\n"));
                assert!(!request.to_ascii_lowercase().contains("cookie:"));
                stream
                    .write_all(
                        format!("HTTP/1.1 302 Found\r\n{set_cookie}Content-Length: 0\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
            let cookie = exchange_token_with_connection(
                socket.connect(),
                "chat-test.example",
                &token,
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(cookie.is_ok(), accepted);
            if accepted {
                assert_eq!(cookie.unwrap(), "harness=private_cookie");
            }
            guest.await.unwrap();
        }
    }

    #[tokio::test]
    async fn proxy_injects_only_private_harness_cookie_for_http_and_sse() {
        for content_type in ["application/json", "text/event-stream"] {
            let (socket, mut listener) = Socket::listener();
            let guest = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = headers(&mut stream).await.to_ascii_lowercase();
                assert!(request.contains("cookie: harness=server_secret\r\n"));
                assert_eq!(request.matches("cookie:").count(), 1);
                assert!(!request.contains("client_secret"));
                assert!(!request.contains("owner_secret"));
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: 2\r\nSet-Cookie: harness=browser_secret\r\n\r\nok").as_bytes()).await.unwrap();
            });
            let mut request = request("/events");
            request.headers_mut().append(
                header::COOKIE,
                HeaderValue::from_static("harness=client_secret; __Host-aukora-owner=owner_secret"),
            );
            request.headers_mut().append(
                header::COOKIE,
                HeaderValue::from_static("other=client_secret"),
            );
            let response = proxy_with_cookie(
                request,
                socket.connect(),
                Duration::from_secs(1),
                1024,
                Some(HeaderValue::from_static("harness=server_secret")),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert_eq!(to_bytes(response.into_body(), 1024).await.unwrap(), "ok");
            guest.await.unwrap();
        }
    }
}
