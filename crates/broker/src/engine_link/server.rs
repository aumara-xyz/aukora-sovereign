// SPDX-License-Identifier: AGPL-3.0-or-later
//! The listener: HTTP/1.1 on a unix socket, one engine call per request, streamed back as it arrives.

use super::budget::{Budget, KeyApproval};
use super::meter::{Meter, Stop};
use super::{refuse, request, Link, LinkRefusal, Peer, ANTHROPIC_VERSION, FORWARDED_BETAS};
use bytes::Bytes;
use canon::digest::Digest32;
use canon::json::{SafeInteger, Value};
use http::{Method, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::Incoming;
use std::convert::Infallible;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

type Body = BoxBody<Bytes, Infallible>;
const MAX_CONNECTIONS: usize = 32;
const MAX_ERROR_BODY: usize = 64 * 1024;
const MAX_ERROR_MESSAGE: usize = 2048;

/// Bind the socket: an existing live socket or any other file there refuses; a stale socket is replaced. The
/// folder must not be writable by others. With a uid check the socket is opened to every local user after the
/// bind (the kernel says who connects); without one it stays the owner's alone.
pub fn bind(socket: &Path, uids_checked: bool) -> canon::Result<UnixListener> {
    let fail = canon::codes::BROKER_CONFIG;
    let parent = socket.parent().ok_or(fail)?;
    let meta = std::fs::symlink_metadata(parent).map_err(|_| fail)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o022 != 0 {
        return Err(fail);
    }
    if let Ok(meta) = std::fs::symlink_metadata(socket) {
        if !meta.file_type().is_socket() || std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return Err(fail);
        }
        std::fs::remove_file(socket).map_err(|_| fail)?;
    }
    let listener = UnixListener::bind(socket).map_err(|_| fail)?;
    let mode = if uids_checked { 0o666 } else { 0o600 };
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(mode)).map_err(|_| fail)?;
    Ok(listener)
}

/// Accept until the listener fails for good.
pub async fn serve(link: Arc<Link>, listener: UnixListener) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let peer = super::peer::of(&stream);
        let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
        let link = link.clone();
        tokio::spawn(async move {
            serve_connection(link, stream, peer).await;
            drop(slot);
        });
    }
}

/// Serve one connection whose peer the caller already read from the kernel.
pub async fn serve_connection(link: Arc<Link>, stream: UnixStream, peer: Peer) {
    let service = hyper::service::service_fn(move |request| {
        let link = link.clone();
        async move { Ok::<_, Infallible>(handle(link, peer, request).await) }
    });
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .max_buf_size(64 * 1024);
    let _ = http.serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
}

async fn handle(link: Arc<Link>, peer: Peer, request: Request<Incoming>) -> Response<Body> {
    if !link.peer_allowed(peer) {
        link.authority.log("refused peer");
        return refusal(&refuse::peer());
    }
    let path = request.uri().path().to_owned();
    if path.starts_with("/v1/files") {
        return refusal(&refuse::files());
    }
    if request.method() != Method::POST || path != "/v1/messages" {
        return refusal(&refuse::not_found());
    }
    match messages(link.clone(), request).await {
        Ok(response) => response,
        Err(refused) => {
            link.authority.log(&format!("refused {} ({})", refused.code, refused.status));
            refusal(&refused)
        }
    }
}

/// Everything a call carries from admission to its receipt.
struct Call {
    id: String,
    model: String,
    budget: Budget,
    budget_id: String,
    key_generation: u64,
    reserved: u64,
    request_sha256: Digest32,
    request_bytes: u64,
    started_at_ms: u64,
}

async fn messages(link: Arc<Link>, request: Request<Incoming>) -> Result<Response<Body>, LinkRefusal> {
    if link.receipts_failed.load(Ordering::SeqCst) {
        return Err(refuse::unavailable("receipts-unavailable"));
    }
    let permit = link.calls.clone().try_acquire_owned().map_err(|_| refuse::busy())?;
    let (parts, body) = request.into_parts();
    let version = parts.headers.get("anthropic-version").map(|v| v.as_bytes().to_vec());
    if version.as_deref().is_some_and(|v| v != ANTHROPIC_VERSION.as_bytes()) {
        return Err(refuse::bad_request("anthropic-version"));
    }
    let betas: Vec<&'static str> = parts
        .headers
        .get_all("anthropic-beta")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|beta| FORWARDED_BETAS.iter().copied().find(|allowed| *allowed == beta.trim()))
        .collect();
    let raw = Limited::new(body, link.limits.max_request_bytes)
        .collect()
        .await
        .map_err(|_| refuse::too_large())?
        .to_bytes();

    // The key the owner entered, and only if its digest is the one the owner approved with the passkey.
    let approved = link.authority.approved().await;
    let state = link.keys.state().map_err(|_| refuse::no_key("no-key"))?;
    if !state.present {
        return Err(refuse::no_key("no-key"));
    }
    let key = link.keys.key_for_generation(state.generation).map_err(|_| refuse::no_key("no-key"))?;
    let approval = KeyApproval::for_key(&key);
    if approved.key_sha256.as_deref() != Some(approval.key_sha256.as_str()) {
        return Err(refuse::no_key("key-not-approved"));
    }
    // The approved budget, unexpired.
    let budget_bytes = approved.budget.ok_or_else(|| refuse::no_budget("no-budget"))?;
    let budget = Budget::parse(&budget_bytes)?;
    let now = link.authority.now_ms();
    if now >= budget.expires_at_ms {
        return Err(refuse::no_budget("budget-expired"));
    }
    let checked = request::check(&raw, &budget, link.limits.max_request_bytes)?;
    if !checked.dropped.is_empty() {
        link.authority.log(&format!("removed request extensions: {}", checked.dropped.join(",")));
    }

    // Reserve the worst case, with the output capped so the worst case fits.
    let budget_id = Budget::digest(&budget_bytes).to_string();
    let id = random_id().map_err(|_| refuse::unavailable("random"))?;
    let mut max_tokens = 0;
    let prices = budget.prices;
    let reserved = link.spend.reserve(&budget_id, &id, |used| {
        if used.requests >= budget.max_requests {
            return Err(refuse::no_budget("budget-requests"));
        }
        let left = budget.total_cap_microusd.saturating_sub(used.microusd);
        let cap = left.min(budget.per_request_cap_microusd);
        let short = if left < budget.per_request_cap_microusd { "budget-exhausted" } else { "budget-per-request" };
        let input = Budget::cost(checked.input_token_bound, prices.input_microusd_per_mtok);
        if input >= cap {
            return Err(refuse::no_budget(short));
        }
        let affordable = u128::from(cap - input) * 1_000_000 / u128::from(prices.output_microusd_per_mtok);
        max_tokens = checked.requested_max_tokens.min(u64::try_from(affordable).unwrap_or(u64::MAX));
        if max_tokens == 0 {
            return Err(refuse::no_budget(short));
        }
        Ok(input + Budget::cost(max_tokens, prices.output_microusd_per_mtok))
    })?;
    let model = checked.model.clone();
    let call = Call {
        id,
        model,
        budget,
        budget_id,
        key_generation: state.generation,
        reserved,
        request_sha256: Digest32::sha256(&[]),
        request_bytes: 0,
        started_at_ms: now,
    };
    let body = match checked.finish(max_tokens) {
        Ok(body) => body,
        Err(refused) => {
            release(&link, &call, "request-not-json");
            return Err(refused);
        }
    };
    // The engine never had the key; a request that carries it anyway is not sent.
    if crate::provider::EchoGuard::new(&key).check(&body).is_err() {
        release(&link, &call, "key-in-request");
        return Err(refuse::bad_request("key-in-request"));
    }
    let call = Call { request_sha256: Digest32::sha256(&body), request_bytes: body.len() as u64, ..call };
    send(link, call, key, body, betas, permit).await
}

/// A reservation that was never sent: settled at zero, no receipt (nothing reached the provider).
fn release(link: &Link, call: &Call, why: &str) {
    if link.spend.settle(&call.budget_id, &call.id, 0).is_err() {
        link.authority.log(&format!("{}: release not written ({why}); charged in full at next start", call.id));
    }
}

async fn send(
    link: Arc<Link>,
    call: Call,
    key: Zeroizing<String>,
    body: Vec<u8>,
    betas: Vec<&'static str>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<Response<Body>, LinkRefusal> {
    let mut header = reqwest::header::HeaderValue::from_str(&key).map_err(|_| refuse::no_key("no-key"))?;
    header.set_sensitive(true);
    let mut builder = link
        .upstream
        .client
        .post(link.upstream.url.clone())
        .header("x-api-key", header)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .header("anthropic-version", ANTHROPIC_VERSION);
    if !betas.is_empty() {
        builder = builder.header("anthropic-beta", betas.join(","));
    }
    let deadline = Instant::now() + link.limits.total;
    let sent = tokio::time::timeout(link.limits.idle, builder.body(body).send()).await;
    let meter = Meter::new(&key, &call.budget.models);
    drop(key);
    let mut response = match sent {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if error.is_connect() => {
            // Nothing reached the provider.
            settle(&link, &call, &meter, Outcome::Unreachable).await;
            return Err(refuse::upstream("provider-unreachable"));
        }
        _ => {
            settle(&link, &call, &meter, Outcome::Interrupted("provider-no-answer")).await;
            return Err(refuse::upstream("provider-no-answer"));
        }
    };
    let status = response.status().as_u16();
    if !response.status().is_success() {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty() && v.len() <= 8 && v.bytes().all(|b| b.is_ascii_digit()))
            .map(str::to_owned);
        let mut error = Vec::new();
        while error.len() < MAX_ERROR_BODY {
            match tokio::time::timeout(Duration::from_secs(10), response.chunk()).await {
                Ok(Ok(Some(chunk))) => error.extend_from_slice(&chunk),
                _ => break,
            }
        }
        error.truncate(MAX_ERROR_BODY);
        let (error_type, message) = provider_error(&error, status, &link, &meter);
        settle(&link, &call, &meter, Outcome::ProviderRefused(status)).await;
        let status = if (400..=599).contains(&status) { status } else { 502 };
        let mut reply = json_response(status, &error_body(&error_type, &message));
        if let Some(seconds) = retry_after {
            if let Ok(value) = http::HeaderValue::from_str(&seconds) {
                reply.headers_mut().insert(http::header::RETRY_AFTER, value);
            }
        }
        return Ok(reply);
    }
    let event_stream = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim() == "text/event-stream");
    if !event_stream {
        settle(&link, &call, &meter, Outcome::Interrupted("provider-not-streaming")).await;
        return Err(refuse::upstream("provider-not-streaming"));
    }
    let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(16);
    tokio::spawn(pump(link, call, response, meter, sender, deadline, permit));
    let mut reply = Response::new(ChannelBody(receiver).boxed());
    let headers = reply.headers_mut();
    headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/event-stream"));
    headers.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
    Ok(reply)
}

/// Pass the provider's stream through, watched; settle and write the receipt; then release the held tail.
async fn pump(
    link: Arc<Link>,
    call: Call,
    mut response: reqwest::Response,
    mut meter: Meter,
    sender: tokio::sync::mpsc::Sender<Bytes>,
    deadline: Instant,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let outcome = loop {
        let left = deadline.saturating_duration_since(Instant::now()).min(link.limits.idle);
        if left.is_zero() {
            break Outcome::Interrupted("provider-timeout");
        }
        let chunk = match tokio::time::timeout(left, response.chunk()).await {
            Err(_) => break Outcome::Interrupted("provider-timeout"),
            Ok(Err(_)) => break Outcome::Interrupted("provider-transport"),
            Ok(Ok(None)) => break Outcome::Ended,
            Ok(Ok(Some(chunk))) => chunk,
        };
        if meter.bytes.saturating_add(chunk.len() as u64) > link.limits.max_response_bytes {
            break Outcome::Interrupted("reply-too-large");
        }
        match meter.feed(&chunk) {
            Err(Stop::KeyEcho) => break Outcome::KeyEcho,
            Err(Stop::Unscannable) => break Outcome::Interrupted("reply-unscannable"),
            Ok(out) if out.is_empty() => {}
            Ok(out) => {
                if sender.send(Bytes::from(out)).await.is_err() {
                    break Outcome::Cancelled;
                }
            }
        }
    };
    drop(response);
    let tail = meter.tail();
    let recorded = settle(&link, &call, &meter, outcome).await;
    drop(permit);
    match outcome {
        Outcome::Ended if recorded && meter.complete() => {
            let _ = sender.send(Bytes::from(tail)).await;
        }
        Outcome::Cancelled => {}
        _ => {
            // The engine learns the call ended and why, never what was withheld.
            let code = match outcome {
                Outcome::Interrupted(code) => code,
                Outcome::KeyEcho => "reply-withheld",
                _ if !recorded => "receipts-unavailable",
                _ => "provider-stream-incomplete",
            };
            let event = format!(
                "\n\nevent: error\ndata: {}\n\n",
                String::from_utf8_lossy(&error_body("api_error", &format!("aukora broker: {code}")))
            );
            let _ = sender.send(Bytes::from(event)).await;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Ended,
    Cancelled,
    KeyEcho,
    Unreachable,
    ProviderRefused(u16),
    Interrupted(&'static str),
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Self::Ended => "completed",
            Self::Cancelled => "cancelled",
            Self::KeyEcho => "key-echo",
            Self::Unreachable => "unreachable",
            Self::ProviderRefused(_) => "provider-refused",
            Self::Interrupted(_) => "interrupted",
        }
    }
}

/// Charge what the call cost, write the spend line and the Aura receipt. Returns whether the receipt is durable.
async fn settle(
    link: &Arc<Link>,
    call: &Call,
    meter: &Meter,
    outcome: Outcome,
) -> bool {
    let measured = call.budget.charge(&meter.usage);
    let (charged, unknown) = match outcome {
        // Nothing billable happened.
        Outcome::Unreachable | Outcome::ProviderRefused(_) => (0, false),
        Outcome::Ended if meter.complete() => (measured, false),
        // The provider may have billed more than it reported: the reservation is the floor.
        _ => (measured.max(call.reserved), true),
    };
    // Every field is the broker's own or an approved name; the guard still reads the whole receipt, decoded, before
    // it goes anywhere durable.
    let receipt = receipt(call, meter, outcome, charged, unknown, link.authority.now_ms()).and_then(|value| {
        if meter.guard_rejects(&value.canonical_bytes()) || meter.guard_rejects(format!("{value:?}").as_bytes()) {
            Err(canon::codes::BROKER_KEY_ECHO)
        } else {
            Ok(value)
        }
    });
    let link2 = link.clone();
    let budget_id = call.budget_id.clone();
    let id = call.id.clone();
    let written = tokio::task::spawn_blocking(move || {
        let spent = link2.spend.settle(&budget_id, &id, charged);
        let recorded = receipt.and_then(|value| link2.authority.record(value));
        (spent, recorded)
    })
    .await;
    let (spent, recorded) = match written {
        Ok(result) => result,
        Err(_) => (Err("spend-state"), Err(canon::codes::BROKER_STATE)),
    };
    let sequence = match recorded {
        Ok(sequence) => sequence.to_string(),
        Err(_) => {
            link.receipts_failed.store(true, Ordering::SeqCst);
            "none".into()
        }
    };
    link.authority.log(&format!(
        "call {} {} model={} in={} out={} cache_read={} reserved={} charged={}{} aura={}{}",
        call.id,
        outcome.name(),
        call.model,
        meter.usage.input_tokens,
        meter.usage.output_tokens,
        meter.usage.cache_read_input_tokens,
        call.reserved,
        charged,
        if unknown { " (usage unknown: reservation charged)" } else { "" },
        sequence,
        if spent.is_err() { " spend-line-unwritten" } else { "" },
    ));
    sequence != "none"
}

fn receipt(call: &Call, meter: &Meter, outcome: Outcome, charged: u64, unknown: bool, ended: u64) -> canon::Result<Value> {
    let text = |s: &str| Value::text(s.to_owned());
    let number = |n: u64| -> canon::Result<Value> {
        Ok(Value::integer(SafeInteger::new(i64::try_from(n.min(9_007_199_254_740_991)).unwrap_or(0))?))
    };
    let detail = match outcome {
        Outcome::Interrupted(code) => code.to_owned(),
        Outcome::ProviderRefused(status) => format!("http-{status}"),
        _ => String::new(),
    };
    let usage = Value::object(vec![
        ("cache_creation_input_tokens".into(), number(meter.usage.cache_creation_input_tokens)?),
        ("cache_read_input_tokens".into(), number(meter.usage.cache_read_input_tokens)?),
        ("input_tokens".into(), number(meter.usage.input_tokens)?),
        ("output_tokens".into(), number(meter.usage.output_tokens)?),
    ])?;
    let body = Value::object(vec![
        ("budget_sha256".into(), text(&call.budget_id)?),
        ("charged_microusd".into(), number(charged)?),
        ("cost_unknown".into(), Value::boolean(unknown)),
        ("detail".into(), text(&detail)?),
        ("ended_at_ms".into(), number(ended)?),
        ("key_generation".into(), number(call.key_generation)?),
        ("model".into(), text(&call.model)?),
        ("outcome".into(), text(outcome.name())?),
        ("provider".into(), text(super::budget::PROVIDER)?),
        ("reported_model".into(), text(meter.reported_model.as_deref().unwrap_or(""))?),
        ("request_bytes".into(), number(call.request_bytes)?),
        ("request_id".into(), text(&call.id)?),
        ("request_sha256".into(), text(&call.request_sha256.to_string())?),
        ("reserved_microusd".into(), number(call.reserved)?),
        ("response_bytes".into(), number(meter.bytes)?),
        ("started_at_ms".into(), number(call.started_at_ms)?),
        ("usage".into(), usage),
    ])?;
    Value::object(vec![("body".into(), body), ("schema".into(), text("aukora-engine-model-receipt-v1")?)])
}

/// The provider's own error type and message, if both are plain and carry nothing of the key; else a generic one.
fn provider_error(bytes: &[u8], status: u16, link: &Link, meter: &Meter) -> (String, String) {
    let fallback = match status {
        401 | 403 => "authentication_error",
        402 => "billing_error",
        429 => "rate_limit_error",
        400 | 404 | 413 | 422 => "invalid_request_error",
        _ => "api_error",
    };
    let generic = (fallback.to_owned(), format!("aukora broker: the provider refused the call (HTTP {status})"));
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else { return generic };
    let error = value.get("error");
    let kind = error.and_then(|e| e.get("type")).and_then(serde_json::Value::as_str).unwrap_or(fallback);
    let message = error.and_then(|e| e.get("message")).and_then(serde_json::Value::as_str).unwrap_or("");
    let plain = |s: &str| s.chars().all(|c| !c.is_control() || c == ' ');
    let known = [
        "authentication_error",
        "permission_error",
        "billing_error",
        "rate_limit_error",
        "invalid_request_error",
        "not_found_error",
        "request_too_large",
        "api_error",
        "overloaded_error",
    ];
    if message.is_empty()
        || message.len() > MAX_ERROR_MESSAGE
        || !plain(message)
        || meter.guard_rejects(message.as_bytes())
        || link.keys.reject_echo(message.as_bytes()).is_err()
    {
        return generic;
    }
    let kind = if known.contains(&kind) { kind } else { fallback };
    (kind.to_owned(), format!("provider (HTTP {status}): {message}"))
}

fn error_body(error_type: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"type": "error", "error": {"type": error_type, "message": message}}))
        .unwrap_or_default()
}

fn json_response(status: u16, body: &[u8]) -> Response<Body> {
    let mut response = Response::new(Full::new(Bytes::copy_from_slice(body)).boxed());
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    response.headers_mut().insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
    response.headers_mut().insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
    response
}

fn refusal(refused: &LinkRefusal) -> Response<Body> {
    json_response(refused.status, &error_body(refused.error_type, refused.message))
}

fn random_id() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The streamed reply: whatever the pump sends, in order, until it drops its sender.
pub(super) struct ChannelBody(pub(super) tokio::sync::mpsc::Receiver<Bytes>);

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|chunk| chunk.map(|bytes| Ok(Frame::data(bytes))))
    }
}
