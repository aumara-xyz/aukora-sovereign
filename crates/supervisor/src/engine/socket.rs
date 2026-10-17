// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine origin's one WebSocket: the harness web client's live connection (`/api/remote.mux`), NODE.md O9.
//!
//! Admission is the request's (proxy.rs: the engine session cookie bound to its ticket and shell session, the binding,
//! the approved release, the path and query checks) plus the upgrade's own: only `GET` to an allowlisted path, a
//! WebSocket version 13 handshake with a well-formed key, and an `Origin` that is exactly the engine origin (a page
//! on any other origin, the shell's included, cannot open it). No extension and no subprotocol is negotiated: the
//! browser's offers (Chrome always offers permessage-deflate) are not forwarded, so the harness never accepts one.
//!
//! Then the two upgraded streams are relayed frame by frame, each frame's header read and checked before its bytes
//! pass: RSV bits clear (nothing was negotiated), a known opcode, control frames whole and at most 125 bytes, frames
//! from the browser masked and frames from the harness not, fragments in order, and a message at most 1 MiB up (the
//! harness's own uplink window is 256 KiB) and 16 MiB down. A violation ends the socket. Every five seconds the
//! session is re-checked: when it ended (the owner signed out, the binding or the release approval changed), when
//! the engine stopped, or after a minute without a frame (the harness pings every two seconds), the browser gets a
//! close frame at the next frame boundary and both connections are dropped.

use super::proxy::{self, Admitted};
use super::{access, Engine};
use crate::host::Host;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The only paths an upgrade may name (the harness's remote stream mux). The web terminal's is not among them.
pub const UPGRADE_PATHS: &[&str] = &["/api/remote.mux"];
pub const MAX_UP_MESSAGE: u64 = 1 << 20;
pub const MAX_DOWN_MESSAGE: u64 = 16 << 20;
const CHECK_EVERY: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(60);
/// A session check that cannot read the floor or the session store this many times in a row closes the socket.
const UNKNOWN_CHECKS: u32 = 6;

/// Close codes the browser may see.
const GOING_AWAY: u16 = 1001;
const PROTOCOL_ERROR: u16 = 1002;
const POLICY: u16 = 1008;
const TOO_BIG: u16 = 1009;

/// Why an upgrade was refused before anything reached the harness.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    NotWebSocket,
    Path,
    Origin,
}

impl Refused {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NotWebSocket => StatusCode::BAD_REQUEST,
            Self::Path => StatusCode::NOT_FOUND,
            Self::Origin => StatusCode::FORBIDDEN,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::NotWebSocket => "Only a WebSocket upgrade is forwarded.\n",
            Self::Path => "not found\n",
            Self::Origin => "This connection may only be opened by the engine's own pages.\n",
        }
    }
}

fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

/// Whether the request asks to change protocols at all (any `Upgrade` header, or `Connection: upgrade`).
pub fn asks_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key("upgrade") || connection_upgrade(headers)
}

fn connection_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

/// The upgrade's own admission (the session's is the proxy's): `target` is the admitted path and query.
pub fn admit_upgrade(method: &Method, headers: &HeaderMap, target: &str, engine_host: &str) -> Result<(), Refused> {
    let websocket = method == Method::GET
        && one(headers, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && connection_upgrade(headers)
        && one(headers, "sec-websocket-version") == Some("13")
        && one(headers, "sec-websocket-key").is_some_and(|key| {
            key.len() == 24 && key.ends_with("==") && key[..22].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        });
    if !websocket {
        return Err(Refused::NotWebSocket);
    }
    let path = target.split('?').next().unwrap_or("");
    if !UPGRADE_PATHS.contains(&path) {
        return Err(Refused::Path);
    }
    if one(headers, "origin") != Some(format!("https://{engine_host}").as_str()) {
        return Err(Refused::Origin);
    }
    Ok(())
}

/// The harness's answer to the forwarded upgrade: `Sec-WebSocket-Accept` to hand the browser (which checks it against
/// its own key, forwarded unchanged) if the harness switched protocols with nothing negotiated; else `None`.
pub fn switched(status: StatusCode, headers: &HeaderMap) -> Option<HeaderValue> {
    let plain = status == StatusCode::SWITCHING_PROTOCOLS
        && one(headers, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && !headers.contains_key("sec-websocket-extensions")
        && !headers.contains_key("sec-websocket-protocol");
    let accept = one(headers, "sec-websocket-accept")?;
    (plain && accept.len() == 28 && accept.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)))
        .then(|| HeaderValue::from_str(accept).ok())
        .flatten()
}

/// What the relay checks one direction against.
#[derive(Clone, Copy)]
pub struct Rules {
    /// Frames must carry a mask (browser to harness) or must not (harness to browser).
    pub masked: bool,
    pub max_message: u64,
}

pub const UP: Rules = Rules { masked: true, max_message: MAX_UP_MESSAGE };
pub const DOWN: Rules = Rules { masked: false, max_message: MAX_DOWN_MESSAGE };

/// One frame's header, as read, with the payload length it announces.
#[derive(Debug)]
pub struct Header {
    pub raw: Vec<u8>,
    pub fin: bool,
    pub opcode: u8,
    pub length: u64,
}

/// Why a frame ended the socket.
#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    Closed,
    Protocol,
    TooBig,
}

impl Violation {
    fn code(&self) -> u16 {
        match self {
            Self::TooBig => TOO_BIG,
            _ => PROTOCOL_ERROR,
        }
    }
}

/// Read and check one frame header. `in_message`: a fragmented data message is open in this direction, with
/// `so_far` payload bytes.
pub async fn read_header<R: AsyncRead + Unpin>(
    from: &mut R,
    rules: Rules,
    in_message: bool,
    so_far: u64,
) -> Result<Header, Violation> {
    let mut raw = vec![0u8; 2];
    from.read_exact(&mut raw).await.map_err(|_| Violation::Closed)?;
    let (fin, rsv, opcode) = (raw[0] & 0x80 != 0, raw[0] & 0x70, raw[0] & 0x0f);
    let (masked, short) = (raw[1] & 0x80 != 0, u64::from(raw[1] & 0x7f));
    if rsv != 0 || masked != rules.masked || !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return Err(Violation::Protocol);
    }
    let length = match short {
        126 => {
            let mut more = [0u8; 2];
            from.read_exact(&mut more).await.map_err(|_| Violation::Closed)?;
            raw.extend_from_slice(&more);
            u64::from(u16::from_be_bytes(more))
        }
        127 => {
            let mut more = [0u8; 8];
            from.read_exact(&mut more).await.map_err(|_| Violation::Closed)?;
            raw.extend_from_slice(&more);
            u64::from_be_bytes(more)
        }
        length => length,
    };
    if masked {
        let mut key = [0u8; 4];
        from.read_exact(&mut key).await.map_err(|_| Violation::Closed)?;
        raw.extend_from_slice(&key);
    }
    if opcode >= 8 {
        // Control frames: whole and small, and allowed between the fragments of a message.
        if !fin || length > 125 {
            return Err(Violation::Protocol);
        }
    } else {
        // A continuation only inside a message; a new message only outside one.
        if (opcode == 0) != in_message {
            return Err(Violation::Protocol);
        }
        if length > rules.max_message || so_far.saturating_add(length) > rules.max_message {
            return Err(Violation::TooBig);
        }
    }
    Ok(Header { raw, fin, opcode, length })
}

/// A close frame from the engine origin to the browser (unmasked, a code, no reason).
pub fn close_frame(code: u16) -> [u8; 4] {
    let [high, low] = code.to_be_bytes();
    [0x88, 0x02, high, low]
}

/// Relay frames from `from` to `to` until either ends, a frame breaks the rules, or `stop` says so. Only a direction
/// that writes to the browser (`notify`) answers a violation or a stop with a close frame, always at a frame
/// boundary. `activity` is the time of the newest frame either way.
async fn pump<R, W>(
    mut from: R,
    mut to: W,
    rules: Rules,
    notify: bool,
    activity: &AtomicU64,
    started: Instant,
    mut stop: tokio::sync::watch::Receiver<Option<u16>>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut in_message, mut so_far) = (false, 0u64);
    loop {
        let header = tokio::select! {
            header = read_header(&mut from, rules, in_message, so_far) => header,
            _ = stop.changed() => {
                let code = (*stop.borrow()).unwrap_or(GOING_AWAY);
                if notify {
                    let _ = to.write_all(&close_frame(code)).await;
                }
                let _ = to.shutdown().await;
                return;
            }
        };
        let header = match header {
            Ok(header) => header,
            Err(violation) => {
                if notify && violation != Violation::Closed {
                    let _ = to.write_all(&close_frame(violation.code())).await;
                }
                let _ = to.shutdown().await;
                return;
            }
        };
        if header.opcode < 8 {
            so_far = if header.fin { 0 } else { so_far + header.length };
            in_message = !header.fin;
        }
        activity.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        if to.write_all(&header.raw).await.is_err() {
            return;
        }
        let copied = tokio::io::copy(&mut (&mut from).take(header.length), &mut to).await;
        if !matches!(copied, Ok(n) if n == header.length) || to.flush().await.is_err() {
            let _ = to.shutdown().await;
            return;
        }
    }
}

/// What the socket re-checks while it is open.
pub struct Watch {
    pub host: Arc<Host>,
    pub engine: Arc<Engine>,
    pub grant: access::Grant,
    pub bearer: String,
}

impl Watch {
    /// Wait until the socket must close; the close code says why.
    async fn until_ended(&self, activity: Arc<AtomicU64>, started: Instant) -> u16 {
        let mut unknown = 0;
        loop {
            tokio::time::sleep(CHECK_EVERY).await;
            let Some(now) = proxy::now() else { return POLICY };
            if self.engine.access.lock().ok().and_then(|mut access| access.session(&self.bearer, now)).is_none() {
                return POLICY;
            }
            match proxy::still_admitted(&self.host, &self.grant, now).await {
                Admitted::Yes => unknown = 0,
                Admitted::Unknown => {
                    unknown += 1;
                    if unknown >= UNKNOWN_CHECKS {
                        return GOING_AWAY;
                    }
                }
                Admitted::Ended => {
                    if let Ok(mut access) = self.engine.access.lock() {
                        access.end(&self.bearer);
                    }
                    return POLICY;
                }
                Admitted::ShellEnded => {
                    self.engine.end_shell(self.grant.shell);
                    return POLICY;
                }
            }
            if !self.engine.is_running() {
                return GOING_AWAY;
            }
            let quiet = started.elapsed().saturating_sub(Duration::from_millis(activity.load(Ordering::Relaxed)));
            if quiet >= IDLE {
                return GOING_AWAY;
            }
        }
    }
}

/// Splice the browser's and the harness's upgraded streams, frame by frame, until either side ends or the watch says
/// the socket must close.
pub async fn splice<B, H>(browser: B, harness: H, watch: Watch)
where
    B: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
{
    splice_with(browser, harness, |activity, started| async move { watch.until_ended(activity, started).await }).await
}

/// `splice` with any watch (the tests give their own).
pub async fn splice_with<B, H, F, Fut>(browser: B, harness: H, watch: F)
where
    B: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(Arc<AtomicU64>, Instant) -> Fut,
    Fut: std::future::Future<Output = u16>,
{
    let started = Instant::now();
    let activity = Arc::new(AtomicU64::new(0));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(None);
    let (browser_read, browser_write) = tokio::io::split(browser);
    let (harness_read, harness_write) = tokio::io::split(harness);
    let up = pump(browser_read, harness_write, UP, false, &activity, started, stop_rx.clone());
    let down = pump(harness_read, browser_write, DOWN, true, &activity, started, stop_rx);
    tokio::pin!(up, down);
    let ended = watch(activity.clone(), started);
    tokio::pin!(ended);
    tokio::select! {
        () = &mut up => {}
        () = &mut down => {}
        code = &mut ended => {
            let _ = stop_tx.send(Some(code));
            // The browser's side closes at its next frame boundary; a harness that is mid-frame gets two seconds.
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut down).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(http::HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    const HOST: &str = "engine.n1.sslip.io";
    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn upgrade(extra: &[(&str, &str)]) -> HeaderMap {
        let mut pairs = vec![
            ("upgrade", "websocket"),
            ("connection", "keep-alive, Upgrade"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", KEY),
            ("origin", "https://engine.n1.sslip.io"),
        ];
        for (name, value) in extra {
            pairs.retain(|(n, _)| n != name);
            pairs.push((name, value));
        }
        headers(&pairs)
    }

    #[test]
    fn only_a_plain_websocket_to_the_mux_from_the_engine_origin_is_admitted() {
        let get = Method::GET;
        assert_eq!(admit_upgrade(&get, &upgrade(&[]), "/api/remote.mux", HOST), Ok(()));
        assert_eq!(admit_upgrade(&get, &upgrade(&[]), "/api/remote.mux?x=1", HOST), Ok(()));
        // Found live: Chrome offers permessage-deflate on every socket. An offer is admitted and never forwarded
        // (proxy.rs forwards only the key and the version), so nothing is negotiated.
        let offer = upgrade(&[("sec-websocket-extensions", "permessage-deflate; client_max_window_bits")]);
        assert_eq!(admit_upgrade(&get, &offer, "/api/remote.mux", HOST), Ok(()));
        for origin in ["https://n1.sslip.io", "https://owner.n1.sslip.io", "http://engine.n1.sslip.io", "null", "https://engine.n1.sslip.io:443"] {
            assert_eq!(admit_upgrade(&get, &upgrade(&[("origin", origin)]), "/api/remote.mux", HOST), Err(Refused::Origin), "{origin}");
        }
        let mut no_origin = upgrade(&[]);
        no_origin.remove("origin");
        assert_eq!(admit_upgrade(&get, &no_origin, "/api/remote.mux", HOST), Err(Refused::Origin));
        let mut two_origins = upgrade(&[]);
        two_origins.append("origin", HeaderValue::from_static("https://engine.n1.sslip.io"));
        assert_eq!(admit_upgrade(&get, &two_origins, "/api/remote.mux", HOST), Err(Refused::Origin));
        for path in ["/api/terminal", "/", "/api/remote.mux/x"] {
            assert_eq!(admit_upgrade(&get, &upgrade(&[]), path, HOST), Err(Refused::Path), "{path}");
        }
        for bad in [
            upgrade(&[("upgrade", "h2c")]),
            upgrade(&[("sec-websocket-version", "8")]),
            upgrade(&[("sec-websocket-key", "short")]),
            upgrade(&[("connection", "keep-alive")]),
        ] {
            assert_eq!(admit_upgrade(&get, &bad, "/api/remote.mux", HOST), Err(Refused::NotWebSocket));
        }
        assert_eq!(admit_upgrade(&Method::POST, &upgrade(&[]), "/api/remote.mux", HOST), Err(Refused::NotWebSocket));
        assert!(asks_upgrade(&headers(&[("connection", "Upgrade")])) && !asks_upgrade(&headers(&[("connection", "close")])));
    }

    #[test]
    fn the_harness_must_switch_with_nothing_negotiated() {
        let accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        let good = headers(&[("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-accept", accept)]);
        assert_eq!(switched(StatusCode::SWITCHING_PROTOCOLS, &good).unwrap(), accept);
        assert!(switched(StatusCode::UNAUTHORIZED, &good).is_none());
        let mut deflate = good.clone();
        deflate.insert("sec-websocket-extensions", HeaderValue::from_static("permessage-deflate"));
        assert!(switched(StatusCode::SWITCHING_PROTOCOLS, &deflate).is_none());
        let mut forged = good.clone();
        forged.insert("sec-websocket-accept", HeaderValue::from_static("short"));
        assert!(switched(StatusCode::SWITCHING_PROTOCOLS, &forged).is_none());
    }

    /// A frame with the given first byte, payload and mask.
    fn frame(first: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = vec![first];
        let bit = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => out.push(bit | n as u8),
            n if n <= 0xffff => {
                out.push(bit | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(bit | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
            }
            None => out.extend_from_slice(payload),
        }
        out
    }

    async fn header_of(bytes: Vec<u8>, rules: Rules, in_message: bool) -> Result<Header, Violation> {
        read_header(&mut bytes.as_slice(), rules, in_message, 0).await
    }

    #[tokio::test]
    async fn frames_are_checked_before_they_pass() {
        let key = Some([1, 2, 3, 4]);
        assert_eq!(header_of(frame(0x81, b"hi", key), UP, false).await.unwrap().length, 2);
        assert_eq!(header_of(frame(0x82, b"hi", None), DOWN, false).await.unwrap().opcode, 2);
        // Masking by direction.
        assert_eq!(header_of(frame(0x81, b"hi", None), UP, false).await.unwrap_err(), Violation::Protocol);
        assert_eq!(header_of(frame(0x81, b"hi", key), DOWN, false).await.unwrap_err(), Violation::Protocol);
        // RSV bits (a compressed frame) and unknown opcodes.
        assert_eq!(header_of(frame(0xC1, b"hi", key), UP, false).await.unwrap_err(), Violation::Protocol);
        assert_eq!(header_of(frame(0x83, b"hi", key), UP, false).await.unwrap_err(), Violation::Protocol);
        // Control frames whole and small; allowed inside a fragmented message.
        assert_eq!(header_of(frame(0x09, b"p", key), UP, false).await.unwrap_err(), Violation::Protocol);
        assert_eq!(header_of(frame(0x89, &[0; 126], key), UP, false).await.unwrap_err(), Violation::Protocol);
        assert!(header_of(frame(0x89, b"p", key), UP, true).await.is_ok());
        // Fragments in order.
        assert_eq!(header_of(frame(0x80, b"x", key), UP, false).await.unwrap_err(), Violation::Protocol);
        assert_eq!(header_of(frame(0x01, b"x", key), UP, true).await.unwrap_err(), Violation::Protocol);
        // Sizes: one frame, and a message across fragments.
        let big = vec![0u8; MAX_UP_MESSAGE as usize + 1];
        assert_eq!(header_of(frame(0x82, &big, key), UP, false).await.unwrap_err(), Violation::TooBig);
        assert!(header_of(frame(0x82, &big, None), DOWN, false).await.is_ok());
        let half = frame(0x80, &vec![0u8; (MAX_UP_MESSAGE / 2 + 1) as usize], key);
        assert_eq!(read_header(&mut half.as_slice(), UP, true, MAX_UP_MESSAGE / 2).await.unwrap_err(), Violation::TooBig);
        let mut huge = vec![0x82, 127];
        huge.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(header_of(huge, DOWN, false).await.unwrap_err(), Violation::TooBig);
        assert_eq!(header_of(vec![0x81], UP, false).await.unwrap_err(), Violation::Closed);
    }

    #[tokio::test]
    async fn frames_pass_unchanged_both_ways_and_a_bad_frame_or_an_ended_session_closes_the_socket() {
        let key = Some([9, 8, 7, 6]);
        // Both ways, byte for byte, including fragments with a ping between them.
        let (browser, mut browser_far) = duplex(1 << 16);
        let (harness, mut harness_far) = duplex(1 << 16);
        let (end_tx, end_rx) = tokio::sync::oneshot::channel::<u16>();
        let relay = tokio::spawn(splice_with(browser, harness, |_, _| async move { end_rx.await.unwrap_or(GOING_AWAY) }));
        let up = [frame(0x01, b"hel", key), frame(0x89, b"", key), frame(0x80, b"lo", key)].concat();
        browser_far.write_all(&up).await.unwrap();
        let mut seen = vec![0u8; up.len()];
        harness_far.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, up);
        let down = [frame(0x81, b"history", None), frame(0x89, b"", None)].concat();
        harness_far.write_all(&down).await.unwrap();
        let mut seen = vec![0u8; down.len()];
        browser_far.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, down);
        // The session ends (signed out): the browser gets a policy close frame and the socket ends.
        end_tx.send(POLICY).unwrap();
        let mut close = [0u8; 4];
        browser_far.read_exact(&mut close).await.unwrap();
        assert_eq!(close, close_frame(POLICY));
        relay.await.unwrap();
        let mut rest = Vec::new();
        assert_eq!(harness_far.read_to_end(&mut rest).await.unwrap(), 0, "the harness side is dropped");

        // An oversized message from the browser never reaches the harness; the socket ends.
        let (browser, mut browser_far) = duplex(1 << 16);
        let (harness, mut harness_far) = duplex(1 << 16);
        let relay = tokio::spawn(splice_with(browser, harness, |_, _| std::future::pending::<u16>()));
        let mut header = vec![0x82, 0x80 | 127];
        header.extend_from_slice(&(MAX_UP_MESSAGE + 1).to_be_bytes());
        header.extend_from_slice(&[1, 2, 3, 4]);
        browser_far.write_all(&header).await.unwrap();
        relay.await.unwrap();
        let mut rest = Vec::new();
        assert_eq!(harness_far.read_to_end(&mut rest).await.unwrap(), 0);

        // A compressed (RSV1) frame from the harness: the browser gets a protocol-error close instead of it.
        let (browser, mut browser_far) = duplex(1 << 16);
        let (harness, mut harness_far) = duplex(1 << 16);
        let relay = tokio::spawn(splice_with(browser, harness, |_, _| std::future::pending::<u16>()));
        harness_far.write_all(&frame(0xC1, b"zz", None)).await.unwrap();
        let mut close = [0u8; 4];
        browser_far.read_exact(&mut close).await.unwrap();
        assert_eq!(close, close_frame(PROTOCOL_ERROR));
        relay.await.unwrap();
    }
}
