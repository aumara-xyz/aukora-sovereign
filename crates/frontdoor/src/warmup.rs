// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Uri};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::UnixStream;

const BOOT: &str = "<script>globalThis[\"__DSH_BOOT__\"] = ";
const MAX_URL_BYTES: usize = 3 * 1024;
const MAX_BODY_FRAMES: usize = 16 * 1024;

#[cfg(test)]
pub(crate) type Connector = std::sync::Arc<
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<UnixStream>> + Send>,
        > + Send
        + Sync,
>;

pub(crate) struct Socket {
    path: PathBuf,
    #[cfg(test)]
    connector: Option<Connector>,
}

impl Socket {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            #[cfg(test)]
            connector: None,
        }
    }

    #[cfg(test)]
    pub fn with_connector(path: &Path, connector: Connector) -> Self {
        Self {
            path: path.to_owned(),
            connector: Some(connector),
        }
    }

    pub async fn connect(&self) -> std::io::Result<UnixStream> {
        #[cfg(test)]
        if let Some(connector) = &self.connector {
            return connector().await;
        }
        UnixStream::connect(&self.path).await
    }
}

pub(crate) struct Limits {
    pub timeout: Duration,
    pub html_bytes: usize,
    pub bundle_bytes: usize,
    pub requests: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            html_bytes: 1024 * 1024,
            bundle_bytes: 32 * 1024 * 1024,
            requests: 8,
        }
    }
}

pub(crate) async fn run(
    socket: &Socket,
    host: &str,
    cookie: HeaderValue,
    limits: Limits,
) -> Result<(), &'static str> {
    let work = async {
        let max_bundles = limits
            .requests
            .checked_sub(1)
            .ok_or("frontdoor:warmup-request-limit")?;
        let html = get(socket, host, &cookie, "/", limits.html_bytes, true).await?;
        let urls = bundle_urls(&html, max_bundles)?;
        for url in urls {
            get(socket, host, &cookie, &url, limits.bundle_bytes, false).await?;
        }
        Ok(())
    };
    // MUTATION: warmup-deadline
    tokio::time::timeout(limits.timeout, work)
        .await
        .map_err(|_| "frontdoor:warmup-timeout")?
}

const MAX_HEAD_BYTES: usize = 32 * 1024;

async fn get(
    socket: &Socket,
    host: &str,
    cookie: &HeaderValue,
    path: &str,
    max_bytes: usize,
    collect: bool,
) -> Result<Vec<u8>, &'static str> {
    let refused = "frontdoor:warmup-response-refused";
    let stream = socket.connect().await.map_err(|_| refused)?;
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_headers(64)
        .max_buf_size(MAX_HEAD_BYTES)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| refused)?;
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, host)
        // MUTATION: warmup-cookie
        .header(header::COOKIE, cookie)
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CONNECTION, "close")
        .body(Body::empty())
        .map_err(|_| refused)?;
    let read = async {
        let response = sender.send_request(request).await.map_err(|_| refused)?;
        // MUTATION: warmup-redirect
        if !response.status().is_success()
            || response.headers().contains_key(header::CONTENT_ENCODING)
        {
            return Err(refused);
        }
        // hyper's max_buf_size bounds the head only when it arrives over several reads; count it
        // here: the status line (with any non-canonical reason phrase) and every header line.
        let reason = response
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map_or(2, |reason| reason.as_bytes().len());
        let head_bytes = response
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len() + 4)
            .sum::<usize>()
            + "HTTP/1.1 200 \r\n\r\n".len()
            + reason;
        if head_bytes > MAX_HEAD_BYTES {
            return Err(refused);
        }
        let mut body = response.into_body();
        let mut size = 0usize;
        let mut frames = 0usize;
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            frames += 1;
            // Bound parsing work independently of payload bytes.
            if frames > MAX_BODY_FRAMES {
                return Err("frontdoor:warmup-frame-limit");
            }
            let frame = frame.map_err(|_| refused)?;
            if let Ok(data) = frame.into_data() {
                size = size.checked_add(data.len()).ok_or(refused)?;
                // MUTATION: warmup-body-limit
                if size > max_bytes {
                    return Err("frontdoor:warmup-body-too-large");
                }
                if collect {
                    bytes.extend_from_slice(&data);
                }
            }
        }
        Ok(bytes)
    };
    // Cancellation drops the HTTP driver and its socket with the body reader.
    tokio::pin!(connection, read);
    tokio::select! {
        result = &mut read => result,
        _ = &mut connection => read.await,
    }
}

pub(crate) fn bundle_urls(html: &[u8], max_bundles: usize) -> Result<Vec<String>, &'static str> {
    let invalid = "frontdoor:warmup-manifest-refused";
    let html = std::str::from_utf8(html).map_err(|_| invalid)?;
    let (_, rest) = html.split_once(BOOT).ok_or(invalid)?;
    if rest.contains(BOOT) {
        return Err(invalid);
    }
    let (json, _) = rest.split_once("</script>").ok_or(invalid)?;
    let graph: Value = serde_json::from_str(json).map_err(|_| invalid)?;
    let batches = graph["batches"].as_array().ok_or(invalid)?;
    // MUTATION: warmup-request-limit
    if batches.len() > max_bundles {
        return Err("frontdoor:warmup-request-limit");
    }
    let mut urls = Vec::new();
    for batch in batches {
        if !matches!(batch["phase"].as_str(), Some("bootstrap" | "application")) {
            return Err(invalid);
        }
        let url = batch["url"].as_str().ok_or(invalid)?;
        // MUTATION: warmup-url-fence
        if !plugin_url(url) {
            return Err("frontdoor:warmup-url-refused");
        }
        if !urls.iter().any(|seen| seen == url) {
            urls.push(url.to_owned());
        }
    }
    Ok(urls)
}

fn plugin_url(url: &str) -> bool {
    if url.len() > MAX_URL_BYTES
        || !url.is_ascii()
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || url.contains(['\\', '%', '#'])
        || url.contains("//")
    {
        return false;
    }
    let Ok(uri) = url.parse::<Uri>() else {
        return false;
    };
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path() != "/plugins/" {
        return false;
    }
    let Some(resources) = url.strip_prefix("/plugins/??") else {
        return false;
    };
    let Some((resources, rev)) = resources.split_once("&rev=") else {
        return false;
    };
    if rev.is_empty() || !rev.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return false;
    }
    resources.split(',').all(|resource| {
        let Some(package) = resource.strip_suffix("/client.js") else {
            return false;
        };
        let segments: Vec<_> = package.split('/').collect();
        let valid_name = |name: &str| {
            !name.is_empty()
                && !matches!(name, "." | "..")
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        };
        match segments.as_slice() {
            [name] => valid_name(name),
            [scope, name] => scope.strip_prefix('@').is_some_and(valid_name) && valid_name(name),
            _ => false,
        }
    })
}

#[cfg(test)]
#[path = "warmup_tests.rs"]
mod tests;
