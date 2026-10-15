// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded loopback transport; frontdoor admits every request before dispatch.

use crate::host::Host;
use canon::{codes, json::Value, Result};
use frontdoor::{
    ingress::{self, Method, RequestInput},
    tls::ProxyObservation,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    Request, Response,
};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};

pub async fn serve(host: Arc<Host>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(host.config.listen)
        .await
        .map_err(|_| canon::Refusal {
            organ: "supervisor",
            reason: "listen",
        })?;
    host.listener_started();
    let slots = Arc::new(tokio::sync::Semaphore::new(ingress::MAX_CONNECTIONS));
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|_| codes::SUPERVISOR_STATE)?;
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let host = host.clone();
        tokio::spawn(async move {
            let slot = Arc::new(slot);
            let held = Arc::clone(&slot);
            let service = hyper::service::service_fn(move |request| {
                handle(host.clone(), peer, request, Arc::clone(&slot))
            });
            let mut server = hyper::server::conn::http1::Builder::new();
            server
                .keep_alive(false)
                .max_buf_size(ingress::MAX_HEADER_BYTES);
            let connection = server.serve_connection(TokioIo::new(stream), service);
            let _closed = tokio::time::timeout(
                Duration::from_millis(ingress::REQUEST_DEADLINE_MS),
                connection,
            )
            .await;
            drop(held);
        });
    }
}

async fn handle(
    host: Arc<Host>,
    peer: SocketAddr,
    request: Request<Incoming>,
    slot: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let response = match admit(&host, peer, request).await {
        Ok((admitted, headers)) => match tokio::task::spawn_blocking(move || {
            let _slot = slot;
            host.dispatch(admitted, &headers)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(codes::SUPERVISOR_STATE),
        },
        Err(code) => Err(code),
    };
    let response = match response {
        Ok(response) => response,
        Err(code) => refusal(code),
    };
    Ok(response.map(|bytes| Full::new(Bytes::from(bytes))))
}

async fn admit(
    host: &Host,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Result<(ingress::AdmittedRequest, http::HeaderMap)> {
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().query().is_some()
    {
        return Err(codes::FRONTDOOR_PATH_REFUSED);
    }
    let method = match *request.method() {
        http::Method::GET => Method::Get,
        http::Method::HEAD => Method::Head,
        http::Method::POST => Method::Post,
        _ => return Err(codes::FRONTDOOR_UNKNOWN_ROUTE),
    };
    let (parts, body) = request.into_parts();
    let bytes = parts
        .headers
        .iter()
        .try_fold(0usize, |count, (key, value)| {
            count.checked_add(key.as_str().len() + value.len() + 4)
        })
        .ok_or(codes::FRONTDOOR_BODY_INVALID)?;
    if bytes > ingress::MAX_HEADER_BYTES {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    }
    let transport = host.config.boundary()?.admit(ProxyObservation {
        peer: peer.ip(),
        forwarded_proto: headers(&parts.headers, "x-forwarded-proto")?,
        host: headers(&parts.headers, "host")?,
    })?;
    let body = Limited::new(body, ingress::MAX_BODY_BYTES)
        .collect()
        .await
        .map_err(|_| codes::FRONTDOOR_BODY_INVALID)?
        .to_bytes()
        .to_vec();
    let input = RequestInput {
        transport,
        method,
        path: parts.uri.path().to_owned(),
        origins: headers(&parts.headers, "origin")?,
        fetch_sites: headers(&parts.headers, "sec-fetch-site")?,
        content_types: headers(&parts.headers, "content-type")?,
        cookies: headers(&parts.headers, "cookie")?,
        body,
    };
    Ok((ingress::admit(input)?, parts.headers))
}

fn headers(headers: &http::HeaderMap, name: &str) -> Result<Vec<String>> {
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

fn refusal(code: canon::Refusal) -> Response<Vec<u8>> {
    let encoded =
        Value::text(code.to_string()).and_then(|code| Value::object(vec![("error".into(), code)]));
    let bytes = match encoded {
        Ok(value) => value.canonical_bytes(),
        Err(_) => b"{\"error\":\"supervisor:refusal-encoding\"}".to_vec(),
    };
    let mut response = Response::new(bytes);
    *response.status_mut() = http::StatusCode::BAD_REQUEST;
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert("cache-control", http::HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        http::HeaderValue::from_static("nosniff"),
    );
    response
}
