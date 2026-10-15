// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded loopback transport; frontdoor admits every request before dispatch.

use crate::host::Host;
use canon::{codes, json::Value, Result};
use frontdoor::ingress::{self, HttpIngress};
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    Request, Response,
};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;

pub async fn serve(host: Arc<Host>) -> Result<()> {
    let ingress = Arc::new(HttpIngress::new(host.config.boundary()?)?);
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
            refuse_overload(stream).await;
            continue;
        };
        let host = host.clone();
        let ingress = ingress.clone();
        tokio::spawn(async move {
            let slot = Arc::new(slot);
            let held = Arc::clone(&slot);
            let service = hyper::service::service_fn(move |request| {
                handle(
                    host.clone(),
                    ingress.clone(),
                    peer,
                    request,
                    Arc::clone(&slot),
                )
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
    ingress: Arc<HttpIngress>,
    peer: SocketAddr,
    request: Request<Incoming>,
    slot: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let response = match ingress.admit_incoming(peer.ip(), request).await {
        Ok(admitted) => match tokio::task::spawn_blocking(move || {
            let _slot = slot;
            host.dispatch(&admitted)
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

async fn refuse_overload(mut stream: tokio::net::TcpStream) {
    let body = refusal(codes::FRONTDOOR_OVERLOADED).into_body();
    let header = format!(
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    // One rejected socket remains in the accept loop, bounded independently of active work.
    let _sent = tokio::time::timeout(Duration::from_millis(100), async {
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await
    })
    .await;
}

fn refusal(code: canon::Refusal) -> Response<Vec<u8>> {
    let encoded =
        Value::text(code.to_string()).and_then(|code| Value::object(vec![("error".into(), code)]));
    let bytes = match encoded {
        Ok(value) => value.canonical_bytes(),
        Err(_) => b"{\"error\":\"supervisor:refusal-encoding\"}".to_vec(),
    };
    let mut response = Response::new(bytes);
    *response.status_mut() = if code == codes::FRONTDOOR_OVERLOADED {
        http::StatusCode::SERVICE_UNAVAILABLE
    } else {
        http::StatusCode::BAD_REQUEST
    };
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
