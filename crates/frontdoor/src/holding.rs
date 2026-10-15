// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    body::Body,
    http::{header, HeaderValue},
    response::Response,
};

pub(crate) fn page(owner_host: &str, head: bool) -> Response {
    // The validated node configuration is the only iframe origin.
    let html =
        include_str!("holding.html").replace("__OWNER_ORIGIN__", &format!("https://{owner_host}"));
    let mut response = Response::new(if head {
        Body::empty()
    } else {
        Body::from(html)
    });
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}
